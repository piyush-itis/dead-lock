import 'dotenv/config';

/**
 * Deadlock - Backend
 *
 * ZERO-KNOWLEDGE: Server stores ONLY encrypted blobs.
 * We never see, never can decrypt, never store plaintext.
 * Compromised DB = useless encrypted data.
 *
 * Database: Set DATABASE_URL for PostgreSQL (Neon, Supabase, etc.)
 * Leave unset for local SQLite.
 */

import express from 'express';
import crypto from 'crypto';
import { initDb, dbQuery, dbGet, isPg } from './db.js';

const app = express();
app.use(express.json({ limit: '100kb' }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'; connect-src 'self' https://api.pwnedpasswords.com");
  next();
});

// CORS - restrict to same origin in production
const ALLOW_ORIGIN = process.env.NODE_ENV === 'production' ? undefined : '*';
app.use((req, res, next) => {
  if (ALLOW_ORIGIN) res.setHeader('Access-Control-Allow-Origin', ALLOW_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Rate limiting (simple in-memory)
const rateLimit = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 min
const RATE_LIMIT_MAX = 30;

function rateLimitMiddleware(req, res, next) {
  const key = req.ip || 'unknown';
  const now = Date.now();
  if (!rateLimit.has(key)) rateLimit.set(key, { count: 0, resetAt: now + RATE_LIMIT_WINDOW });
  const r = rateLimit.get(key);
  if (now > r.resetAt) { r.count = 0; r.resetAt = now + RATE_LIMIT_WINDOW; }
  r.count++;
  if (r.count > RATE_LIMIT_MAX) return res.status(429).json({ error: 'Too many requests' });
  next();
}
app.use(rateLimitMiddleware);

// Validate inputs - reject obviously malicious payloads
function validateUserId(id) {
  return typeof id === 'string' && /^[a-f0-9]{64}$/.test(id) && id.length === 64;
}

function validateBase64(str, maxLen = 500000) {
  return typeof str === 'string' && str.length <= maxLen && /^[A-Za-z0-9+/=]+$/.test(str);
}

function randomId() {
  return crypto.randomBytes(32).toString('hex');
}

// POST /register
app.post('/api/register', async (req, res) => {
  try {
    const { salt, loginHash, authHash } = req.body || {};
    if (!validateBase64(salt, 200) || !validateBase64(loginHash, 200) || !validateBase64(authHash, 200)) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const id = randomId();
    await dbQuery(
      'INSERT INTO users (id, login_hash, salt, auth_hash, created_at) VALUES (?, ?, ?, ?, ?)',
      [id, loginHash, salt, authHash, Date.now()]
    );
    res.json({ userId: id });
  } catch (e) {
    if (e.code === '23505' || e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(400).json({ error: 'Registration failed' });
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /login
app.post('/api/login', async (req, res) => {
  try {
    const { loginHash } = req.body || {};
    if (!validateBase64(loginHash, 200)) return res.status(400).json({ error: 'Invalid input' });
    const row = await dbGet('SELECT id, salt FROM users WHERE login_hash = ?', [loginHash]);
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ userId: row.id, salt: row.salt });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/vault - Fetch encrypted vault
app.post('/api/vault', async (req, res) => {
  try {
    const { userId, authHash } = req.body || {};
    if (!validateUserId(userId) || !validateBase64(authHash, 200)) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const user = await dbGet('SELECT id FROM users WHERE id = ? AND auth_hash = ?', [userId, authHash]);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    const row = await dbGet('SELECT encrypted_data FROM vaults WHERE user_id = ?', [userId]);
    res.json({ encryptedData: row ? row.encrypted_data : null });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/vault - Save encrypted vault
app.put('/api/vault', async (req, res) => {
  try {
    const { userId, authHash, encryptedData } = req.body || {};
    if (!validateUserId(userId) || !validateBase64(authHash, 200) || !validateBase64(encryptedData)) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const user = await dbGet('SELECT id FROM users WHERE id = ? AND auth_hash = ?', [userId, authHash]);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    await dbQuery(
      `INSERT INTO vaults (user_id, encrypted_data, updated_at) VALUES (?, ?, ?)
       ON CONFLICT (user_id) DO UPDATE SET encrypted_data = EXCLUDED.encrypted_data, updated_at = EXCLUDED.updated_at`,
      [userId, encryptedData, Date.now()]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/db - Confirm which database is in use
app.get('/api/db', (req, res) => {
  res.json({ database: isPg() ? 'postgresql' : 'sqlite' });
});

// GET /api/stats
app.get('/api/stats', async (req, res) => {
  try {
    const userRow = await dbGet('SELECT COUNT(*) as n FROM users');
    const vaultRow = await dbGet('SELECT COUNT(*) as n FROM vaults');
    res.json({ userCount: Number(userRow?.n ?? 0), vaultCount: Number(vaultRow?.n ?? 0) });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Serve static frontend in production
if (process.env.NODE_ENV === 'production') {
  const { fileURLToPath } = await import('url');
  const { dirname, join } = await import('path');
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const distPath = join(__dirname, '../dist');
  app.use(express.static(distPath));
  app.get('*', (req, res) => {
    res.sendFile(join(distPath, 'index.html'));
  });
}

const PORT = process.env.PORT || 3000;

initDb()
  .then(() => {
    app.listen(PORT, () => {
      const dbType = process.env.DATABASE_URL ? 'PostgreSQL' : 'SQLite';
      console.log(`Deadlock running on http://localhost:${PORT} (${dbType})`);
    });
  })
  .catch((err) => {
    console.error('Database init failed:', err);
    process.exit(1);
  });
