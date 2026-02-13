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
const isProduction = process.env.NODE_ENV === 'production';

// Trust proxy for correct protocol detection when behind nginx/load balancer
app.set('trust proxy', 1);

app.use(express.json({ limit: '100kb' }));

// In production, reject non-HTTPS requests (requires trust proxy when behind load balancer)
// Localhost is allowed for local prod testing
if (isProduction) {
  app.use((req, res, next) => {
    const host = req.get('host') || '';
    const isLocalhost = host.startsWith('localhost') || host.startsWith('127.0.0.1');
    if (!isLocalhost && !req.secure) {
      return res.status(403).json({ error: 'HTTPS required' });
    }
    next();
  });
}

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self' https://api.pwnedpasswords.com",
  ].join('; '));
  next();
});

// CORS - in production, allow only origins in ALLOWED_ORIGINS (comma-separated)
// If ALLOWED_ORIGINS is empty in production, no CORS header is set (same-origin only)
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',').map((o) => o.trim()).filter(Boolean) || [];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowOrigin = isProduction
    ? ALLOWED_ORIGINS.length > 0 && origin && ALLOWED_ORIGINS.includes(origin)
      ? origin
      : null
    : origin || '*';

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With');
  if (allowOrigin) res.setHeader('Access-Control-Allow-Origin', allowOrigin);

  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// CSRF: require X-Requested-With for state-changing API requests (cross-origin form posts won't include it)
app.use('/api', (req, res, next) => {
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    if (req.get('X-Requested-With') !== 'XMLHttpRequest') {
      return res.status(403).json({ error: 'Invalid request' });
    }
  }
  next();
});

// Rate limiting (in-memory, per-endpoint)
const rateLimitStore = new Map();
const WINDOW_MS = 60 * 1000;

function rateLimit(maxPerWindow) {
  return (req, res, next) => {
    const key = `${req.ip || 'unknown'}:${req.path}`;
    const now = Date.now();
    if (!rateLimitStore.has(key)) rateLimitStore.set(key, { count: 0, resetAt: now + WINDOW_MS });
    const r = rateLimitStore.get(key);
    if (now > r.resetAt) { r.count = 0; r.resetAt = now + WINDOW_MS; }
    r.count++;
    if (r.count > maxPerWindow) return res.status(429).json({ error: 'Too many requests' });
    next();
  };
}

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

function timingSafeEqualBase64(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  try {
    const bufA = Buffer.from(a, 'base64');
    const bufB = Buffer.from(b, 'base64');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

const PBKDF2_ITERATIONS = 600000;

// POST /register
app.post('/api/register', rateLimit(5), async (req, res) => {
  try {
    const { salt, loginHash, authHash, iterations } = req.body || {};
    if (!validateBase64(salt, 200) || !validateBase64(loginHash, 200) || !validateBase64(authHash, 200)) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const iter = Number.isFinite(iterations) && iterations >= 10000 && iterations <= 1000000
      ? Math.round(iterations)
      : PBKDF2_ITERATIONS;
    const id = randomId();
    await dbQuery(
      'INSERT INTO users (id, login_hash, salt, auth_hash, created_at, iterations) VALUES (?, ?, ?, ?, ?, ?)',
      [id, loginHash, salt, authHash, Date.now(), iter]
    );
    res.json({ userId: id });
  } catch (e) {
    if (e.code === '23505' || e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(400).json({ error: 'Registration failed' });
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /login
app.post('/api/login', rateLimit(10), async (req, res) => {
  try {
    const { loginHash } = req.body || {};
    if (!validateBase64(loginHash, 200)) return res.status(400).json({ error: 'Invalid input' });
    const row = await dbGet('SELECT id, salt, iterations FROM users WHERE login_hash = ?', [loginHash]);
    if (!row) {
      if (isProduction) console.warn(`[AUTH] Login failed (unknown loginHash) from ${req.ip}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const iterations = row.iterations ?? 120000;
    res.json({ userId: row.id, salt: row.salt, iterations });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/vault - Fetch encrypted vault
app.post('/api/vault', rateLimit(30), async (req, res) => {
  try {
    const { userId, authHash } = req.body || {};
    if (!validateUserId(userId) || !validateBase64(authHash, 200)) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const user = await dbGet('SELECT id, auth_hash FROM users WHERE id = ?', [userId]);
    if (!user || !timingSafeEqualBase64(authHash, user.auth_hash)) {
      if (isProduction) console.warn(`[AUTH] Vault fetch failed for user ${userId?.slice(0, 8)}... from ${req.ip}`);
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const row = await dbGet('SELECT encrypted_data FROM vaults WHERE user_id = ?', [userId]);
    res.json({ encryptedData: row ? row.encrypted_data : null });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/vault - Save encrypted vault
app.put('/api/vault', rateLimit(30), async (req, res) => {
  try {
    const { userId, authHash, encryptedData } = req.body || {};
    if (!validateUserId(userId) || !validateBase64(authHash, 200) || !validateBase64(encryptedData)) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const user = await dbGet('SELECT id, auth_hash FROM users WHERE id = ?', [userId]);
    if (!user || !timingSafeEqualBase64(authHash, user.auth_hash)) {
      if (isProduction) console.warn(`[AUTH] Vault save failed for user ${userId?.slice(0, 8)}... from ${req.ip}`);
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const now = Date.now();
    await dbQuery(
      `INSERT INTO vaults (user_id, encrypted_data, updated_at) VALUES (?, ?, ?)
       ON CONFLICT (user_id) DO UPDATE SET encrypted_data = EXCLUDED.encrypted_data, updated_at = EXCLUDED.updated_at`,
      [userId, encryptedData, now]
    );
    await dbQuery(
      'INSERT INTO vault_history (id, user_id, encrypted_data, created_at) VALUES (?, ?, ?, ?)',
      [randomId(), userId, encryptedData, now]
    );
    const history = await dbQuery(
      'SELECT id FROM vault_history WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );
    const VAULT_HISTORY_LIMIT = 5;
    if (history.length > VAULT_HISTORY_LIMIT) {
      const toDelete = history.slice(VAULT_HISTORY_LIMIT).map((r) => r.id);
      for (const id of toDelete) {
        await dbQuery('DELETE FROM vault_history WHERE id = ?', [id]);
      }
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/vault/history - List vault versions (last 5)
app.post('/api/vault/history', rateLimit(30), async (req, res) => {
  try {
    const { userId, authHash } = req.body || {};
    if (!validateUserId(userId) || !validateBase64(authHash, 200)) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const user = await dbGet('SELECT id, auth_hash FROM users WHERE id = ?', [userId]);
    if (!user || !timingSafeEqualBase64(authHash, user.auth_hash)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const rows = await dbQuery(
      'SELECT id, created_at FROM vault_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 5',
      [userId]
    );
    res.json({ versions: rows.map((r) => ({ id: r.id, createdAt: r.created_at })) });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/vault/restore - Restore vault from a previous version
app.post('/api/vault/restore', rateLimit(10), async (req, res) => {
  try {
    const { userId, authHash, versionId } = req.body || {};
    if (!validateUserId(userId) || !validateBase64(authHash, 200) || typeof versionId !== 'string' || versionId.length > 100) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const user = await dbGet('SELECT id, auth_hash FROM users WHERE id = ?', [userId]);
    if (!user || !timingSafeEqualBase64(authHash, user.auth_hash)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const version = await dbGet('SELECT encrypted_data FROM vault_history WHERE id = ? AND user_id = ?', [versionId, userId]);
    if (!version) return res.status(404).json({ error: 'Version not found' });
    const now = Date.now();
    await dbQuery(
      `INSERT INTO vaults (user_id, encrypted_data, updated_at) VALUES (?, ?, ?)
       ON CONFLICT (user_id) DO UPDATE SET encrypted_data = EXCLUDED.encrypted_data, updated_at = EXCLUDED.updated_at`,
      [userId, version.encrypted_data, now]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/db - Confirm which database is in use
app.get('/api/db', rateLimit(60), (req, res) => {
  res.json({ database: isPg() ? 'postgresql' : 'sqlite' });
});

// GET /api/stats
app.get('/api/stats', rateLimit(60), async (req, res) => {
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
  const distPath = join(__dirname, '../client/dist');
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
