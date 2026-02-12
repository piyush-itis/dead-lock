/**
 * Deadlock - Backend
 * 
 * ZERO-KNOWLEDGE: Server stores ONLY encrypted blobs.
 * We never see, never can decrypt, never store plaintext.
 * Compromised DB = useless encrypted data.
 */

import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Ensure data directory exists
const dataDir = join(__dirname, '../data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

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

// DB init
const dbPath = join(__dirname, '../data/vault.db');
const db = new Database(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    login_hash TEXT NOT NULL UNIQUE,
    salt TEXT NOT NULL,
    auth_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS vaults (
    user_id TEXT PRIMARY KEY REFERENCES users(id),
    encrypted_data TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_users_login ON users(login_hash);
`);

// Validate inputs - reject obviously malicious payloads
function validateUserId(id) {
  return typeof id === 'string' && /^[a-f0-9]{64}$/.test(id) && id.length === 64;
}

function validateBase64(str, maxLen = 500000) {
  return typeof str === 'string' && str.length <= maxLen && /^[A-Za-z0-9+/=]+$/.test(str);
}

// Generate cryptographically random ID
function randomId() {
  return crypto.randomBytes(32).toString('hex');
}

// POST /register - Client sends: { salt, loginHash, authHash }
app.post('/api/register', (req, res) => {
  try {
    const { salt, loginHash, authHash } = req.body || {};
    if (!validateBase64(salt, 200) || !validateBase64(loginHash, 200) || !validateBase64(authHash, 200)) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const id = randomId();
    const stmt = db.prepare(
      'INSERT INTO users (id, login_hash, salt, auth_hash, created_at) VALUES (?, ?, ?, ?, ?)'
    );
    stmt.run(id, loginHash, salt, authHash, Date.now());
    res.json({ userId: id });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT') return res.status(400).json({ error: 'Registration failed' });
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /login - Client sends: { loginHash }
// Returns userId + salt. Client derives key locally.
app.post('/api/login', (req, res) => {
  try {
    const { loginHash } = req.body || {};
    if (!validateBase64(loginHash, 200)) return res.status(400).json({ error: 'Invalid input' });
    const row = db.prepare('SELECT id, salt FROM users WHERE login_hash = ?').get(loginHash);
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ userId: row.id, salt: row.salt });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /vault/:userId - Fetch encrypted vault. Auth via authHash in body for GET? No - use POST.
// Actually for simplicity: require authHash in body for vault access.
app.post('/api/vault', (req, res) => {
  try {
    const { userId, authHash } = req.body || {};
    if (!validateUserId(userId) || !validateBase64(authHash, 200)) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const user = db.prepare('SELECT id FROM users WHERE id = ? AND auth_hash = ?').get(userId, authHash);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    const row = db.prepare('SELECT encrypted_data FROM vaults WHERE user_id = ?').get(userId);
    res.json({ encryptedData: row ? row.encrypted_data : null });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /vault - Save encrypted vault
app.put('/api/vault', (req, res) => {
  try {
    const { userId, authHash, encryptedData } = req.body || {};
    if (!validateUserId(userId) || !validateBase64(authHash, 200) || !validateBase64(encryptedData)) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const user = db.prepare('SELECT id FROM users WHERE id = ? AND auth_hash = ?').get(userId, authHash);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    db.prepare(`
      INSERT INTO vaults (user_id, encrypted_data, updated_at) VALUES (?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET encrypted_data = excluded.encrypted_data, updated_at = excluded.updated_at
    `).run(userId, encryptedData, Date.now());
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/stats - Aggregate counts only. No PII, no individual data.
// Safe to expose: user count cannot identify anyone.
app.get('/api/stats', (req, res) => {
  try {
    const userCount = db.prepare('SELECT COUNT(*) as n FROM users').get().n;
    const vaultCount = db.prepare('SELECT COUNT(*) as n FROM vaults').get().n;
    res.json({ userCount, vaultCount });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Serve static frontend in production only
if (process.env.NODE_ENV === 'production') {
  const distPath = join(__dirname, '../dist');
  app.use(express.static(distPath));
  app.get('*', (req, res) => {
    res.sendFile(join(distPath, 'index.html'));
  });
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Deadlock running on http://localhost:${PORT}`));
