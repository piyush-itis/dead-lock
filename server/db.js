/**
 * Database layer - PostgreSQL (Neon) only
 * DATABASE_URL is required.
 */

import pg from 'pg';

let db;

export async function initDb() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    throw new Error('DATABASE_URL is required. Use Neon (neon.tech) or Supabase for a free PostgreSQL database.');
  }

  let isLocalhost = false;
  try {
    isLocalhost = /localhost|127\.0\.0\.1/.test(new URL(url).hostname);
  } catch {
    isLocalhost = /localhost|127\.0\.0\.1/.test(url);
  }

  const pool = new pg.Pool({
    connectionString: url,
    ssl: isLocalhost ? false : { rejectUnauthorized: true },
  });

  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    login_hash TEXT NOT NULL UNIQUE,
    salt TEXT NOT NULL,
    auth_hash TEXT NOT NULL,
    created_at BIGINT NOT NULL
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS vaults (
    user_id TEXT PRIMARY KEY REFERENCES users(id),
    encrypted_data TEXT NOT NULL,
    updated_at BIGINT NOT NULL
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS vault_history (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    encrypted_data TEXT NOT NULL,
    created_at BIGINT NOT NULL
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_login ON users(login_hash)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_vault_history_user ON vault_history(user_id)`);
  try {
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS iterations INTEGER DEFAULT 120000`);
  } catch {}

  db = { type: 'pg', pool };
  return db;
}

function toPgParams(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

export async function dbQuery(sql, params = []) {
  if (!db?.pool) throw new Error('Database not initialized');
  const res = await db.pool.query(toPgParams(sql), params);
  return res.rows;
}

export async function dbGet(sql, params = []) {
  const rows = await dbQuery(sql, params);
  return rows[0] || null;
}

export function isPg() {
  return db?.type === 'pg';
}
