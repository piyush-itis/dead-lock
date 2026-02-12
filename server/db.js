/**
 * Database layer - PostgreSQL (hosted) or SQLite (local)
 * Set DATABASE_URL for hosted PostgreSQL. Leave unset for local SQLite.
 */

import pg from 'pg';
import Database from 'better-sqlite3';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

let db;

export async function initDb() {
  const url = process.env.DATABASE_URL;
  if (url) {
    const pool = new pg.Pool({
      connectionString: url,
      ssl: url.includes('localhost') ? false : { rejectUnauthorized: false },
    });
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        login_hash TEXT NOT NULL UNIQUE,
        salt TEXT NOT NULL,
        auth_hash TEXT NOT NULL,
        created_at BIGINT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS vaults (
        user_id TEXT PRIMARY KEY REFERENCES users(id),
        encrypted_data TEXT NOT NULL,
        updated_at BIGINT NOT NULL
      );
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_login ON users(login_hash)`);
    db = { type: 'pg', pool };
  } else {
    const dataDir = join(__dirname, '../data');
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    const sqlite = new Database(join(__dirname, '../data/vault.db'));
    sqlite.exec(`
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
    db = { type: 'sqlite', sqlite };
  }
  return db;
}

function toPgParams(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

export async function dbQuery(sql, params = []) {
  if (db.type === 'pg') {
    const res = await db.pool.query(toPgParams(sql), params);
    return res.rows;
  } else {
    const stmt = db.sqlite.prepare(sql);
    if (/^\s*SELECT/i.test(sql)) {
      return params.length ? stmt.all(...params) : stmt.all();
    }
    stmt.run(...params);
    return [];
  }
}

export async function dbGet(sql, params = []) {
  const rows = await dbQuery(sql, params);
  return rows[0] || null;
}

export function isPg() {
  return db?.type === 'pg';
}
