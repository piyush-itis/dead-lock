/**
 * Vercel serverless catch-all for /api/*
 * Initializes DB and passes request to Express app
 */

import app from '../server/index.js';
import { initDb } from '../server/db.js';

let dbReady = null;

function ensureDb() {
  if (!dbReady) {
    dbReady = initDb();
  }
  return dbReady;
}

export default async function handler(req, res) {
  await ensureDb();
  return app(req, res);
}
