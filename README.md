# Deadlock — Zero-Knowledge Password Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A lightweight, secure password manager where **all sensitive data is encrypted on your device** before it ever reaches the server. If the database is compromised, encrypted data is useless without your master key.

**Open source.** Audit the code. Trust, but verify.

## Security Model

- **12-word master key** — Generated from BIP39 wordlist (~128 bits entropy). Write it down; there is no recovery.
- **Client-side encryption** — AES-256-GCM. Passwords are encrypted in the browser, never sent in plaintext.
- **Zero-knowledge** — The server stores only encrypted blobs, salt, and auth hashes. It cannot decrypt your data.
- **Key derivation** — PBKDF2-SHA256 with 120,000 iterations.
- **Non-recoverable** — Lose your master key = lose access forever. No backdoors, no recovery options.

## Run Locally

```bash
npm install
npm run dev
```

- Frontend: http://localhost:5173  
- API proxy: /api → http://localhost:3000

## Production

```bash
npm run build
NODE_ENV=production npm start
```

Serves the built frontend from `dist/` and API on the same port.

## Data Stored (Server)

| Column       | Purpose                                |
|-------------|-----------------------------------------|
| `login_hash`| SHA256(master) — find account for login  |
| `salt`      | Random per-user — key derivation        |
| `auth_hash` | SHA256(master+salt) — vault access proof |
| `encrypted_data` | AES-GCM ciphertext — your vault   |

The server never sees your master key or plaintext passwords.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting. We welcome third-party audits.

**Requires HTTPS in production.** The auth hash is transmitted on each request; over HTTP it could be intercepted.
