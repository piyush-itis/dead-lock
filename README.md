# Deadlock

> A lightweight, open-source password manager. Your data is encrypted on your device before it ever reaches the server.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow)](https://buymeacoffee.com/piiyush)

---

## Why Deadlock?

- **Zero-knowledge** — The server stores only encrypted blobs. We never see your passwords. A compromised database is useless without your master key.
- **Client-side encryption** — AES-256-GCM. Keys never leave your browser.
- **12-word recovery phrase** — BIP39-style. Write it down; there is no account recovery.
- **Open source** — Audit the code. Trust, but verify.

---

## Quick Start

**Prerequisites:** Node.js 18+, a PostgreSQL database ([Neon](https://neon.tech) free tier works)

```bash
git clone https://github.com/piyush-itis/dead-lock.git
cd deadlock
npm install
```

Copy `.env.example` to `.env` and set your `DATABASE_URL`:

```bash
cp .env.example .env
# Edit .env with your PostgreSQL connection string
```

Run locally:

```bash
npm run dev
```

- **Frontend:** http://localhost:5173  
- **API:** http://localhost:3000

---

## Deploy

Deploy to Vercel, Railway, or Render in a few minutes. See **[DEPLOYMENT.md](DEPLOYMENT.md)** for step-by-step guides.

**Vercel** (recommended): Import the repo, add `DATABASE_URL` and `NODE_ENV=production`, deploy.

---

## Project Structure

```
deadlock/
├── client/         # Frontend (Vite, vanilla JS)
│   ├── main.js     # App logic
│   ├── crypto.js   # Encryption, key derivation
│   └── style.css
├── server/         # Express API
│   ├── index.js    # Routes, middleware
│   └── db.js       # PostgreSQL
├── api/            # Vercel serverless entry
└── vercel.json     # Build & rewrite config
```

---

## Security

| Layer | Implementation |
|-------|----------------|
| Encryption | AES-256-GCM |
| Key derivation | PBKDF2-SHA256, 600k iterations |
| Breach check | HIBP k-anonymity (password never sent) |
| Auth | Timing-safe comparison, rate limits, CSRF protection |

See **[SECURITY.md](SECURITY.md)** for vulnerability reporting and the full security model.

---

## Documentation

| Document | Description |
|----------|-------------|
| [DEPLOYMENT.md](DEPLOYMENT.md) | Deploy to Vercel, Railway, Render |
| [SECURITY.md](SECURITY.md) | Security policy & reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |

---

## Support

If Deadlock is useful to you, consider [buying me a coffee](https://buymeacoffee.com/piiyush).

---

## License

[MIT](LICENSE)

---
