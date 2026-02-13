# Security Audit Notes

Internal audit before open source release. Review periodically.

## ✅ Implemented

| Area | Implementation |
|------|----------------|
| **Encryption** | AES-256-GCM (authenticated) |
| **Key derivation** | PBKDF2-SHA256, 600k iterations (new users), per-user salt |
| **IV** | 12 bytes, random per encryption (GCM requirement) |
| **Zero-knowledge** | Server never receives plaintext; only encrypted blobs |
| **SQL** | Parameterized queries only; no string interpolation |
| **Input validation** | userId format, base64 format, length limits |
| **Error handling** | Generic messages; no stack traces or internal details |
| **Security headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Rate limiting** | Per-endpoint (register: 5/min, login: 10/min, vault: 30/min) |
| **XSS** | User content escaped (escapeHtml, escapeAttr) |
| **Breach check** | HIBP k-anonymity; password never sent |
| **HTTPS** | Required in production; rejects HTTP |
| **CORS** | Restricted to ALLOWED_ORIGINS in production |
| **PostgreSQL SSL** | Certificate verification enabled |
| **Session expiry** | 15 min inactivity logout with warning |
| **Timing-safe compare** | crypto.timingSafeEqual for auth_hash |
| **CSRF** | X-Requested-With header required for state-changing requests |
| **Auth logging** | Failed login/vault attempts logged in production |
| **Vault versioning** | Last 5 versions stored; restore supported |
| **Export/Import** | Encrypted backup download/upload |

## 📋 Pre-Launch Checklist

Before deploying for others:

- [ ] **HTTPS** — Deploy behind TLS (nginx, Vercel, Railway)
- [ ] **Environment** — Set `NODE_ENV=production`
- [ ] **CORS** — Set `ALLOWED_ORIGINS` if frontend/API are split
- [ ] **Database** — `DATABASE_URL` with `sslmode=verify-full` for Postgres
- [ ] **npm audit** — Run `npm audit` and fix any vulnerabilities
- [ ] **File permissions** — Restrict `data/` and SQLite file if used
- [ ] **Backups** — Ensure DB backups; vault data is encrypted

## 🔒 Recommendations

1. **Third-party audit** — For production use with many users, consider a professional security audit
2. **2FA** — Future enhancement; not yet implemented
3. **Distributed rate limiting** — Current in-memory; use Redis for multi-instance deployments

## ⚠️ Known Limitations

- **In-memory rate limiting** — Resets on server restart; distributed attacks could bypass
- **Session state** — No server-side session; authHash in client memory
- **User enumeration** — Login reveals whether loginHash exists (timing)
