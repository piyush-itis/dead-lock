# Security Audit Notes

Internal security review for open source release. Updated periodically.

---

## Implemented Safeguards

| Area | Implementation |
|------|----------------|
| Encryption | AES-256-GCM (authenticated) |
| Key derivation | PBKDF2-SHA256, 600k iterations, per-user salt |
| IV | 12 bytes random per encryption (GCM requirement) |
| Zero-knowledge | Server never receives plaintext |
| SQL | Parameterized queries only |
| Input validation | userId format, base64 format, length limits |
| Error handling | Generic messages; no stack traces |
| Security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Rate limiting | register: 5/min, login: 10/min, vault: 30/min |
| XSS | User content escaped (escapeHtml, escapeAttr) |
| Breach check | HIBP k-anonymity |
| HTTPS | Required in production |
| CORS | Restricted to ALLOWED_ORIGINS |
| PostgreSQL SSL | Certificate verification enabled |
| Session | 15 min inactivity logout |
| Timing-safe compare | crypto.timingSafeEqual for auth_hash |
| CSRF | X-Requested-With header required |
| Vault versioning | Last 5 versions; restore supported |
| Export/Import | Encrypted backup download/upload |

---

## Pre-Deploy Checklist

- [ ] HTTPS (nginx, Vercel, Railway)
- [ ] `NODE_ENV=production`
- [ ] `ALLOWED_ORIGINS` if frontend/API split
- [ ] `DATABASE_URL` with `sslmode=require` for Postgres
- [ ] `npm audit` — fix vulnerabilities
- [ ] Database backups enabled

---

## Recommendations

1. **Third-party audit** — Consider for high-traffic production use
2. **2FA** — Planned enhancement
3. **Distributed rate limiting** — Redis for multi-instance deployments
