# Security Audit Notes

Internal audit before open source release. Review periodically.

## ✅ What We Did Right

| Area | Implementation |
|------|----------------|
| **Encryption** | AES-256-GCM (authenticated) |
| **Key derivation** | PBKDF2-SHA256, 120k iterations, per-user salt |
| **IV** | 12 bytes, random per encryption (GCM requirement) |
| **Zero-knowledge** | Server never receives plaintext; only encrypted blobs |
| **SQL** | Parameterized queries only; no string interpolation |
| **Input validation** | userId format, base64 format, length limits |
| **Error handling** | Generic messages; no stack traces or internal details |
| **Security headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| **Rate limiting** | 30 req/min per IP |
| **XSS** | User content escaped (escapeHtml, escapeAttr) |
| **Breach check** | HIBP k-anonymity; password never sent |

## ⚠️ Addressed Before Release

| Issue | Fix |
|-------|-----|
| CSP blocked HIBP fetch | Added `connect-src https://api.pwnedpasswords.com` |
| b64encode stack overflow | Chunked encoding for large vaults |
| PBKDF2 below OWASP 2023 | Documented; consider Argon2 in future |

## 🔒 Recommendations for Deployers

1. **Use HTTPS** — Non-negotiable. authHash acts as a password equivalent.
2. **Run `npm audit`** — Fix any dependency vulnerabilities.
3. **Restrict /api/stats** — Add auth if you don’t want aggregate counts public.
4. **Database** — Ensure `data/` and `vault.db` have restricted file permissions.

## 📋 Open Source Checklist

- [x] LICENSE file (MIT)
- [x] SECURITY.md (vulnerability disclosure)
- [x] No hardcoded secrets
- [x] README documents security model
- [ ] Consider third-party security audit for production use
