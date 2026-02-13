# Security Policy

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

If you discover a security issue, please report it privately:

1. **Email** at stalain3@gmail.com (or use [GitHub Security Advisories](https://github.com/piyush-itis/dead-lock/security/advisories/new))
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours and will work with you on a fix and coordinated disclosure.

---

## Security Model

| Component | Implementation |
|-----------|----------------|
| **Encryption** | AES-256-GCM (authenticated) |
| **Key derivation** | PBKDF2-SHA256, 600k iterations (new users), per-user salt |
| **Zero-knowledge** | Server stores only encrypted blobs; cannot decrypt |
| **Breach check** | HIBP k-anonymity API; password never leaves device |
| **Auth** | Timing-safe compare, rate limits, CSRF protection |
| **Transport** | HTTPS required in production |

---

## Supported Versions

Security updates are provided for the **latest release**. Please stay up to date.

---

## Known Limitations

- **No recovery** — Lost master key means permanent data loss. By design.
- **HTTPS required** — Auth hash is sent on each request; HTTP is rejected in production.
- **Rate limiting** — In-memory; resets on restart. Distributed setups may need Redis.
- **No 2FA** — Not yet implemented; planned for future releases.
