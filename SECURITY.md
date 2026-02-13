# Security Policy

## Supported Versions

We provide security updates for the latest release. Please update to the newest version.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

If you discover a security issue, please email the maintainer privately (or use GitHub Security Advisories). Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to respond within 48 hours and will keep you updated on the fix and disclosure timeline.

## Security Model (Summary)

- **Zero-knowledge**: Server stores only encrypted data. We cannot decrypt user vaults.
- **Client-side crypto**: AES-256-GCM, PBKDF2-SHA256 (600k iterations for new users; 120k for legacy). Keys derived in browser only.
- **No recovery**: Lost master key = permanent data loss. By design.
- **Breach check**: Uses HIBP k-anonymity API. Passwords never leave the device.

## Known Limitations

- **HTTPS required in production**: authHash is sent on each vault request. Over HTTP it could be intercepted.
- **PBKDF2 iterations**: 600,000 for new users (OWASP). Legacy users: 120,000.
- **Rate limiting**: In-memory, per-endpoint (register: 5/min, login: 10/min, vault: 30/min). Resets on server restart. Distributed attacks could bypass.
- **Timing attacks**: Vault auth_hash comparison uses crypto.timingSafeEqual. Login uses DB lookup.
