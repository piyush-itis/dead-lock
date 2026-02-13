# Contributing to Deadlock

Thanks for your interest in contributing. Every contribution helps.

---

## Getting Started

1. **Fork** the repo and clone your fork.

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up your environment:**
   ```bash
   cp .env.example .env
   ```
   Add a `DATABASE_URL` (e.g. a free [Neon](https://neon.tech) database).

4. **Run the app:**
   ```bash
   npm run dev
   ```

---

## How to Contribute

### Bug reports

Open an issue with:

- A clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Your environment (Node version, OS)

### Feature requests

Open an issue describing the feature and why it would be useful. We’ll discuss before implementation.

### Code changes

1. **Branch** from `main` (e.g. `fix/login-error` or `feat/dark-mode`).

2. **Make your changes** — keep them focused and small when possible.

3. **Test** — run `npm run dev` and verify your changes work.

4. **Open a pull request** with:
   - A clear title and description
   - Reference to any related issues

We’ll review and may ask for changes. Once approved, we’ll merge.

---

## Security

**Do not open a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for how to report them privately.

---

## Code Style

- Use existing patterns in the codebase
- Prefer clarity over cleverness
- No new dependencies without discussion

---

## Questions?

Open a [Discussion](https://github.com/piyush-itis/deadlock/discussions) or an issue. We’re happy to help.
