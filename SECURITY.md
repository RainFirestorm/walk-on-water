# Security Policy

## Overview

Be Still and Know takes privacy and security seriously. All user data is stored locally on the user's device, encrypted at rest, and never transmitted to any server.

---

## Security Architecture

### Encryption
All sensitive user data (notes, prayers, favorites, highlights) is encrypted using **AES-GCM 256-bit** encryption via the browser's native `SubtleCrypto` API.

- Encryption keys are generated on first launch and stored as non-extractable `CryptoKey` objects in **IndexedDB**
- Keys never touch `localStorage`, network requests, or source code
- Each write uses a unique random IV (Initialization Vector)
- Decryption failures return the safe fallback rather than crashing

### Content Security Policy
A strict CSP is enforced via meta tag:
```
default-src 'self'
script-src 'self' 'unsafe-inline'
style-src 'self' 'unsafe-inline'
connect-src 'self' https://bible-api.com https://bolls.life
font-src 'self'
img-src 'self' data: blob: https://images.pexels.com
worker-src 'self'
manifest-src 'self'
```

### Input Sanitization
- All API responses are passed through a DOM-based HTML sanitizer before rendering
- User-typed input is cleaned with `cleanInput()` which strips `<>` characters
- Word search results only allow `<mark>` tags through — all other HTML is stripped

### No External Dependencies
- Zero npm packages or third-party scripts loaded
- Google Fonts replaced with self-hosted WOFF2 files
- No analytics, tracking, or telemetry of any kind
- No cookies, no sessions, no accounts

### Additional Headers
```
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
```

---

## Data Storage

| Data | Storage | Encrypted |
|---|---|---|
| Saved verses | localStorage | ✅ AES-GCM |
| Notes & insights | localStorage | ✅ AES-GCM |
| Prayer journal | localStorage | ✅ AES-GCM |
| Highlights | localStorage | ✅ AES-GCM |
| Reading progress | localStorage | ✅ AES-GCM |
| Bookmarks | localStorage | ✅ AES-GCM |
| Encryption key | IndexedDB | N/A (non-extractable) |

**No data is ever sent off-device.**

---

## Third-Party Services

| Service | Data Sent | Purpose |
|---|---|---|
| bible-api.com | Verse reference only (no PII) | KJV verse text |
| bolls.life | Search query only (no PII) | Word search |
| Web Speech API | Verse text (processed locally) | Read-aloud |

---

## Supported Versions

| Version | Supported |
|---|---|
| Latest (main branch) | ✅ |

---

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not open a public GitHub issue**.

Instead, report it via:
- GitHub: Open a [private security advisory](https://github.com/RainFirestorm/walk-on-water/security/advisories/new)
- Email: Contact the repository owner directly

Please include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if known)

You can expect a response within **72 hours**. We appreciate responsible disclosure.

---

## Known Limitations

- `'unsafe-inline'` is currently required for `script-src` due to inline event handlers. Migrating to `addEventListener` throughout would allow removing this and strengthening the CSP further.
- localStorage encryption protects against data exfiltration but not against an attacker with full device access and DevTools open — this is an inherent limitation of client-side-only apps without a passphrase.
