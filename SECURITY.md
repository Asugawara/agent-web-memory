# Security Model

## What is protected in v0.1

- **Data location**: Research stays on the machine. There is no HTTP client in the codebase; no data leaves your computer.
- **File permissions**: The data directory is mode 0700 and the database file is mode 0600.
- **Redaction before storage**: API keys, secrets, private IPs, file paths, and email addresses are redacted before being written to disk.
- **Private hosts never stored**: URLs on private networks (`localhost`, `192.168.*`, `10.*`, etc.) are never recorded.
- **Injected text is bounded**: Notes are wrapped in XML tags, sanitized, capped at 2,200 characters, and labeled with their source and age.
- **Deletion is verifiable**: `awm forget` marks records for deletion, `awm purge` removes them from the database and all indices.
- **Quarantine for unreliable records**: Mark a note or URL as unreliable with `awm quarantine`; quarantined records are never injected.
- **Release integrity**: Release archives include SHA256 checksums. Install with `cargo install --locked` to verify dependencies.
- **No telemetry**: No metrics, counters, or analytics are collected or sent anywhere.

## What is *not* defended

- **Malicious host**: If someone gains access to your machine or user account, the database is a plain SQLite file, not encrypted at rest.
- **Malicious teammate**: In v0.2, when team sync is added, a teammate could push poisoned research. Bounds are the sanitiser, quarantine, and token revocation.
- **Prompt injection from web pages**: agent-web-memory shows excerpts from web pages to your agents. An agent already reads web pages; this tool bounds the extra exposure by capping notes and limiting context.

## v0.2 and later

Future versions may add:
- **Per-member tokens** stored as SHA-256 hashes and revocable
- **Server-side redaction** re-run before upload and rejected if secrets remain
- **TLS and reverse proxy** for team sync
- **Teammate note sanitization** when pulled locally

## Reporting a security issue

To report a vulnerability, please email security@example.invalid with the subject line `[SECURITY] agent-web-memory vulnerability`.

Do not open a public issue. We will acknowledge receipt within 48 hours and follow up with a fix timeline.
