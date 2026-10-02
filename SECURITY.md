# Security Model

## What is protected in v0.1

- **Data location**: Research stays on the machine. There is no HTTP client in the codebase; no data leaves your computer.
- **File permissions**: The data directory is mode 0700 and the database file and usage-limit sample files are mode 0600.
- **Redaction before storage**: API keys, secrets, private IPs, file paths, and email addresses are redacted before being written to disk.
- **Private hosts never stored**: URLs on private networks (`localhost`, `192.168.*`, `10.*`, etc.) are never recorded.
- **Injected text is bounded**: Notes are wrapped in XML tags, sanitized, capped at 9,500 characters, and labeled with their source and age. A PreToolUse deny (optional, shadow by default) shows the agent the same sanitised earlier result (up to 8,000 characters) in its reason text, capped at 9,500 characters.
- **Deletion is verifiable**: `awm forget` deletes the selected records immediately (tombstones stop them coming back); `awm purge` deletes by date or everything. Usage-limit samples expire after `quota.retention_days` (92 days by default, deleted by whole month); `awm purge --all` deletes them and `awm purge --before` leaves them to retention.
- **Quarantine for unreliable records**: Mark a note or URL as unreliable with `awm quarantine`; quarantined records are never injected.
- **Build integrity**: Builds are local for now: `scripts/install-local.sh` builds from source with `--locked`; a committed `Cargo.lock`, the default build has no network dependencies (`scripts/check.sh` no-network step); release builds add `sync` (an HTTP client used only by `awm sync`) and `serve`. No telemetry.
- **No telemetry**: No metrics, counters, or analytics are collected or sent anywhere.

## Team sync (optional, v0.2 and later)

When you run `awm team join`, team sync is end-to-end encrypted: the server holds only ciphertext and metadata. The operator sees handles and roles; counts and times of members, devices and invites; per stream the record count, padded sizes (256-byte buckets) and the hours records arrived; deletion counts; key epochs; and request logs (IP address, token prefix, path, status, latency). It does not learn which projects are shared: `repo_key` is a keyed hash inside the ciphertext. Encrypted independently with per-organisation keys; the server never sees plaintext research.

**Threats mitigated:** Malicious teammates are bounded by pull-side checks and quarantine (the same rules as your own notes). Leaked device tokens can be revoked and rotated. Leaked invites expire in 7 days and are single-use. Breaches of the server yield only ciphertext (recoverable only if the organisation key leaks separately).

**Explicitly not defended:** A teammate with a valid key can read everything the organisation shares — that is the product. A removed member's local copies stay on their machine. A removed member colluding with the server can forge authorship (key rotation mitigates). The server can withhold the newest records or delay delivery. Compromised clients can push secrets (known shapes are quarantined; others require per-project audits). Prompt injection inside notes is reduced by the same sanitiser as v0.1, not eliminated. For details, see `docs/plan-v3-team.md` §5.2 (threat model) and §5.3 (scope of defence).

## What is *not* defended (local mode, v0.1)

- **Malicious host**: If someone gains access to your machine or user account, the database is a plain SQLite file, not encrypted at rest.
- **Prompt injection from web pages**: agent-web-memory shows sanitised earlier results from web pages (up to 8,000 characters per note) to your agents. An agent already reads web pages; this tool bounds the extra exposure by capping notes and limiting context.

## v0.2 and later

Future versions may add:
- **Per-member tokens** stored as SHA-256 hashes and revocable
- **Server-side redaction** re-run before upload and rejected if secrets remain
- **TLS and reverse proxy** for team sync
- **Teammate note sanitization** when pulled locally

## Reporting a security issue

To report a vulnerability, please email security@example.invalid with the subject line `[SECURITY] agent-web-memory vulnerability`.

Do not open a public issue. We will acknowledge receipt within 48 hours and follow up with a fix timeline. GitHub private vulnerability reporting will replace this when the repository is public.
