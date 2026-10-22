# Security Model

## What is protected in v0.1

- **Data location**: Research stays on the machine unless you join a team (see "Team sync" below); the default build has no HTTP client.
- **File permissions**: The data directory is mode 0700 and the database file is mode 0600.
- **Redaction before storage**: API keys, secrets, private IPs, file paths, and email addresses are redacted before being written to disk.
- **Working directories, local only**: for your own records the database also keeps the working directory each call was made from and the repository checkout that holds it, as plain paths (table `cwd`, schema version 4), so `awm stats` can be split by repository and directory. They are not redacted (they are the names to show) and never leave the machine: a team record carries neither (`sync_payload.rs` `never_shared_fields_are_absent_from_the_json`). Records pulled from teammates have no `cwd` row. Backups taken while migrating (`awm.db.bak-v*`) hold the same paths once the database is at version 4. The `cwd` rows and the `cwd.walked.*` meta rows stay until `awm purge --all`; `awm forget` and `awm purge --before` do not remove them.
- **Private hosts never stored**: URLs on private networks (`localhost`, `192.168.*`, `10.*`, etc.) are never recorded.
- **Injected text is bounded**: Notes are wrapped in XML tags, sanitized, capped at 9,500 characters, and labeled with their source and age. A PreToolUse deny (on by default for repeated fetches of a URL and for repeated searches; `short_circuit.mode` and `short_circuit.query` switch them off) hands the agent the same sanitised earlier result (up to 8,000 characters) as `additionalContext` (a one-line reason carries no page text), capped at 9,500 characters.
- **Deletion is verifiable**: `awm forget` deletes the selected records immediately (tombstones stop them coming back); `awm purge` deletes by date or everything.
- **Quarantine for unreliable records**: Mark a note or URL as unreliable with `awm quarantine`; quarantined records are never injected.
- **Build integrity**: Release archives are built by `.github/workflows/release.yml` from a tagged commit with `--locked` and published with `SHA256SUMS`; `scripts/install.sh` checks the archive against it before installing it (the checksum does not protect against a compromised release); `scripts/install-local.sh` builds from source with `--locked`; a committed `Cargo.lock`, the default build has no network dependencies (`scripts/check.sh` no-network step); release builds add `sync` (an HTTP client used only by `awm sync`) and `serve`. No telemetry.
- **No telemetry**: No metrics, counters, or analytics are collected or sent anywhere.

## Team sync (optional, v0.2 and later)

When you run `awm team join`, team sync is end-to-end encrypted: the server holds only ciphertext and metadata. The operator sees handles and roles; counts and times of members, devices and invites; per stream the record count, padded sizes (256-byte buckets) and the hours records arrived; deletion counts; key epochs; and request logs (IP address, token prefix, path, status, latency). It does not learn which projects are shared: `repo_key` is a keyed hash inside the ciphertext. The server never sees plaintext research.

### Threat model

| Threat | What the attacker gets | Mitigation in v1 | Residual |
|---|---|---|---|
| Malicious teammate | Everything shared with the organisation (the feature); can push misleading or injected notes; cannot delete others' records unless admin | Pull-side checks and quarantine, the same wrapper and preamble as your own notes with a "teammate @handle" label, `team.mute`, admin deletion, removal with rotation, `flag` records, the audit log | A well-formed injection that passes the sanitiser, as for web text in v0.1 |
| Leaked device token | Push as that device; pull ciphertext; read handles; delete all of that member's shared records; rotate the token and lock the real device out; with an admin token: remove members, delete any record and shorten retention | Nothing decrypts without `team.key`; revocation; token rotation; rate limits; audit log | When `team.key` leaks with it (same machine): read access until removal and rotation |
| Leaked invite string | A join ahead of the invitee | Single use, 7-day expiry, handle fixed by the admin; the real invitee's join then fails (410) and they tell the admin; member joins need a manual approval with a fingerprint and code check by default (`team.auto_approve = devices`) | The window between the leak and the removal |
| Compromised server or host (self-hosting machine, cloud operator, backups) | The metadata listed above; the power to withhold, delay, delete or replay ciphertext | End-to-end encryption, associated-data binding, contiguous indexes that expose holes, policy versions inside the ciphertext that only increase, TLS, disk encryption at rest | Traffic analysis; withholding the newest records (tail truncation) cannot be detected; denial of service |
| Internet-facing server (self-hosted on public HTTPS without a VPN, and the cloud) | Anyone can reach `GET /v1/info` and `POST /v1/join`, send requests with guessed tokens, flood the server, or hit a pre-authentication bug in hyper, axum or our handlers; `/v1/info` shows that an awm server runs and its version | Only `info` and `join` answer without a token; device and invite tokens carry 32 random bytes and are looked up by SHA-256 hash, so guessing is infeasible and a copy of the database yields no usable token; invites are single use and expire in 7 days; per-IP limits (30 unauthenticated requests per minute, 10 joins per hour), per-token limits, a 2 MiB body cap and timeouts; TLS only, HSTS whenever the binary terminates TLS; safe defaults (no public listener without TLS, port 80 closed by default, file modes, no key files) and `awm serve check`; the server holds only ciphertext and metadata, so even a full compromise is the row above | Volumetric denial of service (no load balancer or Cloud Armor in v1); a server bug exploitable before authentication yields the compromised-server row |
| Cross-tenant leak (cloud) | Another organisation's data | `org_id` in every key, row-level security set per transaction from the organisation id inside the token before any lookup, an application role without `BYPASSRLS`, cross-tenant tests for every endpoint; a routing bug still yields ciphertext under another organisation's key | That tenant's metadata |
| Prompt injection through teammates' notes | Instructions inside a note | Pull-side checks, the same sanitiser and wrapper as v0.1, provenance on every note, red-team cases with teammate notes | Reduced, not eliminated (as v0.1) |
| A secret in a shared record | A credential reaches teammates | Pre-push check, URL check, pull-side check, `awm team audit`, link-only hosts, opt-in per project | Unknown secret shapes |
| Stolen member laptop | Local database and `team.key` | File modes 0600 (as v0.1); removal and rotation | A local compromise is not defended (see below) |
| The cloud owner's mailbox taken over | The owner's web session: plan, export (ciphertext), organisation deletion | Email-link sign-in only; deletion confirmed by a code sent by email; email notice and audit row on deletion | The hosted copy can be deleted; members keep local copies |
| Forged Stripe webhook | Entitlement changes | Signature verification, event-id dedup, state re-fetched from Stripe | None known |
| Account or card fraud | Chargebacks | Hosted Checkout, Stripe's fraud tools; no card data on our side | Fees |
| Supply chain (crates, base image) | Code on the server or clients | Committed `Cargo.lock`, `cargo deny` as a CI step, base image pinned by digest | An upstream compromise before it is found |

### Explicitly not defended

1. A teammate with a valid key reads everything the organisation shares; that is the product.
2. A compromised member machine.
3. A modified client that pushes secrets or hostile text (honest receivers quarantine known shapes only).
4. The server withholding the newest records, or forging deletions of any record (it can delete any record from every client); metadata and traffic analysis.
5. A removed member's local copies of what they already received.
6. A removed member colluding with the server, not closed in v1 (`docs/sync-v1-crypto.md` §11.1; the later fix is signed roster records); a member colluding with the server forging authorship.
7. Elimination of prompt injection.
8. Legal compulsion against a member or a customer organisation.

The key handling is specified in `docs/sync-v1-crypto.md` and the deletion guarantees in `docs/sync-v1.md`.

## What is *not* defended (local mode, v0.1)

- **Malicious host**: If someone gains access to your machine or user account, the database is a plain SQLite file, not encrypted at rest.
- **Prompt injection from web pages**: agent-web-memory shows sanitised earlier results from web pages (up to 8,000 characters per note) to your agents. An agent already reads web pages; this tool bounds the extra exposure by capping notes and limiting context.

## v0.2 and later

Future versions may add:
- **Server-side redaction** re-run before upload and rejected if secrets remain

## Reporting a security issue

To report a vulnerability, use GitHub private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**.

Do not open a public issue. We will acknowledge receipt within 48 hours and follow up with a fix timeline.
