# awm sync protocol v1

Status: frozen for v0.2 by TM2 (2026-10-02). Source: `docs/plan-v3-team.md` §4.3 (with §3.6, §3.7, §3.9.5, §4.10, §5.1) and the protocol findings of `docs/reports/RV8-team.md`. The serde types are `crates/awm-proto/src/wire.rs`; the JSON Schema snapshots are `crates/awm-proto/schemas/v1/`; the fixtures are `crates/awm-proto/tests/fixtures/v1/`; `crates/awm-proto/tests/wire_snapshots.rs` ties the three together (§17). Where this document and the plan differ, this document is the protocol and `docs/reports/TM2.md` lists the differences.

The record envelope's cryptography (seal, open, wraps, MACs) is TM3's; this document names every field that envelope and those MACs must bind (§5) and the envelope's outer structure the server checks (§9.1).

## Contents

1. Conventions
2. Transport and headers
3. Identifiers and tokens
4. What the server stores and sees
5. Bindings: what the server could swap or forge
6. Endpoints
7. Authorisation
8. Streams and cursors
9. Push
10. Deletion
11. Restore and `generation`
12. Limits and rate limits
13. Errors
14. Versioning and compatibility
15. Record plaintexts
16. Worked examples
17. Fixtures and schemas
18. RV8-team findings and where they are answered

## 1. Conventions

- Bodies are UTF-8 JSON with `Content-Type: application/json`, except `GET /v1/export` (§6). Requests are not compressed: a `Content-Encoding` other than `identity` gets 400 `malformed`.
- Optional fields are omitted when absent and never sent as `null`; a receiver treats `null` like an absent optional field.
- Bytes (blobs, public keys, MACs, wraps) are unpadded base64url (RFC 4648 §5). Padding and non-zero trailing bits are refused, so each value has one encoding.
- Ids are UUIDs in canonical form: 36 characters, lower-case, hyphenated (`6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b`). Upper case, braces, URNs and the 32-character form are refused.
- Times are integer Unix seconds (UTC). An "hour" field is rounded down to a multiple of 3,600.
- A stream index (`idx`) is an integer from 0. A head is the highest index of a stream, or -1 for an empty stream; the next index to write is always `head + 1`. All indexes stay below 2^53.
- Handles are 1-24 characters of `[a-z0-9_-]`. Tags are `[a-z][a-z0-9_]{0,15}`.
- Query strings (`GET /v1/records`, `/v1/deletions`, `/v1/audit`) use the field names of their schema (`records.query`, `deletions.query`, `audit.query`) as parameters; the fixtures show them as JSON objects.

## 2. Transport and headers

### 2.1 Transport

HTTPS only (plan-v3-team §5.4); a client refuses `http://` other than loopback. Every path starts with `/v1/`. `GET /healthz` (200 or 503, no body details) is outside the protocol.

### 2.2 Request headers

- `Authorization: Bearer <device token>` on every endpoint except `GET /v1/info`, `POST /v1/bootstrap` and `POST /v1/join`, which authenticate by the token in their body (or not at all for `info`).
- `Awm-Client` on every `/v1/` request; optional on `GET /v1/info`. Grammar (one space between tokens, at most 256 bytes):

  ```text
  awm-client = "awm/" version " proto/" number " redact/" number *( " " ext )
  version    = core [ "-" pre ]          ; core = MAJOR "." MINOR "." PATCH, each 0 or 1-5 digits without a leading zero
  pre        = 1*32( ALPHA / DIGIT / "." / "-" )
  number     = "0" / ( %x31-39 *5DIGIT ) ; proto is at least 1
  ext        = name "/" value            ; name = 1*( lower-case / DIGIT / "-" ), value = 1*( %x21-7E )
  ```

  `awm/0.2.0 proto/1 redact/3` and `awm/0.3.0-rc.1 proto/2 redact/4 os/macos` are valid. The three named tokens come first and in this order; extension tokens are ignored by a v1 server. Build metadata (`+...`) is refused. A missing or malformed header gets 400 `bad_client_header`. `proto` is the highest protocol version the client speaks; the request path, not the header, selects the version served (§14.5). `redact` is the client's `redact::VERSION`; the server logs it and does not compare it.

### 2.3 `min_client` and 426

The organisation's `min_client` is a server setting (`GET`, `PUT /v1/org/settings`; RV8-team M26), raised only, never below the server release's floor (`GET /v1/info` `min_client`). A request whose `Awm-Client` version is below the organisation's `min_client` by semantic-versioning precedence (a pre-release sorts below its release: `0.2.1-rc.1` < `0.2.1`) gets **426 `client_too_old`** with `min_client` in the body, on exactly these endpoints, the ones that add content or devices:

- `POST /v1/records`, except a request whose items are all `roster` items or markers (RVT1 m5)
- `POST /v1/join`
- `POST /v1/bootstrap` (against the release floor; there is no organisation yet)

Everything else continues for an old client, so it can still pull, delete its records, rotate its token, leave, and (as an admin) remove members and rotate keys. The exemption lets such a client publish the roster revocations and epoch records that go with a removal or rotation, and fill indexes with markers after a 410. `GET /v1/info` is cached by the client for an hour (plan-v3-team §4.6 step 2); the organisation's value is in every `GET /v1/status`.

### 2.4 Response headers

`Retry-After` (seconds) on 429 and 503, with the same value as `retry_after_s` in the body. `Cache-Control: max-age=3600` on `GET /v1/info`; `Cache-Control: no-store` on everything else. `Strict-Transport-Security` whenever the binary or the cloud terminates TLS (plan-v3-team §3.9.2).

## 3. Identifiers and tokens

### 3.1 Ids

| id | made by | when | notes |
|---|---|---|---|
| `org_id` | the first admin's client, with `K_0`: derived from the first device's id and public key and a random nonce (`docs/sync-v1-crypto.md` §2, RVT1 B1) | `awm team create` (`POST /v1/bootstrap`) or `awm cloud login` | never changes: it is in every record's associated data (§5.1); an export and import keep it; it is the `{org}` part of every token (RV8-team M3); the genesis roster record must hash to it |
| `member_id` | the server, random UUIDv4 | bootstrap, or a member join | survives device loss: a device invite for an existing member keeps it (RV8-team M6) |
| `device_id` | the joining client, random UUIDv4 | bootstrap or join | a second device with an existing id gets 409 `device_conflict` |
| record `id` | the writing client, random UUIDv4 | before the push (`event.sync_id`) | unique per organisation, also against the deletion stream (§9, §10.3) |
| `invite_id` | the server | `POST /v1/invites` | |
| `generation` | the server, random UUIDv4 | `awm serve init`, and every `awm serve restore` (§11) | |

### 3.2 Tokens

| token | form | carried in | stored by the server |
|---|---|---|---|
| device | `awm_t_{org}_{secret}` | `Authorization` | SHA-256 hex, looked up by hash |
| invite (the server's half of an invite) | `awm_i_{org}_{secret}` | `POST /v1/join` body | SHA-256 hex |
| bootstrap | `awm_b_{secret}` | `POST /v1/bootstrap` body | SHA-256 hex (path A: `AWM_BOOTSTRAP_SHA256`, plan-v3-team §4.8.1) |

`{org}` is the canonical 36-character `org_id`; `{secret}` is 32 random bytes as 43 base64url characters. Because both parts have a fixed length, the `_` and `-` that base64url allows in the secret never make the split ambiguous: a parser takes the prefix, 36 characters, one `_`, then exactly 43 characters. The server reads `{org}` before any lookup (the cloud sets row-level security from it, plan-v3-team §4.2) and answers 401 `unauthenticated` when the organisation is not one it serves, when the hash is unknown, or when the token, device or member is revoked. Tokens are shown once and never logged; request logs keep the organisation id and the first 6 characters of the secret (plan-v3-team §4.3.1 "token prefix"). The invite string that travels between people is `awmi1_` + base64url(org ‖ S ‖ lp(invite id) ‖ lp(invite token) ‖ lp(handle)) (`docs/sync-v1-crypto.md` §4.1); only the invite id and invite token reach the server, never `S` (plan-v3-team §5.1). The joiner checks that the invite string's `org` equals the `{org}` of its invite token (TM12).

## 4. What the server stores and sees

Per record: the stream (member, device, tag), `idx`, `id`, `epoch`, the ciphertext blob or a deletion marker, the blob's size (a multiple of the 256-byte padding bucket plus 41 bytes, §9.1) and `received_at` rounded down to the hour. Per organisation: handles and roles; member, device and invite counts and times; each device's public key, approval state and last day seen; the join MACs (which it cannot verify, lacking `S`); the wraps and their authenticators; key epochs and their times; the deletion stream; the audit log; the settings of §10.4; `generation`. Request logs (IP address, token prefix, path, status, latency) are kept 14 days (plan-v3-team §4.3.1, assumption).

What the server can infer from that (RV8-team M14): because pushes follow captures, the times of pushes and of the request-log lines reveal each member's web-research activity to about a minute (to `team.push_delay_s` with its jitter when a member sets it); the size bucket tells `link` records from `full` ones; per-stream counts tell how much each device shares. It never sees record plaintext, keys, the invite secret `S`, or members' emails.

## 5. Bindings: what the server could swap or forge

### 5.1 The record envelope's associated data (TM3 binds it)

`AD = "awm1" ‖ org ‖ member ‖ device ‖ tag ‖ idx ‖ record id ‖ epoch` (plan-v3-team §5.1). Every record field the server stores or relays, and what binds it:

| field on the wire | where | AD-bound | if the server swaps or forges it |
|---|---|---|---|
| `org_id` | token, every AD | **yes** | decryption fails at every reader |
| `member` | `StreamHead`, `StreamRecords`, cursor | **yes** | moving a record into another member's stream fails decryption |
| `device` | same | **yes** | moving it to another device's stream fails decryption |
| `tag` | push item, `StreamHead`, `StreamRecords` | **yes** | relabelling `rec` as `policy` or `roster` fails decryption |
| `idx` | push item, pulled item | **yes** | reordering or replaying at another index fails decryption |
| `id` (record id) | push item, pulled item | **yes** | a record served under another id fails decryption, so deletion entries and tombstones (`team:{id}`) always name the record that was decrypted |
| `epoch` | push item, pulled item | **yes** | serving a record under another epoch's key fails decryption |
| `blob` | push item, pulled item | AEAD ciphertext | any change fails authentication |
| `schema` and every plaintext field (§15) | inside the blob | ciphertext | cannot be read or changed |

TM3 must encode the AD so that no two field tuples produce the same bytes (fixed-length ids and integers, or length prefixes) and must use the 16 bytes or the canonical text of each id consistently; `wire::Id::as_bytes` gives the bytes.

### 5.2 Server-supplied values that are not bound, and how clients treat them

| value | the server can | client rule |
|---|---|---|
| `received_at` on pulled records | lie about receipt time | used only to clamp a teammate's `created_at` to ±1 day of it (plan-v3-team §4.5, RVT0 m8); never for ordering or retention decisions |
| deletion markers (`deleted: true`) and deletion-stream entries | forge the deletion of any record | not defended (plan-v3-team §5.3 item 4); the reader deletes and tombstones |
| heads, `more`, missing records, empty pages | withhold the newest records; hold a stream at a gap | not detectable at the tail (§5.2 of the plan); a gap stops that stream (§8.3) and `awm doctor` shows it |
| `generation` | fake a restore | harmless: re-seeding is idempotent (§11) |
| `current_epoch`, `rotation_needed` | claim an old epoch, or withhold the rotation flag | a client never encrypts under an epoch lower than the highest it holds a verified wrap for; an admin client also rotates when its own roster holds a revocation newer than the current epoch's roster entry, whatever `rotation_needed` says (TM12). A rotation dates its `epoch` entry `created_at = max(now, latest applied revoked_at + 1)`, so every revocation it covers is strictly older than the entry and "newer" is `revoked_at >= created_at`, also when the revoking admin's clock runs ahead (RVT3 F6). A client clamps a roster date more than a day ahead of its own clock to that bound (a signed `revoked_at` of `i64::MAX` cannot make every admin rotate on every run), and a revocation dated at the bound decides nothing against an existing `epoch` entry (RVT3v V1) |
| `GET /v1/members`: handles, roles, devices, public keys, `active` | add devices, change handles or roles | handles and device keys are taken from the verified roster (§5.3); a device without a verified roster entry is `unverified` and never receives a wrap (RV8-team X1); a role shown by the server only decides what the server will accept from that member |
| `pending` devices (`device_pubkey`, `handle`, `invite_id`, `join_mac`) | substitute a key | the approver recomputes the join MAC with `S`; a mismatch is not approved. A MAC that verifies proves only that the joiner holds the invite string, which may have leaked, so by default (`team.auto_approve = none`) every join, a member's new device included, also waits for `awm team approve [HANDLE] --code N` on an existing device, after the joining device printed its 6-digit code and fingerprint; `devices` (own new devices) and `all` (every join) are explicit opt-ins that skip the code, and `awm config set` warns once that a leaked string is then let in (RVT2 m3) |
| roster records (withheld, or lost in a restore) | withhold approvals or revocations | clients keep every roster record they have seen (`roster_record`) and verify over those together with the server's; a revocation or removal never goes back (§11, RVT1 M3) |
| `member_id` and `device_token` in join and bootstrap responses | assign another member id | the joining device checks, before its first push, that a verified roster `approve` entry names its device id with the member id and handle of its join response (`keys::Roster::check_own_approval`), else it refuses to push; the approver takes `kind`, `handle` and, for device invites, the member id from its own invite record (never from `pending`), and refuses a `member` approval whose `member_id` its verified roster already holds (`keys::approve`; RVT1 M2) |
| `StreamRecords.member`, `.device`, `.tag` in pull and records responses | answer cursor X with the records of stream Y | a reader matches each entry to a cursor it sent, builds the AD and advances the head from that cursor, and ignores streams it did not ask for (RVT1 m4) |
| `status.org_id`, `.member_id`, `.device_id`, `.role` | claim other ids or another role | the client uses the ids stored at join and the roster's role, never these |
| `pending[].kind`, `.member_id` | relabel a device join as a member join, or name another member | the approver takes kind, handle and member id from its own invite record (row above); an `Unknown` kind is never approved |
| `deletions.oldest` | set it above `deletion_head + 1` on every run | a full reconcile at most once per 24 h, with an `awm doctor` notice |
| deletion entries and 410 `ids` naming the member's **own** `origin = 'local'` records | delete the author's local history | not defended, as for teammates' rows (plan-v3-team §5.3 item 4); TM11 decides between deleting the local row and keeping it with `shareable = 'never'`, and records the choice here |
| `settings` (`retention_days`, `min_client`, `max_members`) | shorten retention, raise `min_client` | `retention_days` is ≥ 30 and a decrease shows for 7 days before it applies (§10.4); `min_client` only blocks pushes and joins |
| `restore_pending`, error bodies | refuse service | denial of service is not defended |

### 5.3 Fields bound by MACs and authenticators (TM3)

- `join_mac` = HMAC-SHA256(HKDF(S, "awm join v1"), "awm join v1" ‖ org ‖ lp(invite id) ‖ lp(handle) ‖ device id ‖ device public key) (`docs/sync-v1-crypto.md` §4.2); the invite id is its canonical 36-character text. A pending device's key, id and handle cannot be substituted.
- An approval wrap's `auth` = HMAC-SHA256(HKDF(S, "awm wrap-auth v1"), "awm wrap-auth v1" ‖ 0x01 ‖ org ‖ device id ‖ epoch ‖ device public key ‖ approver device (`created_by`) ‖ len ‖ wrap) (crypto §5). The server cannot move a wrap to another device or epoch or slip the device a key it made. It does not bind the member id; the roster does (§5.2).
- A rotation wrap's `auth` is the same transcript with mode 0x02 under HKDF(K_{e-1}, "awm rot-auth v1") (`epoch` the new epoch).
- `roster` records are records: their AD (§5.1) binds the approving device's stream and index; their plaintext (§15.5) binds member id, handle, role, device id and public key; the genesis entry hashes to `org_id` (crypto §7).

## 6. Endpoints

Each request and response body has a schema `schemas/v1/{name}.schema.json` and at least one fixture `tests/fixtures/v1/{name}[.variant].json`; "none" means no body.

| method and path | caller | request | response (2xx) | schema names | notes |
|---|---|---|---|---|---|
| `GET /v1/info` | anyone | none | protocols, server version, `cloud`, `generation`, release-floor `min_client`, limits, features | `info.response` | cacheable 1 h; `generation` there is informational, the re-seed reads `GET /v1/status` |
| `POST /v1/bootstrap` | holder of the bootstrap token | bootstrap token, `org_id`, handle, device id, device public key | `org_id`, member id, device id, device token (once), role `admin` | `bootstrap.request`, `bootstrap.response` | single use within 24 h: a used or expired token, or an organisation that already has an admin, gets 410 `invite_gone`; an `org_id` the cloud already holds gets 409 `id_conflict`; the device is approved at once and writes its `genesis` roster record (index 0 of its `roster` stream, epoch 0) next |
| `POST /v1/join` | holder of an invite | invite id and token, handle (must equal the invite's), device id, device public key, join MAC | `org_id`, member id, device id, device token (once), `pending: true` | `join.request`, `join.response` | 410 `invite_gone` when used or expired (a second join with the same invite included); 400 `invalid_value` (`/handle`) when the handle differs; 10 per hour per IP |
| `GET /v1/status` | member (also a pending device, reduced) | none | `generation`, ids, role, own `approved`, `current_epoch`, `rotation_needed`, `restore_pending`, settings, every stream's head, deletion-stream `head` and `oldest`, pending devices | `status.response` | the cursor source; one per sync run; a pending device gets the reduced status below (RVT2 M2) |
| `POST /v1/records` | member: own device's `rec`, `flag`, `stats`, `roster`; admin: also `policy` | 1-100 items `{tag, idx, id, epoch, blob}` or `{tag, idx, id, deleted: true}`, ≤ 1.5 MiB encoded | new heads of the touched streams, `accepted`, `replayed` | `records.push.request`, `records.push.response` | atomic per request; checks and idempotency in §9 |
| `GET /v1/records` | member | `member`, `device`, `tag`, `from`, `limit` ≤ 500 | the stream's `head` and ascending `{idx, id, epoch, blob, received_at}` or `{idx, id, deleted: true}` | `records.query`, `records.response` | one stream |
| `POST /v1/pull` | member | 1-1,000 cursors `{member, device, tag, from}`, `limit` 1-500 records in total | per cursor served, in request order: the stream's `head` and its records; `more` | `pull.request`, `pull.response` | any number of streams in one request (RV8-team M2); §8.4 |
| `GET /v1/deletions` | member | `from`, `limit` ≤ 5,000 | `head`, `oldest`, ascending `{idx, record_id}` | `deletions.query`, `deletions.response` | server-written, contiguous; §8.5 |
| `POST /v1/delete` | member: own member's records; admin: any | exactly one of `{ids}` (1-1,000), `{all_mine: true}`, `{member}` (admin) | `deleted`, `already` | `delete.request`, `delete.response` | idempotent by record id; §10 |
| `GET /v1/members` | member | none | per member: id, handle, role, active, devices (id, public key, approved, revoked) | `members.response` | no emails; unverified until the roster names them (§5.2) |
| `POST /v1/invites` | admin: any `kind`, including `kind: device` for another member; member: `kind: device` for themselves | `kind`, `handle`, `role` (member invites only), `expires_days` 1-30 (default 7) | invite id, invite token (once), `expires_at` | `invites.request`, `invites.response` | the secret `S` is generated and kept by the creating device; a member invite beyond `max_members` gets 403 `forbidden`, beyond the cloud plan 402 (§10.5) |
| `DELETE /v1/invites/{id}` | admin, or the invite's creator | none | 204 | | idempotent; 404 for an unknown id |
| `POST /v1/devices/{id}/approve` | the invite's creating member (the device holding `S` makes valid authenticators) | the wraps of every epoch the device lacks, each `{epoch, wrap, auth}` | 204 | `approve.request` | idempotent by (device, epoch): a wrap for a (device, epoch) already stored is ignored, the first one stays; 400 `invalid_value` (`/wraps`) when an epoch from 0 to current is still missing after the request; cloud: a member approval beyond the plan gets 402 (§10.5) |
| `POST /v1/devices/{id}/revoke` | admin: any device; member: own devices | none | 204 | | revokes the device's token; sets `rotation_needed`; idempotent; the revoking client appends a `roster` revocation (§15.5) |
| `POST /v1/members/{id}/remove` | admin | `delete_records` (optional, default false) | 204 | `members.remove.request` | revokes every token of the member, sets `rotation_needed`; also revokes the devices still pending on the member's invites, and the members those invites created that have no approved device, since only the invite's creator could approve them (RVT2 m2); with `delete_records` all their records go to the deletion stream; 409 `last_admin` for the only admin |
| `POST /v1/members/{id}/role` | admin; cloud owner from the web page | `role` | 204 | `members.role.request` | 409 `last_admin` when it would leave no admin |
| `GET /v1/keys` | member (also a pending device) | none | `current_epoch`, `rotation_needed`, the calling device's wraps with `created_by` | `keys.response` | |
| `POST /v1/keys/rotate` | admin | `epoch` = current + 1, one wrap per device | 204 | `keys.rotate.request` | 409 `epoch_conflict` (with `current_epoch`) otherwise; 400 `invalid_value` for a device the server does not list or has revoked; clears `rotation_needed`; from then on pushes under older epochs get 409 `stale_epoch` |
| `POST /v1/token/rotate` | member | none | the new device token (once) | `token.rotate.response` | the old token stops at once |
| `GET /v1/audit` | admin | `from`, `limit` ≤ 1,000 | `head`, rows `{idx, at, actor?, action, target?, detail?}` | `audit.query`, `audit.response` | never record content |
| `GET /v1/org/settings` | member | none | `retention_days`, `min_client`, `max_members`, `pending_retention?` | `settings.response` | the only settings the server reads (RV8-team M26) |
| `PUT /v1/org/settings` | admin; cloud owner (`retention_days`, `max_members`) | any of `retention_days` (≥ 30), `min_client` (raise only), `max_members`, `cancel_pending_retention` | the settings after the change | `settings.put.request`, `settings.response` | §10.4 |
| `POST /v1/restore/complete` | admin | `generation` (the current one) | 204 | `restore.complete.request` | ends `restore_pending` (§11); idempotent; 400 `invalid_value` (`/generation`) for another generation |
| `GET /v1/export` | admin; cloud owner from the web page | none | the organisation as the canonical SQLite file, `Content-Type: application/vnd.sqlite3`, streamed | | moving between deployments (plan-v3-team §3.1); not JSON, no fixture |

A pending (not yet approved) device may call only `GET /v1/info`, `GET /v1/status` and `GET /v1/keys`; everything else gets 403 `not_approved`.

**The status of a pending device is reduced** (RVT2 M2). Whoever holds a leaked invite string can join and get a pending token, so before an approval the server shows nothing about other members, their streams or other joins. The response keeps the `status.response` schema (every field is present) with only these real values: `generation`, `org_id`, the caller's own `member_id`, `device_id` and `role`, `approved: false`, `current_epoch`, `settings.min_client`, and in `pending` the caller's own entry only. The rest is empty or neutral: `streams: []`, `deletions: {head: -1, oldest: 0}`, `rotation_needed` and `restore_pending` false, `settings.retention_days` 30 (the minimum), `settings.max_members` 0 and no `pending_retention`. A client reads nothing but `approved` and `min_client` until it is approved; once approved, the same device gets the full status. The server also writes at most one `authz.refused` audit row per pending device per hour for its `not_approved` refusals, so a device that polls while it waits does not grow the audit log (RVT2 m1). Every endpoint not listed, and every path under another version prefix that the server does not serve, gets 404 `not_found`.

## 7. Authorisation

| action | anonymous | pending device | member | admin | cloud owner (web session) |
|---|---|---|---|---|---|
| `info` | yes | yes | yes | yes | yes |
| bootstrap | with a valid bootstrap token | - | - | - | through the device flow (TM20) |
| join | with a valid invite | - | - | - | - |
| own status and own keys | no | yes | yes | yes | no |
| pull records and deletions, members | no | no | yes | yes | no (an owner who is also a member uses a member token) |
| push to own device's `rec`, `flag`, `stats` | no | no | yes | yes | no |
| push to own device's `roster` | no | no | own approvals of own devices, own device revocations | yes | no |
| push `policy` | no | no | no | yes | no |
| delete own member's records (any device of the member) | no | no | yes | yes | no |
| delete any record; remove a member; invite and approve new members; rotate keys; write settings; read the audit log; complete a restore | no | no | no | yes | settings (`retention_days`, `max_members`) only |
| device invite, approval and revocation for oneself | no | no | yes | yes | no |
| device invite and revocation for another member | no | no | no | yes | no |
| token rotation for the calling device | no | no | yes | yes | no |
| export | no | no | no | yes | yes |
| delete the organisation | no | no | no | no | yes |
| promote a member to admin | no | no | no | yes | yes (recovery when no admin is left) |

A push to a stream of another device, or to a tag the caller may not write, gets 403 `forbidden` for the whole request. A tag the server does not know gets 400 `invalid_value` (`/records/{i}/tag`).

## 8. Streams and cursors

### 8.1 Streams and tags

A stream is (member, device, tag). v1 tags: `rec` (research records), `flag` (pull-side and review flags), `stats` (daily totals, opt-in), `policy` (admin settings, encrypted) and `roster` (approvals, revocations and epoch membership, written by the approving device; plan-v3-team §5.1). Each device writes only its own streams; the server binds member and device to the token, so a push names only `tag` and `idx`. A stream exists once it holds index 0; `GET /v1/status` lists every existing stream, including those of removed members whose records were kept.

### 8.2 Indexes and markers

- Indexes are contiguous from 0 and assigned by the writing client; the server stores an item only at `idx = head + 1` (§9.1).
- A deleted record keeps its index as a marker `{idx, id, deleted: true}`: the blob is gone, the id stays, so a reader can tell "deleted" from "not yet arrived", and a re-pull never brings the blob back.
- Per-stream indexes avoid the `since=` cursor bug in which a lower sequence number commits after a higher one has been read (possible in Postgres, not in single-writer SQLite): a `PgStore` writer holds the stream's advisory lock for `idx = head + 1` (plan-v3-team §4.2), so a reader of one stream never sees index `k + 1` before `k`.

### 8.3 The reader's cursor

- The client keeps `sync_stream.head_idx` per stream (-1 when it has applied nothing), reads from `head_idx + 1`, applies in index order and advances only over contiguous indexes. A missing index (a response that skips one) stops that stream until the next run; nothing after the gap is applied.
- A record that fails decryption, fails the pull-side checks or has a higher `schema` (§14.4) still advances the cursor: it is dropped, quarantined or skipped as plan-v3-team §4.5 says, never retried by index.
- Unknown tags: a client does not decrypt them but keeps and advances their cursors like any other (§14.3).

### 8.4 `POST /v1/pull`

The client sends a cursor for every stream whose head in `GET /v1/status` is above its own head. The server serves cursors in request order: for each, the records from `from` upward to the stream's head at the time it reads that stream, until `limit` records in total have been returned or the response would exceed 8 MiB encoded. It answers every cursor it reached, each with the stream's `head` at read time, and sets `more: true` when any cursor served got fewer records than `head - from + 1` or when cursors were left unserved (they are absent from `streams`). The client then sends a new request with `from` = last applied index + 1 for the streams that are not complete. A cursor whose `from` is above the head returns no records and the head; a cursor for a stream that does not exist returns `head: -1`. Duplicate cursors (same member, device and tag) get 400 `invalid_value` (`/cursors`). More than 1,000 cursors get 413 `too_large` (`pull_cursors`); a client with more streams splits them across requests.

Each stream's records are read in one consistent snapshot, so they are contiguous and ascending; different streams may be read at different instants, which the per-stream cursor tolerates.

### 8.5 The deletion stream

- Written by the server only, under the per-organisation write lock (`PgStore`: one advisory lock per organisation), so it is contiguous too. Each entry `{idx, record_id}` names a record id; it does not name the stream.
- Entries are kept for `retention_days` + 30 days. `GET /v1/status` and `GET /v1/deletions` give `head` (-1 when empty) and `oldest` (the lowest kept index; `head + 1` when none is kept).
- The client keeps `sync_state.deletion_head` (-1 initially). If `oldest > deletion_head + 1`, entries it has not applied are gone, and it runs a full reconcile (plan-v3-team §3.7): it drops its team rows in 25-row transactions, re-pulls every stream from 0 and then reads the deletion stream from `oldest`.
- For every entry it applies, the client writes `tombstone('tool_use_id', 'team:' || record_id)` whether or not the row exists locally (RV8-team m9), and deletes the row if it exists. The tombstone keeps a later pull (a record still behind a gap in its stream) from storing it.

## 9. Push

### 9.1 Order of checks

The server checks a `POST /v1/records` request in this order and stops at the first failure; nothing of a failed request is stored. `item` in the error body is the 0-based position of the failing item.

1. Token, before any byte of the body is read (RVT2 B1): a declared `Content-Length` above 2 MiB or 1.5 MiB is refused first (413 `body`, `batch_bytes`; nothing is looked up); then the token (401; a failed token is charged to the address's unauthenticated budget before the lookup, §12) and an approved device (403 `not_approved`). Every endpoint that carries a token, not only this one, authenticates before it reads its body, so a request with a bad token and a malformed body is a 401 that counts, not a 400 that does not.
2. Body: ≤ 2 MiB (413 `body`), then ≤ 1.5 MiB (413 `batch_bytes`), measured on the encoded body as received; valid JSON of the schema (400 `malformed`, or 400 `unknown_field` with `field`); 1-100 items (413 `batch_records` above 100, 400 `invalid_value` for none).
3. The rest of the caller's checks: `restore_pending` for a non-admin (503 `restore_pending`, §11), `Awm-Client` against `min_client` (426), every tag known (400 `invalid_value`) and writable by the caller (403 `forbidden`), the member's daily quota (429 `rate_limited` with `limit: records_per_day`; records and markers whose id the server has never seen count, a marker for an id it holds or has in its deletion stream does not, and nothing pushed in the 24 h after a new `generation` counts; §10.3).
4. Each record item's blob: decoded size ≤ 16,384 bytes (413 `blob`); then the envelope structure: first byte `0x01` and length `41 + 256·k` with `k ≥ 1`, that is 297 to 16,169 bytes (422 `bad_envelope`). The server never sees plaintext and checks nothing else about the blob.
5. Each item, in request order, against the stream state including the items before it in the same request:
   1. **Replay**: the stream already holds this `id` at this `idx` (a record or a marker): no change, counted in `replayed`, whatever the blob, epoch or marker form of the retry.
   2. **Conflict**: the stream holds a different id at this `idx`: 409 `stream_conflict` with the stream's `head`.
   3. **Deleted**: a record item whose `id` is in the deletion stream: 410 `deleted` with `ids` listing every record item of the request whose id is deleted. (A marker item for a deleted id passes: it is how the writer fills that index, §10.3.)
   4. **Id taken**: the `id` is stored at another position, or was pre-deleted by another member (§10.3): 409 `id_conflict`.
   5. **Contiguity**: `idx` is not the stream's head + 1: 409 `stream_conflict` with the head.
   6. **Epoch**: a record item whose `epoch` is not the current epoch: 409 `stale_epoch` with `current_epoch`. Markers carry no epoch.
6. All items are stored in one transaction; a marker item for an id not yet in the deletion stream also appends it there. The response gives each touched stream's new head.

### 9.2 Idempotency

A push is idempotent by (stream, idx, id) (RV8-team M1): the replay check (step 4.1) runs before the deletion, id and epoch checks, so a retry of an acknowledged request returns 200 with every item in `replayed`, even if the client re-encrypted it, even after a key rotation, and even if the record has since been deleted (its marker keeps the id). Deletes are idempotent by record id (§10), approvals by (device, epoch), invite revocations by invite id; a second join with the same invite gets 410.

### 9.3 What the client keeps and does

- Before sending, in one short transaction: `event.sync_id`, `event.sync_idx`, the `sync_own` row holding the exact blob, its idx and epoch, the outbox row that references it (`sync_outbox.ref` = `tag:idx`), and the stream head (plan-v3-team §4.6 step 3). A retry resends the stored items unchanged. Roster items are queued the same way (outbox kind `roster`, RVT1 M4).
- 200: set `pushed_at` for every item of the request (accepted or replayed).
- 409 `stream_conflict`: refresh `GET /v1/status`; if the server's head is below the item's idx, the earlier items were lost (an older server copy, §11) and the client re-seeds; if the stored id at that index is not in the local outbox, the device id collides with another copy of this data directory (RVT0 m7: take a new device id through a device invite; `awm doctor` explains it).
- 409 `stale_epoch`: the item never reached a server that holds it (otherwise step 4.1 would have answered); the client fetches `GET /v1/keys`, re-encrypts the same plaintext under the current epoch at the same stream, idx and id (only `epoch` in the AD changes), replaces the stored blob, and retries.
- 410 `deleted`: for each id in `ids`, the client deletes the local row, writes the `team:` tombstone and replaces that item with a marker `{tag, idx, id, deleted: true}` at the same idx, then retries, so the index is filled and the stream stays contiguous (§16.3).
- 503 `restore_pending`, 429, network errors: keep the outbox and retry after `Retry-After` or the backoff (plan-v3-team §3.3).

## 10. Deletion

### 10.1 `POST /v1/delete`

- `{ids}`: 1-1,000 record ids (more get 413 `delete_ids`). For each id the server holds: if the caller's member wrote it (from any device, RV8-team M16) or the caller is an admin, the blob is removed, the stream keeps a marker, and the id is appended to the deletion stream; otherwise the whole request gets 403 `forbidden`. Ids already in the deletion stream count in `already`.
- `{all_mine: true}`: every record of the caller's member, on every device, held at that moment, except `roster` records (below).
- `{member}` (admin): every record of that member, except `roster` records.
- The response counts ids appended (`deleted`) and ids already deleted (`already`); repeating a request gives `deleted: 0`. Skipped `roster` records are counted in neither.
- **The server never deletes a `roster` record, by any path** (TM9 F2). Retention, `{all_mine}`, `{member}` and member removal with record deletion (`POST /v1/members/{id}/remove` with `delete_records`) skip `roster` records: they are not counted, get no deletion entry and keep their blob. `{ids}` naming a `roster` record the server holds fails as a whole with 400 `invalid_value` and `field: /ids`, after the ownership check; nothing is deleted. Roster records leave the server only when the organisation is deleted. Reason: every later joiner, and every client that re-verifies after a restore, verifies the roster as a chain from the genesis (crypto §7); a marker keeps the index but not the sealed approvals, revocations and epoch records the verifier must open, so skipping is the only way the chain stays verifiable. A client has no reason to send a `roster` id (the commands that delete send `rec` and `stats` ids); such a request is refused rather than silently counted as `already`.
- `all_mine` and `member` are limited to 1 per hour per device (a token rotation keeps the allowance), and the two share it (RV8-team M7). The allowance is durable: it is read from the audit log, so it survives a restart and is the same on every instance that shares the database; the hour is then claimed in the store (a compare-and-set) before anything is deleted, so concurrent requests of one token, on one instance or several, delete once and the others get 429 (RVT2 m12). A bulk delete that fails (403, 404) does not use the hour; a refused one gets 429 `rate_limited` with `retry_after_s` and `Retry-After` for the rest of the hour. Each successful bulk delete writes an audit row `delete.notice` (actor: the member; target: the deleting device id; detail: the scope and the `deleted` and `already` counts), in addition to the store's own `delete` row, and admins read it in their next `GET /v1/audit`.
- **Checkpoint.** After every deletion (`{ids}`, `all_mine`, `member`, and a removal with `delete_records`) the server checkpoints its store (`SqliteStore`: `wal_checkpoint(TRUNCATE)`) before it answers, so a 200 means that neither the database file nor its write-ahead log holds the deleted bytes. A failed checkpoint is a 500; the retry is idempotent and checkpoints again. Snapshots and change sets taken before a deletion hold the blob until they age out (plan-v3-team §5.6).

### 10.2 Deletion does not reach records pushed later by another device

`all_mine` deletes what the server holds when it runs. A device of the same member that was offline and later pushes records captured before the deletion is not covered: their ids were never known to the deleting device. The client commands that delete (`forget`, `purge`, `unshare --delete`, `team leave --delete`) therefore delete by id what the member's own devices know, and the offline device's own rows are its own (plan-v3-team §3.6). TM11 states this in `awm purge` output; the protocol does not hide it.

### 10.3 Ids the server has never stored ("pre-deletion")

An id in `{ids}` that the server does not hold is appended to the deletion stream all the same, bound to the caller's member, and counted against the member's daily quota of 5,000 (RVT2 M1): every such id adds a deletion-stream entry that every member pulls, as a record adds a row. A `{ids}` request whose new ids would take the member past the quota is refused as a whole with 429 `rate_limited`, `limit: records_per_day` and `Retry-After` until 00:00 UTC, and nothing of it is written. A marker pushed with an id the server has never seen counts in the same way (it also appends a deletion entry, §9.1); deleting a record the server holds, an id already in the deletion stream, and a marker for an id the server knows count nothing. The 24 h after a new `generation` are exempt, as for pushes. This closes the in-flight case (RV8-team M9): a record that a `forget` deleted while a detached `awm sync` already had it in a batch is refused when that batch arrives (410 `deleted`), and the writer fills its index with a marker. A later push of a pre-deleted id by the same member gets 410 `deleted`; by another member, 409 `id_conflict` (a member cannot block another's records except by guessing a random UUIDv4).

### 10.4 Retention and settings

- The server deletes records whose `received_at` is older than `retention_days` (hourly on a host; bounded batches inside requests at most once an hour on Cloud Run) and appends their ids to the deletion stream. Retention runs from receipt: a re-seeded or backfilled record starts its server retention again when it is received (RVT0 m10, the documented option). Clients also drop teammates' rows whose `created_at` is older than `retention_days` (plan-v3-team §3.7).
- Retention keeps what a later joiner needs. `roster` records are never deleted (§10.1). **The newest `policy` record of each stream (member, device, `policy`) is kept beyond `retention_days`**, whatever its age (TM9 P1): without it, an organisation whose admins push no new policy for a year would lose its current policy and members who join later would never see it. Older `policy` records of the stream expire as usual, and a newest record that its author deleted is a marker, so the stream then has nothing to keep.
- A run is at most one bounded batch of 1,000 records per call and at most one run an hour for the whole organisation (the last run is stored with the data, so every instance on one database shares it); a call within the hour removes nothing and writes nothing. Each run also drops deletion-stream entries older than `retention_days` + 30 days (the newest entry always stays, §8.5) and audit rows older than 400 days (the newest stays), checkpoints, and writes one audit row `retention` with the counts.
- `retention_days` is at least 30. A decrease is stored as `pending_retention` with `effective_at` = now + 7 days, shown in `GET /v1/status`, `GET /v1/org/settings` and the audit log; any admin cancels it with `cancel_pending_retention: true`; an increase applies at once and cancels a pending decrease. `min_client` only rises (400 `invalid_value` otherwise) and never below the release floor. In the cloud, entitlements clamp `retention_days` and `max_members` to the plan (plan-v3-team §7.7).

### 10.5 Seats and payment (cloud)

The cloud's seat count is the number of members with at least one approved, non-revoked device; it is recomputed on every approve, revoke and remove and sent to Stripe as the current count, so retries and races converge (RV8-team m17). A member approval or a member invite that the plan does not allow (Free: 3 members), and every push and invite in a read-only state, get 402 `payment_required` with `state` and `billing_url`; pulls, deletions and exports always work. A device approval of an existing member never changes the seat count.

## 11. Restore and `generation`

Every member's machine holds that member's own records, so a restored server that lost its last writes is repaired by the clients (plan-v3-team §3.9.5).

Server:

1. `awm serve restore` (and `--mark-restored` after a Cloud SQL restore or clone) writes a new `generation` and sets `restore_pending`. The audit log records it. Into a data directory, both refuse with exit 2 while an `awm serve` holds its `server.lock`, and a second `awm serve` on the directory exits 2 as well (RVT2 M5). `--force` keeps the replaced database as `server.db.pre-restore-{time}`; it holds blobs deleted later, so `awm serve` removes it, hourly, once every backup older than it has expired and 8 days after the restore at the latest (`KEEP_FULL_S` + 1 day, the rule without a backup target), and the restore prints that latest date (RVT2 B2).
2. While `restore_pending` is set, non-admin `POST /v1/records`, `POST /v1/invites`, `POST /v1/devices/{id}/approve` and `POST /v1/join` get 503 `restore_pending` with `generation` and `Retry-After`. Pulls, deletions, token rotations, revocations and every admin request continue.
3. `POST /v1/restore/complete {generation}` by an admin clears it.

Clients, when `GET /v1/status` shows a `generation` other than `sync_state.generation`:

1. **Every client, as a reader**: for each stream where the server's head is below its own `head_idx`, lower `head_idx` to the server's head (re-pulled records whose id is already stored are skipped through the unique `event.sync_id`); set `deletion_head` to `oldest - 1` and re-apply the whole kept deletion stream (idempotent, because tombstones are written whether or not the row exists, §8.5). Entries the restored server lost were applied before; entries appended after the restore are applied now.
2. **Every client, as an author**: for every tag, re-push every own item from `sync_own` above the server's head of that stream: a record (`rec` re-built from `event.sync_idx` and re-sealed under the current epoch; other tags re-sealed from the stored blob's plaintext under the current epoch) at the same idx and id, or a marker `{tag, idx, id, deleted: true}` with the stored `record_id` for an index whose record it has deleted since (`sync_own.deleted`); then re-send `POST /v1/delete` for every `team:` tombstone of its own of the last `retention_days` + 30 days. Non-admin pushes wait for 503 `restore_pending` to end; the deletions and an admin's pushes (its roster revocations and epoch records included) do not.
3. **An admin client**, first: for every revocation in its verified roster (a removed member, a revoked device) that the server shows as active, call `POST /v1/members/{id}/remove` or `POST /v1/devices/{id}/revoke`; then, for each epoch from the server's `current_epoch + 1` to its own highest, `POST /v1/keys/rotate` with that epoch's existing key wrapped to the devices that are both in its verified roster and listed (not revoked) by the server; then `POST /v1/restore/complete`. Until an admin has done this, removals made after the backup point are not in force, which is why the restore command prints that an admin must run `awm sync` at once (RV8-team M8).
3a. **Every client, for the roster**: verify the roster over its stored `roster_record` rows together with the server's records; `team_device.revoked` and a member's removal (`team_member.active = 0`) never go back to 0 (RVT1 M3). A client that re-verified only from the restored server would lose a revocation pushed after the backup point.
4. Store the new `generation`.
5. Tokens: a token rotated after the backup point is unknown to the restored server (401). The client keeps its previous device token in `team.key` until its next rotation; on a 401 with the current token after a generation change it tries the previous one once and, if that works, rotates at once, revoking the old token again. Devices and invites created after the backup point get 401 or 410, and `awm doctor` says "the server was restored from a backup older than this device's join; ask an admin for a new invite".

A server that fakes a new generation only causes these idempotent steps.

## 12. Limits and rate limits

All sizes are bytes. Body limits are measured on the encoded JSON body as received (RV8-team m14); a body above a limit is refused before it is parsed. Blob limits are measured on the decoded envelope.

| limit | value | error |
|---|---|---|
| any request body | ≤ 2,097,152 (2 MiB) | 413 `body` |
| `POST /v1/records` body | ≤ 1,572,864 (1.5 MiB) and ≤ 100 items | 413 `batch_bytes`, `batch_records` |
| blob (decoded envelope) | ≤ 16,384 (16 KiB); with the 256-byte padding the largest valid envelope is 16,169 bytes, 21,559 base64url characters; the smallest is 297 bytes, 396 characters | 413 `blob`, 422 `bad_envelope` |
| what fits one push | 100 smallest envelopes (about 50 KB); at most 72 envelopes of the largest size (an item of 21,650 bytes; the batch byte limit binds first, so the client splits by bytes as well as by count) | |
| pull page | ≤ 500 records per `GET /v1/records` or `POST /v1/pull`, and a pull response is cut before 8,388,608 bytes (8 MiB) encoded, with `more: true` | |
| pull cursors | ≤ 1,000 per request | 413 `pull_cursors` |
| deletions page | ≤ 5,000 entries | |
| ids per `POST /v1/delete` | ≤ 1,000 | 413 `delete_ids` |
| audit page | ≤ 1,000 rows | |
| records pushed per member per UTC day | ≤ 5,000: records, pre-deleted ids (`POST /v1/delete {ids}` naming ids the server has never seen) and markers with a new id count; deletions of held records, markers for known ids, and everything within 24 h of a new generation do not (§10.3, RVT2 M1) | 429 `rate_limited` (`limit: records_per_day`) on push and on `delete {ids}`, `Retry-After` until 00:00 UTC |
| requests per token | 60 per minute, burst 120 | 429 |
| `delete` by `all_mine` or `member` | 1 per hour per token, audited | 429 |
| unauthenticated requests per IP (an IPv6 address counts as its /64) | 30 per minute, failed tokens included; joins 10 per hour | 429 |
| request duration | ≤ 30 s from the first byte to the response; a slower request gets a bodyless answer (§13) | 408 |
| `Awm-Client` | ≤ 256 | 400 `bad_client_header` |
| handle | 1-24 characters of `[a-z0-9_-]` | 400 `invalid_value` |
| members per organisation | `max_members` (self-hosted default 100; cloud by plan) | 403 `forbidden`; cloud 402 |
| invite lifetime | 7 days by default, at most 30 | 400 `invalid_value` |

`limit` query parameters of 0 or above the page size get 400 `invalid_value`. `GET /v1/info` publishes the first group as `limits` (the test `the_published_limits_are_the_constants` keeps them equal to `wire::limits`).

Rate-limit state is per server instance and resets when an instance stops (RV8-team m13): path A runs at most 1 instance, the cloud at most 4, so a token can reach up to 4 times the per-token limit there. The client address comes from the socket, or from `X-Forwarded-For` only when the peer is a trusted proxy (plan-v3-team §4.10). The per-address limits key an IPv6 client on its /64 and a v4-mapped address on its IPv4 address (RVT2 m5), since one host usually holds a whole /64. A failed token is charged to its address before the lookup and the charge is given back when the token turns out valid, so a valid token from an address whose budget is spent still works, and an address with no budget left gets 429 for a header that cannot be a device token without a lookup (RVT2 B1). The TLS listener of `awm serve --domain` also caps one address at 16 handshakes in progress and 128 open connections, and closes a connection that sends nothing for 60 s (RVT2 m9).

## 13. Errors

Every non-2xx response has the body `{"error": code, "message": text, ...}` (`error.schema.json`). `message` is English for logs and `awm doctor`; clients never parse it. The other fields belong to particular codes:

| status | `error` | extra fields | client action |
|---|---|---|---|
| 400 | `malformed` | | bug: log, stop this request kind |
| 400 | `unknown_field` | `field` (JSON pointer or parameter name) | bug, or a field sent without the server listing its feature (§14.2) |
| 400 | `invalid_value` | `field` | as named |
| 400 | `bad_client_header` | | bug |
| 401 | `unauthenticated` | | after a new generation try the previous token (§11); else `awm doctor`: token revoked or unknown |
| 402 | `payment_required` (cloud) | `state`, `billing_url` | stop pushes and invites; `awm team status` shows the state |
| 403 | `forbidden` | | role or stream not allowed; also `max_members` reached |
| 403 | `not_approved` | | wait for approval |
| 404 | `not_found` | | |
| 408 | (no body) | | no body; the request took longer than 30 s; retry |
| 409 | `stream_conflict` | `item`, `head` | §9.3 |
| 409 | `id_conflict` | `item` | take a new record id for that item and retry (a fresh UUIDv4 collides only through a bug or a pre-deletion by another member) |
| 409 | `stale_epoch` | `item`, `current_epoch` | re-encrypt under the current epoch (§9.3) |
| 409 | `epoch_conflict` | `current_epoch` | another admin rotated first: refresh keys, rotate again only if still needed |
| 409 | `device_conflict` | | take a new device id and join again |
| 409 | `last_admin` | | promote another admin first |
| 410 | `deleted` | `item`, `ids` | §9.3 |
| 410 | `invite_gone` | | invite or bootstrap token used or expired: ask for a new one |
| 413 | `too_large` | `limit`, `max` | split and retry, or drop the item (blob) |
| 422 | `bad_envelope` | `item` | bug in the envelope code |
| 426 | `client_too_old` | `min_client` | stop pushing; `awm doctor` says to upgrade |
| 429 | `rate_limited` | `retry_after_s`, `limit` for the daily quota | wait |
| 503 | `maintenance` | `retry_after_s` | wait |
| 503 | `restore_pending` | `generation`, `retry_after_s` | run the re-seed (§11); retry pushes later |

There is one fixture per code (`error.{status}.{code}.json`), and the test `every_error_code_has_a_fixture_with_its_status` keeps code, status and schema in step with `wire::ErrorCode::status`.

## 14. Versioning and compatibility

### 14.1 Strict requests, lenient responses

- **A v1 server refuses unknown fields** in request bodies and query strings, at any depth, with 400 `unknown_field` naming the field. Reason: a field the server ignored would leave the client believing a request did something it did not (a deletion scope, a retention hint, a new binding), and every request field is either acted on or refused. The Rust request types carry `#[serde(deny_unknown_fields)]`.
- **A client ignores unknown fields** in responses, error bodies and record plaintexts, at any depth, because servers are upgraded before clients and an older client must keep working against a newer server. The Rust response and plaintext types have no `deny_unknown_fields`.
- Fixtures of the first client release stay in `tests/fixtures/v1/` and every later v1 server must accept them (plan-v3-team §4.3.6): requests only ever lose nothing and gain optional fields, so an old request stays valid.

### 14.2 Changes allowed within v1

Only additive changes: new optional response fields; new endpoints; new tags; new error codes within the existing statuses; new optional request fields and query parameters, each introduced together with a name in `GET /v1/info` `features`, and sent by a client only when the server lists that name (a v1.0 server lists none, so a newer client talking to it sends v1.0 requests). New enum values in requests (a new role, a new invite kind) are new request fields for this purpose and need a feature name. Nothing is removed or changes meaning within v1.

### 14.3 Unknown values a client meets

- Unknown tag in `GET /v1/status`: keep and advance the cursor, do not decrypt (`wire::Tag::known` is `None`).
- Unknown `error` code: decodes as `Unknown`; act on the HTTP status.
- Unknown role: decodes as `Unknown`; treat it as `member`.
- Unknown invite kind in `status.pending`: decodes as `Unknown`; never approved (RVT1 m3).
- Unknown `features`: ignore.

### 14.4 Plaintext `schema` and envelope version

Every plaintext carries `schema` (1 in v0.2). A reader parses `schema` first: a higher `schema` decodes as `Newer` without looking at the other fields, the index counts as applied (the cursor moves on), and `awm doctor` shows "a teammate runs a newer awm" (`wire::decode_plaintext`). `schema` 0, a missing `schema`, or a schema-1 plaintext that does not parse is dropped and counted (plan-v3-team §4.5). Exception: a `roster` record with a higher `schema` is kept (`roster_record`) and verified after an upgrade; until then it does not count (fail closed, RVT1 m10). A new required plaintext field, a changed meaning or a new enum value in a plaintext needs a higher `schema`; new optional plaintext fields do not. The envelope carries its own version byte (`0x01`); a server answers any other with 422.

### 14.5 Introducing v2

A breaking change becomes `/v2/`, served next to `/v1/` by the same server for at least 6 months (plan-v3-team §4.3.6, assumption); `GET /v1/info` lists `protocols: [1, 2]` and the client uses the highest version both list. A client speaking v2 sends `proto/2` and still reaches `/v1/` paths of an older server. A v1-only server answers `/v2/` paths with 404. Data written through v1 stays readable through v2 (the streams, indexes and envelopes are the same records).

## 15. Record plaintexts

What the envelope encrypts, as UTF-8 JSON, before padding (TM3 pads and removes padding). Caps are applied by the writer (TM5, plan-v3-team §3.2) and re-checked by readers (§4.5); the schemas state them. Plaintexts are lenient (§14.1).

### 15.1 `rec` (`plaintext.rec`)

| field | required | notes |
|---|---|---|
| `schema` | yes | 1 |
| `tool` | yes | `WebSearch`, `WebFetch` |
| `query` | no | ≤ 500 characters, re-redacted |
| `url` | no | ≤ 2,048; `url_norm` is not sent, the reader recomputes it |
| `fetch_prompt` | no | `full` only, ≤ 500 |
| `http_code`, `bytes`, `duration_ms` | no | |
| `status` | yes | `ok`, `dead_end`, `refusal` (`placeholder` is never shared) |
| `summary` | no | `full` only, ≤ `team.summary_chars` (≤ 2,000) |
| `results` | yes | ≤ 10 rows `{rank, url (≤ 512), title? (≤ 120)}`; may be empty |
| `agent` | yes | `claude`, `codex` |
| `source` | yes | `hook`, `import` |
| `created_at` | yes | hour |
| `repo_key` | no | 32 hex characters, `full` only |
| `share` | yes | `full`, or `link`: then only `tool`, `url`, `status`, `results` (URL and title), `agent`, `source`, `created_at` |

### 15.2 `flag` (`plaintext.flag`)

`schema`, `record_id`, `reason` (`quarantine` from the pull-side check, `user` from `awm team flag` or review label `h`), `detail?` (≤ 200 characters, redacted), `created_at`.

### 15.3 `stats` (`plaintext.stats`)

`schema`, `day` (`YYYY-MM-DD`, UTC), `shown`, `avoided`, `est_minutes`, `est_tokens` (totals only, plan-v3-team §3.8).

### 15.4 `policy` (`plaintext.policy`, admins)

`schema`, `version` (only increases; the highest a reader holds wins), `deny_hosts`, `link_hosts`, `terms`, `credential_params` (extra query-parameter names for the pre-push URL check), `summary_chars?`. `retention_days`, `min_client` and `max_members` are server settings and never appear here (RV8-team M26).

### 15.5 `roster` (`plaintext.roster`)

`schema` and `entry`, whose `type` is `genesis`, `approve`, `recover`, `revoke` or `epoch`, with the fields of `docs/sync-v1-crypto.md` §7 (`wire::RosterPlaintext` holds `keys::RosterEntry`: one type for the wire and the key flows, RVT1 M1). TM12 may add optional fields only.

## 16. Worked examples

Names: organisation `O`; members alf (admin, device A1) and roy (member, devices B1 and B2); the current epoch is 1 unless stated.

### 16.1 Crash after acknowledgement (RV8-team M1)

1. A1 captures a record. In one transaction it writes `sync_id = R1`, `sync_idx = 44`, the outbox row (blob `X`, idx 44, epoch 1) and `head_idx = 44` for (alf, A1, rec).
2. It sends `POST /v1/records {records: [{tag: rec, idx: 44, id: R1, epoch: 1, blob: X}]}`. The server stores it and answers 200 `accepted: 1`. A1 is killed before writing `pushed_at`.
3. Next run: A1 resends the outbox row unchanged. Step 4.1 finds R1 at (alf, A1, rec, 44): **200, `replayed: 1`**, no duplicate, no 409. A1 sets `pushed_at`.
4. Variant: between 2 and 3 an admin rotated to epoch 2. Step 4.1 still runs before the epoch check: **200, `replayed: 1`**.
5. Variant: the request in step 2 never reached the server, and the epoch moved to 2. The resend gets **409 `stale_epoch`, `current_epoch: 2`**. A1 fetches its epoch-2 wrap, re-encrypts the same plaintext with AD (O, alf, A1, rec, 44, R1, 2), replaces the outbox blob and resends: 200 `accepted: 1`.
6. Variant: the client had re-encrypted with a new nonce (blob `X'`) instead of resending `X`: still **200 `replayed`**, because idempotency is by (stream, idx, id), not by blob; the server keeps `X`.

### 16.2 Pull fan-out (RV8-team M2)

A 100-member organisation with 2 devices each has up to 1,000 streams (5 tags), about 600 with data. After a weekend, 40 members pushed 75 records each: 3,000 new records in 80 `rec` streams plus a few `flag` and `stats` streams.

- One `GET /v1/status` returns every head (about 600 entries, about 80 KB).
- The client sends one `POST /v1/pull` with the 90 cursors whose server head is above its own and `limit: 500`. The server returns 500 records across the first streams and `more: true`; the client repeats with updated `from` values. Six pulls fetch the 3,000 records.
- Total: 7 requests for the run (8 with a push), against the 60-per-minute, burst-120 token limit. Per-stream `GET /v1/records` would have needed at least 90 requests. On an ordinary minute (a few new records), a run is `status`, one `pull` and at most one push: about 3 requests, the figure in plan-v3-team §6.1.

### 16.3 Deletions for in-flight records (RV8-team M9)

(a) `forget` races a detached push on the same device:

1. A detached `awm sync` on B1 has put R7 (idx 12) into an outbox batch with `sync_id` set and `pushed_at` null; the request is not sent yet.
2. `awm forget URL` on B1 waits for `sync.lock`, deletes the local row, writes `tombstone('tool_use_id', 'team:R7')`, and sends `POST /v1/delete {ids: [R7]}` for every row with a `sync_id`, pushed or not. The server holds no R7: it appends R7 to the deletion stream (pre-deletion, §10.3) and answers `deleted: 1`.
3. The batch is sent: **410 `deleted`, `ids: [R7]`, `item: 0`**, nothing stored.
4. B1 replaces the item with `{tag: rec, idx: 12, id: R7, deleted: true}` and resends: 200. The stream is contiguous; readers see a marker at 12 and the deletion entry; no reader ever saw R7's blob.

(b) An admin deletes R8 (idx 13 of B1's stream) after the server acknowledged its push but before B1 recorded `pushed_at` (B1 crashed). B1's resend hits step 4.1, because the marker keeps R8 at idx 13: **200 `replayed`**, nothing stored again. B1 learns of the deletion from the deletion stream on its next pull, deletes its local row and writes the `team:R8` tombstone, so a later re-seed sends a marker for idx 13, never the blob.

(c) A deletion arrives before its record: reader A1's (roy, B1, rec) stream is stalled at a gap at idx 10, and the deletion stream names R7 (idx 12 of that stream). A1 writes the `team:R7` tombstone although it has no such row (m9). When the gap clears, the pull returns a marker at 12 (the server keeps the id) or, if a lying server returns a blob, the tombstone keeps it out.

(d) After a restore to a point before the deletion: the restored server holds R7 again. B1's re-seed step 2 re-sends `POST /v1/delete` for its tombstone `team:R7`: the record is deleted again and readers apply the new deletion entry (§16.4).

### 16.4 Restore (plan-v3-team §3.9.5; RV8-team M8, M9)

State before the backup: generation G1; (alf, A1, rec) head 40; (roy, B1, rec) head 10; epoch 1; deletion head 5. After the backup point: A1 pushed 41-44; B1 pushed 11-12 and deleted R11 (idx 11, deletion entry 6); alf removed member kit (roster revocation, rotation to epoch 2); B1 rotated its token. Then the disk is lost and the server is restored from the backup: generation G2, `restore_pending`, (alf, A1, rec) head 40, (roy, B1, rec) head 10, epoch 1, deletion head 5, kit active, B1's old token valid.

1. roy's B1 syncs first. `GET /v1/status` with its new token: **401**. It tries its previous token: 200, and rotates the token at once (the old one is revoked again). Status shows G2 ≠ G1 and `restore_pending: true`.
2. As a reader it lowers its head for (alf, A1, rec) from 44 to the server's 40, so it will pull 41-44 again once A1 has re-seeded them (it holds them already and skips them by id), and it re-applies the deletion stream from `oldest`.
3. As an author it re-pushes idx 11 as a marker `{idx: 11, id: R11, deleted: true}` and idx 12 as the stored record: **503 `restore_pending`**. It re-sends `POST /v1/delete {ids: [R11, ...]}` for its tombstones: 200, R11 enters the deletion stream as entry 6 (a pre-deletion: the server holds no R11).
4. alf's A1 syncs. Its roster revokes kit, but the server shows kit active: `POST /v1/members/{kit}/remove` (204, kit's tokens revoked). The server's epoch is 1, A1 holds epoch 2: `POST /v1/keys/rotate {epoch: 2, wraps}` with the existing `K_2` wrapped to A1, B1 and B2 (verified in the roster and listed by the server; not to kit's devices). Then `POST /v1/restore/complete {generation: G2}`. A1 re-pushes 41-44 under epoch 2 at their old indexes and ids and stores G2.
5. B1's next run re-sends the step-3 batch. Record 12 was encrypted under epoch 1, so the request fails at item 1 with **409 `stale_epoch`, `current_epoch: 2`** and nothing of it is stored (§9.1); B1 re-encrypts it under epoch 2 at idx 12 with id R12 (only `epoch` in the AD changes) and resends: 200. It stores G2. Readers that already had A1's 41-44 or B1's 12 skip them by id, the others receive them now, and R11 is deleted everywhere through entry 6.

Outcome: no record lost, no deleted record back, kit holds no key of epoch 2 and no valid token, B1's pre-restore token revoked. Records pushed after the backup by a device that never syncs again are lost; the backup's recovery point bounds only that.

## 17. Fixtures and schemas

- `crates/awm-proto/schemas/v1/`: `common.schema.json` ($defs for ids, tokens, handles, tags, heads, base64url, blob, versions) and one schema per request, response, query string and plaintext, written in JSON Schema draft 2020-12 (a subset: `type`, `properties`, `required`, `additionalProperties`, `items`, `minItems`, `maxItems`, `enum`, `const`, `minimum`, `maximum`, `multipleOf`, `minLength`, `maxLength`, `pattern`, `oneOf`, `$ref`). Request schemas set `additionalProperties: false` at every level; response and plaintext schemas leave it open.
- `crates/awm-proto/tests/fixtures/v1/`: one fixture per request and response body of §6 (variants: `delete.request.{ids,all_mine,member}`, `invites.request.{member,device}`, `settings.put.request[.cancel]`), one per error code, and one per plaintext kind (`plaintext.rec.{search,fetch,link}`, `plaintext.roster.{genesis,approve,recover,revoke,epoch}`).
- `crates/awm-proto/tests/wire_snapshots.rs` asserts: every fixture validates against its schema; it decodes into its Rust type and serialises back byte for byte after canonicalisation (sorted keys, no whitespace); the Rust output validates too; removing any field or adding an unknown one at any depth of any fixture is accepted by the schema exactly when serde accepts it (so each schema states the Rust type's required and optional fields and strictness); every declared property appears in a fixture; requests refuse unknown fields and responses and plaintexts ignore them; a plaintext with a higher `schema` decodes as `Newer`; plus the header grammar, token parsing, canonical ids, the envelope check, the limits and the error-code table. The test validates with its own implementation of the schema subset, which fails on any other keyword.

## 18. RV8-team findings and where they are answered

| finding | answer |
|---|---|
| X1 roster | `roster` tag (§8.1), push rights (§7), plaintext (§15.5), unverified devices get no wrap (§5.2) |
| M1 crash after acknowledgement | idempotency by (stream, idx, id) before the epoch check (§9.1, §9.2); outbox holds the blob (§9.3); §16.1 |
| M2 pull fan-out | `POST /v1/pull` (§6, §8.4); §16.2 |
| M3 moving between deployments | `org_id` made by the client and fixed (§3.1); `awm_t_{org}_{secret}` everywhere (§3.2); export keeps ids (§6) |
| M6 member who lost every device | `POST /v1/invites` `kind: device` for another member by an admin (§6, §7); `member_id` survives (§3.1) |
| M7 stolen tokens | bulk deletion 1 per hour, audited (§10.1); `retention_days` ≥ 30, decreases delayed 7 days (§10.4); token rotation and revocation (§6) |
| M8 restore brings back removed members | admin re-applies roster revocations, re-uploads epochs to verified devices, then `POST /v1/restore/complete`; 503 `restore_pending` until then (§11, §16.4) |
| M9 deletions for in-flight records and after restores | pre-deletion of unknown ids (§10.3), 410 `deleted` and markers (§9.3), tombstone re-send after a new generation (§11); §16.3, §16.4 |
| M14 activity timing | §4 |
| M26 one source for `retention_days`, `min_client` | server settings only (§2.3, §10.4); absent from the policy plaintext (§15.4) |
| m9 tombstone for every deletion entry | §8.5 |
| m13 rate-limit state per instance | §12 |
| m14 limits on the encoded body | §12, §9.1 step 1 |
| m17 seats follow the approved count | §10.5 |
