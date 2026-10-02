# Sync v1 cryptography

The end-to-end construction of awm team sync: epoch keys, the record envelope, device keys, invites and joins, approval, the roster, rotation, removal and recovery. It implements plan-v3-team §5.1 with the RV8-team changes (X1, M3, M4, M5, M6, M8, M14). Code: `crates/awm-proto/src/crypto.rs` (envelope) and `crates/awm-proto/src/keys.rs` (key flows). Tests: `crates/awm-proto/tests/crypto.rs`, `crates/awm-proto/tests/keys.rs`. Known-answer vectors: `crates/awm-proto/tests/vectors/v1/`. The wire format around these bytes is `docs/sync-v1.md` (TM2).

Everything below is v1. Ciphertext written by v1 must stay readable: the vectors pin every byte, and a change to any of them is a new version (envelope byte `0x02`, `awmi2_`, `awmk2_`, wrap byte `0x02`), never an edit.

## 1. Primitives

Only maintained RustCrypto and dalek crates, pinned in `Cargo.lock`; no primitive is implemented here.

| use | primitive | crate |
|---|---|---|
| record and wrap encryption | XChaCha20-Poly1305 (24-byte random nonce, 16-byte tag) | `chacha20poly1305` 0.11.0 (feature `zeroize`) |
| key agreement | X25519 | `x25519-dalek` 3.0.0 (`static_secrets`, default `zeroize`) |
| key derivation | HKDF-SHA256 (RFC 5869) | `hkdf` 0.13.0 |
| MACs | HMAC-SHA256, verified in constant time (`verify_slice`) | `hmac` 0.13.0 (feature `zeroize`), `sha2` 0.11.0 |
| randomness | the operating system's source | `getrandom` 0.4 |

Every HKDF `info` and every MAC label is distinct, so no key serves two purposes:

| label | key it derives or domain it separates |
|---|---|
| `awm rec v1` | `K_rec` from `K_e` (records) |
| `awm repo v1` | `K_repo` from `K_0` |
| `awm rot-auth v1` | the rotation authenticator key from `K_e` |
| `awm wrap v1` | the per-wrap key from the X25519 secret; also the wrap AD prefix |
| `awm wrap-auth v1` | the join authenticator key from `S`; also the wrap transcript prefix |
| `awm join v1` | the join MAC key from `S`; also the join transcript prefix |
| `awm code v1` | the 6-digit code key from `S` |
| `awm fp v1` | fingerprint hash prefix |
| `awm export v1` | recovery export checksum prefix |
| `awm1` | record AD prefix |

HKDF is always used with no salt (RFC 5869's zero salt) except for wraps, whose salt is `ephemeral public key ‖ recipient public key`.

## 2. Keys

- **Organisation id**: a UUIDv4 made by the first admin's client together with `K_0` (`KeyRing::create`). It never changes; it is in every AD (M3).
- **Epoch keys** `K_e`: 32 random bytes per epoch 0, 1, 2 ...; a key ring holds epochs 0 to n with no gaps (`KeyRing::from_keys` refuses anything else).
- **`K_rec`** = HKDF-SHA256(`K_e`, "awm rec v1").
- **`K_repo`** = HKDF-SHA256(`K_0`, "awm repo v1"), fixed for the organisation's life (M4). `repo_key(remote)` = the first 32 hex characters of HMAC-SHA256(`K_repo`, normalised remote). Normalising the remote is the caller's (§4.4). `RepoKey::encode` is the content of `team.repo`.
- **Device key pair**: X25519, made when the device joins (`DeviceKeys::generate`).
- **Fingerprint** of a public key `P`: the first 16 bytes of SHA-256("awm fp v1" ‖ `P`), as eight groups of four hex digits (`3f2a 9c01 ...`). The server can compute it too; it identifies a key, it is not a secret.

## 3. Record envelope v1

```
envelope = 0x01 ‖ nonce (24) ‖ XChaCha20-Poly1305(K_rec, nonce, pad(plaintext), AD)
pad(p)   = p ‖ 0x80 ‖ 0x00 ... to the next multiple of 256 bytes (ISO/IEC 7816-4)
```

- Length: 41 + 256·k bytes. A plaintext of 0 to 255 bytes takes one bucket, 256 to 511 two, and so on; the padding is always at least one byte.
- Caps: an envelope is at most 16,384 bytes (§4.3.5), so a plaintext is at most 16,127 bytes; 15 KiB (§3.2) fits.
- A server checks only the structure, with `crypto::check_structure` (version byte, minimum length, size cap, bucket alignment) and answers 422 when it fails.
- Unpadding happens inside the authenticated plaintext, so there is no padding oracle.

### 3.1 Associated data

```
AD = "awm1" ‖ org (16) ‖ member (16) ‖ device (16) ‖ len (1) ‖ tag ‖ idx (u64 BE) ‖ record id (16) ‖ epoch (u32 BE)
```

| field | encoding | why it is bound |
|---|---|---|
| `awm1` | 4 ASCII bytes | version and domain of the AD |
| org | UUID, 16 bytes | a record cannot move to another organisation (or tenant) |
| member | UUID, 16 bytes | nor to another member's stream |
| device | UUID, 16 bytes | nor to another device's stream |
| tag | 1-byte length, then 1-32 bytes of `[a-z0-9_]` | the record kind: `rec`, `flag`, `stats`, `policy`, `roster`; a `rec` cannot be replayed as a `roster` entry |
| idx | u64 big-endian | nor to another position (reorder) |
| record id | UUID, 16 bytes | nor under another id (the deletion stream and tombstones name ids) |
| epoch | u32 big-endian | nor to another epoch, even if two epochs held the same key |

The encoding is injective: fixed widths plus a length-prefixed tag. Test: `changing_any_single_ad_field_fails_decryption`, `ad_encoding_is_injective_on_the_tag`.

### 3.2 What the padding hides (M14)

Padding hides the exact length within 256 bytes. It does not hide the size class. Measured on synthetic payloads at the §3.2 caps (`padding_residual_link_versus_full_size_classes`):

| payload | plaintext | buckets | envelope |
|---|---|---|---|
| link, short URL | 252 B | 1 | 297 B |
| link, typical | 372 B | 2 | 553 B |
| link, 2,048-char URL, 120-char title | 2,350 B | 10 | 2,601 B |
| full, dead end, no summary | 309 B | 2 | 553 B |
| full, 300-char summary, 3 results | 1,131 B | 5 | 1,321 B |
| full, typical: 1,000-char summary, 10 results | 3,049 B | 12 | 3,113 B |
| full, 2,000-char summary, 10 results | 4,489 B | 18 | 4,649 B |

Residual, as §4.3.1 states: the server tells a typical `link` record (1-2 buckets) from a typical `full` one (about 12) by size. The classes overlap at the edges (a dead-end full record has the size of a typical link; a link with a very long URL falls between small and typical full records), so the size is a strong hint, not a proof. Within a class the size also hints at summary length and result count to 256 bytes. Hiding the class would need a minimum size per class (about 3 KiB for links), which v1 does not do.

## 4. Invites and joins

### 4.1 Invite string

`awm team invite` (or `add-device`) gets an invite id and token from the server and makes a 32-byte secret `S` that stays in the admin's `team.key`:

```
awmi1_ ‖ base64url-nopad( org (16) ‖ S (32) ‖ lp(invite id) ‖ lp(token) ‖ lp(handle) )
```

`lp` is a one-byte length prefix; invite id and token are 1-255 bytes, the handle 1-24 characters of `[a-z0-9_-]`. The string goes through a channel the admin trusts. `S` reaches the server never: the join request below holds a MAC of `S`, not `S` (`the_invite_secret_never_leaves_the_creating_device_except_in_the_string`).

### 4.2 Join request and MAC

The joining device makes a key pair and a device id (UUIDv4) and sends, with the token:

```
invite id, handle, device id, public key P, join_mac
transcript = "awm join v1" ‖ org ‖ lp(invite id) ‖ lp(handle) ‖ device id ‖ P
join_mac   = HMAC-SHA256( HKDF(S, "awm join v1"), transcript )
```

The server stores the request but cannot forge one for another key, because it does not hold `S`. `Invite::verify_join` checks it on the admin's machine against the admin's own invite id, handle and organisation id (`a_join_with_a_wrong_mac_is_rejected`: a changed MAC, public key, device id, handle, organisation or `S` fails).

### 4.3 Fingerprint and code (M5)

`awm team join` prints the device's fingerprint and a 6-digit code:

```
code = (first 8 bytes of HMAC-SHA256( HKDF(S, "awm code v1"), transcript ) as u64 BE) mod 10^6, shown as "123 456"
```

`awm team approve HANDLE` recomputes both from the pending request and `S`. The invitee reads the code out over the trusted channel; if a thief joined first with the stolen string, the pending request carries the thief's key and its code differs (`a_stolen_invite_alone_yields_no_history_without_an_approval`). Both values are deterministic in the public key and `S` (`fingerprint_and_code_are_deterministic_from_the_key_and_s`). The code has 20 bits: it is a comparison aid against a key the thief did not choose to match, not a password; a thief would have to find a key pair whose code collides with the honest invitee's, which they cannot know in advance.

A stolen string alone gives no history: keys arrive only as wraps made by an approver, and with `team.auto_approve = devices` (the default) a member join waits for that manual comparison.

## 5. Wraps

An epoch key `K_e` wrapped to device `d` with public key `P`:

```
e  = 32 random bytes (X25519 secret), E = X25519(e, 9)
z  = X25519(e, P)            (rejected if all-zero: low-order P)
K  = HKDF-SHA256(salt E ‖ P, ikm z, info "awm wrap v1")
AD = "awm wrap v1" ‖ org ‖ device id ‖ epoch (u32 BE) ‖ P ‖ E
blob = 0x01 ‖ E (32) ‖ nonce (24) ‖ XChaCha20-Poly1305(K, nonce, K_e, AD)      (105 bytes)
```

This is anonymous encryption to `P` (an ECIES shape like HPKE base mode). Its authenticity comes from a separate authenticator:

```
transcript = "awm wrap-auth v1" ‖ mode (1 byte) ‖ org ‖ device id ‖ epoch (u32 BE) ‖ P ‖ approver device id ‖ len (u16 BE) ‖ blob
auth (join, mode 1)     = HMAC-SHA256( HKDF(S, "awm wrap-auth v1"), transcript )
auth (rotation, mode 2) = HMAC-SHA256( HKDF(K_{e-1}, "awm rot-auth v1"), transcript )
```

A wrap on the wire is `{device id, epoch, approver device, blob, auth}`. A wrap for one device does not open for another (`a_wrap_for_one_device_does_not_open_for_another`: neither under the other device's id nor relabelled).

## 6. Approval

`awm team approve` (and the automatic approval of one's own devices, §4.6 step 7):

1. `Invite::verify_join(request)`: the MAC verifies under this invite's `S`; the result shows fingerprint and code.
2. `approve(ring, invite, verified, info)`: one wrap per epoch 0 to n, mode 1 (authenticated with `S`), plus a roster `approve` entry.
3. The approver seals the roster entry into its own `roster` stream (`seal_roster`) and pushes it with the wraps.

The joining device runs `accept_join(invite, device id, keys, wraps)`: every wrap must be for it, carry a valid `S` authenticator, open with its key, and together the wraps must hold epochs 0 to n. The server never sees `S`, so it cannot slip in a key it knows (`p2_a_wrap_not_authenticated_with_s_is_rejected`: a server-made approval, a modified authenticator, a spliced blob and a changed epoch are all rejected).

## 7. The roster (RV8-team X1)

Every approval, recovery, revocation and rotation appends a roster record to the writing device's own `roster` stream, sealed under the current epoch key like any record. Plaintext (JSON):

```json
{"schema": 1, "entry": {"type": "approve", "member_id": "…", "handle": "alice", "role": "member",
  "kind": "member", "device_id": "…", "device_pub": "<base64url 32 bytes>",
  "approved_at": 1790000100, "approver_device_id": "…"}}
```

| `type` | fields | written by | valid when |
|---|---|---|---|
| `genesis` | member_id, handle, device_id, device_pub, created_at | the first admin's first device (`awm team create`) | index 0, epoch 0, member and device equal the stream's; only one |
| `approve` | member_id, handle, role, kind (`member` or `device`), device_id, device_pub, approved_at, approver_device_id | the approving device | approver = writer; writer verified and of the stream's member; `member` kind: writer is an admin and the member id is new; `device` kind: the member exists, writer is that member or an admin, handle matches; the device id is new |
| `recover` | member_id, handle, device_id, device_pub, recovered_at | the new device of an admin restoring an export | member and device equal the stream's; the member is an admin in the roster; the device id is new |
| `revoke` | member_id, device_id (absent: the whole member), revoked_at, by_device_id | an admin, or a member for their own devices | writer verified, revoker = writer; the device belongs to the member |
| `epoch` | epoch, devices, created_at, by_device_id | the rotating admin, sealed under the new epoch | writer an admin; sealed under the epoch it names |

`Roster::verify(ring, blobs, extra_admins)` opens each record with the AD of the stream it was served from, so the server can neither forge a record (it holds no `K_e`) nor move one (`a_roster_entry_with_a_forged_ad_is_rejected`: another stream, index, record id or epoch, and a record sealed under a server key, are all rejected). It then applies entries to a fixpoint (an entry waits until its writer is verified, so order does not matter: `roster_order_does_not_matter_and_authority_is_checked`), then revocations and epoch records. A member's removal revokes all its devices, including ones approved later.

Admins are the genesis member and members approved with role `admin` by an admin. `extra_admins` lets the caller add the server's role list, which is needed after `awm serve promote` when no roster admin is left; doing so trusts the server's word on roles, which matters only to a member who also colludes with the server (P4/P5 class), because the server alone still cannot write a roster record.

`Roster::status(listed device)` gives `verified`, `unverified` (no roster entry: `awm team members` shows `unverified`), `mismatch` (the server lists another member or key than the roster) or `revoked`.

Clients store the verified result in `team_member` and `team_device` (§4.4) and re-verify when new roster records arrive. If the server deletes or withholds roster records, devices fall back to `unverified` and get no wraps: the failure is closed (fewer wraps, never more). For the same reason server retention must never delete `roster` records: a joiner verifies the whole chain from the genesis entry.

## 8. Rotation and removal

1. `awm team remove @h` appends a roster `revoke` of the member (`device_id` absent) and the server sets `rotation_needed`.
2. The next admin client to sync runs `plan_rotation(ring, roster, listed devices, removed members)`. A listed device gets a wrap only if it has a verified roster entry with the same member and public key (the roster's key is used, not the server's), is not revoked and is not a removed member's. The plan reports the rest: `unverified`, `mismatch`, `revoked`, `removed`, `not_listed` (verified but not listed by the server, which then cannot store a wrap), and `approved_by_removed` (devices of other members that the removed member approved: wrapped, but shown to the admin, because an admin could have enrolled a device under another member's id before being removed).
3. `rotate(ring, plan, by_device, now)` makes `K_{e+1}`, wraps it to the planned devices (mode 2, authenticated with `K_e`), and returns the `epoch` roster entry, which the admin seals under `K_{e+1}`. The admin keeps `K_{e+1}` with `KeyRing::adopt_own_rotation`.
4. Each device runs `KeyRing::accept_rotation(device id, keys, wrap)`: the wrap must be for epoch current + 1 and this device, authenticated with its current `K_e`, and open with its key.
5. From then on the server refuses pushes under older epochs (409, §4.3.2). Old records stay under their epochs.

`RotationPlan` has no public constructor, so no caller can ask `rotate` to wrap to a device the plan excluded. Tests: `p2_a_rotation_wraps_nothing_to_an_extra_server_listed_device`, `p2_a_rotation_wraps_nothing_to_a_server_substituted_key`, `p3_after_rotation_the_removed_members_keys_open_no_new_epoch_record`, `p3_a_revoked_device_of_a_remaining_member_gets_no_wrap`.

## 9. Recovery

- **Another device of the same member**: a device invite (`awm team add-device`), approved by the member's own device (kind `device`).
- **A member who lost every device** (M6): an admin creates `awm team add-device --for @handle`; the new device joins with that invite and the admin approves it with kind `device` under the existing member id, so the member id, streams and deletion rights survive. The admin also revokes the lost devices (`revoke` with `device_id`). Test: `an_admin_re_enrols_a_member_who_lost_every_device_under_the_same_member_id`.
- **Recovery export**: `awm team key export` prints

  ```
  awmk1_ ‖ base64url-nopad( org (16) ‖ n (u32 BE) ‖ n × (epoch (u32 BE) ‖ K_e (32)) ‖ first 4 bytes of SHA-256("awm export v1" ‖ everything before) )
  ```

  for a password manager. The string is the keys themselves (no password: the password manager is the protection); the checksum catches typing errors (`a_recovery_export_rejects_typos_and_gaps`). An admin who lost every device imports it on a new device, obtains a device token for their member id from the server (`awm serve promote` or the operator's path, TM7), and appends a `recover` roster entry for the new device in its own stream. Other clients accept it because the member is an admin in the roster; a non-admin cannot self-enrol this way. The restored admin can then rotate, and remaining devices accept its wraps (`a_recovery_export_restores_an_admins_ability_to_rotate`).
- If every device of every member is lost and no export exists, the server's data is unreadable (the cost of P1).

## 10. What the server sees

Of the crypto layer, the server (and anyone with its database or backups) holds:

| object | visible | hidden |
|---|---|---|
| record | version byte, nonce, length in 256-byte buckets, the AD fields as stream metadata (org, member, device, tag, idx, record id, epoch), push time | plaintext, `K_e`, `K_rec` |
| join request | invite id, token, handle, device id, public key (so the fingerprint), join MAC | `S`, the code (needs `S`) |
| wrap | device id, epoch, approver device id, ephemeral public key, nonce, sealed key, authenticator | the epoch key |
| roster record | as a record: which device approved, revoked or rotated, and when (the server learns these events from the API anyway) | who and what key exactly (inside the ciphertext) |
| key epochs | numbers and times | keys |

Never: plaintext, epoch keys, `K_repo`, invite secrets, device private keys. Test: `p1_nothing_the_server_receives_holds_a_key_or_plaintext` collects every byte string the server receives across create, joins, an own-device approval, a removal, a rotation and a record, and finds no key, device secret or plaintext in any of them; the server's own key ring opens none of the roster records.

## 11. Outcomes P1-P5

| property (§5.1) | outcome in v1 | tests |
|---|---|---|
| P1: the server alone reads no record | holds | `crypto::p1_envelope_shows_the_server_nothing_but_its_length`, `keys::p1_nothing_the_server_receives_holds_a_key_or_plaintext` |
| P2: the server alone cannot make a device accept a key it knows, at join or rotation, nor make a rotating admin wrap to a device it controls | holds (join: `S`; rotation: `K_e`; roster: X1) | `p2_a_wrap_not_authenticated_with_s_is_rejected`, `p2_a_rotation_wrap_forged_by_the_server_is_rejected`, `p2_a_rotation_wraps_nothing_to_an_extra_server_listed_device`, `p2_a_rotation_wraps_nothing_to_a_server_substituted_key`, `a_roster_entry_with_a_forged_ad_is_rejected`, `a_join_with_a_wrong_mac_is_rejected` |
| P3: a removed member alone cannot read records written after the rotation | holds; no wrap to a removed or revoked device is produced | `p3_after_rotation_the_removed_members_keys_open_no_new_epoch_record`, `p3_a_revoked_device_of_a_remaining_member_gets_no_wrap` |
| P4: a removed member colluding with the server | **not defended in v1** (decision below) | `p4_not_defended_removed_member_colluding_with_server_can_push_a_known_key` pins the gap |
| P5: authorship against a member colluding with the server | not defended in v1, as the plan says | `p5_not_defended_member_can_seal_a_record_in_another_members_stream` |

### 11.1 P4 decision

**Decision: P4 stays open in v1; it is not closed within TM3.**

Reasons:

1. The plan's candidate fix is admin signing keys (Ed25519, pinned at join through `S`). No Ed25519 crate is among the pinned dependencies, and TM3 may add none (vetted primitives only; no hand-rolled constructions).
2. The alternative with the pinned crates, authenticating rotation wraps by static-static X25519 between the rotating admin's device key and each receiving device, does not close P4 alone: a device learns which keys are admin keys from the roster, and roster records are authenticated only by `K_e`, which the removed member holds. The removed member and the server can append a forged roster entry naming a new "admin device" and then rotate from it. Closing P4 needs signatures on the roster itself, verifiable by every device and anchored in a key pinned through `S` at join, which is the Ed25519 design.
3. The gap needs both a removed member and the server: an honest server revokes the removed member's tokens and refuses their pushes, and refuses pushes under the old epoch after the rotation.

What closes it later (additive within v1's versioning rules): an `admin_key` roster entry type and a `sig` field on roster records and rotation wraps (Ed25519 over the same transcripts), the approver's signing key delivered inside the `S`-authenticated join wraps, and devices that require signatures once they have pinned an admin key. The test above then has to fail and be inverted.

## 12. Procedures

- **Create**: `KeyRing::create` → organisation id and `K_0`; device key pair; seal a `genesis` roster entry at index 0 of the admin's own `roster` stream under epoch 0; write `team.key` (device secret, epoch keys, pending invite secrets) and `team.repo` (`K_repo`), both mode 0600.
- **Invite**: server issues id and token → `Invite::create` → print `Invite::encode`; keep the invite (with `S`) in `team.key` until approved or expired.
- **Join**: `Invite::parse` → `DeviceKeys::generate` → `JoinRequest::new` → `POST /v1/join`; print the fingerprint and `Invite::confirmation_code`; poll `GET /v1/keys`; `accept_join` on the wraps; write `team.key` and `team.repo`.
- **Approve**: `verify_join` → show fingerprint and code (member joins) → `approve` → `POST /v1/devices/{id}/approve` with the wraps → seal and push the roster entry.
- **Remove and rotate**: `revoke` roster entry → `plan_rotation` (show `approved_by_removed`) → `rotate` → `POST /v1/keys/rotate` → seal the `epoch` entry under the new key and push it → `adopt_own_rotation`.
- **Recover**: as §9.

## 13. Zeroisation

Secret key material is overwritten on drop where the crates support it: `Secret32` (epoch keys, `K_rec`, `K_repo`, invite secrets, derived MAC keys), `EpochKey`, `DeviceKeys` (through `x25519-dalek`'s `StaticSecret`), `SharedSecret`, the AEAD key schedule (`chacha20poly1305` `zeroize`), HMAC state (`hmac` `zeroize`), and the padded plaintext and wrap buffers after use (`secret_material_is_zeroized_on_drop` checks the trait bounds and the explicit `zeroize`). Not covered: strings the caller asks for (`Invite::encode`, `KeyRing::export_recovery`, `RepoKey::encode`, the JSON of `team.key`), decrypted plaintext returned to the caller, by-value copies made when a 32-byte array is passed to a constructor, and anything the operating system swaps to disk.
