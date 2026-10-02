//! The `Store` trait (plan-v3-team §4.2, TM6) and its implementations.
//!
//! A `Store` holds one organisation: `SqliteStore` is one file per organisation, and the
//! multi-tenant `PgStore` (TM26, TM19) hands out one `Store` per organisation, scoped to it
//! before any query runs (the organisation id is read from the token first, `docs/sync-v1.md`
//! §3.2). Every operation of `docs/sync-v1.md` §6 has a method here, so the HTTP layer (TM8),
//! authentication (TM7), deletion and retention (TM9) and backup (TM27) write no SQL of their
//! own. Each method names the endpoint or task that uses it.
//!
//! The trait is object-safe and async: handlers hold an `Arc<dyn Store>` and await the boxed
//! futures. Methods take owned arguments, so a backend can move them onto a blocking thread.
//! Times are Unix seconds passed in by the caller (`now`), so tests control the clock; the
//! store rounds the §4.2 "hour" columns itself.
//!
//! Errors never carry blob contents, token hashes or other row values: [`StoreError`] holds
//! only the fields the error bodies of `docs/sync-v1.md` §13 need.

use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use awm_proto::wire::{
    AuditResponse, DeleteRequest, DeleteResponse, DeletionHeads, DeletionsResponse, DeviceWrap,
    EpochWrap, ErrorBody, ErrorCode, Handle, Id, InviteKind, Key32, KeysResponse, MemberInfo,
    OrgSettings, PullResponse, PushItem, PushResponse, Role, SettingsUpdate, StatusResponse,
    StreamRecords, Tag, Version,
};

#[cfg(feature = "pg")]
pub mod pg;
#[cfg(feature = "sqlite")]
pub mod sqlite;

// ---------------------------------------------------------------------------------------------
// Errors

/// A store failure. The variants that answer a request map to one wire error code
/// ([`StoreError::code`]); `NotEmpty`, `Unsupported` and `Backend` are internal (500).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// 404 `not_found`: an unknown member, device or invite.
    NotFound,
    /// 400 `invalid_value` with `field` (a JSON pointer such as `/handle` or `/wraps`).
    InvalidValue { field: String },
    /// 403 `forbidden`: deleting another member's record without being an admin, a member
    /// invite beyond `max_members`, approving a revoked device.
    Forbidden,
    /// 410 `invite_gone`: an invite or bootstrap token that is unknown, used, revoked or
    /// expired, or a bootstrap of an organisation that already exists.
    Gone,
    /// 409 `device_conflict`: the device id is taken.
    DeviceConflict,
    /// 409 `last_admin`: the change would leave no active admin.
    LastAdmin,
    /// 409 `epoch_conflict`: a rotation whose epoch is not the current one + 1.
    EpochConflict { current_epoch: u32 },
    /// 409 `stream_conflict` at push item `item`; `head` is the stream's head (-1 when empty).
    StreamConflict { item: u32, head: i64 },
    /// 409 `id_conflict` at push item `item`.
    IdConflict { item: u32 },
    /// 409 `stale_epoch` at push item `item`.
    StaleEpoch { item: u32, current_epoch: u32 },
    /// 410 `deleted` at push item `item`; `ids` lists every record item of the request whose
    /// id is in the deletion stream (`docs/sync-v1.md` §9.1 step 4.3).
    Deleted { item: u32, ids: Vec<Id> },
    /// Import into a store that holds an organisation, or a bootstrap token set on one.
    NotEmpty,
    /// The backend does not implement this operation (the `backup_log` methods on `PgStore`).
    Unsupported(&'static str),
    /// Storage failure (I/O, SQLite or Postgres error, a broken invariant). The text names
    /// the operation and the backend's error, never a row value.
    Backend(String),
}

impl StoreError {
    /// The wire error code (`docs/sync-v1.md` §13); `None` for an internal error (500).
    pub fn code(&self) -> Option<ErrorCode> {
        use StoreError::*;
        Some(match self {
            NotFound => ErrorCode::NotFound,
            InvalidValue { .. } => ErrorCode::InvalidValue,
            Forbidden => ErrorCode::Forbidden,
            Gone => ErrorCode::InviteGone,
            DeviceConflict => ErrorCode::DeviceConflict,
            LastAdmin => ErrorCode::LastAdmin,
            EpochConflict { .. } => ErrorCode::EpochConflict,
            StreamConflict { .. } => ErrorCode::StreamConflict,
            IdConflict { .. } => ErrorCode::IdConflict,
            StaleEpoch { .. } => ErrorCode::StaleEpoch,
            Deleted { .. } => ErrorCode::Deleted,
            NotEmpty | Unsupported(_) | Backend(_) => return None,
        })
    }

    /// The HTTP status: the code's status, or 500.
    pub fn status(&self) -> u16 {
        self.code().and_then(ErrorCode::status).unwrap_or(500)
    }

    /// The error body TM8 sends; `None` for an internal error, which TM8 answers with a
    /// bodiless 500 and logs (the text holds no row values).
    pub fn to_body(&self) -> Option<ErrorBody> {
        let code = self.code()?;
        let mut b = ErrorBody::new(code, self.to_string());
        match self {
            StoreError::InvalidValue { field } => b.field = Some(field.clone()),
            StoreError::EpochConflict { current_epoch } => b.current_epoch = Some(*current_epoch),
            StoreError::StreamConflict { item, head } => {
                b.item = Some(*item);
                b.head = Some(*head);
            }
            StoreError::IdConflict { item } => b.item = Some(*item),
            StoreError::StaleEpoch {
                item,
                current_epoch,
            } => {
                b.item = Some(*item);
                b.current_epoch = Some(*current_epoch);
            }
            StoreError::Deleted { item, ids } => {
                b.item = Some(*item);
                b.ids = Some(ids.clone());
            }
            _ => {}
        }
        Some(b)
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use StoreError::*;
        match self {
            NotFound => f.write_str("not found"),
            InvalidValue { field } => write!(f, "invalid value at {field}"),
            Forbidden => f.write_str("forbidden"),
            Gone => f.write_str("invite or bootstrap token used, revoked, expired or unknown"),
            DeviceConflict => f.write_str("device id already registered"),
            LastAdmin => f.write_str("the organisation would be left without an admin"),
            EpochConflict { current_epoch } => {
                write!(f, "epoch must be {} (current + 1)", current_epoch + 1)
            }
            StreamConflict { item, head } => {
                write!(f, "item {item}: stream conflict (head {head})")
            }
            IdConflict { item } => write!(f, "item {item}: record id stored elsewhere"),
            StaleEpoch {
                item,
                current_epoch,
            } => write!(f, "item {item}: epoch is not current ({current_epoch})"),
            Deleted { item, ids } => write!(f, "item {item}: {} record id(s) deleted", ids.len()),
            NotEmpty => f.write_str("the store already holds an organisation"),
            Unsupported(what) => write!(f, "not supported by this store: {what}"),
            Backend(msg) => write!(f, "store: {msg}"),
        }
    }
}

impl std::error::Error for StoreError {}

pub type StoreResult<T> = Result<T, StoreError>;

/// The future every [`Store`] method returns.
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = StoreResult<T>> + Send + 'a>>;

// ---------------------------------------------------------------------------------------------
// Arguments and rows

/// Who acts, for authorisation decisions the store must take inside its transaction (record
/// ownership on delete) and for the `actor` of audit rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Actor {
    pub member_id: Id,
    pub device_id: Id,
    pub admin: bool,
}

/// The organisation's settings at bootstrap (TM7 passes the configured defaults: retention
/// 365 days self-hosted, `min_client` the release floor, `max_members` 100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgDefaults {
    pub retention_days: u32,
    pub min_client: Version,
    pub max_members: u32,
}

/// `POST /v1/bootstrap`, after TM7 parsed the token and hashed both tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBootstrap {
    /// SHA-256 hex of the presented bootstrap token, compared with the stored one.
    pub bootstrap_token_hash: String,
    pub org_id: Id,
    pub handle: Handle,
    pub device_id: Id,
    pub device_pubkey: Key32,
    /// SHA-256 hex of the new device token (the token itself is returned once by TM7).
    pub device_token_hash: String,
    pub defaults: OrgDefaults,
    pub now: i64,
}

/// `POST /v1/join`, after TM7 parsed the invite token and hashed both tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewJoin {
    pub invite_id: Id,
    pub invite_token_hash: String,
    pub handle: Handle,
    pub device_id: Id,
    pub device_pubkey: Key32,
    pub join_mac: Key32,
    pub device_token_hash: String,
    pub now: i64,
}

/// The result of a join: the member the device belongs to (new for a member invite, the
/// existing one for a device invite).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Joined {
    pub org_id: Id,
    pub member_id: Id,
    pub kind: InviteKind,
}

/// `POST /v1/invites`, after TM7 authorised it and generated the invite token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewInvite {
    pub invite_id: Id,
    pub token_hash: String,
    pub kind: InviteKind,
    /// `member`: the new member's handle; `device`: the existing member's handle.
    pub handle: Handle,
    /// `member` invites: the role (default `member`); must be `None` for `device` invites.
    pub role: Option<Role>,
    pub expires_at: i64,
    pub by: Actor,
    pub now: i64,
}

/// An invite as stored (no token hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRow {
    pub invite_id: Id,
    pub kind: InviteKind,
    pub handle: Handle,
    pub role: Option<Role>,
    /// `device` invites: the member the device will belong to.
    pub member_id: Option<Id>,
    /// The creating device and its member.
    pub created_by: Id,
    pub created_by_member: Id,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

/// The device a token hash names, with what TM7 needs to answer 401 or 403 `not_approved`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDevice {
    pub org_id: Id,
    pub member_id: Id,
    pub device_id: Id,
    pub handle: Handle,
    pub role: Role,
    pub approved: bool,
    pub device_revoked: bool,
    pub member_revoked: bool,
}

/// A device row (no token hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    pub device_id: Id,
    pub member_id: Id,
    pub pubkey: Key32,
    /// `None` for the bootstrap device.
    pub join_mac: Option<Key32>,
    pub invite_id: Option<Id>,
    pub approved: bool,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub last_seen_day: Option<i64>,
}

/// A member row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRow {
    pub member_id: Id,
    pub handle: Handle,
    pub role: Role,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

/// The organisation row with its effective settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgRow {
    pub org_id: Id,
    pub created_at: i64,
    pub current_epoch: u32,
    pub rotation_needed: bool,
    pub settings: OrgSettings,
}

/// `generation` and the restore state (§3.9.5, `docs/sync-v1.md` §11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreState {
    pub generation: Id,
    pub restore_pending: bool,
    pub restored_at: Option<i64>,
}

/// `POST /v1/records` after §9.1 steps 1-3 (TM8: body, caller, envelope): the items in
/// request order, for the caller's own streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushBatch {
    pub member_id: Id,
    pub device_id: Id,
    pub items: Vec<PushItem>,
    pub now: i64,
}

/// One audit row to append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub at: i64,
    pub actor: Option<Id>,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
}

/// Row counts per table of an export or import, in [`CANONICAL_TABLES`] order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableCounts(pub Vec<(&'static str, u64)>);

impl TableCounts {
    pub fn get(&self, table: &str) -> Option<u64> {
        self.0.iter().find(|(t, _)| *t == table).map(|(_, n)| *n)
    }
}

/// One `backup_log` row (`SqliteStore` only, §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupLogRow {
    pub seq: i64,
    pub tbl: String,
    pub key: String,
    /// `i`, `u` or `d`.
    pub op: String,
}

/// A change set written by [`Store::export_changes`] or applied by [`Store::apply_changes`]:
/// the `backup_log` range `(after, to]` and the number of distinct rows it touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeSet {
    pub after: i64,
    pub to: i64,
    pub rows: u64,
}

// ---------------------------------------------------------------------------------------------
// The canonical format and logical dumps

/// The tables of the canonical export format (`migrations/sqlite/0001_server.sql`) with their
/// columns, in the order export, import and [`LogicalDump`] use. `backup_log` is not part of
/// it (it is `SqliteStore`'s change log), and neither are the `meta` keys that
/// [`canonical_meta_key`] leaves out (each store's own bookkeeping).
pub const CANONICAL_TABLES: &[(&str, &[&str])] = &[
    (
        "org",
        &[
            "id",
            "created_at",
            "current_epoch",
            "rotation_needed",
            "retention_days",
            "min_client",
            "max_members",
            "pending_retention_days",
            "pending_retention_at",
        ],
    ),
    (
        "member",
        &["id", "handle", "role", "created_at", "revoked_at"],
    ),
    (
        "device",
        &[
            "id",
            "member_id",
            "token_hash",
            "pubkey",
            "join_mac",
            "invite_id",
            "approved",
            "created_at",
            "revoked_at",
            "last_seen_day",
        ],
    ),
    (
        "invite",
        &[
            "id",
            "token_hash",
            "handle",
            "role",
            "kind",
            "member_id",
            "created_by",
            "created_at",
            "expires_at",
            "used_at",
            "revoked_at",
        ],
    ),
    (
        "record",
        &[
            "member_id",
            "device_id",
            "tag",
            "idx",
            "id",
            "epoch",
            "size",
            "received_at",
            "blob",
            "deleted_at",
        ],
    ),
    ("deletion", &["idx", "record_id", "member_id", "deleted_at"]),
    (
        "wrap",
        &["device_id", "epoch", "wrap", "auth", "created_by"],
    ),
    (
        "audit",
        &["idx", "at", "actor", "action", "target", "detail"],
    ),
    ("meta", &["key", "value"]),
];

/// `meta` keys the store owns; [`Store::meta_set`] refuses them and the prefixes below.
pub mod meta_keys {
    /// Random UUIDv4, new on every restore (§3.9.5).
    pub const GENERATION: &str = "generation";
    /// `1` while non-admin writes get 503 `restore_pending` (`docs/sync-v1.md` §11).
    pub const RESTORE_PENDING: &str = "restore_pending";
    /// Unix seconds of the last restore.
    pub const RESTORED_AT: &str = "restored_at";
    /// The bootstrap token's SHA-256 hex and expiry (`awm serve init`).
    pub const BOOTSTRAP_HASH: &str = "bootstrap_token_hash";
    pub const BOOTSTRAP_EXPIRES: &str = "bootstrap_expires_at";
    /// The schema version and each migration's checksum (`schema_checksum.{version}`).
    pub const SCHEMA_VERSION: &str = "schema_version";
    pub const SCHEMA_PREFIX: &str = "schema_";
    pub const BOOTSTRAP_PREFIX: &str = "bootstrap_";
    /// Keys for the caller (free to write with `meta_set`): retention (TM9) and backup (TM27).
    /// Keys starting with `backup_` are not written to `backup_log`.
    pub const LAST_RETENTION: &str = "last_retention";
    pub const BACKUP_CURSOR: &str = "backup_cursor";
    pub const BACKUP_VERIFIED_AT: &str = "backup_verified_at";
    pub const BACKUP_PREFIX: &str = "backup_";

    /// Whether `meta_set` refuses `key`.
    pub fn reserved(key: &str) -> bool {
        matches!(key, GENERATION | RESTORE_PENDING | RESTORED_AT)
            || key.starts_with(SCHEMA_PREFIX)
            || key.starts_with(BOOTSTRAP_PREFIX)
    }
}

/// One column value of a [`LogicalDump`]. `Debug` prints a blob as its length and a digest
/// prefix, never its bytes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DumpValue {
    Null,
    Int(i64),
    Text(String),
    Blob(Vec<u8>),
}

impl fmt::Debug for DumpValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DumpValue::Null => f.write_str("NULL"),
            DumpValue::Int(i) => write!(f, "{i}"),
            DumpValue::Text(s) => write!(f, "{s:?}"),
            DumpValue::Blob(b) => write!(f, "blob({} bytes, {})", b.len(), &checksum(b)[..12]),
        }
    }
}

/// Every row of every canonical table, rows sorted, `meta` without the store's own keys
/// (`schema_*`, `backup_*`). Two stores hold the same organisation exactly when their dumps
/// are equal; the conformance suite and TM27's verification compare dumps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalDump {
    pub tables: Vec<(&'static str, Vec<Vec<DumpValue>>)>,
}

impl LogicalDump {
    pub fn rows(&self, table: &str) -> &[Vec<DumpValue>] {
        self.tables
            .iter()
            .find(|(t, _)| *t == table)
            .map(|(_, r)| r.as_slice())
            .unwrap_or(&[])
    }

    /// SHA-256 hex over a canonical rendering of every row (TM27's table hashes).
    pub fn digest(&self) -> String {
        let mut out = Vec::new();
        for (t, rows) in &self.tables {
            out.extend_from_slice(t.as_bytes());
            out.push(0);
            for row in rows {
                for v in row {
                    match v {
                        DumpValue::Null => out.push(b'n'),
                        DumpValue::Int(i) => {
                            out.push(b'i');
                            out.extend_from_slice(&i.to_be_bytes());
                        }
                        DumpValue::Text(s) => {
                            out.push(b't');
                            out.extend_from_slice(&(s.len() as u64).to_be_bytes());
                            out.extend_from_slice(s.as_bytes());
                        }
                        DumpValue::Blob(b) => {
                            out.push(b'b');
                            out.extend_from_slice(&(b.len() as u64).to_be_bytes());
                            out.extend_from_slice(b);
                        }
                    }
                }
                out.push(b'\n');
            }
        }
        checksum(&out)
    }
}

/// Whether a `meta` key belongs in a logical dump and a canonical export: not the store's
/// schema bookkeeping, not the backup's own state, not a bootstrap token (it opens this
/// server, not the organisation, and is gone once the organisation exists).
pub fn canonical_meta_key(key: &str) -> bool {
    !key.starts_with(meta_keys::SCHEMA_PREFIX)
        && !key.starts_with(meta_keys::BACKUP_PREFIX)
        && !key.starts_with(meta_keys::BOOTSTRAP_PREFIX)
}

/// Token hashes are SHA-256 as 64 lower-case hex characters (§4.10); anything else (a token
/// itself, say) is refused before it reaches a column.
pub fn valid_token_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `t` rounded down to the hour (the "hour" columns of §4.2).
pub fn hour(t: i64) -> i64 {
    t - t.rem_euclid(3_600)
}

// ---------------------------------------------------------------------------------------------
// The trait

/// Server-side storage of one organisation: members, devices, invites, opaque record blobs,
/// the deletion stream, wraps, the audit log and server state (plan-v3-team §4.2).
///
/// Validation that needs no stored state (body sizes, schemas, envelope structure, tags a
/// caller may write, the `Awm-Client` gate, rate limits) is TM8's; checks that depend on
/// stored state run inside the store's transaction, so concurrent requests cannot race them.
pub trait Store: Send + Sync + 'static {
    // --- server state ------------------------------------------------------------------------

    /// `generation` and the restore state: `GET /v1/info`, `GET /v1/status`, and TM8's
    /// 503 `restore_pending` gate.
    fn restore_state(&self) -> StoreFuture<'_, RestoreState>;

    /// Writes a new random `generation`, sets `restore_pending` and `restored_at`, and audits
    /// `restore`: `awm serve restore` and `--mark-restored` (TM27, `docs/sync-v1.md` §11).
    /// Returns the new generation.
    fn renew_generation(&self, now: i64) -> StoreFuture<'_, Id>;

    /// `POST /v1/restore/complete`: clears `restore_pending` when `generation` is the current
    /// one (idempotent), else `InvalidValue { field: "/generation" }`.
    fn complete_restore(&self, generation: Id, by: Actor, now: i64) -> StoreFuture<'_, ()>;

    /// Reads a `meta` key: the backup cursor and last verification (TM27), `last_retention`
    /// (TM9), and any key in [`meta_keys`].
    fn meta_get(&self, key: String) -> StoreFuture<'_, Option<String>>;

    /// Writes a `meta` key that the store does not own ([`meta_keys::reserved`] keys give
    /// `InvalidValue`). Keys starting with `backup_` are not logged in `backup_log`.
    fn meta_set(&self, key: String, value: String) -> StoreFuture<'_, ()>;

    // --- organisation and bootstrap ----------------------------------------------------------

    /// The organisation, `None` before bootstrap: `awm serve init` and `check` (TM15), TM7
    /// (the organisation in a token must be this one), `GET /v1/org/settings`.
    fn org(&self, now: i64) -> StoreFuture<'_, Option<OrgRow>>;

    /// Stores the bootstrap token's hash and expiry: `awm serve init` (TM15) or, on path A,
    /// the `AWM_BOOTSTRAP_SHA256` value at start (TM28). `NotEmpty` once the organisation
    /// exists; a second call before bootstrap replaces the first.
    fn set_bootstrap(&self, token_hash: String, expires_at: i64) -> StoreFuture<'_, ()>;

    /// `POST /v1/bootstrap`: compares the token hash with the stored one (`Gone` when absent,
    /// different, expired or already used, or when the organisation exists), then creates the
    /// organisation, the admin member and its approved device, consumes the token and audits
    /// `bootstrap`, in one transaction (two concurrent uses create one admin, TM7).
    fn bootstrap(&self, req: NewBootstrap) -> StoreFuture<'_, Id>;

    // --- authentication (TM7) ----------------------------------------------------------------

    /// The device whose token hashes to `token_hash`, looked up by hash only; `None` when no
    /// device has it (TM7 answers 401, also for revoked rows).
    fn auth_device(&self, token_hash: String) -> StoreFuture<'_, Option<AuthDevice>>;

    /// Records the day a device was last seen; writes only when the day changed (TM7).
    fn touch_device(&self, device_id: Id, day: i64) -> StoreFuture<'_, ()>;

    /// `POST /v1/token/rotate`: replaces the device's token hash (the old token stops at
    /// once) and audits `token.rotate`. `NotFound` for an unknown or revoked device.
    fn rotate_token(&self, device_id: Id, token_hash: String, now: i64) -> StoreFuture<'_, ()>;

    /// A device (approval authorisation, TM7: the invite's creator approves).
    fn device(&self, device_id: Id) -> StoreFuture<'_, Option<DeviceRow>>;

    /// A member (TM7, TM8).
    fn member(&self, member_id: Id) -> StoreFuture<'_, Option<MemberRow>>;

    /// The active member with that handle (TM7: a member's device invite names themselves).
    fn member_by_handle(&self, handle: Handle) -> StoreFuture<'_, Option<MemberRow>>;

    // --- invites, joins, approvals -----------------------------------------------------------

    /// `POST /v1/invites`. `member` kind: the handle must not be an active member's
    /// (`InvalidValue /handle`), and active members plus open member invites must stay below
    /// `max_members` (`Forbidden`); `device` kind: the handle must be an active member's
    /// (`InvalidValue /handle`) and `role` absent (`InvalidValue /role`). Audits `invite.create`.
    fn create_invite(&self, invite: NewInvite) -> StoreFuture<'_, ()>;

    /// An invite (TM7: `DELETE /v1/invites/{id}` is for an admin or the creator).
    fn invite(&self, invite_id: Id) -> StoreFuture<'_, Option<InviteRow>>;

    /// `DELETE /v1/invites/{id}`: revokes an unused invite (idempotent; `NotFound` for an
    /// unknown id) and audits `invite.revoke`.
    fn revoke_invite(&self, invite_id: Id, by: Actor, now: i64) -> StoreFuture<'_, ()>;

    /// `POST /v1/join`: the invite (by id and token hash) must be unused, unrevoked and
    /// unexpired (`Gone`), the handle must equal the invite's (`InvalidValue /handle`), the
    /// device id must be new (`DeviceConflict`); creates the member (member invite) and the
    /// pending device, marks the invite used and audits `join`, in one transaction.
    fn join(&self, req: NewJoin) -> StoreFuture<'_, Joined>;

    /// `POST /v1/devices/{id}/approve`: stores the wraps idempotently by (device, epoch) (the
    /// first stays), requires a wrap for every epoch from 0 to current afterwards
    /// (`InvalidValue /wraps`; an epoch above current is `InvalidValue /wraps/{i}/epoch`),
    /// marks the device approved and audits `approve`. `NotFound` for an unknown device,
    /// `Forbidden` for a revoked one. `created_by` is the approving device.
    fn approve_device(
        &self,
        device_id: Id,
        wraps: Vec<EpochWrap>,
        by: Actor,
        now: i64,
    ) -> StoreFuture<'_, ()>;

    /// `POST /v1/devices/{id}/revoke`: revokes the device (idempotent), sets
    /// `rotation_needed` and audits `device.revoke`. `NotFound` for an unknown device.
    fn revoke_device(&self, device_id: Id, by: Actor, now: i64) -> StoreFuture<'_, ()>;

    /// `POST /v1/members/{id}/remove`: `LastAdmin` for the only active admin; revokes the
    /// member, every device and its open invites, sets `rotation_needed`, with
    /// `delete_records` deletes every record of the member except its `roster` records
    /// (deletion-stream entries; TM9 F2), audits `member.remove`. Idempotent. Returns the
    /// number of records deleted.
    fn remove_member(
        &self,
        member_id: Id,
        delete_records: bool,
        by: Actor,
        now: i64,
    ) -> StoreFuture<'_, u64>;

    /// `POST /v1/members/{id}/role`, and `awm serve promote` (with `by` = `None`):
    /// `LastAdmin` when it would leave no active admin, `NotFound` for an unknown or removed
    /// member, `InvalidValue /role` for `Unknown`. Audits `member.role`.
    fn set_role(
        &self,
        member_id: Id,
        role: Role,
        by: Option<Actor>,
        now: i64,
    ) -> StoreFuture<'_, ()>;

    /// `GET /v1/members`: every member with its devices, in creation order.
    fn members(&self) -> StoreFuture<'_, Vec<MemberInfo>>;

    // --- keys --------------------------------------------------------------------------------

    /// `GET /v1/keys` for the calling device.
    fn keys(&self, device_id: Id) -> StoreFuture<'_, KeysResponse>;

    /// `POST /v1/keys/rotate`: `EpochConflict` unless `epoch` is current + 1; every wrap must
    /// name a distinct, listed, non-revoked device (`InvalidValue /wraps/{i}/device_id`);
    /// stores the wraps, sets the epoch, clears `rotation_needed`, audits `keys.rotate`.
    fn rotate_keys(
        &self,
        epoch: u32,
        wraps: Vec<DeviceWrap>,
        by: Actor,
        now: i64,
    ) -> StoreFuture<'_, ()>;

    // --- status and settings -----------------------------------------------------------------

    /// `GET /v1/status` for the calling device, read in one snapshot: ids, role, approval,
    /// epoch, `rotation_needed`, `restore_pending`, settings, every stream's head, the
    /// deletion-stream heads, and pending devices (every one for an admin, the member's own
    /// otherwise). `NotFound` for an unknown device.
    fn status(&self, device_id: Id, now: i64) -> StoreFuture<'_, StatusResponse>;

    /// `PUT /v1/org/settings` (`docs/sync-v1.md` §10.4): `retention_days` ≥ 30 (a decrease
    /// becomes pending for 7 days, an increase applies at once and cancels a pending
    /// decrease), `cancel_pending_retention`, `min_client` raise only and never below `floor`,
    /// `max_members` ≥ 1; each refusal is `InvalidValue` naming the field. Audits `settings`.
    /// Returns the settings after the change.
    fn update_settings(
        &self,
        update: SettingsUpdate,
        floor: Version,
        by: Option<Actor>,
        now: i64,
    ) -> StoreFuture<'_, OrgSettings>;

    // --- records -----------------------------------------------------------------------------

    /// `POST /v1/records`, `docs/sync-v1.md` §9.1 steps 4 and 5: each item in request order
    /// against the stream state including the items before it (replay, conflict, deleted, id
    /// taken, contiguity, epoch); all items stored in one transaction or none; a marker for an
    /// id not yet in the deletion stream appends it there. Returns the touched streams' heads.
    fn push(&self, batch: PushBatch) -> StoreFuture<'_, PushResponse>;

    /// The head of one stream (-1 when it does not exist).
    fn stream_head(&self, member_id: Id, device_id: Id, tag: Tag) -> StoreFuture<'_, i64>;

    /// `GET /v1/records`: at most `limit` items from `from` upward, cut before the encoded
    /// response would exceed `max_bytes`, with the stream's head.
    fn records(
        &self,
        member_id: Id,
        device_id: Id,
        tag: Tag,
        from: u64,
        limit: u32,
        max_bytes: usize,
    ) -> StoreFuture<'_, StreamRecords>;

    /// `POST /v1/pull` (`docs/sync-v1.md` §8.4): cursors served in request order, in one
    /// snapshot, until `limit` records in total or `max_bytes` encoded; `more` as §8.4 says.
    /// TM8 checks the cursor count and duplicates first.
    fn pull(
        &self,
        cursors: Vec<awm_proto::wire::Cursor>,
        limit: u32,
        max_bytes: usize,
    ) -> StoreFuture<'_, PullResponse>;

    /// Records pushed by the member since `since` (the daily quota, TM8): record items
    /// received since then plus ids the member pre-deleted since then; markers do not count.
    fn pushed_since(&self, member_id: Id, since: i64) -> StoreFuture<'_, u64>;

    // --- deletion and retention (TM9) --------------------------------------------------------

    /// `POST /v1/delete` (`docs/sync-v1.md` §10): `Ids` — `Forbidden` for the whole request
    /// when any held id belongs to another member and `by` is not an admin; held records lose
    /// their blob and keep a marker; ids not held are pre-deleted, bound to `by`'s member;
    /// `AllMine` — every held record of `by`'s member; `Member` — every held record of that
    /// member (admin only, `NotFound` for an unknown member). Each newly deleted id gets one
    /// deletion-stream entry; ids already there count in `already`. Audits `delete`.
    ///
    /// `roster` records are never deleted (TM9 F2; crypto §7: a joiner verifies the roster
    /// from the genesis): `AllMine` and `Member` skip them, and `Ids` naming a held roster
    /// record fails as a whole with `InvalidValue { field: "/ids" }`, nothing deleted.
    fn delete(&self, req: DeleteRequest, by: Actor, now: i64) -> StoreFuture<'_, DeleteResponse>;

    /// Retention: deletes at most `limit` records whose `received_at` is before `cutoff`,
    /// oldest first, each with a deletion-stream entry, in one transaction; `roster` records
    /// are never selected (TM9 F1). Returns how many; TM9 loops while it returns `limit` and
    /// audits once per run with [`Store::append_audit`].
    fn retention_batch(&self, cutoff: i64, limit: u32, now: i64) -> StoreFuture<'_, u64>;

    /// Removes deletion-stream entries deleted before `before` (retention + 30 days, §3.7),
    /// always keeping the newest entry so that the head never moves back.
    fn prune_deletions(&self, before: i64) -> StoreFuture<'_, u64>;

    /// Removes audit rows before `before` (400 days, §5.5), keeping the newest row.
    fn prune_audit(&self, before: i64) -> StoreFuture<'_, u64>;

    /// After a deletion batch: `SqliteStore` runs `wal_checkpoint(TRUNCATE)` so that, with
    /// `secure_delete`, the deleted bytes leave the file (§5.6); `PgStore` runs `VACUUM`.
    fn checkpoint(&self) -> StoreFuture<'_, ()>;

    /// `GET /v1/deletions`: at most `limit` entries from `from`, with `head` and `oldest`.
    fn deletions(&self, from: u64, limit: u32) -> StoreFuture<'_, DeletionsResponse>;

    /// The deletion stream's `head` and `oldest` (`GET /v1/status`, TM9 tests).
    fn deletion_heads(&self) -> StoreFuture<'_, DeletionHeads>;

    // --- audit -------------------------------------------------------------------------------

    /// Appends an audit row (TM8: `export`, bulk-delete notices; TM9: `retention` counts).
    /// Returns its index.
    fn append_audit(&self, entry: AuditEntry) -> StoreFuture<'_, u64>;

    /// `GET /v1/audit`: at most `limit` rows from `from`, with the head.
    fn audit(&self, from: u64, limit: u32) -> StoreFuture<'_, AuditResponse>;

    // --- export, import, dumps ---------------------------------------------------------------

    /// `GET /v1/export`, `awm serve backup --to FILE`, `PgStore`'s daily export: writes the
    /// organisation as a canonical SQLite file (schema 0001, no `backup_log` rows, no
    /// `backup_*` meta keys) to `dest`, which must not exist; mode 0600.
    fn export_canonical(&self, dest: PathBuf) -> StoreFuture<'_, TableCounts>;

    /// Imports a canonical file into this store, which must hold no organisation
    /// (`NotEmpty`). Every row is copied as it is, `generation` included; a restore then calls
    /// [`Store::renew_generation`] (TM27, TM26).
    fn import_canonical(&self, src: PathBuf) -> StoreFuture<'_, TableCounts>;

    /// Every row of every canonical table, sorted ([`LogicalDump`]).
    fn dump(&self) -> StoreFuture<'_, LogicalDump>;

    // --- incremental backup (`SqliteStore` only, TM27) ---------------------------------------

    /// The highest `backup_log` sequence number (0 when the log is empty and was never used).
    fn backup_log_head(&self) -> StoreFuture<'_, i64> {
        Box::pin(async { Err(StoreError::Unsupported("backup_log")) })
    }

    /// `backup_log` rows after `after`, ascending, at most `limit`.
    fn backup_log(&self, after: i64, limit: u32) -> StoreFuture<'_, Vec<BackupLogRow>> {
        let _ = (after, limit);
        Box::pin(async { Err(StoreError::Unsupported("backup_log")) })
    }

    /// Removes `backup_log` rows up to and including `upto` (after a full snapshot covers them).
    fn prune_backup_log(&self, upto: i64) -> StoreFuture<'_, u64> {
        let _ = upto;
        Box::pin(async { Err(StoreError::Unsupported("backup_log")) })
    }

    /// A full snapshot: a `VACUUM INTO` copy of the whole database (with `backup_log` and
    /// every `meta` key) at `dest`, mode 0600. Returns the `backup_log` head inside the copy.
    fn snapshot(&self, dest: PathBuf) -> StoreFuture<'_, i64> {
        let _ = dest;
        Box::pin(async { Err(StoreError::Unsupported("snapshot")) })
    }

    /// An incremental change set: a SQLite file at `dest` in the 0001 schema (without
    /// triggers) holding the `backup_log` rows after `after` and, read in the same snapshot,
    /// the current row of every key they name that still exists.
    fn export_changes(&self, after: i64, dest: PathBuf) -> StoreFuture<'_, ChangeSet> {
        let _ = (after, dest);
        Box::pin(async { Err(StoreError::Unsupported("export_changes")) })
    }

    /// Applies a change set made by [`Store::export_changes`] (restore, TM27): every key it
    /// names is replaced by the file's row, or deleted when the file has none, in one
    /// transaction.
    fn apply_changes(&self, src: PathBuf) -> StoreFuture<'_, ChangeSet> {
        let _ = src;
        Box::pin(async { Err(StoreError::Unsupported("apply_changes")) })
    }
}

// ---------------------------------------------------------------------------------------------
// SHA-256 for migration checksums and dump digests (`sha2`, TM6 request 1, TM7). Token hashes
// use the same function through `auth::hash`.

/// SHA-256 of `data` as 64 lower-case hex characters.
pub fn checksum(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_the_fips_180_4_vectors() {
        assert_eq!(
            checksum(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            checksum(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            checksum(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            checksum(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn every_store_error_that_answers_a_request_has_its_status() {
        let cases = [
            (StoreError::NotFound, 404),
            (StoreError::InvalidValue { field: "/x".into() }, 400),
            (StoreError::Forbidden, 403),
            (StoreError::Gone, 410),
            (StoreError::DeviceConflict, 409),
            (StoreError::LastAdmin, 409),
            (StoreError::EpochConflict { current_epoch: 1 }, 409),
            (StoreError::StreamConflict { item: 0, head: 3 }, 409),
            (StoreError::IdConflict { item: 0 }, 409),
            (
                StoreError::StaleEpoch {
                    item: 0,
                    current_epoch: 2,
                },
                409,
            ),
            (
                StoreError::Deleted {
                    item: 0,
                    ids: vec![],
                },
                410,
            ),
            (StoreError::NotEmpty, 500),
            (StoreError::Unsupported("x"), 500),
            (StoreError::Backend("x".into()), 500),
        ];
        for (e, status) in cases {
            assert_eq!(e.status(), status, "{e:?}");
            assert_eq!(e.to_body().is_some(), status != 500, "{e:?}");
        }
    }
}
