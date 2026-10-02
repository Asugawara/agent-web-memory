//! `SqliteStore`: one SQLite file `{data}/server.db` per organisation (plan-v3-team §4.2,
//! paths B, C and D of §3.9; TM6).
//!
//! File modes (unix): the data directory is created 0700 and `server.db` 0600 before SQLite
//! opens it; SQLite gives the `-wal` and `-shm` files the database file's mode. Every file the
//! store writes (migration backups, exports, snapshots, change sets) is created 0600 first.
//!
//! Connections: one writer behind a mutex, which every write transaction takes with
//! `BEGIN IMMEDIATE` (so stream and deletion-stream indexes are assigned by one writer at a
//! time, also against another process on the same file), and a small pool of `query_only`
//! readers whose deferred transactions give each read one WAL snapshot. Blocking SQLite calls
//! run on tokio's blocking pool. Pragmas: WAL, `synchronous = FULL` (an acknowledged push
//! survives a power cut), `foreign_keys = ON`, `secure_delete = ON`, `busy_timeout` 5 s.
//!
//! Migrations follow the client's rules (`crates/awm/src/db.rs`, plan-v2 §6.2): checksums of
//! every applied file, no downgrade, a `VACUUM INTO` backup to a 0600 temporary file before
//! `BEGIN IMMEDIATE` when the database holds data, the version re-checked under the lock,
//! foreign keys off around the transaction and `PRAGMA foreign_key_check` before `COMMIT`,
//! `PRAGMA quick_check` after. The version and checksums live in `meta` (`schema_version`,
//! `schema_checksum.{version}`).

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use awm_proto::wire::{
    limits, AuditResponse, AuditRow, Cursor, DeleteRequest, DeleteResponse, DeletionEntry,
    DeletionHeads, DeletionsResponse, DeviceInfo, DeviceWrap, EpochWrap, Handle, Id, InviteKind,
    Key32, KeysResponse, MemberInfo, OrgSettings, OwnHead, PendingDevice, PendingRetention,
    PullResponse, PulledDeleted, PulledItem, PulledRecord, PushItem, PushResponse, Role,
    SettingsUpdate, StatusResponse, StoredWrap, StreamHead, StreamRecords, Tag, Version, B64,
};
use rusqlite::types::{Type, ValueRef};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Row, Transaction, TransactionBehavior,
};

use super::{
    canonical_meta_key, checksum, hour, meta_keys, valid_token_hash, Actor, AuditEntry, AuthDevice,
    BackupLogRow, ChangeSet, DeviceRow, DumpValue, InviteRow, Joined, LogicalDump, MemberRow,
    NewBootstrap, NewInvite, NewJoin, OrgRow, PushBatch, RestoreState, Store, StoreError,
    StoreFuture, StoreResult, TableCounts, CANONICAL_TABLES,
};

/// Embedded migrations: (version, name, SQL). Versions start at 1 and increase by one; there
/// are no down migrations.
pub const MIGRATIONS: &[(u32, &str, &str)] = &[(
    1,
    "0001_server",
    include_str!("../../migrations/sqlite/0001_server.sql"),
)];

/// The database file inside the data directory (plan-v3-team §3.9.2).
pub const DB_FILE: &str = "server.db";

const BUSY_TIMEOUT: Duration = Duration::from_millis(5_000);
const READERS: usize = 4;

/// The key expression `backup_log.key` holds for each logged table (the triggers of 0001).
const LOG_KEYS: &[(&str, &str)] = &[
    ("org", "id"),
    ("member", "id"),
    ("device", "id"),
    ("invite", "id"),
    ("record", "id"),
    ("deletion", "CAST(idx AS TEXT)"),
    ("wrap", "device_id || '/' || epoch"),
    ("audit", "CAST(idx AS TEXT)"),
    ("meta", "key"),
];

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> StoreError {
        // SQLite's messages name constraints and columns, never bound values.
        StoreError::Backend(format!("sqlite: {e}"))
    }
}

fn io_err(what: &str, path: &Path, e: std::io::Error) -> StoreError {
    StoreError::Backend(format!("{what} {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------------------------
// Files, connections and migrations

/// Creates `dir` (and missing parents) with mode 0700 when it does not exist.
fn ensure_private_dir(dir: &Path) -> StoreResult<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| io_err("cannot create directory", dir, e))?;
    // The umask can only remove bits; set the mode explicitly so it is exactly 0700.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| io_err("cannot set mode 0700 on", dir, e))?;
    }
    Ok(())
}

/// Creates an empty file with mode 0600; fails if `path` already exists.
fn create_new_private_file(path: &Path) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn path_str(path: &Path) -> StoreResult<&str> {
    path.to_str()
        .ok_or_else(|| StoreError::Backend(format!("path is not UTF-8: {}", path.display())))
}

/// Opens (creating when missing: the parent 0700, the file 0600) the database at `path` and
/// sets the connection pragmas: WAL, `synchronous = FULL`, `foreign_keys = ON`,
/// `secure_delete = ON`, `busy_timeout` 5 s. Does not migrate.
pub fn open_connection(path: &Path) -> StoreResult<Connection> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        ensure_private_dir(parent)?;
    }
    match create_new_private_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            return Err(io_err("cannot create", path, e));
        }
        _ => {}
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    set_wal(&conn, path)?;
    conn.execute_batch(
        "PRAGMA synchronous=FULL;\n\
         PRAGMA foreign_keys=ON;\n\
         PRAGMA secure_delete=ON;",
    )?;
    Ok(conn)
}

/// Switches a new file to WAL. Two connections switching one new (rollback-mode) file at once
/// can get `SQLITE_BUSY` without the busy handler (SQLite's deadlock avoidance when upgrading
/// a shared lock), so a busy answer is retried until `BUSY_TIMEOUT`.
fn set_wal(conn: &Connection, path: &Path) -> StoreResult<()> {
    let deadline = std::time::Instant::now() + BUSY_TIMEOUT;
    loop {
        match conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get::<_, String>(0)) {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => return Ok(()),
            Ok(mode) => {
                return Err(StoreError::Backend(format!(
                    "cannot set journal_mode=WAL on {} (got {mode})",
                    path.display()
                )))
            }
            Err(rusqlite::Error::SqliteFailure(f, _))
                if f.code == rusqlite::ErrorCode::DatabaseBusy
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(StoreError::Backend(format!(
                    "cannot set journal_mode=WAL on {}: {e}",
                    path.display()
                )))
            }
        }
    }
}

fn open_reader(path: &Path) -> StoreResult<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.execute_batch("PRAGMA query_only=ON;")?;
    Ok(conn)
}

/// Result of [`migrate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrateOutcome {
    /// Schema version before the call.
    pub from: u32,
    /// Schema version after the call.
    pub to: u32,
    /// The `{db}.bak-v{from}` file written before migrating, if any.
    pub backup: Option<PathBuf>,
}

fn table_exists(conn: &Connection, name: &str) -> StoreResult<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn meta_value(conn: &Connection, key: &str) -> StoreResult<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()?)
}

/// The applied schema version: `meta.schema_version`, or 0 before migration 0001.
pub fn schema_version(conn: &Connection) -> StoreResult<u32> {
    if !table_exists(conn, "meta")? {
        return Ok(0);
    }
    match meta_value(conn, meta_keys::SCHEMA_VERSION)? {
        None => Ok(0),
        Some(v) => v
            .parse()
            .map_err(|_| StoreError::Backend("meta.schema_version is not a number".to_string())),
    }
}

fn checksum_key(version: u32) -> String {
    format!("{}checksum.{version}", meta_keys::SCHEMA_PREFIX)
}

/// Applies the embedded [`MIGRATIONS`].
pub fn migrate(conn: &mut Connection) -> StoreResult<MigrateOutcome> {
    migrate_with(conn, MIGRATIONS)
}

/// Applies `migrations` (versions 1, 2, ... in order) under the client's rules (module docs).
pub fn migrate_with(
    conn: &mut Connection,
    migrations: &[(u32, &str, &str)],
) -> StoreResult<MigrateOutcome> {
    validate_list(migrations)?;
    let from = verify_applied(conn, migrations)?;
    let pending: Vec<&(u32, &str, &str)> =
        migrations.iter().filter(|(v, _, _)| *v > from).collect();
    if pending.is_empty() {
        return Ok(MigrateOutcome {
            from,
            to: from,
            backup: None,
        });
    }
    // Data is present once any migration was applied (0001 creates the tables).
    let backup = if from > 0 {
        Some(backup(conn, from)?)
    } else {
        None
    };
    let fk_on = foreign_keys(conn)?;
    if fk_on {
        set_foreign_keys(conn, false)?;
    }
    let applied = apply_pending(conn, migrations, from, &pending);
    if fk_on {
        let restored = set_foreign_keys(conn, true);
        applied?;
        restored?;
    } else {
        applied?;
    }
    quick_check(conn, backup.as_deref())?;
    Ok(MigrateOutcome {
        from,
        to: binary_version(migrations),
        backup,
    })
}

fn apply_pending(
    conn: &mut Connection,
    migrations: &[(u32, &str, &str)],
    from: u32,
    pending: &[&(u32, &str, &str)],
) -> StoreResult<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Another process may have migrated between the checks above and the lock.
    let locked_from = verify_applied(&tx, migrations)?;
    if locked_from != from {
        return Err(StoreError::Backend(format!(
            "the database schema changed during the migration (version {from} -> {locked_from}); \
             run the command again"
        )));
    }
    for (version, name, sql) in pending {
        tx.execute_batch(sql)
            .map_err(|e| StoreError::Backend(format!("migration {name} failed: {e}")))?;
        meta_put(&tx, meta_keys::SCHEMA_VERSION, &version.to_string())?;
        meta_put(&tx, &checksum_key(*version), &checksum(sql.as_bytes()))?;
    }
    foreign_key_check(&tx, "main")?;
    tx.commit()?;
    Ok(())
}

fn foreign_keys(conn: &Connection) -> StoreResult<bool> {
    Ok(conn.query_row("PRAGMA foreign_keys", [], |r| r.get::<_, i64>(0))? == 1)
}

fn set_foreign_keys(conn: &Connection, on: bool) -> StoreResult<()> {
    conn.execute_batch(if on {
        "PRAGMA foreign_keys=ON"
    } else {
        "PRAGMA foreign_keys=OFF"
    })?;
    if foreign_keys(conn)? != on {
        return Err(StoreError::Backend(format!(
            "cannot set PRAGMA foreign_keys={}",
            if on { "ON" } else { "OFF" }
        )));
    }
    Ok(())
}

/// Refuses to commit a transaction that leaves a row violating a foreign key.
fn foreign_key_check(conn: &Connection, schema: &str) -> StoreResult<()> {
    let mut st = conn.prepare(&format!("PRAGMA {schema}.foreign_key_check"))?;
    let rows: Vec<String> = st
        .query_map([], |r| {
            Ok(format!(
                "{} rowid {} -> {}",
                r.get::<_, String>(0)?,
                r.get::<_, Option<i64>>(1)?
                    .map_or_else(|| "?".to_string(), |v| v.to_string()),
                r.get::<_, String>(2)?
            ))
        })?
        .collect::<Result<_, _>>()?;
    if !rows.is_empty() {
        let shown: Vec<&str> = rows.iter().take(5).map(String::as_str).collect();
        return Err(StoreError::Backend(format!(
            "refused: {} row(s) violate a foreign key ({}); nothing was changed",
            rows.len(),
            shown.join("; ")
        )));
    }
    Ok(())
}

fn binary_version(migrations: &[(u32, &str, &str)]) -> u32 {
    migrations.last().map_or(0, |(v, _, _)| *v)
}

fn validate_list(migrations: &[(u32, &str, &str)]) -> StoreResult<()> {
    for (i, (version, name, _)) in migrations.iter().enumerate() {
        if usize::try_from(*version).ok() != Some(i + 1) {
            return Err(StoreError::Backend(format!(
                "embedded migration {name} has version {version}, expected {}",
                i + 1
            )));
        }
    }
    Ok(())
}

/// Refuses a newer database, a missing checksum or a checksum mismatch; returns the version.
fn verify_applied(conn: &Connection, migrations: &[(u32, &str, &str)]) -> StoreResult<u32> {
    let db = schema_version(conn)?;
    let bin = binary_version(migrations);
    if db > bin {
        return Err(StoreError::Backend(format!(
            "server database is from a newer awm ({db}, this binary knows {bin}). Upgrade awm."
        )));
    }
    for (version, name, sql) in migrations.iter().filter(|(v, _, _)| *v <= db) {
        let stored = meta_value(conn, &checksum_key(*version))?.ok_or_else(|| {
            StoreError::Backend(format!(
                "migration {name} has no checksum in meta (database at version {db})"
            ))
        })?;
        let embedded = checksum(sql.as_bytes());
        if stored != embedded {
            return Err(StoreError::Backend(format!(
                "checksum mismatch for migration {name}: the database records {stored}, \
                 this awm embeds {embedded}; refusing to migrate"
            )));
        }
    }
    Ok(db)
}

fn unique_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{}-{nanos}", std::process::id())
}

/// Writes `{db}.bak-v{from}` with `VACUUM INTO` through a new 0600 temporary file, checks the
/// copy is at version `from`, then renames it over any older backup and syncs the directory.
fn backup(conn: &Connection, from: u32) -> StoreResult<PathBuf> {
    let db = conn
        .path()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| StoreError::Backend("cannot back up a database without a file".into()))?;
    let target = PathBuf::from(format!("{db}.bak-v{from}"));
    let tmp = PathBuf::from(format!("{db}.bak-v{from}.tmp-{}", unique_suffix()));
    create_new_private_file(&tmp).map_err(|e| io_err("cannot create", &tmp, e))?;
    let result = (|| {
        conn.execute("VACUUM INTO ?1", [path_str(&tmp)?])?;
        sync_file(&tmp)?;
        let copied = {
            let copy = Connection::open_with_flags(
                &tmp,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            schema_version(&copy)?
        };
        if copied != from {
            return Err(StoreError::Backend(format!(
                "the database schema changed during the migration (version {from} -> {copied}); \
                 run the command again"
            )));
        }
        std::fs::rename(&tmp, &target).map_err(|e| io_err("cannot move backup to", &target, e))?;
        sync_dir(&target)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map(|()| target)
}

fn sync_file(path: &Path) -> StoreResult<()> {
    std::fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| io_err("cannot sync", path, e))
}

fn sync_dir(path: &Path) -> StoreResult<()> {
    #[cfg(unix)]
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::File::open(dir)
            .and_then(|f| f.sync_all())
            .map_err(|e| io_err("cannot sync directory", dir, e))?;
    }
    let _ = path;
    Ok(())
}

/// Runs after `COMMIT`: a failure means the migration is already applied.
fn quick_check(conn: &Connection, backup: Option<&Path>) -> StoreResult<()> {
    let mut st = conn.prepare("PRAGMA quick_check")?;
    let rows: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<_, _>>()?;
    if rows != ["ok"] {
        let restore = match backup {
            Some(b) => format!("the backup taken before migrating is {}", b.display()),
            None => "no backup was taken (the database held no data)".to_string(),
        };
        return Err(StoreError::Backend(format!(
            "PRAGMA quick_check failed after migration (the migration is already committed; \
             {restore}): {}",
            rows.join("; ")
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Column conversions (errors name the column, never its value)

#[derive(Debug)]
struct BadColumn(&'static str);

impl std::fmt::Display for BadColumn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "column {} holds an invalid value", self.0)
    }
}

impl std::error::Error for BadColumn {}

fn bad(i: usize, what: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(i, Type::Text, Box::new(BadColumn(what)))
}

fn id_at(r: &Row<'_>, i: usize) -> rusqlite::Result<Id> {
    let s: String = r.get(i)?;
    Id::parse(&s).map_err(|_| bad(i, "id"))
}

fn opt_id_at(r: &Row<'_>, i: usize) -> rusqlite::Result<Option<Id>> {
    match r.get::<_, Option<String>>(i)? {
        None => Ok(None),
        Some(s) => Id::parse(&s).map(Some).map_err(|_| bad(i, "id")),
    }
}

fn key_at(r: &Row<'_>, i: usize) -> rusqlite::Result<Key32> {
    let v: Vec<u8> = r.get(i)?;
    v.try_into().map(Key32).map_err(|_| bad(i, "32-byte key"))
}

fn opt_key_at(r: &Row<'_>, i: usize) -> rusqlite::Result<Option<Key32>> {
    match r.get::<_, Option<Vec<u8>>>(i)? {
        None => Ok(None),
        Some(v) => v
            .try_into()
            .map(|a| Some(Key32(a)))
            .map_err(|_| bad(i, "32-byte key")),
    }
}

fn handle_at(r: &Row<'_>, i: usize) -> rusqlite::Result<Handle> {
    let s: String = r.get(i)?;
    Handle::parse(&s).map_err(|_| bad(i, "handle"))
}

fn tag_at(r: &Row<'_>, i: usize) -> rusqlite::Result<Tag> {
    let s: String = r.get(i)?;
    Tag::parse(&s).map_err(|_| bad(i, "tag"))
}

fn role_at(r: &Row<'_>, i: usize) -> rusqlite::Result<Role> {
    match r.get::<_, String>(i)?.as_str() {
        "member" => Ok(Role::Member),
        "admin" => Ok(Role::Admin),
        _ => Err(bad(i, "role")),
    }
}

fn opt_role_at(r: &Row<'_>, i: usize) -> rusqlite::Result<Option<Role>> {
    match r.get::<_, Option<String>>(i)?.as_deref() {
        None => Ok(None),
        Some("member") => Ok(Some(Role::Member)),
        Some("admin") => Ok(Some(Role::Admin)),
        Some(_) => Err(bad(i, "role")),
    }
}

fn kind_at(r: &Row<'_>, i: usize) -> rusqlite::Result<InviteKind> {
    match r.get::<_, String>(i)?.as_str() {
        "member" => Ok(InviteKind::Member),
        "device" => Ok(InviteKind::Device),
        _ => Err(bad(i, "invite kind")),
    }
}

fn u32_at(r: &Row<'_>, i: usize) -> rusqlite::Result<u32> {
    let v: i64 = r.get(i)?;
    u32::try_from(v).map_err(|_| bad(i, "u32"))
}

fn u64_at(r: &Row<'_>, i: usize) -> rusqlite::Result<u64> {
    let v: i64 = r.get(i)?;
    u64::try_from(v).map_err(|_| bad(i, "u64"))
}

fn role_str(role: Role, field: &str) -> StoreResult<&'static str> {
    match role {
        Role::Member => Ok("member"),
        Role::Admin => Ok("admin"),
        Role::Unknown => Err(StoreError::InvalidValue {
            field: field.to_string(),
        }),
    }
}

fn i64_of(v: u64, field: impl FnOnce() -> String) -> StoreResult<i64> {
    // Indexes stay below 2^53 (`docs/sync-v1.md` §1).
    i64::try_from(v)
        .ok()
        .filter(|v| *v < (1_i64 << 53))
        .ok_or_else(|| StoreError::InvalidValue { field: field() })
}

fn check_hash(hash: &str, field: &str) -> StoreResult<()> {
    if valid_token_hash(hash) {
        Ok(())
    } else {
        Err(StoreError::InvalidValue {
            field: field.to_string(),
        })
    }
}

fn broken(what: &str) -> StoreError {
    StoreError::Backend(format!("broken invariant: {what}"))
}

// ---------------------------------------------------------------------------------------------
// Statements shared by several operations

fn meta_put(conn: &Connection, key: &str, value: &str) -> StoreResult<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value WHERE value <> excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn audit_tx(
    conn: &Connection,
    at: i64,
    actor: Option<Id>,
    action: &str,
    target: Option<String>,
    detail: Option<String>,
) -> StoreResult<i64> {
    conn.execute(
        "INSERT INTO audit (idx, at, actor, action, target, detail) \
         VALUES ((SELECT COALESCE(MAX(idx), -1) + 1 FROM audit), ?1, ?2, ?3, ?4, ?5)",
        params![at, actor.map(|a| a.to_string()), action, target, detail],
    )?;
    Ok(conn.query_row("SELECT MAX(idx) FROM audit", [], |r| r.get(0))?)
}

/// The organisation row as stored (`pending_retention` not yet promoted).
struct RawOrg {
    id: Id,
    created_at: i64,
    current_epoch: u32,
    rotation_needed: bool,
    retention_days: u32,
    min_client: Version,
    max_members: u32,
    pending: Option<(u32, i64)>,
}

impl RawOrg {
    /// The settings as they apply at `now`: a pending decrease whose 7 days are over is in
    /// force (it is also written back by the next settings change or retention run).
    fn effective(&self, now: i64) -> OrgSettings {
        match self.pending {
            Some((days, at)) if at <= now => OrgSettings {
                retention_days: days,
                min_client: self.min_client.clone(),
                max_members: self.max_members,
                pending_retention: None,
            },
            pending => OrgSettings {
                retention_days: self.retention_days,
                min_client: self.min_client.clone(),
                max_members: self.max_members,
                pending_retention: pending.map(|(retention_days, effective_at)| PendingRetention {
                    retention_days,
                    effective_at,
                }),
            },
        }
    }
}

fn load_org(conn: &Connection) -> StoreResult<Option<RawOrg>> {
    let row = conn
        .query_row(
            "SELECT id, created_at, current_epoch, rotation_needed, retention_days, min_client, \
                    max_members, pending_retention_days, pending_retention_at \
               FROM org",
            [],
            |r| {
                let min: String = r.get(5)?;
                let pending = match (r.get::<_, Option<i64>>(7)?, r.get::<_, Option<i64>>(8)?) {
                    (Some(d), Some(at)) => Some((u32::try_from(d).map_err(|_| bad(7, "u32"))?, at)),
                    _ => None,
                };
                Ok(RawOrg {
                    id: id_at(r, 0)?,
                    created_at: r.get(1)?,
                    current_epoch: u32_at(r, 2)?,
                    rotation_needed: r.get::<_, i64>(3)? == 1,
                    retention_days: u32_at(r, 4)?,
                    min_client: Version::parse(&min).map_err(|_| bad(5, "version"))?,
                    max_members: u32_at(r, 6)?,
                    pending,
                })
            },
        )
        .optional()?;
    Ok(row)
}

fn require_org(conn: &Connection) -> StoreResult<RawOrg> {
    load_org(conn)?.ok_or_else(|| broken("no organisation"))
}

/// Writes a due pending retention decrease into `retention_days`.
fn promote_retention(conn: &Connection, now: i64) -> StoreResult<()> {
    conn.execute(
        "UPDATE org SET retention_days = pending_retention_days, \
                        pending_retention_days = NULL, pending_retention_at = NULL \
          WHERE pending_retention_at IS NOT NULL AND pending_retention_at <= ?1",
        [now],
    )?;
    Ok(())
}

fn stream_head_tx(conn: &Connection, member: &str, device: &str, tag: &str) -> StoreResult<i64> {
    Ok(conn.query_row(
        "SELECT COALESCE(MAX(idx), -1) FROM record \
          WHERE member_id = ?1 AND device_id = ?2 AND tag = ?3",
        params![member, device, tag],
        |r| r.get(0),
    )?)
}

fn deletion_heads_tx(conn: &Connection) -> StoreResult<DeletionHeads> {
    let (min, max): (Option<i64>, Option<i64>) =
        conn.query_row("SELECT MIN(idx), MAX(idx) FROM deletion", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    let head = max.unwrap_or(-1);
    Ok(DeletionHeads {
        head,
        oldest: min.unwrap_or(head + 1),
    })
}

/// Appends `record_id` to the deletion stream at head + 1.
fn append_deletion(conn: &Connection, record_id: &str, member: &str, at: i64) -> StoreResult<()> {
    conn.prepare_cached(
        "INSERT INTO deletion (idx, record_id, member_id, deleted_at) \
         VALUES ((SELECT COALESCE(MAX(idx), -1) + 1 FROM deletion), ?1, ?2, ?3)",
    )?
    .execute(params![record_id, member, hour(at)])?;
    Ok(())
}

fn in_deletions(conn: &Connection, record_id: &str) -> StoreResult<Option<String>> {
    Ok(conn
        .prepare_cached("SELECT member_id FROM deletion WHERE record_id = ?1")?
        .query_row([record_id], |r| r.get(0))
        .optional()?)
}

/// Removes a held record's blob, keeps its marker, and appends its id to the deletion stream
/// unless it is there. Returns true when an entry was appended.
fn delete_held(conn: &Connection, record_id: &str, owner: &str, now: i64) -> StoreResult<bool> {
    conn.prepare_cached(
        "UPDATE record SET blob = NULL, deleted_at = ?2 WHERE id = ?1 AND blob IS NOT NULL",
    )?
    .execute(params![record_id, hour(now)])?;
    if in_deletions(conn, record_id)?.is_some() {
        return Ok(false);
    }
    append_deletion(conn, record_id, owner, now)?;
    Ok(true)
}

/// Deletes every held record of `member`; returns how many entries were appended.
fn delete_member_rows(conn: &Connection, member: &str, now: i64) -> StoreResult<u64> {
    let ids: Vec<String> = conn
        .prepare(
            "SELECT id FROM record WHERE member_id = ?1 AND blob IS NOT NULL \
              ORDER BY device_id, tag, idx",
        )?
        .query_map([member], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut n = 0;
    for id in ids {
        if delete_held(conn, &id, member, now)? {
            n += 1;
        }
    }
    Ok(n)
}

fn active_admins(conn: &Connection) -> StoreResult<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM member WHERE role = 'admin' AND revoked_at IS NULL",
        [],
        |r| r.get(0),
    )?)
}

fn member_row(r: &Row<'_>) -> rusqlite::Result<MemberRow> {
    Ok(MemberRow {
        member_id: id_at(r, 0)?,
        handle: handle_at(r, 1)?,
        role: role_at(r, 2)?,
        created_at: r.get(3)?,
        revoked_at: r.get(4)?,
    })
}

fn pulled_item(r: &Row<'_>) -> rusqlite::Result<PulledItem> {
    let idx = u64_at(r, 0)?;
    let id = id_at(r, 1)?;
    match r.get::<_, Option<Vec<u8>>>(3)? {
        None => Ok(PulledItem::Deleted(PulledDeleted { idx, id })),
        Some(blob) => Ok(PulledItem::Record(PulledRecord {
            idx,
            id,
            epoch: match r.get::<_, Option<i64>>(2)? {
                Some(e) => u32::try_from(e).map_err(|_| bad(2, "epoch"))?,
                None => return Err(bad(2, "epoch")),
            },
            blob: B64(blob),
            received_at: r.get(4)?,
        })),
    }
}

/// The encoded JSON length of `v` plus one byte for the separator.
fn json_len<T: serde::Serialize>(v: &T) -> usize {
    serde_json::to_vec(v).map_or(0, |b| b.len()) + 1
}

/// Reads a stream from `from` into `out`, at most `limit` items, while `budget` bytes last.
/// Returns true when the byte budget cut the read.
fn read_stream(
    conn: &Connection,
    out: &mut StreamRecords,
    from: i64,
    limit: u32,
    budget: &mut usize,
) -> StoreResult<bool> {
    let mut st = conn.prepare_cached(
        "SELECT idx, id, epoch, blob, received_at FROM record \
          WHERE member_id = ?1 AND device_id = ?2 AND tag = ?3 AND idx >= ?4 \
          ORDER BY idx LIMIT ?5",
    )?;
    let mut rows = st.query(params![
        out.member.to_string(),
        out.device.to_string(),
        out.tag.as_str(),
        from,
        limit
    ])?;
    while let Some(r) = rows.next()? {
        let item = pulled_item(r)?;
        let len = json_len(&item);
        if len > *budget {
            return Ok(true);
        }
        *budget -= len;
        out.records.push(item);
    }
    Ok(false)
}

fn dump_value(v: ValueRef<'_>) -> DumpValue {
    match v {
        ValueRef::Null => DumpValue::Null,
        ValueRef::Integer(i) => DumpValue::Int(i),
        // No column of the schema is REAL; render one exactly rather than drop it.
        ValueRef::Real(f) => DumpValue::Text(format!("real:{f:?}")),
        ValueRef::Text(t) => DumpValue::Text(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => DumpValue::Blob(b.to_vec()),
    }
}

fn dump_tx(conn: &Connection, schema: &str) -> StoreResult<LogicalDump> {
    let mut tables = Vec::new();
    for (table, cols) in CANONICAL_TABLES {
        let sql = format!("SELECT {} FROM {schema}.{table}", cols.join(", "));
        let mut st = conn.prepare(&sql)?;
        let mut rows = st.query([])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            let row: Vec<DumpValue> = (0..cols.len())
                .map(|i| r.get_ref(i).map(dump_value))
                .collect::<Result<_, _>>()?;
            if *table == "meta" {
                if let Some(DumpValue::Text(k)) = row.first() {
                    if !canonical_meta_key(k) {
                        continue;
                    }
                }
            }
            out.push(row);
        }
        out.sort();
        tables.push((*table, out));
    }
    Ok(LogicalDump { tables })
}

fn store_holds_org(conn: &Connection) -> StoreResult<bool> {
    let n: i64 = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM org) + (SELECT COUNT(*) FROM member) \
              + (SELECT COUNT(*) FROM device) + (SELECT COUNT(*) FROM invite) \
              + (SELECT COUNT(*) FROM record) + (SELECT COUNT(*) FROM deletion) \
              + (SELECT COUNT(*) FROM wrap) + (SELECT COUNT(*) FROM audit)",
        [],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// The canonical meta filter in SQL (for `meta` rows of an attached file).
const CANONICAL_META_SQL: &str = "key NOT LIKE 'schema\\_%' ESCAPE '\\' \
     AND key NOT LIKE 'backup\\_%' ESCAPE '\\' AND key NOT LIKE 'bootstrap\\_%' ESCAPE '\\'";

fn canonical_counts(conn: &Connection, schema: &str) -> StoreResult<TableCounts> {
    let mut out = Vec::new();
    for (table, _) in CANONICAL_TABLES {
        let filter = if *table == "meta" {
            format!(" WHERE {CANONICAL_META_SQL}")
        } else {
            String::new()
        };
        let n: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {schema}.{table}{filter}"),
            [],
            |r| r.get(0),
        )?;
        out.push((*table, u64::try_from(n).unwrap_or(0)));
    }
    Ok(TableCounts(out))
}

/// The schema of an attached file must be this binary's (the canonical format is versioned
/// with the migrations).
fn check_attached_schema(conn: &Connection, schema: &str) -> StoreResult<()> {
    let get = |key: &str| -> StoreResult<Option<String>> {
        Ok(conn
            .query_row(
                &format!("SELECT value FROM {schema}.meta WHERE key = ?1"),
                [key],
                |r| r.get(0),
            )
            .optional()?)
    };
    let bin = binary_version(MIGRATIONS);
    let version = get(meta_keys::SCHEMA_VERSION)?;
    if version.as_deref() != Some(bin.to_string().as_str()) {
        return Err(StoreError::Backend(format!(
            "the file is not in this binary's canonical format (schema {}, expected {bin})",
            version.as_deref().unwrap_or("none")
        )));
    }
    for (v, name, sql) in MIGRATIONS {
        if get(&checksum_key(*v))? != Some(checksum(sql.as_bytes())) {
            return Err(StoreError::Backend(format!(
                "the file's checksum for migration {name} differs from this binary's"
            )));
        }
    }
    Ok(())
}

/// Copies `src` (an attached file in the 0001 schema) into `main`, table by table in
/// [`CANONICAL_TABLES`] order. Foreign keys are deferred to the end of the transaction and
/// checked before it commits.
fn copy_canonical(tx: &Transaction<'_>, src: &str) -> StoreResult<TableCounts> {
    tx.execute_batch("PRAGMA defer_foreign_keys=ON")?;
    let mut out = Vec::new();
    for (table, cols) in CANONICAL_TABLES {
        let cols = cols.join(", ");
        let n = if *table == "meta" {
            // The importer keeps its own schema and backup keys; every other key is the file's.
            tx.execute(
                &format!(
                    "DELETE FROM main.meta WHERE {CANONICAL_META_SQL} \
                       AND key NOT IN (SELECT key FROM {src}.meta)"
                ),
                [],
            )?;
            tx.execute(
                &format!(
                    "INSERT INTO main.meta (key, value) SELECT key, value FROM {src}.meta \
                      WHERE {CANONICAL_META_SQL} \
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value \
                      WHERE value <> excluded.value"
                ),
                [],
            )?;
            tx.query_row(
                &format!("SELECT COUNT(*) FROM {src}.meta WHERE {CANONICAL_META_SQL}"),
                [],
                |r| r.get::<_, i64>(0),
            )? as usize
        } else {
            tx.execute(
                &format!("INSERT INTO main.{table} ({cols}) SELECT {cols} FROM {src}.{table}"),
                [],
            )?
        };
        out.push((*table, n as u64));
    }
    // A bootstrap token set on the importing server opens nothing once it holds an organisation.
    tx.execute(
        "DELETE FROM main.meta WHERE key LIKE 'bootstrap\\_%' ESCAPE '\\'",
        [],
    )?;
    foreign_key_check(tx, "main")?;
    Ok(TableCounts(out))
}

/// Attaches an existing file (ATTACH would create a missing one).
fn attach_existing(conn: &Connection, path: &Path, schema: &str) -> StoreResult<()> {
    if !path.is_file() {
        return Err(StoreError::Backend(format!(
            "no such file: {}",
            path.display()
        )));
    }
    conn.execute(
        &format!("ATTACH DATABASE ?1 AS {schema}"),
        [path_str(path)?],
    )?;
    Ok(())
}

/// Opens a finished copy (`VACUUM INTO` output) as a standalone file in rollback mode.
fn finish_copy(path: &Path) -> StoreResult<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.query_row("PRAGMA journal_mode=DELETE", [], |r| r.get::<_, String>(0))?;
    conn.execute_batch("PRAGMA secure_delete=ON; PRAGMA foreign_keys=OFF;")?;
    Ok(conn)
}

fn backup_log_head_tx(conn: &Connection, schema: &str) -> StoreResult<i64> {
    Ok(conn
        .query_row(
            &format!("SELECT seq FROM {schema}.sqlite_sequence WHERE name = 'backup_log'"),
            [],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

/// Runs `f` with a new file at `dest` (0600); removes it when `f` fails.
fn with_new_file<T>(dest: &Path, f: impl FnOnce() -> StoreResult<T>) -> StoreResult<T> {
    create_new_private_file(dest).map_err(|e| io_err("cannot create", dest, e))?;
    let result = f().and_then(|v| sync_file(dest).map(|()| v));
    if result.is_err() {
        let _ = std::fs::remove_file(dest);
        for suffix in ["-journal", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", dest.display()));
        }
    }
    result
}

// ---------------------------------------------------------------------------------------------
// The store

struct Inner {
    path: PathBuf,
    writer: Mutex<Connection>,
    readers: Mutex<Vec<Connection>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic inside a transaction drops (rolls back) it, so the connection stays usable.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Inner {
    fn write<T>(&self, f: impl FnOnce(&Transaction<'_>) -> StoreResult<T>) -> StoreResult<T> {
        let mut conn = lock(&self.writer);
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    fn read<T>(&self, f: impl FnOnce(&Transaction<'_>) -> StoreResult<T>) -> StoreResult<T> {
        let mut conn = match lock(&self.readers).pop() {
            Some(c) => c,
            None => open_reader(&self.path)?,
        };
        let out = (|| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
            let out = f(&tx)?;
            tx.commit()?;
            Ok(out)
        })();
        let mut pool = lock(&self.readers);
        if pool.len() < READERS {
            pool.push(conn);
        }
        out
    }

    /// A connection of its own for `VACUUM INTO` and change sets, so the writer is not held.
    fn side_connection(&self) -> StoreResult<Connection> {
        let conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        Ok(conn)
    }
}

/// The SQLite-backed store (paths B, C and D of §3.9).
#[derive(Clone)]
pub struct SqliteStore {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore")
            .field("path", &self.inner.path)
            .finish()
    }
}

impl SqliteStore {
    /// Opens or creates `{data_dir}/server.db` (directory 0700, file 0600) and runs the
    /// embedded migrations.
    pub fn open(data_dir: &Path) -> StoreResult<SqliteStore> {
        SqliteStore::open_file(&data_dir.join(DB_FILE))
    }

    /// Opens or creates the database file at `path` and runs the embedded migrations.
    pub fn open_file(path: &Path) -> StoreResult<SqliteStore> {
        let mut conn = open_connection(path)?;
        migrate(&mut conn)?;
        Ok(SqliteStore {
            inner: Arc::new(Inner {
                path: path.to_path_buf(),
                writer: Mutex::new(conn),
                readers: Mutex::new(Vec::new()),
            }),
        })
    }

    /// The database file.
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    fn run<T, F>(&self, f: F) -> StoreFuture<'static, T>
    where
        T: Send + 'static,
        F: FnOnce(&Inner) -> StoreResult<T> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || f(&inner))
                .await
                .map_err(|e| StoreError::Backend(format!("blocking task failed: {e}")))?
        })
    }

    fn write<T, F>(&self, f: F) -> StoreFuture<'static, T>
    where
        T: Send + 'static,
        F: FnOnce(&Transaction<'_>) -> StoreResult<T> + Send + 'static,
    {
        self.run(move |i| i.write(f))
    }

    fn read<T, F>(&self, f: F) -> StoreFuture<'static, T>
    where
        T: Send + 'static,
        F: FnOnce(&Transaction<'_>) -> StoreResult<T> + Send + 'static,
    {
        self.run(move |i| i.read(f))
    }
}

fn restore_state_tx(conn: &Connection) -> StoreResult<RestoreState> {
    let generation = meta_value(conn, meta_keys::GENERATION)?
        .and_then(|g| Id::parse(&g).ok())
        .ok_or_else(|| broken("meta.generation missing or not a uuid"))?;
    let pending = meta_value(conn, meta_keys::RESTORE_PENDING)?.as_deref() == Some("1");
    let restored_at = meta_value(conn, meta_keys::RESTORED_AT)?.and_then(|v| v.parse().ok());
    Ok(RestoreState {
        generation,
        restore_pending: pending,
        restored_at,
    })
}

fn push_tx(tx: &Transaction<'_>, b: &PushBatch) -> StoreResult<PushResponse> {
    let current_epoch = require_org(tx)?.current_epoch;
    let member = b.member_id.to_string();
    let device = b.device_id.to_string();
    let mut tags: Vec<Tag> = Vec::new();
    let (mut accepted, mut replayed) = (0u32, 0u32);
    for (i, item) in b.items.iter().enumerate() {
        let n = u32::try_from(i).map_err(|_| broken("batch too long"))?;
        let tag = item.tag().as_str();
        let idx = i64_of(item.idx(), || format!("/records/{i}/idx"))?;
        let id = item.id().to_string();
        if !tags.iter().any(|t| t.as_str() == tag) {
            tags.push(item.tag().clone());
        }
        // 4.1 replay and 4.2 conflict.
        let stored: Option<String> = tx
            .prepare_cached(
                "SELECT id FROM record \
                  WHERE member_id = ?1 AND device_id = ?2 AND tag = ?3 AND idx = ?4",
            )?
            .query_row(params![member, device, tag, idx], |r| r.get(0))
            .optional()?;
        match stored {
            Some(s) if s == id => {
                replayed += 1;
                continue;
            }
            Some(_) => {
                return Err(StoreError::StreamConflict {
                    item: n,
                    head: stream_head_tx(tx, &member, &device, tag)?,
                })
            }
            None => {}
        }
        // 4.3 deleted: a record item whose id this member deleted.
        let deleted_by = in_deletions(tx, &id)?;
        if matches!(item, PushItem::Record(_)) && deleted_by.as_deref() == Some(member.as_str()) {
            let mut ids = Vec::new();
            for other in &b.items {
                if let PushItem::Record(r) = other {
                    let rid = r.id.to_string();
                    if in_deletions(tx, &rid)?.as_deref() == Some(member.as_str())
                        && !ids.contains(&r.id)
                    {
                        ids.push(r.id);
                    }
                }
            }
            return Err(StoreError::Deleted { item: n, ids });
        }
        // 4.4 id taken: stored at another position, or pre-deleted by another member.
        let elsewhere = tx
            .prepare_cached("SELECT 1 FROM record WHERE id = ?1")?
            .query_row([&id], |_| Ok(()))
            .optional()?
            .is_some();
        if elsewhere || deleted_by.as_deref().is_some_and(|m| m != member) {
            return Err(StoreError::IdConflict { item: n });
        }
        // 4.5 contiguity.
        let head = stream_head_tx(tx, &member, &device, tag)?;
        if idx != head + 1 {
            return Err(StoreError::StreamConflict { item: n, head });
        }
        let received = hour(b.now);
        match item {
            PushItem::Record(r) => {
                // 4.6 epoch.
                if r.epoch != current_epoch {
                    return Err(StoreError::StaleEpoch {
                        item: n,
                        current_epoch,
                    });
                }
                tx.prepare_cached(
                    "INSERT INTO record (member_id, device_id, tag, idx, id, epoch, size, \
                                         received_at, blob, deleted_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
                )?
                .execute(params![
                    member,
                    device,
                    tag,
                    idx,
                    id,
                    r.epoch,
                    r.blob.0.len() as i64,
                    received,
                    r.blob.0
                ])?;
            }
            PushItem::Deleted(_) => {
                tx.prepare_cached(
                    "INSERT INTO record (member_id, device_id, tag, idx, id, epoch, size, \
                                         received_at, blob, deleted_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, NULL, 0, ?6, NULL, ?6)",
                )?
                .execute(params![member, device, tag, idx, id, received])?;
                if deleted_by.is_none() {
                    append_deletion(tx, &id, &member, b.now)?;
                }
            }
        }
        accepted += 1;
    }
    let heads = tags
        .into_iter()
        .map(|tag| {
            let head = stream_head_tx(tx, &member, &device, tag.as_str())?;
            Ok(OwnHead { tag, head })
        })
        .collect::<StoreResult<_>>()?;
    Ok(PushResponse {
        heads,
        accepted,
        replayed,
    })
}

fn delete_tx(
    tx: &Transaction<'_>,
    req: &DeleteRequest,
    by: &Actor,
    now: i64,
) -> StoreResult<DeleteResponse> {
    let caller = by.member_id.to_string();
    let (mut deleted, mut already) = (0u64, 0u64);
    let target = match req {
        DeleteRequest::Ids(ids) => {
            let mut seen = HashSet::new();
            let ids: Vec<String> = ids
                .iter()
                .filter(|id| seen.insert(**id))
                .map(Id::to_string)
                .collect();
            let mut held = Vec::with_capacity(ids.len());
            for id in &ids {
                let owner: Option<String> = tx
                    .prepare_cached("SELECT member_id FROM record WHERE id = ?1")?
                    .query_row([id], |r| r.get(0))
                    .optional()?;
                if owner.as_deref().is_some_and(|o| o != caller) && !by.admin {
                    return Err(StoreError::Forbidden);
                }
                held.push(owner);
            }
            for (id, owner) in ids.iter().zip(held) {
                let appended = match owner {
                    Some(o) => delete_held(tx, id, &o, now)?,
                    None if in_deletions(tx, id)?.is_some() => false,
                    None => {
                        // Pre-deletion (`docs/sync-v1.md` §10.3), bound to the caller.
                        append_deletion(tx, id, &caller, now)?;
                        true
                    }
                };
                if appended {
                    deleted += 1;
                } else {
                    already += 1;
                }
            }
            "ids".to_string()
        }
        DeleteRequest::AllMine => {
            deleted = delete_member_rows(tx, &caller, now)?;
            "all_mine".to_string()
        }
        DeleteRequest::Member(m) => {
            if !by.admin {
                return Err(StoreError::Forbidden);
            }
            let m = m.to_string();
            let exists = tx
                .query_row("SELECT 1 FROM member WHERE id = ?1", [&m], |_| Ok(()))
                .optional()?
                .is_some();
            if !exists {
                return Err(StoreError::NotFound);
            }
            deleted = delete_member_rows(tx, &m, now)?;
            format!("member:{m}")
        }
    };
    audit_tx(
        tx,
        now,
        Some(by.member_id),
        "delete",
        Some(target),
        Some(format!("deleted={deleted} already={already}")),
    )?;
    Ok(DeleteResponse { deleted, already })
}

fn settings_tx(
    tx: &Transaction<'_>,
    u: &SettingsUpdate,
    floor: &Version,
    by: Option<Actor>,
    now: i64,
) -> StoreResult<OrgSettings> {
    promote_retention(tx, now)?;
    let org = require_org(tx)?;
    let invalid = |f: &str| StoreError::InvalidValue {
        field: f.to_string(),
    };
    let mut retention = org.retention_days;
    let mut pending = org.pending;
    let mut min_client = org.min_client.clone();
    let mut max_members = org.max_members;
    if u.cancel_pending_retention == Some(true) {
        pending = None;
    }
    if let Some(r) = u.retention_days {
        if r < limits::RETENTION_DAYS_MIN {
            return Err(invalid("/retention_days"));
        }
        if r >= retention {
            retention = r;
            pending = None;
        } else {
            pending = Some((r, now + limits::RETENTION_DECREASE_DELAY_S));
        }
    }
    if let Some(v) = &u.min_client {
        if *v < org.min_client || v < floor {
            return Err(invalid("/min_client"));
        }
        min_client = v.clone();
    }
    if let Some(m) = u.max_members {
        if m == 0 {
            return Err(invalid("/max_members"));
        }
        max_members = m;
    }
    let changed = retention != org.retention_days
        || pending != org.pending
        || min_client != org.min_client
        || max_members != org.max_members;
    if changed {
        tx.execute(
            "UPDATE org SET retention_days = ?1, min_client = ?2, max_members = ?3, \
                            pending_retention_days = ?4, pending_retention_at = ?5",
            params![
                retention,
                min_client.to_string(),
                max_members,
                pending.map(|p| p.0),
                pending.map(|p| p.1)
            ],
        )?;
        let pending_text =
            pending.map_or_else(|| "none".to_string(), |(d, at)| format!("{d}@{at}"));
        audit_tx(
            tx,
            now,
            by.map(|a| a.member_id),
            "settings",
            None,
            Some(format!(
                "retention_days={retention} pending_retention={pending_text} \
                 min_client={min_client} max_members={max_members}"
            )),
        )?;
    }
    Ok(require_org(tx)?.effective(now))
}

fn status_tx(tx: &Transaction<'_>, device_id: Id, now: i64) -> StoreResult<StatusResponse> {
    let (member_id, approved): (Id, bool) = tx
        .query_row(
            "SELECT member_id, approved FROM device WHERE id = ?1",
            [device_id.to_string()],
            |r| Ok((id_at(r, 0)?, r.get::<_, i64>(1)? == 1)),
        )
        .optional()?
        .ok_or(StoreError::NotFound)?;
    let role = tx.query_row(
        "SELECT role FROM member WHERE id = ?1",
        [member_id.to_string()],
        |r| role_at(r, 0),
    )?;
    let org = require_org(tx)?;
    let restore = restore_state_tx(tx)?;
    let streams = tx
        .prepare(
            "SELECT member_id, device_id, tag, MAX(idx) FROM record \
              GROUP BY member_id, device_id, tag ORDER BY member_id, device_id, tag",
        )?
        .query_map([], |r| {
            Ok(StreamHead {
                member: id_at(r, 0)?,
                device: id_at(r, 1)?,
                tag: tag_at(r, 2)?,
                head: r.get(3)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    let pending = tx
        .prepare(
            "SELECT d.id, d.member_id, m.handle, i.kind, d.invite_id, d.pubkey, d.join_mac, \
                    d.created_at \
               FROM device d JOIN member m ON m.id = d.member_id \
               JOIN invite i ON i.id = d.invite_id \
              WHERE d.approved = 0 AND d.revoked_at IS NULL AND m.revoked_at IS NULL \
                AND (?1 OR d.member_id = ?2) \
              ORDER BY d.created_at, d.id",
        )?
        .query_map(params![role == Role::Admin, member_id.to_string()], |r| {
            Ok(PendingDevice {
                device_id: id_at(r, 0)?,
                member_id: id_at(r, 1)?,
                handle: handle_at(r, 2)?,
                kind: kind_at(r, 3)?,
                invite_id: id_at(r, 4)?,
                device_pubkey: key_at(r, 5)?,
                join_mac: key_at(r, 6)?,
                joined_at: hour(r.get(7)?),
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(StatusResponse {
        generation: restore.generation,
        org_id: org.id,
        member_id,
        device_id,
        role,
        approved,
        current_epoch: org.current_epoch,
        rotation_needed: org.rotation_needed,
        restore_pending: restore.restore_pending,
        settings: org.effective(now),
        streams,
        deletions: deletion_heads_tx(tx)?,
        pending,
    })
}

fn pull_tx(
    tx: &Transaction<'_>,
    cursors: &[Cursor],
    limit: u32,
    max_bytes: usize,
) -> StoreResult<PullResponse> {
    let empty = PullResponse {
        streams: Vec::new(),
        more: false,
    };
    let mut budget = max_bytes.saturating_sub(json_len(&empty));
    let mut remaining = limit;
    let mut more = false;
    let mut streams = Vec::new();
    for (ci, c) in cursors.iter().enumerate() {
        if remaining == 0 {
            more = true;
            break;
        }
        let head = stream_head_tx(
            tx,
            &c.member.to_string(),
            &c.device.to_string(),
            c.tag.as_str(),
        )?;
        let mut sr = StreamRecords {
            member: c.member,
            device: c.device,
            tag: c.tag.clone(),
            head,
            records: Vec::new(),
        };
        let base = json_len(&sr);
        if base > budget {
            more = true;
            break;
        }
        budget -= base;
        let from = i64_of(c.from, || format!("/cursors/{ci}/from"))?;
        let cut = read_stream(tx, &mut sr, from, remaining, &mut budget)?;
        let wanted = (head - from + 1).max(0);
        let got = sr.records.len();
        remaining -= u32::try_from(got).map_err(|_| broken("page too long"))?;
        if (got as i64) < wanted {
            more = true;
        }
        streams.push(sr);
        if cut {
            more |= ci + 1 < cursors.len();
            break;
        }
    }
    Ok(PullResponse { streams, more })
}

fn changes_info(conn: &Connection, schema: &str, after: i64) -> StoreResult<ChangeSet> {
    let (min, max, rows): (Option<i64>, Option<i64>, i64) = conn.query_row(
        &format!(
            "SELECT MIN(seq), MAX(seq), (SELECT COUNT(*) FROM \
                    (SELECT DISTINCT tbl, key FROM {schema}.backup_log)) \
               FROM {schema}.backup_log"
        ),
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    Ok(ChangeSet {
        after: min.map_or(after, |m| m - 1),
        to: max.unwrap_or(after),
        rows: u64::try_from(rows).unwrap_or(0),
    })
}

fn columns_of(table: &str) -> StoreResult<&'static [&'static str]> {
    CANONICAL_TABLES
        .iter()
        .find(|(t, _)| *t == table)
        .map(|(_, c)| *c)
        .ok_or_else(|| broken("unknown table"))
}

impl Store for SqliteStore {
    fn restore_state(&self) -> StoreFuture<'_, RestoreState> {
        self.read(|tx| restore_state_tx(tx))
    }

    fn renew_generation(&self, now: i64) -> StoreFuture<'_, Id> {
        self.write(move |tx| {
            let generation = Id::new_v4();
            meta_put(tx, meta_keys::GENERATION, &generation.to_string())?;
            meta_put(tx, meta_keys::RESTORE_PENDING, "1")?;
            meta_put(tx, meta_keys::RESTORED_AT, &now.to_string())?;
            audit_tx(
                tx,
                now,
                None,
                "restore",
                None,
                Some(format!("generation={generation}")),
            )?;
            Ok(generation)
        })
    }

    fn complete_restore(&self, generation: Id, by: Actor, now: i64) -> StoreFuture<'_, ()> {
        self.write(move |tx| {
            let state = restore_state_tx(tx)?;
            if state.generation != generation {
                return Err(StoreError::InvalidValue {
                    field: "/generation".into(),
                });
            }
            if state.restore_pending {
                meta_put(tx, meta_keys::RESTORE_PENDING, "0")?;
                audit_tx(
                    tx,
                    now,
                    Some(by.member_id),
                    "restore.complete",
                    None,
                    Some(format!("generation={generation}")),
                )?;
            }
            Ok(())
        })
    }

    fn meta_get(&self, key: String) -> StoreFuture<'_, Option<String>> {
        self.read(move |tx| meta_value(tx, &key))
    }

    fn meta_set(&self, key: String, value: String) -> StoreFuture<'_, ()> {
        self.write(move |tx| {
            if meta_keys::reserved(&key) {
                return Err(StoreError::InvalidValue {
                    field: "key".into(),
                });
            }
            meta_put(tx, &key, &value)
        })
    }

    fn org(&self, now: i64) -> StoreFuture<'_, Option<OrgRow>> {
        self.read(move |tx| {
            Ok(load_org(tx)?.map(|o| OrgRow {
                org_id: o.id,
                created_at: o.created_at,
                current_epoch: o.current_epoch,
                rotation_needed: o.rotation_needed,
                settings: o.effective(now),
            }))
        })
    }

    fn set_bootstrap(&self, token_hash: String, expires_at: i64) -> StoreFuture<'_, ()> {
        self.write(move |tx| {
            check_hash(&token_hash, "token_hash")?;
            if load_org(tx)?.is_some() {
                return Err(StoreError::NotEmpty);
            }
            meta_put(tx, meta_keys::BOOTSTRAP_HASH, &token_hash)?;
            meta_put(tx, meta_keys::BOOTSTRAP_EXPIRES, &expires_at.to_string())
        })
    }

    fn bootstrap(&self, req: NewBootstrap) -> StoreFuture<'_, Id> {
        self.write(move |tx| {
            check_hash(&req.bootstrap_token_hash, "bootstrap_token")?;
            check_hash(&req.device_token_hash, "device_token")?;
            if load_org(tx)?.is_some() {
                return Err(StoreError::Gone);
            }
            let stored = meta_value(tx, meta_keys::BOOTSTRAP_HASH)?;
            let expires: Option<i64> =
                meta_value(tx, meta_keys::BOOTSTRAP_EXPIRES)?.and_then(|v| v.parse().ok());
            let valid = stored.as_deref() == Some(req.bootstrap_token_hash.as_str())
                && expires.is_some_and(|e| req.now < e);
            if !valid {
                return Err(StoreError::Gone);
            }
            let d = &req.defaults;
            if d.retention_days < limits::RETENTION_DAYS_MIN {
                return Err(StoreError::InvalidValue {
                    field: "retention_days".into(),
                });
            }
            if d.max_members == 0 {
                return Err(StoreError::InvalidValue {
                    field: "max_members".into(),
                });
            }
            let device = req.device_id.to_string();
            if tx
                .query_row("SELECT 1 FROM device WHERE id = ?1", [&device], |_| Ok(()))
                .optional()?
                .is_some()
            {
                return Err(StoreError::DeviceConflict);
            }
            tx.execute(
                "INSERT INTO org (id, created_at, current_epoch, rotation_needed, retention_days, \
                                  min_client, max_members) VALUES (?1, ?2, 0, 0, ?3, ?4, ?5)",
                params![
                    req.org_id.to_string(),
                    req.now,
                    d.retention_days,
                    d.min_client.to_string(),
                    d.max_members
                ],
            )?;
            let member = Id::new_v4();
            tx.execute(
                "INSERT INTO member (id, handle, role, created_at) VALUES (?1, ?2, 'admin', ?3)",
                params![member.to_string(), req.handle.as_str(), req.now],
            )?;
            tx.execute(
                "INSERT INTO device (id, member_id, token_hash, pubkey, approved, created_at) \
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                params![
                    device,
                    member.to_string(),
                    req.device_token_hash,
                    req.device_pubkey.0.as_slice(),
                    req.now
                ],
            )?;
            tx.execute(
                "DELETE FROM meta WHERE key IN (?1, ?2)",
                params![meta_keys::BOOTSTRAP_HASH, meta_keys::BOOTSTRAP_EXPIRES],
            )?;
            audit_tx(tx, req.now, Some(member), "bootstrap", Some(device), None)?;
            Ok(member)
        })
    }

    fn auth_device(&self, token_hash: String) -> StoreFuture<'_, Option<AuthDevice>> {
        self.read(move |tx| {
            if !valid_token_hash(&token_hash) {
                return Ok(None);
            }
            Ok(tx
                .query_row(
                    "SELECT o.id, d.member_id, d.id, m.handle, m.role, d.approved, \
                            d.revoked_at IS NOT NULL, m.revoked_at IS NOT NULL \
                       FROM device d JOIN member m ON m.id = d.member_id CROSS JOIN org o \
                      WHERE d.token_hash = ?1",
                    [&token_hash],
                    |r| {
                        Ok(AuthDevice {
                            org_id: id_at(r, 0)?,
                            member_id: id_at(r, 1)?,
                            device_id: id_at(r, 2)?,
                            handle: handle_at(r, 3)?,
                            role: role_at(r, 4)?,
                            approved: r.get::<_, i64>(5)? == 1,
                            device_revoked: r.get(6)?,
                            member_revoked: r.get(7)?,
                        })
                    },
                )
                .optional()?)
        })
    }

    fn touch_device(&self, device_id: Id, day: i64) -> StoreFuture<'_, ()> {
        let inner = Arc::clone(&self.inner);
        self.run(move |_| {
            let id = device_id.to_string();
            let seen: Option<Option<i64>> = inner.read(|tx| {
                Ok(tx
                    .query_row(
                        "SELECT last_seen_day FROM device WHERE id = ?1",
                        [&id],
                        |r| r.get(0),
                    )
                    .optional()?)
            })?;
            match seen {
                // An unknown device, or the day is already recorded: nothing to write.
                None => return Ok(()),
                Some(Some(d)) if d == day => return Ok(()),
                Some(_) => {}
            }
            inner.write(|tx| {
                tx.execute(
                    "UPDATE device SET last_seen_day = ?2 \
                      WHERE id = ?1 AND (last_seen_day IS NULL OR last_seen_day <> ?2)",
                    params![id, day],
                )?;
                Ok(())
            })
        })
    }

    fn rotate_token(&self, device_id: Id, token_hash: String, now: i64) -> StoreFuture<'_, ()> {
        self.write(move |tx| {
            check_hash(&token_hash, "token_hash")?;
            let id = device_id.to_string();
            let member: Option<Id> = tx
                .query_row(
                    "SELECT d.member_id FROM device d JOIN member m ON m.id = d.member_id \
                      WHERE d.id = ?1 AND d.revoked_at IS NULL AND m.revoked_at IS NULL",
                    [&id],
                    |r| id_at(r, 0),
                )
                .optional()?;
            let member = member.ok_or(StoreError::NotFound)?;
            tx.execute(
                "UPDATE device SET token_hash = ?2 WHERE id = ?1",
                params![id, token_hash],
            )?;
            audit_tx(tx, now, Some(member), "token.rotate", Some(id), None)?;
            Ok(())
        })
    }

    fn device(&self, device_id: Id) -> StoreFuture<'_, Option<DeviceRow>> {
        self.read(move |tx| {
            Ok(tx
                .query_row(
                    "SELECT id, member_id, pubkey, join_mac, invite_id, approved, created_at, \
                            revoked_at, last_seen_day FROM device WHERE id = ?1",
                    [device_id.to_string()],
                    |r| {
                        Ok(DeviceRow {
                            device_id: id_at(r, 0)?,
                            member_id: id_at(r, 1)?,
                            pubkey: key_at(r, 2)?,
                            join_mac: opt_key_at(r, 3)?,
                            invite_id: opt_id_at(r, 4)?,
                            approved: r.get::<_, i64>(5)? == 1,
                            created_at: r.get(6)?,
                            revoked_at: r.get(7)?,
                            last_seen_day: r.get(8)?,
                        })
                    },
                )
                .optional()?)
        })
    }

    fn member(&self, member_id: Id) -> StoreFuture<'_, Option<MemberRow>> {
        self.read(move |tx| {
            Ok(tx
                .query_row(
                    "SELECT id, handle, role, created_at, revoked_at FROM member WHERE id = ?1",
                    [member_id.to_string()],
                    member_row,
                )
                .optional()?)
        })
    }

    fn member_by_handle(&self, handle: Handle) -> StoreFuture<'_, Option<MemberRow>> {
        self.read(move |tx| {
            Ok(tx
                .query_row(
                    "SELECT id, handle, role, created_at, revoked_at FROM member \
                      WHERE handle = ?1 AND revoked_at IS NULL",
                    [handle.as_str()],
                    member_row,
                )
                .optional()?)
        })
    }

    fn create_invite(&self, inv: NewInvite) -> StoreFuture<'_, ()> {
        self.write(move |tx| {
            check_hash(&inv.token_hash, "token_hash")?;
            let org = require_org(tx)?;
            let active: Option<String> = tx
                .query_row(
                    "SELECT id FROM member WHERE handle = ?1 AND revoked_at IS NULL",
                    [inv.handle.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            let invalid = |f: &str| StoreError::InvalidValue {
                field: f.to_string(),
            };
            let (kind, role, member) = match inv.kind {
                InviteKind::Member => {
                    let role = role_str(inv.role.unwrap_or(Role::Member), "/role")?;
                    if active.is_some() {
                        return Err(invalid("/handle"));
                    }
                    let taken: i64 = tx.query_row(
                        "SELECT (SELECT COUNT(*) FROM member WHERE revoked_at IS NULL) \
                              + (SELECT COUNT(*) FROM invite WHERE kind = 'member' \
                                    AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?1)",
                        [inv.now],
                        |r| r.get(0),
                    )?;
                    if taken >= i64::from(org.max_members) {
                        return Err(StoreError::Forbidden);
                    }
                    ("member", Some(role), None)
                }
                InviteKind::Device => {
                    if inv.role.is_some() {
                        return Err(invalid("/role"));
                    }
                    let member = active.ok_or_else(|| invalid("/handle"))?;
                    ("device", None, Some(member))
                }
                InviteKind::Unknown => return Err(invalid("/kind")),
            };
            let id = inv.invite_id.to_string();
            tx.execute(
                "INSERT INTO invite (id, token_hash, handle, role, kind, member_id, created_by, \
                                     created_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    id,
                    inv.token_hash,
                    inv.handle.as_str(),
                    role,
                    kind,
                    member,
                    inv.by.device_id.to_string(),
                    inv.now,
                    inv.expires_at
                ],
            )?;
            audit_tx(
                tx,
                inv.now,
                Some(inv.by.member_id),
                "invite.create",
                Some(id),
                Some(format!("kind={kind}")),
            )?;
            Ok(())
        })
    }

    fn invite(&self, invite_id: Id) -> StoreFuture<'_, Option<InviteRow>> {
        self.read(move |tx| {
            Ok(tx
                .query_row(
                    "SELECT i.id, i.kind, i.handle, i.role, i.member_id, i.created_by, \
                            d.member_id, i.created_at, i.expires_at, i.used_at, i.revoked_at \
                       FROM invite i JOIN device d ON d.id = i.created_by WHERE i.id = ?1",
                    [invite_id.to_string()],
                    |r| {
                        Ok(InviteRow {
                            invite_id: id_at(r, 0)?,
                            kind: kind_at(r, 1)?,
                            handle: handle_at(r, 2)?,
                            role: opt_role_at(r, 3)?,
                            member_id: opt_id_at(r, 4)?,
                            created_by: id_at(r, 5)?,
                            created_by_member: id_at(r, 6)?,
                            created_at: r.get(7)?,
                            expires_at: r.get(8)?,
                            used_at: r.get(9)?,
                            revoked_at: r.get(10)?,
                        })
                    },
                )
                .optional()?)
        })
    }

    fn revoke_invite(&self, invite_id: Id, by: Actor, now: i64) -> StoreFuture<'_, ()> {
        self.write(move |tx| {
            let id = invite_id.to_string();
            let open: Option<bool> = tx
                .query_row(
                    "SELECT used_at IS NULL AND revoked_at IS NULL FROM invite WHERE id = ?1",
                    [&id],
                    |r| r.get(0),
                )
                .optional()?;
            match open {
                None => Err(StoreError::NotFound),
                Some(false) => Ok(()),
                Some(true) => {
                    tx.execute(
                        "UPDATE invite SET revoked_at = ?2 WHERE id = ?1",
                        params![id, now],
                    )?;
                    audit_tx(tx, now, Some(by.member_id), "invite.revoke", Some(id), None)?;
                    Ok(())
                }
            }
        })
    }

    fn join(&self, req: NewJoin) -> StoreFuture<'_, Joined> {
        self.write(move |tx| {
            check_hash(&req.invite_token_hash, "invite_token")?;
            check_hash(&req.device_token_hash, "device_token")?;
            let org = load_org(tx)?.ok_or(StoreError::Gone)?;
            let invite_id = req.invite_id.to_string();
            let invite = tx
                .query_row(
                    "SELECT kind, handle, role, member_id, expires_at, \
                            used_at IS NULL AND revoked_at IS NULL \
                       FROM invite WHERE id = ?1 AND token_hash = ?2",
                    params![invite_id, req.invite_token_hash],
                    |r| {
                        Ok((
                            kind_at(r, 0)?,
                            handle_at(r, 1)?,
                            opt_role_at(r, 2)?,
                            opt_id_at(r, 3)?,
                            r.get::<_, i64>(4)?,
                            r.get::<_, bool>(5)?,
                        ))
                    },
                )
                .optional()?;
            let (kind, handle, role, member_for_device, expires_at, open) =
                invite.ok_or(StoreError::Gone)?;
            if !open || req.now >= expires_at {
                return Err(StoreError::Gone);
            }
            if handle != req.handle {
                return Err(StoreError::InvalidValue {
                    field: "/handle".into(),
                });
            }
            let device = req.device_id.to_string();
            if tx
                .query_row("SELECT 1 FROM device WHERE id = ?1", [&device], |_| Ok(()))
                .optional()?
                .is_some()
            {
                return Err(StoreError::DeviceConflict);
            }
            let member = match kind {
                InviteKind::Member => {
                    let taken = tx
                        .query_row(
                            "SELECT 1 FROM member WHERE handle = ?1 AND revoked_at IS NULL",
                            [handle.as_str()],
                            |_| Ok(()),
                        )
                        .optional()?
                        .is_some();
                    if taken {
                        return Err(StoreError::InvalidValue {
                            field: "/handle".into(),
                        });
                    }
                    let member = Id::new_v4();
                    let role = role_str(role.unwrap_or(Role::Member), "/role")?;
                    tx.execute(
                        "INSERT INTO member (id, handle, role, created_at) VALUES (?1, ?2, ?3, ?4)",
                        params![member.to_string(), handle.as_str(), role, req.now],
                    )?;
                    member
                }
                InviteKind::Device | InviteKind::Unknown => {
                    let member = member_for_device.ok_or_else(|| broken("device invite"))?;
                    let active = tx
                        .query_row(
                            "SELECT 1 FROM member WHERE id = ?1 AND revoked_at IS NULL",
                            [member.to_string()],
                            |_| Ok(()),
                        )
                        .optional()?
                        .is_some();
                    if !active {
                        return Err(StoreError::Gone);
                    }
                    member
                }
            };
            tx.execute(
                "INSERT INTO device (id, member_id, token_hash, pubkey, join_mac, invite_id, \
                                     approved, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)",
                params![
                    device,
                    member.to_string(),
                    req.device_token_hash,
                    req.device_pubkey.0.as_slice(),
                    req.join_mac.0.as_slice(),
                    invite_id,
                    req.now
                ],
            )?;
            tx.execute(
                "UPDATE invite SET used_at = ?2 WHERE id = ?1",
                params![invite_id, req.now],
            )?;
            let kind_text = if kind == InviteKind::Member {
                "member"
            } else {
                "device"
            };
            audit_tx(
                tx,
                req.now,
                Some(member),
                "join",
                Some(device),
                Some(format!("kind={kind_text} invite={invite_id}")),
            )?;
            Ok(Joined {
                org_id: org.id,
                member_id: member,
                kind,
            })
        })
    }

    fn approve_device(
        &self,
        device_id: Id,
        wraps: Vec<EpochWrap>,
        by: Actor,
        now: i64,
    ) -> StoreFuture<'_, ()> {
        self.write(move |tx| {
            let id = device_id.to_string();
            let state: Option<(bool, bool)> = tx
                .query_row(
                    "SELECT approved = 1, revoked_at IS NOT NULL FROM device WHERE id = ?1",
                    [&id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (approved, revoked) = state.ok_or(StoreError::NotFound)?;
            if revoked {
                return Err(StoreError::Forbidden);
            }
            let current = require_org(tx)?.current_epoch;
            let mut inserted = 0;
            for (i, w) in wraps.iter().enumerate() {
                if w.epoch > current {
                    return Err(StoreError::InvalidValue {
                        field: format!("/wraps/{i}/epoch"),
                    });
                }
                inserted += tx
                    .prepare_cached(
                        "INSERT INTO wrap (device_id, epoch, wrap, auth, created_by) \
                         VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(device_id, epoch) DO NOTHING",
                    )?
                    .execute(params![
                        id,
                        w.epoch,
                        w.wrap.0,
                        w.auth.0.as_slice(),
                        by.device_id.to_string()
                    ])?;
            }
            let held: i64 = tx.query_row(
                "SELECT COUNT(*) FROM wrap WHERE device_id = ?1 AND epoch <= ?2",
                params![id, current],
                |r| r.get(0),
            )?;
            if held != i64::from(current) + 1 {
                return Err(StoreError::InvalidValue {
                    field: "/wraps".into(),
                });
            }
            if !approved {
                tx.execute("UPDATE device SET approved = 1 WHERE id = ?1", [&id])?;
            }
            if !approved || inserted > 0 {
                audit_tx(
                    tx,
                    now,
                    Some(by.member_id),
                    "approve",
                    Some(id),
                    Some(format!("wraps={inserted}")),
                )?;
            }
            Ok(())
        })
    }

    fn revoke_device(&self, device_id: Id, by: Actor, now: i64) -> StoreFuture<'_, ()> {
        self.write(move |tx| {
            let id = device_id.to_string();
            let revoked: Option<bool> = tx
                .query_row(
                    "SELECT revoked_at IS NOT NULL FROM device WHERE id = ?1",
                    [&id],
                    |r| r.get(0),
                )
                .optional()?;
            match revoked {
                None => Err(StoreError::NotFound),
                Some(true) => Ok(()),
                Some(false) => {
                    tx.execute(
                        "UPDATE device SET revoked_at = ?2 WHERE id = ?1",
                        params![id, now],
                    )?;
                    tx.execute(
                        "UPDATE org SET rotation_needed = 1 WHERE rotation_needed = 0",
                        [],
                    )?;
                    audit_tx(tx, now, Some(by.member_id), "device.revoke", Some(id), None)?;
                    Ok(())
                }
            }
        })
    }

    fn remove_member(
        &self,
        member_id: Id,
        delete_records: bool,
        by: Actor,
        now: i64,
    ) -> StoreFuture<'_, u64> {
        self.write(move |tx| {
            let id = member_id.to_string();
            let row: Option<(Role, bool)> = tx
                .query_row(
                    "SELECT role, revoked_at IS NULL FROM member WHERE id = ?1",
                    [&id],
                    |r| Ok((role_at(r, 0)?, r.get(1)?)),
                )
                .optional()?;
            let (role, active) = row.ok_or(StoreError::NotFound)?;
            if active && role == Role::Admin && active_admins(tx)? <= 1 {
                return Err(StoreError::LastAdmin);
            }
            if active {
                tx.execute(
                    "UPDATE member SET revoked_at = ?2 WHERE id = ?1",
                    params![id, now],
                )?;
                tx.execute(
                    "UPDATE invite SET revoked_at = ?2 \
                      WHERE used_at IS NULL AND revoked_at IS NULL \
                        AND (member_id = ?1 OR created_by IN \
                             (SELECT id FROM device WHERE member_id = ?1))",
                    params![id, now],
                )?;
                tx.execute(
                    "UPDATE device SET revoked_at = ?2 WHERE member_id = ?1 AND revoked_at IS NULL",
                    params![id, now],
                )?;
                tx.execute(
                    "UPDATE org SET rotation_needed = 1 WHERE rotation_needed = 0",
                    [],
                )?;
            }
            let deleted = if delete_records {
                delete_member_rows(tx, &id, now)?
            } else {
                0
            };
            if active || deleted > 0 {
                audit_tx(
                    tx,
                    now,
                    Some(by.member_id),
                    "member.remove",
                    Some(id),
                    Some(format!("delete_records={delete_records} deleted={deleted}")),
                )?;
            }
            Ok(deleted)
        })
    }

    fn set_role(
        &self,
        member_id: Id,
        role: Role,
        by: Option<Actor>,
        now: i64,
    ) -> StoreFuture<'_, ()> {
        self.write(move |tx| {
            let new = role_str(role, "/role")?;
            let id = member_id.to_string();
            let current: Option<Role> = tx
                .query_row(
                    "SELECT role FROM member WHERE id = ?1 AND revoked_at IS NULL",
                    [&id],
                    |r| role_at(r, 0),
                )
                .optional()?;
            let current = current.ok_or(StoreError::NotFound)?;
            if current == role {
                return Ok(());
            }
            if current == Role::Admin && active_admins(tx)? <= 1 {
                return Err(StoreError::LastAdmin);
            }
            tx.execute(
                "UPDATE member SET role = ?2 WHERE id = ?1",
                params![id, new],
            )?;
            audit_tx(
                tx,
                now,
                by.map(|a| a.member_id),
                "member.role",
                Some(id),
                Some(format!("role={new}")),
            )?;
            Ok(())
        })
    }

    fn members(&self) -> StoreFuture<'_, Vec<MemberInfo>> {
        self.read(|tx| {
            let mut devices: BTreeMap<String, Vec<DeviceInfo>> = BTreeMap::new();
            let mut st = tx.prepare(
                "SELECT member_id, id, pubkey, approved, revoked_at IS NOT NULL FROM device \
                  ORDER BY created_at, id",
            )?;
            let mut rows = st.query([])?;
            while let Some(r) = rows.next()? {
                devices.entry(r.get(0)?).or_default().push(DeviceInfo {
                    device_id: id_at(r, 1)?,
                    device_pubkey: key_at(r, 2)?,
                    approved: r.get::<_, i64>(3)? == 1,
                    revoked: r.get(4)?,
                });
            }
            let members = tx
                .prepare(
                    "SELECT id, handle, role, created_at, revoked_at FROM member \
                      ORDER BY created_at, id",
                )?
                .query_map([], member_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(members
                .into_iter()
                .map(|m| MemberInfo {
                    devices: devices.remove(&m.member_id.to_string()).unwrap_or_default(),
                    member_id: m.member_id,
                    handle: m.handle,
                    role: m.role,
                    active: m.revoked_at.is_none(),
                })
                .collect())
        })
    }

    fn keys(&self, device_id: Id) -> StoreFuture<'_, KeysResponse> {
        self.read(move |tx| {
            let id = device_id.to_string();
            if tx
                .query_row("SELECT 1 FROM device WHERE id = ?1", [&id], |_| Ok(()))
                .optional()?
                .is_none()
            {
                return Err(StoreError::NotFound);
            }
            let org = require_org(tx)?;
            let wraps = tx
                .prepare(
                    "SELECT epoch, wrap, auth, created_by FROM wrap WHERE device_id = ?1 \
                      ORDER BY epoch",
                )?
                .query_map([&id], |r| {
                    Ok(StoredWrap {
                        epoch: u32_at(r, 0)?,
                        wrap: B64(r.get(1)?),
                        auth: key_at(r, 2)?,
                        created_by: id_at(r, 3)?,
                    })
                })?
                .collect::<Result<_, _>>()?;
            Ok(KeysResponse {
                current_epoch: org.current_epoch,
                rotation_needed: org.rotation_needed,
                wraps,
            })
        })
    }

    fn rotate_keys(
        &self,
        epoch: u32,
        wraps: Vec<DeviceWrap>,
        by: Actor,
        now: i64,
    ) -> StoreFuture<'_, ()> {
        self.write(move |tx| {
            let current = require_org(tx)?.current_epoch;
            if u64::from(epoch) != u64::from(current) + 1 {
                return Err(StoreError::EpochConflict {
                    current_epoch: current,
                });
            }
            if wraps.is_empty() {
                return Err(StoreError::InvalidValue {
                    field: "/wraps".into(),
                });
            }
            let mut seen = HashSet::new();
            for (i, w) in wraps.iter().enumerate() {
                let id = w.device_id.to_string();
                let listed = tx
                    .query_row(
                        "SELECT 1 FROM device d JOIN member m ON m.id = d.member_id \
                          WHERE d.id = ?1 AND d.revoked_at IS NULL AND m.revoked_at IS NULL",
                        [&id],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                if !listed || !seen.insert(w.device_id) {
                    return Err(StoreError::InvalidValue {
                        field: format!("/wraps/{i}/device_id"),
                    });
                }
                tx.execute(
                    "INSERT INTO wrap (device_id, epoch, wrap, auth, created_by) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        id,
                        epoch,
                        w.wrap.0,
                        w.auth.0.as_slice(),
                        by.device_id.to_string()
                    ],
                )?;
            }
            tx.execute(
                "UPDATE org SET current_epoch = ?1, rotation_needed = 0",
                [epoch],
            )?;
            audit_tx(
                tx,
                now,
                Some(by.member_id),
                "keys.rotate",
                None,
                Some(format!("epoch={epoch} devices={}", wraps.len())),
            )?;
            Ok(())
        })
    }

    fn status(&self, device_id: Id, now: i64) -> StoreFuture<'_, StatusResponse> {
        self.read(move |tx| status_tx(tx, device_id, now))
    }

    fn update_settings(
        &self,
        update: SettingsUpdate,
        floor: Version,
        by: Option<Actor>,
        now: i64,
    ) -> StoreFuture<'_, OrgSettings> {
        self.write(move |tx| settings_tx(tx, &update, &floor, by, now))
    }

    fn push(&self, batch: PushBatch) -> StoreFuture<'_, PushResponse> {
        self.write(move |tx| push_tx(tx, &batch))
    }

    fn stream_head(&self, member_id: Id, device_id: Id, tag: Tag) -> StoreFuture<'_, i64> {
        self.read(move |tx| {
            stream_head_tx(
                tx,
                &member_id.to_string(),
                &device_id.to_string(),
                tag.as_str(),
            )
        })
    }

    fn records(
        &self,
        member_id: Id,
        device_id: Id,
        tag: Tag,
        from: u64,
        limit: u32,
        max_bytes: usize,
    ) -> StoreFuture<'_, StreamRecords> {
        self.read(move |tx| {
            let from = i64_of(from, || "from".to_string())?;
            let head = stream_head_tx(
                tx,
                &member_id.to_string(),
                &device_id.to_string(),
                tag.as_str(),
            )?;
            let mut out = StreamRecords {
                member: member_id,
                device: device_id,
                tag,
                head,
                records: Vec::new(),
            };
            let mut budget = max_bytes.saturating_sub(json_len(&out));
            read_stream(tx, &mut out, from, limit, &mut budget)?;
            Ok(out)
        })
    }

    fn pull(
        &self,
        cursors: Vec<Cursor>,
        limit: u32,
        max_bytes: usize,
    ) -> StoreFuture<'_, PullResponse> {
        self.read(move |tx| pull_tx(tx, &cursors, limit, max_bytes))
    }

    fn pushed_since(&self, member_id: Id, since: i64) -> StoreFuture<'_, u64> {
        self.read(move |tx| {
            let n: i64 = tx.query_row(
                "SELECT (SELECT COUNT(*) FROM record \
                          WHERE member_id = ?1 AND epoch IS NOT NULL AND received_at >= ?2) \
                      + (SELECT COUNT(*) FROM deletion d \
                          WHERE d.member_id = ?1 AND d.deleted_at >= ?2 \
                            AND NOT EXISTS (SELECT 1 FROM record r WHERE r.id = d.record_id))",
                params![member_id.to_string(), hour(since)],
                |r| r.get(0),
            )?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }

    fn delete(&self, req: DeleteRequest, by: Actor, now: i64) -> StoreFuture<'_, DeleteResponse> {
        self.write(move |tx| delete_tx(tx, &req, &by, now))
    }

    fn retention_batch(&self, cutoff: i64, limit: u32, now: i64) -> StoreFuture<'_, u64> {
        self.write(move |tx| {
            promote_retention(tx, now)?;
            let rows: Vec<(String, String)> = tx
                .prepare(
                    "SELECT id, member_id FROM record \
                      WHERE blob IS NOT NULL AND received_at < ?1 \
                      ORDER BY received_at, rowid LIMIT ?2",
                )?
                .query_map(params![cutoff, limit], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            for (id, member) in &rows {
                delete_held(tx, id, member, now)?;
            }
            Ok(rows.len() as u64)
        })
    }

    fn prune_deletions(&self, before: i64) -> StoreFuture<'_, u64> {
        self.write(move |tx| {
            Ok(tx.execute(
                "DELETE FROM deletion WHERE deleted_at < ?1 \
                   AND idx < (SELECT MAX(idx) FROM deletion)",
                [before],
            )? as u64)
        })
    }

    fn prune_audit(&self, before: i64) -> StoreFuture<'_, u64> {
        self.write(move |tx| {
            Ok(tx.execute(
                "DELETE FROM audit WHERE at < ?1 AND idx < (SELECT MAX(idx) FROM audit)",
                [before],
            )? as u64)
        })
    }

    fn checkpoint(&self) -> StoreFuture<'_, ()> {
        self.run(|inner| {
            let conn = lock(&inner.writer);
            let (busy, log, done): (i64, i64, i64) =
                conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
            if busy != 0 {
                return Err(StoreError::Backend(format!(
                    "wal_checkpoint(TRUNCATE) was blocked ({done} of {log} frames copied)"
                )));
            }
            Ok(())
        })
    }

    fn deletions(&self, from: u64, limit: u32) -> StoreFuture<'_, DeletionsResponse> {
        self.read(move |tx| {
            let heads = deletion_heads_tx(tx)?;
            let from = i64_of(from, || "from".to_string())?;
            let entries = tx
                .prepare(
                    "SELECT idx, record_id FROM deletion WHERE idx >= ?1 ORDER BY idx LIMIT ?2",
                )?
                .query_map(params![from, limit], |r| {
                    Ok(DeletionEntry {
                        idx: u64_at(r, 0)?,
                        record_id: id_at(r, 1)?,
                    })
                })?
                .collect::<Result<_, _>>()?;
            Ok(DeletionsResponse {
                head: heads.head,
                oldest: heads.oldest,
                entries,
            })
        })
    }

    fn deletion_heads(&self) -> StoreFuture<'_, DeletionHeads> {
        self.read(|tx| deletion_heads_tx(tx))
    }

    fn append_audit(&self, e: AuditEntry) -> StoreFuture<'_, u64> {
        self.write(move |tx| {
            let idx = audit_tx(tx, e.at, e.actor, &e.action, e.target, e.detail)?;
            u64::try_from(idx).map_err(|_| broken("audit idx"))
        })
    }

    fn audit(&self, from: u64, limit: u32) -> StoreFuture<'_, AuditResponse> {
        self.read(move |tx| {
            let from = i64_of(from, || "from".to_string())?;
            let head: i64 =
                tx.query_row("SELECT COALESCE(MAX(idx), -1) FROM audit", [], |r| r.get(0))?;
            let rows = tx
                .prepare(
                    "SELECT idx, at, actor, action, target, detail FROM audit \
                      WHERE idx >= ?1 ORDER BY idx LIMIT ?2",
                )?
                .query_map(params![from, limit], |r| {
                    Ok(AuditRow {
                        idx: u64_at(r, 0)?,
                        at: r.get(1)?,
                        actor: opt_id_at(r, 2)?,
                        action: r.get(3)?,
                        target: r.get(4)?,
                        detail: r.get(5)?,
                    })
                })?
                .collect::<Result<_, _>>()?;
            Ok(AuditResponse { head, rows })
        })
    }

    fn export_canonical(&self, dest: PathBuf) -> StoreFuture<'_, TableCounts> {
        self.run(move |inner| {
            let side = inner.side_connection()?;
            with_new_file(&dest, || {
                side.execute("VACUUM INTO ?1", [path_str(&dest)?])?;
                let mut out = finish_copy(&dest)?;
                let tx = out.transaction()?;
                // The backup's own state and a not yet used bootstrap token stay on this server.
                tx.execute(
                    "DELETE FROM meta WHERE key LIKE 'backup\\_%' ESCAPE '\\' \
                        OR key LIKE 'bootstrap\\_%' ESCAPE '\\'",
                    [],
                )?;
                tx.execute("DELETE FROM backup_log", [])?;
                tx.commit()?;
                out.execute_batch("VACUUM")?;
                canonical_counts(&out, "main")
            })
        })
    }

    fn import_canonical(&self, src: PathBuf) -> StoreFuture<'_, TableCounts> {
        self.run(move |inner| {
            let mut conn = lock(&inner.writer);
            if store_holds_org(&conn)? {
                return Err(StoreError::NotEmpty);
            }
            attach_existing(&conn, &src, "src")?;
            let result = (|| {
                check_attached_schema(&conn, "src")?;
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                if store_holds_org(&tx)? {
                    return Err(StoreError::NotEmpty);
                }
                let counts = copy_canonical(&tx, "src")?;
                tx.commit()?;
                Ok(counts)
            })();
            let detached = conn.execute_batch("DETACH DATABASE src");
            let counts = result?;
            detached?;
            Ok(counts)
        })
    }

    fn dump(&self) -> StoreFuture<'_, LogicalDump> {
        self.read(|tx| dump_tx(tx, "main"))
    }

    fn backup_log_head(&self) -> StoreFuture<'_, i64> {
        self.read(|tx| backup_log_head_tx(tx, "main"))
    }

    fn backup_log(&self, after: i64, limit: u32) -> StoreFuture<'_, Vec<BackupLogRow>> {
        self.read(move |tx| {
            Ok(tx
                .prepare(
                    "SELECT seq, tbl, key, op FROM backup_log WHERE seq > ?1 \
                      ORDER BY seq LIMIT ?2",
                )?
                .query_map(params![after, limit], |r| {
                    Ok(BackupLogRow {
                        seq: r.get(0)?,
                        tbl: r.get(1)?,
                        key: r.get(2)?,
                        op: r.get(3)?,
                    })
                })?
                .collect::<Result<_, _>>()?)
        })
    }

    fn prune_backup_log(&self, upto: i64) -> StoreFuture<'_, u64> {
        self.write(move |tx| {
            Ok(tx.execute("DELETE FROM backup_log WHERE seq <= ?1", [upto])? as u64)
        })
    }

    fn snapshot(&self, dest: PathBuf) -> StoreFuture<'_, i64> {
        self.run(move |inner| {
            let side = inner.side_connection()?;
            with_new_file(&dest, || {
                side.execute("VACUUM INTO ?1", [path_str(&dest)?])?;
                let copy = finish_copy(&dest)?;
                backup_log_head_tx(&copy, "main")
            })
        })
    }

    fn export_changes(&self, after: i64, dest: PathBuf) -> StoreFuture<'_, ChangeSet> {
        self.run(move |inner| {
            let live = inner.path.clone();
            with_new_file(&dest, || {
                let mut out = Connection::open_with_flags(
                    &dest,
                    OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )?;
                out.busy_timeout(BUSY_TIMEOUT)?;
                out.query_row("PRAGMA journal_mode=DELETE", [], |r| r.get::<_, String>(0))?;
                out.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA secure_delete=ON;")?;
                migrate(&mut out)?;
                let triggers: Vec<String> = out
                    .prepare("SELECT name FROM sqlite_master WHERE type = 'trigger'")?
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                for t in triggers {
                    out.execute_batch(&format!("DROP TRIGGER \"{t}\""))?;
                }
                out.execute_batch("DELETE FROM meta; DELETE FROM backup_log;")?;
                attach_existing(&out, &live, "live")?;
                let result: StoreResult<ChangeSet> = (|| {
                    // Deferred: the first statement takes `main` for writing and `live` for
                    // reading only, and the read lasts until COMMIT, so the log range and the
                    // rows come from one snapshot of the live database.
                    let tx = out.transaction()?;
                    tx.execute(
                        "INSERT INTO main.backup_log (seq, tbl, key, op) \
                         SELECT seq, tbl, key, op FROM live.backup_log WHERE seq > ?1",
                        [after],
                    )?;
                    for (table, key) in LOG_KEYS {
                        let cols = columns_of(table)?.join(", ");
                        tx.execute(
                            &format!(
                                "INSERT INTO main.{table} ({cols}) SELECT {cols} FROM live.{table} \
                                  WHERE {key} IN (SELECT key FROM main.backup_log WHERE tbl = ?1)"
                            ),
                            [table],
                        )?;
                    }
                    let info = changes_info(&tx, "main", after)?;
                    tx.commit()?;
                    Ok(info)
                })();
                let detached = out.execute_batch("DETACH DATABASE live");
                let info = result?;
                detached?;
                Ok(ChangeSet { after, ..info })
            })
        })
    }

    fn apply_changes(&self, src: PathBuf) -> StoreFuture<'_, ChangeSet> {
        self.run(move |inner| {
            let mut conn = lock(&inner.writer);
            attach_existing(&conn, &src, "inc")?;
            let result = (|| {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                tx.execute_batch("PRAGMA defer_foreign_keys=ON")?;
                let unknown: i64 = tx.query_row(
                    &format!(
                        "SELECT COUNT(*) FROM inc.backup_log WHERE tbl NOT IN ({})",
                        LOG_KEYS
                            .iter()
                            .map(|(t, _)| format!("'{t}'"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    [],
                    |r| r.get(0),
                )?;
                if unknown > 0 {
                    return Err(StoreError::Backend(
                        "change set names a table this binary does not know".into(),
                    ));
                }
                for (table, key) in LOG_KEYS {
                    let cols = columns_of(table)?.join(", ");
                    let keep = if *table == "meta" {
                        format!(" AND {CANONICAL_META_SQL}")
                    } else {
                        String::new()
                    };
                    tx.execute(
                        &format!(
                            "DELETE FROM main.{table} WHERE {key} IN \
                             (SELECT key FROM inc.backup_log WHERE tbl = ?1){keep}"
                        ),
                        [table],
                    )?;
                    tx.execute(
                        &format!(
                            "INSERT INTO main.{table} ({cols}) SELECT {cols} FROM inc.{table} \
                              WHERE true{keep}"
                        ),
                        [],
                    )?;
                }
                foreign_key_check(&tx, "main")?;
                let info = changes_info(&tx, "inc", 0)?;
                tx.commit()?;
                Ok(info)
            })();
            let detached = conn.execute_batch("DETACH DATABASE inc");
            let info = result?;
            detached?;
            Ok(info)
        })
    }
}
