//! Database connections, schema migrations and version checks (plan-v2 §6.1, §6.2).
//!
//! File modes (unix): the parent directory is created 0700 and a new database
//! file is created 0600 before SQLite first opens it. SQLite's unix VFS gives
//! the `-wal`, `-shm` and `-journal` files the same permissions as the main
//! database file, so they are 0600 as well. Backups written by [`migrate`] are
//! created 0600 the same way.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

/// Embedded migrations: (version, name, SQL). Versions start at 1 and increase
/// by one. There are no down migrations.
pub const MIGRATIONS: &[(u32, &str, &str)] = &[
    (1, "0001_init", include_str!("../migrations/0001_init.sql")),
    (
        2,
        "0002_event_agent",
        include_str!("../migrations/0002_event_agent.sql"),
    ),
];

/// Who opens the database; decides creation and `busy_timeout`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Sync hooks: never create, give up on a lock quickly.
    HookRead,
    /// Async capture hook.
    Capture,
    /// CLI commands.
    Cli,
}

impl Role {
    /// `busy_timeout` for this role (assumptions, plan-v2 §5.4 and §6.1).
    pub fn busy_timeout(self) -> Duration {
        match self {
            Role::HookRead => Duration::from_millis(50),
            Role::Capture => Duration::from_millis(2_000),
            Role::Cli => Duration::from_millis(5_000),
        }
    }

    fn may_create(self) -> bool {
        !matches!(self, Role::HookRead)
    }
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

/// Result of [`check_version`]; hooks use it and never migrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionCheck {
    Current,
    Older { db: u32, bin: u32 },
    Newer { db: u32, bin: u32 },
}

/// Opens the database at `path` and sets the connection pragmas.
///
/// `Capture` and `Cli` create the parent directory (0700) and the file (0600)
/// when missing. `HookRead` opens read-write without create and fails if the
/// file is missing, creating nothing.
pub fn open(path: &Path, role: Role) -> anyhow::Result<Connection> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if role.may_create() {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            crate::paths::ensure_private_dir(parent)?;
        }
        create_private_file(path)?;
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    } else if !path.is_file() {
        bail!("database not found: {}", path.display());
    }
    let conn = Connection::open_with_flags(path, flags)
        .with_context(|| format!("cannot open database {}", path.display()))?;
    conn.busy_timeout(role.busy_timeout())?;
    let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        bail!(
            "cannot set journal_mode=WAL on {} (got {mode})",
            path.display()
        );
    }
    conn.execute_batch(
        "PRAGMA synchronous=NORMAL;\n\
         PRAGMA foreign_keys=ON;\n\
         PRAGMA secure_delete=ON;",
    )?;
    Ok(conn)
}

/// Creates an empty file with mode 0600 if `path` does not exist yet.
/// SQLite treats an empty file as an empty database.
fn create_private_file(path: &Path) -> anyhow::Result<()> {
    match create_new_private_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        r => r.with_context(|| format!("cannot create {}", path.display())),
    }
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
    // The umask can only remove bits; set the mode explicitly so it is exactly 0600.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Whether the linked SQLite was compiled with FTS5.
pub fn has_fts5(conn: &Connection) -> anyhow::Result<bool> {
    let mut st = conn.prepare("PRAGMA compile_options")?;
    let opts = st.query_map([], |r| r.get::<_, String>(0))?;
    for opt in opts {
        if opt?.contains("ENABLE_FTS5") {
            return Ok(true);
        }
    }
    Ok(false)
}

/// sha256 hex of a migration's text, as stored in `schema_version.checksum`.
pub fn checksum(sql: &str) -> String {
    Sha256::digest(sql.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Highest applied schema version; 0 when `schema_version` does not exist or is empty.
pub fn schema_version(conn: &Connection) -> anyhow::Result<u32> {
    if !table_exists(conn, "schema_version")? {
        return Ok(0);
    }
    let v: Option<u32> =
        conn.query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))?;
    Ok(v.unwrap_or(0))
}

/// Compares the database's schema version with the binary's. Never writes.
pub fn check_version(conn: &Connection) -> anyhow::Result<VersionCheck> {
    let db = schema_version(conn)?;
    let bin = binary_version(MIGRATIONS);
    Ok(match db.cmp(&bin) {
        std::cmp::Ordering::Equal => VersionCheck::Current,
        std::cmp::Ordering::Less => VersionCheck::Older { db, bin },
        std::cmp::Ordering::Greater => VersionCheck::Newer { db, bin },
    })
}

/// Applies the embedded [`MIGRATIONS`] (plan-v2 §6.2).
pub fn migrate(conn: &mut Connection) -> anyhow::Result<MigrateOutcome> {
    migrate_with(conn, MIGRATIONS)
}

/// Applies `migrations` (sorted, versions 1, 2, ...) to `conn`.
///
/// Order: FTS5 check; refuse a newer database; verify the checksum of every
/// applied migration; when the database holds data and migrations are pending,
/// `VACUUM INTO '{db}.bak-v{from}'` (outside any transaction, as SQLite
/// requires); `BEGIN IMMEDIATE`, re-check the version, apply each pending file
/// and insert its `schema_version` row; `COMMIT`; `PRAGMA quick_check`.
pub fn migrate_with(
    conn: &mut Connection,
    migrations: &[(u32, &str, &str)],
) -> anyhow::Result<MigrateOutcome> {
    validate_list(migrations)?;
    if !has_fts5(conn)? {
        bail!(
            "SQLite was built without FTS5 (ENABLE_FTS5 missing from PRAGMA compile_options); \
             awm cannot use this database"
        );
    }
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

    let backup = if holds_data(conn, from)? {
        Some(backup(conn, from)?)
    } else {
        None
    };

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Another process may have migrated between the checks above and the lock.
    let locked_from = verify_applied(&tx, migrations)?;
    if locked_from != from {
        bail!(
            "the database schema changed during the migration (version {from} -> {locked_from}); \
             run the command again"
        );
    }
    for (version, name, sql) in &pending {
        tx.execute_batch(sql)
            .with_context(|| format!("migration {name} failed"))?;
        tx.execute(
            "INSERT INTO schema_version (version, name, checksum, applied_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![version, name, checksum(sql), now_ms()],
        )
        .with_context(|| format!("cannot record migration {name}"))?;
    }
    tx.commit()?;

    quick_check(conn, backup.as_deref())?;
    Ok(MigrateOutcome {
        from,
        to: binary_version(migrations),
        backup,
    })
}

fn binary_version(migrations: &[(u32, &str, &str)]) -> u32 {
    migrations.last().map_or(0, |(v, _, _)| *v)
}

fn validate_list(migrations: &[(u32, &str, &str)]) -> anyhow::Result<()> {
    for (i, (version, name, _)) in migrations.iter().enumerate() {
        let expected = u32::try_from(i + 1)?;
        if *version != expected {
            bail!("embedded migration {name} has version {version}, expected {expected}");
        }
    }
    Ok(())
}

/// Refuses a newer database, a missing applied migration or a checksum
/// mismatch; returns the highest applied version.
fn verify_applied(conn: &Connection, migrations: &[(u32, &str, &str)]) -> anyhow::Result<u32> {
    let db = schema_version(conn)?;
    let bin = binary_version(migrations);
    if db > bin {
        bail!("agent-web-memory: database is from a newer awm ({db}). Upgrade awm.");
    }
    if db == 0 {
        return Ok(0);
    }
    let mut st = conn.prepare("SELECT name, checksum FROM schema_version WHERE version = ?1")?;
    for (version, name, sql) in migrations.iter().filter(|(v, _, _)| *v <= db) {
        let row: Option<(String, String)> = st
            .query_row([version], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let (_, stored) = row.ok_or_else(|| {
            anyhow!("migration {name} is missing from schema_version (database at version {db})")
        })?;
        if stored != checksum(sql) {
            bail!(
                "checksum mismatch for migration {name}: the database records {stored}, \
                 this awm embeds {}; refusing to migrate",
                checksum(sql)
            );
        }
    }
    Ok(db)
}

/// Data is present when any migration was applied or `event` has a row.
fn holds_data(conn: &Connection, from: u32) -> anyhow::Result<bool> {
    if from > 0 {
        return Ok(true);
    }
    if !table_exists(conn, "event")? {
        return Ok(false);
    }
    Ok(conn
        .query_row("SELECT 1 FROM event LIMIT 1", [], |_| Ok(()))
        .optional()?
        .is_some())
}

/// Writes `{db}.bak-v{from}` with `VACUUM INTO`. The copy goes to a new 0600
/// temporary file whose name is unique to this process and call
/// (`{db}.bak-v{from}.tmp-{pid}-{nanos}`, created with `create_new`), is synced,
/// checked to be at schema version `from` (another migrator may have committed
/// since `from` was read), then renamed over any older backup; on unix the
/// directory is synced after the rename so the new name survives a power cut.
fn backup(conn: &Connection, from: u32) -> anyhow::Result<PathBuf> {
    let db = conn
        .path()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| anyhow!("cannot back up a database that has no file"))?;
    let target = PathBuf::from(format!("{db}.bak-v{from}"));
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    let tmp = PathBuf::from(format!(
        "{db}.bak-v{from}.tmp-{}-{nanos}",
        std::process::id()
    ));
    create_new_private_file(&tmp).with_context(|| format!("cannot create {}", tmp.display()))?;
    let result = write_backup(conn, from, &tmp, &target);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result?;
    Ok(target)
}

fn write_backup(conn: &Connection, from: u32, tmp: &Path, target: &Path) -> anyhow::Result<()> {
    let tmp_str = tmp
        .to_str()
        .ok_or_else(|| anyhow!("backup path is not valid UTF-8: {}", tmp.display()))?;
    conn.execute("VACUUM INTO ?1", [tmp_str])
        .with_context(|| format!("backup to {} failed", tmp.display()))?;
    std::fs::File::open(tmp)
        .and_then(|f| f.sync_all())
        .with_context(|| format!("cannot sync {}", tmp.display()))?;
    let copied = {
        let copy = Connection::open_with_flags(
            tmp,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("cannot open {}", tmp.display()))?;
        schema_version(&copy)?
    };
    if copied != from {
        bail!(
            "the database schema changed during the migration (version {from} -> {copied}); \
             run the command again"
        );
    }
    std::fs::rename(tmp, target)
        .with_context(|| format!("cannot move backup to {}", target.display()))?;
    #[cfg(unix)]
    if let Some(dir) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::File::open(dir)
            .and_then(|f| f.sync_all())
            .with_context(|| format!("cannot sync directory {}", dir.display()))?;
    }
    Ok(())
}

/// Runs after `COMMIT`: a failure means the migration is already applied.
fn quick_check(conn: &Connection, backup: Option<&Path>) -> anyhow::Result<()> {
    let mut st = conn.prepare("PRAGMA quick_check")?;
    let rows: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<_, _>>()?;
    if rows != ["ok"] {
        let restore = match backup {
            Some(b) => format!("the backup taken before migrating is {}", b.display()),
            None => "no backup was taken (the database held no data)".to_string(),
        };
        bail!(
            "PRAGMA quick_check failed after migration (the migration is already committed; \
             {restore}): {}",
            rows.join("; ")
        );
    }
    Ok(())
}

fn table_exists(conn: &Connection, name: &str) -> anyhow::Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn now_ms() -> i64 {
    let ms = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    i64::try_from(ms).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leftovers(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".bak-v"))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_backup_is_refused_when_the_copy_is_not_at_the_expected_version() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = open(&dir.path().join("awm.db"), Role::Cli).unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 2);

        // `from` was read as 1, but the database is at 2 by the time of `VACUUM INTO`.
        let err = backup(&conn, 1).unwrap_err().to_string();
        assert_eq!(
            err,
            "the database schema changed during the migration (version 1 -> 2); \
             run the command again"
        );
        assert_eq!(leftovers(dir.path()), Vec::<String>::new());

        let target = backup(&conn, 2).unwrap();
        assert_eq!(target.file_name().unwrap(), "awm.db.bak-v2");
        assert_eq!(leftovers(dir.path()), ["awm.db.bak-v2"]);
        let copy = Connection::open(&target).unwrap();
        assert_eq!(schema_version(&copy).unwrap(), 2);
    }

    #[test]
    fn a_refused_backup_leaves_the_existing_backup_alone() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = open(&dir.path().join("awm.db"), Role::Cli).unwrap();
        migrate(&mut conn).unwrap();
        let old = dir.path().join("awm.db.bak-v1");
        std::fs::write(&old, b"older backup").unwrap();
        assert!(backup(&conn, 1).is_err());
        assert_eq!(std::fs::read(&old).unwrap(), b"older backup");
        assert_eq!(leftovers(dir.path()), ["awm.db.bak-v1"]);
    }
}
