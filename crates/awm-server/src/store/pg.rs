//! `PgStore`: pooled Postgres with `org_id` row-level security (plan-v3-team §4.2, TM26).
//!
//! One database holds many organisations (the cloud) or one (self-host path A, Cloud SQL).
//! Every table of `migrations/pg/0001_server.sql` has an `org_id` column leading its keys, and
//! row-level security, enabled and forced on every table, admits only the rows whose `org_id`
//! equals the transaction's `awm.org` setting. [`PgStore::for_org`] hands out a [`Store`] for
//! one organisation scope ([`PgOrg`]); each of its transactions sets `awm.org` with
//! `set_config('awm.org', $1, true)` (the parameterised form of `SET LOCAL`) as its first
//! statement, so no statement of a scope runs without it, and a statement can only ever see
//! the scope's rows. Statements name `org_id` only to insert it.
//!
//! The scope key is the organisation id TM19 reads from the token (`awm_t_{org}_{secret}`);
//! `org.id` inside the scope is the organisation id the bootstrap or the canonical import
//! wrote, and TM7 compares it with the token's (`AuthDevice::org_id`).
//!
//! Roles (§4.2): the server connects as the application role (`awm_app`), which owns no table
//! and has no `BYPASSRLS`; [`PgStore::connect`] refuses to serve otherwise. Migrations run at
//! start over a second connection as the owner role (`awm_owner`, `--database-url-owner-env`),
//! in one transaction under `pg_advisory_xact_lock`, with checksums in `schema_migrations` and
//! no downgrade ([`migrate`]).
//!
//! Write transactions run at READ COMMITTED behind transaction-scoped advisory locks, which
//! give the single-writer guarantees `SqliteStore` gets from its file lock:
//! - every write takes the organisation's lock exclusively, except pushes of records only, which
//!   take it shared; so the deletion stream, the audit log, membership and settings have one
//!   writer per organisation at a time (§4.3.4), and a push's checks against the deletion
//!   stream cannot race a deletion;
//! - a push also takes one exclusive lock per stream it writes (sorted, after the organisation
//!   lock), so `idx = head + 1` is checked and written by one writer per stream (§4.2);
//! - a push of one new id into two streams at once is settled by the `record_id_unique`
//!   constraint, reported as `IdConflict` like the serial check.
//!
//! Reads run in one REPEATABLE READ, READ ONLY transaction each, so `status` and `pull` read one
//! snapshot. The pool holds at most [`MAX_POOL_SIZE`] connections (§4.2, W31). TLS is not
//! built in: connect over the Cloud SQL Unix socket (`host=/cloudsql/...`, W31), localhost or a
//! private network; any other TCP host is refused unless the operator accepts the risk
//! (`--database-insecure-network`, RVT2 M4; TLS to Postgres is a later dependency decision).

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use awm_proto::wire::{
    limits, AuditResponse, AuditRow, Cursor, DeleteRequest, DeleteResponse, DeletionEntry,
    DeletionHeads, DeletionsResponse, DeviceInfo, DeviceWrap, EpochWrap, Handle, Id, InviteKind,
    Key32, KeysResponse, MemberInfo, OrgSettings, OwnHead, PendingDevice, PullResponse,
    PulledDeleted, PulledItem, PulledRecord, PushItem, PushResponse, Role, SettingsUpdate,
    StatusResponse, StoredWrap, StreamHead, StreamRecords, Tag, Version, B64,
};
use deadpool_postgres::{
    Manager, ManagerConfig, Object, Pool, PoolError, RecyclingMethod, Runtime,
};
use tokio_postgres::error::SqlState;
use tokio_postgres::types::{FromSql, ToSql, Type};
use tokio_postgres::{Config, IsolationLevel, NoTls, Row};

use super::{
    binary_version, broken, canonical_meta_key, check_applied, check_hash, hour, i64_of, item_len,
    json_len, meta_keys, role_str, valid_token_hash, validate_list, Actor, AuditEntry, AuthDevice,
    DeviceRow, DumpValue, InviteRow, Joined, LogicalDump, MemberRow, NewBootstrap, NewInvite,
    NewJoin, OrgRow, PushBatch, RawOrg, RestoreState, Store, StoreError, StoreFuture, StoreResult,
    TableCounts, CANONICAL_META_SQL, CANONICAL_TABLES, HOLDS_ORG_SQL,
};

/// Embedded migrations: (version, name, SQL). Versions start at 1 and increase by one; there
/// are no down migrations.
pub const MIGRATIONS: &[(u32, &str, &str)] = &[(
    1,
    "0001_server",
    include_str!("../../migrations/pg/0001_server.sql"),
)];

/// Connections per [`PgStore`] (§4.2: Cloud Run instances may open at most 100 connections to
/// a Cloud SQL database, W31; 10 per instance is the plan's assumption).
pub const MAX_POOL_SIZE: usize = 10;

/// `application_name` of the server's connections unless the URL sets one.
pub const APPLICATION_NAME: &str = "awm-server";

/// How long a request waits for a pooled connection before it fails.
const POOL_WAIT: Duration = Duration::from_secs(30);
/// Connect timeout unless the URL sets one.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The tables that hold organisation rows, children first (`delete_org`, the catalog tests).
pub const ORG_TABLES: &[&str] = &[
    "claim", "audit", "wrap", "deletion", "record", "invite", "device", "member", "meta", "org",
];

/// The `claim` name of retention runs (TM9 P2).
pub const RETENTION_CLAIM: &str = "retention";

/// The version table, created by the runner under its lock before any migration file runs.
/// Readable by every role (the policy admits every row), writable only by its owner.
const SCHEMA_MIGRATIONS_DDL: &str = "\
CREATE TABLE schema_migrations (
  version    INTEGER NOT NULL PRIMARY KEY CHECK (version >= 1),
  name       TEXT    NOT NULL,
  checksum   TEXT    NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE schema_migrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE schema_migrations FORCE ROW LEVEL SECURITY;
CREATE POLICY readable ON schema_migrations USING (true) WITH CHECK (true);
REVOKE ALL ON schema_migrations FROM PUBLIC;
DO $$ BEGIN
  EXECUTE format('GRANT SELECT ON schema_migrations TO %I', current_setting('awm.app_role'));
END $$;
";

// ---------------------------------------------------------------------------------------------
// Errors (never a row value: no DETAIL, HINT or WHERE of a server error)

/// A Postgres error as text: the SQLSTATE, the server's primary message and the names of the
/// constraint, table and column, or the client-side error and its cause. The DETAIL field
/// (which repeats key values, e.g. a token hash in a unique violation) is never included.
fn pg_text(e: &tokio_postgres::Error) -> String {
    match e.as_db_error() {
        Some(db) => {
            let mut s = format!("{} {}", db.code().code(), db.message());
            for (what, v) in [
                ("constraint", db.constraint()),
                ("table", db.table()),
                ("column", db.column()),
            ] {
                if let Some(v) = v {
                    s.push_str(&format!(" ({what} {v})"));
                }
            }
            s
        }
        None => match std::error::Error::source(e) {
            Some(cause) => format!("{e}: {cause}"),
            None => e.to_string(),
        },
    }
}

impl From<tokio_postgres::Error> for StoreError {
    fn from(e: tokio_postgres::Error) -> StoreError {
        StoreError::Backend(format!("postgres: {}", pg_text(&e)))
    }
}

fn pool_err(e: PoolError) -> StoreError {
    match e {
        PoolError::Backend(e) => StoreError::Backend(format!("postgres pool: {}", pg_text(&e))),
        other => StoreError::Backend(format!("postgres pool: {other}")),
    }
}

fn is_unique_violation(e: &tokio_postgres::Error, constraint: &str) -> bool {
    e.as_db_error().is_some_and(|db| {
        *db.code() == SqlState::UNIQUE_VIOLATION && db.constraint() == Some(constraint)
    })
}

// ---------------------------------------------------------------------------------------------
// URLs, roles, locks

/// Parses a database URL: the TCP form (`postgres://user:pass@host:port/db`) or the Cloud SQL
/// Unix-socket form (`postgres://user:pass@/db?host=/cloudsql/project:region:instance`, W31; the
/// socket directory may also be percent-encoded in the host part). Sets `application_name`
/// and a connect timeout when the URL has none. The error never repeats the URL (it holds the
/// password).
pub fn parse_url(url: &str) -> StoreResult<Config> {
    let mut cfg: Config = url.parse().map_err(|_| {
        StoreError::Backend(
            "invalid database URL (the URL is not shown: it holds a password)".into(),
        )
    })?;
    if cfg.get_application_name().is_none() {
        cfg.application_name(APPLICATION_NAME);
    }
    if cfg.get_connect_timeout().is_none() {
        cfg.connect_timeout(CONNECT_TIMEOUT);
    }
    Ok(cfg)
}

fn lock_key(parts: &[&str]) -> i64 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0u8]);
    }
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    i64::from_be_bytes(b)
}

/// The advisory-lock key of an organisation scope (its write lock).
pub fn org_lock_key(org: Id) -> i64 {
    lock_key(&["awm.org", &org.to_string()])
}

/// The advisory-lock key of one stream of a scope.
pub fn stream_lock_key(org: Id, member: Id, device: Id, tag: &str) -> i64 {
    lock_key(&[
        "awm.stream",
        &org.to_string(),
        &member.to_string(),
        &device.to_string(),
        tag,
    ])
}

/// The advisory-lock key the migration runner holds for its transaction.
pub fn migration_lock_key() -> i64 {
    lock_key(&["awm.migrate"])
}

/// Whether `ip` is this host's or a private network's: loopback, RFC 1918, IPv6 unique local
/// (`fc00::/7`) or link-local (`169.254.0.0/16`, `fe80::/10`).
pub fn private_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v) => v.is_loopback() || v.is_private() || v.is_link_local(),
        IpAddr::V6(v) => {
            let s = v.segments()[0];
            v.is_loopback() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
    }
}

/// RVT2 M4: the connections have no TLS (`NoTls`), so a host outside this machine and the
/// private ranges would carry the metadata and ciphertext, and accept changed rows, over a
/// network anyone on the path can read and write. Returns the first such host of `cfg`, or
/// `None` when every host is a Unix socket (the Cloud SQL socket), an address [`private_ip`]
/// accepts, or a name that resolves only to such addresses (`localhost`, a compose service).
/// A name that does not resolve is returned too.
pub async fn public_host(cfg: &Config) -> Option<String> {
    use tokio_postgres::config::Host;
    let port = cfg.get_ports().first().copied().unwrap_or(5432);
    for ip in cfg.get_hostaddrs() {
        if !private_ip(*ip) {
            return Some(ip.to_string());
        }
    }
    if !cfg.get_hostaddrs().is_empty() {
        // `hostaddr` is what the connection uses; `host` then only names the server.
        return None;
    }
    for h in cfg.get_hosts() {
        let Host::Tcp(name) = h else { continue };
        if let Ok(ip) = name.parse::<IpAddr>() {
            if !private_ip(ip) {
                return Some(name.clone());
            }
            continue;
        }
        match tokio::net::lookup_host((name.as_str(), port)).await {
            Ok(addrs) => {
                let addrs: Vec<_> = addrs.collect();
                if addrs.is_empty() || addrs.iter().any(|a| !private_ip(a.ip())) {
                    return Some(name.clone());
                }
            }
            Err(_) => return Some(name.clone()),
        }
    }
    None
}

/// The refusal of [`public_host`] (`awm serve` exits 2 with it).
pub fn public_host_refusal(host: &str) -> String {
    format!(
        "the database host {host} is not loopback, a private address (RFC 1918, ULA, \
         link-local) or a Unix socket, and the connection has no TLS: anyone on the path could \
         read and change the data. Connect over a private network or the Cloud SQL socket \
         (host=/cloudsql/...), or accept the risk with --database-insecure-network \
         (server.toml database_insecure_network = true)"
    )
}

async fn connect_one(cfg: &Config) -> StoreResult<tokio_postgres::Client> {
    let (client, conn) = cfg.connect(NoTls).await?;
    tokio::spawn(async move {
        // The connection ends when the client is dropped; an I/O error ends it too.
        let _ = conn.await;
    });
    Ok(client)
}

// ---------------------------------------------------------------------------------------------
// Migrations

/// Result of [`migrate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrateOutcome {
    /// Schema version before the call.
    pub from: u32,
    /// Schema version after the call.
    pub to: u32,
}

/// Applies the embedded [`MIGRATIONS`] over a connection as the owner role (`owner`), granting
/// data access to `app_role` (the user of the application URL).
pub async fn migrate(owner: &Config, app_role: &str) -> StoreResult<MigrateOutcome> {
    migrate_with(owner, app_role, MIGRATIONS).await
}

/// Applies `migrations` (versions 1, 2, ... in order): in one transaction under
/// `pg_advisory_xact_lock(migration_lock_key())`, creating `schema_migrations` first when it
/// is missing; refuses a newer database, a missing checksum and a changed checksum; a run
/// with nothing pending changes nothing. Before committing it checks that the application role
/// exists, is not a superuser, has no `BYPASSRLS` and is not the owner, and that every table of
/// the schema has row-level security enabled and forced.
pub async fn migrate_with(
    owner: &Config,
    app_role: &str,
    migrations: &[(u32, &str, &str)],
) -> StoreResult<MigrateOutcome> {
    validate_list(migrations)?;
    let mut client = connect_one(owner).await?;
    let tx = client.transaction().await?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&migration_lock_key()])
        .await?;
    let me: String = tx.query_one("SELECT current_user::text", &[]).await?.get(0);
    if me == app_role {
        return Err(StoreError::Backend(
            "the application role must not be the role that runs the migrations".into(),
        ));
    }
    let role = tx
        .query_opt(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1",
            &[&app_role],
        )
        .await?;
    match role {
        None => {
            return Err(StoreError::Backend(format!(
                "the application role {app_role} does not exist; create it before migrating"
            )))
        }
        Some(r) if r.get::<_, bool>(0) || r.get::<_, bool>(1) => {
            return Err(StoreError::Backend(format!(
                "the application role {app_role} bypasses row-level security \
                 (superuser or BYPASSRLS); refusing to migrate"
            )))
        }
        Some(_) => {}
    }
    tx.execute("SELECT set_config('awm.app_role', $1, true)", &[&app_role])
        .await?;
    let exists: bool = tx
        .query_one("SELECT to_regclass('schema_migrations') IS NOT NULL", &[])
        .await?
        .get(0);
    if !exists {
        tx.batch_execute(SCHEMA_MIGRATIONS_DDL).await?;
    }
    let from = verify_applied(&tx, migrations).await?;
    let pending: Vec<&(u32, &str, &str)> =
        migrations.iter().filter(|(v, _, _)| *v > from).collect();
    if pending.is_empty() && exists {
        tx.rollback().await?;
        return Ok(MigrateOutcome { from, to: from });
    }
    for (version, name, sql) in &pending {
        tx.batch_execute(sql).await.map_err(|e| {
            StoreError::Backend(format!("migration {name} failed: {}", pg_text(&e)))
        })?;
        tx.execute(
            "INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
            &[&(*version as i32), name, &super::checksum(sql.as_bytes())],
        )
        .await?;
    }
    let unforced: i64 = tx
        .query_one(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') \
                AND NOT (c.relrowsecurity AND c.relforcerowsecurity)",
            &[],
        )
        .await?
        .get(0);
    if unforced > 0 {
        return Err(StoreError::Backend(format!(
            "refused: {unforced} table(s) without forced row-level security; nothing was changed"
        )));
    }
    tx.commit().await?;
    Ok(MigrateOutcome {
        from,
        to: binary_version(migrations),
    })
}

/// Refuses a newer database, a missing checksum or a checksum mismatch; returns the version.
async fn verify_applied(
    tx: &tokio_postgres::Transaction<'_>,
    migrations: &[(u32, &str, &str)],
) -> StoreResult<u32> {
    let rows = tx
        .query(
            "SELECT version, checksum FROM schema_migrations ORDER BY version",
            &[],
        )
        .await?;
    let applied: BTreeMap<u32, String> = rows
        .iter()
        .map(|r| (r.get::<_, i32>(0) as u32, r.get::<_, String>(1)))
        .collect();
    check_versions(&applied, migrations)
}

fn check_versions(
    applied: &BTreeMap<u32, String>,
    migrations: &[(u32, &str, &str)],
) -> StoreResult<u32> {
    let db = applied.keys().next_back().copied().unwrap_or(0);
    check_applied(db, migrations, "schema_migrations", |v| {
        Ok(applied.get(&v).cloned())
    })
}

// ---------------------------------------------------------------------------------------------
// The store and its organisation scopes

/// What [`PgStore::delete_org`] removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgDeletion {
    /// Rows deleted per table, in [`ORG_TABLES`] order.
    pub rows: Vec<(&'static str, u64)>,
    /// Tables vacuumed afterwards (through the owner connection; empty without one).
    pub vacuumed: Vec<&'static str>,
}

/// Pool counters (tests, `awm serve check`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStatus {
    pub max_size: usize,
    pub size: usize,
    pub available: usize,
    pub waiting: usize,
}

/// The Postgres-backed store (path A and the cloud): a pool of application-role connections
/// and, when given, the owner role's configuration (migrations at start, `VACUUM` after an
/// organisation is deleted).
pub struct PgStore {
    pool: Pool,
    owner: Option<Config>,
}

impl std::fmt::Debug for PgStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgStore")
            .field("pool", &self.pool_status())
            .field("owner", &self.owner.is_some())
            .finish()
    }
}

impl PgStore {
    /// Connects to `url` as the application role with a pool of `pool_size` connections
    /// (capped at [`MAX_POOL_SIZE`]). With `owner_url` (the value of the variable that
    /// `--database-url-owner-env` names) it first runs the migrations as the owner role.
    /// Then it refuses to serve when the application role is a superuser, has `BYPASSRLS`, or
    /// owns (or may act as the owner of) any table of the schema, and when the schema is not at
    /// this binary's version with matching checksums. A TCP host outside loopback and the
    /// private ranges is refused before anything is sent ([`public_host`]); see
    /// [`PgStore::connect_with`].
    pub async fn connect(
        url: &str,
        owner_url: Option<&str>,
        pool_size: usize,
    ) -> StoreResult<PgStore> {
        PgStore::connect_with(url, owner_url, pool_size, false).await
    }

    /// [`PgStore::connect`]; `insecure_network` (`--database-insecure-network`) accepts a host
    /// that [`public_host`] refuses.
    pub async fn connect_with(
        url: &str,
        owner_url: Option<&str>,
        pool_size: usize,
        insecure_network: bool,
    ) -> StoreResult<PgStore> {
        if pool_size == 0 {
            return Err(StoreError::Backend("pool size must be at least 1".into()));
        }
        let app = parse_url(url)?;
        let app_role = app
            .get_user()
            .ok_or_else(|| StoreError::Backend("the database URL names no user".into()))?
            .to_string();
        let owner = owner_url.map(parse_url).transpose()?;
        if !insecure_network {
            for cfg in std::iter::once(&app).chain(owner.as_ref()) {
                if let Some(host) = public_host(cfg).await {
                    return Err(StoreError::Backend(public_host_refusal(&host)));
                }
            }
        }
        if let Some(o) = &owner {
            migrate(o, &app_role).await?;
        }
        let mgr = Manager::from_config(
            app,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(mgr)
            .max_size(pool_size.min(MAX_POOL_SIZE))
            .wait_timeout(Some(POOL_WAIT))
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|e| StoreError::Backend(format!("postgres pool: {e}")))?;
        let store = PgStore { pool, owner };
        store.check_app_role().await?;
        Ok(store)
    }

    async fn check_app_role(&self) -> StoreResult<()> {
        let c = self.pool.get().await.map_err(pool_err)?;
        let r = c
            .query_one(
                "SELECT r.rolsuper, r.rolbypassrls, \
                        (SELECT count(*) FROM pg_class t \
                           JOIN pg_namespace n ON n.oid = t.relnamespace \
                          WHERE n.nspname = current_schema() AND t.relkind IN ('r', 'p') \
                            AND pg_has_role(current_user, t.relowner, 'MEMBER')) \
                   FROM pg_roles r WHERE r.rolname = current_user",
                &[],
            )
            .await?;
        if r.get::<_, bool>(0) || r.get::<_, bool>(1) {
            return Err(StoreError::Backend(
                "the application role bypasses row-level security (superuser or BYPASSRLS); \
                 refusing to serve"
                    .into(),
            ));
        }
        if r.get::<_, i64>(2) > 0 {
            return Err(StoreError::Backend(
                "the application role owns, or may act as the owner of, a table of the schema; \
                 refusing to serve"
                    .into(),
            ));
        }
        let exists: bool = c
            .query_one("SELECT to_regclass('schema_migrations') IS NOT NULL", &[])
            .await?
            .get(0);
        if !exists {
            return Err(StoreError::Backend(
                "the database is not migrated; start once with the owner URL \
                 (--database-url-owner-env)"
                    .into(),
            ));
        }
        let rows = c
            .query(
                "SELECT version, checksum FROM schema_migrations ORDER BY version",
                &[],
            )
            .await?;
        let applied: BTreeMap<u32, String> = rows
            .iter()
            .map(|r| (r.get::<_, i32>(0) as u32, r.get::<_, String>(1)))
            .collect();
        let db = check_versions(&applied, MIGRATIONS)?;
        if db < binary_version(MIGRATIONS) {
            return Err(StoreError::Backend(format!(
                "the database schema is at version {db}, this binary needs {}; start once with \
                 the owner URL (--database-url-owner-env) to migrate",
                binary_version(MIGRATIONS)
            )));
        }
        Ok(())
    }

    /// The store of one organisation scope. Nothing is read or written until a method runs,
    /// so a scope for an unknown key costs nothing (TM19 routes from the token before any
    /// lookup); its methods then see no rows.
    pub fn for_org(&self, org: Id) -> Arc<dyn Store> {
        Arc::new(self.scope(org))
    }

    /// The concrete scope (for [`PgOrg::claim`]).
    pub fn scope(&self, org: Id) -> PgOrg {
        PgOrg {
            pool: self.pool.clone(),
            org,
            key: org.to_string(),
        }
    }

    /// Creates the organisation scope `org` if needed: its `generation` (a new UUIDv4) and
    /// `restore_pending = 0`, as `SqliteStore`'s migration seeds them; idempotent. Returns
    /// its store, empty and ready for `set_bootstrap` or `import_canonical`.
    pub async fn create_org(&self, org: Id) -> StoreResult<Arc<dyn Store>> {
        let scope = self.scope(org);
        scope.seed().await?;
        Ok(Arc::new(scope))
    }

    /// Deletes the organisation `org` (§5.6, TM22): every row of every table with that
    /// `org_id`, in one transaction under its write lock, then `VACUUM` of each affected table
    /// through the owner connection (outside the transaction; skipped without an owner URL).
    /// Rows are invisible at once; the bytes leave the data pages when they are reused and
    /// Cloud SQL's backups and recovery logs within the §5.6 window.
    pub async fn delete_org(&self, org: Id) -> StoreResult<OrgDeletion> {
        let rows = self.scope(org).delete_everything().await?;
        let mut vacuumed = Vec::new();
        if let Some(owner) = &self.owner {
            let client = connect_one(owner).await?;
            for (table, n) in &rows {
                if *n > 0 {
                    client.batch_execute(&format!("VACUUM {table}")).await?;
                    vacuumed.push(*table);
                }
            }
        }
        Ok(OrgDeletion { rows, vacuumed })
    }

    /// The pool's counters.
    pub fn pool_status(&self) -> PoolStatus {
        let s = self.pool.status();
        PoolStatus {
            max_size: s.max_size,
            size: s.size,
            available: s.available,
            waiting: s.waiting,
        }
    }
}

/// One organisation scope of a [`PgStore`]: a [`Store`] whose every transaction sets
/// `awm.org` to the scope's key first.
#[derive(Clone)]
pub struct PgOrg {
    pool: Pool,
    org: Id,
    key: String,
}

impl std::fmt::Debug for PgOrg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgOrg").field("org", &self.org).finish()
    }
}

/// How a transaction locks its organisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// REPEATABLE READ, READ ONLY: one snapshot, no lock.
    Read,
    /// READ COMMITTED without the organisation lock (a single-row update).
    Write,
    /// READ COMMITTED with the organisation lock shared (pushes of records only).
    Shared,
    /// READ COMMITTED with the organisation lock exclusive (every other write).
    Exclusive,
}

/// A scope's transaction: `awm.org` is set, the lock taken.
struct Tx<'a> {
    tx: deadpool_postgres::Transaction<'a>,
}

type Params<'p> = &'p [&'p (dyn ToSql + Sync)];

impl Tx<'_> {
    async fn rows(&self, sql: &str, p: Params<'_>) -> StoreResult<Vec<Row>> {
        let st = self.tx.prepare_cached(sql).await?;
        Ok(self.tx.query(&st, p).await?)
    }

    async fn opt(&self, sql: &str, p: Params<'_>) -> StoreResult<Option<Row>> {
        let st = self.tx.prepare_cached(sql).await?;
        Ok(self.tx.query_opt(&st, p).await?)
    }

    async fn one(&self, sql: &str, p: Params<'_>) -> StoreResult<Row> {
        let st = self.tx.prepare_cached(sql).await?;
        Ok(self.tx.query_one(&st, p).await?)
    }

    async fn exec(&self, sql: &str, p: Params<'_>) -> StoreResult<u64> {
        let st = self.tx.prepare_cached(sql).await?;
        Ok(self.tx.execute(&st, p).await?)
    }

    async fn commit(self) -> StoreResult<()> {
        Ok(self.tx.commit().await?)
    }
}

impl PgOrg {
    /// The scope's key (the `org_id` of its rows).
    pub fn org(&self) -> Id {
        self.org
    }

    async fn client(&self) -> StoreResult<Object> {
        self.pool.get().await.map_err(pool_err)
    }

    /// Begins a transaction: `awm.org` first, then the organisation lock of `mode`.
    async fn begin<'c>(&self, c: &'c mut Object, mode: Mode) -> StoreResult<Tx<'c>> {
        let b = c.build_transaction();
        let tx = match mode {
            Mode::Read => {
                b.isolation_level(IsolationLevel::RepeatableRead)
                    .read_only(true)
                    .start()
                    .await?
            }
            _ => {
                b.isolation_level(IsolationLevel::ReadCommitted)
                    .start()
                    .await?
            }
        };
        let tx = Tx { tx };
        tx.exec("SELECT set_config('awm.org', $1, true)", &[&self.key])
            .await?;
        match mode {
            Mode::Exclusive => {
                tx.exec(
                    "SELECT pg_advisory_xact_lock($1)",
                    &[&org_lock_key(self.org)],
                )
                .await?;
            }
            Mode::Shared => {
                tx.exec(
                    "SELECT pg_advisory_xact_lock_shared($1)",
                    &[&org_lock_key(self.org)],
                )
                .await?;
            }
            Mode::Read | Mode::Write => {}
        }
        Ok(tx)
    }

    async fn seed(&self) -> StoreResult<()> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let insert = "INSERT INTO meta (org_id, key, value) VALUES ($1, $2, $3) \
                      ON CONFLICT (org_id, key) DO NOTHING";
        tx.exec(
            insert,
            &[&self.key, &meta_keys::GENERATION, &Id::new_v4().to_string()],
        )
        .await?;
        tx.exec(insert, &[&self.key, &meta_keys::RESTORE_PENDING, &"0"])
            .await?;
        tx.commit().await
    }

    async fn delete_everything(&self) -> StoreResult<Vec<(&'static str, u64)>> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        tx.exec("SET CONSTRAINTS ALL DEFERRED", &[]).await?;
        let mut out = Vec::new();
        for table in ORG_TABLES {
            out.push((*table, tx.exec(&format!("DELETE FROM {table}"), &[]).await?));
        }
        tx.commit().await?;
        Ok(out)
    }

    /// A compare-and-set claim of the hourly run `name` at `at` (TM9 P2): true when no run of
    /// `name` was claimed less than `interval_s` seconds before or after `at` (or the claim is
    /// this run's, at the same `at`), and the claim is then `at`; false when another run holds
    /// the interval. Under the organisation lock, so two instances cannot both win one
    /// interval, also when their clocks differ by less than the interval.
    pub async fn claim(&self, name: &str, at: i64, interval_s: i64) -> StoreResult<bool> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let won = claim_tx(&tx, &self.key, name, at, interval_s).await?;
        tx.commit().await?;
        Ok(won)
    }
}

async fn claim_tx(
    tx: &Tx<'_>,
    key: &str,
    name: &str,
    at: i64,
    interval_s: i64,
) -> StoreResult<bool> {
    let prev: Option<i64> = match tx
        .opt("SELECT at FROM claim WHERE name = $1", &[&name])
        .await?
    {
        Some(r) => Some(col(&r, 0)?),
        None => None,
    };
    if let Some(prev) = prev {
        if prev == at {
            return Ok(true);
        }
        // Either direction: an instance whose clock is behind the winner's must not win the
        // same interval again (unlike `retention::due`, which treats a future `last` as due).
        if at.abs_diff(prev) < interval_s.unsigned_abs() {
            return Ok(false);
        }
    }
    tx.exec(
        "INSERT INTO claim (org_id, name, at) VALUES ($1, $2, $3) \
         ON CONFLICT (org_id, name) DO UPDATE SET at = excluded.at",
        &[&key, &name, &at],
    )
    .await?;
    Ok(true)
}

// ---------------------------------------------------------------------------------------------
// Column conversions (errors name the column, never its value)

fn bad(r: &Row, i: usize) -> StoreError {
    let name = r.columns().get(i).map_or("?", |c| c.name());
    StoreError::Backend(format!("column {name} holds an invalid value"))
}

fn col<'a, T: FromSql<'a>>(r: &'a Row, i: usize) -> StoreResult<T> {
    r.try_get(i).map_err(|_| bad(r, i))
}

fn id_at(r: &Row, i: usize) -> StoreResult<Id> {
    let s: String = col(r, i)?;
    Id::parse(&s).map_err(|_| bad(r, i))
}

fn opt_id_at(r: &Row, i: usize) -> StoreResult<Option<Id>> {
    match col::<Option<String>>(r, i)? {
        None => Ok(None),
        Some(s) => Id::parse(&s).map(Some).map_err(|_| bad(r, i)),
    }
}

fn key_at(r: &Row, i: usize) -> StoreResult<Key32> {
    let v: Vec<u8> = col(r, i)?;
    v.try_into().map(Key32).map_err(|_| bad(r, i))
}

fn opt_key_at(r: &Row, i: usize) -> StoreResult<Option<Key32>> {
    match col::<Option<Vec<u8>>>(r, i)? {
        None => Ok(None),
        Some(v) => v.try_into().map(|a| Some(Key32(a))).map_err(|_| bad(r, i)),
    }
}

fn handle_at(r: &Row, i: usize) -> StoreResult<Handle> {
    let s: String = col(r, i)?;
    Handle::parse(&s).map_err(|_| bad(r, i))
}

fn tag_at(r: &Row, i: usize) -> StoreResult<Tag> {
    let s: String = col(r, i)?;
    Tag::parse(&s).map_err(|_| bad(r, i))
}

fn role_of(s: &str) -> Option<Role> {
    match s {
        "member" => Some(Role::Member),
        "admin" => Some(Role::Admin),
        _ => None,
    }
}

fn role_at(r: &Row, i: usize) -> StoreResult<Role> {
    let s: String = col(r, i)?;
    role_of(&s).ok_or_else(|| bad(r, i))
}

fn opt_role_at(r: &Row, i: usize) -> StoreResult<Option<Role>> {
    match col::<Option<String>>(r, i)? {
        None => Ok(None),
        Some(s) => role_of(&s).map(Some).ok_or_else(|| bad(r, i)),
    }
}

fn kind_at(r: &Row, i: usize) -> StoreResult<InviteKind> {
    match col::<String>(r, i)?.as_str() {
        "member" => Ok(InviteKind::Member),
        "device" => Ok(InviteKind::Device),
        _ => Err(bad(r, i)),
    }
}

fn u32_at(r: &Row, i: usize) -> StoreResult<u32> {
    let v: i64 = col(r, i)?;
    u32::try_from(v).map_err(|_| bad(r, i))
}

fn u64_at(r: &Row, i: usize) -> StoreResult<u64> {
    let v: i64 = col(r, i)?;
    u64::try_from(v).map_err(|_| bad(r, i))
}

/// A 0/1 flag column.
fn flag_at(r: &Row, i: usize) -> StoreResult<bool> {
    Ok(col::<i64>(r, i)? == 1)
}

fn dump_value(r: &Row, i: usize) -> StoreResult<DumpValue> {
    let ty = r.columns().get(i).map(|c| c.type_().clone());
    Ok(match ty {
        Some(t) if t == Type::INT8 => {
            col::<Option<i64>>(r, i)?.map_or(DumpValue::Null, DumpValue::Int)
        }
        Some(t) if t == Type::TEXT => {
            col::<Option<String>>(r, i)?.map_or(DumpValue::Null, DumpValue::Text)
        }
        Some(t) if t == Type::BYTEA => {
            col::<Option<Vec<u8>>>(r, i)?.map_or(DumpValue::Null, DumpValue::Blob)
        }
        _ => return Err(bad(r, i)),
    })
}

/// A canonical value as a parameter of the column type `ty`.
#[cfg(feature = "sqlite")]
fn param_of(v: DumpValue, ty: &Type, what: &str) -> StoreResult<Box<dyn ToSql + Sync + Send>> {
    let unexpected = || {
        StoreError::Backend(format!(
            "canonical file: column {what} has an unexpected type"
        ))
    };
    Ok(match v {
        DumpValue::Null if *ty == Type::INT8 => Box::new(None::<i64>),
        DumpValue::Null if *ty == Type::TEXT => Box::new(None::<String>),
        DumpValue::Null if *ty == Type::BYTEA => Box::new(None::<Vec<u8>>),
        DumpValue::Int(i) if *ty == Type::INT8 => Box::new(i),
        DumpValue::Text(s) if *ty == Type::TEXT => Box::new(s),
        DumpValue::Blob(b) if *ty == Type::BYTEA => Box::new(b),
        _ => return Err(unexpected()),
    })
}

// ---------------------------------------------------------------------------------------------
// Statements shared by several operations

async fn meta_value(tx: &Tx<'_>, key: &str) -> StoreResult<Option<String>> {
    match tx
        .opt("SELECT value FROM meta WHERE key = $1", &[&key])
        .await?
    {
        Some(r) => Ok(Some(col(&r, 0)?)),
        None => Ok(None),
    }
}

async fn meta_put(tx: &Tx<'_>, org: &str, key: &str, value: &str) -> StoreResult<()> {
    tx.exec(
        "INSERT INTO meta (org_id, key, value) VALUES ($1, $2, $3) \
         ON CONFLICT (org_id, key) DO UPDATE SET value = excluded.value \
          WHERE meta.value <> excluded.value",
        &[&org, &key, &value],
    )
    .await?;
    Ok(())
}

async fn audit_tx(
    tx: &Tx<'_>,
    org: &str,
    at: i64,
    actor: Option<Id>,
    action: &str,
    target: Option<String>,
    detail: Option<String>,
) -> StoreResult<i64> {
    let r = tx
        .one(
            "INSERT INTO audit (org_id, idx, at, actor, action, target, detail) \
             VALUES ($1, (SELECT COALESCE(MAX(idx), -1) + 1 FROM audit), $2, $3, $4, $5, $6) \
             RETURNING idx",
            &[
                &org,
                &at,
                &actor.map(|a| a.to_string()),
                &action,
                &target,
                &detail,
            ],
        )
        .await?;
    col(&r, 0)
}

async fn load_org(tx: &Tx<'_>) -> StoreResult<Option<RawOrg>> {
    let Some(r) = tx
        .opt(
            "SELECT id, created_at, current_epoch, rotation_needed, retention_days, min_client, \
                    max_members, pending_retention_days, pending_retention_at \
               FROM org",
            &[],
        )
        .await?
    else {
        return Ok(None);
    };
    let min: String = col(&r, 5)?;
    let pending = match (col::<Option<i64>>(&r, 7)?, col::<Option<i64>>(&r, 8)?) {
        (Some(d), Some(at)) => Some((u32::try_from(d).map_err(|_| bad(&r, 7))?, at)),
        _ => None,
    };
    Ok(Some(RawOrg {
        id: id_at(&r, 0)?,
        created_at: col(&r, 1)?,
        current_epoch: u32_at(&r, 2)?,
        rotation_needed: flag_at(&r, 3)?,
        retention_days: u32_at(&r, 4)?,
        min_client: Version::parse(&min).map_err(|_| bad(&r, 5))?,
        max_members: u32_at(&r, 6)?,
        pending,
    }))
}

async fn require_org(tx: &Tx<'_>) -> StoreResult<RawOrg> {
    load_org(tx).await?.ok_or_else(|| broken("no organisation"))
}

async fn promote_retention(tx: &Tx<'_>, now: i64) -> StoreResult<()> {
    tx.exec(
        "UPDATE org SET retention_days = pending_retention_days, \
                        pending_retention_days = NULL, pending_retention_at = NULL \
          WHERE pending_retention_at IS NOT NULL AND pending_retention_at <= $1",
        &[&now],
    )
    .await?;
    Ok(())
}

async fn stream_head_tx(tx: &Tx<'_>, member: &str, device: &str, tag: &str) -> StoreResult<i64> {
    let r = tx
        .one(
            "SELECT COALESCE(MAX(idx), -1) FROM record \
              WHERE member_id = $1 AND device_id = $2 AND tag = $3",
            &[&member, &device, &tag],
        )
        .await?;
    col(&r, 0)
}

async fn deletion_heads_tx(tx: &Tx<'_>) -> StoreResult<DeletionHeads> {
    let r = tx
        .one("SELECT MIN(idx), MAX(idx) FROM deletion", &[])
        .await?;
    let (min, max): (Option<i64>, Option<i64>) = (col(&r, 0)?, col(&r, 1)?);
    let head = max.unwrap_or(-1);
    Ok(DeletionHeads {
        head,
        oldest: min.unwrap_or(head + 1),
    })
}

/// Appends `record_id` to the deletion stream at head + 1 (under the organisation lock).
async fn append_deletion(
    tx: &Tx<'_>,
    org: &str,
    record_id: &str,
    member: &str,
    at: i64,
) -> StoreResult<()> {
    tx.exec(
        "INSERT INTO deletion (org_id, idx, record_id, member_id, deleted_at) \
         VALUES ($1, (SELECT COALESCE(MAX(idx), -1) + 1 FROM deletion), $2, $3, $4)",
        &[&org, &record_id, &member, &hour(at)],
    )
    .await?;
    Ok(())
}

async fn in_deletions(tx: &Tx<'_>, record_id: &str) -> StoreResult<Option<String>> {
    match tx
        .opt(
            "SELECT member_id FROM deletion WHERE record_id = $1",
            &[&record_id],
        )
        .await?
    {
        Some(r) => Ok(Some(col(&r, 0)?)),
        None => Ok(None),
    }
}

/// Removes a held record's blob, keeps its marker, and appends its id to the deletion stream
/// unless it is there. Returns true when an entry was appended.
async fn delete_held(
    tx: &Tx<'_>,
    org: &str,
    record_id: &str,
    owner: &str,
    now: i64,
) -> StoreResult<bool> {
    tx.exec(
        "UPDATE record SET blob = NULL, deleted_at = $2 WHERE id = $1 AND blob IS NOT NULL",
        &[&record_id, &hour(now)],
    )
    .await?;
    if in_deletions(tx, record_id).await?.is_some() {
        return Ok(false);
    }
    append_deletion(tx, org, record_id, owner, now).await?;
    Ok(true)
}

/// Deletes every held record of `member` except `roster` records (TM9 F2); returns how many
/// entries were appended.
async fn delete_member_rows(tx: &Tx<'_>, org: &str, member: &str, now: i64) -> StoreResult<u64> {
    let rows = tx
        .rows(
            "SELECT id FROM record WHERE member_id = $1 AND blob IS NOT NULL \
                AND tag <> 'roster' \
              ORDER BY device_id, tag, idx",
            &[&member],
        )
        .await?;
    let mut n = 0;
    for r in &rows {
        let id: String = col(r, 0)?;
        if delete_held(tx, org, &id, member, now).await? {
            n += 1;
        }
    }
    Ok(n)
}

async fn active_admins(tx: &Tx<'_>) -> StoreResult<i64> {
    let r = tx
        .one(
            "SELECT COUNT(*) FROM member WHERE role = 'admin' AND revoked_at IS NULL",
            &[],
        )
        .await?;
    col(&r, 0)
}

async fn exists(tx: &Tx<'_>, sql: &str, p: Params<'_>) -> StoreResult<bool> {
    Ok(tx.opt(sql, p).await?.is_some())
}

fn member_row(r: &Row) -> StoreResult<MemberRow> {
    Ok(MemberRow {
        member_id: id_at(r, 0)?,
        handle: handle_at(r, 1)?,
        role: role_at(r, 2)?,
        created_at: col(r, 3)?,
        revoked_at: col(r, 4)?,
    })
}

fn pulled_item(r: &Row) -> StoreResult<PulledItem> {
    let idx = u64_at(r, 0)?;
    let id = id_at(r, 1)?;
    match col::<Option<Vec<u8>>>(r, 3)? {
        None => Ok(PulledItem::Deleted(PulledDeleted { idx, id })),
        Some(blob) => Ok(PulledItem::Record(PulledRecord {
            idx,
            id,
            epoch: match col::<Option<i64>>(r, 2)? {
                Some(e) => u32::try_from(e).map_err(|_| bad(r, 2))?,
                None => return Err(bad(r, 2)),
            },
            blob: B64(blob),
            received_at: col(r, 4)?,
        })),
    }
}

/// Reads a stream from `from` into `out`, at most `limit` items, while `budget` bytes last.
/// Returns true when the byte budget cut the read.
async fn read_stream(
    tx: &Tx<'_>,
    out: &mut StreamRecords,
    from: i64,
    limit: u32,
    budget: &mut usize,
) -> StoreResult<bool> {
    let rows = tx
        .rows(
            "SELECT idx, id, epoch, blob, received_at FROM record \
              WHERE member_id = $1 AND device_id = $2 AND tag = $3 AND idx >= $4 \
              ORDER BY idx LIMIT $5",
            &[
                &out.member.to_string(),
                &out.device.to_string(),
                &out.tag.as_str(),
                &from,
                &i64::from(limit),
            ],
        )
        .await?;
    for r in &rows {
        let item = pulled_item(r)?;
        let len = item_len(&item);
        if len > *budget {
            return Ok(true);
        }
        *budget -= len;
        out.records.push(item);
    }
    Ok(false)
}

#[cfg(feature = "sqlite")]
async fn store_holds_org(tx: &Tx<'_>) -> StoreResult<bool> {
    let r = tx.one(HOLDS_ORG_SQL, &[]).await?;
    Ok(col::<i64>(&r, 0)? > 0)
}

async fn restore_state_tx(tx: &Tx<'_>) -> StoreResult<RestoreState> {
    let generation = meta_value(tx, meta_keys::GENERATION)
        .await?
        .and_then(|g| Id::parse(&g).ok())
        .ok_or_else(|| broken("meta.generation missing or not a uuid (scope not created?)"))?;
    let pending = meta_value(tx, meta_keys::RESTORE_PENDING).await?.as_deref() == Some("1");
    let restored_at = meta_value(tx, meta_keys::RESTORED_AT)
        .await?
        .and_then(|v| v.parse().ok());
    Ok(RestoreState {
        generation,
        restore_pending: pending,
        restored_at,
    })
}

/// The ORDER BY of a canonical table in exports (deterministic; `record` in retention order).
#[cfg(feature = "sqlite")]
fn export_order(table: &str) -> &'static str {
    match table {
        "org" | "member" | "device" | "invite" => "id",
        "record" => "received_at, member_id, device_id, tag, idx",
        "deletion" | "audit" => "idx",
        "wrap" => "device_id, epoch",
        _ => "key",
    }
}

// ---------------------------------------------------------------------------------------------
// The operations

impl PgOrg {
    async fn restore_state_impl(&self) -> StoreResult<RestoreState> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let out = restore_state_tx(&tx).await?;
        tx.commit().await?;
        Ok(out)
    }

    async fn renew_generation_impl(&self, now: i64) -> StoreResult<Id> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let k = &self.key;
        let generation = Id::new_v4();
        meta_put(&tx, k, meta_keys::GENERATION, &generation.to_string()).await?;
        meta_put(&tx, k, meta_keys::RESTORE_PENDING, "1").await?;
        meta_put(&tx, k, meta_keys::RESTORED_AT, &now.to_string()).await?;
        audit_tx(
            &tx,
            k,
            now,
            None,
            "restore",
            None,
            Some(format!("generation={generation}")),
        )
        .await?;
        tx.commit().await?;
        Ok(generation)
    }

    async fn complete_restore_impl(&self, generation: Id, by: Actor, now: i64) -> StoreResult<()> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let state = restore_state_tx(&tx).await?;
        if state.generation != generation {
            return Err(StoreError::InvalidValue {
                field: "/generation".into(),
            });
        }
        if state.restore_pending {
            meta_put(&tx, &self.key, meta_keys::RESTORE_PENDING, "0").await?;
            audit_tx(
                &tx,
                &self.key,
                now,
                Some(by.member_id),
                "restore.complete",
                None,
                Some(format!("generation={generation}")),
            )
            .await?;
        }
        tx.commit().await
    }

    async fn meta_get_impl(&self, key: String) -> StoreResult<Option<String>> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let out = meta_value(&tx, &key).await?;
        tx.commit().await?;
        Ok(out)
    }

    async fn meta_set_impl(&self, key: String, value: String) -> StoreResult<()> {
        if meta_keys::reserved(&key) {
            return Err(StoreError::InvalidValue {
                field: "key".into(),
            });
        }
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        meta_put(&tx, &self.key, &key, &value).await?;
        tx.commit().await
    }

    async fn org_impl(&self, now: i64) -> StoreResult<Option<OrgRow>> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let out = load_org(&tx).await?.map(|o| OrgRow {
            org_id: o.id,
            created_at: o.created_at,
            current_epoch: o.current_epoch,
            rotation_needed: o.rotation_needed,
            settings: o.effective(now),
        });
        tx.commit().await?;
        Ok(out)
    }

    async fn set_bootstrap_impl(&self, token_hash: String, expires_at: i64) -> StoreResult<()> {
        check_hash(&token_hash, "token_hash")?;
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        if load_org(&tx).await?.is_some() {
            return Err(StoreError::NotEmpty);
        }
        meta_put(&tx, &self.key, meta_keys::BOOTSTRAP_HASH, &token_hash).await?;
        meta_put(
            &tx,
            &self.key,
            meta_keys::BOOTSTRAP_EXPIRES,
            &expires_at.to_string(),
        )
        .await?;
        tx.commit().await
    }

    async fn bootstrap_impl(&self, req: NewBootstrap) -> StoreResult<Id> {
        check_hash(&req.bootstrap_token_hash, "bootstrap_token")?;
        check_hash(&req.device_token_hash, "device_token")?;
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let k = &self.key;
        if load_org(&tx).await?.is_some() {
            return Err(StoreError::Gone);
        }
        let stored = meta_value(&tx, meta_keys::BOOTSTRAP_HASH).await?;
        let expires: Option<i64> = meta_value(&tx, meta_keys::BOOTSTRAP_EXPIRES)
            .await?
            .and_then(|v| v.parse().ok());
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
        if exists(&tx, "SELECT 1 FROM device WHERE id = $1", &[&device]).await? {
            return Err(StoreError::DeviceConflict);
        }
        tx.exec(
            "INSERT INTO org (org_id, id, created_at, current_epoch, rotation_needed, \
                              retention_days, min_client, max_members) \
             VALUES ($1, $2, $3, 0, 0, $4, $5, $6)",
            &[
                k,
                &req.org_id.to_string(),
                &req.now,
                &i64::from(d.retention_days),
                &d.min_client.to_string(),
                &i64::from(d.max_members),
            ],
        )
        .await?;
        let member = Id::new_v4();
        tx.exec(
            "INSERT INTO member (org_id, id, handle, role, created_at) \
             VALUES ($1, $2, $3, 'admin', $4)",
            &[k, &member.to_string(), &req.handle.as_str(), &req.now],
        )
        .await?;
        tx.exec(
            "INSERT INTO device (org_id, id, member_id, token_hash, pubkey, approved, created_at) \
             VALUES ($1, $2, $3, $4, $5, 1, $6)",
            &[
                k,
                &device,
                &member.to_string(),
                &req.device_token_hash,
                &req.device_pubkey.0.as_slice(),
                &req.now,
            ],
        )
        .await?;
        tx.exec(
            "DELETE FROM meta WHERE key IN ($1, $2)",
            &[&meta_keys::BOOTSTRAP_HASH, &meta_keys::BOOTSTRAP_EXPIRES],
        )
        .await?;
        audit_tx(
            &tx,
            k,
            req.now,
            Some(member),
            "bootstrap",
            Some(device),
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(member)
    }

    async fn auth_device_impl(&self, token_hash: String) -> StoreResult<Option<AuthDevice>> {
        if !valid_token_hash(&token_hash) {
            return Ok(None);
        }
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let row = tx
            .opt(
                "SELECT o.id, d.member_id, d.id, m.handle, m.role, d.approved, \
                        d.revoked_at IS NOT NULL, m.revoked_at IS NOT NULL \
                   FROM device d JOIN member m ON m.id = d.member_id CROSS JOIN org o \
                  WHERE d.token_hash = $1",
                &[&token_hash],
            )
            .await?;
        let out = match row {
            None => None,
            Some(r) => Some(AuthDevice {
                org_id: id_at(&r, 0)?,
                member_id: id_at(&r, 1)?,
                device_id: id_at(&r, 2)?,
                handle: handle_at(&r, 3)?,
                role: role_at(&r, 4)?,
                approved: flag_at(&r, 5)?,
                device_revoked: col(&r, 6)?,
                member_revoked: col(&r, 7)?,
            }),
        };
        tx.commit().await?;
        Ok(out)
    }

    async fn touch_device_impl(&self, device_id: Id, day: i64) -> StoreResult<()> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Write).await?;
        // Writes only when the day changed; an unknown device matches no row.
        tx.exec(
            "UPDATE device SET last_seen_day = $2 \
              WHERE id = $1 AND last_seen_day IS DISTINCT FROM $2",
            &[&device_id.to_string(), &day],
        )
        .await?;
        tx.commit().await
    }

    async fn rotate_token_impl(
        &self,
        device_id: Id,
        token_hash: String,
        now: i64,
    ) -> StoreResult<()> {
        check_hash(&token_hash, "token_hash")?;
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let id = device_id.to_string();
        let member = match tx
            .opt(
                "SELECT d.member_id FROM device d JOIN member m ON m.id = d.member_id \
                  WHERE d.id = $1 AND d.revoked_at IS NULL AND m.revoked_at IS NULL",
                &[&id],
            )
            .await?
        {
            Some(r) => id_at(&r, 0)?,
            None => return Err(StoreError::NotFound),
        };
        tx.exec(
            "UPDATE device SET token_hash = $2 WHERE id = $1",
            &[&id, &token_hash],
        )
        .await?;
        audit_tx(
            &tx,
            &self.key,
            now,
            Some(member),
            "token.rotate",
            Some(id),
            None,
        )
        .await?;
        tx.commit().await
    }

    async fn device_impl(&self, device_id: Id) -> StoreResult<Option<DeviceRow>> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let out = match tx
            .opt(
                "SELECT id, member_id, pubkey, join_mac, invite_id, approved, created_at, \
                        revoked_at, last_seen_day FROM device WHERE id = $1",
                &[&device_id.to_string()],
            )
            .await?
        {
            None => None,
            Some(r) => Some(DeviceRow {
                device_id: id_at(&r, 0)?,
                member_id: id_at(&r, 1)?,
                pubkey: key_at(&r, 2)?,
                join_mac: opt_key_at(&r, 3)?,
                invite_id: opt_id_at(&r, 4)?,
                approved: flag_at(&r, 5)?,
                created_at: col(&r, 6)?,
                revoked_at: col(&r, 7)?,
                last_seen_day: col(&r, 8)?,
            }),
        };
        tx.commit().await?;
        Ok(out)
    }

    async fn member_impl(&self, member_id: Id) -> StoreResult<Option<MemberRow>> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let out = match tx
            .opt(
                "SELECT id, handle, role, created_at, revoked_at FROM member WHERE id = $1",
                &[&member_id.to_string()],
            )
            .await?
        {
            None => None,
            Some(r) => Some(member_row(&r)?),
        };
        tx.commit().await?;
        Ok(out)
    }

    async fn member_by_handle_impl(&self, handle: Handle) -> StoreResult<Option<MemberRow>> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let out = match tx
            .opt(
                "SELECT id, handle, role, created_at, revoked_at FROM member \
                  WHERE handle = $1 AND revoked_at IS NULL",
                &[&handle.as_str()],
            )
            .await?
        {
            None => None,
            Some(r) => Some(member_row(&r)?),
        };
        tx.commit().await?;
        Ok(out)
    }

    async fn create_invite_impl(&self, inv: NewInvite) -> StoreResult<()> {
        check_hash(&inv.token_hash, "token_hash")?;
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let org = require_org(&tx).await?;
        let active: Option<String> = match tx
            .opt(
                "SELECT id FROM member WHERE handle = $1 AND revoked_at IS NULL",
                &[&inv.handle.as_str()],
            )
            .await?
        {
            Some(r) => Some(col(&r, 0)?),
            None => None,
        };
        let invalid = |f: &str| StoreError::InvalidValue {
            field: f.to_string(),
        };
        let (kind, role, member) = match inv.kind {
            InviteKind::Member => {
                let role = role_str(inv.role.unwrap_or(Role::Member), "/role")?;
                if active.is_some() {
                    return Err(invalid("/handle"));
                }
                let r = tx
                    .one(
                        "SELECT (SELECT COUNT(*) FROM member WHERE revoked_at IS NULL) \
                              + (SELECT COUNT(*) FROM invite WHERE kind = 'member' \
                                    AND used_at IS NULL AND revoked_at IS NULL \
                                    AND expires_at > $1)",
                        &[&inv.now],
                    )
                    .await?;
                let taken: i64 = col(&r, 0)?;
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
        tx.exec(
            "INSERT INTO invite (org_id, id, token_hash, handle, role, kind, member_id, \
                                 created_by, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            &[
                &self.key,
                &id,
                &inv.token_hash,
                &inv.handle.as_str(),
                &role,
                &kind,
                &member,
                &inv.by.device_id.to_string(),
                &inv.now,
                &inv.expires_at,
            ],
        )
        .await?;
        audit_tx(
            &tx,
            &self.key,
            inv.now,
            Some(inv.by.member_id),
            "invite.create",
            Some(id),
            Some(format!("kind={kind}")),
        )
        .await?;
        tx.commit().await
    }

    async fn invite_impl(&self, invite_id: Id) -> StoreResult<Option<InviteRow>> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let out = match tx
            .opt(
                "SELECT i.id, i.kind, i.handle, i.role, i.member_id, i.created_by, \
                        d.member_id, i.created_at, i.expires_at, i.used_at, i.revoked_at \
                   FROM invite i JOIN device d ON d.id = i.created_by WHERE i.id = $1",
                &[&invite_id.to_string()],
            )
            .await?
        {
            None => None,
            Some(r) => Some(InviteRow {
                invite_id: id_at(&r, 0)?,
                kind: kind_at(&r, 1)?,
                handle: handle_at(&r, 2)?,
                role: opt_role_at(&r, 3)?,
                member_id: opt_id_at(&r, 4)?,
                created_by: id_at(&r, 5)?,
                created_by_member: id_at(&r, 6)?,
                created_at: col(&r, 7)?,
                expires_at: col(&r, 8)?,
                used_at: col(&r, 9)?,
                revoked_at: col(&r, 10)?,
            }),
        };
        tx.commit().await?;
        Ok(out)
    }

    async fn revoke_invite_impl(&self, invite_id: Id, by: Actor, now: i64) -> StoreResult<()> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let id = invite_id.to_string();
        let open: Option<bool> = match tx
            .opt(
                "SELECT used_at IS NULL AND revoked_at IS NULL FROM invite WHERE id = $1",
                &[&id],
            )
            .await?
        {
            Some(r) => Some(col(&r, 0)?),
            None => None,
        };
        match open {
            None => Err(StoreError::NotFound),
            Some(false) => Ok(()),
            Some(true) => {
                tx.exec(
                    "UPDATE invite SET revoked_at = $2 WHERE id = $1",
                    &[&id, &now],
                )
                .await?;
                audit_tx(
                    &tx,
                    &self.key,
                    now,
                    Some(by.member_id),
                    "invite.revoke",
                    Some(id),
                    None,
                )
                .await?;
                tx.commit().await
            }
        }
    }

    async fn join_impl(&self, req: NewJoin) -> StoreResult<Joined> {
        check_hash(&req.invite_token_hash, "invite_token")?;
        check_hash(&req.device_token_hash, "device_token")?;
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let k = &self.key;
        let org = load_org(&tx).await?.ok_or(StoreError::Gone)?;
        let invite_id = req.invite_id.to_string();
        let Some(r) = tx
            .opt(
                "SELECT kind, handle, role, member_id, expires_at, \
                        used_at IS NULL AND revoked_at IS NULL \
                   FROM invite WHERE id = $1 AND token_hash = $2",
                &[&invite_id, &req.invite_token_hash],
            )
            .await?
        else {
            return Err(StoreError::Gone);
        };
        let (kind, handle, role, member_for_device, expires_at, open) = (
            kind_at(&r, 0)?,
            handle_at(&r, 1)?,
            opt_role_at(&r, 2)?,
            opt_id_at(&r, 3)?,
            col::<i64>(&r, 4)?,
            col::<bool>(&r, 5)?,
        );
        if !open || req.now >= expires_at {
            return Err(StoreError::Gone);
        }
        if handle != req.handle {
            return Err(StoreError::InvalidValue {
                field: "/handle".into(),
            });
        }
        let device = req.device_id.to_string();
        if exists(&tx, "SELECT 1 FROM device WHERE id = $1", &[&device]).await? {
            return Err(StoreError::DeviceConflict);
        }
        let member = match kind {
            InviteKind::Member => {
                if exists(
                    &tx,
                    "SELECT 1 FROM member WHERE handle = $1 AND revoked_at IS NULL",
                    &[&handle.as_str()],
                )
                .await?
                {
                    return Err(StoreError::InvalidValue {
                        field: "/handle".into(),
                    });
                }
                let member = Id::new_v4();
                let role = role_str(role.unwrap_or(Role::Member), "/role")?;
                tx.exec(
                    "INSERT INTO member (org_id, id, handle, role, created_at) \
                     VALUES ($1, $2, $3, $4, $5)",
                    &[k, &member.to_string(), &handle.as_str(), &role, &req.now],
                )
                .await?;
                member
            }
            InviteKind::Device | InviteKind::Unknown => {
                let member = member_for_device.ok_or_else(|| broken("device invite"))?;
                if !exists(
                    &tx,
                    "SELECT 1 FROM member WHERE id = $1 AND revoked_at IS NULL",
                    &[&member.to_string()],
                )
                .await?
                {
                    return Err(StoreError::Gone);
                }
                member
            }
        };
        tx.exec(
            "INSERT INTO device (org_id, id, member_id, token_hash, pubkey, join_mac, invite_id, \
                                 approved, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8)",
            &[
                k,
                &device,
                &member.to_string(),
                &req.device_token_hash,
                &req.device_pubkey.0.as_slice(),
                &req.join_mac.0.as_slice(),
                &invite_id,
                &req.now,
            ],
        )
        .await?;
        tx.exec(
            "UPDATE invite SET used_at = $2 WHERE id = $1",
            &[&invite_id, &req.now],
        )
        .await?;
        let kind_text = if kind == InviteKind::Member {
            "member"
        } else {
            "device"
        };
        audit_tx(
            &tx,
            k,
            req.now,
            Some(member),
            "join",
            Some(device),
            Some(format!("kind={kind_text} invite={invite_id}")),
        )
        .await?;
        tx.commit().await?;
        Ok(Joined {
            org_id: org.id,
            member_id: member,
            kind,
        })
    }

    async fn approve_device_impl(
        &self,
        device_id: Id,
        wraps: Vec<EpochWrap>,
        by: Actor,
        now: i64,
    ) -> StoreResult<()> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let id = device_id.to_string();
        let Some(r) = tx
            .opt(
                "SELECT approved = 1, revoked_at IS NOT NULL FROM device WHERE id = $1",
                &[&id],
            )
            .await?
        else {
            return Err(StoreError::NotFound);
        };
        let (approved, revoked): (bool, bool) = (col(&r, 0)?, col(&r, 1)?);
        if revoked {
            return Err(StoreError::Forbidden);
        }
        let current = require_org(&tx).await?.current_epoch;
        let mut inserted = 0u64;
        for (i, w) in wraps.iter().enumerate() {
            if w.epoch > current {
                return Err(StoreError::InvalidValue {
                    field: format!("/wraps/{i}/epoch"),
                });
            }
            inserted += tx
                .exec(
                    "INSERT INTO wrap (org_id, device_id, epoch, wrap, auth, created_by) \
                     VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT (org_id, device_id, epoch) DO NOTHING",
                    &[
                        &self.key,
                        &id,
                        &i64::from(w.epoch),
                        &w.wrap.0,
                        &w.auth.0.as_slice(),
                        &by.device_id.to_string(),
                    ],
                )
                .await?;
        }
        let r = tx
            .one(
                "SELECT COUNT(*) FROM wrap WHERE device_id = $1 AND epoch <= $2",
                &[&id, &i64::from(current)],
            )
            .await?;
        if col::<i64>(&r, 0)? != i64::from(current) + 1 {
            return Err(StoreError::InvalidValue {
                field: "/wraps".into(),
            });
        }
        if !approved {
            tx.exec("UPDATE device SET approved = 1 WHERE id = $1", &[&id])
                .await?;
        }
        if !approved || inserted > 0 {
            audit_tx(
                &tx,
                &self.key,
                now,
                Some(by.member_id),
                "approve",
                Some(id),
                Some(format!("wraps={inserted}")),
            )
            .await?;
        }
        tx.commit().await
    }

    async fn revoke_device_impl(&self, device_id: Id, by: Actor, now: i64) -> StoreResult<()> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let id = device_id.to_string();
        let revoked: Option<bool> = match tx
            .opt(
                "SELECT revoked_at IS NOT NULL FROM device WHERE id = $1",
                &[&id],
            )
            .await?
        {
            Some(r) => Some(col(&r, 0)?),
            None => None,
        };
        match revoked {
            None => Err(StoreError::NotFound),
            Some(true) => Ok(()),
            Some(false) => {
                tx.exec(
                    "UPDATE device SET revoked_at = $2 WHERE id = $1",
                    &[&id, &now],
                )
                .await?;
                tx.exec(
                    "UPDATE org SET rotation_needed = 1 WHERE rotation_needed = 0",
                    &[],
                )
                .await?;
                audit_tx(
                    &tx,
                    &self.key,
                    now,
                    Some(by.member_id),
                    "device.revoke",
                    Some(id),
                    None,
                )
                .await?;
                tx.commit().await
            }
        }
    }

    async fn remove_member_impl(
        &self,
        member_id: Id,
        delete_records: bool,
        by: Actor,
        now: i64,
    ) -> StoreResult<u64> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let id = member_id.to_string();
        let Some(r) = tx
            .opt(
                "SELECT role, revoked_at IS NULL FROM member WHERE id = $1",
                &[&id],
            )
            .await?
        else {
            return Err(StoreError::NotFound);
        };
        let (role, active): (Role, bool) = (role_at(&r, 0)?, col(&r, 1)?);
        if active && role == Role::Admin && active_admins(&tx).await? <= 1 {
            return Err(StoreError::LastAdmin);
        }
        if active {
            tx.exec(
                "UPDATE member SET revoked_at = $2 WHERE id = $1",
                &[&id, &now],
            )
            .await?;
            tx.exec(
                "UPDATE invite SET revoked_at = $2 \
                  WHERE used_at IS NULL AND revoked_at IS NULL \
                    AND (member_id = $1 OR created_by IN \
                         (SELECT id FROM device WHERE member_id = $1))",
                &[&id, &now],
            )
            .await?;
            tx.exec(
                "UPDATE device SET revoked_at = $2 WHERE member_id = $1 AND revoked_at IS NULL",
                &[&id, &now],
            )
            .await?;
            // RVT2 m2, as `SqliteStore::remove_member`.
            tx.exec(
                "UPDATE member SET revoked_at = $2 \
                  WHERE revoked_at IS NULL AND id IN \
                        (SELECT d.member_id FROM device d JOIN invite i ON i.id = d.invite_id \
                          WHERE i.kind = 'member' AND d.approved = 0 \
                            AND i.created_by IN (SELECT id FROM device WHERE member_id = $1)) \
                    AND NOT EXISTS (SELECT 1 FROM device x \
                                     WHERE x.member_id = member.id AND x.approved = 1)",
                &[&id, &now],
            )
            .await?;
            tx.exec(
                "UPDATE device SET revoked_at = $2 \
                  WHERE approved = 0 AND revoked_at IS NULL AND invite_id IN \
                        (SELECT id FROM invite WHERE created_by IN \
                                (SELECT id FROM device WHERE member_id = $1))",
                &[&id, &now],
            )
            .await?;
            tx.exec(
                "UPDATE org SET rotation_needed = 1 WHERE rotation_needed = 0",
                &[],
            )
            .await?;
        }
        let deleted = if delete_records {
            delete_member_rows(&tx, &self.key, &id, now).await?
        } else {
            0
        };
        if active || deleted > 0 {
            audit_tx(
                &tx,
                &self.key,
                now,
                Some(by.member_id),
                "member.remove",
                Some(id),
                Some(format!("delete_records={delete_records} deleted={deleted}")),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(deleted)
    }

    async fn set_role_impl(
        &self,
        member_id: Id,
        role: Role,
        by: Option<Actor>,
        now: i64,
    ) -> StoreResult<()> {
        let new = role_str(role, "/role")?;
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let id = member_id.to_string();
        let current = match tx
            .opt(
                "SELECT role FROM member WHERE id = $1 AND revoked_at IS NULL",
                &[&id],
            )
            .await?
        {
            Some(r) => role_at(&r, 0)?,
            None => return Err(StoreError::NotFound),
        };
        if current == role {
            return Ok(());
        }
        if current == Role::Admin && active_admins(&tx).await? <= 1 {
            return Err(StoreError::LastAdmin);
        }
        tx.exec("UPDATE member SET role = $2 WHERE id = $1", &[&id, &new])
            .await?;
        audit_tx(
            &tx,
            &self.key,
            now,
            by.map(|a| a.member_id),
            "member.role",
            Some(id),
            Some(format!("role={new}")),
        )
        .await?;
        tx.commit().await
    }

    async fn members_impl(&self) -> StoreResult<Vec<MemberInfo>> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let mut devices: BTreeMap<String, Vec<DeviceInfo>> = BTreeMap::new();
        for r in &tx
            .rows(
                "SELECT member_id, id, pubkey, approved, revoked_at IS NOT NULL FROM device \
                  ORDER BY created_at, id",
                &[],
            )
            .await?
        {
            devices.entry(col(r, 0)?).or_default().push(DeviceInfo {
                device_id: id_at(r, 1)?,
                device_pubkey: key_at(r, 2)?,
                approved: flag_at(r, 3)?,
                revoked: col(r, 4)?,
            });
        }
        let mut out = Vec::new();
        for r in &tx
            .rows(
                "SELECT id, handle, role, created_at, revoked_at FROM member \
                  ORDER BY created_at, id",
                &[],
            )
            .await?
        {
            let m = member_row(r)?;
            out.push(MemberInfo {
                devices: devices.remove(&m.member_id.to_string()).unwrap_or_default(),
                member_id: m.member_id,
                handle: m.handle,
                role: m.role,
                active: m.revoked_at.is_none(),
            });
        }
        tx.commit().await?;
        Ok(out)
    }

    async fn keys_impl(&self, device_id: Id) -> StoreResult<KeysResponse> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let id = device_id.to_string();
        if !exists(&tx, "SELECT 1 FROM device WHERE id = $1", &[&id]).await? {
            return Err(StoreError::NotFound);
        }
        let org = require_org(&tx).await?;
        let mut wraps = Vec::new();
        for r in &tx
            .rows(
                "SELECT epoch, wrap, auth, created_by FROM wrap WHERE device_id = $1 \
                  ORDER BY epoch",
                &[&id],
            )
            .await?
        {
            wraps.push(StoredWrap {
                epoch: u32_at(r, 0)?,
                wrap: B64(col(r, 1)?),
                auth: key_at(r, 2)?,
                created_by: id_at(r, 3)?,
            });
        }
        tx.commit().await?;
        Ok(KeysResponse {
            current_epoch: org.current_epoch,
            rotation_needed: org.rotation_needed,
            wraps,
        })
    }

    async fn rotate_keys_impl(
        &self,
        epoch: u32,
        wraps: Vec<DeviceWrap>,
        by: Actor,
        now: i64,
    ) -> StoreResult<()> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let current = require_org(&tx).await?.current_epoch;
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
            let listed = exists(
                &tx,
                "SELECT 1 FROM device d JOIN member m ON m.id = d.member_id \
                  WHERE d.id = $1 AND d.revoked_at IS NULL AND m.revoked_at IS NULL",
                &[&id],
            )
            .await?;
            if !listed || !seen.insert(w.device_id) {
                return Err(StoreError::InvalidValue {
                    field: format!("/wraps/{i}/device_id"),
                });
            }
            tx.exec(
                "INSERT INTO wrap (org_id, device_id, epoch, wrap, auth, created_by) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &self.key,
                    &id,
                    &i64::from(epoch),
                    &w.wrap.0,
                    &w.auth.0.as_slice(),
                    &by.device_id.to_string(),
                ],
            )
            .await?;
        }
        tx.exec(
            "UPDATE org SET current_epoch = $1, rotation_needed = 0",
            &[&i64::from(epoch)],
        )
        .await?;
        audit_tx(
            &tx,
            &self.key,
            now,
            Some(by.member_id),
            "keys.rotate",
            None,
            Some(format!("epoch={epoch} devices={}", wraps.len())),
        )
        .await?;
        tx.commit().await
    }

    async fn status_impl(&self, device_id: Id, now: i64) -> StoreResult<StatusResponse> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let Some(r) = tx
            .opt(
                "SELECT member_id, approved FROM device WHERE id = $1",
                &[&device_id.to_string()],
            )
            .await?
        else {
            return Err(StoreError::NotFound);
        };
        let (member_id, approved) = (id_at(&r, 0)?, flag_at(&r, 1)?);
        let r = tx
            .one(
                "SELECT role FROM member WHERE id = $1",
                &[&member_id.to_string()],
            )
            .await?;
        let role = role_at(&r, 0)?;
        let org = require_org(&tx).await?;
        let restore = restore_state_tx(&tx).await?;
        let mut streams = Vec::new();
        for r in &tx
            .rows(
                "SELECT member_id, device_id, tag, MAX(idx) FROM record \
                  GROUP BY member_id, device_id, tag ORDER BY member_id, device_id, tag",
                &[],
            )
            .await?
        {
            streams.push(StreamHead {
                member: id_at(r, 0)?,
                device: id_at(r, 1)?,
                tag: tag_at(r, 2)?,
                head: col(r, 3)?,
            });
        }
        let mut pending = Vec::new();
        for r in &tx
            .rows(
                "SELECT d.id, d.member_id, m.handle, i.kind, d.invite_id, d.pubkey, d.join_mac, \
                        d.created_at \
                   FROM device d JOIN member m ON m.id = d.member_id \
                   JOIN invite i ON i.id = d.invite_id \
                  WHERE d.approved = 0 AND d.revoked_at IS NULL AND m.revoked_at IS NULL \
                    AND ($1 OR d.member_id = $2) \
                  ORDER BY d.created_at, d.id",
                &[&(role == Role::Admin), &member_id.to_string()],
            )
            .await?
        {
            pending.push(PendingDevice {
                device_id: id_at(r, 0)?,
                member_id: id_at(r, 1)?,
                handle: handle_at(r, 2)?,
                kind: kind_at(r, 3)?,
                invite_id: id_at(r, 4)?,
                device_pubkey: key_at(r, 5)?,
                join_mac: key_at(r, 6)?,
                joined_at: hour(col(r, 7)?),
            });
        }
        let deletions = deletion_heads_tx(&tx).await?;
        tx.commit().await?;
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
            deletions,
            pending,
        })
    }

    async fn update_settings_impl(
        &self,
        u: SettingsUpdate,
        floor: Version,
        by: Option<Actor>,
        now: i64,
    ) -> StoreResult<OrgSettings> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        promote_retention(&tx, now).await?;
        let org = require_org(&tx).await?;
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
            if *v < org.min_client || *v < floor {
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
            tx.exec(
                "UPDATE org SET retention_days = $1, min_client = $2, max_members = $3, \
                                pending_retention_days = $4, pending_retention_at = $5",
                &[
                    &i64::from(retention),
                    &min_client.to_string(),
                    &i64::from(max_members),
                    &pending.map(|p| i64::from(p.0)),
                    &pending.map(|p| p.1),
                ],
            )
            .await?;
            let pending_text =
                pending.map_or_else(|| "none".to_string(), |(d, at)| format!("{d}@{at}"));
            audit_tx(
                &tx,
                &self.key,
                now,
                by.map(|a| a.member_id),
                "settings",
                None,
                Some(format!(
                    "retention_days={retention} pending_retention={pending_text} \
                     min_client={min_client} max_members={max_members}"
                )),
            )
            .await?;
        }
        let out = require_org(&tx).await?.effective(now);
        tx.commit().await?;
        Ok(out)
    }

    async fn push_impl(&self, b: PushBatch) -> StoreResult<PushResponse> {
        // A marker may append to the deletion stream: the organisation lock, exclusively.
        let mode = if b.items.iter().any(|i| matches!(i, PushItem::Deleted(_))) {
            Mode::Exclusive
        } else {
            Mode::Shared
        };
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, mode).await?;
        let mut keys: Vec<i64> = b
            .items
            .iter()
            .map(|i| stream_lock_key(self.org, b.member_id, b.device_id, i.tag().as_str()))
            .collect();
        keys.sort_unstable();
        keys.dedup();
        for key in &keys {
            tx.exec("SELECT pg_advisory_xact_lock($1)", &[key]).await?;
        }
        let current_epoch = require_org(&tx).await?.current_epoch;
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
            let stored: Option<String> = match tx
                .opt(
                    "SELECT id FROM record \
                      WHERE member_id = $1 AND device_id = $2 AND tag = $3 AND idx = $4",
                    &[&member, &device, &tag, &idx],
                )
                .await?
            {
                Some(r) => Some(col(&r, 0)?),
                None => None,
            };
            match stored {
                Some(s) if s == id => {
                    replayed += 1;
                    continue;
                }
                Some(_) => {
                    return Err(StoreError::StreamConflict {
                        item: n,
                        head: stream_head_tx(&tx, &member, &device, tag).await?,
                    })
                }
                None => {}
            }
            // 4.3 deleted: a record item whose id this member deleted.
            let deleted_by = in_deletions(&tx, &id).await?;
            if matches!(item, PushItem::Record(_)) && deleted_by.as_deref() == Some(member.as_str())
            {
                let mut ids = Vec::new();
                for other in &b.items {
                    if let PushItem::Record(r) = other {
                        let rid = r.id.to_string();
                        if in_deletions(&tx, &rid).await?.as_deref() == Some(member.as_str())
                            && !ids.contains(&r.id)
                        {
                            ids.push(r.id);
                        }
                    }
                }
                return Err(StoreError::Deleted { item: n, ids });
            }
            // 4.4 id taken: stored at another position, or pre-deleted by another member.
            let elsewhere = exists(&tx, "SELECT 1 FROM record WHERE id = $1", &[&id]).await?;
            if elsewhere || deleted_by.as_deref().is_some_and(|m| m != member) {
                return Err(StoreError::IdConflict { item: n });
            }
            // 4.5 contiguity.
            let head = stream_head_tx(&tx, &member, &device, tag).await?;
            if idx != head + 1 {
                return Err(StoreError::StreamConflict { item: n, head });
            }
            let received = hour(b.now);
            let inserted = match item {
                PushItem::Record(r) => {
                    // 4.6 epoch.
                    if r.epoch != current_epoch {
                        return Err(StoreError::StaleEpoch {
                            item: n,
                            current_epoch,
                        });
                    }
                    let st = tx
                        .tx
                        .prepare_cached(
                            "INSERT INTO record (org_id, member_id, device_id, tag, idx, id, \
                                                 epoch, size, received_at, blob, deleted_at) \
                             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL)",
                        )
                        .await?;
                    tx.tx
                        .execute(
                            &st,
                            &[
                                &self.key,
                                &member,
                                &device,
                                &tag,
                                &idx,
                                &id,
                                &i64::from(r.epoch),
                                &(r.blob.0.len() as i64),
                                &received,
                                &r.blob.0,
                            ],
                        )
                        .await
                }
                PushItem::Deleted(_) => {
                    let st = tx
                        .tx
                        .prepare_cached(
                            "INSERT INTO record (org_id, member_id, device_id, tag, idx, id, \
                                                 epoch, size, received_at, blob, deleted_at) \
                             VALUES ($1, $2, $3, $4, $5, $6, NULL, 0, $7, NULL, $7)",
                        )
                        .await?;
                    tx.tx
                        .execute(
                            &st,
                            &[&self.key, &member, &device, &tag, &idx, &id, &received],
                        )
                        .await
                }
            };
            match inserted {
                Ok(_) => {}
                // The same new id pushed into another stream by a concurrent transaction.
                Err(e) if is_unique_violation(&e, "record_id_unique") => {
                    return Err(StoreError::IdConflict { item: n })
                }
                Err(e) => return Err(e.into()),
            }
            if matches!(item, PushItem::Deleted(_)) && deleted_by.is_none() {
                append_deletion(&tx, &self.key, &id, &member, b.now).await?;
            }
            accepted += 1;
        }
        let mut heads = Vec::new();
        for tag in tags {
            let head = stream_head_tx(&tx, &member, &device, tag.as_str()).await?;
            heads.push(OwnHead { tag, head });
        }
        tx.commit().await?;
        Ok(PushResponse {
            heads,
            accepted,
            replayed,
        })
    }

    async fn stream_head_impl(&self, member_id: Id, device_id: Id, tag: Tag) -> StoreResult<i64> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let out = stream_head_tx(
            &tx,
            &member_id.to_string(),
            &device_id.to_string(),
            tag.as_str(),
        )
        .await?;
        tx.commit().await?;
        Ok(out)
    }

    async fn records_impl(
        &self,
        member_id: Id,
        device_id: Id,
        tag: Tag,
        from: u64,
        limit: u32,
        max_bytes: usize,
    ) -> StoreResult<StreamRecords> {
        let from = i64_of(from, || "from".to_string())?;
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let head = stream_head_tx(
            &tx,
            &member_id.to_string(),
            &device_id.to_string(),
            tag.as_str(),
        )
        .await?;
        let mut out = StreamRecords {
            member: member_id,
            device: device_id,
            tag,
            head,
            records: Vec::new(),
        };
        let mut budget = max_bytes.saturating_sub(json_len(&out));
        read_stream(&tx, &mut out, from, limit, &mut budget).await?;
        tx.commit().await?;
        Ok(out)
    }

    async fn pull_impl(
        &self,
        cursors: Vec<Cursor>,
        limit: u32,
        max_bytes: usize,
    ) -> StoreResult<PullResponse> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let empty = PullResponse {
            streams: Vec::new(),
            more: false,
        };
        let mut budget = max_bytes.saturating_sub(json_len(&empty));
        let mut remaining = limit;
        let mut more = false;
        let mut streams = Vec::new();
        for (ci, cur) in cursors.iter().enumerate() {
            if remaining == 0 {
                more = true;
                break;
            }
            let head = stream_head_tx(
                &tx,
                &cur.member.to_string(),
                &cur.device.to_string(),
                cur.tag.as_str(),
            )
            .await?;
            let mut sr = StreamRecords {
                member: cur.member,
                device: cur.device,
                tag: cur.tag.clone(),
                head,
                records: Vec::new(),
            };
            let base = json_len(&sr);
            if base > budget {
                more = true;
                break;
            }
            budget -= base;
            let from = i64_of(cur.from, || format!("/cursors/{ci}/from"))?;
            let cut = read_stream(&tx, &mut sr, from, remaining, &mut budget).await?;
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
        tx.commit().await?;
        Ok(PullResponse { streams, more })
    }

    async fn pushed_since_impl(&self, member_id: Id, since: i64) -> StoreResult<u64> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let r = tx
            .one(
                "SELECT (SELECT COUNT(*) FROM record \
                          WHERE member_id = $1 AND epoch IS NOT NULL AND received_at >= $2) \
                      + (SELECT COUNT(*) FROM deletion d \
                          WHERE d.member_id = $1 AND d.deleted_at >= $2 \
                            AND NOT EXISTS (SELECT 1 FROM record r \
                                             WHERE r.id = d.record_id AND r.epoch IS NOT NULL))",
                &[&member_id.to_string(), &hour(since)],
            )
            .await?;
        let n: i64 = col(&r, 0)?;
        tx.commit().await?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    async fn unknown_ids_impl(&self, ids: Vec<Id>) -> StoreResult<u64> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let mut seen = HashSet::new();
        let mut n = 0u64;
        for id in ids.iter().filter(|id| seen.insert(**id)) {
            let r = tx
                .one(
                    "SELECT EXISTS (SELECT 1 FROM record WHERE id = $1) \
                         OR EXISTS (SELECT 1 FROM deletion WHERE record_id = $1)",
                    &[&id.to_string()],
                )
                .await?;
            let known: bool = col(&r, 0)?;
            n += u64::from(!known);
        }
        tx.commit().await?;
        Ok(n)
    }

    async fn delete_impl(
        &self,
        req: DeleteRequest,
        by: Actor,
        now: i64,
    ) -> StoreResult<DeleteResponse> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let k = &self.key;
        let caller = by.member_id.to_string();
        let (mut deleted, mut already) = (0u64, 0u64);
        let target = match &req {
            DeleteRequest::Ids(ids) => {
                let mut seen = HashSet::new();
                let ids: Vec<String> = ids
                    .iter()
                    .filter(|id| seen.insert(**id))
                    .map(Id::to_string)
                    .collect();
                let mut held = Vec::with_capacity(ids.len());
                for id in &ids {
                    let row = match tx
                        .opt("SELECT member_id, tag FROM record WHERE id = $1", &[id])
                        .await?
                    {
                        Some(r) => Some((col::<String>(&r, 0)?, col::<String>(&r, 1)?)),
                        None => None,
                    };
                    let owner = row.as_ref().map(|(o, _)| o.clone());
                    if owner.as_deref().is_some_and(|o| o != caller) && !by.admin {
                        return Err(StoreError::Forbidden);
                    }
                    // TM9 F2: a roster record is never deleted (crypto §7); the whole request fails.
                    if row.as_ref().is_some_and(|(_, t)| t == "roster") {
                        return Err(StoreError::InvalidValue {
                            field: "/ids".into(),
                        });
                    }
                    held.push(owner);
                }
                for (id, owner) in ids.iter().zip(held) {
                    let appended = match owner {
                        Some(o) => delete_held(&tx, k, id, &o, now).await?,
                        None if in_deletions(&tx, id).await?.is_some() => false,
                        None => {
                            // Pre-deletion (`docs/sync-v1.md` §10.3), bound to the caller.
                            append_deletion(&tx, k, id, &caller, now).await?;
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
                deleted = delete_member_rows(&tx, k, &caller, now).await?;
                "all_mine".to_string()
            }
            DeleteRequest::Member(m) => {
                if !by.admin {
                    return Err(StoreError::Forbidden);
                }
                let m = m.to_string();
                if !exists(&tx, "SELECT 1 FROM member WHERE id = $1", &[&m]).await? {
                    return Err(StoreError::NotFound);
                }
                deleted = delete_member_rows(&tx, k, &m, now).await?;
                format!("member:{m}")
            }
        };
        audit_tx(
            &tx,
            k,
            now,
            Some(by.member_id),
            "delete",
            Some(target),
            Some(format!("deleted={deleted} already={already}")),
        )
        .await?;
        tx.commit().await?;
        Ok(DeleteResponse { deleted, already })
    }

    async fn retention_batch_impl(&self, cutoff: i64, limit: u32, now: i64) -> StoreResult<u64> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        promote_retention(&tx, now).await?;
        // TM9 P2: a run that another instance claimed within the hour deletes nothing.
        if !claim_tx(
            &tx,
            &self.key,
            RETENTION_CLAIM,
            now,
            crate::retention::INTERVAL_S,
        )
        .await?
        {
            tx.commit().await?;
            return Ok(0);
        }
        // TM9 F1: `roster` records are never deleted by retention (crypto §7). TM9 P1: the
        // newest `policy` record of each stream is kept whatever its age; older ones expire.
        // Ties within an hour go in stream order (SQLite: insertion order).
        let rows = tx
            .rows(
                "SELECT id, member_id FROM record r \
                  WHERE blob IS NOT NULL AND received_at < $1 AND tag <> 'roster' \
                    AND NOT (tag = 'policy' AND idx = (SELECT MAX(p.idx) FROM record p \
                          WHERE p.member_id = r.member_id \
                            AND p.device_id = r.device_id AND p.tag = 'policy')) \
                  ORDER BY received_at, member_id, device_id, tag, idx LIMIT $2",
                &[&cutoff, &i64::from(limit)],
            )
            .await?;
        for r in &rows {
            let (id, member): (String, String) = (col(r, 0)?, col(r, 1)?);
            delete_held(&tx, &self.key, &id, &member, now).await?;
        }
        tx.commit().await?;
        Ok(rows.len() as u64)
    }

    async fn prune_impl(&self, sql: &'static str, before: i64) -> StoreResult<u64> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let n = tx.exec(sql, &[&before]).await?;
        tx.commit().await?;
        Ok(n)
    }

    async fn deletions_impl(&self, from: u64, limit: u32) -> StoreResult<DeletionsResponse> {
        let from = i64_of(from, || "from".to_string())?;
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let heads = deletion_heads_tx(&tx).await?;
        let mut entries = Vec::new();
        for r in &tx
            .rows(
                "SELECT idx, record_id FROM deletion WHERE idx >= $1 ORDER BY idx LIMIT $2",
                &[&from, &i64::from(limit)],
            )
            .await?
        {
            entries.push(DeletionEntry {
                idx: u64_at(r, 0)?,
                record_id: id_at(r, 1)?,
            });
        }
        tx.commit().await?;
        Ok(DeletionsResponse {
            head: heads.head,
            oldest: heads.oldest,
            entries,
        })
    }

    async fn deletion_heads_impl(&self) -> StoreResult<DeletionHeads> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let out = deletion_heads_tx(&tx).await?;
        tx.commit().await?;
        Ok(out)
    }

    async fn append_audit_impl(&self, e: AuditEntry) -> StoreResult<u64> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        let idx = audit_tx(&tx, &self.key, e.at, e.actor, &e.action, e.target, e.detail).await?;
        tx.commit().await?;
        u64::try_from(idx).map_err(|_| broken("audit idx"))
    }

    async fn audit_impl(&self, from: u64, limit: u32) -> StoreResult<AuditResponse> {
        let from = i64_of(from, || "from".to_string())?;
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let r = tx
            .one("SELECT COALESCE(MAX(idx), -1) FROM audit", &[])
            .await?;
        let head: i64 = col(&r, 0)?;
        let mut rows = Vec::new();
        for r in &tx
            .rows(
                "SELECT idx, at, actor, action, target, detail FROM audit \
                  WHERE idx >= $1 ORDER BY idx LIMIT $2",
                &[&from, &i64::from(limit)],
            )
            .await?
        {
            rows.push(AuditRow {
                idx: u64_at(r, 0)?,
                at: col(r, 1)?,
                actor: opt_id_at(r, 2)?,
                action: col(r, 3)?,
                target: col(r, 4)?,
                detail: col(r, 5)?,
            });
        }
        tx.commit().await?;
        Ok(AuditResponse { head, rows })
    }

    async fn dump_impl(&self) -> StoreResult<LogicalDump> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        let mut tables = Vec::new();
        for (table, cols) in CANONICAL_TABLES {
            let sql = format!("SELECT {} FROM {table}", cols.join(", "));
            let mut out = Vec::new();
            for r in &tx.rows(&sql, &[]).await? {
                let row: Vec<DumpValue> = (0..cols.len())
                    .map(|i| dump_value(r, i))
                    .collect::<StoreResult<_>>()?;
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
        tx.commit().await?;
        Ok(LogicalDump { tables })
    }

    #[cfg(feature = "sqlite")]
    async fn export_impl(&self, dest: PathBuf) -> StoreResult<TableCounts> {
        let (send, recv) = tokio::sync::mpsc::channel::<canonical::Msg>(4);
        let writer = tokio::task::spawn_blocking(move || canonical::write(&dest, recv));
        let produced = self.export_rows(send).await;
        let written = writer
            .await
            .map_err(|e| StoreError::Backend(format!("export writer failed: {e}")))?;
        // The writer's error (an existing file, I/O) explains a failed send best.
        let counts = written?;
        produced?;
        Ok(counts)
    }

    #[cfg(feature = "sqlite")]
    async fn export_rows(
        &self,
        send: tokio::sync::mpsc::Sender<canonical::Msg>,
    ) -> StoreResult<()> {
        const PAGE: i32 = 500;
        let stopped = || StoreError::Backend("export writer stopped".into());
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Read).await?;
        for (table, cols) in CANONICAL_TABLES {
            let sql = format!(
                "SELECT {} FROM {table} ORDER BY {}",
                cols.join(", "),
                export_order(table)
            );
            let st = tx.tx.prepare(&sql).await?;
            let portal = tx.tx.bind(&st, &[]).await?;
            loop {
                let rows = tx.tx.query_portal(&portal, PAGE).await?;
                let n = rows.len();
                let mut page = Vec::with_capacity(n);
                for r in &rows {
                    let row: Vec<DumpValue> = (0..cols.len())
                        .map(|i| dump_value(r, i))
                        .collect::<StoreResult<_>>()?;
                    if *table == "meta" {
                        if let Some(DumpValue::Text(k)) = row.first() {
                            if !canonical_meta_key(k) {
                                continue;
                            }
                        }
                    }
                    page.push(row);
                }
                send.send(canonical::Msg::Rows(table, page))
                    .await
                    .map_err(|_| stopped())?;
                if n < PAGE as usize {
                    break;
                }
            }
        }
        tx.commit().await?;
        send.send(canonical::Msg::Done).await.map_err(|_| stopped())
    }

    #[cfg(feature = "sqlite")]
    async fn import_impl(&self, src: PathBuf) -> StoreResult<TableCounts> {
        let mut c = self.client().await?;
        let tx = self.begin(&mut c, Mode::Exclusive).await?;
        if store_holds_org(&tx).await? {
            return Err(StoreError::NotEmpty);
        }
        tx.exec("SET CONSTRAINTS ALL DEFERRED", &[]).await?;
        let (send, mut recv) = tokio::sync::mpsc::channel::<StoreResult<canonical::Msg>>(4);
        let reader = tokio::task::spawn_blocking(move || canonical::read(&src, &send));
        let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
        let mut file_meta: Vec<(String, String)> = Vec::new();
        let result: StoreResult<()> = async {
            loop {
                match recv.recv().await {
                    Some(Ok(canonical::Msg::Rows(table, rows))) => {
                        *counts.entry(table).or_default() += rows.len() as u64;
                        if table == "meta" {
                            for row in rows {
                                if let [DumpValue::Text(k), DumpValue::Text(v)] = row.as_slice() {
                                    file_meta.push((k.clone(), v.clone()));
                                } else {
                                    return Err(StoreError::Backend(
                                        "canonical file: meta row of an unexpected type".into(),
                                    ));
                                }
                            }
                        } else {
                            self.insert_rows(&tx, table, rows).await?;
                        }
                    }
                    Some(Ok(canonical::Msg::Done)) => return Ok(()),
                    Some(Err(e)) => return Err(e),
                    None => return Err(StoreError::Backend("import reader stopped".into())),
                }
            }
        }
        .await;
        drop(recv);
        reader
            .await
            .map_err(|e| StoreError::Backend(format!("import reader failed: {e}")))?;
        result?;
        // The importer keeps its own backup keys; every other key is the file's, and a
        // bootstrap token set here opens nothing once the scope holds an organisation.
        let file_keys: HashSet<&str> = file_meta.iter().map(|(k, _)| k.as_str()).collect();
        let mut drop_keys = Vec::new();
        for r in &tx.rows("SELECT key FROM meta", &[]).await? {
            let k: String = col(r, 0)?;
            let bootstrap = k.starts_with(meta_keys::BOOTSTRAP_PREFIX);
            if bootstrap || (canonical_meta_key(&k) && !file_keys.contains(k.as_str())) {
                drop_keys.push(k);
            }
        }
        for k in &drop_keys {
            tx.exec("DELETE FROM meta WHERE key = $1", &[k]).await?;
        }
        for (k, v) in &file_meta {
            meta_put(&tx, &self.key, k, v).await?;
        }
        // Deferred foreign keys are checked here.
        tx.commit().await?;
        Ok(TableCounts(
            CANONICAL_TABLES
                .iter()
                .map(|(t, _)| (*t, counts.get(t).copied().unwrap_or(0)))
                .collect(),
        ))
    }

    #[cfg(feature = "sqlite")]
    async fn insert_rows(
        &self,
        tx: &Tx<'_>,
        table: &'static str,
        rows: Vec<Vec<DumpValue>>,
    ) -> StoreResult<()> {
        let cols = CANONICAL_TABLES
            .iter()
            .find(|(t, _)| *t == table)
            .map(|(_, c)| *c)
            .ok_or_else(|| broken("unknown table"))?;
        let marks: Vec<String> = (2..=cols.len() + 1).map(|i| format!("${i}")).collect();
        let sql = format!(
            "INSERT INTO {table} (org_id, {}) VALUES ($1, {})",
            cols.join(", "),
            marks.join(", ")
        );
        let st = tx.tx.prepare_cached(&sql).await?;
        let types = st.params().to_vec();
        for row in rows {
            if row.len() != cols.len() {
                return Err(broken("canonical row width"));
            }
            let mut boxed: Vec<Box<dyn ToSql + Sync + Send>> = Vec::with_capacity(cols.len() + 1);
            boxed.push(Box::new(self.key.clone()));
            for (i, v) in row.into_iter().enumerate() {
                let what = format!("{table}.{}", cols[i]);
                boxed.push(param_of(v, &types[i + 1], &what)?);
            }
            let refs: Vec<&(dyn ToSql + Sync)> =
                boxed.iter().map(|b| &**b as &(dyn ToSql + Sync)).collect();
            tx.tx.execute(&st, &refs).await?;
        }
        Ok(())
    }
}

impl Store for PgOrg {
    fn restore_state(&self) -> StoreFuture<'_, RestoreState> {
        Box::pin(self.restore_state_impl())
    }
    fn renew_generation(&self, now: i64) -> StoreFuture<'_, Id> {
        Box::pin(self.renew_generation_impl(now))
    }
    fn complete_restore(&self, generation: Id, by: Actor, now: i64) -> StoreFuture<'_, ()> {
        Box::pin(self.complete_restore_impl(generation, by, now))
    }
    fn meta_get(&self, key: String) -> StoreFuture<'_, Option<String>> {
        Box::pin(self.meta_get_impl(key))
    }
    fn meta_set(&self, key: String, value: String) -> StoreFuture<'_, ()> {
        Box::pin(self.meta_set_impl(key, value))
    }
    fn org(&self, now: i64) -> StoreFuture<'_, Option<OrgRow>> {
        Box::pin(self.org_impl(now))
    }
    fn set_bootstrap(&self, token_hash: String, expires_at: i64) -> StoreFuture<'_, ()> {
        Box::pin(self.set_bootstrap_impl(token_hash, expires_at))
    }
    fn bootstrap(&self, req: NewBootstrap) -> StoreFuture<'_, Id> {
        Box::pin(self.bootstrap_impl(req))
    }
    fn auth_device(&self, token_hash: String) -> StoreFuture<'_, Option<AuthDevice>> {
        Box::pin(self.auth_device_impl(token_hash))
    }
    fn touch_device(&self, device_id: Id, day: i64) -> StoreFuture<'_, ()> {
        Box::pin(self.touch_device_impl(device_id, day))
    }
    fn rotate_token(&self, device_id: Id, token_hash: String, now: i64) -> StoreFuture<'_, ()> {
        Box::pin(self.rotate_token_impl(device_id, token_hash, now))
    }
    fn device(&self, device_id: Id) -> StoreFuture<'_, Option<DeviceRow>> {
        Box::pin(self.device_impl(device_id))
    }
    fn member(&self, member_id: Id) -> StoreFuture<'_, Option<MemberRow>> {
        Box::pin(self.member_impl(member_id))
    }
    fn member_by_handle(&self, handle: Handle) -> StoreFuture<'_, Option<MemberRow>> {
        Box::pin(self.member_by_handle_impl(handle))
    }
    fn create_invite(&self, invite: NewInvite) -> StoreFuture<'_, ()> {
        Box::pin(self.create_invite_impl(invite))
    }
    fn invite(&self, invite_id: Id) -> StoreFuture<'_, Option<InviteRow>> {
        Box::pin(self.invite_impl(invite_id))
    }
    fn revoke_invite(&self, invite_id: Id, by: Actor, now: i64) -> StoreFuture<'_, ()> {
        Box::pin(self.revoke_invite_impl(invite_id, by, now))
    }
    fn join(&self, req: NewJoin) -> StoreFuture<'_, Joined> {
        Box::pin(self.join_impl(req))
    }
    fn approve_device(
        &self,
        device_id: Id,
        wraps: Vec<EpochWrap>,
        by: Actor,
        now: i64,
    ) -> StoreFuture<'_, ()> {
        Box::pin(self.approve_device_impl(device_id, wraps, by, now))
    }
    fn revoke_device(&self, device_id: Id, by: Actor, now: i64) -> StoreFuture<'_, ()> {
        Box::pin(self.revoke_device_impl(device_id, by, now))
    }
    fn remove_member(
        &self,
        member_id: Id,
        delete_records: bool,
        by: Actor,
        now: i64,
    ) -> StoreFuture<'_, u64> {
        Box::pin(self.remove_member_impl(member_id, delete_records, by, now))
    }
    fn set_role(
        &self,
        member_id: Id,
        role: Role,
        by: Option<Actor>,
        now: i64,
    ) -> StoreFuture<'_, ()> {
        Box::pin(self.set_role_impl(member_id, role, by, now))
    }
    fn members(&self) -> StoreFuture<'_, Vec<MemberInfo>> {
        Box::pin(self.members_impl())
    }
    fn keys(&self, device_id: Id) -> StoreFuture<'_, KeysResponse> {
        Box::pin(self.keys_impl(device_id))
    }
    fn rotate_keys(
        &self,
        epoch: u32,
        wraps: Vec<DeviceWrap>,
        by: Actor,
        now: i64,
    ) -> StoreFuture<'_, ()> {
        Box::pin(self.rotate_keys_impl(epoch, wraps, by, now))
    }
    fn status(&self, device_id: Id, now: i64) -> StoreFuture<'_, StatusResponse> {
        Box::pin(self.status_impl(device_id, now))
    }
    fn update_settings(
        &self,
        update: SettingsUpdate,
        floor: Version,
        by: Option<Actor>,
        now: i64,
    ) -> StoreFuture<'_, OrgSettings> {
        Box::pin(self.update_settings_impl(update, floor, by, now))
    }
    fn push(&self, batch: PushBatch) -> StoreFuture<'_, PushResponse> {
        Box::pin(self.push_impl(batch))
    }
    fn stream_head(&self, member_id: Id, device_id: Id, tag: Tag) -> StoreFuture<'_, i64> {
        Box::pin(self.stream_head_impl(member_id, device_id, tag))
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
        Box::pin(self.records_impl(member_id, device_id, tag, from, limit, max_bytes))
    }
    fn pull(
        &self,
        cursors: Vec<Cursor>,
        limit: u32,
        max_bytes: usize,
    ) -> StoreFuture<'_, PullResponse> {
        Box::pin(self.pull_impl(cursors, limit, max_bytes))
    }
    fn pushed_since(&self, member_id: Id, since: i64) -> StoreFuture<'_, u64> {
        Box::pin(self.pushed_since_impl(member_id, since))
    }
    fn unknown_ids(&self, ids: Vec<Id>) -> StoreFuture<'_, u64> {
        Box::pin(self.unknown_ids_impl(ids))
    }
    fn claim(&self, name: String, at: i64, interval_s: i64) -> StoreFuture<'_, bool> {
        Box::pin(async move { PgOrg::claim(self, &name, at, interval_s).await })
    }
    fn delete(&self, req: DeleteRequest, by: Actor, now: i64) -> StoreFuture<'_, DeleteResponse> {
        Box::pin(self.delete_impl(req, by, now))
    }
    fn retention_batch(&self, cutoff: i64, limit: u32, now: i64) -> StoreFuture<'_, u64> {
        Box::pin(self.retention_batch_impl(cutoff, limit, now))
    }
    fn prune_deletions(&self, before: i64) -> StoreFuture<'_, u64> {
        Box::pin(self.prune_impl(
            "DELETE FROM deletion WHERE deleted_at < $1 \
               AND idx < (SELECT MAX(idx) FROM deletion)",
            before,
        ))
    }
    fn prune_audit(&self, before: i64) -> StoreFuture<'_, u64> {
        Box::pin(self.prune_impl(
            "DELETE FROM audit WHERE at < $1 AND idx < (SELECT MAX(idx) FROM audit)",
            before,
        ))
    }
    /// A no-op on Postgres. TM9 calls it after every delete request and every retention run;
    /// a `VACUUM` there would need the owner role (the application role owns no table, and
    /// `VACUUM` is the owner's), would scan the table shared by every organisation, and would
    /// serialise concurrent requests on the table's vacuum lock. Deleted rows are invisible to
    /// every query at once; their bytes stay in data pages until autovacuum (or the `VACUUM`
    /// of [`PgStore::delete_org`]) lets them be reused, as §5.6 states for `PgStore`.
    fn checkpoint(&self) -> StoreFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn deletions(&self, from: u64, limit: u32) -> StoreFuture<'_, DeletionsResponse> {
        Box::pin(self.deletions_impl(from, limit))
    }
    fn deletion_heads(&self) -> StoreFuture<'_, DeletionHeads> {
        Box::pin(self.deletion_heads_impl())
    }
    fn append_audit(&self, entry: AuditEntry) -> StoreFuture<'_, u64> {
        Box::pin(self.append_audit_impl(entry))
    }
    fn audit(&self, from: u64, limit: u32) -> StoreFuture<'_, AuditResponse> {
        Box::pin(self.audit_impl(from, limit))
    }
    #[cfg(feature = "sqlite")]
    fn export_canonical(&self, dest: PathBuf) -> StoreFuture<'_, TableCounts> {
        Box::pin(self.export_impl(dest))
    }
    #[cfg(not(feature = "sqlite"))]
    fn export_canonical(&self, dest: PathBuf) -> StoreFuture<'_, TableCounts> {
        let _ = dest;
        Box::pin(async {
            Err(StoreError::Unsupported(
                "canonical export needs the sqlite feature",
            ))
        })
    }
    #[cfg(feature = "sqlite")]
    fn import_canonical(&self, src: PathBuf) -> StoreFuture<'_, TableCounts> {
        Box::pin(self.import_impl(src))
    }
    #[cfg(not(feature = "sqlite"))]
    fn import_canonical(&self, src: PathBuf) -> StoreFuture<'_, TableCounts> {
        let _ = src;
        Box::pin(async {
            Err(StoreError::Unsupported(
                "canonical import needs the sqlite feature",
            ))
        })
    }
    fn dump(&self) -> StoreFuture<'_, LogicalDump> {
        Box::pin(self.dump_impl())
    }
}

// ---------------------------------------------------------------------------------------------
// The canonical SQLite file (export and import), on tokio's blocking pool

#[cfg(feature = "sqlite")]
mod canonical {
    use std::collections::BTreeMap;
    use std::path::Path;

    use rusqlite::types::Value;
    use rusqlite::{params_from_iter, Connection, OpenFlags};
    use tokio::sync::mpsc::{Receiver, Sender};

    use super::CANONICAL_META_SQL;
    use crate::store::sqlite::{
        check_attached_schema, columns_of, dump_value, finish_copy, migrate, with_new_file,
    };
    use crate::store::CANONICAL_TABLES;
    use crate::store::{DumpValue, StoreError, StoreResult, TableCounts};

    const PAGE: usize = 500;

    /// Rows of one canonical table, in [`CANONICAL_TABLES`] order; `Done` ends a complete
    /// stream (a stream that ends without it is a failed one).
    pub(super) enum Msg {
        Rows(&'static str, Vec<Vec<DumpValue>>),
        Done,
    }

    fn value(v: DumpValue) -> Value {
        match v {
            DumpValue::Null => Value::Null,
            DumpValue::Int(i) => Value::Integer(i),
            DumpValue::Text(s) => Value::Text(s),
            DumpValue::Blob(b) => Value::Blob(b),
        }
    }

    /// Writes a canonical file at `dest` (which must not exist; 0600, rollback journal) from
    /// the rows `recv` delivers: the 0001 schema with its triggers, no `backup_log` rows, only
    /// the canonical `meta` keys plus the schema version and checksum. Removes the file when
    /// anything fails after it was created.
    pub(super) fn write(dest: &Path, mut recv: Receiver<Msg>) -> StoreResult<TableCounts> {
        with_new_file(dest, || {
            let mut conn = finish_copy(dest)?;
            migrate(&mut conn)?;
            let tx = conn.transaction()?;
            // The seeded generation and restore state give way to the organisation's.
            tx.execute(&format!("DELETE FROM meta WHERE {CANONICAL_META_SQL}"), [])?;
            let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
            loop {
                match recv.blocking_recv() {
                    Some(Msg::Rows(table, rows)) => {
                        let cols = columns_of(table)?;
                        let marks: Vec<String> =
                            (1..=cols.len()).map(|i| format!("?{i}")).collect();
                        let sql = format!(
                            "INSERT INTO {table} ({}) VALUES ({})",
                            cols.join(", "),
                            marks.join(", ")
                        );
                        let mut st = tx.prepare_cached(&sql)?;
                        for row in rows {
                            st.execute(params_from_iter(row.into_iter().map(value)))?;
                            *counts.entry(table).or_default() += 1;
                        }
                    }
                    Some(Msg::Done) => break,
                    None => return Err(StoreError::Backend("export reader stopped".into())),
                }
            }
            tx.execute("DELETE FROM backup_log", [])?;
            let violations: i64 =
                tx.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
                    r.get(0)
                })?;
            if violations > 0 {
                return Err(StoreError::Backend(format!(
                    "refused: {violations} row(s) of the export violate a foreign key"
                )));
            }
            tx.commit()?;
            conn.execute_batch("VACUUM")?;
            drop(conn);
            Ok(TableCounts(
                CANONICAL_TABLES
                    .iter()
                    .map(|(t, _)| (*t, counts.get(t).copied().unwrap_or(0)))
                    .collect(),
            ))
        })
    }

    /// Reads a canonical file for an import: refuses a missing file and one whose schema
    /// version or checksum is not this binary's, then sends every canonical row (`meta`
    /// filtered), table by table in [`CANONICAL_TABLES`] order and rowid order, and `Done`.
    pub(super) fn read(src: &Path, send: &Sender<StoreResult<Msg>>) {
        if let Err(e) = read_rows(src, send) {
            let _ = send.blocking_send(Err(e));
        }
    }

    fn read_rows(src: &Path, send: &Sender<StoreResult<Msg>>) -> StoreResult<()> {
        if !src.is_file() {
            return Err(StoreError::Backend(format!(
                "no such file: {}",
                src.display()
            )));
        }
        let conn = Connection::open_with_flags(
            src,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        check_attached_schema(&conn, "main")?;
        let stopped = || StoreError::Backend("import writer stopped".into());
        for (table, cols) in CANONICAL_TABLES {
            let filter = if *table == "meta" {
                format!(" WHERE {CANONICAL_META_SQL}")
            } else {
                String::new()
            };
            let mut st = conn.prepare(&format!(
                "SELECT {} FROM {table}{filter} ORDER BY rowid",
                cols.join(", ")
            ))?;
            let mut rows = st.query([])?;
            let mut page = Vec::with_capacity(PAGE);
            while let Some(r) = rows.next()? {
                let row: Vec<DumpValue> = (0..cols.len())
                    .map(|i| r.get_ref(i).map(dump_value))
                    .collect::<Result<_, _>>()?;
                page.push(row);
                if page.len() == PAGE {
                    send.blocking_send(Ok(Msg::Rows(table, std::mem::take(&mut page))))
                        .map_err(|_| stopped())?;
                }
            }
            if !page.is_empty() {
                send.blocking_send(Ok(Msg::Rows(table, page)))
                    .map_err(|_| stopped())?;
            }
        }
        send.blocking_send(Ok(Msg::Done)).map_err(|_| stopped())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_parse_in_the_tcp_and_the_cloud_sql_socket_forms() {
        use tokio_postgres::config::Host;
        let tcp = parse_url("postgres://awm_app:secret@127.0.0.1:54329/awm_test").unwrap();
        assert_eq!(tcp.get_hosts(), &[Host::Tcp("127.0.0.1".into())]);
        assert_eq!(tcp.get_ports(), &[54329]);
        assert_eq!(tcp.get_user(), Some("awm_app"));
        assert_eq!(tcp.get_dbname(), Some("awm_test"));
        assert_eq!(tcp.get_application_name(), Some(APPLICATION_NAME));
        assert_eq!(tcp.get_connect_timeout(), Some(&CONNECT_TIMEOUT));
        #[cfg(unix)]
        {
            let sock = "/cloudsql/my-project:us-central1:awm-db";
            for url in [
                "postgres://awm_app:secret@/awm?host=/cloudsql/my-project:us-central1:awm-db"
                    .to_string(),
                "postgres://awm_app:secret@%2Fcloudsql%2Fmy-project%3Aus-central1%3Aawm-db/awm"
                    .to_string(),
                format!("host={sock} user=awm_app password=secret dbname=awm"),
            ] {
                let c = parse_url(&url).unwrap();
                assert_eq!(c.get_hosts(), &[Host::Unix(sock.into())], "{url}");
                assert_eq!(c.get_dbname(), Some("awm"));
                assert_eq!(c.get_user(), Some("awm_app"));
                assert_eq!(c.get_password(), Some(&b"secret"[..]));
            }
        }
        // The URL (and its password) never appears in the error.
        let e = parse_url("postgres://awm_app:hunter2@host:notaport/db").unwrap_err();
        assert!(!e.to_string().contains("hunter2"), "{e}");
        let named = parse_url("postgres://u@h/d?application_name=x").unwrap();
        assert_eq!(named.get_application_name(), Some("x"));
    }

    #[test]
    fn lock_keys_differ_per_organisation_and_stream() {
        let (a, b) = (Id::new_v4(), Id::new_v4());
        let (m, d) = (Id::new_v4(), Id::new_v4());
        assert_ne!(org_lock_key(a), org_lock_key(b));
        assert_eq!(org_lock_key(a), org_lock_key(a));
        assert_ne!(
            stream_lock_key(a, m, d, "rec"),
            stream_lock_key(a, m, d, "flag")
        );
        assert_ne!(
            stream_lock_key(a, m, d, "rec"),
            stream_lock_key(b, m, d, "rec")
        );
        assert_ne!(stream_lock_key(a, m, d, "rec"), org_lock_key(a));
    }

    #[test]
    fn versions_are_checked_like_the_sqlite_runner() {
        let sum = crate::store::checksum(MIGRATIONS[0].2.as_bytes());
        let mut applied = BTreeMap::new();
        assert_eq!(check_versions(&applied, MIGRATIONS).unwrap(), 0);
        applied.insert(1, sum.clone());
        assert_eq!(check_versions(&applied, MIGRATIONS).unwrap(), 1);
        applied.insert(1, "0".repeat(64));
        assert!(check_versions(&applied, MIGRATIONS)
            .unwrap_err()
            .to_string()
            .contains("checksum mismatch"));
        applied.insert(1, sum);
        applied.insert(2, "0".repeat(64));
        assert!(check_versions(&applied, MIGRATIONS)
            .unwrap_err()
            .to_string()
            .contains("newer awm"));
        assert!(validate_list(&[(2, "x", "")]).is_err());
    }

    #[test]
    fn the_migration_controls_no_transaction_and_covers_every_table() {
        let sql = MIGRATIONS[0].2;
        let code: String = sql
            .lines()
            .map(|l| l.split("--").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
            .to_uppercase();
        for word in [
            "BEGIN;",
            "COMMIT",
            "ROLLBACK",
            "SAVEPOINT",
            "VACUUM",
            "BYPASSRLS",
        ] {
            assert!(!code.contains(word), "{word}");
        }
        for table in ORG_TABLES {
            assert!(sql.contains(&format!("CREATE TABLE {table} (")), "{table}");
            assert!(
                sql.contains(&format!("'{table}'")),
                "{table} in the RLS loop"
            );
        }
        assert!(!code.contains("BACKUP_LOG"), "SqliteStore only");
        let canonical: Vec<&str> = CANONICAL_TABLES.iter().map(|(t, _)| *t).collect();
        for t in &canonical {
            assert!(ORG_TABLES.contains(t));
        }
    }
}
