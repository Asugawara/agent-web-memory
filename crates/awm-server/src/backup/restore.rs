//! Restore from a backup chain, and the self-verification (plan-v3-team §6.2, §3.9.5, §4.8.1,
//! TM27).
//!
//! **Chain** ([`select_chain`]): the full snapshot (or export) whose manifest time is the
//! latest at or before `--at` (the latest of all without it), then the change sets of its
//! generation that start at or before its head, in order of their heads, each starting where
//! the previous one ended, written at or before `--at`. A gap (a change set missing between
//! two others, or before the first) is refused, and so is a manifest whose data object is
//! missing. Data objects without a manifest (uploads cut short) are not part of any chain.
//!
//! **Assembly** ([`assemble`]): every object is downloaded into a private directory and
//! checked against its manifest (SHA-256 and size) and with `PRAGMA integrity_check`; the
//! full snapshot becomes `server.db`, opened by `SqliteStore` (which migrates an older
//! schema), and each change set is applied with `Store::apply_changes`, its head checked
//! against the manifest. Any mismatch names the object (exit 3).
//!
//! **Restore** ([`run`]): into a data directory, the assembled database is finished in a
//! staging directory inside it (a new `generation`, `restore_pending` and `restored_at` through
//! `Store::renew_generation`, the backup state reset, the restored generation appended to the
//! lineage, a WAL checkpoint, `PRAGMA integrity_check` again) and only then moved to
//! `server.db`; an existing database is refused unless `--force`, which first renames it (and
//! its `-wal` and `-shm` files) to `server.db.pre-restore-{time}`, which the hourly retention
//! of `awm serve` removes after the backups' window ([`super::local`], RVT2 B2). A data
//! directory whose `server.lock` a running server holds is refused (RVT2 M5). Into a `PgStore`
//! organisation, the assembled database is exported in the canonical format and imported into
//! the (empty) organisation, then given a new `generation`. `--mark-restored` only renews the
//! `generation` (after a Cloud SQL restore or clone).
//!
//! **Verification** ([`verify`]): the latest chain is assembled into a temporary directory and
//! compared, table by table (row counts and `LogicalDump::digest`), with a snapshot of the live
//! database taken afterwards, brought to the same point by the live snapshot's own change set
//! since the chain's end; so writes during the verification do not make it fail, and every
//! row the chain holds is compared. The result and its time go to `meta`; the directory is
//! removed.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use awm_proto::wire::Id;

use super::full::{blocking, integrity_check, io, mkdir_private, write_private, TempDir};
use super::manifest::{Kind, Manifest};
use super::target::{Bucket, Target};
use super::{keys, list_all, parse_lineage, read_manifest, BackupError};
use crate::lockfile::{self, DataLock, LockError};
use crate::store::sqlite::{SqliteStore, DB_FILE};
use crate::store::{LogicalDump, Store, StoreError};

/// Restore failures are [`BackupError`]s; [`BackupError::exit_code`] maps them (§4.8.1).
pub type RestoreError = BackupError;

/// How many restored-from generations [`keys::LINEAGE`] remembers.
const LINEAGE_MAX: usize = 16;

// ---------------------------------------------------------------------------------------------
// Chains

/// A full snapshot (or export) and the change sets that follow it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub full: Manifest,
    pub incrs: Vec<Manifest>,
}

impl Chain {
    pub fn generation(&self) -> Id {
        self.full.generation
    }

    /// The data keys, in the order they are applied.
    pub fn keys(&self) -> Vec<String> {
        std::iter::once(&self.full)
            .chain(&self.incrs)
            .map(Manifest::data_key)
            .collect()
    }

    /// The `backup_log` head the chain reaches (`None` for an export).
    pub fn end(&self) -> Option<i64> {
        self.incrs.last().map_or(self.full.to, |m| m.to)
    }

    /// The time of the last object.
    pub fn time(&self) -> i64 {
        self.incrs.last().map_or(self.full.time, |m| m.time)
    }
}

/// Picks the chain to restore (module docs); `at` in Unix seconds.
pub async fn select_chain(bucket: &dyn Bucket, at: Option<i64>) -> Result<Chain, BackupError> {
    let listing = list_all(bucket).await?;
    let mut best: Option<Manifest> = None;
    for (g, objs) in &listing {
        for seq in &objs.full_json {
            let Some(m) = read_manifest(bucket, Kind::Full, *g, *seq).await? else {
                continue;
            };
            if at.is_some_and(|a| m.time > a) {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|b| (m.time, m.seq) > (b.time, b.seq))
            {
                best = Some(m);
            }
        }
    }
    let full = best.ok_or_else(|| {
        BackupError::NoBackup(match at {
            Some(a) => format!("no full snapshot at or before {a} in {}", bucket.url()),
            None => format!("no full snapshot in {}", bucket.url()),
        })
    })?;
    let generation = full.generation;
    let objs = &listing[&generation];
    if !objs.full_data.contains(&full.seq) {
        return Err(BackupError::Corrupt {
            object: full.data_key(),
            reason: "missing (its manifest exists)".into(),
        });
    }
    let mut incrs = Vec::new();
    if let (Kind::Full, Some(start)) = (full.kind, full.to) {
        let mut cursor = start;
        for seq in objs.incr_json.range(start + 1..) {
            let Some(m) = read_manifest(bucket, Kind::Incr, generation, *seq).await? else {
                continue;
            };
            if at.is_some_and(|a| m.time > a) {
                continue;
            }
            let (Some(after), Some(to)) = (m.after, m.to) else {
                return Err(BackupError::Corrupt {
                    object: m.key(),
                    reason: "a change set without its cursor range".into(),
                });
            };
            if after > cursor {
                return Err(BackupError::MissingIncrement {
                    generation,
                    after: cursor,
                });
            }
            if !objs.incr_data.contains(seq) {
                return Err(BackupError::Corrupt {
                    object: m.data_key(),
                    reason: "missing (its manifest exists)".into(),
                });
            }
            cursor = to;
            incrs.push(m);
        }
    }
    Ok(Chain { full, incrs })
}

async fn download(bucket: &dyn Bucket, m: &Manifest) -> Result<Vec<u8>, BackupError> {
    let key = m.data_key();
    let bytes = bucket
        .get(key.clone())
        .await?
        .ok_or_else(|| BackupError::Corrupt {
            object: key.clone(),
            reason: "missing (its manifest exists)".into(),
        })?;
    if !m.matches(&bytes) {
        return Err(BackupError::Corrupt {
            object: key,
            reason: "SHA-256 or size differs from its manifest".into(),
        });
    }
    Ok(bytes)
}

/// Writes `bytes` to `path` (0600) and runs `PRAGMA integrity_check`; returns the file's
/// `backup_log` head. Failures name `object`.
async fn place(path: PathBuf, bytes: Vec<u8>, object: String) -> Result<i64, BackupError> {
    blocking(move || {
        write_private(&path, &bytes)?;
        integrity_check(&path).map_err(|reason| BackupError::Corrupt { object, reason })
    })
    .await
}

/// Downloads and checks every object of `chain` into `dir` (private, empty) and applies it
/// (module docs). Returns the open store over `dir/server.db`.
pub async fn assemble(
    bucket: &dyn Bucket,
    chain: &Chain,
    dir: &Path,
) -> Result<SqliteStore, BackupError> {
    mkdir_private(dir)?;
    let full = &chain.full;
    let bytes = download(bucket, full).await?;
    let head = place(dir.join(DB_FILE), bytes, full.data_key()).await?;
    if full.kind == Kind::Full && Some(head) != full.to {
        return Err(BackupError::Corrupt {
            object: full.data_key(),
            reason: format!("head {head} differs from its manifest"),
        });
    }
    let data = dir.to_path_buf();
    let store = blocking(move || {
        SqliteStore::open(&data).map_err(|e| BackupError::Unusable(e.to_string()))
    })
    .await?;
    for m in &chain.incrs {
        let bytes = download(bucket, m).await?;
        let path = dir.join(format!("incr-{}.db", m.seq));
        place(path.clone(), bytes, m.data_key()).await?;
        let cs = store
            .apply_changes(path.clone())
            .await
            .map_err(|e| BackupError::Corrupt {
                object: m.data_key(),
                reason: e.to_string(),
            })?;
        if cs.rows > 0 && Some(cs.to) != m.to {
            return Err(BackupError::Corrupt {
                object: m.data_key(),
                reason: format!("head {} differs from its manifest", cs.to),
            });
        }
        let _ = std::fs::remove_file(&path);
    }
    Ok(store)
}

// ---------------------------------------------------------------------------------------------
// Verification

/// One table of a verification: rows and `LogicalDump::digest` over that table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableCheck {
    pub table: String,
    pub rows: u64,
    pub digest: String,
}

/// A successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// The full snapshot the chain starts from, and how many objects it has in all.
    pub full: String,
    pub objects: usize,
    /// The head the chain reaches.
    pub cursor: Option<i64>,
    /// Rows changed in the live database since the chain's end (shipped by the next change set).
    pub behind_rows: u64,
    /// `false` for an export chain (`PgStore`): it was checked and opened, but the live
    /// database moved since the export, so rows were counted, not compared.
    pub compared: bool,
    pub tables: Vec<TableCheck>,
}

impl VerifyReport {
    /// One line for `meta.backup_verify_detail` and logs.
    pub fn summary(&self) -> String {
        format!(
            "{} + {} change set(s) to cursor {}, {} table(s) {}, {} row change(s) newer than the backup",
            self.full,
            self.objects.saturating_sub(1),
            self.cursor.map_or("-".into(), |c| c.to_string()),
            self.tables.len(),
            if self.compared { "identical" } else { "counted" },
            self.behind_rows
        )
    }
}

fn tables_of(dump: &LogicalDump) -> Vec<TableCheck> {
    dump.tables
        .iter()
        .map(|(t, rows)| TableCheck {
            table: t.to_string(),
            rows: rows.len() as u64,
            digest: LogicalDump {
                tables: vec![(*t, rows.clone())],
            }
            .digest(),
        })
        .collect()
}

/// `awm serve backup --verify` and the weekly self-verification (module docs). Writes
/// `backup_verify_at`, `backup_verify_ok` (`1` or `0`), `backup_verify_ok_at` on success and
/// `backup_verify_detail`, and removes its temporary directory under `scratch`.
pub async fn verify(
    store: &dyn Store,
    bucket: &dyn Bucket,
    now: i64,
    scratch: &Path,
) -> Result<VerifyReport, BackupError> {
    let result = match TempDir::new(scratch, "verify") {
        Ok(tmp) => verify_in(store, bucket, tmp.path()).await,
        Err(e) => Err(e),
    };
    let (ok, detail) = match &result {
        Ok(r) => ("1", r.summary()),
        Err(e) => ("0", e.to_string()),
    };
    store
        .meta_set(keys::VERIFY_AT.into(), now.to_string())
        .await?;
    store.meta_set(keys::VERIFY_OK.into(), ok.into()).await?;
    store.meta_set(keys::VERIFY_DETAIL.into(), detail).await?;
    if result.is_ok() {
        store
            .meta_set(keys::VERIFY_OK_AT.into(), now.to_string())
            .await?;
    }
    result
}

async fn verify_in(
    store: &dyn Store,
    bucket: &dyn Bucket,
    dir: &Path,
) -> Result<VerifyReport, BackupError> {
    let chain = select_chain(bucket, None).await?;
    let restored = assemble(bucket, &chain, &dir.join("chain")).await?;
    let live_dir = dir.join("live");
    mkdir_private(&live_dir)?;
    let mut behind_rows = 0;
    let (live_dump, compared) = match store.snapshot(live_dir.join(DB_FILE)).await {
        Ok(live_head) => {
            let ld = live_dir.clone();
            let live = blocking(move || {
                SqliteStore::open(&ld).map_err(|e| BackupError::Unusable(e.to_string()))
            })
            .await?;
            let end = chain.end().unwrap_or(0);
            if live_head < end {
                return Err(BackupError::Mismatch(format!(
                    "the backup reaches cursor {end}, beyond the live database's {live_head}"
                )));
            }
            let delta = dir.join("delta.db");
            let cs = live.export_changes(end, delta.clone()).await?;
            if cs.rows > 0 {
                restored.apply_changes(delta).await?;
            }
            behind_rows = cs.rows;
            (Some(live.dump().await?), true)
        }
        Err(StoreError::Unsupported(_)) => (None, false),
        Err(e) => return Err(e.into()),
    };
    let restored_dump = restored.dump().await?;
    let mine = tables_of(&restored_dump);
    if let Some(live_dump) = live_dump {
        let theirs = tables_of(&live_dump);
        let differ: Vec<String> = mine
            .iter()
            .zip(&theirs)
            .filter(|(a, b)| a != b)
            .map(|(a, b)| {
                format!(
                    "{} ({} rows in the backup, {} live)",
                    a.table, a.rows, b.rows
                )
            })
            .collect();
        if !differ.is_empty() || mine.len() != theirs.len() {
            return Err(BackupError::Mismatch(format!(
                "tables differ: {}",
                differ.join(", ")
            )));
        }
    }
    Ok(VerifyReport {
        full: chain.full.data_key(),
        objects: 1 + chain.incrs.len(),
        cursor: chain.end(),
        behind_rows,
        compared,
        tables: mine,
    })
}

// ---------------------------------------------------------------------------------------------
// Restore

/// Where `--from` points.
#[derive(Debug, Clone)]
pub enum RestoreSource {
    /// No source (`--mark-restored`).
    None,
    /// A backup target: the chain is chosen there.
    Bucket(Arc<dyn Bucket>),
    /// A database file: a full snapshot or a canonical export (`awm serve backup --to FILE`,
    /// `GET /v1/export`).
    File(PathBuf),
}

impl RestoreSource {
    /// `--from URL|FILE`: a value with `://` is a backup URL ([`Target::parse`], opened from
    /// the environment), anything else a file.
    pub fn parse(from: &str) -> Result<RestoreSource, BackupError> {
        if from.contains("://") {
            Ok(RestoreSource::Bucket(Target::parse(from)?.open()?))
        } else {
            Ok(RestoreSource::File(PathBuf::from(from)))
        }
    }
}

/// What is restored into.
#[derive(Clone)]
pub enum RestoreDest {
    /// `--data DIR` (`SqliteStore`).
    Data(PathBuf),
    /// `--database-url`: a `PgStore` organisation scope (`PgStore::create_org`), which must be
    /// empty; `scratch` is a private directory for the assembly.
    Store {
        store: Arc<dyn Store>,
        scratch: PathBuf,
    },
}

/// `awm serve restore` (§4.8.1).
#[derive(Clone)]
pub struct RestoreRequest {
    pub source: RestoreSource,
    pub dest: RestoreDest,
    /// `--at TIME` in Unix seconds (backup URLs only).
    pub at: Option<i64>,
    /// `--force`: replace an existing `server.db` (renamed to `server.db.pre-restore-{now}`).
    pub force: bool,
    /// `--mark-restored`: only renew the `generation` of the destination.
    pub mark_restored: bool,
    pub now: i64,
}

/// What a restore did (TM15 prints it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// The new `generation`.
    pub generation: Id,
    /// The `generation` the backup was written under (`None` for `--mark-restored`).
    pub restored_from: Option<Id>,
    /// The objects applied, in order (the file for a file source).
    pub objects: Vec<String>,
    /// The time of the last object applied (backup URLs).
    pub point_in_time: Option<i64>,
    /// The `backup_log` head the chain reached.
    pub cursor: Option<i64>,
    /// Rows per canonical table after the restore, before the new generation's audit row.
    pub counts: Vec<(String, u64)>,
    /// `LogicalDump::digest` of the restored data before the new generation was written (the
    /// live database's digest at the backup point, when nothing is lost).
    pub digest: Option<String>,
    /// The database file written (`--data`).
    pub path: Option<PathBuf>,
    /// Where `--force` moved the previous database.
    pub pre_restore: Option<PathBuf>,
    /// When `awm serve` removes that copy at the latest ([`super::local::removal_date`]; earlier
    /// once every backup older than it has expired).
    pub pre_restore_removed_by: Option<i64>,
}

/// Renews the generation of `store` and resets its backup state, recording `from` in the
/// lineage (so the next server keeps and expires the old generation's objects).
async fn finish(store: &dyn Store, from: Option<Id>, now: i64) -> Result<Id, BackupError> {
    let mut lineage = parse_lineage(store.meta_get(keys::LINEAGE.into()).await?.as_deref());
    if let Some(from) = from {
        lineage.retain(|g| *g != from);
        lineage.push(from);
    }
    if lineage.len() > LINEAGE_MAX {
        lineage.drain(..lineage.len() - LINEAGE_MAX);
    }
    let generation = store.renew_generation(now).await?;
    for key in keys::STATE {
        store.meta_set(key.to_string(), String::new()).await?;
    }
    let joined: Vec<String> = lineage.iter().map(Id::to_string).collect();
    store
        .meta_set(keys::LINEAGE.into(), joined.join(","))
        .await?;
    Ok(generation)
}

/// The assembled database in `staging`: from the chain in a bucket, or from a file.
struct Assembled {
    store: SqliteStore,
    objects: Vec<String>,
    point_in_time: Option<i64>,
    cursor: Option<i64>,
}

async fn assemble_source(
    source: &RestoreSource,
    at: Option<i64>,
    staging: &Path,
) -> Result<Assembled, BackupError> {
    match source {
        RestoreSource::None => Err(BackupError::Refused(
            "--from URL|FILE is required (or --mark-restored)".into(),
        )),
        RestoreSource::Bucket(bucket) => {
            let chain = select_chain(&**bucket, at).await?;
            let store = assemble(&**bucket, &chain, staging).await?;
            Ok(Assembled {
                store,
                objects: chain.keys(),
                point_in_time: Some(chain.time()),
                cursor: chain.end(),
            })
        }
        RestoreSource::File(file) => {
            if at.is_some() {
                return Err(BackupError::Refused("--at needs a backup URL".into()));
            }
            mkdir_private(staging)?;
            let bytes = std::fs::read(file).map_err(|e| io("cannot read", file, e))?;
            let head = place(staging.join(DB_FILE), bytes, file.display().to_string()).await?;
            let data = staging.to_path_buf();
            let store = blocking(move || {
                SqliteStore::open(&data).map_err(|e| BackupError::Unusable(e.to_string()))
            })
            .await?;
            Ok(Assembled {
                store,
                objects: vec![file.display().to_string()],
                point_in_time: None,
                cursor: Some(head),
            })
        }
    }
}

fn counts_of(dump: &LogicalDump) -> Vec<(String, u64)> {
    dump.tables
        .iter()
        .map(|(t, rows)| (t.to_string(), rows.len() as u64))
        .collect()
}

/// `awm serve restore` (module docs, §4.8.1). Exit codes through [`BackupError::exit_code`]:
/// 2 refused (an existing database without `--force`, an organisation in the target store,
/// `--mark-restored` with `--from`, no source), 3 a manifest mismatch, a missing object or
/// change set, a failed integrity check, 1 anything else.
pub async fn run(req: RestoreRequest) -> Result<RestoreReport, RestoreError> {
    if req.mark_restored {
        return mark_restored(req).await;
    }
    match &req.dest {
        RestoreDest::Data(dir) => restore_data(&req, dir).await,
        RestoreDest::Store { store, scratch } => restore_store(&req, &**store, scratch).await,
    }
}

async fn mark_restored(req: RestoreRequest) -> Result<RestoreReport, BackupError> {
    if !matches!(req.source, RestoreSource::None) || req.at.is_some() {
        return Err(BackupError::Refused(
            "--mark-restored takes no --from and no --at: it only renews the generation".into(),
        ));
    }
    let mut _lock = None;
    let (store, path): (Arc<dyn Store>, Option<PathBuf>) = match &req.dest {
        RestoreDest::Data(dir) => {
            let db = dir.join(DB_FILE);
            if !db.is_file() {
                return Err(BackupError::Refused(format!(
                    "{} does not exist",
                    db.display()
                )));
            }
            _lock = Some(lock_dir(dir)?);
            let d = dir.clone();
            let s = blocking(move || {
                SqliteStore::open(&d).map_err(|e| BackupError::Unusable(e.to_string()))
            })
            .await?;
            (Arc::new(s), Some(db))
        }
        RestoreDest::Store { store, .. } => (Arc::clone(store), None),
    };
    let generation = store.renew_generation(req.now).await?;
    let dump = store.dump().await?;
    Ok(RestoreReport {
        generation,
        restored_from: None,
        objects: Vec::new(),
        point_in_time: None,
        cursor: None,
        counts: counts_of(&dump),
        digest: None,
        path,
        pre_restore: None,
        pre_restore_removed_by: None,
    })
}

/// `{dir}/server.lock` for the restore (RVT2 M5): refused (exit 2) while a server holds it, and
/// held until the restore returns, so no server starts on a half-restored directory.
fn lock_dir(dir: &Path) -> Result<DataLock, BackupError> {
    lockfile::try_lock(dir).map_err(|e| match e {
        LockError::Held(p) => BackupError::Refused(format!(
            "{} is held: a server is running on {}; stop the server first",
            p.display(),
            dir.display()
        )),
        LockError::Io(m) => BackupError::Io(m),
    })
}

async fn restore_data(req: &RestoreRequest, dir: &Path) -> Result<RestoreReport, BackupError> {
    let db = dir.join(DB_FILE);
    let exists = db.exists();
    if exists && !req.force {
        return Err(BackupError::Refused(format!(
            "{} exists: stop the server and pass --force to move it to {DB_FILE}.pre-restore-{} first",
            db.display(),
            req.now
        )));
    }
    mkdir_private(dir)?;
    let _lock = lock_dir(dir)?;
    let staging = TempDir::new(dir, "restore")?;
    let a = assemble_source(&req.source, req.at, staging.path()).await?;
    let dump = a.store.dump().await?;
    let restored_from = Some(a.store.restore_state().await?.generation);
    let generation = finish(&a.store, restored_from, req.now).await?;
    a.store.checkpoint().await?;
    drop(a.store);
    let staged = staging.path().join(DB_FILE);
    {
        let s = staged.clone();
        blocking(move || integrity_check(&s).map_err(BackupError::Unusable)).await?;
    }
    let mut pre_restore = None;
    if exists {
        let moved = dir.join(format!("{DB_FILE}.pre-restore-{}", req.now));
        for suffix in ["", "-wal", "-shm"] {
            let from = PathBuf::from(format!("{}{suffix}", db.display()));
            if from.exists() {
                let to = PathBuf::from(format!("{}{suffix}", moved.display()));
                std::fs::rename(&from, &to).map_err(|e| io("cannot move", &from, e))?;
            }
        }
        pre_restore = Some(moved);
    }
    std::fs::rename(&staged, &db)
        .map_err(|e| io("cannot move the restored database to", &db, e))?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(RestoreReport {
        generation,
        restored_from,
        objects: a.objects,
        point_in_time: a.point_in_time,
        cursor: a.cursor,
        counts: counts_of(&dump),
        digest: Some(dump.digest()),
        path: Some(db),
        pre_restore_removed_by: pre_restore
            .as_ref()
            .map(|_| super::local::removal_date(req.now)),
        pre_restore,
    })
}

async fn restore_store(
    req: &RestoreRequest,
    dest: &dyn Store,
    scratch: &Path,
) -> Result<RestoreReport, BackupError> {
    if dest.org(req.now).await?.is_some() {
        return Err(BackupError::Refused(
            "the target database already holds an organisation: restore into an empty one \
             (--force applies to --data only)"
                .into(),
        ));
    }
    mkdir_private(scratch)?;
    let staging = TempDir::new(scratch, "restore")?;
    let a = assemble_source(&req.source, req.at, &staging.path().join("db")).await?;
    let dump = a.store.dump().await?;
    let restored_from = Some(a.store.restore_state().await?.generation);
    let canonical = staging.path().join("canonical.db");
    a.store.export_canonical(canonical.clone()).await?;
    drop(a.store);
    match dest.import_canonical(canonical).await {
        Ok(_) => {}
        Err(StoreError::NotEmpty) => {
            return Err(BackupError::Refused(
                "the target database already holds an organisation".into(),
            ))
        }
        Err(e) => return Err(e.into()),
    }
    let generation = finish(dest, restored_from, req.now).await?;
    Ok(RestoreReport {
        generation,
        restored_from,
        objects: a.objects,
        point_in_time: a.point_in_time,
        cursor: a.cursor,
        counts: counts_of(&dump),
        digest: Some(dump.digest()),
        path: None,
        pre_restore: None,
        pre_restore_removed_by: None,
    })
}
