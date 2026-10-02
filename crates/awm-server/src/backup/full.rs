//! Full snapshots and canonical exports (plan-v3-team §6.2, TM27).
//!
//! A full snapshot is `Store::snapshot` (a `VACUUM INTO` copy with `backup_log` and every
//! `meta` key, 0600), named after the `backup_log` head inside the copy; the next change set
//! starts there. `PgStore` has no `backup_log`: its backup is `Store::export_canonical`, named
//! after its time. Both upload create-only, the data object first and its manifest second, so
//! a reader that finds a manifest finds a complete object, and an interrupted upload leaves at
//! most a data object without a manifest, which restore ignores and retention removes.
//!
//! Also here: the helpers every step shares (temporary files, row counts and
//! `PRAGMA integrity_check` on a SQLite file, the paired upload, the `meta` bookkeeping), the
//! on-demand [`snapshot_now`] (`awm serve backup`) and [`pg_daily_export`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use awm_proto::wire::Id;
use rusqlite::{Connection, OpenFlags, OptionalExtension};

use super::manifest::{Kind, Manifest, Origin};
use super::target::{Bucket, TargetError};
use super::{keys, parse_lineage, BackupError, Clock, FULL_INTERVAL_S};
use crate::store::{Store, StoreError, CANONICAL_TABLES};

// ---------------------------------------------------------------------------------------------
// Temporary files and directories

static N: AtomicU64 = AtomicU64::new(0);

fn unique(tag: &str) -> String {
    format!(
        ".backup-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// A temporary file name in a private directory, removed (with SQLite's side files) on drop.
/// The file itself is created by whoever writes it (the store creates its outputs 0600).
pub(crate) struct TempFile(PathBuf);

impl TempFile {
    pub(crate) fn new(dir: &Path, tag: &str) -> TempFile {
        TempFile(dir.join(format!("{}.db", unique(tag))))
    }

    pub(crate) fn path(&self) -> PathBuf {
        self.0.clone()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        for suffix in ["-journal", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

/// A private (0700) temporary directory, removed with its contents on drop.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(parent: &Path, tag: &str) -> Result<TempDir, BackupError> {
        let dir = parent.join(unique(tag));
        mkdir_private(&dir)?;
        Ok(TempDir(dir))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn io(what: &str, path: &Path, e: impl std::fmt::Display) -> BackupError {
    BackupError::Io(format!("{what} {}: {e}", path.display()))
}

/// Creates `dir` (and missing parents) with mode 0700 when it does not exist.
pub(crate) fn mkdir_private(dir: &Path) -> Result<(), BackupError> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
        .map_err(|e| io("cannot create directory", dir, e))
}

/// Writes `bytes` to a new file (0600) at `path` and syncs it; fails when `path` exists.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| io("cannot create", path, e))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| io("cannot write", path, e))
}

pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, BackupError> + Send + 'static,
) -> Result<T, BackupError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| BackupError::Io(format!("blocking task failed: {e}")))?
}

// ---------------------------------------------------------------------------------------------
// SQLite files

fn open_read_only(path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

/// Rows per table in a SQLite file: the canonical tables and `backup_log`, when present.
pub(crate) fn count_rows(path: &Path) -> Result<BTreeMap<String, u64>, String> {
    let conn = open_read_only(path).map_err(|e| e.to_string())?;
    let mut out = BTreeMap::new();
    let tables = CANONICAL_TABLES
        .iter()
        .map(|(t, _)| *t)
        .chain(std::iter::once("backup_log"));
    for t in tables {
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [t],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if exists {
            let n: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM \"{t}\""), [], |r| r.get(0))
                .map_err(|e| e.to_string())?;
            out.insert(t.to_string(), u64::try_from(n).unwrap_or(0));
        }
    }
    Ok(out)
}

/// `PRAGMA integrity_check` on a file; returns its `backup_log` head (0 when the log was never
/// used or does not exist). The error text is SQLite's (no row values).
pub(crate) fn integrity_check(path: &Path) -> Result<i64, String> {
    let conn = open_read_only(path).map_err(|e| e.to_string())?;
    let rows: Vec<String> = conn
        .prepare("PRAGMA integrity_check")
        .and_then(|mut s| {
            s.query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<_>>()
        })
        .map_err(|e| e.to_string())?;
    if rows != ["ok"] {
        let first = rows.first().map(String::as_str).unwrap_or("no result");
        return Err(format!("integrity_check: {first}"));
    }
    let has_sequence: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE name = 'sqlite_sequence'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !has_sequence {
        return Ok(0);
    }
    conn.query_row(
        "SELECT seq FROM sqlite_sequence WHERE name = 'backup_log'",
        [],
        |r| r.get::<_, i64>(0),
    )
    .optional()
    .map(|v| v.unwrap_or(0))
    .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------------------------
// Uploads

/// An object pair written (or, `reused`, found complete and kept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uploaded {
    pub key: String,
    pub manifest: Manifest,
    pub reused: bool,
}

/// A data object and its manifest, ready to upload, with the temporary file it was read
/// from (kept for a retry, removed on drop).
pub(crate) struct Prepared {
    pub manifest: Manifest,
    pub bytes: Vec<u8>,
    pub file: TempFile,
}

impl Prepared {
    /// Reads the bytes again after a failed attempt consumed them.
    pub(crate) async fn reload(&mut self) -> Result<(), BackupError> {
        let path = self.file.path();
        self.bytes =
            blocking(move || std::fs::read(&path).map_err(|e| io("cannot read", &path, e))).await?;
        if !self.manifest.matches(&self.bytes) {
            return Err(BackupError::Io("temporary file changed".into()));
        }
        Ok(())
    }
}

/// Reads a finished file and builds its manifest.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare(
    file: TempFile,
    kind: Kind,
    generation: Id,
    seq: i64,
    after: Option<i64>,
    to: Option<i64>,
    time: i64,
    origin: Origin,
    writer: Id,
) -> Result<Prepared, BackupError> {
    let path = file.path();
    let (bytes, rows) = blocking(move || {
        let bytes = std::fs::read(&path).map_err(|e| io("cannot read", &path, e))?;
        let rows = count_rows(&path).map_err(|e| io("cannot count rows of", &path, e))?;
        Ok((bytes, rows))
    })
    .await?;
    let manifest = Manifest::new(
        kind, generation, seq, after, to, time, origin, writer, &bytes, rows,
    );
    Ok(Prepared {
        manifest,
        bytes,
        file,
    })
}

/// Why a paired upload stopped.
pub(crate) enum PutError {
    /// The data object's key is taken.
    DataExists,
    /// The data object was written, but the manifest's key is taken.
    ManifestExists,
    /// The data upload failed; nothing was written.
    DataFailed(BackupError),
    /// The data object was written, the manifest upload failed.
    ManifestFailed(BackupError),
}

/// Uploads the data object, then its manifest, both create-only. The bytes are moved into
/// the upload ([`Prepared::reload`] reads them again for a retry).
pub(crate) async fn put_pair(bucket: &dyn Bucket, p: &mut Prepared) -> Result<(), PutError> {
    let manifest = &p.manifest;
    match bucket
        .put_new(manifest.data_key(), std::mem::take(&mut p.bytes))
        .await
    {
        Ok(()) => {}
        Err(TargetError::AlreadyExists { .. }) => return Err(PutError::DataExists),
        Err(e) => return Err(PutError::DataFailed(e.into())),
    }
    match bucket.put_new(manifest.key(), manifest.to_bytes()).await {
        Ok(()) => Ok(()),
        Err(TargetError::AlreadyExists { .. }) => Err(PutError::ManifestExists),
        Err(e) => Err(PutError::ManifestFailed(e.into())),
    }
}

/// A complete pair already stored for `kind` at `seq`: its data object is listed and its
/// manifest is valid. A data object without a manifest (an interrupted upload) is `None`.
pub(crate) async fn existing(
    bucket: &dyn Bucket,
    kind: Kind,
    generation: Id,
    seq: i64,
) -> Result<Option<Manifest>, BackupError> {
    let listing = bucket.list(format!("{}/{generation}", kind.dir())).await?;
    if !listing.objects.contains(&format!("{seq}.db")) {
        return Ok(None);
    }
    super::read_manifest(bucket, kind, generation, seq).await
}

// ---------------------------------------------------------------------------------------------
// `meta` bookkeeping

async fn set(store: &dyn Store, key: &str, value: String) -> Result<(), StoreError> {
    store.meta_set(key.to_string(), value).await
}

/// After a successful upload: the time and key, cleared error state, and for a full snapshot
/// or export its time and key.
pub(crate) async fn mark_ok(
    store: &dyn Store,
    now: i64,
    m: &Manifest,
    full: bool,
) -> Result<(), StoreError> {
    set(store, keys::LAST_OK_AT, now.to_string()).await?;
    set(store, keys::LAST_OBJECT, m.data_key()).await?;
    if full {
        set(store, keys::LAST_FULL_AT, m.time.to_string()).await?;
        set(store, keys::LAST_FULL, m.data_key()).await?;
    }
    for k in [keys::ERROR, keys::ERROR_AT, keys::FAILING_SINCE] {
        set(store, k, String::new()).await?;
    }
    Ok(())
}

/// After a failed step: the error text, its time, and the first failure since the last
/// success (`check` fails after an hour of failures).
pub(crate) async fn record_failure(store: &dyn Store, now: i64, error: &BackupError) {
    let since = store
        .meta_get(keys::FAILING_SINCE.to_string())
        .await
        .ok()
        .flatten()
        .filter(|s| !s.is_empty());
    let _ = set(store, keys::ERROR, error.to_string()).await;
    let _ = set(store, keys::ERROR_AT, now.to_string()).await;
    if since.is_none() {
        let _ = set(store, keys::FAILING_SINCE, now.to_string()).await;
    }
}

/// The generations whose objects this server keeps and expires: its own and those it was
/// restored from.
pub(crate) async fn scope(store: &dyn Store, generation: Id) -> Result<Vec<Id>, StoreError> {
    let mut gens = parse_lineage(store.meta_get(keys::LINEAGE.into()).await?.as_deref());
    gens.push(generation);
    Ok(gens)
}

// ---------------------------------------------------------------------------------------------
// Full snapshots and exports

/// Takes a full snapshot of a `SqliteStore` into a temporary file in `scratch` and builds
/// its manifest; `Unsupported` from a store without `backup_log`.
pub(crate) async fn prepare_full(
    store: &dyn Store,
    generation: Id,
    now: i64,
    origin: Origin,
    writer: Id,
    scratch: &Path,
) -> Result<Prepared, BackupError> {
    let tmp = TempFile::new(scratch, "full");
    let seq = store.snapshot(tmp.path()).await?;
    prepare(
        tmp,
        Kind::Full,
        generation,
        seq,
        None,
        Some(seq),
        now,
        origin,
        writer,
    )
    .await
}

/// Writes a canonical export into a temporary file and builds its manifest (seq = `now`).
pub(crate) async fn prepare_export(
    store: &dyn Store,
    generation: Id,
    now: i64,
    origin: Origin,
    writer: Id,
    scratch: &Path,
) -> Result<Prepared, BackupError> {
    let tmp = TempFile::new(scratch, "export");
    store.export_canonical(tmp.path()).await?;
    prepare(
        tmp,
        Kind::Export,
        generation,
        now,
        None,
        None,
        now,
        origin,
        writer,
    )
    .await
}

/// Uploads a full snapshot or export that may meet its own twin: when the data key is taken
/// and a valid manifest for the same object is stored, the stored pair stands (`reused`);
/// anything else at that key is another server (`Conflict`).
async fn upload_or_reuse(bucket: &dyn Bucket, mut p: Prepared) -> Result<Uploaded, BackupError> {
    let m = p.manifest.clone();
    match put_pair(bucket, &mut p).await {
        Ok(()) => Ok(Uploaded {
            key: m.data_key(),
            manifest: m,
            reused: false,
        }),
        Err(PutError::DataExists) => match existing(bucket, m.kind, m.generation, m.seq).await? {
            Some(found) if found.to == m.to => Ok(Uploaded {
                key: found.data_key(),
                manifest: found,
                reused: true,
            }),
            _ => Err(BackupError::Conflict(format!(
                "{} already exists",
                m.data_key()
            ))),
        },
        Err(PutError::ManifestExists) => {
            Err(BackupError::Conflict(format!("{} already exists", m.key())))
        }
        Err(PutError::DataFailed(e)) | Err(PutError::ManifestFailed(e)) => Err(e),
    }
}

/// `awm serve backup [--to URL]` (§4.8.1): an on-demand full snapshot (`SqliteStore`) or
/// canonical export (`PgStore`) to `bucket`, written under the store's current generation
/// with origin `on-demand`. It neither prunes `backup_log` nor moves the server's cursor, so a
/// running server's chain is untouched, and it writes no `backup_*` state (the configured
/// target's status stays the server's). When the same snapshot is already stored (nothing
/// changed since the server's last full snapshot), that object is returned with `reused`.
pub async fn snapshot_now(
    store: &dyn Store,
    bucket: &dyn Bucket,
    now: i64,
    scratch: &Path,
) -> Result<Uploaded, BackupError> {
    let generation = store.restore_state().await?.generation;
    let writer = Id::new_v4();
    let p = match store.backup_log_head().await {
        Ok(_) => prepare_full(store, generation, now, Origin::OnDemand, writer, scratch).await?,
        Err(StoreError::Unsupported(_)) => {
            prepare_export(store, generation, now, Origin::OnDemand, writer, scratch).await?
        }
        Err(e) => return Err(e.into()),
    };
    upload_or_reuse(bucket, p).await
}

/// The `PgStore` backup with `--backup` (§6.2, §4.8.1): a canonical export to
/// `full/{generation}/{time}.db` with its manifest when the last one is a day old or more (or
/// absent), then retention over the store's generations. Returns `None` when not due. Call it
/// hourly from `awm serve` on a host, or once from the scheduled Cloud Run job. Works with any
/// `Store` (the tests run it over a `SqliteStore` too).
pub async fn pg_daily_export(
    store: &dyn Store,
    bucket: &dyn Bucket,
    clock: &dyn Clock,
    scratch: &Path,
) -> Result<Option<Uploaded>, BackupError> {
    let now = clock.now();
    let last = store
        .meta_get(keys::LAST_FULL_AT.into())
        .await?
        .and_then(|s| s.parse::<i64>().ok());
    if last.is_some_and(|t| (0..FULL_INTERVAL_S).contains(&(now - t))) {
        return Ok(None);
    }
    let result = async {
        let generation = store.restore_state().await?.generation;
        let p =
            prepare_export(store, generation, now, Origin::Daily, Id::new_v4(), scratch).await?;
        let up = upload_or_reuse(bucket, p).await?;
        mark_ok(store, now, &up.manifest, true).await?;
        Ok::<_, BackupError>((generation, up))
    }
    .await;
    let (generation, up) = match result {
        Ok(v) => v,
        Err(e) => {
            record_failure(store, now, &e).await;
            return Err(e);
        }
    };
    let gens = scope(store, generation).await?;
    super::run::retention(bucket, now, &gens).await?;
    Ok(Some(up))
}
