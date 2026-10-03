//! The backup loop of `awm serve` with `SqliteStore` (plan-v3-team §6.2, §5.6, TM27).
//!
//! [`Backup::tick`] runs every [`INCR_INTERVAL_S`] (60 s) from [`Backup::run`]:
//!
//! 1. **Start** (first tick): reads the generation, the `backup_log` head and the lineage,
//!    checks the prefix for another writer (below), then writes the start full snapshot
//!    (origin `restore` right after a restore, else `start`). A restarted server whose head has
//!    not moved finds its own snapshot `full/{generation}/{head}.db` already stored and keeps
//!    it; a data object without a manifest left by an interrupted upload is deleted and
//!    written again.
//! 2. **Full snapshot** when the store's generation changed, a full snapshot was requested
//!    ([`Backup::request_full`], TM15 calls it after a migration), or the last one is a day old.
//!    When nothing was logged since the last one, an audit row `backup.full` moves the head so
//!    that the new snapshot gets a name of its own. After the upload: `backup_cursor` = its
//!    head, `prune_backup_log(head)`, retention.
//! 3. Otherwise an **incremental** change set when `backup_log` grew; none when it did not.
//!    `backup_cursor` moves only after both objects are stored.
//! 4. **Hourly**: the foreign-writer check, retention ([`retention`]) and the removal of
//!    `{db}.bak-v*` and `{db}.pre-restore-*` files older than the oldest kept full snapshot,
//!    or 8 days old at most (TM9's caveat, RVT2 B2; [`super::local`]).
//! 5. **Weekly**: [`super::restore::verify`].
//!
//! Two servers on one prefix (§6.2: "fail loudly instead of interleaving"): uploads are
//! create-only, so two processes over the same database (or a copy of it) compute the same
//! names and the later one fails its upload; at start and every hour the listing is checked
//! for objects this process did not write: in its own generation beyond its start head (an
//! on-demand `awm serve backup` full snapshot excepted), or in a generation outside its
//! lineage written within the last 25 h at start, or since its start later. Any of these
//! stops all uploads and deletions of this process (it never deletes another server's
//! objects), writes `meta.backup_conflict`, and `check` prints `FAIL backup` until a restart.
//!
//! Failures (an unreachable bucket, a full disk) are recorded in `meta` (`backup_error`,
//! `backup_failing_since`) and retried at the next tick from the same cursor.

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use awm_proto::wire::Id;

use super::full::{
    existing, mark_ok, prepare_full, put_pair, record_failure, scope, Prepared, PutError, Uploaded,
};
use super::incr::prepare_incremental;
use super::manifest::{data_key, Kind, Manifest, Origin};
use super::restore::{verify, VerifyReport};
use super::target::Bucket;
use super::{
    keys, list_all, parse_lineage, read_manifest, BackupError, Clock, FOREIGN_RECENT_S,
    FULL_INTERVAL_S, INCR_INTERVAL_S, KEEP_FULL_S, RETENTION_INTERVAL_S, VERIFY_INTERVAL_S,
};
use crate::store::{AuditEntry, Store};

/// The audit action of the row that moves an unchanged head before a full snapshot.
pub const AUDIT_FULL: &str = "backup.full";

/// Where the loop keeps its files and what else it does.
#[derive(Clone)]
pub struct RunOptions {
    /// Temporary snapshots, change sets and verification copies (private; the data
    /// directory for `SqliteStore`, so files never leave its filesystem).
    pub scratch_dir: PathBuf,
    /// The data directory whose `server.db.bak-v*` files retention removes (TM9); `None`
    /// leaves them alone.
    pub data_dir: Option<PathBuf>,
    /// Seconds between self-verifications (`None`: never).
    pub verify_interval_s: Option<i64>,
    /// Called for every upload, retention run, verification and failure (TM15 logs them; the
    /// texts hold keys, counts and times only).
    pub on_event: Option<EventSink>,
}

impl RunOptions {
    /// Temporary files in `scratch_dir`, `.bak-v*` removal there too, weekly verification.
    pub fn new(scratch_dir: impl Into<PathBuf>) -> RunOptions {
        let scratch_dir = scratch_dir.into();
        RunOptions {
            data_dir: Some(scratch_dir.clone()),
            scratch_dir,
            verify_interval_s: Some(VERIFY_INTERVAL_S),
            on_event: None,
        }
    }
}

impl fmt::Debug for RunOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunOptions")
            .field("scratch_dir", &self.scratch_dir)
            .field("data_dir", &self.data_dir)
            .field("verify_interval_s", &self.verify_interval_s)
            .finish()
    }
}

/// A callback for [`Event`]s.
pub type EventSink = Arc<dyn Fn(&Event) + Send + Sync>;

/// What the loop did, for logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Uploaded { key: String, size: u64 },
    Reused { key: String },
    Retention(RetentionReport),
    Verified { ok: bool, detail: String },
    Failed(String),
    Conflict(String),
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Uploaded { key, size } => write!(f, "backup: uploaded {key} ({size} bytes)"),
            Event::Reused { key } => write!(f, "backup: {key} already stored, kept"),
            Event::Retention(r) => write!(
                f,
                "backup retention: {} object(s) and {} .bak-v file(s) removed, {} full snapshot(s) kept",
                r.deleted.len(),
                r.bak_removed.len(),
                r.kept_fulls
            ),
            Event::Verified { ok, detail } => {
                write!(f, "backup verify {}: {detail}", if *ok { "ok" } else { "FAILED" })
            }
            Event::Failed(e) => write!(f, "backup failed: {e}"),
            Event::Conflict(e) => write!(f, "backup stopped: {e}"),
        }
    }
}

/// What one tick did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A full snapshot (or the start snapshot found already stored, `reused`).
    Full(Uploaded),
    Incremental(Uploaded),
    /// `backup_log` did not grow: nothing uploaded.
    Unchanged,
    /// Uploads are stopped (another server writes to the prefix).
    Blocked(String),
}

/// The result of a tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickReport {
    pub step: Step,
    pub retention: Option<RetentionReport>,
    /// A verification that ran in this tick (its error text when it failed).
    pub verify: Option<Result<VerifyReport, String>>,
}

/// Totals of [`Backup::run`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunReport {
    pub ticks: u64,
    pub uploads: u64,
    pub failures: u64,
    pub blocked: Option<String>,
}

struct State {
    started: bool,
    run_start: i64,
    start_head: i64,
    generation: Option<Id>,
    cursor: i64,
    last_full_seq: Option<i64>,
    last_full_time: i64,
    last_hourly: Option<i64>,
    last_verify: Option<i64>,
    lineage: Vec<Id>,
    /// Data keys this process wrote (its own interrupted uploads may be replaced).
    own: BTreeSet<String>,
    blocked: Option<String>,
}

/// The backup runner of one `SqliteStore`.
pub struct Backup {
    store: Arc<dyn Store>,
    bucket: Arc<dyn Bucket>,
    clock: Arc<dyn Clock>,
    opts: RunOptions,
    writer: Id,
    requested: Mutex<Option<Origin>>,
    state: tokio::sync::Mutex<State>,
}

impl fmt::Debug for Backup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Backup")
            .field("bucket", &self.bucket.url())
            .field("writer", &self.writer)
            .finish()
    }
}

/// `tokio::spawn(backup::run::run(store, bucket, clock, shutdown, opts))` in `awm serve`.
pub async fn run<F>(
    store: Arc<dyn Store>,
    bucket: Arc<dyn Bucket>,
    clock: Arc<dyn Clock>,
    shutdown: F,
    opts: RunOptions,
) -> RunReport
where
    F: Future<Output = ()> + Send,
{
    Backup::new(store, bucket, clock, opts).run(shutdown).await
}

impl Backup {
    pub fn new(
        store: Arc<dyn Store>,
        bucket: Arc<dyn Bucket>,
        clock: Arc<dyn Clock>,
        opts: RunOptions,
    ) -> Arc<Backup> {
        Arc::new(Backup {
            store,
            bucket,
            clock,
            opts,
            writer: Id::new_v4(),
            requested: Mutex::new(None),
            state: tokio::sync::Mutex::new(State {
                started: false,
                run_start: 0,
                start_head: 0,
                generation: None,
                cursor: 0,
                last_full_seq: None,
                last_full_time: 0,
                last_hourly: None,
                last_verify: None,
                lineage: Vec::new(),
                own: BTreeSet::new(),
                blocked: None,
            }),
        })
    }

    /// Asks for a full snapshot at the next tick (TM15: after a migration, with
    /// [`Origin::Migration`]).
    pub fn request_full(&self, origin: Origin) {
        *self.requested.lock().unwrap_or_else(|e| e.into_inner()) = Some(origin);
    }

    fn emit(&self, e: Event) {
        if let Some(sink) = &self.opts.on_event {
            sink(&e);
        }
    }

    /// Runs a tick now, then one every [`INCR_INTERVAL_S`] until `shutdown` completes, then a
    /// last tick so that what changed since is shipped before the process exits.
    pub async fn run<F>(self: Arc<Self>, shutdown: F) -> RunReport
    where
        F: Future<Output = ()> + Send,
    {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut report = RunReport::default();
        loop {
            self.tick_into(&mut report).await;
            tokio::select! {
                biased;
                _ = &mut shutdown => break,
                _ = self.clock.sleep(INCR_INTERVAL_S as u64) => {}
            }
        }
        self.tick_into(&mut report).await;
        report
    }

    async fn tick_into(&self, report: &mut RunReport) {
        report.ticks += 1;
        match self.tick().await {
            Ok(r) => match r.step {
                Step::Full(u) | Step::Incremental(u) if !u.reused => report.uploads += 1,
                Step::Blocked(b) => report.blocked = Some(b),
                _ => {}
            },
            Err(BackupError::Conflict(c)) => report.blocked = Some(c),
            Err(_) => report.failures += 1,
        }
    }

    /// One step of the cadence (module docs). A failure is recorded in `meta` and returned;
    /// the next tick retries.
    pub async fn tick(&self) -> Result<TickReport, BackupError> {
        let mut st = self.state.lock().await;
        if let Some(b) = &st.blocked {
            return Ok(TickReport {
                step: Step::Blocked(b.clone()),
                retention: None,
                verify: None,
            });
        }
        let now = self.clock.now();
        let result = self.step(&mut st, now).await;
        if let Err(e) = &result {
            match e {
                BackupError::Conflict(c) => {
                    st.blocked = Some(c.clone());
                    let _ = self
                        .store
                        .meta_set(keys::CONFLICT.into(), format!("{c} (at {now})"))
                        .await;
                    self.emit(Event::Conflict(c.clone()));
                }
                e => {
                    record_failure(&*self.store, now, e).await;
                    self.emit(Event::Failed(e.to_string()));
                }
            }
        }
        result
    }

    async fn step(&self, st: &mut State, now: i64) -> Result<TickReport, BackupError> {
        let mut report = TickReport {
            step: Step::Unchanged,
            retention: None,
            verify: None,
        };
        let mut full = false;
        let starting = !st.started;
        if starting {
            report.step = Step::Full(self.start(st, now).await?);
            full = true;
        } else {
            let generation = self.store.restore_state().await?.generation;
            let requested = self
                .requested
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            let origin = if st.generation != Some(generation) {
                // The previous generation's objects are this database's history, not another
                // server's: keep them in the lineage (foreign check, retention scope).
                if let Some(old) = st.generation.filter(|g| !st.lineage.contains(g)) {
                    let mut stored =
                        parse_lineage(self.store.meta_get(keys::LINEAGE.into()).await?.as_deref());
                    if !stored.contains(&old) {
                        stored.push(old);
                    }
                    let joined: Vec<String> = stored.iter().map(Id::to_string).collect();
                    self.store
                        .meta_set(keys::LINEAGE.into(), joined.join(","))
                        .await?;
                    st.lineage.push(old);
                }
                Some(Origin::Generation)
            } else if requested.is_some() {
                requested
            } else if now - st.last_full_time >= FULL_INTERVAL_S {
                Some(Origin::Daily)
            } else {
                None
            };
            report.step = match origin {
                Some(origin) => match self.full(st, now, origin).await {
                    Ok(u) => {
                        full = true;
                        Step::Full(u)
                    }
                    Err(e) => {
                        if let Some(r) = requested {
                            self.request_full(r);
                        }
                        return Err(e);
                    }
                },
                None => self.incremental(st, now).await?,
            };
        }
        let hourly = st
            .last_hourly
            .is_none_or(|t| !(0..RETENTION_INTERVAL_S).contains(&(now - t)));
        if full || hourly {
            // The start ran its own check before its first upload.
            if hourly && !starting {
                self.foreign_check(st, now, false).await?;
            }
            let r = self.retention(st, now).await?;
            self.emit(Event::Retention(r.clone()));
            report.retention = Some(r);
            st.last_hourly = Some(now);
        }
        if let Some(interval) = self.opts.verify_interval_s {
            if st
                .last_verify
                .is_none_or(|t| !(0..interval).contains(&(now - t)))
            {
                st.last_verify = Some(now);
                let v = verify(&*self.store, &*self.bucket, now, &self.opts.scratch_dir).await;
                let (ok, detail) = match &v {
                    Ok(r) => (true, r.summary()),
                    Err(e) => (false, e.to_string()),
                };
                self.emit(Event::Verified { ok, detail });
                report.verify = Some(v.map_err(|e| e.to_string()));
            }
        }
        Ok(report)
    }

    async fn start(&self, st: &mut State, now: i64) -> Result<Uploaded, BackupError> {
        let state = self.store.restore_state().await?;
        let generation = state.generation;
        let head = self.store.backup_log_head().await?;
        st.lineage = parse_lineage(self.store.meta_get(keys::LINEAGE.into()).await?.as_deref());
        st.last_verify = self
            .store
            .meta_get(keys::VERIFY_AT.into())
            .await?
            .and_then(|s| s.parse().ok());
        st.generation = Some(generation);
        st.start_head = head;
        st.run_start = now;
        self.foreign_check(st, now, true).await?;
        let up = match existing(&*self.bucket, Kind::Full, generation, head).await? {
            Some(m) if m.kind == Kind::Full && m.to == Some(head) => {
                // A restarted server whose head did not move: its snapshot stands.
                st.cursor = head;
                st.last_full_seq = Some(head);
                st.last_full_time = m.time;
                self.store
                    .meta_set(keys::CURSOR.into(), head.to_string())
                    .await?;
                mark_ok(&*self.store, now, &m, true).await?;
                self.store.prune_backup_log(head).await?;
                self.emit(Event::Reused { key: m.data_key() });
                Uploaded {
                    key: m.data_key(),
                    manifest: m,
                    reused: true,
                }
            }
            _ => {
                // A data object without a manifest at this name is an upload of an earlier
                // process cut short: remove it so the snapshot can be written again.
                let name = format!("{head}.db");
                let dir = format!("{}/{generation}", Kind::Full.dir());
                if self.bucket.list(dir).await?.objects.contains(&name)
                    && read_manifest(&*self.bucket, Kind::Full, generation, head)
                        .await?
                        .is_none()
                {
                    self.bucket
                        .delete(data_key(Kind::Full, generation, head))
                        .await?;
                }
                let origin = if state.restore_pending {
                    Origin::Restore
                } else {
                    Origin::Start
                };
                self.full(st, now, origin).await?
            }
        };
        st.started = true;
        Ok(up)
    }

    async fn full(
        &self,
        st: &mut State,
        now: i64,
        origin: Origin,
    ) -> Result<Uploaded, BackupError> {
        let generation = self.store.restore_state().await?.generation;
        let head = self.store.backup_log_head().await?;
        if st.generation == Some(generation) && st.last_full_seq == Some(head) {
            // Nothing logged since the last full snapshot: move the head so the new snapshot
            // gets its own name (create-only uploads never overwrite).
            self.store
                .append_audit(AuditEntry {
                    at: now,
                    actor: None,
                    action: AUDIT_FULL.into(),
                    target: None,
                    detail: Some(format!("seq={head}")),
                })
                .await?;
        }
        let p = prepare_full(
            &*self.store,
            generation,
            now,
            origin,
            self.writer,
            &self.opts.scratch_dir,
        )
        .await?;
        let m = p.manifest.clone();
        self.put(st, p).await?;
        let seq = m.seq;
        st.generation = Some(generation);
        st.cursor = seq;
        st.last_full_seq = Some(seq);
        st.last_full_time = now;
        self.store
            .meta_set(keys::CURSOR.into(), seq.to_string())
            .await?;
        mark_ok(&*self.store, now, &m, true).await?;
        // The snapshot holds every change up to its head: the log before it is not needed.
        self.store.prune_backup_log(seq).await?;
        self.emit(Event::Uploaded {
            key: m.data_key(),
            size: m.size,
        });
        Ok(Uploaded {
            key: m.data_key(),
            manifest: m,
            reused: false,
        })
    }

    async fn incremental(&self, st: &mut State, now: i64) -> Result<Step, BackupError> {
        let generation = st
            .generation
            .ok_or_else(|| BackupError::Io("no generation".into()))?;
        // The head is one cheap read; a change set is a throwaway database file.
        if self.store.backup_log_head().await? <= st.cursor {
            return Ok(Step::Unchanged);
        }
        let Some(p) = prepare_incremental(
            &*self.store,
            generation,
            st.cursor,
            now,
            self.writer,
            &self.opts.scratch_dir,
        )
        .await?
        else {
            return Ok(Step::Unchanged);
        };
        let m = p.manifest.clone();
        self.put(st, p).await?;
        let to = m.to.unwrap_or(m.seq);
        st.cursor = to;
        self.store
            .meta_set(keys::CURSOR.into(), to.to_string())
            .await?;
        mark_ok(&*self.store, now, &m, false).await?;
        self.emit(Event::Uploaded {
            key: m.data_key(),
            size: m.size,
        });
        Ok(Step::Incremental(Uploaded {
            key: m.data_key(),
            manifest: m,
            reused: false,
        }))
    }

    /// The paired upload; a data object this process left without a manifest (an upload cut
    /// short) is replaced once; any other object at the key is another server.
    async fn put(&self, st: &mut State, mut p: Prepared) -> Result<(), BackupError> {
        let data = p.manifest.data_key();
        let mut retried = false;
        loop {
            match put_pair(&*self.bucket, &mut p).await {
                Ok(()) => {
                    st.own.insert(data);
                    return Ok(());
                }
                Err(PutError::DataExists) if !retried && st.own.contains(&data) => {
                    let m = &p.manifest;
                    if read_manifest(&*self.bucket, m.kind, m.generation, m.seq)
                        .await?
                        .is_some()
                    {
                        return Err(BackupError::Conflict(format!("{} already exists", m.key())));
                    }
                    self.bucket.delete(data.clone()).await?;
                    p.reload().await?;
                    retried = true;
                }
                Err(PutError::DataExists) => {
                    return Err(BackupError::Conflict(format!(
                        "{data} already exists (written by another process)"
                    )))
                }
                Err(PutError::ManifestExists) => {
                    st.own.insert(data);
                    return Err(BackupError::Conflict(format!(
                        "{} already exists (written by another process)",
                        p.manifest.key()
                    )));
                }
                Err(PutError::DataFailed(e)) => return Err(e),
                Err(PutError::ManifestFailed(e)) => {
                    st.own.insert(data);
                    return Err(e);
                }
            }
        }
    }

    /// Looks for objects another server wrote (module docs).
    async fn foreign_check(&self, st: &State, now: i64, at_start: bool) -> Result<(), BackupError> {
        let Some(generation) = st.generation else {
            return Ok(());
        };
        let listing = list_all(&*self.bucket).await?;
        for (g, objs) in &listing {
            if *g == generation {
                for seq in objs.incr_data.iter().chain(&objs.incr_json) {
                    let key = data_key(Kind::Incr, *g, *seq);
                    if *seq > st.start_head && !st.own.contains(&key) {
                        return Err(BackupError::Conflict(format!(
                            "{key} was not written by this server"
                        )));
                    }
                }
                for seq in objs.full_json.range(st.start_head + 1..) {
                    let key = data_key(Kind::Full, *g, *seq);
                    if st.own.contains(&key) {
                        continue;
                    }
                    match read_manifest(&*self.bucket, Kind::Full, *g, *seq).await {
                        Ok(Some(m)) if m.origin == Origin::OnDemand => {}
                        _ => {
                            return Err(BackupError::Conflict(format!(
                                "{key} was not written by this server"
                            )))
                        }
                    }
                }
            } else if !st.lineage.contains(g) {
                let mut newest: Option<(i64, String)> = None;
                for (kind, set) in [(Kind::Full, &objs.full_json), (Kind::Incr, &objs.incr_json)] {
                    if let Some(seq) = set.last() {
                        if let Ok(Some(m)) = read_manifest(&*self.bucket, kind, *g, *seq).await {
                            if newest.as_ref().is_none_or(|(t, _)| m.time > *t) {
                                newest = Some((m.time, m.data_key()));
                            }
                        }
                    }
                }
                let since = if at_start {
                    now - FOREIGN_RECENT_S
                } else {
                    st.run_start
                };
                if let Some((t, key)) = newest {
                    if t >= since {
                        return Err(BackupError::Conflict(format!(
                            "generation {g} (not this database's {generation}) wrote {key} at {t}"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    async fn retention(&self, st: &State, now: i64) -> Result<RetentionReport, BackupError> {
        let generation = st
            .generation
            .ok_or_else(|| BackupError::Io("no generation".into()))?;
        let gens = scope(&*self.store, generation).await?;
        let mut r = retention(&*self.bucket, now, &gens).await?;
        if let Some(t) = r.oldest_kept {
            self.store
                .meta_set(keys::OLDEST_KEPT.into(), t.to_string())
                .await?;
        }
        if let Some(dir) = &self.opts.data_dir {
            let before = super::local::cutoff(now, r.oldest_kept);
            r.bak_removed = super::local::remove_before(dir, before)?;
        }
        Ok(r)
    }
}

// ---------------------------------------------------------------------------------------------
// Retention

/// What a retention run kept and removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionReport {
    /// Full snapshots (or exports) kept.
    pub kept_fulls: usize,
    /// The time of the oldest kept full snapshot: everything older is gone.
    pub oldest_kept: Option<i64>,
    /// Keys removed, in deletion order (each manifest before its data object).
    pub deleted: Vec<String>,
    /// `{db}.bak-v*` files removed.
    pub bak_removed: Vec<PathBuf>,
}

/// Retention over the generations in `scope` (§6.2, §5.6): keeps every complete full snapshot
/// (or export) written within [`KEEP_FULL_S`] of `now` (at least the newest one), and every
/// change set newer than the oldest kept one; deletes the other objects of those generations,
/// each manifest before its data object, so an interrupted run leaves only data objects
/// without manifests, which restore ignores and the next run removes. Objects of other
/// generations and names that are not backup objects are never touched. Deletes nothing when a
/// listing or a manifest cannot be read.
pub async fn retention(
    bucket: &dyn Bucket,
    now: i64,
    scope: &[Id],
) -> Result<RetentionReport, BackupError> {
    let listing = list_all(bucket).await?;
    let mut fulls: Vec<Manifest> = Vec::new();
    for g in scope {
        let Some(objs) = listing.get(g) else {
            continue;
        };
        for seq in &objs.full_json {
            if !objs.full_data.contains(seq) {
                continue;
            }
            if let Some(m) = read_manifest(bucket, Kind::Full, *g, *seq).await? {
                fulls.push(m);
            }
        }
    }
    let Some(newest) = fulls.iter().max_by_key(|m| (m.time, m.seq)) else {
        return Ok(RetentionReport::default());
    };
    let mut kept: Vec<&Manifest> = fulls
        .iter()
        .filter(|m| m.time >= now - KEEP_FULL_S)
        .collect();
    if kept.is_empty() {
        kept.push(newest);
    }
    let oldest_kept = kept.iter().map(|m| m.time).min();
    let mut doomed: Vec<String> = Vec::new();
    for g in scope {
        let Some(objs) = listing.get(g) else {
            continue;
        };
        let s_keep = kept
            .iter()
            .filter(|m| m.generation == *g)
            .map(|m| m.seq)
            .min();
        match s_keep {
            None => {
                // No kept snapshot in this generation: the generations of a lineage follow one
                // another, so all of it is older than the oldest kept snapshot.
                if fulls
                    .iter()
                    .filter(|m| m.generation == *g)
                    .all(|m| Some(m.time) < oldest_kept)
                {
                    doomed.extend(objs.keys(*g));
                }
            }
            Some(s_keep) => {
                let old = super::GenObjects {
                    full_json: objs.full_json.range(..s_keep).copied().collect(),
                    full_data: objs.full_data.range(..s_keep).copied().collect(),
                    incr_json: objs.incr_json.range(..=s_keep).copied().collect(),
                    incr_data: objs.incr_data.range(..=s_keep).copied().collect(),
                };
                doomed.extend(old.keys(*g));
            }
        }
    }
    for key in &doomed {
        bucket.delete(key.clone()).await?;
    }
    Ok(RetentionReport {
        kept_fulls: kept.len(),
        oldest_kept,
        deleted: doomed,
        bak_removed: Vec::new(),
    })
}

/// Removes `{dir}/server.db.bak-v*` (migration backups, TM9) and `server.db.pre-restore-*`
/// files (RVT2 B2) made before `before` (Unix seconds): they hold every blob of their moment,
/// deleted ones included, so they follow the backups' window (§5.6). [`super::local`] has the
/// rule; this name stays for its callers.
pub fn remove_bak_files(dir: &Path, before: i64) -> Result<Vec<PathBuf>, BackupError> {
    super::local::remove_before(dir, before)
}
