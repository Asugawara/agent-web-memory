//! Server retention (plan-v3-team §3.7, §5.6, §6.1; `docs/sync-v1.md` §8.5, §10.4).
//!
//! A run deletes the blobs of records whose `received_at` is older than the organisation's
//! effective `retention_days` (from `Store::org(now)`, so a pending decrease applies only once
//! its 7 days are over), oldest first, in batches of at most [`BATCH_ROWS`], each record with
//! one deletion-stream entry (`Store::retention_batch`). Retention runs from receipt: a
//! re-seeded record starts again when it is received (`docs/sync-v1.md` §10.4). `roster`
//! records are never deleted (crypto §7; the store skips them, TM9 F1). Then it prunes
//! deletion-stream entries older than retention + 30 days and audit rows older than 400 days
//! (both keep their newest row, so heads never move back), checkpoints (`SqliteStore`: the
//! deleted bytes leave the file and the WAL), appends one `retention` audit row with the
//! counts and writes `meta.last_retention`.
//!
//! Runs are at most one per hour per organisation, keyed on `last_retention`; a second run
//! within the hour is a no-op. Two schedules:
//! - [`hourly`]: a tokio task for a host (`awm serve`): runs at start if the last run is an
//!   hour old, then every hour, until shutdown;
//! - [`request_time`]: for Cloud Run, where CPU is not allocated between requests (§6.1): TM8
//!   calls it from a request hook; it deletes at most [`BATCH_ROWS`] rows per call and runs at
//!   most once an hour.
//!
//! Both take the time from the caller ([`Clock`] for `hourly`), so tests control it.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use awm_proto::wire::Id;

use crate::delete::Claim;
use crate::store::{meta_keys, AuditEntry, Store, StoreError, StoreResult};

/// Records deleted per `retention_batch` call, and at most per [`request_time`] call (§6.1).
pub const BATCH_ROWS: u32 = 1_000;
/// At most one run per this many seconds (§3.7, §6.1).
pub const INTERVAL_S: i64 = 3_600;
/// Deletion-stream entries are kept for `retention_days` + this many days (§3.7).
pub const DELETION_EXTRA_DAYS: i64 = 30;
/// Audit rows are kept this many days (§5.5).
pub const AUDIT_DAYS: i64 = 400;
/// After a failed run, [`hourly`] tries again after this many seconds.
pub const RETRY_AFTER_ERROR_S: u64 = 300;
/// The audit action of a run.
pub const AUDIT_ACTION: &str = "retention";

const DAY_S: i64 = 86_400;

/// What one run did (also written, as counts, to its audit row).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionRun {
    /// The effective `retention_days` the run applied.
    pub retention_days: u32,
    /// Records whose blob was deleted (each with one deletion-stream entry).
    pub deleted: u64,
    /// `retention_batch` calls.
    pub batches: u32,
    /// `false` when a bounded run ([`request_time`]) stopped with a full batch, so older
    /// records may remain for the next run.
    pub complete: bool,
    pub pruned_deletions: u64,
    pub pruned_audit: u64,
}

/// Whether a run is due at `now` after the last one at `last` (none yet, or an hour ago; a
/// `last` in the future, after the clock went back, counts as due).
pub fn due(last: Option<i64>, now: i64) -> bool {
    match last {
        Some(last) => !(0..INTERVAL_S).contains(&(now - last)),
        None => true,
    }
}

/// `meta.last_retention` (Unix seconds); `None` before the first run or when unreadable.
pub async fn last_retention(store: &dyn Store) -> StoreResult<Option<i64>> {
    Ok(store
        .meta_get(meta_keys::LAST_RETENTION.into())
        .await?
        .and_then(|v| v.parse().ok()))
}

/// A full run when due (batches until one returns fewer than [`BATCH_ROWS`]); `None` when not
/// due, when the store holds no organisation yet, or while another run of the organisation
/// is in progress in this process.
pub async fn run(store: &dyn Store, now: i64) -> StoreResult<Option<RetentionRun>> {
    pass(store, now, None).await
}

/// The request-time schedule (Cloud Run, §6.1): one batch of at most [`BATCH_ROWS`] rows when
/// a run is due, at most once an hour (keyed on `last_retention`). Returns the number of
/// records deleted, or `None` when nothing ran (not due, no organisation, a run in progress,
/// or a store error: a request never fails because of retention, and the next due request
/// tries again).
pub async fn request_time(store: &dyn Store, now: i64) -> Option<usize> {
    match pass(store, now, Some(1)).await {
        Ok(Some(r)) => usize::try_from(r.deleted).ok(),
        _ => None,
    }
}

/// The TM1 stub's signature, still TM8's default `RetentionRunner` (`AppState::new`). It has
/// no store to act on and deletes nothing (an error TM8 logs, never a panic): TM8 wires
/// [`runner`] instead, `AppState::with_retention_runner(Arc::new(retention::runner(store)))`.
pub fn sweep(_retention_days: u32) -> Result<u64, crate::store::StoreError> {
    Err(StoreError::Unsupported(
        "retention::sweep has no store; wire retention::runner(store)",
    ))
}

/// TM8's synchronous `RetentionRunner` (`Fn(u32) -> Result<u64, StoreError>`, called on
/// `spawn_blocking` from `AppState::retention_tick` and `POST /internal/retention`): the
/// request-time schedule over `store` with the system clock. Each call is one bounded batch of
/// at most [`BATCH_ROWS`] rows with everything a run does (prunes, checkpoint, audit row,
/// `last_retention`), at most once an hour (a call within the hour returns `Ok(0)` and writes
/// nothing). The `u32` argument (TM8 passes the stored `retention_days`) is not used: the run
/// reads the effective value from `Store::org(now)` itself, so a pending decrease applies only
/// when due. Must run on a thread of a tokio runtime's blocking pool (it blocks on the store's
/// futures); outside a runtime it returns `Backend`.
pub fn runner(store: Arc<dyn Store>) -> impl Fn(u32) -> Result<u64, StoreError> + Send + Sync {
    runner_with_clock(store, Arc::new(SystemClock))
}

/// [`runner`] with an injected clock (tests).
pub fn runner_with_clock(
    store: Arc<dyn Store>,
    clock: Arc<dyn Clock>,
) -> impl Fn(u32) -> Result<u64, StoreError> + Send + Sync {
    move |_retention_days| {
        let rt = tokio::runtime::Handle::try_current().map_err(|_| {
            StoreError::Backend("retention runner called outside a tokio runtime".into())
        })?;
        let now = clock.now();
        let run = rt.block_on(pass(&*store, now, Some(1)))?;
        Ok(run.map_or(0, |r| r.deleted))
    }
}

/// Organisations with a run in progress in this process.
static RUNNING: Mutex<BTreeSet<Id>> = Mutex::new(BTreeSet::new());

async fn pass(
    store: &dyn Store,
    now: i64,
    max_batches: Option<u32>,
) -> StoreResult<Option<RetentionRun>> {
    let Some(org) = store.org(now).await? else {
        return Ok(None);
    };
    let Some(_claim) = Claim::take(&RUNNING, org.org_id) else {
        return Ok(None);
    };
    if !due(last_retention(store).await?, now) {
        return Ok(None);
    }
    let days = org.settings.retention_days;
    let cutoff = now - i64::from(days) * DAY_S;
    let (mut deleted, mut batches, mut complete) = (0u64, 0u32, false);
    while max_batches.is_none_or(|m| batches < m) {
        let n = store.retention_batch(cutoff, BATCH_ROWS, now).await?;
        deleted += n;
        batches += 1;
        if n < u64::from(BATCH_ROWS) {
            complete = true;
            break;
        }
    }
    let pruned_deletions = store
        .prune_deletions(now - (i64::from(days) + DELETION_EXTRA_DAYS) * DAY_S)
        .await?;
    let pruned_audit = store.prune_audit(now - AUDIT_DAYS * DAY_S).await?;
    store.checkpoint().await?;
    store
        .append_audit(AuditEntry {
            at: now,
            actor: None,
            action: AUDIT_ACTION.into(),
            target: None,
            detail: Some(format!(
                "deleted={deleted} batches={batches} complete={complete} \
                 pruned_deletions={pruned_deletions} pruned_audit={pruned_audit} \
                 retention_days={days}"
            )),
        })
        .await?;
    store
        .meta_set(meta_keys::LAST_RETENTION.into(), now.to_string())
        .await?;
    Ok(Some(RetentionRun {
        retention_days: days,
        deleted,
        batches,
        complete,
        pruned_deletions,
        pruned_audit,
    }))
}

// ---------------------------------------------------------------------------------------------
// The hourly task

/// Time for [`hourly`]: the current Unix time and a sleep. Tests pass a clock whose sleep
/// advances its own time.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> i64;
    fn sleep(&self, secs: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// The system clock and `tokio::time::sleep`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }

    fn sleep(&self, secs: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(Duration::from_secs(secs)))
    }
}

/// What [`hourly`] did until shutdown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HourlyReport {
    /// Runs that did their work (not the no-op checks).
    pub runs: u32,
    /// Runs that failed with a store error (retried after [`RETRY_AFTER_ERROR_S`]).
    pub failures: u32,
    /// Records deleted over all runs.
    pub deleted: u64,
}

/// The host schedule (`awm serve`, `tokio::spawn(retention::hourly(store, clock, shutdown))`):
/// runs at once when `last_retention` is at least an hour old (or absent), then sleeps until
/// the next run is due, every hour; a failed run is retried after [`RETRY_AFTER_ERROR_S`].
/// Returns when `shutdown` completes (checked before every sleep and during it; a run in
/// progress finishes first).
pub async fn hourly<F>(store: Arc<dyn Store>, clock: Arc<dyn Clock>, shutdown: F) -> HourlyReport
where
    F: Future<Output = ()> + Send,
{
    let mut shutdown = std::pin::pin!(shutdown);
    let mut report = HourlyReport::default();
    loop {
        let now = clock.now();
        let wait = match run(&*store, now).await {
            Ok(Some(r)) => {
                report.runs += 1;
                report.deleted += r.deleted;
                INTERVAL_S as u64
            }
            Ok(None) => match last_retention(&*store).await {
                Ok(Some(last)) if !due(Some(last), now) => (last + INTERVAL_S - now) as u64,
                // No organisation yet (or a run of it in progress elsewhere in the process).
                Ok(_) => INTERVAL_S as u64,
                Err(_) => RETRY_AFTER_ERROR_S,
            },
            Err(_) => {
                report.failures += 1;
                RETRY_AFTER_ERROR_S
            }
        };
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = clock.sleep(wait) => {}
        }
    }
    report
}
