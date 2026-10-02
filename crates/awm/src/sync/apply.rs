//! Deletion bookkeeping shared by the commands that delete and by `awm sync` (plan-v3-team §3.6,
//! §3.7, §3.9.5; `docs/sync-v1.md` §8.5, §9.3, §10, §11; TM11).
//!
//! `pull.rs` keeps the incoming path (the `GET /v1/deletions` pages, the deletion-head cursor
//! and the full reconcile), because it needs the engine session and its HTTP client. This module
//! holds the rules both directions share, on a plain connection, so that `awm forget`, `awm
//! purge` and `awm quarantine` can queue deletions in a build without the `sync` feature too:
//!
//! - [`own_deletion`], the outgoing side for one record id of this member: the `sync_own` item
//!   becomes a marker, `tombstone('tool_use_id', 'team:' || id)` is written, and an outbox
//!   `delete` row is queued (sent by `push::deletions`, or at once by the command);
//! - [`deletions`], the incoming rules for one transaction of at most [`CHUNK_ROWS`] entries;
//! - [`drop_team_rows`], retention and the full reconcile in transactions of [`CHUNK_ROWS`] rows;
//! - [`after_deletions`], backups taken at schema 3 or higher, and FTS `optimize` with
//!   `wal_checkpoint(TRUNCATE)` at most once a day;
//! - [`resend_ids`], the `team:` tombstones a re-seed sends again after a restore.
//!
//! Every `DELETE FROM event` here goes through the FTS delete trigger (`event_fts_ad`) and keeps
//! the receiver's `injection`, `injection_item` (its `event_id` becomes NULL, its `origin` stays)
//! and `outcome` rows (migration 0003).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, TransactionBehavior};

use crate::paths;
use crate::sync::state;

/// Rows per transaction for remote deletions, retention and the full reconcile (§3.6).
pub const CHUNK_ROWS: usize = 25;
/// The lock file `awm sync` holds (the engine's `LOCK_FILE`, which exists only with `sync`).
pub const SYNC_LOCK: &str = "sync.lock";
/// How long the commands that delete wait for `sync.lock` before they refuse (§3.6).
pub const LOCK_WAIT: Duration = Duration::from_secs(10);
/// `sync_state` key: rows were deleted since the last FTS `optimize` and checkpoint.
pub const SCRUB_PENDING: &str = "scrub_pending";
/// `sync_state` key: when `awm sync` last ran FTS `optimize` and `wal_checkpoint(TRUNCATE)`.
pub const LAST_SCRUB: &str = "last_scrub";
/// `sync_state` key prefix: a record of this member that is not in this device's `sync_own`
/// (one of the member's other machines wrote it) and that this device deleted remotely. A
/// re-seed sends these again, as it sends the ids of `sync_own` (value: unix ms).
pub const OWN_DELETED: &str = "own_deleted.";
/// `sync_state` key prefix: a teammate's record deleted on this machine only (`forget`,
/// `purge`); its `team:` tombstone keeps it out of later pulls, and a re-seed never sends it,
/// not even from an admin's device (value: unix ms).
pub const LOCAL_ONLY: &str = "local_only.";

const DAY_MS: i64 = 86_400_000;

fn tombstone(tx: &Connection, id: &str, now_ms: i64) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO tombstone (kind, value, created_at) VALUES ('tool_use_id', ?1, ?2)",
        params![format!("team:{id}"), now_ms],
    )?;
    Ok(())
}

/// The outgoing side of one record id of this member, in the caller's transaction: the
/// `sync_own` item becomes a marker (a re-seed pushes a marker, never the blob), the `team:`
/// tombstone is written, and with `queue` an outbox `delete` row is added unless one is queued
/// already. An id that is not in `sync_own` (a record of the member's other machine) is noted
/// under [`OWN_DELETED`], so a re-seed sends it again (§3.9.5). Pushed or not: an id that the
/// server never stored is pre-deleted (`docs/sync-v1.md` §10.3), so a batch still in flight
/// gets 410.
pub fn own_deletion(tx: &Connection, id: &str, now_ms: i64, queue: bool) -> Result<()> {
    let own = tx.execute(
        "UPDATE sync_own SET deleted = 1, blob = NULL, epoch = NULL WHERE record_id = ?1",
        [id],
    )?;
    if own == 0 {
        state::set(tx, &format!("{OWN_DELETED}{id}"), &now_ms.to_string())?;
    }
    tombstone(tx, id, now_ms)?;
    if queue {
        tx.execute(
            "INSERT INTO sync_outbox (kind, ref, created_at) SELECT 'delete', ?1, ?2 \
             WHERE NOT EXISTS (SELECT 1 FROM sync_outbox WHERE kind = 'delete' AND ref = ?1)",
            params![id, now_ms],
        )?;
    }
    Ok(())
}

/// A teammate's record deleted on this machine only: its id is noted under [`LOCAL_ONLY`] so
/// that a re-seed after a restore does not delete the teammate's server copy (the `team:`
/// tombstone itself is written by the caller, as `forget` writes every `tool_use_id`).
pub fn local_only(tx: &Connection, id: &str, now_ms: i64) -> Result<()> {
    state::set(tx, &format!("{LOCAL_ONLY}{id}"), &now_ms.to_string())
}

/// What one transaction of deletion entries did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// Teammates' rows, and rows of the member's other machines, deleted.
    pub team_rows: usize,
    /// This device's own captures named by an entry: kept, never shared again.
    pub own_kept: usize,
}

/// Applies deletion-stream entries (record ids) in the caller's transaction, which holds at
/// most [`CHUNK_ROWS`] of them (§3.6; `docs/sync-v1.md` §8.5):
///
/// - the `team:` tombstone is written for every entry, whether or not a row exists, so a later
///   pull (a record behind a gap, a full re-pull, a lying server) cannot store it;
/// - a team row with that `sync_id` is deleted (its text leaves the FTS index through the
///   trigger; the receiver's `injection`, `injection_item` and `outcome` rows stay);
/// - an own `origin = 'local'` row is kept, with `shareable = 'never'`, and its `sync_own` item
///   becomes a marker, so neither a push nor a re-seed sends it again (`docs/sync-v1.md` §5.2
///   row "deletion entries naming the member's own records": the local copy is the user's
///   history, and a deletion made by one of the member's other devices or by an admin removes
///   the shared copy only).
pub fn deletions(tx: &Connection, ids: &[String], now_ms: i64) -> Result<Applied> {
    let mut a = Applied::default();
    for id in ids {
        tombstone(tx, id, now_ms)?;
        tx.execute(
            "UPDATE sync_own SET deleted = 1, blob = NULL, epoch = NULL WHERE record_id = ?1",
            [id],
        )?;
        let own = tx.execute(
            "UPDATE event SET shareable = 'never' WHERE sync_id = ?1 AND origin = 'local'",
            [id],
        )?;
        if own > 0 {
            a.own_kept += 1;
        } else {
            a.team_rows += tx.execute(
                "DELETE FROM event WHERE sync_id = ?1 AND origin = 'team'",
                [id],
            )?;
        }
    }
    Ok(a)
}

/// Deletes team rows (`origin = 'team'`) created before `before_ms` (all of them with `None`)
/// in transactions of at most [`CHUNK_ROWS`] rows with a pause between them, so hooks find the
/// write lock free (retention, §3.7; the full reconcile, §3.6). The row count of every
/// transaction is appended to `sizes`. Returns the number of rows deleted.
pub fn drop_team_rows(
    conn: &mut Connection,
    before_ms: Option<i64>,
    sizes: &mut Vec<usize>,
) -> Result<usize> {
    let before = before_ms.unwrap_or(i64::MAX);
    let mut total = 0;
    loop {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n = tx.execute(
            "DELETE FROM event WHERE id IN \
               (SELECT id FROM event WHERE origin = 'team' AND created_at < ?1 LIMIT ?2)",
            params![before, CHUNK_ROWS as i64],
        )?;
        tx.commit()?;
        if n == 0 {
            break;
        }
        sizes.push(n);
        total += n;
        if n < CHUNK_ROWS {
            break;
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    Ok(total)
}

/// The schema version a `{db}.bak-v{N}` file was taken at (also its unfinished `.tmp-` copies).
fn backup_version(name: &str) -> Option<u32> {
    let rest = name.strip_prefix(&format!("{}.bak-v", paths::DB_FILE))?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Deletes the `{db}.bak-v{N}` files taken at schema 3 or higher: they may hold team rows that
/// a remote deletion just removed. Older ones (schema 1 and 2) cannot hold team rows and stay
/// (§3.6); `awm forget` on the member's own machine still deletes all of them (plan-v2 §6.4).
pub fn remove_team_backups(data_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut gone = Vec::new();
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return Ok(gone);
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let is_file = e.file_type().is_ok_and(|t| t.is_file());
        if is_file && backup_version(&name).is_some_and(|v| v >= 3) {
            std::fs::remove_file(e.path())
                .with_context(|| format!("cannot delete {}", e.path().display()))?;
            gone.push(e.path());
        }
    }
    gone.sort();
    Ok(gone)
}

/// What [`after_deletions`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Scrub {
    /// Backups deleted (schema 3 or higher).
    pub backups: Vec<PathBuf>,
    /// FTS `optimize` and `wal_checkpoint(TRUNCATE)` ran in this call.
    pub scrubbed: bool,
}

/// The end of the deleting part of an `awm sync` run. When `deleted` rows went (remote
/// deletions, retention, a reconcile): the backups taken at schema 3 or higher are deleted and
/// a scrub is noted as pending. A pending scrub (FTS `optimize`, then
/// `wal_checkpoint(TRUNCATE)`) runs at most once a day ([`LAST_SCRUB`]), never on every run:
/// `optimize` rewrites the whole index and would hold the write lock the hooks wait for. Marks
/// older than `retention_days` + 30 days are dropped (no re-seed sends those tombstones).
pub fn after_deletions(
    conn: &Connection,
    data_dir: &Path,
    deleted: usize,
    retention_days: Option<u32>,
    now_ms: i64,
) -> Result<Scrub> {
    let mut out = Scrub::default();
    if deleted > 0 {
        out.backups = remove_team_backups(data_dir)?;
        state::set(conn, SCRUB_PENDING, "1")?;
    }
    if let Some(days) = retention_days {
        let cutoff = now_ms - (i64::from(days) + 30) * DAY_MS;
        conn.execute(
            "DELETE FROM sync_state WHERE (key LIKE 'own_deleted.%' OR key LIKE 'local_only.%') \
             AND CAST(value AS INTEGER) < ?1",
            [cutoff],
        )?;
    }
    let due = match state::get_i64(conn, LAST_SCRUB)? {
        None => true,
        // A time in the future (a clock that went back) does not block the scrub for good.
        Some(last) => now_ms - last >= DAY_MS || last > now_ms,
    };
    if due && state::get(conn, SCRUB_PENDING)?.is_some() {
        conn.execute("INSERT INTO event_fts(event_fts) VALUES('optimize')", [])?;
        // A reader in another process can keep the checkpoint from finishing; tomorrow's runs
        // and `awm forget` checkpoint again.
        let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            r.get::<_, i64>(0)
        });
        state::set(conn, LAST_SCRUB, &now_ms.to_string())?;
        state::remove(conn, SCRUB_PENDING)?;
        out.scrubbed = true;
    }
    Ok(out)
}

/// The record ids whose `team:` tombstone a re-seed sends again with `POST /v1/delete`
/// (§3.9.5; `docs/sync-v1.md` §11 step 2): tombstones written since `since_ms` (the last
/// `retention_days` + 30 days) for this device's own items (`sync_own`), for records of the
/// member's other machines this device deleted ([`OWN_DELETED`]) and, on an admin's device, for
/// every other record, except teammates' records deleted on this machine only ([`LOCAL_ONLY`]).
pub fn resend_ids(conn: &Connection, since_ms: i64, admin: bool) -> Result<Vec<String>> {
    let mut st = conn.prepare(
        "SELECT substr(t.value, 6) FROM tombstone t \
         WHERE t.kind = 'tool_use_id' AND t.value LIKE 'team:%' AND t.created_at >= ?1 \
           AND NOT EXISTS (SELECT 1 FROM sync_state s WHERE s.key = 'local_only.' || substr(t.value, 6)) \
           AND (?2 = 1 \
             OR EXISTS (SELECT 1 FROM sync_own o WHERE o.record_id = substr(t.value, 6)) \
             OR EXISTS (SELECT 1 FROM sync_state s WHERE s.key = 'own_deleted.' || substr(t.value, 6))) \
         ORDER BY t.created_at, t.value",
    )?;
    let ids = st
        .query_map(params![since_ms, i64::from(admin)], |r| {
            r.get::<_, String>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(ids)
}

/// Takes `sync.lock` for a command that deletes, waiting up to [`LOCK_WAIT`] for a running
/// `awm sync`, then refusing (§3.6). The lock is released when the file is dropped.
pub fn lock_sync(data_dir: &Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts
        .open(data_dir.join(SYNC_LOCK))
        .context("cannot open sync.lock")?;
    let start = Instant::now();
    loop {
        match f.try_lock() {
            Ok(()) => return Ok(f),
            Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < LOCK_WAIT => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(std::fs::TryLockError::WouldBlock) => bail!(
                "awm sync is running (sync.lock was held for {} s): nothing was changed; try \
                 again in a moment",
                LOCK_WAIT.as_secs()
            ),
            Err(std::fs::TryLockError::Error(e)) => return Err(e).context("cannot take sync.lock"),
        }
    }
}

/// Sends the queued outbox `delete` rows now (`push::deletions`), for a command that holds
/// `sync.lock`. Returns the number of requests that went through; a network failure leaves the
/// rows queued and is returned as the error.
#[cfg(feature = "sync")]
pub fn send_queued(data_dir: &Path) -> Result<usize> {
    use crate::db::{self, Role};
    use crate::sync::http::Client;
    use crate::sync::state::Identity;
    use crate::sync::{push, Env, Opts, Report, Session};

    let config = crate::config::load(&data_dir.join(paths::CONFIG_FILE))?;
    let env = Env {
        data_dir: data_dir.to_path_buf(),
        config,
        now_ms: None,
    };
    let opts = Opts::default();
    let ident = Identity::load(data_dir)?;
    let ring = ident.ring()?;
    let ca = ident.team.ca_file.as_deref().map(Path::new);
    let client = Client::new(&ident.team.server_url, Some(&ident.key.device_token), ca)?;
    let conn = db::open(&data_dir.join(paths::DB_FILE), Role::Sync)?;
    let mut s = Session {
        env: &env,
        opts: &opts,
        device: ident.device_keys(),
        conn,
        ident,
        ring,
        client,
        status: None,
        roster: awm_proto::keys::Roster::default(),
        keys_refreshed: false,
        report: Report::default(),
    };
    push::deletions(&mut s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_versions_are_read_from_the_name() {
        assert_eq!(backup_version("awm.db.bak-v2"), Some(2));
        assert_eq!(backup_version("awm.db.bak-v3"), Some(3));
        assert_eq!(backup_version("awm.db.bak-v12.tmp-1-2"), Some(12));
        assert_eq!(backup_version("awm.db.bak-vx"), None);
        assert_eq!(backup_version("other.db.bak-v3"), None);
    }
}
