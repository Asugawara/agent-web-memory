//! Built-in backup and restore (plan-v3-team §6.2, §3.9.5, §4.8.1, §5.6; TM27).
//!
//! `SqliteStore` ships a full snapshot at start, daily, after a migration and after a restore,
//! and an incremental change set every 60 s when `backup_log` grew, to `gs://`, `s3://` or
//! `file://` ([`target`]), with create-only uploads and a JSON manifest per object
//! ([`manifest`]). Retention keeps the full snapshots of the last 7 days and every change set
//! newer than the oldest kept one, and deletes the rest itself ([`run::retention`]). A restore
//! takes the latest full snapshot at or before a time plus its change sets in order, checks
//! every object against its manifest and the result with `PRAGMA integrity_check`, and writes
//! a new `generation` ([`restore`]). `PgStore` writes a daily canonical export instead
//! ([`full::pg_daily_export`]).
//!
//! Entry points (TM15 wires `awm serve`, `backup` and `restore` to them):
//!
//! | what | call |
//! |---|---|
//! | `--backup URL` | [`Target::parse`], then [`Target::open`] → `Arc<dyn Bucket>` |
//! | the loop in `awm serve` (`SqliteStore`) | [`run::run`] or [`run::Backup::new`] + [`run::Backup::run`] |
//! | full snapshot after a migration | [`run::Backup::request_full`] with [`Origin::Migration`] |
//! | `awm serve backup [--to URL]` | [`full::snapshot_now`] (`SqliteStore`: snapshot; `PgStore`: export) |
//! | `awm serve backup --verify` | [`restore::verify`] |
//! | `awm serve restore` | [`restore::run`] with a [`restore::RestoreRequest`]; [`BackupError::exit_code`] |
//! | `PgStore` with `--backup` | [`full::pg_daily_export`] (call it hourly; it exports once a day) |
//! | `awm serve check` | [`status`] then [`BackupStatus::check`] |
//!
//! The backup's state lives in `meta` under `backup_*` keys ([`keys`]), which the store does
//! not log in `backup_log` and leaves out of dumps and canonical exports. Messages and errors
//! hold object keys, counts and times, never a credential, a row value or blob bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use awm_proto::wire::Id;

use crate::store::{Store, StoreError, StoreResult};

pub mod manifest;
pub mod target;

#[cfg(feature = "sqlite")]
pub mod full;
#[cfg(feature = "sqlite")]
pub mod incr;
#[cfg(feature = "sqlite")]
pub mod restore;
#[cfg(feature = "sqlite")]
pub mod run;

pub use crate::retention::{Clock, SystemClock};
pub use manifest::{Kind, Manifest, Origin, FORMAT};
pub use target::{Bucket, Target, TargetError};

/// Seconds between incremental change sets (§6.2).
pub const INCR_INTERVAL_S: i64 = 60;
/// Seconds between daily full snapshots (and `PgStore` exports).
pub const FULL_INTERVAL_S: i64 = 86_400;
/// Full snapshots newer than this are kept (§6.2: 7 days).
pub const KEEP_FULL_S: i64 = 7 * 86_400;
/// Seconds between retention runs and foreign-writer checks on a host (§3.9.2: hourly).
pub const RETENTION_INTERVAL_S: i64 = 3_600;
/// Seconds between self-verifications (§6.2: weekly).
pub const VERIFY_INTERVAL_S: i64 = 7 * 86_400;
/// `check`: FAIL when uploads have failed for longer than this (§4.8.1: 1 h).
pub const FAILING_FAIL_S: i64 = 3_600;
/// `check`: FAIL when the last full snapshot is older than this (§4.8.1: 48 h).
pub const FULL_FAIL_S: i64 = 48 * 3_600;
/// `check`: WARN when the last successful verification is older than this (§4.8.1: 30 days).
pub const VERIFY_WARN_S: i64 = 30 * 86_400;
/// At start, another generation that wrote to the prefix within this many seconds counts as a
/// live server (a live server writes at least a daily full snapshot).
pub const FOREIGN_RECENT_S: i64 = 25 * 3_600;

/// The `meta` keys of the backup (all `backup_*`: not logged, not in dumps or exports).
pub mod keys {
    pub use crate::store::meta_keys::BACKUP_CURSOR as CURSOR;
    /// Unix seconds and key of the last successful upload.
    pub const LAST_OK_AT: &str = "backup_last_ok_at";
    pub const LAST_OBJECT: &str = "backup_last_object";
    /// Unix seconds and key of the last full snapshot (or export) uploaded or confirmed.
    pub const LAST_FULL_AT: &str = "backup_last_full_at";
    pub const LAST_FULL: &str = "backup_last_full";
    /// The last failure (text without values), when it happened, and the first failure since
    /// the last success.
    pub const ERROR: &str = "backup_error";
    pub const ERROR_AT: &str = "backup_error_at";
    pub const FAILING_SINCE: &str = "backup_failing_since";
    /// Set when another server writes to the same prefix; uploads stop until a restart.
    pub const CONFLICT: &str = "backup_conflict";
    /// The last verification: `1` or `0`, when, the last success, and a short summary.
    pub const VERIFY_OK: &str = "backup_verify_ok";
    pub const VERIFY_AT: &str = "backup_verify_at";
    pub const VERIFY_OK_AT: &str = "backup_verify_ok_at";
    pub const VERIFY_DETAIL: &str = "backup_verify_detail";
    /// Generations this database was restored from, newest last (comma-separated): their
    /// objects are this server's history, kept and expired by its retention.
    pub const LINEAGE: &str = "backup_lineage";

    /// Every key a restore resets (all but [`LINEAGE`], which it extends).
    pub const STATE: &[&str] = &[
        CURSOR,
        LAST_OK_AT,
        LAST_OBJECT,
        LAST_FULL_AT,
        LAST_FULL,
        ERROR,
        ERROR_AT,
        FAILING_SINCE,
        CONFLICT,
        VERIFY_OK,
        VERIFY_AT,
        VERIFY_OK_AT,
        VERIFY_DETAIL,
    ];
}

// ---------------------------------------------------------------------------------------------
// Errors

/// A backup, verification or restore failure. The text names objects, cursors and tables,
/// never a row value or a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupError {
    Store(StoreError),
    Target(TargetError),
    /// Local file I/O (temporary files, the data directory).
    Io(String),
    /// Another server writes to the same prefix (a create-only upload found an object, or the
    /// listing shows objects this process did not write). Uploads stop.
    Conflict(String),
    /// An object does not match its manifest, a manifest is malformed, or a downloaded
    /// database fails `PRAGMA integrity_check` (exit 3).
    Corrupt {
        object: String,
        reason: String,
    },
    /// A gap in a chain of change sets (exit 3).
    MissingIncrement {
        generation: Id,
        after: i64,
    },
    /// The restored or verified database cannot be used (exit 3).
    Unusable(String),
    /// A verification found the backup different from the live database (exit 3).
    Mismatch(String),
    /// Nothing to restore (no full snapshot at or before the time asked for).
    NoBackup(String),
    /// The request is refused as given (exit 2): a database in the way without `--force`, an
    /// organisation in the target `PgStore`, `--mark-restored` with a source.
    Refused(String),
}

impl BackupError {
    /// The exit code of `awm serve backup` and `awm serve restore` (§4.8.1): 2 refused
    /// configuration, 3 database unusable (manifest mismatch, failed integrity check, a
    /// missing change set, a verification mismatch), 1 anything else.
    pub fn exit_code(&self) -> i32 {
        match self {
            BackupError::Refused(_) | BackupError::Target(TargetError::Invalid(_)) => 2,
            BackupError::Corrupt { .. }
            | BackupError::MissingIncrement { .. }
            | BackupError::Unusable(_)
            | BackupError::Mismatch(_) => 3,
            _ => 1,
        }
    }
}

impl fmt::Display for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackupError::Store(e) => write!(f, "{e}"),
            BackupError::Target(e) => write!(f, "{e}"),
            BackupError::Io(m) => write!(f, "backup: {m}"),
            BackupError::Conflict(m) => {
                write!(f, "another server writes to this backup prefix: {m}")
            }
            BackupError::Corrupt { object, reason } => {
                write!(f, "backup object {object} refused: {reason}")
            }
            BackupError::MissingIncrement { generation, after } => write!(
                f,
                "missing incremental change set after cursor {after} in incr/{generation}/: the \
                 chain is broken (restore an earlier point with --at)"
            ),
            BackupError::Unusable(m) => write!(f, "restored database unusable: {m}"),
            BackupError::Mismatch(m) => write!(f, "backup differs from the live database: {m}"),
            BackupError::NoBackup(m) => write!(f, "nothing to restore: {m}"),
            BackupError::Refused(m) => write!(f, "refused: {m}"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<StoreError> for BackupError {
    fn from(e: StoreError) -> BackupError {
        BackupError::Store(e)
    }
}

impl From<TargetError> for BackupError {
    fn from(e: TargetError) -> BackupError {
        BackupError::Target(e)
    }
}

// ---------------------------------------------------------------------------------------------
// Listing

/// The objects of one generation, by sequence number.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenObjects {
    pub full_data: BTreeSet<i64>,
    pub full_json: BTreeSet<i64>,
    pub incr_data: BTreeSet<i64>,
    pub incr_json: BTreeSet<i64>,
}

impl GenObjects {
    /// Every key of the generation, manifests first for each pair.
    pub fn keys(&self, generation: Id) -> Vec<String> {
        let mut out = Vec::new();
        for (kind, json, data) in [
            (Kind::Full, &self.full_json, &self.full_data),
            (Kind::Incr, &self.incr_json, &self.incr_data),
        ] {
            for seq in json {
                out.push(manifest::manifest_key(kind, generation, *seq));
            }
            for seq in data {
                out.push(manifest::data_key(kind, generation, *seq));
            }
        }
        out
    }
}

/// Every backup object under the prefix, by generation. Names that are not ours (another
/// directory, a file that is not `{seq}.db` or `{seq}.json`) are left out and never touched.
pub async fn list_all(bucket: &dyn Bucket) -> Result<BTreeMap<Id, GenObjects>, BackupError> {
    let mut out: BTreeMap<Id, GenObjects> = BTreeMap::new();
    for top in ["full", "incr"] {
        let gens = bucket.list(top.to_string()).await?;
        for dir in gens.dirs {
            let Ok(generation) = Id::parse(&dir) else {
                continue;
            };
            let objects = bucket.list(format!("{top}/{dir}")).await?;
            let entry = out.entry(generation).or_default();
            for name in objects.objects {
                let Some((seq, is_manifest)) = manifest::parse_name(&name) else {
                    continue;
                };
                let set = match (top, is_manifest) {
                    ("full", true) => &mut entry.full_json,
                    ("full", false) => &mut entry.full_data,
                    (_, true) => &mut entry.incr_json,
                    (_, false) => &mut entry.incr_data,
                };
                set.insert(seq);
            }
        }
    }
    Ok(out)
}

/// Reads and checks the manifest at `key`: `None` when absent, `Corrupt` naming the key when
/// it is malformed or describes another object.
pub async fn read_manifest(
    bucket: &dyn Bucket,
    kind_dir: Kind,
    generation: Id,
    seq: i64,
) -> Result<Option<Manifest>, BackupError> {
    let key = manifest::manifest_key(kind_dir, generation, seq);
    let Some(bytes) = bucket.get(key.clone()).await? else {
        return Ok(None);
    };
    let m = Manifest::from_bytes(&bytes).map_err(|e| BackupError::Corrupt {
        object: key.clone(),
        reason: e.0.to_string(),
    })?;
    if m.generation != generation || m.seq != seq || m.kind.dir() != kind_dir.dir() {
        return Err(BackupError::Corrupt {
            object: key,
            reason: "manifest describes another object".into(),
        });
    }
    Ok(Some(m))
}

// ---------------------------------------------------------------------------------------------
// Status for `awm serve check`

/// The backup state recorded in `meta`, for `awm serve check` (TM15).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupStatus {
    pub last_ok_at: Option<i64>,
    pub last_object: Option<String>,
    pub last_full_at: Option<i64>,
    pub last_full: Option<String>,
    pub error: Option<String>,
    pub error_at: Option<i64>,
    pub failing_since: Option<i64>,
    pub conflict: Option<String>,
    pub verify_ok: Option<bool>,
    pub verify_at: Option<i64>,
    pub verify_ok_at: Option<i64>,
    pub verify_detail: Option<String>,
}

/// The level of a `check` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

/// One `check` line for the `backup` check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckLine {
    pub level: Level,
    pub text: String,
}

/// The §4.8.1 text for a server without `--backup`.
pub const NO_TARGET: &str = "NO BACKUP TARGET: a disk loss destroys membership, invites, key \
                             wraps and every record no member still holds; set --backup \
                             gs://... (docs/self-host.md#backup)";

/// Reads the backup state from `meta` (empty values count as absent).
pub async fn status(store: &dyn Store) -> StoreResult<BackupStatus> {
    let mut v = BTreeMap::new();
    for key in keys::STATE {
        if let Some(s) = store.meta_get(key.to_string()).await? {
            if !s.is_empty() {
                v.insert(*key, s);
            }
        }
    }
    let int = |k: &str| v.get(k).and_then(|s| s.parse::<i64>().ok());
    let text = |k: &str| v.get(k).cloned();
    Ok(BackupStatus {
        last_ok_at: int(keys::LAST_OK_AT),
        last_object: text(keys::LAST_OBJECT),
        last_full_at: int(keys::LAST_FULL_AT),
        last_full: text(keys::LAST_FULL),
        error: text(keys::ERROR),
        error_at: int(keys::ERROR_AT),
        failing_since: int(keys::FAILING_SINCE),
        conflict: text(keys::CONFLICT),
        verify_ok: v.get(keys::VERIFY_OK).map(|s| s == "1"),
        verify_at: int(keys::VERIFY_AT),
        verify_ok_at: int(keys::VERIFY_OK_AT),
        verify_detail: text(keys::VERIFY_DETAIL),
    })
}

fn ago(now: i64, t: i64) -> String {
    let d = (now - t).max(0);
    if d < 120 {
        format!("{d} s ago")
    } else if d < 2 * 3_600 {
        format!("{} min ago", d / 60)
    } else if d < 2 * 86_400 {
        format!("{} h ago", d / 3_600)
    } else {
        format!("{} d ago", d / 86_400)
    }
}

impl BackupStatus {
    /// The `backup` lines of `awm serve check` (§4.8.1) for `target` (the `--backup` URL, or
    /// `None` without one): WARN `NO BACKUP TARGET`; FAIL for another writer on the prefix,
    /// uploads failing for more than 1 h, no full snapshot within 48 h, and a failed last
    /// verification; WARN for no successful verification within 30 days; otherwise one OK
    /// line.
    pub fn check(&self, target: Option<&str>, now: i64) -> Vec<CheckLine> {
        let Some(target) = target else {
            return vec![CheckLine {
                level: Level::Warn,
                text: NO_TARGET.into(),
            }];
        };
        let mut out = Vec::new();
        let fail = |text: String| CheckLine {
            level: Level::Fail,
            text,
        };
        if let Some(c) = &self.conflict {
            out.push(fail(format!(
                "another server writes to {target}; uploads stopped: {c}"
            )));
        }
        if let Some(since) = self.failing_since {
            if now - since > FAILING_FAIL_S {
                out.push(fail(format!(
                    "last backup upload failing for more than 1 h (since {}): {}",
                    ago(now, since),
                    self.error.as_deref().unwrap_or("unknown error")
                )));
            }
        }
        match self.last_full_at {
            Some(t) if now - t <= FULL_FAIL_S => {}
            Some(t) => out.push(fail(format!(
                "no full snapshot within 48 h (last {})",
                ago(now, t)
            ))),
            None => out.push(fail("no full snapshot within 48 h (none yet)".into())),
        }
        if self.verify_ok == Some(false) {
            out.push(fail(format!(
                "last --verify failed {}: {}",
                self.verify_at
                    .map_or("at an unknown time".into(), |t| ago(now, t)),
                self.verify_detail.as_deref().unwrap_or("no detail")
            )));
        }
        if !self.verify_ok_at.is_some_and(|t| now - t <= VERIFY_WARN_S) {
            out.push(CheckLine {
                level: Level::Warn,
                text: format!(
                    "no successful --verify within 30 days (last success: {})",
                    self.verify_ok_at.map_or("never".into(), |t| ago(now, t))
                ),
            });
        }
        if out.is_empty() {
            out.push(CheckLine {
                level: Level::Ok,
                text: format!(
                    "{target}, last upload {}, last full {}, verified {}",
                    self.last_ok_at.map_or("never".into(), |t| ago(now, t)),
                    self.last_full_at.map_or("never".into(), |t| ago(now, t)),
                    self.verify_ok_at.map_or("never".into(), |t| ago(now, t)),
                ),
            });
        }
        out
    }
}

/// Parses [`keys::LINEAGE`].
pub fn parse_lineage(v: Option<&str>) -> Vec<Id> {
    v.unwrap_or("")
        .split(',')
        .filter_map(|s| Id::parse(s.trim()).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_follow_4_8_1() {
        assert_eq!(BackupError::Refused("x".into()).exit_code(), 2);
        assert_eq!(
            BackupError::Target(TargetError::Invalid("x".into())).exit_code(),
            2
        );
        assert_eq!(
            BackupError::Corrupt {
                object: "o".into(),
                reason: "r".into()
            }
            .exit_code(),
            3
        );
        assert_eq!(
            BackupError::MissingIncrement {
                generation: Id::new_v4(),
                after: 1
            }
            .exit_code(),
            3
        );
        assert_eq!(BackupError::Unusable("x".into()).exit_code(), 3);
        assert_eq!(BackupError::Mismatch("x".into()).exit_code(), 3);
        assert_eq!(BackupError::Io("x".into()).exit_code(), 1);
        assert_eq!(BackupError::Conflict("x".into()).exit_code(), 1);
    }
}
