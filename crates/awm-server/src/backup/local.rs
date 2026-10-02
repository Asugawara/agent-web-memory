//! Copies of the database that stay in the data directory and hold deleted blobs
//! (plan-v3-team §5.6, RVT2 B2): `server.db.bak-v*` (written before a migration) and
//! `server.db.pre-restore-{time}` with its `-wal` and `-shm` files (`awm serve restore
//! --force`). They follow the backups' window: a copy goes once it is older than the oldest
//! full snapshot the backup retention keeps ([`keys::OLDEST_KEPT`]), and in any case once it is
//! [`KEEP_FULL_S`] + 1 day old, which is the rule without a backup target. So a record deleted
//! after a restore is gone from every file under `--data` within 8 days, as from the backups.
//!
//! `awm serve` runs [`sweep`] from its hourly retention task (with or without `--backup`); the
//! backup loop also removes them after its own retention. A copy's time is the one in its name
//! (`pre-restore-{time}`) or, for `.bak-v*`, its modification time.

use std::path::{Path, PathBuf};

use super::{keys, BackupError, KEEP_FULL_S};
use crate::store::sqlite::DB_FILE;
use crate::store::Store;

const DAY_S: i64 = 86_400;

/// When a copy made at `made_at` is removed at the latest (`made_at` + [`KEEP_FULL_S`] + 1 day).
pub fn removal_date(made_at: i64) -> i64 {
    made_at + KEEP_FULL_S + DAY_S
}

/// Copies made before the returned time go: the oldest kept full snapshot (when the backup
/// retention reported one), but never later than [`KEEP_FULL_S`] + 1 day before `now`.
pub fn cutoff(now: i64, oldest_kept: Option<i64>) -> i64 {
    let latest = now - KEEP_FULL_S - DAY_S;
    oldest_kept.map_or(latest, |o| o.max(latest))
}

/// The time of a local copy named `name` (its name's time for a pre-restore copy, else
/// `modified`); `None` for any other file.
fn copy_time(name: &str, modified: Option<i64>) -> Option<i64> {
    let pre = format!("{DB_FILE}.pre-restore-");
    if let Some(rest) = name.strip_prefix(&pre) {
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        let suffix = &rest[digits.len()..];
        if !digits.is_empty() && matches!(suffix, "" | "-wal" | "-shm") {
            return digits.parse().ok().or(modified);
        }
        return None;
    }
    if name.starts_with(&format!("{DB_FILE}.bak-v")) {
        return modified;
    }
    None
}

/// Removes the local copies in `dir` made before `before` (Unix seconds); returns them sorted.
pub fn remove_before(dir: &Path, before: i64) -> Result<Vec<PathBuf>, BackupError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(super::full::io("cannot list", dir, e)),
    };
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        if copy_time(name, modified).is_some_and(|t| t < before) {
            let path = entry.path();
            std::fs::remove_file(&path).map_err(|e| super::full::io("cannot remove", &path, e))?;
            removed.push(path);
        }
    }
    removed.sort();
    Ok(removed)
}

/// The hourly removal of `awm serve` (`SqliteStore`): [`remove_before`] at [`cutoff`], with the
/// oldest kept full snapshot the backup loop last recorded (none without `--backup`).
pub async fn sweep(store: &dyn Store, dir: &Path, now: i64) -> Result<Vec<PathBuf>, BackupError> {
    let oldest_kept = store
        .meta_get(keys::OLDEST_KEPT.into())
        .await?
        .and_then(|v| v.parse().ok());
    let dir = dir.to_path_buf();
    let before = cutoff(now, oldest_kept);
    super::full::blocking(move || remove_before(&dir, before)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_are_named_by_time_and_other_files_are_not_copies() {
        let pre = format!("{DB_FILE}.pre-restore-1790000000");
        assert_eq!(copy_time(&pre, Some(5)), Some(1_790_000_000));
        assert_eq!(
            copy_time(&format!("{pre}-wal"), Some(5)),
            Some(1_790_000_000)
        );
        assert_eq!(copy_time(&format!("{pre}-shm"), None), Some(1_790_000_000));
        assert_eq!(copy_time(&format!("{pre}-x"), Some(5)), None);
        assert_eq!(
            copy_time(&format!("{DB_FILE}.bak-v1-abc"), Some(7)),
            Some(7)
        );
        for other in [
            DB_FILE,
            "server.db-wal",
            "server.lock",
            "server.toml",
            "acme",
        ] {
            assert_eq!(copy_time(other, Some(1)), None, "{other}");
        }
    }

    #[test]
    fn the_cutoff_is_the_oldest_kept_snapshot_but_never_later_than_eight_days() {
        let now = 100 * DAY_S;
        assert_eq!(cutoff(now, None), now - 8 * DAY_S);
        assert_eq!(cutoff(now, Some(now - 3 * DAY_S)), now - 3 * DAY_S);
        assert_eq!(cutoff(now, Some(now - 30 * DAY_S)), now - 8 * DAY_S);
        assert_eq!(removal_date(0), 8 * DAY_S);
    }
}
