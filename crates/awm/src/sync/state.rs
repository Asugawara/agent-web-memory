//! `sync_state`, the backoff and the team files (plan-v3-team §4.4, §4.6 step 8, §4.7; TM10).
//!
//! `sync_state` is a key/value table of text. Times are Unix milliseconds as decimal text, like
//! `event.created_at`. Keys written by the engine:
//!
//! | key | meaning |
//! |---|---|
//! | `last_ok` | end of the last run that finished without an error |
//! | `last_error` | the last failure, one line without any key, token or record text; removed by a success |
//! | `backoff_until`, `backoff_level` | no spawned run before this time; 1, 2, 4 ... 60 minutes, reset by a success |
//! | `generation` | the server generation the client last re-seeded for (§3.9.5) |
//! | `info_cached_at`, `info_json` | `GET /v1/info`, cached an hour |
//! | `min_client_block` | set to the organisation's `min_client` while this build is below it: pushes are stopped |
//! | `share_all_since` | when `team.share_all_projects` was first seen on (RVT1 m14); removed while the switch is off |
//! | `deletion_head` | highest deletion-stream index applied |
//! | `policy_version`, `policy_json` | the highest policy record seen |
//! | `skipped.{reason}` | pre-push counters of the last run (`awm team status`) |
//! | `dropped.{reason}`, `quarantined` | pull-side counters, cumulative |
//! | `newer_schema` | a teammate's record had a higher plaintext `schema` (`doctor` notice) |
//! | `server_restored_before_join` | the server was restored from a backup older than this device's join |
//! | `last_spawn` | TM13's debounce; never written here |

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};

pub const LAST_OK: &str = "last_ok";
pub const LAST_ERROR: &str = "last_error";
pub const BACKOFF_UNTIL: &str = "backoff_until";
pub const BACKOFF_LEVEL: &str = "backoff_level";
pub const GENERATION: &str = "generation";
pub const INFO_CACHED_AT: &str = "info_cached_at";
pub const INFO_JSON: &str = "info_json";
pub const MIN_CLIENT_BLOCK: &str = "min_client_block";
pub const SHARE_ALL_SINCE: &str = "share_all_since";
pub const DELETION_HEAD: &str = "deletion_head";
pub const POLICY_VERSION: &str = "policy_version";
pub const POLICY_JSON: &str = "policy_json";
pub const NEWER_SCHEMA: &str = "newer_schema";

/// How long `GET /v1/info` is cached (plan-v3-team §4.6 step 2), in milliseconds.
pub const INFO_TTL_MS: i64 = 3_600_000;
/// The longest backoff, in minutes (plan-v3-team §3.3).
pub const BACKOFF_MAX_MINUTES: i64 = 60;

/// One value, if present.
pub fn get(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM sync_state WHERE key = ?1", [key], |r| {
            r.get(0)
        })
        .optional()?)
}

/// The head of the stream `(member, device, tag)` as this device stores it: the highest idx
/// applied or queued, -1 when there is none.
pub fn stream_head(
    conn: &Connection,
    member: impl std::fmt::Display,
    device: impl std::fmt::Display,
    tag: &str,
) -> Result<i64> {
    Ok(conn
        .query_row(
            "SELECT head_idx FROM sync_stream WHERE member_id = ?1 AND device_id = ?2 AND tag = ?3",
            params![member.to_string(), device.to_string(), tag],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(-1))
}

/// Writes one value.
pub fn set(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO sync_state (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

/// Removes one value.
pub fn remove(conn: &Connection, key: &str) -> Result<()> {
    conn.execute("DELETE FROM sync_state WHERE key = ?1", [key])?;
    Ok(())
}

/// A value read as a number; `None` when absent or not a number.
pub fn get_i64(conn: &Connection, key: &str) -> Result<Option<i64>> {
    Ok(get(conn, key)?.and_then(|v| v.trim().parse().ok()))
}

/// Adds `n` to a counter.
pub fn bump(conn: &Connection, key: &str, n: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO sync_state (key, value) VALUES (?1, CAST(?2 AS TEXT)) \
         ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + ?2 AS TEXT)",
        params![key, n],
    )?;
    Ok(())
}

/// Replaces every `skipped.*` counter with the ones of this run.
pub fn set_skipped(
    conn: &Connection,
    counts: &std::collections::BTreeMap<String, u64>,
) -> Result<()> {
    conn.execute("DELETE FROM sync_state WHERE key LIKE 'skipped.%'", [])?;
    for (reason, n) in counts {
        set(conn, &format!("skipped.{reason}"), &n.to_string())?;
    }
    Ok(())
}

/// The `skipped.*` counters.
pub fn skipped(conn: &Connection) -> Result<std::collections::BTreeMap<String, u64>> {
    let mut st = conn.prepare("SELECT key, value FROM sync_state WHERE key LIKE 'skipped.%'")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = std::collections::BTreeMap::new();
    for row in rows {
        let (k, v) = row?;
        out.insert(
            k.trim_start_matches("skipped.").to_string(),
            v.parse().unwrap_or(0),
        );
    }
    Ok(out)
}

/// Members the user confirmed as admins with `awm team members --trust-admin @h` (a JSON list of
/// member ids). `Roster::verify` uses them only while the verified roster holds no admin
/// (RVT1 M5). Written by `awm team` (TM12).
pub const TRUSTED_ADMINS: &str = "trusted_admins";

/// The member ids of [`TRUSTED_ADMINS`] (TM12).
pub fn trusted_admins(conn: &Connection) -> Result<Vec<String>> {
    Ok(get(conn, TRUSTED_ADMINS)?
        .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
        .unwrap_or_default())
}

/// Adds member ids to [`TRUSTED_ADMINS`] (TM12).
pub fn add_trusted_admins(conn: &Connection, ids: &[String]) -> Result<()> {
    let mut all = trusted_admins(conn)?;
    all.extend(ids.iter().cloned());
    all.sort();
    all.dedup();
    set(conn, TRUSTED_ADMINS, &serde_json::to_string(&all)?)
}

/// The values of `sync_state` that `awm doctor` and `awm team status` show.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncState {
    pub generation: Option<String>,
    pub last_ok: Option<i64>,
    pub last_error: Option<String>,
    pub backoff_until: Option<i64>,
    pub info_cached_at: Option<i64>,
    pub min_client_block: Option<String>,
    pub share_all_since: Option<i64>,
    pub deletion_head: Option<i64>,
    pub newer_schema: bool,
}

impl SyncState {
    pub fn load(conn: &Connection) -> Result<SyncState> {
        Ok(SyncState {
            generation: get(conn, GENERATION)?,
            last_ok: get_i64(conn, LAST_OK)?,
            last_error: get(conn, LAST_ERROR)?,
            backoff_until: get_i64(conn, BACKOFF_UNTIL)?,
            info_cached_at: get_i64(conn, INFO_CACHED_AT)?,
            min_client_block: get(conn, MIN_CLIENT_BLOCK)?,
            share_all_since: get_i64(conn, SHARE_ALL_SINCE)?,
            deletion_head: get_i64(conn, DELETION_HEAD)?,
            newer_schema: get(conn, NEWER_SCHEMA)?.is_some(),
        })
    }
}

/// The backoff after `level` consecutive failures: 1, 2, 4, 8, 16, 32, then 60 minutes.
pub fn backoff_minutes(level: u32) -> i64 {
    if level == 0 {
        return 0;
    }
    (1i64 << (level - 1).min(6)).min(BACKOFF_MAX_MINUTES)
}

/// When a spawned run may start again, if a backoff is running.
pub fn backoff_active(conn: &Connection, now_ms: i64) -> Result<Option<i64>> {
    Ok(get_i64(conn, BACKOFF_UNTIL)?.filter(|until| *until > now_ms))
}

/// Records a failed run: `last_error` and a longer backoff. `retry_after_s` (a 429 or 503
/// `Retry-After`) sets the backoff to that wait without raising the level.
pub fn record_failure(
    conn: &Connection,
    now_ms: i64,
    message: &str,
    retry_after_s: Option<u32>,
) -> Result<()> {
    let one_line: String = message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(300)
        .collect();
    set(conn, LAST_ERROR, &one_line)?;
    let until = match retry_after_s {
        Some(s) => now_ms + i64::from(s) * 1_000,
        None => {
            let level = get_i64(conn, BACKOFF_LEVEL)?.unwrap_or(0).clamp(0, 30) as u32 + 1;
            set(conn, BACKOFF_LEVEL, &level.to_string())?;
            now_ms + backoff_minutes(level) * 60_000
        }
    };
    set(conn, BACKOFF_UNTIL, &until.to_string())
}

/// Records a run that finished: `last_ok`, no error, no backoff.
pub fn record_success(conn: &Connection, now_ms: i64) -> Result<()> {
    set(conn, LAST_OK, &now_ms.to_string())?;
    remove(conn, LAST_ERROR)?;
    remove(conn, BACKOFF_UNTIL)?;
    remove(conn, BACKOFF_LEVEL)
}

#[cfg(feature = "sync")]
pub use files::*;

/// `team.toml` and `team.key` (plan-v3-team §4.7), read and written here until `awm team`
/// (TM12) owns them. Both are mode 0600 in the data directory; a file readable by others is
/// refused.
#[cfg(feature = "sync")]
mod files {
    use std::collections::BTreeMap;
    use std::fmt;
    use std::path::{Path, PathBuf};

    use anyhow::{bail, Context, Result};
    use awm_proto::keys::{DeviceKeys, EpochKey, KeyRing};
    use awm_proto::wire::{Id, Key32};
    use serde::{Deserialize, Serialize};

    pub use crate::paths::{TEAM_KEY, TEAM_TOML};

    /// `team.toml`: where the server is and who this device is.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct TeamToml {
        pub server_url: String,
        pub org_id: Id,
        pub member_id: Id,
        pub handle: String,
        pub device_id: Id,
        /// A PEM file with the CA of a server behind an internal CA (`team.ca_file`, §4.7).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ca_file: Option<String>,
    }

    /// One epoch key in `team.key`.
    #[derive(Clone, Serialize, Deserialize)]
    pub struct EpochKeyEntry {
        pub epoch: u32,
        pub key: Key32,
    }

    /// An invite this device created and has not seen approved: the invite string holds the
    /// secret `S`, which approval needs (`awm_proto::keys::Invite::parse`).
    #[derive(Clone, Serialize, Deserialize)]
    pub struct PendingInvite {
        /// `awmi1_...`
        pub invite: String,
        /// `member` or `device`: what the invite admits (the approver's own record, §5.2).
        pub kind: String,
        /// `device` invites: the member the new device joins (this member, or one an admin
        /// re-enrols).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub member_id: Option<String>,
        /// `member` invites: `member` (default) or `admin`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
    }

    /// `team.key`: the device token, the device's private key, the epoch keys and the pending
    /// invite secrets. JSON. Unknown keys survive a rewrite.
    #[derive(Clone, Serialize, Deserialize)]
    pub struct TeamKey {
        pub device_token: String,
        /// The token before the last rotation; tried once after a restore (sync-v1 §11 step 5).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub previous_device_token: Option<String>,
        pub device_secret: Key32,
        #[serde(default)]
        pub epoch_keys: Vec<EpochKeyEntry>,
        #[serde(default)]
        pub pending_invites: Vec<PendingInvite>,
        #[serde(flatten)]
        pub extra: BTreeMap<String, serde_json::Value>,
    }

    impl fmt::Debug for TeamKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TeamKey")
                .field("epochs", &self.epoch_keys.len())
                .field("pending_invites", &self.pending_invites.len())
                .finish_non_exhaustive()
        }
    }

    /// Both files, read.
    pub struct Identity {
        pub team: TeamToml,
        pub key: TeamKey,
    }

    impl fmt::Debug for Identity {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Identity")
                .field("handle", &self.team.handle)
                .finish_non_exhaustive()
        }
    }

    pub fn team_toml_path(dir: &Path) -> PathBuf {
        dir.join(TEAM_TOML)
    }

    pub fn team_key_path(dir: &Path) -> PathBuf {
        dir.join(TEAM_KEY)
    }

    #[cfg(unix)]
    fn check_private(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("cannot read {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            bail!(
                "{} is readable by other users (mode {:o}); run: chmod 600 {}",
                path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
                mode & 0o777,
                path.display()
            );
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_private(_path: &Path) -> Result<()> {
        Ok(())
    }

    /// Writes `bytes` to `path` with mode 0600, through a temporary file in the same directory.
    pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let tmp = dir.join(format!(
            ".{}.tmp-{}",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
            std::process::id()
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let result = (|| -> std::io::Result<()> {
            let mut f = opts.open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result.with_context(|| format!("cannot write {}", path.display()))
    }

    impl TeamToml {
        pub fn load(dir: &Path) -> Result<TeamToml> {
            let path = team_toml_path(dir);
            check_private(&path)?;
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            toml::from_str(&text).with_context(|| format!("cannot parse {}", path.display()))
        }

        pub fn save(&self, dir: &Path) -> Result<()> {
            let text = toml::to_string(self).context("cannot encode team.toml")?;
            write_private(&team_toml_path(dir), text.as_bytes())
        }
    }

    impl TeamKey {
        pub fn load(dir: &Path) -> Result<TeamKey> {
            let path = team_key_path(dir);
            check_private(&path)?;
            let text =
                std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
            serde_json::from_slice(&text)
                .map_err(|_| anyhow::anyhow!("cannot parse {}", path.display()))
        }

        pub fn save(&self, dir: &Path) -> Result<()> {
            let bytes = serde_json::to_vec_pretty(self).context("cannot encode team.key")?;
            write_private(&team_key_path(dir), &bytes)
        }

        /// The key ring of the stored epoch keys.
        pub fn ring(&self, org: Id) -> Result<KeyRing> {
            let keys: Vec<EpochKey> = self
                .epoch_keys
                .iter()
                .map(|e| EpochKey::from_bytes(e.epoch, e.key.0))
                .collect();
            KeyRing::from_keys(*org.as_uuid(), keys).map_err(|e| anyhow::anyhow!("team.key: {e}"))
        }

        /// Replaces the stored epoch keys with `ring`'s.
        pub fn set_ring(&mut self, ring: &KeyRing) {
            self.epoch_keys = ring
                .epochs()
                .map(|k| EpochKeyEntry {
                    epoch: k.epoch(),
                    key: Key32(*k.expose_secret()),
                })
                .collect();
        }

        pub fn device_keys(&self) -> DeviceKeys {
            DeviceKeys::from_secret_bytes(self.device_secret.0)
        }
    }

    impl Identity {
        pub fn load(dir: &Path) -> Result<Identity> {
            Ok(Identity {
                team: TeamToml::load(dir)?,
                key: TeamKey::load(dir)?,
            })
        }

        pub fn ring(&self) -> Result<KeyRing> {
            self.key.ring(self.team.org_id)
        }

        pub fn device_keys(&self) -> DeviceKeys {
            self.key.device_keys()
        }

        /// A client for the team server under this device's token (and `team.ca_file`).
        pub fn client(&self) -> Result<crate::sync::http::Client> {
            let ca = self.team.ca_file.as_deref().map(Path::new);
            crate::sync::http::Client::new(&self.team.server_url, Some(&self.key.device_token), ca)
        }

        pub fn save_key(&self, dir: &Path) -> Result<()> {
            self.key.save(dir)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_doubles_to_an_hour() {
        let got: Vec<i64> = (0..10).map(backoff_minutes).collect();
        assert_eq!(got, [0, 1, 2, 4, 8, 16, 32, 60, 60, 60]);
    }
}
