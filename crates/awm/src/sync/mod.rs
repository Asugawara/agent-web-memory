//! Team sync engine (plan-v3-team §4.6, TM10): `awm sync`.
//!
//! Network code (`http`, `push`, `pull`, `reseed`, `roster`, and the engine below) exists only
//! with the `sync` feature and is reached only from `cli/sync.rs`, never from hook, matching or
//! render modules (§4.1 item 4).
//!
//! One run, in this order (`run`):
//!
//! 1. take `{data_dir}/sync.lock` (a second run exits 0 at once), read `team.toml` and
//!    `team.key`, open the database as `Role::Sync`, refuse a schema below 3;
//! 2. `GET /v1/info`, cached an hour; below `min_client` pushes stop;
//! 3. `GET /v1/status`; new epoch keys through `GET /v1/keys`;
//! 4. when `generation` differs from the stored one: the re-seed (`reseed`);
//! 5. pull (`pull`), then the deletion stream;
//! 6. approvals of pending devices and, for an admin, the rotation (`roster`);
//! 7. push: the outbox, the eligible rows, the deletions (`push`);
//! 8. `sync_state` (`state`): `last_ok` or `last_error` and the backoff.
//!
//! `--push-only` skips step 5 and `--pull-only` steps 6 and 7 (`Opts`); the re-seed of step 4
//! runs in both, as it repairs a restored server rather than sending anything new.
//!
//! The reading steps come before the push (the plan lists the push first): a device must hold
//! the verified roster before it may push content (sync-v1 §5.2, `check_own_approval`), and an
//! admin that rotates first never meets a 409 `stale_epoch` of its own making.

pub mod apply;
pub mod eligible;
#[cfg(feature = "sync")]
pub mod http;
pub mod payload;
#[cfg(feature = "sync")]
pub mod pull;
#[cfg(feature = "sync")]
pub mod push;
#[cfg(feature = "sync")]
pub mod reseed;
#[cfg(feature = "sync")]
pub mod roster;
pub mod spawn;
pub mod state;

#[cfg(feature = "sync")]
pub use engine::*;

#[cfg(feature = "sync")]
mod engine {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use anyhow::{bail, Context, Result};
    use awm_proto::keys::{DeviceKeys, KeyRing, Roster};
    use awm_proto::wire::{ErrorCode, Id, InfoResponse, StatusResponse};
    use rusqlite::Connection;

    use crate::config::{AutoApprove, Config};
    use crate::db::{self, Role, VersionCheck};
    use crate::paths;
    use crate::sync::http::{self, CallError, Client};
    use crate::sync::state::{self, Identity};
    use crate::sync::{pull, push, reseed, roster};

    /// The name of the lock file in the data directory.
    pub const LOCK_FILE: &str = "sync.lock";

    /// Where a run reads from: the data directory and the configuration.
    #[derive(Debug, Clone)]
    pub struct Env {
        pub data_dir: PathBuf,
        pub config: Config,
        /// A fixed clock for tests; `None` is the real time.
        pub now_ms: Option<i64>,
    }

    impl Env {
        /// `AWM_HOME` or the default data directory, and its `config.toml`.
        pub fn from_environment() -> Result<Env> {
            let data_dir = paths::data_dir()?;
            let config = crate::config::load(&data_dir.join(paths::CONFIG_FILE))?;
            Ok(Env {
                data_dir,
                config,
                now_ms: None,
            })
        }
    }

    /// `awm sync --backfill`: share older records of the named projects (plan-v3-team §3.4
    /// item 2). `values` are `cwd_hash` or `repo_key` values of existing `share_rule` rows.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Backfill {
        pub since_ms: Option<i64>,
        pub values: Vec<String>,
    }

    /// The decision of `team.auto_approve` for one pending device (TM12's `team::auto_approve`).
    pub type ApproveFn = fn(AutoApprove, bool) -> bool;

    /// Options of a run.
    #[derive(Debug, Clone, Default)]
    pub struct Opts {
        /// The hook spawn: nothing is printed by the caller.
        pub quiet: bool,
        /// A run started by a hook honours the backoff; one the user starts does not.
        pub honour_backoff: bool,
        pub backfill: Option<Backfill>,
        /// With `backfill`: count what would be shared, send nothing, open no connection.
        pub dry_run: bool,
        /// `awm sync --push-only`: skip step 5 (pull, deletion stream, retention).
        pub push_only: bool,
        /// `awm sync --pull-only`: skip steps 6 and 7 (approvals, rotation, push).
        pub pull_only: bool,
        /// Tests: stop after the server acknowledged a push, before `pushed_at` is written.
        #[doc(hidden)]
        pub crash_after_ack: bool,
        /// Tests: replaces `team::auto_approve` (a TM12 stub until `awm team` lands).
        #[doc(hidden)]
        pub approve: Option<ApproveFn>,
    }

    /// What a run did.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Report {
        pub pushed: usize,
        pub pulled: usize,
        pub dropped: usize,
        pub quarantined: usize,
        pub skipped_newer: usize,
        pub deletions_applied: usize,
        pub approvals: usize,
        pub rotated: bool,
        pub reseeded: bool,
        pub reconciled: bool,
        /// Pushes stopped: below `min_client`, or no verified roster entry for this device.
        pub push_blocked: Option<String>,
        /// This device is waiting for an approval (nothing to do yet).
        pub waiting_for_approval: bool,
        /// Local rows that stay local, by counter name (`awm team status`).
        pub skipped: BTreeMap<String, u64>,
        /// Milliseconds of every pull write transaction.
        pub apply_ms: Vec<u64>,
        /// Rows of every transaction that applied deletion entries or dropped team rows
        /// (retention, reconcile): at most `apply::CHUNK_ROWS` each (TM11).
        pub delete_tx_rows: Vec<usize>,
        /// The most rows any write transaction of the record or the deletion path held: at most
        /// `apply::CHUNK_ROWS` (RVT3 F18).
        pub max_rows_per_txn: usize,
        /// Items the server refused for good (400, 403, 413, 422 on a single-item push): dropped
        /// as markers, counted in `dropped.push_rejected` (RVT3 F17).
        pub rejected: usize,
        /// `sync_state.last_ok` before this run (`awm sync` after `pushed 0`, RVT3 F21).
        pub previous_ok_ms: Option<i64>,
        /// Rows left in `sync_outbox` when the run finished.
        pub outbox_left: usize,
        /// Eligible rows this run did not queue (`team.push_delay_s`, or pushes stopped).
        pub unqueued: usize,
        pub pull_ms: u64,
    }

    impl Report {
        /// The 95th percentile of the pull write transactions, in milliseconds.
        pub fn apply_p95_ms(&self) -> Option<u64> {
            if self.apply_ms.is_empty() {
                return None;
            }
            let mut v = self.apply_ms.clone();
            v.sort_unstable();
            Some(v[((v.len() as f64 * 0.95).ceil() as usize).clamp(1, v.len()) - 1])
        }
    }

    /// How a run ended.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Outcome {
        /// Another run holds the lock.
        Locked,
        /// A backoff is running until this time (a hook-started run only).
        BackedOff {
            until_ms: i64,
        },
        /// The database is not at this build's schema; the message says what to do.
        Refused(String),
        /// `--backfill --dry-run`: records that would be shared, and why the others stay.
        DryRun {
            would_share: usize,
            kept: BTreeMap<String, u64>,
        },
        Done(Report),
    }

    /// Everything a run holds. The steps (`push`, `pull`, `reseed`, `roster`) take it; `awm team`
    /// (TM12) does not need it.
    #[doc(hidden)]
    pub struct Session<'a> {
        pub(crate) env: &'a Env,
        pub(crate) opts: &'a Opts,
        pub(crate) conn: Connection,
        pub(crate) ident: Identity,
        pub(crate) ring: KeyRing,
        pub(crate) device: DeviceKeys,
        pub(crate) client: Client,
        pub(crate) status: Option<StatusResponse>,
        pub(crate) roster: Roster,
        /// `GET /v1/keys` was called in this run (a failed decryption fetches the keys once).
        pub(crate) keys_refreshed: bool,
        pub(crate) report: Report,
    }

    impl Session<'_> {
        pub(crate) fn now_ms(&self) -> i64 {
            self.env.now_ms.unwrap_or_else(crate::hook::now_ms)
        }
    }

    fn real_now(env: &Env) -> i64 {
        env.now_ms.unwrap_or_else(crate::hook::now_ms)
    }

    /// Takes the lock; `None` when another process holds it.
    fn take_lock(dir: &std::path::Path) -> Result<Option<std::fs::File>> {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let f = opts
            .open(dir.join(LOCK_FILE))
            .with_context(|| format!("cannot open {}", LOCK_FILE))?;
        match f.try_lock() {
            Ok(()) => Ok(Some(f)),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(e).context("cannot take sync.lock"),
        }
    }

    /// The first run with `team.share_all_projects` on records the time; a run with it off
    /// forgets it, so turning it on again starts a new window (RVT1 m14).
    fn track_share_all(conn: &Connection, cfg: &Config, now_ms: i64) -> Result<()> {
        if cfg.team.share_all_projects {
            if state::get(conn, state::SHARE_ALL_SINCE)?.is_none() {
                state::set(conn, state::SHARE_ALL_SINCE, &now_ms.to_string())?;
            }
            Ok(())
        } else {
            state::remove(conn, state::SHARE_ALL_SINCE)
        }
    }

    /// Runs `awm sync` once.
    pub fn run(env: &Env, opts: &Opts) -> Result<Outcome> {
        let dir = env.data_dir.as_path();
        if !state::configured(dir) && !opts.dry_run {
            bail!(
                "this machine is not in a team (no team.toml and team.key in the data directory)"
            );
        }
        let Some(_lock) = take_lock(dir)? else {
            return Ok(Outcome::Locked);
        };
        let db_path = dir.join(paths::DB_FILE);
        if !db_path.is_file() {
            bail!("no database at {}. Run: awm init", db_path.display());
        }
        let conn = db::open(&db_path, Role::Sync)?;
        match db::check_version(&conn)? {
            VersionCheck::Current => {}
            VersionCheck::Older { .. } => {
                return Ok(Outcome::Refused(
                    "database needs an upgrade. Run: awm doctor".into(),
                ))
            }
            VersionCheck::Newer { db, .. } => {
                return Ok(Outcome::Refused(format!(
                    "database is from a newer awm ({db}). Upgrade awm."
                )))
            }
        }
        let now = real_now(env);
        if opts.honour_backoff {
            if let Some(until_ms) = state::backoff_active(&conn, now)? {
                return Ok(Outcome::BackedOff { until_ms });
            }
        }
        track_share_all(&conn, &env.config, now)?;
        if opts.dry_run {
            let backfill = opts.backfill.as_ref();
            let scan = push::scan(&conn, &env.config, backfill, 100_000)?;
            return Ok(Outcome::DryRun {
                would_share: scan.candidates.len(),
                kept: scan.counts,
            });
        }
        let ident = Identity::load(dir)?;
        let ring = ident.ring()?;
        let ca = ident.team.ca_file.as_deref().map(std::path::Path::new);
        let client = Client::new(&ident.team.server_url, Some(&ident.key.device_token), ca)?;
        let mut s = Session {
            env,
            opts,
            device: ident.device_keys(),
            conn,
            ident,
            ring,
            client,
            status: None,
            roster: Roster::default(),
            keys_refreshed: false,
            report: Report::default(),
        };
        let previous_ok = state::get_i64(&s.conn, state::LAST_OK)?;
        match session(&mut s) {
            Ok(()) => {
                s.report.previous_ok_ms = previous_ok;
                s.report.outbox_left = s
                    .conn
                    .query_row("SELECT COUNT(*) FROM sync_outbox", [], |r| {
                        r.get::<_, i64>(0)
                    })?
                    .max(0) as usize;
                // Only a full run counts as the last successful sync (RVT3v V9): `team status`
                // and the `awm sync` waiting line would otherwise count a run that pushed (or
                // pulled) nothing by design.
                if !opts.pull_only && !opts.push_only {
                    state::record_success(&s.conn, real_now(env))?;
                }
                Ok(Outcome::Done(s.report))
            }
            Err(e) => {
                let retry_after = e.downcast_ref::<CallError>().and_then(|c| c.retry_after());
                let _ = state::record_failure(&s.conn, real_now(env), &e.to_string(), retry_after);
                Err(e)
            }
        }
    }

    fn cached_info(s: &mut Session<'_>) -> Result<InfoResponse> {
        let now = s.now_ms();
        if let (Some(at), Some(json)) = (
            state::get_i64(&s.conn, state::INFO_CACHED_AT)?,
            state::get(&s.conn, state::INFO_JSON)?,
        ) {
            if now - at < state::INFO_TTL_MS {
                if let Ok(info) = serde_json::from_str::<InfoResponse>(&json) {
                    return Ok(info);
                }
            }
        }
        let info = s.client.info()?;
        state::set(&s.conn, state::INFO_JSON, &serde_json::to_string(&info)?)?;
        state::set(&s.conn, state::INFO_CACHED_AT, &now.to_string())?;
        Ok(info)
    }

    /// `GET /v1/status`; after a restore a rotated token may be unknown (401): the previous one
    /// is tried once and, if it works, the token is rotated at once (sync-v1 §11 step 5).
    fn status(s: &mut Session<'_>) -> Result<StatusResponse> {
        match s.client.status() {
            Ok(st) => Ok(st),
            Err(e) if e.status() == Some(401) && s.ident.key.previous_device_token.is_some() => {
                let previous = s
                    .ident
                    .key
                    .previous_device_token
                    .clone()
                    .unwrap_or_default();
                let alt = s.client.with_token(Some(&previous));
                let st = alt.status().map_err(|_| e)?;
                let fresh = alt.rotate_token()?;
                s.ident.key.previous_device_token = Some(previous);
                s.ident.key.device_token = fresh.device_token.as_str().to_string();
                s.ident.save_key(&s.env.data_dir)?;
                s.client = s.client.with_token(Some(&s.ident.key.device_token));
                Ok(st)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn session(s: &mut Session<'_>) -> Result<()> {
        let info = cached_info(s)?;
        if !info.protocols.contains(&awm_proto::wire::PROTOCOL_VERSION) {
            bail!("the server speaks no protocol version this awm knows");
        }
        let status = status(s)?;
        let own = http::own_version();
        let blocked = [&info.min_client, &status.settings.min_client]
            .into_iter()
            .filter(|min| own < **min)
            .max()
            .cloned();
        match &blocked {
            Some(min) => {
                state::set(&s.conn, state::MIN_CLIENT_BLOCK, &min.to_string())?;
                s.report.push_blocked = Some(format!(
                    "this awm is older than the team's minimum {min}; upgrade awm"
                ));
            }
            None => state::remove(&s.conn, state::MIN_CLIENT_BLOCK)?,
        }
        if !status.approved {
            s.report.waiting_for_approval = true;
            s.status = Some(status);
            return Ok(());
        }
        s.status = Some(status);
        let epoch = s.status.as_ref().map_or(0, |st| st.current_epoch);
        if epoch > s.ring.current_epoch() {
            push::refresh_keys(s)?;
        }
        let now = s.now_ms();
        s.roster = roster::verify_and_store(&s.conn, &s.ring, now)?.0;

        // The re-seed, when the server's generation is not the stored one.
        let generation = s.status.as_ref().map(|st| st.generation.to_string());
        if let Some(g) = generation {
            match state::get(&s.conn, state::GENERATION)? {
                None => state::set(&s.conn, state::GENERATION, &g)?,
                Some(stored) if stored != g => reseed::run(s)?,
                Some(_) => {}
            }
        }

        if !s.opts.push_only {
            pull::run(s)?;
            let before = state::get(&s.conn, "reconciled_notice")?;
            pull::apply_deletions(s)?;
            if before.is_none() && state::get(&s.conn, "reconciled_notice")?.is_some() {
                s.report.reconciled = true;
                pull::run(s)?;
            }
            let expired = pull::prune_retention(s)?;
            // Backups at schema 3+ go after a remote deletion; FTS optimize at most once a day
            // (TM11).
            let deleted = s.report.deletions_applied + expired + usize::from(s.report.reconciled);
            let days = s.status.as_ref().map(|st| st.settings.retention_days);
            let now = s.now_ms();
            crate::sync::apply::after_deletions(&s.conn, &s.env.data_dir, deleted, days, now)?;
            s.roster = roster::verify_and_store(&s.conn, &s.ring, now)?.0;
        }
        if s.opts.pull_only {
            return Ok(());
        }

        let decide: ApproveFn = s.opts.approve.unwrap_or(crate::team::auto_approve);
        s.report.approvals += roster::approve_pending(s, &decide)?;
        s.report.rotated |= roster::rotate_if_needed(s)?;

        match push::run(s) {
            Ok(_) => {}
            Err(e) => {
                // A 426 is not a failure of the run: the state says so for `awm doctor`.
                let too_old = e
                    .downcast_ref::<CallError>()
                    .is_some_and(|c| c.code() == Some(ErrorCode::ClientTooOld));
                if !too_old {
                    return Err(e);
                }
                s.report.push_blocked = Some("the server refused this awm version (426)".into());
            }
        }
        Ok(())
    }

    /// Own member and device ids of a session, for the modules.
    impl Session<'_> {
        #[allow(dead_code)]
        pub(crate) fn ids(&self) -> (Id, Id) {
            (self.ident.team.member_id, self.ident.team.device_id)
        }
    }
}
