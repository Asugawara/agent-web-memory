//! Cutoff calibration (plan-v2 §3.3).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};

use super::{query_channel, MatchOpts};
use crate::db::{self, Role};
use crate::paths;

pub const DEFAULT_CUTOFF_QUERY: f64 = 42.0;
pub const DEFAULT_CUTOFF_PROMPT: f64 = 49.0;
/// Fewer records than this keep the defaults.
pub const MIN_RECORDS: usize = 50;
const SAMPLE: i64 = 500;

#[derive(Debug, Clone, PartialEq)]
pub struct Calibration {
    pub cutoff_query: f64,
    pub cutoff_prompt: Option<f64>,
    /// Records with text that were sampled.
    pub n: usize,
}

#[derive(clap::Args, Debug, Default)]
pub struct Args {}

fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()?)
}

fn meta_set(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn meta_f64(conn: &Connection, key: &str) -> Result<Option<f64>> {
    Ok(meta_get(conn, key)?.and_then(|v| v.parse().ok()))
}

/// Records of this machine: teammates' rows (`origin = 'team'`) change neither the count nor the
/// sample (RVT0 M15).
fn record_count(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM event WHERE origin = 'local'",
        [],
        |r| r.get(0),
    )?)
}

/// A copy of the database without teammates' rows, for the scores: BM25 weighs a term by how
/// rare it is among all indexed documents, so teammates' text would move the cutoff even if
/// their rows could never be a hit. Deleted with its journal files when dropped.
///
/// The copy holds every teammate row until they are deleted from it, so a process killed in
/// between (a hook timeout, a session end) leaves one behind: it lives in `{data}/tmp/` (mode
/// 0700) as `awm.db.calibrate-{pid}-{nanos}`, the next calibration, `awm forget` and a remote
/// deletion remove the stale ones ([`sweep_stale_copies`]), and `awm purge --all` and
/// `awm uninstall` delete the directory (RVT3 F7).
struct LocalCopy {
    path: std::path::PathBuf,
    conn: Connection,
}

/// The name prefix of a calibration copy in `{data}/tmp/`.
pub const COPY_PREFIX: &str = "awm.db.calibrate-";
/// A copy older than this is stale whatever its process.
const COPY_MAX_AGE: Duration = Duration::from_secs(3_600);

/// Whether `name` is a calibration copy or one of its journal files.
pub fn is_copy_name(name: &str) -> bool {
    name.starts_with(COPY_PREFIX)
}

/// The pid and creation time (Unix nanoseconds) in a copy's name, journal suffixes included.
fn copy_parts(name: &str) -> Option<(u32, u128)> {
    let mut it = name.strip_prefix(COPY_PREFIX)?.split('-');
    let pid = it.next()?.parse().ok()?;
    let nanos = it.next()?.parse().ok()?;
    Some((pid, nanos))
}

/// Whether process `pid` still runs (on unix, `kill -0`; elsewhere assumed to run, so only the
/// age rule applies).
fn pid_alive(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    if Path::new("/proc/self").is_dir() {
        return Path::new("/proc").join(pid.to_string()).exists();
    }
    #[cfg(unix)]
    {
        // A failure to ask counts as alive: the copy then goes after an hour.
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_or(true, |s| s.success())
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Deletes the stale calibration copies in `{data_dir}/tmp/`: those whose process no longer
/// runs, those older than an hour, and names that do not parse. Returns the deleted paths. A
/// missing directory, or a `tmp` that is not a real directory, deletes nothing.
pub fn sweep_stale_copies(data_dir: &Path) -> Result<Vec<PathBuf>> {
    let dir = data_dir.join(paths::TMP_DIR);
    let mut gone = Vec::new();
    if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
        return Ok(gone);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut alive: std::collections::HashMap<u32, bool> = std::collections::HashMap::new();
    for e in std::fs::read_dir(&dir)?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !is_copy_name(&name) || !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let stale = match copy_parts(&name) {
            Some((pid, nanos)) => {
                now.saturating_sub(nanos) > COPY_MAX_AGE.as_nanos()
                    || !*alive.entry(pid).or_insert_with(|| pid_alive(pid))
            }
            None => true,
        };
        if stale {
            std::fs::remove_file(e.path())?;
            gone.push(e.path());
        }
    }
    gone.sort();
    Ok(gone)
}

impl LocalCopy {
    /// `None` when the database holds no teammate row (the scores then use the database itself),
    /// or when `{data}/tmp` exists but is not a real directory.
    fn of(conn: &Connection) -> Result<Option<LocalCopy>> {
        let team: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM event WHERE origin = 'team' LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if team.is_none() {
            return Ok(None);
        }
        let Some(db_path) = conn.path().map(PathBuf::from) else {
            return Ok(None);
        };
        let Some(data_dir) = db_path.parent() else {
            return Ok(None);
        };
        let dir = data_dir.join(paths::TMP_DIR);
        match std::fs::symlink_metadata(&dir) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Ok(None),
            Err(_) => paths::ensure_private_dir(&dir)?,
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        sweep_stale_copies(data_dir)?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = dir.join(format!("{COPY_PREFIX}{}-{nanos}", std::process::id()));
        // An empty private file: `VACUUM INTO` accepts it, and the copy is never world-readable.
        let mut open = std::fs::OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        open.open(&path)?;
        let made = (|| -> Result<Connection> {
            conn.execute("VACUUM INTO ?1", [path.to_string_lossy().as_ref()])?;
            let copy = Connection::open(&path)?;
            copy.execute("DELETE FROM event WHERE origin = 'team'", [])?;
            Ok(copy)
        })();
        match made {
            Ok(copy) => Ok(Some(LocalCopy { path, conn: copy })),
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                Err(e)
            }
        }
    }
}

impl Drop for LocalCopy {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut name = self.path.clone().into_os_string();
            name.push(suffix);
            let _ = std::fs::remove_file(name);
        }
    }
}

fn median(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

/// Stored query cutoff, or the default.
pub fn cutoff_query(conn: &Connection) -> Result<f64> {
    Ok(meta_f64(conn, "cutoff.query")?.unwrap_or(DEFAULT_CUTOFF_QUERY))
}

/// Stored prompt cutoff, or the default.
pub fn cutoff_prompt(conn: &Connection) -> Result<f64> {
    Ok(meta_f64(conn, "cutoff.prompt")?.unwrap_or(DEFAULT_CUTOFF_PROMPT))
}

/// Sets `meta.cutoff.query` to the median top-1 score of the 500 most recent
/// records with text, each searched against strictly older records (rules 1 and 3
/// only). Records without any hit have no score and are left out of the median.
/// `meta.calibrated_n` is the total record count, which [`should_recalibrate`] compares.
pub fn run(conn: &Connection) -> Result<Calibration> {
    let recent: Vec<(String, String, i64)> = {
        let mut st = conn.prepare(
            "SELECT tool_use_id, COALESCE(query, fetch_prompt), created_at FROM event \
             WHERE COALESCE(query, fetch_prompt, '') != '' AND origin = 'local' \
             ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = st.query_map([SAMPLE], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let n = recent.len();
    let copy = if n < MIN_RECORDS {
        None
    } else {
        // A copy that cannot be made (a hook inside a transaction, a full disk) must not fail the
        // calibration: the scores then come from the live database.
        LocalCopy::of(conn).unwrap_or(None)
    };
    let corpus = copy.as_ref().map_or(conn, |c| &c.conn);
    let cutoff_query = if n < MIN_RECORDS {
        DEFAULT_CUTOFF_QUERY
    } else {
        let mut scores = Vec::new();
        for (tool_use_id, text, created_at) in &recent {
            let opts = MatchOpts {
                caller_tool_use_id: Some(tool_use_id.clone()),
                before_ms: Some(*created_at),
                limit: 1,
                ..MatchOpts::default()
            };
            if let Some(hit) = query_channel(corpus, text, f64::NEG_INFINITY, &opts)?.first() {
                scores.push(hit.score);
            }
        }
        scores.sort_by(f64::total_cmp);
        if scores.is_empty() {
            DEFAULT_CUTOFF_QUERY
        } else {
            median(&scores)
        }
    };
    meta_set(conn, "cutoff.query", &cutoff_query.to_string())?;
    meta_set(conn, "calibrated_at", &now_ms().to_string())?;
    meta_set(conn, "calibrated_n", &record_count(conn)?.to_string())?;
    let stored_prompt = meta_f64(conn, "cutoff.prompt")?;
    let cutoff_prompt = stored_prompt.or((n < MIN_RECORDS).then_some(DEFAULT_CUTOFF_PROMPT));
    Ok(Calibration {
        cutoff_query,
        cutoff_prompt,
        n,
    })
}

/// True when the record count has doubled since `meta.calibrated_n`, or when it never ran.
pub fn should_recalibrate(conn: &Connection) -> Result<bool> {
    let count = record_count(conn)?;
    Ok(
        match meta_get(conn, "calibrated_n")?.and_then(|v| v.parse::<i64>().ok()) {
            None => true,
            Some(n) => count >= n.max(1) * 2,
        },
    )
}

/// Stores `meta.cutoff.prompt`: the 75th percentile (nearest rank) of the prompt top-1 scores.
/// An empty slice changes nothing.
pub fn set_prompt_cutoff(conn: &Connection, scores: &[f64]) -> Result<()> {
    if scores.is_empty() {
        return Ok(());
    }
    let mut s = scores.to_vec();
    s.sort_by(f64::total_cmp);
    let idx = ((s.len() - 1) as f64 * 0.75).round() as usize;
    meta_set(conn, "cutoff.prompt", &s[idx].to_string())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// `awm calibrate`.
pub fn run_cli(_args: Args) -> Result<()> {
    let conn = db::open(&paths::db_path()?, Role::Cli)?;
    let c = run(&conn)?;
    println!("cutoff.query  {:.2}", c.cutoff_query);
    match c.cutoff_prompt {
        Some(p) => println!("cutoff.prompt {p:.2}"),
        None => println!("cutoff.prompt not set (computed during import)"),
    }
    println!("records       {}", c.n);
    if c.n < MIN_RECORDS {
        println!("fewer than {MIN_RECORDS} records: defaults in use");
    }
    Ok(())
}
