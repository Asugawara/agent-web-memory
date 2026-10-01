//! Async capture: turns a PostToolUse payload into `event` and `result` rows
//! (plan-v2 §4.3, §5.4). Prints nothing; the hook wrapper always exits 0.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Context;
use rusqlite::{params, Connection, ErrorCode, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use url::Url;

use crate::config::{Config, Mode};
use crate::db::{self, Role, VersionCheck};
use crate::hosts;
use crate::paths;
use crate::record::{sha256_hex, Record};
use crate::sanitize;

#[derive(Debug, Clone)]
pub struct CaptureOpts {
    pub data_dir: PathBuf,
    pub config: Config,
    pub now_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureOutcome {
    Captured,
    Skipped(&'static str),
    Spooled,
    Off,
}

/// Re-runs spooled payloads, then captures `payload`.
pub fn run(payload: &Value, opts: &CaptureOpts) -> anyhow::Result<CaptureOutcome> {
    if opts.config.mode == Mode::Off {
        return Ok(CaptureOutcome::Off);
    }
    if let Err(e) = drain_spool(opts) {
        if std::env::var_os("AWM_DEBUG").is_some_and(|v| v == "1") {
            eprintln!("awm: cannot drain the spool: {e:#}");
        }
    }
    capture_one(payload, opts)
}

/// Re-runs every spool file, oldest first. Files that were captured or skipped
/// (and files that are not JSON) are deleted; a file that hits a lock again stays
/// and ends the pass. Returns the number of files deleted.
pub fn drain_spool(opts: &CaptureOpts) -> anyhow::Result<usize> {
    let dir = opts.data_dir.join(paths::SPOOL_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", dir.display())),
    };
    let mut files: Vec<(i64, PathBuf)> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| (spool_time(&p), p))
        .collect();
    files.sort();
    let mut deleted = 0;
    for (ts, path) in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // The spool holds the redacted record; anything else is not ours to keep.
        let Ok(rec) = serde_json::from_str::<Record>(&text) else {
            if std::fs::remove_file(&path).is_ok() {
                deleted += 1;
            }
            continue;
        };
        let mut o = opts.clone();
        o.now_ms = ts;
        match store(rec, &o, false) {
            Ok(CaptureOutcome::Spooled) => break,
            Ok(_) => {
                if std::fs::remove_file(&path).is_ok() {
                    deleted += 1;
                }
            }
            Err(e) if is_busy(&e) => break,
            Err(_) => {}
        }
    }
    Ok(deleted)
}

/// The `{now_ms}` prefix of a spool file name; 0 when it has none.
fn spool_time(path: &Path) -> i64 {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.split('-').next())
        .and_then(|t| t.parse().ok())
        .unwrap_or(0)
}

fn is_busy(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        matches!(
            c.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(f, _))
                if matches!(f.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
        )
    })
}

fn capture_one(payload: &Value, opts: &CaptureOpts) -> anyhow::Result<CaptureOutcome> {
    if !opts.data_dir.join(paths::DB_FILE).is_file() {
        return Ok(CaptureOutcome::Skipped("no database"));
    }
    let terms = &opts.config.capture.redact_terms;
    let Some(rec) = Record::from_hook(payload, opts.now_ms, terms)? else {
        return Ok(CaptureOutcome::Skipped("not a web tool"));
    };
    store(rec, opts, true)
}

/// Stores a redacted record, spooling it when the database is locked.
fn store(
    mut rec: Record,
    opts: &CaptureOpts,
    spool_on_busy: bool,
) -> anyhow::Result<CaptureOutcome> {
    let start = Instant::now();
    let db_path = opts.data_dir.join(paths::DB_FILE);
    if !db_path.is_file() {
        return Ok(CaptureOutcome::Skipped("no database"));
    }
    let mut conn = db::open(&db_path, Role::Capture)?;
    if db::check_version(&conn)? != VersionCheck::Current {
        return Ok(CaptureOutcome::Skipped("schema"));
    }
    let agent_kind = if rec.agent_id.is_some() {
        "subagent"
    } else {
        "main"
    };

    let skip = match decide(&conn, &mut rec, &opts.config) {
        Ok(skip) => skip,
        Err(e) if is_busy(&e) && spool_on_busy => return spool(&rec, opts, &conn),
        Err(e) => return Err(e),
    };
    let outcome = match skip {
        Some(reason) => CaptureOutcome::Skipped(reason),
        None => {
            quarantine(&mut rec);
            match insert(&mut conn, &rec) {
                Ok(true) => CaptureOutcome::Captured,
                Ok(false) => CaptureOutcome::Skipped("duplicate"),
                Err(e) if is_busy(&e) && spool_on_busy => return spool(&rec, opts, &conn),
                Err(e) => return Err(e),
            }
        }
    };
    let label = if outcome == CaptureOutcome::Captured {
        "captured"
    } else {
        "skipped"
    };
    let total_ms = i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX);
    // The record is already stored; a lost log row is not worth a spool file.
    let _ = conn.execute(
        "INSERT INTO hook_run (started_at, hook, session_id, agent_kind, total_ms, outcome) \
         VALUES (?1, 'capture', ?2, ?3, ?4, ?5)",
        params![opts.now_ms, rec.session_id, agent_kind, total_ms, label],
    );
    Ok(outcome)
}

/// Reads tombstones and `purged_before`, applies the private-host rules and
/// drops private result rows. Returns the reason to skip, if any.
fn decide(
    conn: &Connection,
    rec: &mut Record,
    config: &Config,
) -> anyhow::Result<Option<&'static str>> {
    let exclude = &config.capture.exclude_hosts;
    let private = |u: &str| Url::parse(u).map_or(true, |u| hosts::is_private(&u, exclude));
    match &rec.url {
        Some(url) => {
            if private(url) {
                return Ok(Some("private host"));
            }
        }
        None => {
            if !rec.results.is_empty() && rec.results.iter().all(|r| private(&r.url)) {
                return Ok(Some("private host"));
            }
            rec.results.retain(|r| !private(&r.url));
            for (i, r) in rec.results.iter_mut().enumerate() {
                r.rank = i64::try_from(i).unwrap_or(i64::MAX) + 1;
            }
            rec.match_text = rec.match_text();
        }
    }

    let tombstoned = |kind: &str, value: &str| -> anyhow::Result<bool> {
        Ok(conn
            .query_row(
                "SELECT 1 FROM tombstone WHERE kind = ?1 AND value = ?2",
                params![kind, value],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    };
    if tombstoned("tool_use_id", &rec.tool_use_id)? {
        return Ok(Some("tombstone"));
    }
    if let Some(norm) = &rec.url_norm {
        if tombstoned("url_hash", &sha256_hex(norm))? {
            return Ok(Some("tombstone"));
        }
    }
    let purged: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'purged_before'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(before) = purged.and_then(|v| v.trim().parse::<i64>().ok()) {
        if rec.created_at < before {
            return Ok(Some("purged"));
        }
    }
    Ok(None)
}

/// Sets `quarantine_reason` (§4.3): the summary decides; a marker phrase in the
/// fetch prompt or query also quarantines.
fn quarantine(rec: &mut Record) {
    rec.quarantine_reason = sanitize::record_quarantine_reason(
        rec.summary.as_deref(),
        rec.fetch_prompt.as_deref(),
        rec.query.as_deref(),
    );
}

/// Inserts the event and its results in one transaction; `false` when the
/// `tool_use_id` already exists.
fn insert(conn: &mut Connection, rec: &Record) -> anyhow::Result<bool> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let inserted = tx.execute(
        "INSERT INTO event (tool_use_id, tool, session_id, agent_id, agent_type, cwd_hash, \
         created_at, query, url, url_norm, fetch_prompt, http_code, bytes, duration_ms, status, \
         summary, match_text, source, quarantined, quarantine_reason) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, \
         ?19, ?20) ON CONFLICT(tool_use_id) DO NOTHING",
        params![
            rec.tool_use_id,
            rec.tool.as_db_str(),
            rec.session_id,
            rec.agent_id,
            rec.agent_type,
            rec.cwd_hash,
            rec.created_at,
            rec.query,
            rec.url,
            rec.url_norm,
            rec.fetch_prompt,
            rec.http_code,
            rec.bytes,
            rec.duration_ms,
            rec.status.as_db_str(),
            rec.summary,
            rec.match_text,
            rec.source,
            i64::from(rec.quarantine_reason.is_some()),
            rec.quarantine_reason,
        ],
    )?;
    if inserted == 0 {
        return Ok(false);
    }
    let event_id = tx.last_insert_rowid();
    {
        let mut st = tx.prepare(
            "INSERT INTO result (event_id, rank, url, url_norm, title) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for r in &rec.results {
            st.execute(params![event_id, r.rank, r.url, r.url_norm, r.title])?;
        }
    }
    tx.commit()?;
    Ok(true)
}

/// Writes the redacted record to `{data_dir}/spool/{now_ms}-{tool_use_id}.json` (0600).
fn spool(rec: &Record, opts: &CaptureOpts, conn: &Connection) -> anyhow::Result<CaptureOutcome> {
    let dir = opts.data_dir.join(paths::SPOOL_DIR);
    paths::ensure_private_dir(&dir)?;
    let id: String = rec
        .tool_use_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let name = format!("{}-{id}.json", opts.now_ms);
    let tmp = dir.join(format!("{name}.tmp"));
    let target = dir.join(&name);
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    {
        use std::io::Write;
        let mut f = open
            .open(&tmp)
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        f.write_all(serde_json::to_string(rec)?.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &target)
        .with_context(|| format!("cannot move the spool file to {}", target.display()))?;
    // Best effort and without waiting: the database is locked.
    let _ = conn.busy_timeout(std::time::Duration::ZERO);
    let _ = conn.execute(
        "INSERT INTO hook_run (started_at, hook, session_id, agent_kind, total_ms, outcome) \
         VALUES (?1, 'capture', ?2, ?3, 0, 'spooled')",
        params![
            opts.now_ms,
            rec.session_id,
            if rec.agent_id.is_some() {
                "subagent"
            } else {
                "main"
            }
        ],
    );
    Ok(CaptureOutcome::Spooled)
}
