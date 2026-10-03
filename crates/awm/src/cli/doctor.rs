//! `awm doctor`: installation checks, and the §8.2 transcript-based coverage and delivery metrics.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::bail;
use rusqlite::Connection;

use crate::capture::{self, CaptureOpts};
use crate::config;
use crate::db::{self, Role, VersionCheck};
use crate::import::transcript_files;
use crate::paths;

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Captured events over web tool calls found in transcripts
    #[arg(long)]
    pub coverage: bool,
    /// Shown injections whose ref appears in the transcript
    #[arg(long)]
    pub delivery: bool,
    /// Count `<awm-notes` in transcripts
    #[arg(long)]
    pub prompt_tags: bool,
    /// Transcript directory (default ~/.claude/projects)
    #[arg(long, value_name = "DIR")]
    pub projects: Option<PathBuf>,
    /// Only calls and injections on or after this date (YYYY-MM-DD)
    #[arg(long, value_name = "DATE")]
    pub since: Option<String>,
}

/// (captured, total) web tool calls.
#[derive(Debug, Default, Clone, Copy)]
pub struct Counts {
    pub captured: i64,
    pub total: i64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Coverage {
    pub main: Counts,
    pub subagent: Counts,
}

impl Coverage {
    pub fn all(&self) -> Counts {
        Counts {
            captured: self.main.captured + self.subagent.captured,
            total: self.main.total + self.subagent.total,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Delivery {
    pub delivered: i64,
    pub checked: i64,
    pub unreadable: i64,
}

fn ok(msg: &str) {
    println!("[ok]   {msg}");
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let dir = paths::data_dir()?;
    println!("data dir: {}", dir.display());
    let path = paths::db_path()?;
    if !path.is_file() {
        println!(
            "[fail] database not found at {}. Run: awm init",
            path.display()
        );
        bail!("doctor found a problem");
    }
    let mut conn = db::open(&path, Role::Cli)?;
    let mut failed = false;
    match db::check_version(&conn)? {
        VersionCheck::Current => ok(&format!(
            "database schema version {} is current",
            db::schema_version(&conn)?
        )),
        VersionCheck::Older { db: from, bin } => {
            let out = db::migrate(&mut conn)?;
            ok(&format!(
                "database upgraded from schema version {from} to {bin}{}",
                out.backup
                    .map(|b| format!(" (backup: {})", b.display()))
                    .unwrap_or_default()
            ));
        }
        VersionCheck::Newer { db: v, .. } => {
            println!("[fail] database is from a newer awm ({v}). Upgrade awm.");
            bail!("doctor found a problem");
        }
    }
    if db::has_fts5(&conn)? {
        ok("SQLite has FTS5");
    } else {
        println!("[fail] SQLite was built without FTS5");
        failed = true;
    }
    let quick: Vec<String> = conn
        .prepare("PRAGMA quick_check")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;
    if quick == ["ok"] {
        ok("quick_check passed");
    } else {
        println!("[fail] quick_check: {}", quick.join("; "));
        failed = true;
    }
    match conn.execute(
        "INSERT INTO event_fts(event_fts, rank) VALUES('integrity-check', 1)",
        [],
    ) {
        Ok(_) => ok("search index matches the records"),
        Err(e) => {
            println!("[fail] search index: {e}. Run: awm reindex");
            failed = true;
        }
    }
    let cfg = config::load(&paths::config_path()?)?;
    for w in &cfg.warnings {
        println!("[warn] {w}");
    }
    spool(&dir, &cfg)?;
    latency_summary(&conn)?;
    consent(&conn)?;
    quota_samples(&dir);
    // Only a machine in a team has this section; without `team.toml` the output is unchanged.
    if dir.join(crate::paths::TEAM_TOML).exists() {
        failed |= team_section(&dir);
    }

    let since = match &args.since {
        Some(d) => Some(super::parse_date(d)?),
        None => None,
    };
    if args.coverage || args.delivery || args.prompt_tags {
        let projects = super::projects_dir(&args.projects)?;
        if args.coverage {
            let c = coverage(&conn, &projects, since)?;
            print_coverage(&c);
        }
        if args.delivery {
            print_delivery(&delivery(&conn, since)?);
        }
        if args.prompt_tags {
            let (n, files) = prompt_tags(&projects);
            println!("prompt tags: {n} occurrences of <awm-notes in {files} transcript files");
        }
    }
    if failed {
        bail!("doctor found a problem");
    }
    Ok(())
}

fn spool(dir: &std::path::Path, cfg: &config::Config) -> anyhow::Result<()> {
    let spool_dir = dir.join(paths::SPOOL_DIR);
    let before = std::fs::read_dir(&spool_dir).map_or(0, Iterator::count);
    let opts = CaptureOpts {
        data_dir: dir.to_path_buf(),
        config: cfg.clone(),
        now_ms: super::now_ms(),
    };
    let drained = capture::drain_spool(&opts)?;
    let left = std::fs::read_dir(&spool_dir).map_or(0, Iterator::count);
    ok(&format!(
        "spool: {before} file(s) found, {drained} ingested, {left} left"
    ));
    Ok(())
}

fn latency_summary(conn: &Connection) -> anyhow::Result<()> {
    let mut total = Vec::new();
    let mut deadlines = 0;
    let mut st = conn.prepare(
        "SELECT total_ms, outcome FROM hook_run WHERE hook IN ('prompt','pre-fetch','post-tool')",
    )?;
    for r in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))? {
        let (ms, outcome) = r?;
        total.push(ms);
        if outcome == "deadline" {
            deadlines += 1;
        }
    }
    let n = i64::try_from(total.len()).unwrap_or(i64::MAX);
    if n == 0 {
        ok("hook latency: no sync hook runs recorded yet");
    } else {
        ok(&format!(
            "hook latency over {n} runs: p50 {} ms, p95 {} ms, deadline hits {}",
            super::percentile(&mut total.clone(), 50.0).unwrap_or(0),
            super::percentile(&mut total, 95.0).unwrap_or(0),
            super::pct(deadlines, n).unwrap_or_default()
        ));
    }
    Ok(())
}

fn consent(conn: &Connection) -> anyhow::Result<()> {
    match crate::hook::meta_value(conn, "consent.record")?.as_deref() {
        Some("yes") => ok("recording is on"),
        _ => println!("[warn] recording is off. Run: awm init --record"),
    }
    Ok(())
}

/// One line, never a failure.
fn quota_samples(dir: &std::path::Path) {
    let now = super::now_ms();
    let (n, newest) =
        crate::quota::store::recent(&dir.join(crate::quota::DIR), now - 24 * 3_600_000);
    match newest.filter(|_| n > 0) {
        Some(t) => {
            let mins = (now - t).max(0) / 60_000;
            let age = if mins >= 60 {
                format!("{}h{}m", mins / 60, mins % 60)
            } else if mins > 0 {
                format!("{mins}m")
            } else {
                format!("{}s", ((now - t).max(0) / 1000))
            };
            ok(&format!(
                "quota samples: {n} in the last 24 h (last {age} ago)"
            ));
        }
        None => ok(
            "quota samples: none in the last 24 h (optional; to enable: awm setup --statusline)",
        ),
    }
}

/// The team lines of `awm doctor` (plan-v3-team §4.9). They read `awm team status` rather than
/// repeating it; `true` when one is a `[fail]`. Nothing printed here holds a token, a key or
/// record text: the status carries none.
#[cfg(not(feature = "sync"))]
fn team_section(_dir: &std::path::Path) -> bool {
    println!("[warn] team.toml exists, but this build has no team support: nothing is synced");
    false
}

#[cfg(feature = "sync")]
fn team_section(dir: &std::path::Path) -> bool {
    use serde_json::Value;

    let v = match super::team::status_report(dir) {
        Ok(v) => v,
        Err(e) => {
            println!("[fail] team: {}", e.to_string().replace('\n', " "));
            return true;
        }
    };
    let text = |k: &str| v[k].as_str().map(str::to_string);
    let mut failed = false;
    ok(&format!(
        "team: @{} ({}) in organisation {} on {}",
        text("handle").unwrap_or_default(),
        text("role").unwrap_or_default(),
        text("org_id").unwrap_or_default(),
        text("server_url").unwrap_or_default()
    ));
    match text("server_error") {
        None => {
            ok("team server reachable");
            ok("team token accepted by the server");
        }
        Some(e) if e.contains(" 401") || e.contains("unauthorized") => {
            println!(
                "[fail] team token rejected by the server ({e}): ask an admin for a device \
                 invite (awm team add-device)"
            );
            failed = true;
        }
        Some(e) => {
            println!("[warn] team server not reachable: {e}");
            println!("[warn] team token not checked (the server did not answer)");
        }
    }
    match (&v["info"], text("min_client_block")) {
        (_, Some(m)) => println!(
            "[warn] team pushes stopped: this awm is older than the team's minimum {m}: upgrade awm"
        ),
        (Value::Object(i), None) => ok(&format!(
            "team protocol {}, min_client {} (this awm {})",
            i["protocols"]
                .as_array()
                .map(|a| a
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(","))
                .unwrap_or_default(),
            i["min_client"].as_str().unwrap_or("?"),
            env!("CARGO_PKG_VERSION")
        )),
        _ => ok("team protocol: not fetched yet (run: awm sync)"),
    }
    match (v["epoch"].as_u64(), v["server_epoch"].as_u64()) {
        (None, _) => {
            println!(
                "[fail] team key epochs: none present on this device (awm sync; awm team status)"
            );
            failed = true;
        }
        (Some(e), Some(s)) if s > e => println!(
            "[warn] team key epochs: this device has up to {e}, the server is at {s}: run awm sync"
        ),
        (Some(e), _) => ok(&format!("team key epochs present up to {e}")),
    }
    let approval = text("approval").unwrap_or_default();
    if approval == "approved" {
        ok("team approval: this device is approved");
    } else {
        println!("[warn] team approval: {approval}");
    }
    if let Some(p) = text("push_blocked") {
        println!("[warn] team pushes stopped: {p}");
    }
    if v["extra_admins_ignored"] == Value::Bool(true) {
        ok("team: trusted server admins are ignored while a verified admin exists");
    }
    ok(&format!(
        "team last sync: {}",
        text("last_ok").unwrap_or_else(|| "never".into())
    ));
    if let Some(b) = text("backoff_until") {
        println!("[warn] team sync backoff until {b}");
    }
    let last_error = text("last_error");
    if let Some(e) = &last_error {
        println!("[warn] team last error: {e}");
    }
    let counts = |k: &str| -> Vec<(String, u64)> {
        v[k].as_object()
            .map(|o| {
                o.iter()
                    .filter_map(|(r, n)| Some((r.clone(), n.as_u64()?)))
                    .filter(|(_, n)| *n > 0)
                    .collect()
            })
            .unwrap_or_default()
    };
    let outbox: u64 = v["outbox"]
        .as_object()
        .map(|o| o.values().filter_map(Value::as_u64).sum())
        .unwrap_or(0);
    ok(&format!("team outbox: {outbox} item(s) waiting to be sent"));
    for (title, key) in [
        ("kept local in the last run", "skipped"),
        ("dropped from teammates since joining", "dropped"),
    ] {
        let c = counts(key);
        if !c.is_empty() {
            println!(
                "[warn] team {title}: {}",
                c.iter()
                    .map(|(r, n)| format!("{r} {n}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    match v["streams_behind"].as_u64() {
        Some(0) => ok("team streams: none behind the server"),
        Some(n) => println!(
            "[warn] team streams: {n} behind the server; one that stays behind after awm sync has a gap"
        ),
        None => {}
    }
    if v["newer_schema"] == Value::Bool(true) {
        println!("[warn] team: a teammate's record needs a newer awm: upgrade awm");
    }
    if v["server_restored_before_join"] == Value::Bool(true) {
        println!(
            "[warn] team: the server was restored from a backup older than this device's join"
        );
    }
    // The server holds another record at a position of this device's stream: the data directory
    // was copied to another machine (RVT0 m7).
    if last_error
        .as_deref()
        .is_some_and(|e| e.contains("copied to another machine"))
    {
        println!(
            "[fail] team device id collision: the server holds another record where this device \
             writes next, so another machine uses this device id (a copied data directory). Take a \
             new device id through a device invite: on a machine in the team run awm team \
             add-device, then on this machine use a new data directory and awm team join"
        );
        failed = true;
    }
    failed
}

fn since_ok(ts: i64, since: Option<i64>) -> bool {
    since.is_none_or(|s| ts >= s)
}

/// Hook-captured events over web tool uses in transcripts of sessions where a hook ran.
pub fn coverage(
    conn: &Connection,
    projects: &std::path::Path,
    since: Option<i64>,
) -> anyhow::Result<Coverage> {
    let sessions: HashSet<String> = conn
        .prepare(
            "SELECT session_id FROM hook_run WHERE session_id IS NOT NULL \
             UNION SELECT session_id FROM event WHERE source = 'hook' AND origin = 'local'",
        )?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let captured: HashSet<String> = conn
        .prepare("SELECT tool_use_id FROM event WHERE source = 'hook' AND origin = 'local'")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut seen = HashSet::new();
    let mut cov = Coverage::default();
    for file in transcript_files(projects) {
        for call in super::web_calls_in(&file) {
            if !sessions.contains(&call.session_id)
                || !since_ok(call.ts_ms, since)
                || !seen.insert(call.tool_use_id.clone())
            {
                continue;
            }
            let c = if call.subagent {
                &mut cov.subagent
            } else {
                &mut cov.main
            };
            c.total += 1;
            if captured.contains(&call.tool_use_id) {
                c.captured += 1;
            }
        }
    }
    Ok(cov)
}

fn share(c: Counts) -> String {
    super::pct(c.captured, c.total).unwrap_or_else(|| "n/a".to_string())
}

fn print_coverage(c: &Coverage) {
    let all = c.all();
    println!(
        "capture coverage: {} ({} of {} web tool calls)",
        share(all),
        all.captured,
        all.total
    );
    println!(
        "  main: {} ({} of {})",
        share(c.main),
        c.main.captured,
        c.main.total
    );
    println!(
        "  subagent: {} ({} of {})",
        share(c.subagent),
        c.subagent.captured,
        c.subagent.total
    );
}

/// Shown injections with items whose ref (inject) or deny text reached the right transcript.
pub fn delivery(conn: &Connection, since: Option<i64>) -> anyhow::Result<Delivery> {
    let mut st = conn.prepare(
        "SELECT ref, mode, agent_id, tool_use_id, transcript_path, created_at FROM injection i \
         WHERE mode IN ('inject','deny') \
           AND EXISTS (SELECT 1 FROM injection_item ii WHERE ii.injection_id = i.id)",
    )?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, i64>(5)?,
        ))
    })?;
    let mut cache: HashMap<PathBuf, Option<String>> = HashMap::new();
    let mut d = Delivery::default();
    for row in rows {
        let (ref_id, mode, agent, tool_use_id, path, created) = row?;
        if !since_ok(created, since) {
            continue;
        }
        let file = path
            .as_deref()
            .and_then(|p| super::transcript_file(p, agent.as_deref()));
        let Some(file) = file else {
            d.unreadable += 1;
            continue;
        };
        let text = cache
            .entry(file.clone())
            .or_insert_with(|| std::fs::read_to_string(&file).ok());
        let Some(text) = text else {
            d.unreadable += 1;
            continue;
        };
        d.checked += 1;
        let found = text.lines().any(|l| {
            if mode == "deny" {
                tool_use_id.as_deref().is_some_and(|id| l.contains(id))
                    && l.contains("already fetched")
            } else {
                l.contains(&ref_id) && l.contains("awm-notes")
            }
        });
        if found {
            d.delivered += 1;
        }
    }
    Ok(d)
}

fn print_delivery(d: &Delivery) {
    println!(
        "delivery: {} ({} of {} shown injections found in transcripts)",
        super::pct(d.delivered, d.checked).unwrap_or_else(|| "n/a".to_string()),
        d.delivered,
        d.checked
    );
    if d.unreadable > 0 {
        println!("  not checkable (transcript missing): {}", d.unreadable);
    }
}

/// (occurrences, files with at least one) of `<awm-notes` under `projects`.
pub fn prompt_tags(projects: &std::path::Path) -> (usize, usize) {
    let mut n = 0;
    let mut files = 0;
    for file in transcript_files(projects) {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let c = text.matches("<awm-notes").count();
        if c > 0 {
            n += c;
            files += 1;
        }
    }
    (n, files)
}

/// Printed by `report`.
pub fn coverage_pct(c: Counts) -> Option<String> {
    super::pct(c.captured, c.total)
}
