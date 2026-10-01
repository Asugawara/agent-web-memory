//! `awm forget`, `awm purge`, `awm quarantine`, `awm unquarantine`, and the data
//! part of `awm uninstall` (plan-v2 §6.4, §2.3).
//!
//! Every command shows what it selected and asks on a terminal unless `--yes`
//! is given. Without a terminal and without `--yes` it refuses, changes
//! nothing and exits with code 2.
//!
//! Deletion order (§6.4): injections that showed or mention the selected
//! records, then the records (cascading to `result`; `event_fts_ad` removes
//! them from the index), tombstones, then `optimize` of the FTS index and
//! `wal_checkpoint(TRUNCATE)`. `secure_delete=ON` (set by `db::open`) zeroes
//! freed pages and deleted cells. Backups `{db}.bak-v*` and spool files are
//! deleted last, because neither can be scrubbed partially.

use std::collections::BTreeSet;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::cli::{fmt_ts, parse_date};
use crate::db::{self, Role, VersionCheck};
use crate::normalize::norm_url;
use crate::note::{Status, Tool};
use crate::paths;
use crate::record::{sha256_hex, Record};

/// Replaces a forgotten URL inside text that is kept (summaries, queries, titles).
const SCRUBBED: &str = "[forgotten url]";
/// Records listed before a confirmation question.
const PREVIEW_ROWS: usize = 10;

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// `last` (the newest record) or a URL
    #[arg(
        value_name = "last|URL",
        conflicts_with_all = ["id", "ref_id"],
        required_unless_present_any = ["id", "ref_id"]
    )]
    pub target: Option<String>,
    /// Forget the record with this id (as printed by `awm log` and `awm search`)
    #[arg(long, value_name = "N", conflicts_with = "ref_id")]
    pub id: Option<i64>,
    /// Forget the records shown by one injection (the ref in `<awm-notes ref=...>`)
    #[arg(long = "ref", value_name = "REF")]
    pub ref_id: Option<String>,
    /// Do not ask for confirmation
    #[arg(long)]
    pub yes: bool,
}

#[derive(clap::Args, Debug, Default)]
pub struct PurgeArgs {
    /// Delete records, injections and hook runs older than this UTC date (YYYY-MM-DD)
    #[arg(
        long,
        value_name = "YYYY-MM-DD",
        conflicts_with = "all",
        required_unless_present = "all"
    )]
    pub before: Option<String>,
    /// Delete the whole data directory
    #[arg(long)]
    pub all: bool,
    /// Do not ask for confirmation
    #[arg(long)]
    pub yes: bool,
}

#[derive(clap::Args, Debug, Default)]
pub struct QuarantineArgs {
    /// A record id or a URL
    #[arg(value_name = "ID|URL")]
    pub target: String,
    /// Do not ask for confirmation
    #[arg(long)]
    pub yes: bool,
}

/// How a command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The change was made.
    Done,
    /// Nothing matched; nothing changed.
    Nothing,
    /// The user answered no; nothing changed.
    Declined,
    /// No terminal and no `--yes`; nothing changed.
    Refused,
}

impl Outcome {
    /// Process exit code: 2 for a refusal, else 0.
    pub fn exit_code(self) -> i32 {
        match self {
            Outcome::Refused => 2,
            _ => 0,
        }
    }
}

/// The environment of a command, injected for tests.
pub struct Io<'a> {
    pub data_dir: PathBuf,
    /// Whether stdin is a terminal (questions can be asked).
    pub terminal: bool,
    pub input: &'a mut dyn BufRead,
    pub out: &'a mut dyn Write,
    pub now_ms: i64,
}

/// What a deletion removed, as printed afterwards.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Deleted {
    pub events: usize,
    pub results: usize,
    pub injections: usize,
    pub hook_runs: usize,
    /// Kept records whose result rows or text were rewritten (`forget <url>`).
    pub updated: usize,
    pub tombstoned_ids: usize,
    pub tombstoned_url: bool,
    pub backups: Vec<PathBuf>,
    pub spool_files: usize,
    /// `wal_checkpoint(TRUNCATE)` could not finish because another connection was reading.
    pub wal_busy: bool,
}

/// Runs `f` with the process stdin, stdout and data dir.
pub fn with_stdio<T>(f: impl FnOnce(&mut Io<'_>) -> anyhow::Result<T>) -> anyhow::Result<T> {
    let stdin = std::io::stdin();
    let terminal = stdin.is_terminal();
    let mut input = stdin.lock();
    let mut out = std::io::stdout().lock();
    let mut io = Io {
        data_dir: paths::data_dir()?,
        terminal,
        input: &mut input,
        out: &mut out,
        now_ms: crate::cli::now_ms(),
    };
    f(&mut io)
}

/// Exits with code 2 after a refusal.
pub fn finish(outcome: Outcome) -> anyhow::Result<()> {
    if outcome == Outcome::Refused {
        std::io::stdout().flush()?;
        std::process::exit(outcome.exit_code());
    }
    Ok(())
}

pub fn run(args: Args) -> anyhow::Result<()> {
    finish(with_stdio(|io| run_forget(&args, io))?)
}

pub fn run_purge(args: PurgeArgs) -> anyhow::Result<()> {
    finish(with_stdio(|io| run_purge_with(&args, io))?)
}

pub fn run_quarantine(args: QuarantineArgs) -> anyhow::Result<()> {
    finish(with_stdio(|io| run_quarantine_with(&args, true, io))?)
}

pub fn run_unquarantine(args: QuarantineArgs) -> anyhow::Result<()> {
    finish(with_stdio(|io| run_quarantine_with(&args, false, io))?)
}

/// Asks `question` unless `yes`. `None` means go ahead.
fn confirm(
    io: &mut Io<'_>,
    yes: bool,
    question: &str,
    rerun: &str,
) -> anyhow::Result<Option<Outcome>> {
    if yes {
        return Ok(None);
    }
    if !io.terminal {
        writeln!(
            io.out,
            "No terminal for confirmation; nothing changed. Re-run with --yes: {rerun} --yes"
        )?;
        return Ok(Some(Outcome::Refused));
    }
    write!(io.out, "{question} [y/N] ")?;
    io.out.flush()?;
    let mut answer = String::new();
    io.input.read_line(&mut answer)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(None)
    } else {
        writeln!(io.out, "Nothing changed.")?;
        Ok(Some(Outcome::Declined))
    }
}

/// Opens the existing database of `data_dir` for writing; refuses a missing or mismatched schema.
fn open_db(data_dir: &Path) -> anyhow::Result<Connection> {
    let path = data_dir.join(paths::DB_FILE);
    if !path.is_file() {
        bail!("no database at {}. Run: awm init", path.display());
    }
    let conn = db::open(&path, Role::Cli)?;
    match db::check_version(&conn)? {
        VersionCheck::Current => Ok(conn),
        VersionCheck::Older { .. } => bail!("database needs an upgrade. Run: awm doctor"),
        VersionCheck::Newer { db, .. } => {
            bail!("database is from a newer awm ({db}). Upgrade awm.")
        }
    }
}

// ---------------------------------------------------------------------------
// Selection

/// One record as listed before a question.
struct Row {
    id: i64,
    tool_use_id: String,
    created_at: i64,
    tool: String,
    target: String,
}

fn rows(conn: &Connection, where_sql: &str, p: impl rusqlite::Params) -> anyhow::Result<Vec<Row>> {
    let sql = format!(
        "SELECT id, tool_use_id, created_at, tool, COALESCE(query, url, '') FROM event \
         WHERE {where_sql} ORDER BY created_at DESC, id DESC"
    );
    let mut st = conn.prepare(&sql)?;
    let found = st.query_map(p, |r| {
        Ok(Row {
            id: r.get(0)?,
            tool_use_id: r.get(1)?,
            created_at: r.get(2)?,
            tool: r.get(3)?,
            target: r.get(4)?,
        })
    })?;
    Ok(found.collect::<rusqlite::Result<_>>()?)
}

fn print_rows(out: &mut dyn Write, rows: &[Row]) -> anyhow::Result<()> {
    for r in rows.iter().take(PREVIEW_ROWS) {
        writeln!(
            out,
            "  #{}  {}  {}  {}",
            r.id,
            fmt_ts(r.created_at),
            r.tool,
            plain(&r.target)
        )?;
    }
    if rows.len() > PREVIEW_ROWS {
        writeln!(out, "  ... and {} more", rows.len() - PREVIEW_ROWS)?;
    }
    Ok(())
}

/// Control characters become spaces; stored text must not drive the terminal.
fn plain(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// A URL given to `forget <url>`.
struct UrlTarget {
    norm: String,
    /// ASCII-lowercased spellings searched for in kept text, longest first.
    needles: Vec<String>,
}

impl UrlTarget {
    fn new(norm: String, spellings: impl IntoIterator<Item = String>) -> UrlTarget {
        let mut set: BTreeSet<String> = spellings
            .into_iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        set.insert(norm.to_ascii_lowercase());
        let mut needles: Vec<String> = set.into_iter().collect();
        needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
        UrlTarget { norm, needles }
    }

    fn mentioned_in(&self, text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        self.needles
            .iter()
            .any(|n| !matches_of(&lower, n).is_empty())
    }

    fn scrub(&self, text: &str) -> String {
        let mut text = text.to_string();
        for n in &self.needles {
            let lower = text.to_ascii_lowercase();
            let found = matches_of(&lower, n);
            for (start, end) in found.into_iter().rev() {
                text.replace_range(start..end, SCRUBBED);
            }
        }
        text
    }
}

/// Byte ranges where `needle` occurs in `hay` as a whole URL: the next
/// character (after one optional `/`) must not continue a path or host.
/// `hay` must be ASCII-lowercased so the ranges are valid for the original text.
fn matches_of(hay: &str, needle: &str) -> Vec<(usize, usize)> {
    let continues = |c: char| c.is_alphanumeric() || "-_~%/".contains(c);
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(pos) = hay[from..].find(needle) {
        let start = from + pos;
        let mut end = start + needle.len();
        let rest = &hay[end..];
        let rest = match rest.strip_prefix('/') {
            Some(r) if !needle.ends_with('/') => {
                end += 1;
                r
            }
            _ => rest,
        };
        if !rest.chars().next().is_some_and(continues) {
            found.push((start, end));
        }
        from = start + needle.len().max(1);
    }
    found
}

/// What a deletion removes.
#[derive(Default)]
struct Selection {
    event_ids: Vec<i64>,
    tool_use_ids: Vec<String>,
    url: Option<UrlTarget>,
    /// `purge --before`: unix ms at 00:00 UTC of the date.
    before: Option<i64>,
}

impl Selection {
    fn of_rows(rows: &[Row]) -> Selection {
        Selection {
            event_ids: rows.iter().map(|r| r.id).collect(),
            tool_use_ids: rows.iter().map(|r| r.tool_use_id.clone()).collect(),
            ..Selection::default()
        }
    }
}

// ---------------------------------------------------------------------------
// forget

pub fn run_forget(args: &Args, io: &mut Io<'_>) -> anyhow::Result<Outcome> {
    let mut conn = open_db(&io.data_dir)?;
    let (rows, url, rerun) = if let Some(id) = args.id {
        let rows = rows(&conn, "id = ?1", [id])?;
        if rows.is_empty() {
            bail!("no record with id {id}");
        }
        (rows, None, format!("awm forget --id {id}"))
    } else if let Some(r) = &args.ref_id {
        let injection: Option<i64> = conn
            .query_row("SELECT id FROM injection WHERE ref = ?1", [r], |x| x.get(0))
            .optional()?;
        let injection = injection.ok_or_else(|| anyhow!("no injection with ref {r}"))?;
        let rows = rows(
            &conn,
            "id IN (SELECT event_id FROM injection_item WHERE injection_id = ?1)",
            [injection],
        )?;
        (rows, None, format!("awm forget --ref {r}"))
    } else {
        let target = args.target.as_deref().unwrap_or_default();
        if target == "last" {
            let rows = rows(
                &conn,
                "id = (SELECT id FROM event ORDER BY created_at DESC, id DESC LIMIT 1)",
                [],
            )?;
            (rows, None, "awm forget last".to_string())
        } else {
            let norm = norm_url(target)
                .ok_or_else(|| anyhow!("not a URL: {target:?} (use last, --id N or --ref REF)"))?;
            let rows = rows(&conn, "url_norm = ?1", [&norm])?;
            let mut spellings: Vec<String> = vec![target.to_string()];
            spellings.extend(rows.iter().map(|r| r.target.clone()));
            let mut st = conn.prepare("SELECT DISTINCT url FROM result WHERE url_norm = ?1")?;
            for u in st.query_map([&norm], |r| r.get::<_, String>(0))? {
                spellings.push(u?);
            }
            drop(st);
            (
                rows,
                Some(UrlTarget::new(norm, spellings)),
                format!("awm forget '{target}'"),
            )
        }
    };

    let mut sel = Selection::of_rows(&rows);
    sel.url = url;
    let preview = preview(&conn, &sel)?;
    if rows.is_empty() && sel.url.is_none() {
        writeln!(io.out, "Nothing to forget.")?;
        return Ok(Outcome::Nothing);
    }
    if !rows.is_empty() {
        writeln!(io.out, "Records to forget:")?;
        print_rows(io.out, &rows)?;
    }
    if let Some(u) = &sel.url {
        writeln!(
            io.out,
            "{} search record(s) list or mention {}; that part is removed from them.",
            preview.updated, u.norm
        )?;
        writeln!(
            io.out,
            "Future records of this URL are skipped (a SHA-256 of it is kept, not the URL)."
        )?;
    }
    writeln!(
        io.out,
        "Injection log entries to delete: {}.",
        preview.injections
    )?;
    let question = if rows.is_empty() && preview.updated == 0 && preview.injections == 0 {
        "Nothing stored for it. Skip it in future records?".to_string()
    } else {
        format!("Forget {} record(s) permanently?", rows.len())
    };
    if let Some(o) = confirm(io, args.yes, &question, &rerun)? {
        return Ok(o);
    }
    let deleted = apply(&mut conn, &sel, io.now_ms)?;
    drop(conn);
    let deleted = cleanup_files(&io.data_dir, deleted)?;
    print_deleted(io.out, &deleted)?;
    Ok(Outcome::Done)
}

/// Counts shown before the question; computed with the same rules as [`apply`].
struct Preview {
    injections: usize,
    updated: usize,
}

fn preview(conn: &Connection, sel: &Selection) -> anyhow::Result<Preview> {
    let affected = match &sel.url {
        Some(u) => affected_events(conn, u, &sel.event_ids)?,
        None => Affected::default(),
    };
    Ok(Preview {
        injections: injections_of(conn, sel, &affected)?.len(),
        updated: affected.all().len(),
    })
}

/// Kept records touched by `forget <url>`.
#[derive(Default)]
struct Affected {
    /// Search records with a `result` row of the URL.
    listing: BTreeSet<i64>,
    /// Records whose query, fetch prompt, summary or a result title mention it.
    mentioning: BTreeSet<i64>,
}

impl Affected {
    fn all(&self) -> BTreeSet<i64> {
        self.listing.union(&self.mentioning).copied().collect()
    }
}

fn affected_events(conn: &Connection, u: &UrlTarget, selected: &[i64]) -> anyhow::Result<Affected> {
    let selected: BTreeSet<i64> = selected.iter().copied().collect();
    let mut a = Affected::default();
    let mut st = conn.prepare("SELECT DISTINCT event_id FROM result WHERE url_norm = ?1")?;
    for id in st.query_map([&u.norm], |r| r.get::<_, i64>(0))? {
        a.listing.insert(id?);
    }
    let mut text_st = conn.prepare(
        "SELECT id, COALESCE(query, '') || char(10) || COALESCE(fetch_prompt, '') || char(10) \
                || COALESCE(summary, '') FROM event \
         WHERE instr(lower(COALESCE(query, '') || char(10) || COALESCE(fetch_prompt, '') \
                || char(10) || COALESCE(summary, '')), ?1) > 0",
    )?;
    let mut title_st = conn.prepare(
        "SELECT event_id, title FROM result \
         WHERE url_norm <> ?2 AND instr(lower(COALESCE(title, '')), ?1) > 0",
    )?;
    for n in &u.needles {
        for row in text_st.query_map([n], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))? {
            let (id, text) = row?;
            if u.mentioned_in(&text) {
                a.mentioning.insert(id);
            }
        }
        for row in title_st.query_map(params![n, u.norm], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })? {
            let (id, title) = row?;
            if u.mentioned_in(&title) {
                a.mentioning.insert(id);
            }
        }
    }
    a.listing.retain(|id| !selected.contains(id));
    a.mentioning.retain(|id| !selected.contains(id));
    Ok(a)
}

/// Step 1: injections that showed a selected record, were triggered by one,
/// are older than `before`, or (for a URL) mention it or showed a record that listed it.
fn injections_of(
    conn: &Connection,
    sel: &Selection,
    affected: &Affected,
) -> anyhow::Result<BTreeSet<i64>> {
    let mut ids = BTreeSet::new();
    let mut by_item =
        conn.prepare("SELECT DISTINCT injection_id FROM injection_item WHERE event_id = ?1")?;
    for event in sel.event_ids.iter().chain(&affected.listing) {
        for id in by_item.query_map([event], |r| r.get::<_, i64>(0))? {
            ids.insert(id?);
        }
    }
    let mut by_trigger = conn.prepare("SELECT id FROM injection WHERE tool_use_id = ?1")?;
    for t in &sel.tool_use_ids {
        for id in by_trigger.query_map([t], |r| r.get::<_, i64>(0))? {
            ids.insert(id?);
        }
    }
    if let Some(before) = sel.before {
        let mut st = conn.prepare("SELECT id FROM injection WHERE created_at < ?1")?;
        for id in st.query_map([before], |r| r.get::<_, i64>(0))? {
            ids.insert(id?);
        }
    }
    if let Some(u) = &sel.url {
        let mut st = conn.prepare(
            "SELECT id, COALESCE(trigger_text, '') || char(10) || COALESCE(rendered, '') \
             FROM injection \
             WHERE instr(lower(COALESCE(trigger_text, '') || char(10) || COALESCE(rendered, '')), ?1) > 0",
        )?;
        for n in &u.needles {
            for row in st.query_map([n], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))? {
                let (id, text) = row?;
                if u.mentioned_in(&text) {
                    ids.insert(id);
                }
            }
        }
    }
    Ok(ids)
}

fn count(conn: &Connection, table: &str) -> anyhow::Result<usize> {
    let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
    Ok(usize::try_from(n).unwrap_or(0))
}

/// Steps 1-5 of §6.4: one transaction, then FTS optimize and WAL truncation.
fn apply(conn: &mut Connection, sel: &Selection, now_ms: i64) -> anyhow::Result<Deleted> {
    let mut d = Deleted::default();
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let affected = match &sel.url {
        Some(u) => affected_events(&tx, u, &sel.event_ids)?,
        None => Affected::default(),
    };
    let injections = injections_of(&tx, sel, &affected)?;
    let (results_before, injections_before) = (count(&tx, "result")?, count(&tx, "injection")?);

    {
        let mut del = tx.prepare("DELETE FROM injection WHERE id = ?1")?;
        for id in &injections {
            del.execute([id])?;
        }
        let mut del = tx.prepare("DELETE FROM event WHERE id = ?1")?;
        for id in &sel.event_ids {
            d.events += del.execute([id])?;
        }
    }
    if let Some(u) = &sel.url {
        tx.execute("DELETE FROM result WHERE url_norm = ?1", [&u.norm])?;
        for id in affected.all() {
            rewrite_event(&tx, id, u)?;
        }
        d.updated = affected.all().len();
    }
    if let Some(before) = sel.before {
        d.hook_runs = tx.execute("DELETE FROM hook_run WHERE started_at < ?1", [before])?;
        // Integer unix ms, as capture and import parse it; never moved backwards.
        let old: Option<String> = tx
            .query_row(
                "SELECT value FROM meta WHERE key = 'purged_before'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let old = old.and_then(|v| v.trim().parse::<i64>().ok());
        let value = old.map_or(before, |o| o.max(before));
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('purged_before', ?1) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [value.to_string()],
        )?;
    }
    {
        let mut ins = tx.prepare(
            "INSERT OR IGNORE INTO tombstone (kind, value, created_at) VALUES (?1, ?2, ?3)",
        )?;
        for t in &sel.tool_use_ids {
            d.tombstoned_ids += ins.execute(params!["tool_use_id", t, now_ms])?;
        }
        if let Some(u) = &sel.url {
            ins.execute(params!["url_hash", sha256_hex(&u.norm), now_ms])?;
            d.tombstoned_url = true;
        }
    }
    d.results = results_before - count(&tx, "result")?;
    d.injections = injections_before - count(&tx, "injection")?;
    tx.commit()?;

    // Step 5: merge the FTS segments so deleted terms leave the index pages
    // (the freed pages are zeroed by secure_delete), then empty the WAL.
    conn.execute("INSERT INTO event_fts(event_fts) VALUES('optimize')", [])?;
    let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
    d.wal_busy = busy != 0;
    Ok(d)
}

/// Removes the forgotten URL from a kept record: its text and titles are
/// scrubbed and `match_text` is recomputed (the update trigger reindexes it).
fn rewrite_event(conn: &Connection, id: i64, u: &UrlTarget) -> anyhow::Result<()> {
    type Ev = (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
    );
    let (tool, query, url, fetch_prompt, summary, status): Ev = conn.query_row(
        "SELECT tool, query, url, fetch_prompt, summary, status FROM event WHERE id = ?1",
        [id],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        },
    )?;
    let scrub = |s: Option<String>| s.map(|s| u.scrub(&s));
    let (query, fetch_prompt, summary) = (scrub(query), scrub(fetch_prompt), scrub(summary));
    let mut results = Vec::new();
    {
        let mut st = conn.prepare(
            "SELECT rank, url, url_norm, title FROM result WHERE event_id = ?1 ORDER BY rank",
        )?;
        let found = st.query_map([id], |r| {
            Ok(crate::record::ResultRow {
                rank: r.get(0)?,
                url: r.get(1)?,
                url_norm: r.get(2)?,
                title: r.get(3)?,
            })
        })?;
        for row in found {
            let mut row = row?;
            if let Some(t) = &row.title {
                let clean = u.scrub(t);
                if &clean != t {
                    conn.execute(
                        "UPDATE result SET title = ?1 WHERE event_id = ?2 AND rank = ?3",
                        params![clean, id, row.rank],
                    )?;
                    row.title = Some(clean);
                }
            }
            results.push(row);
        }
    }
    let rec = Record {
        tool_use_id: String::new(),
        tool: Tool::from_db_str(&tool).ok_or_else(|| anyhow!("bad tool {tool}"))?,
        session_id: String::new(),
        agent_id: None,
        agent_type: None,
        cwd_hash: String::new(),
        created_at: 0,
        query: query.clone(),
        url,
        url_norm: None,
        fetch_prompt: fetch_prompt.clone(),
        http_code: None,
        bytes: None,
        duration_ms: None,
        status: Status::from_db_str(&status).unwrap_or(Status::Ok),
        summary: summary.clone(),
        match_text: String::new(),
        source: String::new(),
        results,
        quarantine_reason: None,
    };
    conn.execute(
        "UPDATE event SET query = ?1, fetch_prompt = ?2, summary = ?3, match_text = ?4 WHERE id = ?5",
        params![query, fetch_prompt, summary, rec.match_text(), id],
    )?;
    Ok(())
}

/// Step 6: backups `{db}.bak-v*` (also unfinished `.tmp` copies) and spool files.
fn cleanup_files(data_dir: &Path, mut d: Deleted) -> anyhow::Result<Deleted> {
    let prefix = format!("{}.bak-v", paths::DB_FILE);
    if let Ok(entries) = std::fs::read_dir(data_dir) {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().starts_with(&prefix) && e.path().is_file() {
                std::fs::remove_file(e.path())
                    .with_context(|| format!("cannot delete {}", e.path().display()))?;
                d.backups.push(e.path());
            }
        }
    }
    d.backups.sort();
    if let Ok(entries) = std::fs::read_dir(data_dir.join(paths::SPOOL_DIR)) {
        for e in entries.flatten() {
            if e.path().is_file() {
                std::fs::remove_file(e.path())
                    .with_context(|| format!("cannot delete {}", e.path().display()))?;
                d.spool_files += 1;
            }
        }
    }
    Ok(d)
}

fn print_deleted(out: &mut dyn Write, d: &Deleted) -> anyhow::Result<()> {
    writeln!(
        out,
        "Deleted {} record(s), {} result row(s), {} injection log entr{} and {} hook run(s).",
        d.events,
        d.results,
        d.injections,
        if d.injections == 1 { "y" } else { "ies" },
        d.hook_runs
    )?;
    if d.updated > 0 {
        writeln!(out, "Removed the URL from {} kept record(s).", d.updated)?;
    }
    writeln!(
        out,
        "Tombstoned {} tool_use id(s){}.",
        d.tombstoned_ids,
        if d.tombstoned_url {
            " and 1 URL hash"
        } else {
            ""
        }
    )?;
    if d.backups.is_empty() {
        writeln!(out, "Deleted 0 backups.")?;
    } else {
        let names: Vec<String> = d.backups.iter().map(|p| p.display().to_string()).collect();
        writeln!(
            out,
            "Deleted {} backup(s): {}.",
            d.backups.len(),
            names.join(", ")
        )?;
    }
    writeln!(out, "Deleted {} spool file(s).", d.spool_files)?;
    if d.wal_busy {
        writeln!(
            out,
            "Warning: another process has the database open, so awm.db-wal could not be emptied; \
             it may hold old copies of the deleted data until SQLite overwrites that space."
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// purge

pub fn run_purge_with(args: &PurgeArgs, io: &mut Io<'_>) -> anyhow::Result<Outcome> {
    if args.all {
        return purge_all(io, args.yes, "awm purge --all").map(|(o, _)| o);
    }
    let date = args.before.as_deref().unwrap_or_default();
    let before = parse_date(date)?;
    if before > io.now_ms {
        bail!(
            "{date} is in the future; records captured before it would be skipped until then. \
             To delete everything use: awm purge --all"
        );
    }
    let mut conn = open_db(&io.data_dir)?;
    let rows = rows(&conn, "created_at < ?1", [before])?;
    let mut sel = Selection::of_rows(&rows);
    sel.before = Some(before);
    let injections = injections_of(&conn, &sel, &Affected::default())?.len();
    let hook_runs: i64 = conn.query_row(
        "SELECT COUNT(*) FROM hook_run WHERE started_at < ?1",
        [before],
        |r| r.get(0),
    )?;
    writeln!(
        io.out,
        "Before {date} (00:00 UTC): {} record(s), {injections} injection log entr{}, {hook_runs} hook run(s).",
        rows.len(),
        if injections == 1 { "y" } else { "ies" },
    )?;
    print_rows(io.out, &rows)?;
    writeln!(
        io.out,
        "Records older than {date} found later by capture or import are skipped."
    )?;
    let question = format!("Delete {} record(s) permanently?", rows.len());
    if let Some(o) = confirm(
        io,
        args.yes,
        &question,
        &format!("awm purge --before {date}"),
    )? {
        return Ok(o);
    }
    let deleted = apply(&mut conn, &sel, io.now_ms)?;
    drop(conn);
    let deleted = cleanup_files(&io.data_dir, deleted)?;
    print_deleted(io.out, &deleted)?;
    Ok(Outcome::Done)
}

/// What `purge --all` found in the data dir before deleting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirSummary {
    pub bytes: u64,
    /// `None` when the database is missing or cannot be read.
    pub records: Option<i64>,
}

/// Names in the data dir that awm creates (plan-v2 §5.7, §6.2, `capture` spool).
fn ours(name: &str) -> bool {
    let db = paths::DB_FILE;
    name == db
        || name == format!("{db}-wal")
        || name == format!("{db}-shm")
        || name == format!("{db}-journal")
        || name.starts_with(&format!("{db}.bak-v"))
        || name == paths::CONFIG_FILE
        || name == paths::SPOOL_DIR
        || name == ".DS_Store"
}

fn dir_bytes(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => dir_bytes(&e.path()),
            Ok(t) if t.is_file() => e.metadata().map_or(0, |m| m.len()),
            _ => 0,
        })
        .sum()
}

fn record_count(data_dir: &Path) -> Option<i64> {
    let path = data_dir.join(paths::DB_FILE);
    if !path.is_file() {
        return None;
    }
    let conn = db::open(&path, Role::Cli).ok()?;
    conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0))
        .ok()
}

/// Formats a byte count as `3.6 MB` (decimal units).
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn describe(s: &DirSummary) -> String {
    match s.records {
        Some(n) => format!("{}, {n} records", human_size(s.bytes)),
        None => human_size(s.bytes),
    }
}

/// `purge --all` (also the data part of `awm uninstall`): prints the data dir,
/// its size and record count, asks, then deletes it. Only entries awm creates
/// are deleted; anything else is listed and the directory is kept.
/// Returns `(Outcome::Nothing, None)` when the directory does not exist.
pub fn purge_all(
    io: &mut Io<'_>,
    yes: bool,
    rerun: &str,
) -> anyhow::Result<(Outcome, Option<DirSummary>)> {
    let dir = io.data_dir.clone();
    if !dir.is_dir() {
        writeln!(
            io.out,
            "No data directory at {}; nothing to delete.",
            dir.display()
        )?;
        return Ok((Outcome::Nothing, None));
    }
    let summary = DirSummary {
        bytes: dir_bytes(&dir),
        records: record_count(&dir),
    };
    writeln!(
        io.out,
        "Data directory: {} ({})",
        dir.display(),
        describe(&summary)
    )?;
    let question = format!("Delete {} and everything awm stored in it?", dir.display());
    if let Some(o) = confirm(io, yes, &question, rerun)? {
        return Ok((o, Some(summary)));
    }
    let mut foreign = Vec::new();
    for e in std::fs::read_dir(&dir)
        .with_context(|| format!("cannot read {}", dir.display()))?
        .flatten()
    {
        let name = e.file_name().to_string_lossy().into_owned();
        let path = e.path();
        if !ours(&name) {
            foreign.push(name);
            continue;
        }
        let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
        let removed = if is_dir {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        removed.with_context(|| format!("cannot delete {}", path.display()))?;
    }
    if foreign.is_empty() {
        std::fs::remove_dir(&dir).with_context(|| format!("cannot delete {}", dir.display()))?;
        writeln!(
            io.out,
            "Deleted {} ({}).",
            dir.display(),
            describe(&summary)
        )?;
    } else {
        foreign.sort();
        writeln!(
            io.out,
            "Deleted awm's files in {} ({}). Kept the directory: it also holds {}, which awm did not create.",
            dir.display(),
            describe(&summary),
            foreign.join(", ")
        )?;
    }
    Ok((Outcome::Done, Some(summary)))
}

// ---------------------------------------------------------------------------
// quarantine

/// Sets `quarantined = 1` (with `reason`) on the given records so matching
/// skips them. Returns how many records changed.
pub fn quarantine_events(conn: &Connection, ids: &[i64], reason: &str) -> anyhow::Result<usize> {
    let mut st = conn.prepare(
        "UPDATE event SET quarantined = 1, quarantine_reason = COALESCE(quarantine_reason, ?2) \
         WHERE id = ?1 AND quarantined = 0",
    )?;
    let mut n = 0;
    for id in ids {
        n += st.execute(params![id, reason])?;
    }
    Ok(n)
}

/// Clears `quarantined` and `quarantine_reason`. Returns how many records changed.
pub fn unquarantine_events(conn: &Connection, ids: &[i64]) -> anyhow::Result<usize> {
    let mut st = conn.prepare(
        "UPDATE event SET quarantined = 0, quarantine_reason = NULL WHERE id = ?1 AND quarantined = 1",
    )?;
    let mut n = 0;
    for id in ids {
        n += st.execute([id])?;
    }
    Ok(n)
}

pub fn run_quarantine_with(
    args: &QuarantineArgs,
    on: bool,
    io: &mut Io<'_>,
) -> anyhow::Result<Outcome> {
    let conn = open_db(&io.data_dir)?;
    let target = args.target.trim();
    let flag = if on { 0 } else { 1 };
    let rows = if let Ok(id) = target.parse::<i64>() {
        let rows = rows(&conn, "id = ?1", [id])?;
        if rows.is_empty() {
            bail!("no record with id {id}");
        }
        rows
    } else {
        let norm = norm_url(target).ok_or_else(|| anyhow!("not a record id or URL: {target:?}"))?;
        rows(&conn, "url_norm = ?1", [&norm])?
    };
    let state = if on { "quarantined" } else { "not quarantined" };
    let ids: Vec<i64> = {
        let mut st = conn.prepare("SELECT 1 FROM event WHERE id = ?1 AND quarantined = ?2")?;
        let mut ids = Vec::new();
        for r in &rows {
            if st.exists(params![r.id, flag])? {
                ids.push(r.id);
            }
        }
        ids
    };
    if ids.is_empty() {
        writeln!(
            io.out,
            "No matching record that is {}.",
            if on { "not quarantined" } else { "quarantined" }
        )?;
        return Ok(Outcome::Nothing);
    }
    let picked: Vec<Row> = rows.into_iter().filter(|r| ids.contains(&r.id)).collect();
    writeln!(io.out, "Records to mark {state}:")?;
    print_rows(io.out, &picked)?;
    let verb = if on { "quarantine" } else { "unquarantine" };
    let question = format!("{} {} record(s)?", capitalise(verb), ids.len());
    if let Some(o) = confirm(io, args.yes, &question, &format!("awm {verb} '{target}'"))? {
        return Ok(o);
    }
    let n = if on {
        quarantine_events(&conn, &ids, "awm quarantine")?
    } else {
        unquarantine_events(&conn, &ids)?
    };
    writeln!(
        io.out,
        "{} {n} record(s).",
        if on {
            "Quarantined"
        } else {
            "Lifted the quarantine on"
        }
    )?;
    Ok(Outcome::Done)
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}
