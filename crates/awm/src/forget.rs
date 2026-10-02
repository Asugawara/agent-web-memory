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
//! deleted last, because neither can be scrubbed partially; they are deleted
//! even when `optimize` or the checkpoint fails after the commit.
//!
//! `forget <url>` and `purge --before` select their records again inside the
//! deleting transaction, so a record stored while the question waited goes too.
//!
//! In a team (`team.toml` exists; plan-v3-team §3.6, TM11) the commands take
//! `sync.lock` first (waiting up to 10 s, then refusing) and, inside the same
//! transaction, record the remote side of every deleted row that has a
//! `sync_id`, pushed or not (`sync::apply::own_deletion`): the member's own rows,
//! including copies of the member's other machines' records, are deleted on the
//! server; teammates' rows are deleted on this machine only. The deletions are
//! sent in the foreground after the commit and stay queued in `sync_outbox` when
//! the server does not answer. `purge` deletes remotely first and refuses
//! offline unless `--local-only`; `purge --all` runs `awm team leave --delete`
//! first. A build without the `sync` feature queues the deletions and refuses
//! `purge` without `--local-only`.

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
use crate::record::{sha256_hex, Agent, Record};

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
    /// In a team: delete on this machine only; your shared records stay on the server
    #[arg(long)]
    pub local_only: bool,
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
    /// `purge --all`: the data dir holds entries awm did not create; nothing changed.
    Foreign,
}

impl Outcome {
    /// Process exit code: 2 for a refusal, else 0.
    pub fn exit_code(self) -> i32 {
        match self {
            Outcome::Refused | Outcome::Foreign => 2,
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
    /// In a team: the remote side (§3.6).
    pub remote: Option<Remote>,
    /// Record ids whose remote deletion this command recorded (not printed).
    pub own_ids: Vec<String>,
}

/// The remote side of a deletion in a team, as printed afterwards (plan-v3-team §4.9).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Remote {
    /// Own shared records deleted on the server by this command.
    pub sent: usize,
    /// Deletions left in `sync_outbox` for the next `awm sync` (the server did not answer).
    pub queued: usize,
    /// `--local-only`: own shared records that stay on the server.
    pub kept: Option<usize>,
    /// Own shared records rewritten by `forget <url>`: deleted on the server, shared again
    /// (under a new record id) by the next `awm sync`.
    pub superseded: usize,
    /// Teammates' records deleted on this machine only.
    pub teammates: usize,
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

/// Exits with code 2 after a refusal or when `purge --all` found foreign entries.
pub fn finish(outcome: Outcome) -> anyhow::Result<()> {
    if outcome.exit_code() != 0 {
        std::io::stdout().flush()?;
        std::process::exit(outcome.exit_code());
    }
    Ok(())
}

/// Quotes `s` for a POSIX shell: single quotes, with `'` written as `'\''`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
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
#[derive(Clone)]
struct UrlTarget {
    /// The argument as given.
    arg: String,
    norm: String,
    /// ASCII-lowercased spellings searched for in kept text, longest first.
    needles: Vec<String>,
}

impl UrlTarget {
    fn new(arg: &str, norm: String, spellings: impl IntoIterator<Item = String>) -> UrlTarget {
        let mut set: BTreeSet<String> = spellings
            .into_iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        set.insert(norm.to_ascii_lowercase());
        let mut needles: Vec<String> = set.into_iter().collect();
        needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
        UrlTarget {
            arg: arg.to_string(),
            norm,
            needles,
        }
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
#[derive(Default, Clone)]
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

    /// `forget <url>` and `purge --before` select again (inside the deleting
    /// transaction), so records stored after the question are included.
    /// `forget last`, `--id` and `--ref` keep the confirmed set (`None`).
    fn reselect(&self, conn: &Connection) -> anyhow::Result<Option<Selection>> {
        if let Some(u) = &self.url {
            let (rows, url) = select_url(conn, &u.arg, &u.norm)?;
            return Ok(Some(Selection {
                url: Some(url),
                ..Selection::of_rows(&rows)
            }));
        }
        if let Some(before) = self.before {
            let rows = rows(conn, "created_at < ?1", [before])?;
            return Ok(Some(Selection {
                before: Some(before),
                ..Selection::of_rows(&rows)
            }));
        }
        Ok(None)
    }
}

/// Records with the URL's `url_norm`, and the spellings searched for in kept
/// text: the argument, the stored URLs of those records and of result rows.
fn select_url(conn: &Connection, arg: &str, norm: &str) -> anyhow::Result<(Vec<Row>, UrlTarget)> {
    let rows = rows(conn, "url_norm = ?1", [norm])?;
    let mut spellings: Vec<String> = vec![arg.to_string()];
    spellings.extend(rows.iter().map(|r| r.target.clone()));
    let mut st = conn.prepare("SELECT DISTINCT url FROM result WHERE url_norm = ?1")?;
    for u in st.query_map([norm], |r| r.get::<_, String>(0))? {
        spellings.push(u?);
    }
    drop(st);
    let url = UrlTarget::new(arg, norm.to_string(), spellings);
    Ok((rows, url))
}

// ---------------------------------------------------------------------------
// Team side (plan-v3-team §3.6; TM11)

/// The member id in `team.toml`, read without the `sync` feature; `None` outside a team.
fn team_member(dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(dir.join(crate::cli::where_::TEAM_TOML)).ok()?;
    let table = text.parse::<toml::Table>().ok()?;
    table.get("member_id")?.as_str().map(str::to_string)
}

/// The member's shared records this machine knows of: own captures the server accepted and
/// copies of the member's other machines' records.
fn own_shared(conn: &Connection, member: &str) -> anyhow::Result<usize> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM event WHERE sync_id IS NOT NULL \
           AND ((origin = 'local' AND pushed_at IS NOT NULL) OR (origin = 'team' AND member = ?1))",
        [member],
        |r| r.get(0),
    )?;
    Ok(usize::try_from(n).unwrap_or(0))
}

/// This machine in a team, while a command that deletes runs.
struct Team {
    member: String,
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    dir: PathBuf,
    /// `purge --local-only`: nothing is sent or queued.
    local_only: bool,
    /// `sync.lock`, held until the command ends (§3.6).
    _lock: std::fs::File,
}

impl Team {
    /// `None` outside a team; in one, takes `sync.lock` (waiting up to 10 s, then refusing).
    fn join(dir: &Path, local_only: bool) -> anyhow::Result<Option<Team>> {
        let Some(member) = team_member(dir) else {
            return Ok(None);
        };
        let lock = crate::sync::apply::lock_sync(dir)?;
        Ok(Some(Team {
            member,
            dir: dir.to_path_buf(),
            local_only,
            _lock: lock,
        }))
    }

    /// `POST /v1/delete {ids}` now, before anything local is deleted (`purge`). `Err` inside
    /// `Ok` says why the server could not be asked (offline, 5xx, 429, no team key).
    #[cfg(feature = "sync")]
    fn delete_now(&self, ids: &[String]) -> anyhow::Result<Result<(), String>> {
        use awm_proto::wire::{limits, DeleteRequest, Id};
        let ident = match crate::sync::state::Identity::load(&self.dir) {
            Ok(i) => i,
            Err(e) => return Ok(Err(e.to_string())),
        };
        let ca = ident.team.ca_file.as_deref().map(Path::new);
        let client = crate::sync::http::Client::new(
            &ident.team.server_url,
            Some(&ident.key.device_token),
            ca,
        )?;
        let ids: Vec<Id> = ids.iter().filter_map(|i| Id::parse(i).ok()).collect();
        for chunk in ids.chunks(limits::DELETE_IDS) {
            match client.delete(&DeleteRequest::Ids(chunk.to_vec())) {
                Ok(_) => {}
                Err(e) if e.transient() => return Ok(Err(e.to_string())),
                Err(e) => bail!(
                    "the server refused the deletion ({e}): nothing was deleted on this machine"
                ),
            }
        }
        Ok(Ok(()))
    }

    #[cfg(not(feature = "sync"))]
    fn delete_now(&self, _ids: &[String]) -> anyhow::Result<Result<(), String>> {
        Ok(Err("this awm was built without team sync".to_string()))
    }

    /// After the commit: sends the queued deletions in the foreground (§3.3) and counts what
    /// went and what stays queued for the next `awm sync`.
    fn send(&self, conn: &Connection, d: &mut Deleted) -> anyhow::Result<()> {
        if self.local_only || d.own_ids.is_empty() {
            return Ok(());
        }
        // A failure (no network, 5xx, 429) leaves the rows queued; they are counted below.
        #[cfg(feature = "sync")]
        let _ = crate::sync::apply::send_queued(&self.dir);
        let mut st =
            conn.prepare("SELECT 1 FROM sync_outbox WHERE kind = 'delete' AND ref = ?1")?;
        let mut queued = 0;
        for id in &d.own_ids {
            if st.exists([id])? {
                queued += 1;
            }
        }
        let total = d.own_ids.len();
        if let Some(r) = d.remote.as_mut() {
            r.queued = queued;
            r.sent = total - queued;
        }
        Ok(())
    }
}

/// One row with a `sync_id`, read before it is deleted or rewritten.
struct TeamRow {
    event: i64,
    sync_id: String,
    team_copy: bool,
    pushed: bool,
}

/// The remote side of a deletion, read inside the deleting transaction (§3.6): rows of the
/// member (own captures and copies of the member's other machines' records, §3.5) are deleted
/// on the server; teammates' rows on this machine only.
struct TeamSide {
    local_only: bool,
    own: Vec<TeamRow>,
    teammates: Vec<String>,
    /// Own rows that `forget <url>` rewrites (they mention the URL).
    rewritten: Vec<TeamRow>,
}

impl TeamSide {
    fn read(
        conn: &Connection,
        team: &Team,
        deleted: &[i64],
        rewritten: &BTreeSet<i64>,
    ) -> anyhow::Result<TeamSide> {
        let mut st = conn.prepare(
            "SELECT origin, member, sync_id, pushed_at IS NOT NULL FROM event \
             WHERE id = ?1 AND sync_id IS NOT NULL",
        )?;
        let mut read = |id: i64| -> anyhow::Result<Option<(bool, TeamRow)>> {
            let row = st
                .query_row([id], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, bool>(3)?,
                    ))
                })
                .optional()?;
            Ok(row.map(|(origin, member, sync_id, pushed)| {
                let team_copy = origin == "team";
                let own = !team_copy || member.as_deref() == Some(team.member.as_str());
                let row = TeamRow {
                    event: id,
                    sync_id,
                    team_copy,
                    pushed,
                };
                (own, row)
            }))
        };
        let mut side = TeamSide {
            local_only: team.local_only,
            own: Vec::new(),
            teammates: Vec::new(),
            rewritten: Vec::new(),
        };
        for id in deleted {
            match read(*id)? {
                Some((true, row)) => side.own.push(row),
                Some((false, row)) => side.teammates.push(row.sync_id),
                None => {}
            }
        }
        for id in rewritten {
            if let Some((true, row)) = read(*id)? {
                side.rewritten.push(row);
            }
        }
        Ok(side)
    }

    /// Sync ids of the member's deleted rows.
    fn own_ids(&self) -> Vec<String> {
        self.own.iter().map(|r| r.sync_id.clone()).collect()
    }

    /// Writes the remote side in the deleting transaction; ids in `sent` are deleted on the
    /// server already and get no outbox row.
    fn write(
        self,
        tx: &Connection,
        now_ms: i64,
        sent: &BTreeSet<String>,
        d: &mut Deleted,
    ) -> anyhow::Result<()> {
        use crate::sync::apply;
        let mut r = Remote {
            teammates: self.teammates.len(),
            ..Remote::default()
        };
        for id in &self.teammates {
            apply::local_only(tx, id, now_ms)?;
        }
        if self.local_only {
            r.kept = Some(self.own.iter().filter(|o| o.team_copy || o.pushed).count());
            // The member's other machines' copies keep their server records: a re-seed must
            // not delete them either.
            for o in self.own.iter().filter(|o| o.team_copy) {
                apply::local_only(tx, &o.sync_id, now_ms)?;
            }
            d.remote = Some(r);
            return Ok(());
        }
        for o in &self.own {
            apply::own_deletion(tx, &o.sync_id, now_ms, !sent.contains(&o.sync_id))?;
            d.own_ids.push(o.sync_id.clone());
        }
        // Supersede (§3.6): the shared copy of a rewritten record is deleted and the cleaned
        // record is pushed again under a new id by the next `awm sync`.
        for o in &self.rewritten {
            apply::own_deletion(tx, &o.sync_id, now_ms, true)?;
            d.own_ids.push(o.sync_id.clone());
            if !o.team_copy {
                tx.execute(
                    "UPDATE event SET sync_id = NULL, sync_idx = NULL, pushed_at = NULL, \
                       shareable = CASE WHEN shareable = 'never' THEN 'never' ELSE 'no' END \
                     WHERE id = ?1",
                    [o.event],
                )?;
                r.superseded += 1;
            }
        }
        d.remote = Some(r);
        Ok(())
    }

    /// `quarantine`: the member's quarantined shared records are deleted on the server; a
    /// teammate's copy is quarantined here only (its author or an admin deletes it).
    fn write_quarantine(self, tx: &Connection, now_ms: i64, d: &mut Deleted) -> anyhow::Result<()> {
        for o in &self.own {
            crate::sync::apply::own_deletion(tx, &o.sync_id, now_ms, true)?;
            d.own_ids.push(o.sync_id.clone());
        }
        d.remote = Some(Remote {
            teammates: self.teammates.len(),
            ..Remote::default()
        });
        Ok(())
    }
}

fn print_remote(out: &mut dyn Write, r: &Remote, verb: &str) -> anyhow::Result<()> {
    if let Some(kept) = r.kept {
        writeln!(
            out,
            "--local-only: {kept} shared record(s) of yours stay on the server; awm team \
             delete-mine deletes all of your shared records there."
        )?;
    } else {
        writeln!(out, "Deleted {} shared record(s) on the server.", r.sent)?;
        if r.queued > 0 {
            writeln!(
                out,
                "{} deletion(s) queued for the next awm sync (the server did not answer).",
                r.queued
            )?;
        }
    }
    if r.superseded > 0 {
        writeln!(
            out,
            "Superseded {} shared record(s): the server copy is deleted, and the next awm sync \
             shares the cleaned record again.",
            r.superseded
        )?;
    }
    if r.teammates > 0 {
        writeln!(
            out,
            "{} teammate record(s) {verb} on this machine only; their server copies stay with \
             their authors.",
            r.teammates
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// forget

pub fn run_forget(args: &Args, io: &mut Io<'_>) -> anyhow::Result<Outcome> {
    let mut conn = open_db(&io.data_dir)?;
    // `rerun`: the command as typed, for the refusal hint. `again`: the same
    // command when running it again is safe (it selects by URL), for the busy-WAL hint.
    let (rows, url, rerun, again) = if let Some(id) = args.id {
        let rows = rows(&conn, "id = ?1", [id])?;
        if rows.is_empty() {
            bail!("no record with id {id}");
        }
        (rows, None, format!("awm forget --id {id}"), None)
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
        (
            rows,
            None,
            format!("awm forget --ref {}", shell_quote(r)),
            None,
        )
    } else {
        let target = args.target.as_deref().unwrap_or_default();
        if target == "last" {
            // Your newest record: a local capture or, in a team, a copy of a record of your
            // other machine (plan-v3-team §3.5).
            let own = team_member(&io.data_dir).unwrap_or_default();
            let rows = rows(
                &conn,
                "id = (SELECT id FROM event WHERE origin = 'local' \
                         OR (origin = 'team' AND member = ?1) \
                       ORDER BY created_at DESC, id DESC LIMIT 1)",
                [own],
            )?;
            (rows, None, "awm forget last".to_string(), None)
        } else {
            let norm = norm_url(target)
                .ok_or_else(|| anyhow!("not a URL: {target:?} (use last, --id N or --ref REF)"))?;
            let (rows, url) = select_url(&conn, target, &norm)?;
            let rerun = format!("awm forget {}", shell_quote(target));
            (rows, Some(url), rerun.clone(), Some(rerun))
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
    let question = if !rows.is_empty() {
        format!("Forget {} record(s) permanently?", rows.len())
    } else if preview.updated == 0 && preview.injections == 0 {
        "Nothing stored for it. Skip it in future records?".to_string()
    } else {
        format!(
            "Remove it from {} kept search record(s), delete {} injection log entr{} and skip it in future records?",
            preview.updated,
            preview.injections,
            if preview.injections == 1 { "y" } else { "ies" }
        )
    };
    if let Some(o) = confirm(io, args.yes, &question, &rerun)? {
        return Ok(o);
    }
    let team = Team::join(&io.data_dir, false)?;
    let mut deleted = apply(&mut conn, &sel, io.now_ms, team.as_ref(), &BTreeSet::new())?;
    if let Some(t) = &team {
        t.send(&conn, &mut deleted)?;
    }
    finish_deletion(io, conn, deleted, again.as_deref())
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

/// Steps 1-4 of §6.4 in one transaction. `forget <url>` and `purge --before`
/// select again inside it ([`Selection::reselect`]). In a team the remote side
/// of every deleted or rewritten row is recorded in the same transaction
/// ([`TeamSide`]); ids in `sent` were deleted on the server already (`purge`).
fn apply(
    conn: &mut Connection,
    sel: &Selection,
    now_ms: i64,
    team: Option<&Team>,
    sent: &BTreeSet<String>,
) -> anyhow::Result<Deleted> {
    let mut d = Deleted::default();
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let fresh = sel.reselect(&tx)?;
    let sel = fresh.as_ref().unwrap_or(sel);
    let affected = match &sel.url {
        Some(u) => affected_events(&tx, u, &sel.event_ids)?,
        None => Affected::default(),
    };
    let side = match team {
        Some(t) => Some(TeamSide::read(&tx, t, &sel.event_ids, &affected.all())?),
        None => None,
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
    if let Some(side) = side {
        side.write(&tx, now_ms, sent, &mut d)?;
    }
    d.results = results_before - count(&tx, "result")?;
    d.injections = injections_before - count(&tx, "injection")?;
    tx.commit()?;
    Ok(d)
}

/// Step 5: merge the FTS segments so deleted terms leave the index pages
/// (the freed pages are zeroed by secure_delete), then empty the WAL.
/// Returns whether the checkpoint was blocked by another connection.
fn scrub(conn: &Connection) -> anyhow::Result<bool> {
    conn.execute("INSERT INTO event_fts(event_fts) VALUES('optimize')", [])?;
    let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
    Ok(busy != 0)
}

/// After the commit: step 5, then step 6 even if step 5 failed, then the
/// report; errors are returned after the report. `again` is the command to
/// run again when the WAL could not be emptied (only when that is safe).
fn finish_deletion(
    io: &mut Io<'_>,
    conn: Connection,
    mut d: Deleted,
    again: Option<&str>,
) -> anyhow::Result<Outcome> {
    let scrubbed = scrub(&conn);
    drop(conn);
    let cleaned = cleanup_files(&io.data_dir, &mut d);
    d.wal_busy = matches!(scrubbed, Ok(true));
    print_deleted(io.out, &d, again)?;
    scrubbed.context(
        "the records are deleted, but the search index could not be compacted or awm.db-wal \
         emptied; awm.db and awm.db-wal may still hold old copies of the deleted data",
    )?;
    cleaned?;
    Ok(Outcome::Done)
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
        agent: Agent::Claude,
        results,
        quarantine_reason: None,
    };
    conn.execute(
        "UPDATE event SET query = ?1, fetch_prompt = ?2, summary = ?3, match_text = ?4 WHERE id = ?5",
        params![query, fetch_prompt, summary, rec.match_text(), id],
    )?;
    Ok(())
}

/// Step 6: backups `{db}.bak-v*` (also unfinished `.tmp` copies), stale
/// calibration copies in `tmp/` and the `*.json` files of `spool/`. A `spool` that is not a real directory (a
/// symlink) is not followed.
fn cleanup_files(data_dir: &Path, d: &mut Deleted) -> anyhow::Result<()> {
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
    // Calibration copies a killed process left in `tmp/` (RVT3 F7).
    d.backups
        .extend(crate::matching::calibrate::sweep_stale_copies(data_dir)?);
    d.backups.sort();
    let spool = data_dir.join(paths::SPOOL_DIR);
    if !std::fs::symlink_metadata(&spool).is_ok_and(|m| m.is_dir()) {
        return Ok(());
    }
    if let Ok(entries) = std::fs::read_dir(&spool) {
        for e in entries.flatten() {
            if spool_file(&e) {
                std::fs::remove_file(e.path())
                    .with_context(|| format!("cannot delete {}", e.path().display()))?;
                d.spool_files += 1;
            }
        }
    }
    Ok(())
}

/// A pending capture in `spool/`: a regular `*.json` file (symlinks are not files here).
fn spool_file(e: &std::fs::DirEntry) -> bool {
    e.file_type().is_ok_and(|t| t.is_file())
        && Path::new(&e.file_name())
            .extension()
            .is_some_and(|x| x == "json")
}

/// A calibration copy in `tmp/`: a regular file named `awm.db.calibrate-*`
/// (with its journal files; RVT3 F7).
fn tmp_file(e: &std::fs::DirEntry) -> bool {
    e.file_type().is_ok_and(|t| t.is_file())
        && e.file_name()
            .to_str()
            .is_some_and(crate::matching::calibrate::is_copy_name)
}

/// A usage sample in `quota/`: a regular file named `samples-YYYY-MM.ndjson`
/// (symlinks are not files here; plan-quota §5.2).
fn quota_file(e: &std::fs::DirEntry) -> bool {
    e.file_type().is_ok_and(|t| t.is_file())
        && e.file_name()
            .to_str()
            .is_some_and(crate::quota::store::is_sample_file)
}

fn print_deleted(out: &mut dyn Write, d: &Deleted, again: Option<&str>) -> anyhow::Result<()> {
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
    if let Some(r) = &d.remote {
        print_remote(out, r, "deleted")?;
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
    if d.spool_files == 0 {
        writeln!(out, "Deleted 0 spool file(s).")?;
    } else {
        writeln!(
            out,
            "Deleted {} spool file(s): pending captures were discarded; `awm import` reads them \
             again from the Claude Code transcripts.",
            d.spool_files
        )?;
    }
    if d.wal_busy {
        let when = match again {
            Some(cmd) => format!("Re-run `{cmd} --yes` when no Claude Code session is active."),
            None => "They are emptied when the last process closes the database; make sure no \
                     Claude Code session is active."
                .to_string(),
        };
        writeln!(
            out,
            "Warning: another process has the database open, so awm.db and awm.db-wal could not \
             be scrubbed; they may hold old copies of the deleted data. {when}"
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// purge

pub fn run_purge_with(args: &PurgeArgs, io: &mut Io<'_>) -> anyhow::Result<Outcome> {
    if args.all {
        let (step, rerun) = if args.local_only {
            (TeamStep::LocalOnly, "awm purge --all --local-only")
        } else {
            (TeamStep::Leave, "awm purge --all")
        };
        return purge_all_with(io, args.yes, rerun, step).map(|(o, _)| o);
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
    // `date` passed `parse_date`, so it needs no quoting.
    let rerun = format!(
        "awm purge --before {date}{}",
        if args.local_only { " --local-only" } else { "" }
    );
    if let Some(o) = confirm(io, args.yes, &question, &rerun)? {
        return Ok(o);
    }
    let team = Team::join(&io.data_dir, args.local_only)?;
    // Remote first (§3.6): the member's shared records in the range are deleted on the server
    // before anything here; offline, nothing is deleted unless --local-only.
    let mut sent = BTreeSet::new();
    if let Some(t) = team.as_ref().filter(|t| !t.local_only) {
        let own = TeamSide::read(&conn, t, &sel.event_ids, &BTreeSet::new())?.own_ids();
        if !own.is_empty() {
            if let Err(why) = t.delete_now(&own)? {
                writeln!(
                    io.out,
                    "The server cannot be reached ({why}), and awm purge deletes your shared \
                     records on the server first: nothing was deleted. To delete on this machine \
                     only: awm purge --before {date} --local-only ({} shared record(s) would stay \
                     on the server).",
                    own.len()
                )?;
                return Ok(Outcome::Refused);
            }
            sent.extend(own);
        }
    }
    let mut deleted = apply(&mut conn, &sel, io.now_ms, team.as_ref(), &sent)?;
    if let Some(t) = &team {
        t.send(&conn, &mut deleted)?;
    }
    finish_deletion(io, conn, deleted, Some(&rerun))
}

/// What `purge --all` found in the data dir before deleting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirSummary {
    pub bytes: u64,
    /// `None` when the database is missing or cannot be read.
    pub records: Option<i64>,
}

/// File names in the data dir that awm creates (plan-v2 §5.7, §6.2; the team
/// files of plan-v3-team §4.7 and §4.4); `spool/` and `config.toml` are checked
/// by [`foreign_entries`].
fn ours(name: &str) -> bool {
    let db = paths::DB_FILE;
    name == db
        || name == format!("{db}-wal")
        || name == format!("{db}-shm")
        || name == format!("{db}-journal")
        || name.starts_with(&format!("{db}.bak-v"))
        || name == ".DS_Store"
        || name == crate::cli::where_::TEAM_TOML
        || name == crate::cli::where_::TEAM_KEY
        || name == crate::team::TEAM_REPO
        || name == crate::sync::apply::SYNC_LOCK
}

/// Whether `path` reads as an awm configuration: TOML whose top-level keys
/// are all keys of [`Config`](crate::config::Config). Values are not checked,
/// so a mistyped value does not make the owner's own file foreign.
fn awm_config(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(table) = text.parse::<toml::Table>() else {
        return false;
    };
    let Ok(known) = toml::Table::try_from(crate::config::Config::default()) else {
        return false;
    };
    table.keys().all(|k| known.contains_key(k))
}

/// Entries of the data dir that awm did not create, as paths relative to it.
/// A symlink with an awm name is ours (only the link is deleted); `spool/`
/// must be a symlink or a directory of regular `*.json` files, and `quota/` a
/// symlink or a directory of regular sample files ([`quota_file`]).
fn foreign_entries(dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut foreign = Vec::new();
    for e in std::fs::read_dir(dir)
        .with_context(|| format!("cannot read {}", dir.display()))?
        .flatten()
    {
        let name = e.file_name().to_string_lossy().into_owned();
        let Ok(kind) = e.file_type() else {
            foreign.push(name);
            continue;
        };
        let ok = if kind.is_symlink() {
            ours(&name)
                || name == paths::CONFIG_FILE
                || name == paths::SPOOL_DIR
                || name == crate::quota::DIR
        } else if let (true, Some(allowed)) = (kind.is_dir(), dir_filter(&name)) {
            for f in std::fs::read_dir(e.path())
                .with_context(|| format!("cannot read {}", e.path().display()))?
                .flatten()
            {
                if !allowed(&f) {
                    foreign.push(format!("{name}/{}", f.file_name().to_string_lossy()));
                }
            }
            true
        } else if name == paths::CONFIG_FILE && kind.is_file() {
            awm_config(&e.path())
        } else {
            ours(&name) && kind.is_file()
        };
        if !ok {
            foreign.push(name);
        }
    }
    foreign.sort();
    Ok(foreign)
}

/// The files a real directory of the data dir may hold, by its name: `spool/`
/// holds [`spool_file`]s, `quota/` holds [`quota_file`]s and `tmp/` holds
/// [`tmp_file`]s. `None` for any other directory, which is foreign.
fn dir_filter(name: &str) -> Option<fn(&std::fs::DirEntry) -> bool> {
    if name == paths::SPOOL_DIR {
        Some(spool_file)
    } else if name == crate::quota::DIR {
        Some(quota_file)
    } else if name == paths::TMP_DIR {
        Some(tmp_file)
    } else {
        None
    }
}

/// Prints the refusal of `purge --all` when the data dir holds foreign entries.
fn refuse_foreign(io: &mut Io<'_>, dir: &Path, foreign: &[String]) -> anyhow::Result<Outcome> {
    writeln!(
        io.out,
        "Not deleting {}: it holds entries awm did not create: {}. Nothing changed. \
         Check AWM_HOME, or move those entries out and run the command again.",
        dir.display(),
        foreign.join(", ")
    )?;
    Ok(Outcome::Foreign)
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
/// its size and record count, asks, then deletes it. If the directory holds
/// any entry awm did not create, nothing is deleted: the entries are listed
/// and the outcome is [`Outcome::Foreign`] (exit code 2). The check runs
/// before the question and again after it.
/// Returns `(Outcome::Nothing, None)` when the directory does not exist.
/// `awm uninstall` calls this after its own team question; `awm purge --all`
/// calls [`purge_all_with`], which leaves the team first.
pub fn purge_all(
    io: &mut Io<'_>,
    yes: bool,
    rerun: &str,
) -> anyhow::Result<(Outcome, Option<DirSummary>)> {
    purge_all_with(io, yes, rerun, TeamStep::None)
}

/// What `purge --all` does about a team before it deletes the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TeamStep {
    /// Nothing (`awm uninstall` asked its own question).
    None,
    /// `awm team leave --delete` first (§3.6); its failure deletes nothing.
    Leave,
    /// `--local-only`: the shared records stay on the server, and the output says so.
    LocalOnly,
}

/// Printed by `purge --all` after the remote deletion (`docs/sync-v1.md` §10.2, TM2).
const ALL_MINE_GAP: &str = "Not covered: records that another of your devices captured \
     earlier and pushes after this deletion (it was offline). Run awm purge or awm team \
     delete-mine on that device too.";

/// The team step of `purge --all`; `Some` ends the command with that outcome.
fn team_step(io: &mut Io<'_>, dir: &Path, step: TeamStep) -> anyhow::Result<Option<Outcome>> {
    if step == TeamStep::None || team_member(dir).is_none() {
        return Ok(None);
    }
    if step == TeamStep::LocalOnly {
        let member = team_member(dir).unwrap_or_default();
        let kept = open_db(dir).map_or(0, |c| own_shared(&c, &member).unwrap_or(0));
        writeln!(
            io.out,
            "--local-only: {kept} shared record(s) of yours stay on the server, and this \
             device's token stays valid until an admin removes the device (awm team remove \
             @HANDLE --delete-records also deletes the records)."
        )?;
        return Ok(None);
    }
    io.out.flush()?;
    match leave_with_delete(dir) {
        Ok(()) => {
            writeln!(io.out, "{ALL_MINE_GAP}")?;
            Ok(None)
        }
        Err(e) => {
            writeln!(
                io.out,
                "awm team leave --delete did not finish ({e}): nothing was deleted on this \
                 machine. Run awm purge --all again later, or awm purge --all --local-only to \
                 delete only this machine's data."
            )?;
            Ok(Some(Outcome::Refused))
        }
    }
}

#[cfg(feature = "sync")]
fn leave_with_delete(dir: &Path) -> anyhow::Result<()> {
    crate::cli::team::leave_delete(dir)
}

#[cfg(not(feature = "sync"))]
fn leave_with_delete(_dir: &Path) -> anyhow::Result<()> {
    bail!("this awm was built without team sync, so it cannot delete your shared records")
}

/// `purge --all` with the team step of `step` between the question and the deletion.
fn purge_all_with(
    io: &mut Io<'_>,
    yes: bool,
    rerun: &str,
    step: TeamStep,
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
    let foreign = foreign_entries(&dir)?;
    if !foreign.is_empty() {
        return Ok((refuse_foreign(io, &dir, &foreign)?, None));
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
    let foreign = foreign_entries(&dir)?;
    if !foreign.is_empty() {
        return Ok((refuse_foreign(io, &dir, &foreign)?, Some(summary)));
    }
    if let Some(o) = team_step(io, &dir, step)? {
        return Ok((o, Some(summary)));
    }
    if step != TeamStep::None {
        // Leaving wrote and removed files; check once more before deleting everything.
        let foreign = foreign_entries(&dir)?;
        if !foreign.is_empty() {
            return Ok((refuse_foreign(io, &dir, &foreign)?, Some(summary)));
        }
    }
    // Only awm's entries are left: files and symlinks (removed as links, never
    // followed), a real `spool/` holding only `*.json` files and a real
    // `quota/` holding only sample files.
    for e in std::fs::read_dir(&dir)
        .with_context(|| format!("cannot read {}", dir.display()))?
        .flatten()
    {
        let path = e.path();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(allowed) = dir_filter(&name) else {
                bail!(
                    "cannot delete {}: a directory awm did not create appeared",
                    path.display()
                );
            };
            for f in std::fs::read_dir(&path)
                .with_context(|| format!("cannot read {}", path.display()))?
                .flatten()
                .filter(allowed)
            {
                std::fs::remove_file(f.path())
                    .with_context(|| format!("cannot delete {}", f.path().display()))?;
            }
            // Fails, deleting nothing more, if anything else appeared meanwhile.
            std::fs::remove_dir(&path)
        } else {
            std::fs::remove_file(&path)
        }
        .with_context(|| format!("cannot delete {}", path.display()))?;
    }
    std::fs::remove_dir(&dir).with_context(|| format!("cannot delete {}", dir.display()))?;
    writeln!(
        io.out,
        "Deleted {} ({}).",
        dir.display(),
        describe(&summary)
    )?;
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
    let mut conn = open_db(&io.data_dir)?;
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
    let rerun = format!("awm {verb} {}", shell_quote(target));
    if let Some(o) = confirm(io, args.yes, &question, &rerun)? {
        return Ok(o);
    }
    let mut d = Deleted::default();
    let n = if on {
        // In a team a quarantined shared record of yours is deleted on the server too (§4.9).
        let team = Team::join(&io.data_dir, false)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n = quarantine_events(&tx, &ids, "awm quarantine")?;
        if let Some(t) = &team {
            TeamSide::read(&tx, t, &ids, &BTreeSet::new())?
                .write_quarantine(&tx, io.now_ms, &mut d)?;
        }
        tx.commit()?;
        if let Some(t) = &team {
            t.send(&conn, &mut d)?;
        }
        n
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
    if let Some(r) = &d.remote {
        print_remote(io.out, r, "quarantined")?;
    }
    Ok(Outcome::Done)
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}
