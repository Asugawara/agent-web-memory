//! `awm init`: consent text (S4), database creation, optional import, result text (S5)
//! (plan-v2 §2.1 step 5, §2.2).

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

use rusqlite::{params, Connection};

use crate::config::{self, Config};
use crate::db::{self, Role};
use crate::import::{self, ImportOpts, ImportSummary};
use crate::paths;

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Record web research from now on (answers the first question)
    #[arg(long)]
    pub record: bool,
    /// Import past web research from transcripts (answers the second question)
    #[arg(long)]
    pub import: bool,
    /// Import only the tool_use ids listed in FILE
    #[arg(long, value_name = "FILE")]
    pub only_ids: Option<PathBuf>,
    /// Transcript directory (default ~/.claude/projects)
    #[arg(long, value_name = "DIR")]
    pub projects: Option<PathBuf>,
    /// Codex CLI sessions directory (default $CODEX_HOME/sessions or ~/.codex/sessions)
    #[arg(long, value_name = "DIR")]
    pub codex_dir: Option<PathBuf>,
    /// Do not import Codex CLI rollouts
    #[arg(long)]
    pub no_codex: bool,
    /// Answer yes to both questions
    #[arg(long)]
    pub yes: bool,
}

const DAY_MS: i64 = 86_400_000;

/// Formats a byte count as `3.6 GB` (decimal units).
fn human_size(bytes: u64) -> String {
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

fn consent_text(data_dir: &str) -> String {
    format!(
        "agent-web-memory keeps a local record of your coding agents' web research so they can reuse it.\n\
\n\
Recorded for every WebSearch and WebFetch call in Claude Code (main agent and subagents):\n\
\x20 query or fetch prompt, URL, result titles and URLs, the tool's summary, HTTP status,\n\
\x20 time, session id, subagent id, and a hash of the working directory.\n\
Not recorded: your prompts (except the first 200 characters of a prompt that contained\n\
\x20 a URL with a matching note, kept in the local log), code, files, other tools.\n\
Stored in: {data_dir}/awm.db  (this machine only; awm makes no network requests)\n\
Delete everything at any time: awm purge --all\n"
    )
}

const NO_TERMINAL: &str = "No terminal for questions. Re-run with your answers:\n\
\x20 awm init --record --import    record from now on and import past research\n\
\x20 awm init --record             record from now on only";

fn ask(question: &str, input: &mut dyn BufRead, out: &mut dyn Write) -> anyhow::Result<bool> {
    write!(out, "{question} ")?;
    out.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn meta_set(conn: &Connection, key: &str, value: &str) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let data_dir = paths::data_dir()?;
    let tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let stdin = std::io::stdin();
    run_with(
        args,
        &data_dir,
        tty,
        &mut stdin.lock(),
        &mut std::io::stdout(),
        import::now_ms(),
    )
}

/// `run` with the environment injected.
pub fn run_with(
    args: Args,
    data_dir: &std::path::Path,
    tty: bool,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    now_ms: i64,
) -> anyhow::Result<()> {
    let projects = match &args.projects {
        Some(p) => p.clone(),
        None => import::default_projects_dir()?,
    };
    let files = import::transcript_files(&projects);
    let bytes: u64 = files
        .iter()
        .filter_map(|f| std::fs::metadata(f).ok())
        .map(|m| m.len())
        .sum();

    let codex =
        import::resolve_codex_dir(args.codex_dir.clone(), args.no_codex).filter(|d| d.is_dir());
    writeln!(out, "{}", consent_text(&data_dir.display().to_string()))?;
    if let Some(dir) = &codex {
        let files = import::codex_files(dir);
        let bytes: u64 = files
            .iter()
            .filter_map(|f| std::fs::metadata(f).ok())
            .map(|m| m.len())
            .sum();
        writeln!(
            out,
            "Also imports Codex CLI rollouts from {} ({} files, {}).\n",
            dir.display(),
            files.len(),
            human_size(bytes)
        )?;
    }

    let mut record = args.record || args.yes;
    let mut import_wanted = args.import || args.yes;
    let mut declined_record = false;
    let flags_given = args.record || args.import || args.yes;
    if tty {
        if !record {
            record = ask("Record web research from now on? [y/N]", input, out)?;
            declined_record = !record;
        }
        if !import_wanted {
            import_wanted = ask(
                &format!(
                    "Also import past web research from {} transcript files in ~/.claude/projects ({})? [y/N]",
                    files.len(),
                    human_size(bytes)
                ),
                input,
                out,
            )?;
        }
    } else if !flags_given {
        writeln!(out, "{NO_TERMINAL}")?;
        return Ok(());
    }

    paths::ensure_private_dir(data_dir)?;
    let db_path = data_dir.join(paths::DB_FILE);
    let mut conn = db::open(&db_path, Role::Cli)?;
    db::migrate(&mut conn)?;
    let config_path = data_dir.join(paths::CONFIG_FILE);
    if !config_path.exists() {
        Config::default().save(&config_path)?;
    }
    if record {
        meta_set(&conn, "consent.record", "yes")?;
    } else if declined_record {
        meta_set(&conn, "consent.record", "no")?;
    }

    let mut summary = None;
    if import_wanted {
        meta_set(&conn, "consent.import", "yes")?;
        let config = config::load(&config_path)?;
        let only_ids = args
            .only_ids
            .as_deref()
            .map(import::read_only_ids)
            .transpose()?;
        drop(conn);
        summary = Some(import::import_all(&ImportOpts {
            projects_dir: projects,
            codex_dir: codex,
            data_dir: data_dir.to_path_buf(),
            config,
            only_ids,
            now_ms,
        })?);
        conn = db::open(&db_path, Role::Cli)?;
    }
    print_result(out, &conn, summary.as_ref(), now_ms)
}

fn print_result(
    out: &mut dyn Write,
    conn: &Connection,
    summary: Option<&ImportSummary>,
    now_ms: i64,
) -> anyhow::Result<()> {
    let Some(s) = summary.filter(|s| s.records_inserted > 0) else {
        writeln!(
            out,
            "Nothing imported yet. Notes appear after your agents search the web."
        )?;
        return Ok(());
    };
    writeln!(out, "{}", import::summary_line(s, false))?;
    writeln!(
        out,
        "Skipped {} private-network URLs; redacted {} secret-like strings.",
        s.skipped_private, s.redactions
    )?;
    writeln!(
        out,
        "Match cutoff calibrated on {} recent searches.",
        s.calibrated
    )?;
    if let Some(url) = top_url(conn, now_ms)? {
        writeln!(
            out,
            "Try it: paste into Claude Code:  What did I find out about {url} last time?"
        )?;
    } else if let Some(q) = latest_query(conn)? {
        writeln!(out, "Try it: awm search \"{q}\"")?;
    }
    Ok(())
}

/// The `https://` URL with the most status-ok fetches in the last 30 days (at least two).
fn top_url(conn: &Connection, now_ms: i64) -> anyhow::Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT url FROM event WHERE tool = 'WebFetch' AND status = 'ok' AND quarantined = 0 AND origin = 'local' \
             AND url LIKE 'https://%' AND created_at >= ?1 \
             GROUP BY url_norm HAVING COUNT(*) >= 2 \
             ORDER BY COUNT(*) DESC, MAX(created_at) DESC LIMIT 1",
            [now_ms - 30 * DAY_MS],
            |r| r.get(0),
        )
        .ok())
}

fn latest_query(conn: &Connection) -> anyhow::Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT query FROM event WHERE tool = 'WebSearch' AND quarantined = 0 AND origin = 'local' \
             ORDER BY created_at DESC, id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok())
}
