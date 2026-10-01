//! `awm review`: label shown or would-be-shown notes (plan-v2 §8.3).

use std::collections::VecDeque;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};
use serde_json::Value;

use crate::config;
use crate::matching::{self, Hit, MatchOpts};
use crate::note::{Channel, RenderCtx};
use crate::paths;
use crate::render;

/// Hard upper bound for `--limit`.
const MAX_LIMIT: u32 = 50;
const REPLY_CHARS: usize = 200;
const WINDOW_MS: i64 = 300_000;
const MAX_CALLS: usize = 5;

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Items to label (default review.daily_limit, at most 50)
    #[arg(long)]
    pub limit: Option<u32>,
}

struct Item {
    injection_id: i64,
    position: i64,
    event_id: i64,
    score: f64,
    ref_id: String,
    created_at: i64,
    hook: String,
    channel: String,
    mode: String,
    session_id: String,
    agent_id: Option<String>,
    tool_use_id: Option<String>,
    transcript_path: Option<String>,
    trigger_text: Option<String>,
    cutoff: Option<f64>,
}

/// What the agent did after a note, read from its transcript.
#[derive(Debug, Default, PartialEq)]
pub struct NextSteps {
    pub reply: Option<String>,
    pub calls: Vec<String>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let conn = super::open_db()?;
    let cfg = config::load(&paths::config_path()?)?;
    let limit = args
        .limit
        .unwrap_or(cfg.review.daily_limit)
        .clamp(1, MAX_LIMIT);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_with(&conn, limit, &mut stdin.lock(), &mut stdout.lock())
}

pub fn run_with(
    conn: &Connection,
    limit: u32,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let items = unlabelled(conn, limit)?;
    if items.is_empty() {
        writeln!(out, "Nothing to review.")?;
        return Ok(());
    }
    let total = items.len();
    let mut keys = Keys {
        input,
        pending: VecDeque::new(),
    };
    let mut labelled = 0;
    for (i, item) in items.iter().enumerate() {
        show(conn, item, i + 1, total, out)?;
        loop {
            write!(out, "Label [2 changed next step, 1 relevant, 0 not relevant, h harmful, s skip, q quit]: ")?;
            out.flush()?;
            let Some(key) = keys.next() else {
                writeln!(out)?;
                writeln!(out, "Labelled {labelled} of {total} items.")?;
                return Ok(());
            };
            writeln!(out)?;
            match key {
                '0' | '1' | '2' | 'h' => {
                    conn.execute(
                        "INSERT INTO outcome (injection_id, position, label, labelled_at) \
                         VALUES (?1, ?2, ?3, ?4)",
                        params![
                            item.injection_id,
                            item.position,
                            key.to_string(),
                            super::now_ms()
                        ],
                    )?;
                    labelled += 1;
                    break;
                }
                's' => break,
                'q' => {
                    writeln!(out, "Labelled {labelled} of {total} items.")?;
                    return Ok(());
                }
                _ => writeln!(out, "Unknown key {key:?}.")?,
            }
        }
    }
    writeln!(out, "Labelled {labelled} of {total} items.")?;
    Ok(())
}

/// Characters from a line-oriented input, whitespace skipped.
struct Keys<'a> {
    input: &'a mut dyn BufRead,
    pending: VecDeque<char>,
}

impl Keys<'_> {
    fn next(&mut self) -> Option<char> {
        loop {
            if let Some(c) = self.pending.pop_front() {
                return Some(c.to_ascii_lowercase());
            }
            let mut line = String::new();
            if self.input.read_line(&mut line).ok()? == 0 {
                return None;
            }
            self.pending
                .extend(line.chars().filter(|c| !c.is_whitespace()));
        }
    }
}

fn unlabelled(conn: &Connection, limit: u32) -> anyhow::Result<Vec<Item>> {
    let mut st = conn.prepare(
        "SELECT ii.injection_id, ii.position, ii.event_id, ii.score, i.ref, i.created_at, \
                i.hook, i.channel, i.mode, i.session_id, i.agent_id, i.tool_use_id, \
                i.transcript_path, i.trigger_text, i.cutoff \
         FROM injection_item ii JOIN injection i ON i.id = ii.injection_id \
         WHERE NOT EXISTS (SELECT 1 FROM outcome o \
                           WHERE o.injection_id = ii.injection_id AND o.position = ii.position) \
         ORDER BY i.created_at DESC, ii.injection_id DESC, ii.position \
         LIMIT ?1",
    )?;
    let rows = st.query_map([limit], |r| {
        Ok(Item {
            injection_id: r.get(0)?,
            position: r.get(1)?,
            event_id: r.get(2)?,
            score: r.get(3)?,
            ref_id: r.get(4)?,
            created_at: r.get(5)?,
            hook: r.get(6)?,
            channel: r.get(7)?,
            mode: r.get(8)?,
            session_id: r.get(9)?,
            agent_id: r.get(10)?,
            tool_use_id: r.get(11)?,
            transcript_path: r.get(12)?,
            trigger_text: r.get(13)?,
            cutoff: r.get(14)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Control characters become spaces; transcript text must not drive the terminal.
fn plain(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn show(
    conn: &Connection,
    it: &Item,
    n: usize,
    total: usize,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let kind = if it.agent_id.is_some() {
        "subagent"
    } else {
        "main"
    };
    writeln!(out, "\n--- item {n}/{total} ---")?;
    writeln!(
        out,
        "{}  {}  {kind}  channel {}  mode {}  ref {}",
        super::fmt_ts(it.created_at),
        it.hook,
        it.channel,
        it.mode,
        it.ref_id
    )?;
    if let Some(t) = &it.trigger_text {
        writeln!(out, "trigger: {}", plain(t))?;
    }
    match it.cutoff {
        Some(c) => writeln!(out, "score {:.1} against cutoff {c:.1}", it.score)?,
        None => writeln!(out, "score {:.1}", it.score)?,
    }
    let note_text = render_item(conn, it)?;
    writeln!(
        out,
        "{}",
        note_text
            .as_deref()
            .unwrap_or("(the note cannot be rendered)")
    )?;
    match transcript_for(it).and_then(|p| next_steps(&p, it.tool_use_id.as_deref(), it.created_at))
    {
        None => writeln!(out, "next steps: (transcript not available)")?,
        Some(ns) => {
            match &ns.reply {
                Some(r) => writeln!(out, "next reply: {r}")?,
                None => writeln!(out, "next reply: (none found)")?,
            }
            if ns.calls.is_empty() {
                writeln!(out, "following web calls: (none within 5 minutes)")?;
            } else {
                writeln!(out, "following web calls:")?;
                for c in &ns.calls {
                    writeln!(out, "  {c}")?;
                }
            }
        }
    }
    Ok(())
}

fn render_item(conn: &Connection, it: &Item) -> anyhow::Result<Option<String>> {
    let cwd_hash: String = conn
        .query_row(
            "SELECT cwd_hash FROM event WHERE session_id = ?1 LIMIT 1",
            [&it.session_id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    let opts = MatchOpts {
        caller_session: it.session_id.clone(),
        caller_agent: it.agent_id.clone(),
        caller_cwd_hash: cwd_hash,
        limit: 1,
        ..MatchOpts::default()
    };
    let hit = Hit {
        event_id: it.event_id,
        score: it.score,
        seen: 1,
    };
    let note = matching::to_note(conn, &hit, &opts)?;
    let ctx = RenderCtx {
        channel: Channel::from_db_str(&it.channel).unwrap_or(Channel::Query),
        now_ms: it.created_at,
        utc_offset_min: 0,
        ref_id: it.ref_id.clone(),
        max_notes: 1,
    };
    Ok(render::render(&[note], &ctx).map(|r| r.text))
}

fn transcript_for(it: &Item) -> Option<PathBuf> {
    super::transcript_file(it.transcript_path.as_deref()?, it.agent_id.as_deref())
}

/// The agent's next reply text and up to five following web calls within five minutes.
pub fn next_steps(path: &Path, tool_use_id: Option<&str>, created_at: i64) -> Option<NextSteps> {
    let text = std::fs::read_to_string(path).ok()?;
    let lines: Vec<Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let ts_of = |v: &Value| v["timestamp"].as_str().and_then(super::parse_iso_ms);
    let by_id = tool_use_id.and_then(|id| {
        lines.iter().position(|v| {
            v["message"]["content"].as_array().is_some_and(|b| {
                b.iter()
                    .any(|x| x["type"] == "tool_result" && x["tool_use_id"] == id)
            })
        })
    });
    let anchor = by_id.or_else(|| {
        lines
            .iter()
            .position(|v| ts_of(v).is_some_and(|t| t >= created_at))
    })?;
    let anchor_ts = ts_of(&lines[anchor]).unwrap_or(created_at);
    let mut ns = NextSteps::default();
    for v in &lines[anchor + 1..] {
        if ts_of(v).is_some_and(|t| t > anchor_ts + WINDOW_MS) {
            break;
        }
        if v["message"]["role"] != "assistant" {
            continue;
        }
        let Some(blocks) = v["message"]["content"].as_array() else {
            continue;
        };
        for b in blocks {
            if ns.reply.is_none() && b["type"] == "text" {
                let t = plain(b["text"].as_str().unwrap_or("")).trim().to_string();
                if !t.is_empty() {
                    ns.reply = Some(t.chars().take(REPLY_CHARS).collect());
                }
            }
        }
        for c in super::calls_of_line(v, false) {
            if ns.calls.len() < MAX_CALLS && Some(c.tool_use_id.as_str()) != tool_use_id {
                ns.calls.push(format!("{} {}", c.tool, plain(&c.target)));
            }
        }
    }
    Some(ns)
}
