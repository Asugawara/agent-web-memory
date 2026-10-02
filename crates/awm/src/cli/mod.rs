//! Read-only and maintenance subcommands.

pub mod cloud;
pub mod config_cmd;
pub mod doctor;
pub mod export;
pub mod log;
pub mod reindex;
pub mod report;
pub mod review;
pub mod search;
#[cfg(feature = "serve")]
pub mod serve;
pub mod setup;
pub mod stats;
pub mod statusline;
pub mod sync;
pub mod team;
pub mod uninstall;
pub mod where_;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use rusqlite::Connection;
use serde_json::Value;

use crate::db::{self, Role, VersionCheck};
use crate::paths;

/// The scaffold commands of the team work (TM1): print a message and exit with status 2.
pub(crate) fn not_implemented(command: &str) -> ! {
    eprintln!("awm {command}: not implemented in this build");
    std::process::exit(2)
}

/// Opens the existing database for a CLI command. Refuses a missing, older or newer schema.
pub(crate) fn open_db() -> anyhow::Result<Connection> {
    let path = paths::db_path()?;
    if !path.is_file() {
        bail!("no database at {}. Run: awm init", path.display());
    }
    let conn = db::open(&path, Role::Cli)?;
    match db::check_version(&conn)? {
        VersionCheck::Current => Ok(conn),
        VersionCheck::Older { .. } => {
            bail!("database needs an upgrade. Run: awm doctor")
        }
        VersionCheck::Newer { db, .. } => {
            bail!("database is from a newer awm ({db}). Upgrade awm.")
        }
    }
}

pub(crate) fn now_ms() -> i64 {
    crate::hook::now_ms()
}

/// `YYYY-MM-DD HH:MM:SS` in UTC.
pub(crate) fn fmt_ts(ms: i64) -> String {
    let fmt = time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    time::OffsetDateTime::from_unix_timestamp(ms.div_euclid(1000))
        .ok()
        .and_then(|t| t.format(&fmt).ok())
        .unwrap_or_else(|| "1970-01-01 00:00:00".to_string())
}

/// `YYYY-MM-DD` in UTC.
pub(crate) fn fmt_day(ms: i64) -> String {
    fmt_ts(ms)[..10].to_string()
}

/// `YYYY-MM-DD` as unix milliseconds at 00:00 UTC.
pub(crate) fn parse_date(s: &str) -> anyhow::Result<i64> {
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    let d =
        time::Date::parse(s, &fmt).with_context(|| format!("expected YYYY-MM-DD, got {s:?}"))?;
    Ok(d.midnight().assume_utc().unix_timestamp() * 1000)
}

/// Nearest-rank percentile of an unsorted list.
pub(crate) fn percentile(values: &mut [i64], p: f64) -> Option<i64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let rank = ((p / 100.0) * values.len() as f64).ceil() as usize;
    Some(values[rank.clamp(1, values.len()) - 1])
}

/// `part / whole` as a percentage with one decimal, `None` when `whole` is 0.
pub(crate) fn pct(part: i64, whole: i64) -> Option<String> {
    (whole > 0).then(|| format!("{:.1}%", part as f64 * 100.0 / whole as f64))
}

/// Prints nested objects as indented `key: value` lines.
pub(crate) fn render_value(v: &Value, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                match val {
                    Value::Object(_) => {
                        out.push_str(&format!("{pad}{k}:\n"));
                        render_value(val, indent + 1, out);
                    }
                    other => out.push_str(&format!("{pad}{k}: {}\n", scalar(other))),
                }
            }
        }
        other => out.push_str(&format!("{pad}{}\n", scalar(other))),
    }
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".to_string(),
        other => other.to_string(),
    }
}

/// One web tool call found in a transcript.
#[derive(Debug, Clone)]
pub(crate) struct TranscriptCall {
    pub tool_use_id: String,
    pub session_id: String,
    pub ts_ms: i64,
    pub tool: String,
    /// The line came from `.../subagents/agent-*.jsonl`.
    pub subagent: bool,
    /// The WebSearch query or WebFetch URL, held in memory only.
    pub target: String,
}

pub(crate) fn parse_iso_ms(s: &str) -> Option<i64> {
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    i64::try_from(t.unix_timestamp_nanos() / 1_000_000).ok()
}

pub(crate) fn is_subagent_file(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == "subagents")
}

/// Every WebSearch / WebFetch `tool_use` of one transcript file.
pub(crate) fn web_calls_in(path: &Path) -> Vec<TranscriptCall> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let subagent = is_subagent_file(path);
    let mut calls = Vec::new();
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        calls.extend(calls_of_line(&v, subagent));
    }
    calls
}

/// Web tool uses of one parsed assistant line.
pub(crate) fn calls_of_line(v: &Value, subagent: bool) -> Vec<TranscriptCall> {
    let Some(blocks) = v["message"]["content"].as_array() else {
        return Vec::new();
    };
    let session = v["sessionId"].as_str().unwrap_or("").to_string();
    let ts = v["timestamp"].as_str().and_then(parse_iso_ms).unwrap_or(0);
    blocks
        .iter()
        .filter(|b| b["type"] == "tool_use")
        .filter_map(|b| {
            let tool = b["name"].as_str()?;
            if tool != "WebSearch" && tool != "WebFetch" {
                return None;
            }
            let key = if tool == "WebSearch" { "query" } else { "url" };
            Some(TranscriptCall {
                tool_use_id: b["id"].as_str()?.to_string(),
                session_id: session.clone(),
                ts_ms: ts,
                tool: tool.to_string(),
                subagent,
                target: b["input"][key].as_str().unwrap_or("").to_string(),
            })
        })
        .collect()
}

/// The transcript projects directory: `--projects` or `~/.claude/projects`.
pub(crate) fn projects_dir(arg: &Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match arg {
        Some(p) => Ok(p.clone()),
        None => crate::import::default_projects_dir(),
    }
}

/// The transcript file that holds an agent's own lines: the subagent file when
/// `agent_id` is set and the file exists, else the main transcript.
pub(crate) fn transcript_file(transcript_path: &str, agent_id: Option<&str>) -> Option<PathBuf> {
    let main = PathBuf::from(transcript_path);
    if let Some(agent) = agent_id {
        let sub = main
            .with_extension("")
            .join("subagents")
            .join(format!("agent-{agent}.jsonl"));
        if sub.is_file() {
            return Some(sub);
        }
    }
    main.is_file().then_some(main)
}
