//! Cutoff calibration (plan-v2 §3.3).

use std::time::{SystemTime, UNIX_EPOCH};

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

fn record_count(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0))?)
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
             WHERE COALESCE(query, fetch_prompt, '') != '' \
             ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = st.query_map([SAMPLE], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let n = recent.len();
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
            if let Some(hit) = query_channel(conn, text, f64::NEG_INFINITY, &opts)?.first() {
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
