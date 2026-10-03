//! Replay harness for the post-tool hook's matching step (`docs/reports/PERF1.md`).
//!
//! `#[ignore]`d: it needs a database copy. Run it in release mode against a copy, never the live
//! database:
//!
//! ```text
//! AWM_PERF_DB=/path/to/copy/awm.db AWM_PERF_OUT=/path/to/ids.tsv \
//!   cargo test --release -p agent-web-memory --lib perf_ -- --ignored --nocapture --test-threads=1
//! ```
//!
//! * `perf_replay`: the last `AWM_PERF_N` (default 300) events, or the events of `AWM_PERF_IDS`
//!   (comma separated ids), each replayed on a fresh connection (as a hook process opens one, so
//!   the SQLite page cache is cold) through the post-tool matching steps. Prints the per-phase
//!   p50 / p95 / max, and the matching step of the pre-PERF1 SQL (`legacy_query_channel`) next to
//!   the current one. `AWM_PERF_OUT` receives one line per trigger: index, tool, tokens, hit ids,
//!   phase microseconds. Nothing from the database but ids and counts is printed.
//! * `perf_equivalence`: the current query channel against the legacy one over every event's
//!   text and four cutoffs; any difference in the hits fails the test.
//! * `perf_variants`: timings of SQL variants; `AWM_PERF_PRAGMA` runs a batch after the open.

use std::time::Instant;

use rusqlite::{params, Connection};

use super::{
    calibrate, finish, fts, norm_query, query_channel, url_channel, Candidate, Hit, MatchOpts,
    CANDIDATES, RULES_SQL,
};
use crate::db::{self, Role};
use crate::normalize::norm_url;

/// The query channel as it was before PERF1: BM25 and the rules in one joined statement,
/// `ORDER BY bm25 LIMIT 300`, the cutoff applied per row afterwards.
fn legacy_query_channel(
    conn: &Connection,
    text: &str,
    cutoff: f64,
    opts: &MatchOpts,
) -> anyhow::Result<Vec<Hit>> {
    let Some(expr) = fts::match_expr(text) else {
        return Ok(Vec::new());
    };
    let sql = format!(
        "SELECT e.id, e.tool, e.query, e.url_norm, e.created_at, -bm25(event_fts) AS score \
         FROM event_fts JOIN event e ON e.id = event_fts.rowid \
         WHERE event_fts MATCH ?6 AND e.status = 'ok' AND {RULES_SQL} \
         ORDER BY bm25(event_fts) LIMIT ?7"
    );
    let mut st = conn.prepare_cached(&sql)?;
    let rows = st.query_map(
        params![
            opts.caller_tool_use_id,
            opts.caller_session,
            opts.caller_agent,
            opts.exclude_same_agent,
            opts.before_ms,
            expr,
            CANDIDATES
        ],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, f64>(5)?,
            ))
        },
    )?;
    let mut cands = Vec::new();
    for row in rows {
        let (id, tool, query, url_norm, created_at, score) = row?;
        if score < cutoff {
            continue;
        }
        let group = match tool.as_str() {
            "WebFetch" => format!("u:{}", url_norm.as_deref().unwrap_or("")),
            _ => format!("q:{}", norm_query(query.as_deref().unwrap_or(""))),
        };
        cands.push(Candidate {
            id,
            group,
            created_at,
            score,
            url_norm: if tool == "WebFetch" { url_norm } else { None },
        });
    }
    finish(conn, cands, opts)
}

struct Trigger {
    tool: String,
    query: Option<String>,
    url: Option<String>,
    prompt: Option<String>,
    session: String,
    agent: Option<String>,
    cwd_hash: String,
    tool_use_id: String,
}

fn load_triggers(db_path: &std::path::Path) -> Vec<Trigger> {
    let conn = db::open(db_path, Role::HookRead).unwrap();
    let sql = match std::env::var("AWM_PERF_IDS") {
        Ok(ids) => format!(
            "SELECT tool, query, url, fetch_prompt, session_id, agent_id, cwd_hash, tool_use_id \
             FROM event WHERE id IN ({}) ORDER BY id",
            ids.split(',')
                .filter_map(|i| i.trim().parse::<i64>().ok())
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
        Err(_) => "SELECT tool, query, url, fetch_prompt, session_id, agent_id, cwd_hash, \
                   tool_use_id FROM (SELECT * FROM event ORDER BY id DESC LIMIT ?1) ORDER BY id"
            .to_string(),
    };
    let n: i64 = std::env::var("AWM_PERF_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let mut st = conn.prepare(&sql).unwrap();
    let map = |r: &rusqlite::Row<'_>| {
        Ok(Trigger {
            tool: r.get(0)?,
            query: r.get(1)?,
            url: r.get(2)?,
            prompt: r.get(3)?,
            session: r.get(4)?,
            agent: r.get(5)?,
            cwd_hash: r.get(6)?,
            tool_use_id: r.get(7)?,
        })
    };
    let rows: rusqlite::Result<Vec<Trigger>> = if sql.contains("?1") {
        st.query_map([n], map).unwrap().collect()
    } else {
        st.query_map([], map).unwrap().collect()
    };
    rows.unwrap()
}

fn shown_ids(conn: &Connection, t: &Trigger) -> Vec<i64> {
    let mut st = conn
        .prepare_cached(
            "SELECT DISTINCT ii.event_id FROM injection_item ii \
             JOIN injection i ON i.id = ii.injection_id \
             WHERE i.session_id = ?1 AND i.agent_id IS ?2 AND i.mode IN ('inject', 'deny') \
               AND ii.event_id IS NOT NULL",
        )
        .unwrap();
    st.query_map(params![t.session, t.agent], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn opts_of(conn: &Connection, t: &Trigger) -> MatchOpts {
    MatchOpts {
        caller_session: t.session.clone(),
        caller_agent: t.agent.clone(),
        caller_cwd_hash: t.cwd_hash.clone(),
        caller_tool_use_id: Some(t.tool_use_id.clone()),
        before_ms: None,
        exclude_same_agent: true,
        limit: 3,
        shown_event_ids: shown_ids(conn, t),
    }
}

fn us(t: Instant) -> u128 {
    t.elapsed().as_micros()
}

fn pct(sorted: &[u128], p: f64) -> u128 {
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

fn db_path() -> Option<std::path::PathBuf> {
    std::env::var_os("AWM_PERF_DB").map(std::path::PathBuf::from)
}

#[test]
#[ignore = "needs AWM_PERF_DB, a copy of a database"]
fn perf_replay() {
    let Some(db_path) = db_path() else {
        eprintln!("AWM_PERF_DB is not set");
        return;
    };
    let triggers = load_triggers(&db_path);
    let mut lines = Vec::new();
    // phase name -> microseconds per trigger
    let names = [
        "open",
        "version",
        "opts",
        "cutoff",
        "url",
        "match",
        "total",
        "to_note",
        "legacy_match",
    ];
    let mut cols: Vec<Vec<u128>> = vec![Vec::new(); names.len()];
    for (i, t) in triggers.iter().enumerate() {
        let t0 = Instant::now();
        let conn = db::open(&db_path, Role::HookRead).unwrap();
        let p_open = us(t0);
        let t1 = Instant::now();
        assert_eq!(
            db::check_version(&conn).unwrap(),
            db::VersionCheck::Current,
            "migrate the copy first (awm doctor)"
        );
        let p_version = us(t1);
        let t2 = Instant::now();
        let opts = opts_of(&conn, t);
        let p_opts = us(t2);

        let search = Instant::now();
        let mut ids: Vec<i64> = Vec::new();
        let (mut p_cutoff, mut p_url, mut p_match) = (0, 0, 0);
        let mut tokens = 0;
        let mut hits = Vec::new();
        let mut query_text: Option<String> = t.query.clone();
        let mut ran_query = false;
        // WebFetch: the url channel first, then the query channel on the fetch prompt;
        // WebSearch: the query channel on the query (post_tool.rs).
        if t.tool == "WebFetch" {
            query_text = t.prompt.clone().filter(|p| !p.is_empty());
            if let Some(norm) = t.url.as_deref().and_then(norm_url) {
                let u = Instant::now();
                hits = url_channel(&conn, &norm, &opts).unwrap();
                p_url = us(u);
            }
        }
        if hits.is_empty() {
            if let Some(text) = query_text.as_deref().filter(|s| !s.is_empty()) {
                tokens = fts::match_expr(text).map_or(0, |e| e.matches(" OR ").count() + 1);
                let c = Instant::now();
                let cutoff = calibrate::cutoff_query(&conn).unwrap();
                p_cutoff = us(c);
                let m = Instant::now();
                hits = query_channel(&conn, text, cutoff, &opts).unwrap();
                p_match = us(m);
                ran_query = true;
            }
        }
        let p_total = us(search);
        let tn = Instant::now();
        let own = super::own_member_id();
        for h in &hits {
            ids.push(h.event_id);
            super::to_note_as(&conn, h, &opts, own.as_deref()).unwrap();
        }
        let p_note = us(tn);

        // The same trigger through the pre-PERF1 SQL, on its own fresh connection.
        let mut p_legacy = 0;
        if ran_query {
            let lconn = db::open(&db_path, Role::HookRead).unwrap();
            let lopts = opts_of(&lconn, t);
            let l = Instant::now();
            let lhits = legacy_query_channel(
                &lconn,
                query_text.as_deref().unwrap(),
                calibrate::cutoff_query(&lconn).unwrap(),
                &lopts,
            )
            .unwrap();
            p_legacy = us(l);
            assert_eq!(
                lhits.iter().map(|h| h.event_id).collect::<Vec<_>>(),
                ids,
                "trigger {i}: the legacy channel chose other hits"
            );
        }
        let row = [
            p_open, p_version, p_opts, p_cutoff, p_url, p_match, p_total, p_note, p_legacy,
        ];
        for (c, v) in cols.iter_mut().zip(row) {
            c.push(v);
        }
        lines.push(format!(
            "{i}\t{}\t{tokens}\t{}\t{}",
            t.tool,
            ids.iter().map(i64::to_string).collect::<Vec<_>>().join(","),
            row.iter()
                .map(u128::to_string)
                .collect::<Vec<_>>()
                .join("\t"),
        ));
    }
    if let Some(out) = std::env::var_os("AWM_PERF_OUT") {
        std::fs::write(out, lines.join("\n") + "\n").unwrap();
    }
    println!("triggers {}", triggers.len());
    println!("phase           p50_us   p95_us   max_us   mean_us");
    for (name, c) in names.iter().zip(&mut cols) {
        c.sort_unstable();
        let mean = c.iter().sum::<u128>() / c.len() as u128;
        println!(
            "{name:<12} {:>8} {:>8} {:>8} {:>9}",
            pct(c, 0.5),
            pct(c, 0.95),
            c[c.len() - 1],
            mean
        );
    }
}

/// The current and the legacy query channel agree on every event's text and four cutoffs.
#[test]
#[ignore = "needs AWM_PERF_DB, a copy of a database"]
fn perf_equivalence() {
    let Some(db_path) = db_path() else {
        return;
    };
    let conn = db::open(&db_path, Role::HookRead).unwrap();
    let rows: Vec<(String, String, Option<String>, String, String, String)> = {
        let mut st = conn
            .prepare(
                "SELECT COALESCE(query, fetch_prompt), session_id, agent_id, cwd_hash, \
                        tool_use_id, tool FROM event \
                 WHERE COALESCE(query, fetch_prompt, '') != '' ORDER BY id",
            )
            .unwrap();
        st.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
    };
    let mut compared = 0usize;
    let mut with_hits = 0usize;
    for (text, session, agent, cwd_hash, tool_use_id, tool) in &rows {
        let t = Trigger {
            tool: tool.clone(),
            query: None,
            url: None,
            prompt: None,
            session: session.clone(),
            agent: agent.clone(),
            cwd_hash: cwd_hash.clone(),
            tool_use_id: tool_use_id.clone(),
        };
        let mut opts = opts_of(&conn, &t);
        for (limit, before) in [(3, None), (3, Some(1_790_950_000_000)), (1, None)] {
            opts.limit = limit;
            opts.before_ms = before;
            for cutoff in [f64::NEG_INFINITY, 10.0, 27.0, 42.0] {
                let new = query_channel(&conn, text, cutoff, &opts).unwrap();
                let old = legacy_query_channel(&conn, text, cutoff, &opts).unwrap();
                assert_eq!(new, old, "cutoff {cutoff} limit {limit} before {before:?}");
                compared += 1;
                with_hits += usize::from(!new.is_empty());
            }
        }
    }
    println!("equivalence: {compared} comparisons identical, {with_hits} with hits");
}

/// Times variants of the query-channel SQL, one pass over the triggers per variant, a fresh
/// connection per trigger. Prints only counts and microseconds.
#[test]
#[ignore = "needs AWM_PERF_DB, a copy of a database"]
fn perf_variants() {
    let Some(db_path) = db_path() else {
        return;
    };
    let exprs: Vec<String> = {
        let conn = db::open(&db_path, Role::HookRead).unwrap();
        let mut st = conn
            .prepare(
                "SELECT COALESCE(query, fetch_prompt) FROM (SELECT * FROM event ORDER BY id DESC \
                 LIMIT 300) WHERE COALESCE(query, fetch_prompt, '') != ''",
            )
            .unwrap();
        let texts: Vec<String> = st
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        texts.iter().filter_map(|t| fts::match_expr(t)).collect()
    };
    let variants: &[(&str, &str)] = &[
        (
            "count",
            "SELECT count(*) FROM event_fts WHERE event_fts MATCH ?1",
        ),
        (
            "rowids",
            "SELECT rowid FROM event_fts WHERE event_fts MATCH ?1",
        ),
        (
            "bm25_only",
            "SELECT rowid, -bm25(event_fts) FROM event_fts WHERE event_fts MATCH ?1",
        ),
        (
            "bm25_sorted",
            "SELECT rowid, bm25(event_fts) AS b FROM event_fts WHERE event_fts MATCH ?1 ORDER BY b",
        ),
    ];
    for (name, sql) in variants {
        let mut times = Vec::new();
        let mut rows_total = 0usize;
        for expr in &exprs {
            let conn = db::open(&db_path, Role::HookRead).unwrap();
            let t = Instant::now();
            if let Ok(p) = std::env::var("AWM_PERF_PRAGMA") {
                conn.execute_batch(&p).unwrap();
            }
            let mut st = conn.prepare_cached(sql).unwrap();
            let mut rows = st.query([expr]).unwrap();
            while let Some(_r) = rows.next().unwrap() {
                rows_total += 1;
            }
            times.push(us(t));
        }
        times.sort_unstable();
        println!(
            "{name:<12} n={} rows/run={} p50={} p95={} max={}",
            times.len(),
            rows_total / times.len(),
            pct(&times, 0.5),
            pct(&times, 0.95),
            times[times.len() - 1]
        );
    }
}
