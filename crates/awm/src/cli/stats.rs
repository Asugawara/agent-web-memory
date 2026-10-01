//! `awm stats`: the §8.2 metrics.

use std::collections::BTreeMap;

use rusqlite::Connection;
use serde_json::{json, Map, Value};

const FOLLOWUP_WINDOW_MS: i64 = 120_000;

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Hook latency per hook and agent kind
    #[arg(long)]
    pub latency: bool,
    /// Import coverage
    #[arg(long)]
    pub import: bool,
    /// Record status mix
    #[arg(long)]
    pub status: bool,
    /// Value rate: label-2 items per shown item and per 100 captured events
    #[arg(long)]
    pub value: bool,
    /// Injections followed by a web call to the same URL
    #[arg(long)]
    pub followups: bool,
    /// Print JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let conn = super::open_db()?;
    let v = collect(&conn, &args)?;
    if args.json {
        println!("{v}");
    } else {
        let mut out = String::new();
        super::render_value(&v, 0, &mut out);
        print!("{out}");
    }
    Ok(())
}

/// The selected sections as one object; the default section when no flag is given.
pub fn collect(conn: &Connection, args: &Args) -> anyhow::Result<Value> {
    let any = args.latency || args.import || args.status || args.value || args.followups;
    let mut out = Map::new();
    if !any {
        out.insert("injections".into(), injections(conn)?);
    }
    if args.latency {
        out.insert("latency".into(), latency(conn)?);
    }
    if args.import {
        out.insert("import".into(), import(conn)?);
    }
    if args.status {
        out.insert("status".into(), status(conn)?);
    }
    if args.value {
        out.insert("value".into(), value(conn)?);
    }
    if args.followups {
        out.insert("followups".into(), followups(conn)?);
    }
    Ok(Value::Object(out))
}

fn count(conn: &Connection, sql: &str) -> anyhow::Result<i64> {
    Ok(conn.query_row(sql, [], |r| r.get(0))?)
}

/// Rows of (key, count) as an object.
fn grouped(conn: &Connection, sql: &str) -> anyhow::Result<Value> {
    let mut st = conn.prepare(sql)?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    let mut m = Map::new();
    for r in rows {
        let (k, n) = r?;
        m.insert(k, json!(n));
    }
    Ok(Value::Object(m))
}

fn injections(conn: &Connection) -> anyhow::Result<Value> {
    let kind = "CASE WHEN agent_id IS NULL THEN 'main' ELSE 'subagent' END";
    let shown = "mode IN ('inject','deny')";
    let would = "mode IN ('shadow','shadow_deny')";
    let mut day: BTreeMap<String, i64> = BTreeMap::new();
    let mut st = conn.prepare(&format!("SELECT created_at FROM injection WHERE {shown}"))?;
    for ms in st.query_map([], |r| r.get::<_, i64>(0))? {
        *day.entry(super::fmt_day(ms?)).or_default() += 1;
    }
    let mut precision = Map::new();
    let mut st = conn.prepare(
        "SELECT i.channel, \
                SUM(o.label IN ('1','2')), SUM(o.label = '2'), COUNT(*) \
         FROM outcome o JOIN injection i ON i.id = o.injection_id \
         WHERE i.mode IN ('inject','deny') GROUP BY i.channel ORDER BY i.channel",
    )?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    for r in rows {
        let (ch, loose, strict, labelled) = r?;
        precision.insert(
            ch,
            json!({
                "labelled": labelled,
                "loose": super::pct(loose, labelled),
                "strict": super::pct(strict, labelled),
            }),
        );
    }
    let with_label = |labels: &str| {
        count(
            conn,
            &format!(
                "SELECT COUNT(DISTINCT o.injection_id) FROM outcome o \
                 JOIN injection i ON i.id = o.injection_id \
                 WHERE i.mode IN ('inject','deny') AND o.label IN ({labels})"
            ),
        )
    };
    let mut chars: Vec<i64> = conn
        .prepare(&format!(
            "SELECT rendered_chars FROM injection WHERE {shown}"
        ))?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let refetch = refetch_after_deny(conn)?;
    Ok(json!({
        "shown": count(conn, &format!("SELECT COUNT(*) FROM injection WHERE {shown}"))?,
        "shown_by_channel": grouped(conn, &format!("SELECT channel, COUNT(*) FROM injection WHERE {shown} GROUP BY channel ORDER BY channel"))?,
        "shown_by_agent_kind": grouped(conn, &format!("SELECT {kind}, COUNT(*) FROM injection WHERE {shown} GROUP BY 1 ORDER BY 1"))?,
        "shown_by_day": day,
        "would_have_shown": count(conn, &format!("SELECT COUNT(*) FROM injection WHERE {would}"))?,
        "would_have_shown_by_channel": grouped(conn, &format!("SELECT channel, COUNT(*) FROM injection WHERE {would} GROUP BY channel ORDER BY channel"))?,
        "accepted": with_label("'1','2'")?,
        "changed_next_step": with_label("'2'")?,
        "harmful": with_label("'h'")?,
        "per_note_precision": precision,
        "refetch_after_deny": refetch,
        "rendered_chars": {
            "p50": super::percentile(&mut chars, 50.0),
            "p95": super::percentile(&mut chars, 95.0),
        },
    }))
}

fn refetch_after_deny(conn: &Connection) -> anyhow::Result<Value> {
    let denies = count(conn, "SELECT COUNT(*) FROM injection WHERE mode = 'deny'")?;
    let refetched = count(
        conn,
        &format!(
            "SELECT COUNT(*) FROM injection i WHERE i.mode = 'deny' AND EXISTS ( \
               SELECT 1 FROM injection_item ii JOIN event src ON src.id = ii.event_id \
               JOIN event e ON e.url_norm = src.url_norm \
                 AND e.session_id = i.session_id AND e.agent_id IS i.agent_id \
                 AND e.created_at > i.created_at AND e.created_at <= i.created_at + {FOLLOWUP_WINDOW_MS} \
                 AND (i.tool_use_id IS NULL OR e.tool_use_id != i.tool_use_id) \
               WHERE ii.injection_id = i.id AND src.url_norm IS NOT NULL)"
        ),
    )?;
    Ok(json!({"denies": denies, "refetched": refetched, "share": super::pct(refetched, denies)}))
}

/// Total times, search times and deadline hits of one hook and agent kind.
type LatencyGroup = (Vec<i64>, Vec<i64>, i64);

fn latency(conn: &Connection) -> anyhow::Result<Value> {
    let mut groups: BTreeMap<(String, String), LatencyGroup> = BTreeMap::new();
    let mut st =
        conn.prepare("SELECT hook, agent_kind, total_ms, search_ms, outcome FROM hook_run")?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Option<i64>>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    for r in rows {
        let (hook, kind, total, search, outcome) = r?;
        let g = groups.entry((hook, kind)).or_default();
        g.0.push(total);
        if let Some(s) = search {
            g.1.push(s);
        }
        if outcome == "deadline" {
            g.2 += 1;
        }
    }
    let mut out = Map::new();
    for ((hook, kind), (mut total, mut search, deadlines)) in groups {
        let n = i64::try_from(total.len()).unwrap_or(i64::MAX);
        out.insert(
            format!("{hook}/{kind}"),
            json!({
                "runs": n,
                "total_ms_p50": super::percentile(&mut total, 50.0),
                "total_ms_p95": super::percentile(&mut total, 95.0),
                "search_ms_p50": super::percentile(&mut search, 50.0),
                "search_ms_p95": super::percentile(&mut search, 95.0),
                "deadline_share": super::pct(deadlines, n),
            }),
        );
    }
    Ok(Value::Object(out))
}

fn import(conn: &Connection) -> anyhow::Result<Value> {
    let found = count(
        conn,
        "SELECT COALESCE(SUM(events_found),0) FROM import_source",
    )?;
    let inserted = count(
        conn,
        "SELECT COALESCE(SUM(events_inserted),0) FROM import_source",
    )?;
    Ok(json!({
        "files": grouped(conn, "SELECT status, COUNT(*) FROM import_source GROUP BY status ORDER BY status")?,
        "records_found": found,
        "records_inserted": inserted,
        "records_not_inserted": found - inserted,
    }))
}

fn status(conn: &Connection) -> anyhow::Result<Value> {
    grouped(
        conn,
        "SELECT status, COUNT(*) FROM event GROUP BY status ORDER BY status",
    )
}

/// §8.2 value rate. `label2_over_shown` is the plain share of label-2 items among shown items;
/// `per_100_captured` is the plan's estimate: per channel, the label-2 share of labelled items
/// times the items shown, summed, plus label-2 denies, over hook-captured events, times 100.
fn value(conn: &Connection) -> anyhow::Result<Value> {
    let shown = count(
        conn,
        "SELECT COUNT(*) FROM injection_item ii JOIN injection i ON i.id = ii.injection_id \
         WHERE i.mode IN ('inject','deny')",
    )?;
    let label2 = count(
        conn,
        "SELECT COUNT(*) FROM outcome o JOIN injection i ON i.id = o.injection_id \
         WHERE i.mode IN ('inject','deny') AND o.label = '2'",
    )?;
    let mut st = conn.prepare(
        "SELECT i.channel, \
                (SELECT COUNT(*) FROM injection_item x JOIN injection j ON j.id = x.injection_id \
                   WHERE j.mode = 'inject' AND j.channel = i.channel), \
                COUNT(*), SUM(o.label = '2') \
         FROM outcome o JOIN injection i ON i.id = o.injection_id \
         WHERE i.mode = 'inject' GROUP BY i.channel ORDER BY i.channel",
    )?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    let mut estimate = 0.0;
    for r in rows {
        let (items, labelled, two) = r?;
        if labelled > 0 {
            estimate += two as f64 / labelled as f64 * items as f64;
        }
    }
    let deny2 = count(
        conn,
        "SELECT COUNT(*) FROM outcome o JOIN injection i ON i.id = o.injection_id \
         WHERE i.mode = 'deny' AND o.label = '2'",
    )?;
    let captured = count(conn, "SELECT COUNT(*) FROM event WHERE source = 'hook'")?;
    let per_100 = (captured > 0).then(|| (estimate + deny2 as f64) * 100.0 / captured as f64);
    Ok(json!({
        "shown_items": shown,
        "labelled_2": label2,
        "label2_over_shown": super::pct(label2, shown),
        "captured_events": captured,
        "per_100_captured": per_100.map(|v| format!("{v:.1}")),
    }))
}

fn followups(conn: &Connection) -> anyhow::Result<Value> {
    let mut out = Map::new();
    for (name, modes) in [
        ("shown", "'inject','deny'"),
        ("would_have_shown", "'shadow','shadow_deny'"),
    ] {
        let total = count(
            conn,
            &format!("SELECT COUNT(*) FROM injection WHERE mode IN ({modes})"),
        )?;
        let followed = |window: &str| {
            count(
                conn,
                &format!(
                    "SELECT COUNT(*) FROM injection i WHERE i.mode IN ({modes}) AND EXISTS ( \
                       SELECT 1 FROM injection_item ii JOIN event src ON src.id = ii.event_id \
                       JOIN event e ON e.url_norm = src.url_norm \
                         AND e.session_id = i.session_id AND e.agent_id IS i.agent_id \
                         AND e.created_at > i.created_at {window} \
                         AND (i.tool_use_id IS NULL OR e.tool_use_id != i.tool_use_id) \
                       WHERE ii.injection_id = i.id AND src.url_norm IS NOT NULL)"
                ),
            )
        };
        let in_session = followed("")?;
        let in_2min = followed(&format!(
            "AND e.created_at <= i.created_at + {FOLLOWUP_WINDOW_MS}"
        ))?;
        out.insert(
            name.into(),
            json!({
                "injections": total,
                "followed_in_session": in_session,
                "followed_within_2_min": in_2min,
                "share_in_session": super::pct(in_session, total),
            }),
        );
    }
    Ok(Value::Object(out))
}
