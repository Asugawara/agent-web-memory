//! `awm stats`: the §8.2 metrics.

use std::collections::{BTreeMap, HashMap, HashSet};

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
    /// Estimated time and tokens saved by the notes shown (a counterfactual estimate)
    #[arg(long)]
    pub savings: bool,
    /// With --savings: only injections created on or after this date (YYYY-MM-DD, UTC)
    #[arg(long, value_name = "DATE")]
    pub since: Option<String>,
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
        if let Value::Object(map) = &v {
            for (k, val) in map {
                if k == "savings" {
                    out.push_str(&savings_text(val));
                } else if k == "by_agent" {
                    out.push_str(&by_agent_text(val));
                } else {
                    let mut one = Map::new();
                    one.insert(k.clone(), val.clone());
                    super::render_value(&Value::Object(one), 0, &mut out);
                }
            }
        }
        print!("{out}");
    }
    Ok(())
}

/// The selected sections as one object; the default section when no flag is given.
pub fn collect(conn: &Connection, args: &Args) -> anyhow::Result<Value> {
    let any =
        args.latency || args.import || args.status || args.value || args.followups || args.savings;
    let mut out = Map::new();
    if !any {
        out.insert("by_agent".into(), by_agent(conn)?);
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
    if args.savings {
        out.insert("savings".into(), savings(conn, args.since.as_deref())?);
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

/// Events per coding agent (`event.agent`); both agents are always listed.
fn by_agent(conn: &Connection) -> anyhow::Result<Value> {
    let mut v = json!({"claude": 0, "codex": 0});
    if let (Value::Object(m), Value::Object(found)) = (
        &mut v,
        grouped(conn, "SELECT agent, COUNT(*) FROM event GROUP BY agent")?,
    ) {
        m.extend(found);
    }
    Ok(v)
}

/// `by agent: claude N, codex M`.
fn by_agent_text(v: &Value) -> String {
    let parts: Vec<String> = v
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, n)| format!("{k} {n}"))
        .collect();
    format!("by agent: {}\n", parts.join(", "))
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

/// id, created_at, session, agent, triggering tool_use_id, rendered_chars.
type ShownInjection = (i64, i64, String, Option<String>, Option<String>, i64);

/// One web call with the fields the savings estimate needs.
struct Call {
    id: i64,
    tool_use_id: String,
    at: i64,
    session: String,
    agent: Option<String>,
    /// `u:` + url_norm for a fetch, `q:` + normalised query for a search.
    key: Option<String>,
    is_fetch: bool,
    ok: bool,
    duration_ms: Option<i64>,
    summary_chars: i64,
}

fn load_calls(conn: &Connection) -> anyhow::Result<Vec<Call>> {
    let mut st = conn.prepare(
        "SELECT id, tool_use_id, created_at, session_id, agent_id, tool, url_norm, query, status, \
                duration_ms, COALESCE(length(summary), 0) \
         FROM event ORDER BY created_at, id",
    )?;
    let rows = st.query_map([], |r| {
        let tool: String = r.get(5)?;
        let url_norm: Option<String> = r.get(6)?;
        let query: Option<String> = r.get(7)?;
        let is_fetch = tool == "WebFetch";
        let key = if is_fetch {
            url_norm.map(|u| format!("u:{u}"))
        } else {
            query.map(|q| format!("q:{}", crate::normalize::norm_query(&q)))
        };
        Ok(Call {
            id: r.get(0)?,
            tool_use_id: r.get(1)?,
            at: r.get(2)?,
            session: r.get(3)?,
            agent: r.get(4)?,
            key,
            is_fetch,
            ok: r.get::<_, String>(8)? == "ok",
            duration_ms: r.get(9)?,
            summary_chars: r.get(10)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Median duration (ms) and median summary length (chars) of the ok calls in `calls`.
fn medians<'a>(calls: impl Iterator<Item = &'a Call>) -> (Option<i64>, Option<i64>) {
    let mut durations = Vec::new();
    let mut chars = Vec::new();
    for c in calls {
        if let Some(d) = c.duration_ms {
            durations.push(d);
        }
        chars.push(c.summary_chars);
    }
    (
        super::percentile(&mut durations, 50.0),
        super::percentile(&mut chars, 50.0),
    )
}

/// Time and tokens of repeated ok calls: (count, duration ms, summary chars).
fn repeats(calls: &[Call], fetch: bool) -> (i64, i64, i64) {
    let mut seen = HashSet::new();
    let (mut n, mut ms, mut chars) = (0, 0, 0);
    for c in calls.iter().filter(|c| c.ok && c.is_fetch == fetch) {
        let Some(key) = &c.key else { continue };
        if !seen.insert(key.clone()) {
            n += 1;
            ms += c.duration_ms.unwrap_or(0);
            chars += c.summary_chars;
        }
    }
    (n, ms, chars)
}

/// Estimated savings. Counterfactual: an avoided item is a shown note whose call was not repeated
/// by the same session and agent afterwards; its cost is the median of the same call's history.
fn savings(conn: &Connection, since: Option<&str>) -> anyhow::Result<Value> {
    let since_ms = since.map(super::parse_date).transpose()?;
    let calls = load_calls(conn)?;
    let by_id: HashMap<i64, &Call> = calls.iter().map(|c| (c.id, c)).collect();
    let mut by_key: HashMap<&str, Vec<&Call>> = HashMap::new();
    for c in calls.iter().filter(|c| c.ok) {
        if let Some(k) = &c.key {
            by_key.entry(k).or_default().push(c);
        }
    }
    let mut all_calls: HashMap<&str, Vec<&Call>> = HashMap::new();
    for c in &calls {
        if let Some(k) = &c.key {
            all_calls.entry(k).or_default().push(c);
        }
    }
    let labelled2: HashSet<(i64, i64)> = conn
        .prepare("SELECT injection_id, position FROM outcome WHERE label = '2'")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;

    let mut st = conn.prepare(
        "SELECT id, created_at, session_id, agent_id, tool_use_id, rendered_chars FROM injection \
         WHERE mode IN ('inject','deny') AND created_at >= ?1 ORDER BY created_at, id",
    )?;
    let injections: Vec<ShownInjection> = st
        .query_map([since_ms.unwrap_or(i64::MIN)], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut items = conn.prepare(
        "SELECT position, event_id FROM injection_item WHERE injection_id = ?1 ORDER BY position",
    )?;

    // Per tool: median over all ok events, used when an item has no history of its own.
    let fallback = |fetch: bool| medians(calls.iter().filter(|c| c.ok && c.is_fetch == fetch));
    let (fb_fetch, fb_search) = (fallback(true), fallback(false));

    let (mut avoided, mut followed) = (0_i64, 0_i64);
    let (mut ms, mut chars) = (0.0_f64, 0.0_f64);
    let (mut conf_n, mut conf_ms, mut conf_chars) = (0_i64, 0.0_f64, 0.0_f64);
    let mut overhead = 0.0_f64;
    for (id, at, session, agent, tool_use_id, rendered) in &injections {
        overhead += *rendered as f64 / 4.0;
        let rows: Vec<(i64, i64)> = items
            .query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut costs = Vec::new();
        let mut recalled = false;
        for (position, event_id) in rows {
            let Some(src) = by_id.get(&event_id) else {
                continue;
            };
            let Some(key) = &src.key else { continue };
            recalled |= all_calls.get(key.as_str()).is_some_and(|v| {
                v.iter().any(|e| {
                    e.session == *session
                        && e.agent == *agent
                        && e.at > *at
                        && tool_use_id.as_deref() != Some(e.tool_use_id.as_str())
                })
            });
            let past = by_key
                .get(key.as_str())
                .map(|v| v.iter().copied().filter(|e| e.at <= *at))
                .into_iter()
                .flatten();
            let (d, c) = match medians(past) {
                (None, None) => {
                    if src.is_fetch {
                        fb_fetch
                    } else {
                        fb_search
                    }
                }
                (d, c) => {
                    let fb = if src.is_fetch { fb_fetch } else { fb_search };
                    (d.or(fb.0), c.or(fb.1))
                }
            };
            costs.push((
                labelled2.contains(&(*id, position)),
                d.unwrap_or(0) as f64,
                c.unwrap_or(0) as f64 / 4.0,
            ));
        }
        if recalled {
            followed += 1;
            continue;
        }
        avoided += 1;
        for (two, d, t) in costs {
            ms += d;
            chars += t;
            if two {
                conf_n += 1;
                conf_ms += d;
                conf_chars += t;
            }
        }
    }
    let (rf_n, rf_ms, rf_chars) = repeats(&calls, true);
    let (rs_n, rs_ms, rs_chars) = repeats(&calls, false);
    let ceiling = |n: i64, ms: i64, chars: i64| json!({"count": n, "duration_ms": ms, "tokens": chars as f64 / 4.0});
    Ok(json!({
        "since": since,
        "shown": injections.len(),
        "avoided": avoided,
        "followed_up": followed,
        "time_saved_ms": ms,
        "tokens_saved": chars,
        "overhead_tokens": overhead,
        "net_tokens": chars - overhead,
        "confirmed": {"items": conf_n, "time_saved_ms": conf_ms, "tokens_saved": conf_chars},
        "ceiling": {
            "repeat_fetches": ceiling(rf_n, rf_ms, rf_chars),
            "repeat_searches": ceiling(rs_n, rs_ms, rs_chars),
        },
    }))
}

fn num(v: &Value, path: &[&str]) -> f64 {
    path.iter()
        .try_fold(v, |v, k| v.get(*k))
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
}

fn minutes(ms: f64) -> String {
    format!("{:.1} min", ms / 60_000.0)
}

fn kilo(tokens: f64) -> String {
    format!("{:.1}k", tokens / 1000.0)
}

fn savings_text(v: &Value) -> String {
    let since = v["since"].as_str().map(|d| format!(" since {d}"));
    let mut o = String::from("savings (an estimate of what did not happen, not a measurement):\n");
    o.push_str(&format!(
        "  shown: injections with mode inject or deny{}\n",
        since.unwrap_or_default()
    ));
    o.push_str(
        "  avoided: shown, and no item was called again by the same session and agent afterwards\n",
    );
    o.push_str("  followed up: shown, and the agent called an item anyway\n");
    o.push_str("  time saved: per avoided item, median duration of past ok calls of the same url or normalised query (fallback: all ok calls of that tool)\n");
    o.push_str("  tokens saved: the same median of summary length, chars / 4; overhead: rendered chars / 4 of all shown\n");
    o.push_str("  confirmed: avoided items you labelled 2 in awm review\n");
    if v["shown"].as_i64() == Some(0) {
        o.push_str("No notes shown yet.\n");
    } else {
        let int = |k: &str| v[k].as_i64().unwrap_or(0);
        o.push_str(&format!("  shown:            {}\n", int("shown")));
        o.push_str(&format!("  avoided:          {}\n", int("avoided")));
        o.push_str(&format!("  followed up:      {}\n", int("followed_up")));
        o.push_str(&format!(
            "  est. time saved:  {}\n",
            minutes(num(v, &["time_saved_ms"]))
        ));
        o.push_str(&format!(
            "  est. tokens saved: {}\n",
            kilo(num(v, &["tokens_saved"]))
        ));
        o.push_str(&format!(
            "  overhead tokens:  {}\n",
            kilo(num(v, &["overhead_tokens"]))
        ));
        o.push_str(&format!(
            "  net tokens:       {}\n",
            kilo(num(v, &["net_tokens"]))
        ));
        o.push_str(&format!(
            "  confirmed:        {} items, {}, {} tokens\n",
            num(v, &["confirmed", "items"]) as i64,
            minutes(num(v, &["confirmed", "time_saved_ms"])),
            kilo(num(v, &["confirmed", "tokens_saved"]))
        ));
    }
    for (label, k) in [
        ("repeat fetches", "repeat_fetches"),
        ("repeat searches", "repeat_searches"),
    ] {
        o.push_str(&format!(
            "  ceiling, {label}: {} ({}, {} tokens; whole record, ignores --since)\n",
            num(v, &["ceiling", k, "count"]) as i64,
            minutes(num(v, &["ceiling", k, "duration_ms"])),
            kilo(num(v, &["ceiling", k, "tokens"]))
        ));
    }
    o
}
