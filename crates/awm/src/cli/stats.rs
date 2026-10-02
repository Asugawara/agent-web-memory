//! `awm stats`: the §8.2 metrics.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

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
    /// Transcript directory for the quota block (default ~/.claude/projects)
    #[arg(long, value_name = "DIR")]
    pub projects: Option<PathBuf>,
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
        out.insert("query_deny".into(), query_deny(conn)?);
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
        // An unresolvable home only leaves the quota block without transcripts.
        let projects = super::projects_dir(&args.projects).unwrap_or_default();
        out.insert(
            "savings".into(),
            savings(conn, args.since.as_deref(), &projects)?,
        );
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
    let denies = count(
        conn,
        "SELECT COUNT(*) FROM injection WHERE mode = 'deny' AND channel = 'url'",
    )?;
    let refetched = count(
        conn,
        &format!(
            "SELECT COUNT(*) FROM injection i WHERE i.mode = 'deny' AND i.channel = 'url' AND EXISTS ( \
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

/// Time window of `research_after_deny`: a repeat of the denied search by the same agent.
const RETRY_WINDOW_MS: i64 = 120_000;

/// Session, agent id, time, tool use id and trigger text of a deny.
type DenyRow = (String, Option<String>, i64, Option<String>, Option<String>);

/// QD1 §5.4: the PreToolUse deny on repeated searches (`hook = 'PreToolUse'`, `channel = 'query'`).
/// Counts cover shadow and real denies. `relation` is read from the earlier record against the
/// caller: another coding agent first, then the same session (a sibling), then the caller's
/// project (from any event of the caller's session; `other_session_project_unknown` when none
/// was captured). The caller's coding agent is Codex when its transcript is under `/.codex/` or its
/// tool use id starts with `exec-`. `by_age` is cumulative.
fn query_deny(conn: &Connection) -> anyhow::Result<Value> {
    const ROWS: &str = "FROM injection i JOIN injection_item ii ON ii.injection_id = i.id \
        JOIN event e ON e.id = ii.event_id \
        WHERE i.hook = 'PreToolUse' AND i.channel = 'query' AND ii.position = 1";
    let codex = "COALESCE(i.transcript_path LIKE '%/.codex/%' OR i.tool_use_id LIKE 'exec-%', 0)";
    let shadow = count(
        conn,
        "SELECT COUNT(*) FROM injection WHERE hook = 'PreToolUse' AND channel = 'query' AND mode = 'shadow_deny'",
    )?;
    let denied = count(
        conn,
        "SELECT COUNT(*) FROM injection WHERE hook = 'PreToolUse' AND channel = 'query' AND mode = 'deny'",
    )?;
    let mut by_kind = json!({"main": 0, "subagent": 0});
    if let (Value::Object(m), Value::Object(found)) = (
        &mut by_kind,
        grouped(
            conn,
            "SELECT CASE WHEN agent_id IS NULL THEN 'main' ELSE 'subagent' END, COUNT(*) \
             FROM injection WHERE hook = 'PreToolUse' AND channel = 'query' GROUP BY 1",
        )?,
    ) {
        m.extend(found);
    }
    let mut by_relation = json!({
        "sibling": 0, "other_session_same_project": 0, "other_project": 0,
        "other_session_project_unknown": 0, "other_coding_agent": 0
    });
    let relation = format!(
        "SELECT CASE \
           WHEN (e.agent = 'codex') != {codex} THEN 'other_coding_agent' \
           WHEN e.session_id = i.session_id THEN 'sibling' \
           WHEN NOT EXISTS (SELECT 1 FROM event c WHERE c.session_id = i.session_id) \
             THEN 'other_session_project_unknown' \
           WHEN EXISTS (SELECT 1 FROM event c WHERE c.session_id = i.session_id \
                          AND c.cwd_hash = e.cwd_hash) THEN 'other_session_same_project' \
           ELSE 'other_project' END, COUNT(*) {ROWS} GROUP BY 1"
    );
    if let (Value::Object(m), Value::Object(found)) = (&mut by_relation, grouped(conn, &relation)?)
    {
        m.extend(found);
    }
    let within = |ms: i64| {
        count(
            conn,
            &format!("SELECT COUNT(*) {ROWS} AND i.created_at - e.created_at <= {ms}"),
        )
    };
    let mut labels = json!({"2": 0, "1": 0, "0": 0, "h": 0});
    if let (Value::Object(m), Value::Object(found)) = (
        &mut labels,
        grouped(
            conn,
            "SELECT o.label, COUNT(*) FROM outcome o JOIN injection i ON i.id = o.injection_id \
             WHERE i.hook = 'PreToolUse' AND i.channel = 'query' GROUP BY o.label",
        )?,
    ) {
        m.extend(found);
    }
    let searches = count(conn, "SELECT COUNT(*) FROM event WHERE tool = 'WebSearch'")?;
    let per_100 = (searches > 0)
        .then(|| format!("{:.2}", (shadow + denied) as f64 * 100.0 / searches as f64));

    // Research after a deny: the same agent searches the same token set within 2 minutes.
    let mut st = conn.prepare(
        "SELECT session_id, agent_id, created_at, tool_use_id, trigger_text FROM injection \
         WHERE hook = 'PreToolUse' AND channel = 'query' AND mode = 'deny'",
    )?;
    let denies: Vec<DenyRow> = st
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut again = conn.prepare(
        "SELECT query FROM event WHERE tool = 'WebSearch' AND session_id = ?1 AND agent_id IS ?2 \
           AND created_at > ?3 AND created_at <= ?3 + ?4 AND (?5 IS NULL OR tool_use_id != ?5)",
    )?;
    let mut researched = 0;
    for (session, agent, at, tool_use_id, trigger) in &denies {
        let key = crate::normalize::token_set(trigger.as_deref().unwrap_or(""));
        let queries = again.query_map(
            rusqlite::params![session, agent, at, RETRY_WINDOW_MS, tool_use_id],
            |r| r.get::<_, Option<String>>(0),
        )?;
        let mut hit = false;
        for q in queries {
            hit |= q?.is_some_and(|q| crate::normalize::token_set(&q) == key);
        }
        researched += i64::from(hit);
    }
    let n = i64::try_from(denies.len()).unwrap_or(i64::MAX);
    Ok(json!({
        "shadow": shadow,
        "denied": denied,
        "by_agent_kind": by_kind,
        "by_relation": by_relation,
        "by_age": {"within_30_min": within(1_800_000)?, "within_24_h": within(86_400_000)?},
        "labels": labels,
        "per_100_searches": per_100,
        "research_after_deny": {
            "denies": n, "researched": researched, "share": super::pct(researched, n)
        },
    }))
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

/// id, created_at, session, agent, triggering tool_use_id, rendered_chars, mode, Codex.
type ShownInjection = (
    i64,
    i64,
    String,
    Option<String>,
    Option<String>,
    i64,
    String,
    bool,
);

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
    /// `event.bytes`: size of the fetched page, which the fetch summariser read.
    bytes: Option<i64>,
}

fn load_calls(conn: &Connection) -> anyhow::Result<Vec<Call>> {
    let mut st = conn.prepare(
        "SELECT id, tool_use_id, created_at, session_id, agent_id, tool, url_norm, query, status, \
                duration_ms, COALESCE(length(summary), 0), bytes \
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
            bytes: r.get(11)?,
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

/// Median page size of the ok calls in `calls` that recorded more than 0 bytes.
fn median_bytes<'a>(calls: impl Iterator<Item = &'a Call>) -> Option<i64> {
    let mut bytes: Vec<i64> = calls.filter_map(|c| c.bytes).filter(|b| *b > 0).collect();
    super::percentile(&mut bytes, 50.0)
}

/// Time, tokens and page bytes of repeated ok calls: (count, duration ms, summary chars, bytes).
fn repeats(calls: &[Call], fetch: bool) -> (i64, i64, i64, i64) {
    let mut seen = HashSet::new();
    let (mut n, mut ms, mut chars, mut bytes) = (0, 0, 0, 0);
    for c in calls.iter().filter(|c| c.ok && c.is_fetch == fetch) {
        let Some(key) = &c.key else { continue };
        if !seen.insert(key.clone()) {
            n += 1;
            ms += c.duration_ms.unwrap_or(0);
            chars += c.summary_chars;
            bytes += c.bytes.unwrap_or(0).max(0);
        }
    }
    (n, ms, chars, bytes)
}

/// Money for one avoided item. A fetch: the summariser reads `bytes / 4` tokens and writes the
/// summary (`tokens`); a search: the search fee. The main model's read of the summary is priced
/// only when `main_input_per_mtok` is set.
fn item_cost(p: &crate::config::Pricing, fetch: bool, bytes: i64, tokens: f64) -> f64 {
    let main = tokens * p.main_input_per_mtok / 1e6;
    if fetch {
        bytes as f64 / 4.0 * p.summariser_input_per_mtok / 1e6
            + tokens * p.summariser_output_per_mtok / 1e6
            + main
    } else {
        p.search_fee_per_call + main
    }
}

/// Estimated savings. Counterfactual: an avoided item is a shown note whose call was not repeated
/// by the same session and agent afterwards; its cost is the median of the same call's history.
fn savings(conn: &Connection, since: Option<&str>, projects: &Path) -> anyhow::Result<Value> {
    let since_ms = since.map(super::parse_date).transpose()?;
    let pricing = crate::config::load(&crate::paths::config_path()?)?.pricing;
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
        "SELECT id, created_at, session_id, agent_id, tool_use_id, rendered_chars, mode, \
                COALESCE(transcript_path LIKE '%/.codex/%' OR tool_use_id LIKE 'exec-%', 0) \
         FROM injection WHERE mode IN ('inject','deny') AND created_at >= ?1 ORDER BY created_at, id",
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
                r.get(6)?,
                r.get::<_, i64>(7)? != 0,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut items = conn.prepare(
        "SELECT position, event_id FROM injection_item WHERE injection_id = ?1 ORDER BY position",
    )?;

    // Per tool: median over the ok events up to the injection, used only when an item has no
    // history of its own (the item's own history stops at the injection too, RVQ0 m5).
    let fallback = |fetch: bool, at: i64| {
        medians(
            calls
                .iter()
                .filter(|c| c.ok && c.is_fetch == fetch && c.at <= at),
        )
    };
    let fallback_bytes =
        |at: i64| median_bytes(calls.iter().filter(|c| c.ok && c.is_fetch && c.at <= at));

    let (mut avoided, mut followed) = (0_i64, 0_i64);
    let (mut ms, mut chars) = (0.0_f64, 0.0_f64);
    let (mut conf_n, mut conf_ms, mut conf_chars) = (0_i64, 0.0_f64, 0.0_f64);
    let (mut bytes, mut conf_bytes) = (0_i64, 0_i64);
    let (mut cost, mut conf_cost) = (0.0_f64, 0.0_f64);
    let mut overhead = 0.0_f64;
    // Quota block: the cost of every avoided non-Codex item, and the part that was proven.
    let (mut quota_estimated, mut quota_proven, mut codex) = (0.0_f64, 0.0_f64, 0_i64);
    for (id, at, session, agent, tool_use_id, rendered, mode, is_codex) in &injections {
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
            // Only a fetch has a page the summariser would have read; a search adds 0.
            let page = if src.is_fetch {
                let own = median_bytes(
                    by_key
                        .get(key.as_str())
                        .map(|v| v.iter().copied().filter(|e| e.at <= *at))
                        .into_iter()
                        .flatten(),
                );
                own.or_else(|| fallback_bytes(*at)).unwrap_or(0)
            } else {
                0
            };
            let (d, c) = match medians(past) {
                (Some(d), Some(c)) => (Some(d), Some(c)),
                (d, c) => {
                    let fb = fallback(src.is_fetch, *at);
                    (d.or(fb.0), c.or(fb.1))
                }
            };
            costs.push((
                labelled2.contains(&(*id, position)),
                d.unwrap_or(0) as f64,
                c.unwrap_or(0) as f64 / 4.0,
                page,
                item_cost(&pricing, src.is_fetch, page, c.unwrap_or(0) as f64 / 4.0),
            ));
        }
        if recalled {
            followed += 1;
            continue;
        }
        avoided += 1;
        if *is_codex {
            codex += 1;
        }
        for (two, d, t, page, c) in costs {
            cost += c;
            if !*is_codex {
                quota_estimated += c;
                if two || mode == "deny" {
                    quota_proven += c;
                }
            }
            ms += d;
            chars += t;
            bytes += page;
            if two {
                conf_bytes += page;
                conf_cost += c;
                conf_n += 1;
                conf_ms += d;
                conf_chars += t;
            }
        }
    }
    let (rf_n, rf_ms, rf_chars, rf_bytes) = repeats(&calls, true);
    let (rs_n, rs_ms, rs_chars, rs_bytes) = repeats(&calls, false);
    let ceiling = |fetch: bool, n: i64, ms: i64, chars: i64, bytes: i64| {
        let tokens = chars as f64 / 4.0;
        let total = if fetch {
            // Linear in bytes and tokens, so the totals price the same as the items.
            item_cost(&pricing, true, bytes, tokens)
        } else {
            n as f64 * pricing.search_fee_per_call + tokens * pricing.main_input_per_mtok / 1e6
        };
        json!({
            "est_cost": total,
            "count": n,
            "duration_ms": ms,
            "tokens": chars as f64 / 4.0,
            "bytes": bytes,
            "summariser_tokens": bytes / 4,
        })
    };
    let quota = quota_section(
        quota_estimated,
        quota_proven,
        codex,
        &pricing,
        projects,
        super::now_ms(),
    );
    Ok(json!({
        "since": since,
        "shown": injections.len(),
        "avoided": avoided,
        "followed_up": followed,
        "time_saved_ms": ms,
        "tokens_saved": chars,
        "overhead_tokens": overhead,
        "net_tokens": chars - overhead,
        "est_cost": cost,
        "overhead_cost": overhead * pricing.main_input_per_mtok / 1e6,
        "net_cost": (pricing.main_input_per_mtok > 0.0)
            .then(|| cost - overhead * pricing.main_input_per_mtok / 1e6),
        "pricing": {
            "currency": pricing.currency,
            "summariser_input_per_mtok": pricing.summariser_input_per_mtok,
            "summariser_output_per_mtok": pricing.summariser_output_per_mtok,
            "search_fee_per_call": pricing.search_fee_per_call,
            "main_input_per_mtok": pricing.main_input_per_mtok,
        },
        "est_bytes_not_fetched": bytes,
        "est_summariser_tokens": bytes / 4,
        "confirmed": {
            "items": conf_n,
            "time_saved_ms": conf_ms,
            "tokens_saved": conf_chars,
            "est_bytes_not_fetched": conf_bytes,
            "est_summariser_tokens": conf_bytes / 4,
            "est_cost": conf_cost,
        },
        "ceiling": {
            "repeat_fetches": ceiling(true, rf_n, rf_ms, rf_chars, rf_bytes),
            "repeat_searches": ceiling(false, rs_n, rs_ms, rs_chars, rs_bytes),
        },
        "quota": quota,
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
    if tokens >= 1_000_000.0 {
        format!("{:.1}M", tokens / 1_000_000.0)
    } else {
        format!("{:.1}k", tokens / 1000.0)
    }
}

/// The summariser column: an upper bound, `0k` when nothing was read.
fn upper_bound(tokens: f64) -> String {
    if tokens == 0.0 {
        "<= 0k".into()
    } else {
        format!("<= {}", kilo(tokens))
    }
}

/// Decimal KB or MB with one decimal.
fn size(bytes: f64) -> String {
    if bytes >= 1_000_000.0 {
        format!("{:.1} MB", bytes / 1_000_000.0)
    } else {
        format!("{:.1} KB", bytes / 1000.0)
    }
}

/// `text` wrapped at `width` columns, every line indented by two spaces.
fn wrap(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut line = String::from("  ");
    for word in text.split_whitespace() {
        if line.len() > 2 && line.len() + 1 + word.len() > width {
            out.push_str(&line);
            out.push('\n');
            line = String::from("  ");
        }
        if line.len() > 2 {
            line.push(' ');
        }
        line.push_str(word);
    }
    out.push_str(&line);
    out.push('\n');
    out
}

/// `$1.31` (USD) or `1.31 EUR`; `<$0.01` for a positive amount that rounds to nothing.
fn money(amount: f64, currency: &str) -> String {
    let usd = currency == "USD";
    let (pre, post) = if usd {
        ("$".to_string(), String::new())
    } else {
        (String::new(), format!(" {currency}"))
    };
    if amount > 0.0 && amount < 0.005 {
        format!("<{pre}0.01{post}")
    } else {
        format!("{pre}{amount:.2}{post}")
    }
}

fn savings_text(v: &Value) -> String {
    let int = |k: &str| v[k].as_i64().unwrap_or(0);
    let row = |label: &str, items: f64, base: &[&str], bytes: Option<(f64, f64)>| {
        let mut r = vec![label.to_string(), (items as i64).to_string()];
        r.extend(base.iter().map(|s| s.to_string()));
        match bytes {
            Some((b, t)) => {
                r.push(size(b));
                r.push(upper_bound(t));
            }
            None => r.extend(["-".to_string(), "-".to_string()]),
        }
        r
    };
    let fetches = ["ceiling", "repeat_fetches"];
    let searches = ["ceiling", "repeat_searches"];
    let cells = |path: &[&str], key_bytes: &str, key_tokens: &str, time: &str, tokens: &str| {
        let at = |k: &str| {
            let mut p = path.to_vec();
            p.push(k);
            num(v, &p)
        };
        (
            minutes(at(time)),
            kilo(at(tokens)),
            at(key_bytes),
            at(key_tokens),
        )
    };
    let avoided = cells(
        &[],
        "est_bytes_not_fetched",
        "est_summariser_tokens",
        "time_saved_ms",
        "tokens_saved",
    );
    let confirmed = cells(
        &["confirmed"],
        "est_bytes_not_fetched",
        "est_summariser_tokens",
        "time_saved_ms",
        "tokens_saved",
    );
    let rf = cells(
        &fetches,
        "bytes",
        "summariser_tokens",
        "duration_ms",
        "tokens",
    );
    let rs = cells(
        &searches,
        "bytes",
        "summariser_tokens",
        "duration_ms",
        "tokens",
    );
    let currency = v["pricing"]["currency"].as_str().unwrap_or("USD");
    let mut rows = vec![
        row(
            "avoided (est.)",
            int("avoided") as f64,
            &[&avoided.0, &avoided.1],
            Some((avoided.2, avoided.3)),
        ),
        row(
            "confirmed (label 2)",
            num(v, &["confirmed", "items"]),
            &[&confirmed.0, &confirmed.1],
            Some((confirmed.2, confirmed.3)),
        ),
        row(
            "ceiling: repeat fetches",
            num(v, &["ceiling", "repeat_fetches", "count"]),
            &[&rf.0, &rf.1],
            Some((rf.2, rf.3)),
        ),
        row(
            "ceiling: repeat searches",
            num(v, &["ceiling", "repeat_searches", "count"]),
            &[&rs.0, &rs.1],
            None,
        ),
    ];
    let cost_paths: [&[&str]; 4] = [
        &[],
        &["confirmed"],
        &["ceiling", "repeat_fetches"],
        &["ceiling", "repeat_searches"],
    ];
    for (r, path) in rows.iter_mut().zip(cost_paths) {
        let mut p = path.to_vec();
        p.push("est_cost");
        r.push(money(num(v, &p), currency));
    }
    let head = [
        "",
        "items",
        "time",
        "tokens",
        "page bytes",
        "summariser",
        "cost",
    ];
    let widths: Vec<usize> = (0..head.len())
        .map(|c| {
            rows.iter()
                .map(|r| r[c].len())
                .chain([head[c].len()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let line = |r: &[String]| {
        let mut o = format!("  {:<w$}", r[0], w = widths[0]);
        for c in 1..r.len() {
            o.push_str(&format!("  {:>w$}", r[c], w = widths[c]));
        }
        o.push('\n');
        o
    };
    let mut o = String::from("savings: an estimate of what did not happen, not a measurement\n\n");
    o.push_str(&line(&head.map(String::from)));
    for r in &rows {
        o.push_str(&line(r));
    }
    o.push('\n');
    if int("shown") == 0 {
        o.push_str("  No notes shown yet.\n");
    } else {
        o.push_str(&format!(
            "  shown {} = avoided {} + followed up {}; note overhead {} tokens, net {}; est. cost {}",
            int("shown"),
            int("avoided"),
            int("followed_up"),
            kilo(num(v, &["overhead_tokens"])),
            kilo(num(v, &["net_tokens"])),
            money(num(v, &["est_cost"]), currency)
        ));
        if !v["net_cost"].is_null() {
            o.push_str(&format!(
                ", net {} after pricing the note overhead",
                money(num(v, &["net_cost"]), currency)
            ));
        }
        o.push('\n');
    }
    if let Some(d) = v["since"].as_str() {
        o.push_str(&format!("  since {d} (ceilings use the whole record)\n"));
    }
    o.push('\n');
    let footnote = wrap(
        "tokens: main-model context, summary chars / 4. page bytes: what the fetch summariser read; \
         summariser tokens <= bytes / 4 (upper bound). per avoided item: median of past ok calls of \
         the same url or normalised query (fallback: all ok calls of that tool). confirmed: avoided \
         items you labelled 2 in awm review. cost: fetch summariser tokens at [pricing] rates \
         (default Claude Haiku 4.5: $1/M in, $5/M out) plus $0.01 per avoided search (Anthropic web \
         search fee); main-model tokens priced only when main_input_per_mtok is set; a subscription \
         pays none of this per call.",
        100,
    );
    o.push_str(&footnote);
    o.push_str(&quota_text(&v["quota"]));
    o
}

/// The `savings.quota` block (plan-quota §8, §10.2): the calibration of the status line samples
/// priced with the saved cost. `estimated` and `proven` are in USD, the cost column's unit; with
/// another currency no sample is read and the status is `not_usd`.
fn quota_section(
    estimated: f64,
    proven: f64,
    codex: i64,
    pricing: &crate::config::Pricing,
    projects: &Path,
    now_ms: i64,
) -> Value {
    use crate::quota::{calibrate, store, totals};
    let usd = pricing.currency == "USD";
    let samples = match (usd, crate::paths::data_dir()) {
        (true, Ok(dir)) => store::read_all(&dir.join(crate::quota::DIR)),
        _ => Vec::new(),
    };
    let sids: HashSet<String> = samples.iter().map(|s| s.sid.clone()).collect();
    let sessions = totals::read(projects, &sids);
    let cal = calibrate::calibrate(&samples, &sessions, now_ms);
    let mut v = serde_json::to_value(&cal).unwrap_or(Value::Null);
    if !usd {
        v["status"] = json!("not_usd");
    }
    let pct = |band: &calibrate::Band, saved: f64| {
        serde_json::to_value(band.scale(saved)).unwrap_or(Value::Null)
    };
    for (rate, out) in cal
        .rates
        .iter()
        .zip(v["rates"].as_array_mut().into_iter().flatten())
    {
        out["five_hour_pct"] = json!({
            "estimated": pct(&rate.k5, estimated),
            "proven": pct(&rate.k5, proven),
        });
        out["seven_day_pct"] = match &rate.k7 {
            Some(k7) => json!({"estimated": pct(k7, estimated), "proven": pct(k7, proven)}),
            None => Value::Null,
        };
    }
    v["saved_usd"] = json!({"estimated": estimated, "proven": proven});
    v["codex_injections_excluded"] = json!(codex);
    // One rate prices all of the savings; false when a valid window lies outside every
    // rate's group (another account-week), or when several rates price them differently.
    let covered = |rate: &calibrate::Rate| {
        rate.d7_reset.is_none()
            || cal
                .windows
                .list
                .iter()
                .filter(|w| w.verdict == calibrate::Verdict::Valid)
                .all(|w| Some(w.d7_reset) == rate.d7_reset)
    };
    v["rates_cover_all_savings"] = json!(cal.rates.len() < 2 && cal.rates.iter().all(covered));
    v
}

/// `text` wrapped at 100 columns with every line indented by four spaces.
fn wrap_deep(text: &str) -> String {
    wrap(text, 98).lines().map(|l| format!("  {l}\n")).collect()
}

/// `{x:.2}%` below 10, `{x:.1}%` from 10.
fn pct(x: f64) -> String {
    if x < 10.0 {
        format!("{x:.2}%")
    } else {
        format!("{x:.1}%")
    }
}

/// A whole number without decimals, else one decimal.
fn points(x: f64) -> String {
    if x.fract() == 0.0 {
        format!("{x:.0}")
    } else {
        format!("{x:.1}")
    }
}

/// The quota block of `awm stats --savings` (plan-quota §10.1), appended after the footnote.
fn quota_text(v: &Value) -> String {
    let n = |path: &[&str]| num(v, path);
    let int = |path: &[&str]| n(path) as i64;
    match v["status"].as_str().unwrap_or("no_samples") {
        "not_usd" => {
            return wrap(
                "quota: shown only with [pricing] currency = \"USD\"; the status line reports cost in USD.",
                100,
            )
        }
        "no_samples" => {
            return wrap(
                "quota: no status line samples yet. To see these savings as a share of your 5-hour \
                 and 7-day usage limits, run: awm setup --statusline",
                100,
            )
        }
        "collecting" => {
            return wrap(
                &format!(
                    "quota: collecting status line samples ({} from {} sessions, the first on {}). \
                     A figure needs 5 five-hour windows on 2 days with at least 10 points and $20 \
                     of local use each, per 7-day reset; {} valid windows so far.",
                    int(&["samples"]),
                    int(&["sessions"]),
                    super::fmt_day(int(&["first_sample_ms"])),
                    int(&["windows", "valid"]),
                ),
                100,
            )
        }
        _ => {}
    }
    let rates = v["rates"].as_array().cloned().unwrap_or_default();
    let mut o = wrap(
        &format!(
            "quota: share of your Claude usage limits ({} status line samples from {} sessions)",
            int(&["samples"]),
            int(&["sessions"]),
        ),
        100,
    );
    for r in &rates {
        let f = |path: &[&str]| num(r, path);
        let label = match r["d7_reset"].as_i64() {
            None => "all windows".to_string(),
            Some(0) => "no 7-day reset".to_string(),
            Some(d) => format!("7d reset {}", super::fmt_day(d * 1000)),
        };
        let k5 = f(&["k5", "w1"]);
        o.push_str(&wrap(
            &format!(
                "{label}, {} windows on {} days: 1% of a 5h window = {} (windows {}-{})",
                int_of(r, "windows"),
                int_of(r, "days"),
                money(1.0 / k5, "USD"),
                money(1.0 / f(&["spread5", "p75"]), "USD"),
                money(1.0 / f(&["spread5", "p25"]), "USD"),
            ),
            100,
        ));
        // `pending`: the estimated figure says so when σ is unknown; a proven one stays silent.
        let line = |name: &str, pcts: &Value| {
            let part = |kind: &str, pending: bool| {
                let at = |w: &str| pcts[kind][w].as_f64();
                let x = at("w1").unwrap_or(0.0);
                let range = match (at("w10"), at("w0")) {
                    _ if x <= 0.0 => String::new(),
                    (Some(lo), Some(hi)) => format!(" ({}-{})", pct(lo), pct(hi)),
                    _ if pending => " (range pending)".to_string(),
                    _ => String::new(),
                };
                (pct(x), range)
            };
            let (est, est_range) = part("estimated", true);
            let (proven, mut proven_range) = part("proven", false);
            if n(&["saved_usd", "proven"]) <= 0.0 {
                proven_range = " (no denied calls or labelled items yet)".to_string();
            }
            format!(
                "{name}: estimated {est} of one window in total{est_range}, proven {proven}{proven_range}"
            )
        };
        o.push_str(&wrap_deep(&line("5h", &r["five_hour_pct"])));
        if r["seven_day_pct"].is_null() {
            o.push_str(&wrap_deep(&format!(
                "7d: collecting ({} of 10 points of 7-day use in these windows)",
                points(f(&["dp7_sum"]))
            )));
        } else {
            o.push_str(&wrap_deep(&line("7d", &r["seven_day_pct"])));
        }
    }
    let mut notes = Vec::new();
    if rates.len() >= 2 {
        notes.push(
            "savings are not split by account; each line prices all of them at its own rate."
                .to_string(),
        );
    } else if v["rates_cover_all_savings"] == json!(false) {
        notes.push("savings from all accounts are priced at this account-week's rate".to_string());
    }
    for r in &rates {
        let weeks = int_of(r, "account_weeks");
        if r["selection"] == "pooled" && weeks > 1 {
            notes.push(format!(
                "these windows come from {weeks} account-weeks, pooled; their plans may differ."
            ));
        }
    }
    let saturated = int(&["windows", "saturated"]);
    if saturated > 0 {
        notes.push(format!(
            "{saturated} windows reached 100%; samples after that point are not used."
        ));
    }
    if let Some(r) = rates.iter().find(|r| r["cache_read_share"].is_null()) {
        notes.push(format!(
            "the cache-read range needs the totals of 3 finished sessions in these windows; {} so far.",
            int_of(r, "sessions_with_totals")
        ));
    }
    let codex = int(&["codex_injections_excluded"]);
    if codex > 0 {
        notes.push(format!(
            "{codex} Codex {} not counted (Codex has its own limits).",
            if codex == 1 {
                "injection is"
            } else {
                "injections are"
            }
        ));
    }
    for note in notes {
        o.push_str(&wrap(&format!("note: {note}"), 100));
    }
    o.push_str(&wrap(
        "estimated: an upper bound; it assumes every avoided note replaced a call, and the fetch \
         summariser read <= bytes / 4 tokens. proven: denied calls and items you labelled 2. $: \
         list-price use as Claude Code reports it to the status line. Ranges: the limit counting \
         cached tokens at 10x to 0x their list price; models and other token kinds weighted like \
         list prices. Use on claude.ai or other machines, which the samples cannot see, makes the \
         figures too high.",
        100,
    ));
    o
}

fn int_of(v: &Value, key: &str) -> i64 {
    v[key].as_i64().unwrap_or(0)
}
