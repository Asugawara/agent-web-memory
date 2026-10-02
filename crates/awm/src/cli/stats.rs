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
    /// With --savings: only injections created on or after this date (YYYY-MM-DD, UTC); with
    /// --team: the first day summed (default: the last 30 days)
    #[arg(long, value_name = "DATE")]
    pub since: Option<String>,
    /// With --value: count only the notes from your records or from teammates' records
    #[arg(long, value_enum)]
    pub origin: Option<super::log::Origin>,
    /// Daily totals of the members who share them (shown when at least 3 members reported)
    #[arg(long)]
    pub team: bool,
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
                } else if k == "team" {
                    out.push_str(&team_text(val));
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
    let any = args.latency
        || args.import
        || args.status
        || args.value
        || args.followups
        || args.savings
        || args.team;
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
        out.insert("value".into(), value(conn, args.origin)?);
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
    if args.team {
        let since = args.since.as_deref().map(super::parse_date).transpose()?;
        out.insert("team".into(), team_totals(conn, since, super::now_ms())?);
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
        grouped(
            conn,
            "SELECT agent, COUNT(*) FROM event WHERE origin = 'local' GROUP BY agent",
        )?,
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
    let searches = count(
        conn,
        "SELECT COUNT(*) FROM event WHERE tool = 'WebSearch' AND origin = 'local'",
    )?;
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
        "SELECT status, COUNT(*) FROM event WHERE origin = 'local' GROUP BY status ORDER BY status",
    )
}

/// `meta` key of a review label `L` ("label 2, and it avoided a multi-step research loop"): the
/// outcome row itself holds label `2` (its CHECK allows no other), this key marks the loop.
pub(crate) fn loop_key(injection_id: i64, position: i64) -> String {
    format!("review.loop.{injection_id}.{position}")
}

/// §8.2 value rate. `label2_over_shown` is the plain share of label-2 items among shown items;
/// `per_100_captured` is the plan's estimate: per channel, the label-2 share of labelled items
/// times the items shown, summed, plus label-2 denies, over hook-captured events, times 100.
///
/// "My captures" (the denominator) are the `origin = 'local'` events. `origin` restricts the
/// numerators to the notes whose item came from your records (`local`) or from teammates'
/// records (`team`, `injection_item.origin`, kept when the record is deleted); without it every
/// shown note counts. For `team` there is no per-100 figure (a teammate's capture is not yours);
/// the line-7 inputs are `labelled`, `labelled_2`, the estimate `label2_estimate` (the label-2
/// share of labelled notes times the notes shown) and `loop_labelled` (review key `L`).
fn value(conn: &Connection, origin: Option<super::log::Origin>) -> anyhow::Result<Value> {
    // `ii` is joined wherever an item's origin is read.
    let only = origin.map_or(String::new(), |o| {
        format!(" AND ii.origin = '{}'", o.as_str())
    });
    let shown = count(
        conn,
        &format!(
            "SELECT COUNT(*) FROM injection_item ii JOIN injection i ON i.id = ii.injection_id \
             WHERE i.mode IN ('inject','deny'){only}"
        ),
    )?;
    let outcomes = "FROM outcome o JOIN injection i ON i.id = o.injection_id \
        JOIN injection_item ii ON ii.injection_id = o.injection_id AND ii.position = o.position";
    let label2 = count(
        conn,
        &format!(
            "SELECT COUNT(*) {outcomes} WHERE i.mode IN ('inject','deny') AND o.label = '2'{only}"
        ),
    )?;
    let labelled = count(
        conn,
        &format!("SELECT COUNT(*) {outcomes} WHERE i.mode IN ('inject','deny'){only}"),
    )?;
    let mut st = conn.prepare(&format!(
        "SELECT i.channel, \
                (SELECT COUNT(*) FROM injection_item ii JOIN injection j ON j.id = ii.injection_id \
                   WHERE j.mode = 'inject' AND j.channel = i.channel{only}), \
                COUNT(*), SUM(o.label = '2') \
         {outcomes} \
         WHERE i.mode = 'inject'{only} GROUP BY i.channel ORDER BY i.channel"
    ))?;
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
        &format!("SELECT COUNT(*) {outcomes} WHERE i.mode = 'deny' AND o.label = '2'{only}"),
    )?;
    let captured = count(
        conn,
        "SELECT COUNT(*) FROM event WHERE source = 'hook' AND origin = 'local'",
    )?;
    let per_100 = (captured > 0).then(|| (estimate + deny2 as f64) * 100.0 / captured as f64);
    let mut v = json!({
        "origin": origin.map_or("all", super::log::Origin::as_str),
        "shown_items": shown,
        "labelled_2": label2,
        "label2_over_shown": super::pct(label2, shown),
        "captured_events": captured,
        "per_100_captured": per_100.map(|v| format!("{v:.1}")),
    });
    if origin == Some(super::log::Origin::Team) {
        let loops = count(
            conn,
            &format!(
                "SELECT COUNT(*) {outcomes} JOIN meta mk \
                   ON mk.key = 'review.loop.' || o.injection_id || '.' || o.position \
                 WHERE i.mode IN ('inject','deny') AND o.label = '2'{only}"
            ),
        )?;
        v["per_100_captured"] = Value::Null;
        v["captured_events"] = Value::Null;
        v["labelled"] = json!(labelled);
        v["label2_over_labelled"] = json!(super::pct(label2, labelled));
        v["label2_estimate"] = json!(format!("{:.1}", estimate + deny2 as f64));
        v["loop_labelled"] = json!(loops);
    }
    Ok(v)
}

/// A day whose totals count in `--team`.
const MIN_REPORTERS: usize = 3;
/// Default window of `--team`, in days.
const TEAM_WINDOW_DAYS: i64 = 30;

/// `sync_state` key of one member's daily totals, kept by the pull (`sync_state.team_stats.*`).
#[cfg(feature = "sync")]
pub(crate) fn team_stats_key(member_id: &str, day: &str) -> String {
    format!("team_stats.{member_id}.{day}")
}

/// `--team`: the sum of the daily `stats` records of the members who share them (tag `stats`,
/// decrypted on pull), over the last 30 days or from `since`. Totals only: the members are
/// counted, never named, and nothing is shown unless at least [`MIN_REPORTERS`] reported.
fn team_totals(conn: &Connection, since: Option<i64>, now_ms: i64) -> anyhow::Result<Value> {
    let from_day = super::fmt_day(since.unwrap_or(now_ms - TEAM_WINDOW_DAYS * 86_400_000));
    let mut st = conn.prepare("SELECT key, value FROM sync_state WHERE key LIKE 'team_stats.%'")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let active: HashSet<String> = conn
        .prepare("SELECT member_id FROM team_member WHERE active = 1")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut reporters = HashSet::new();
    let (mut shown, mut avoided, mut minutes, mut tokens) = (0_u128, 0_u128, 0_u128, 0_u128);
    let mut days = HashSet::new();
    for r in rows {
        let (key, text) = r?;
        let rest = key.trim_start_matches("team_stats.");
        let Some((member, day)) = rest.rsplit_once('.') else {
            continue;
        };
        // Members the roster knows and has not removed; with no roster yet, every reporter.
        if (!active.is_empty() && !active.contains(member)) || day < from_day.as_str() {
            continue;
        }
        let Ok(p) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let get = |k: &str| u128::from(p[k].as_u64().unwrap_or(0));
        reporters.insert(member.to_string());
        days.insert(day.to_string());
        shown += get("shown");
        avoided += get("avoided");
        minutes += get("est_minutes");
        tokens += get("est_tokens");
    }
    let n = reporters.len();
    let mut v = json!({"reported": n, "min_reporters": MIN_REPORTERS, "since": from_day});
    if n >= MIN_REPORTERS {
        v["days"] = json!(days.len());
        v["totals"] = json!({
            "shown": u64::try_from(shown).unwrap_or(u64::MAX),
            "avoided": u64::try_from(avoided).unwrap_or(u64::MAX),
            "est_minutes": u64::try_from(minutes).unwrap_or(u64::MAX),
            "est_tokens": u64::try_from(tokens).unwrap_or(u64::MAX),
        });
    } else {
        v["totals"] = Value::Null;
    }
    Ok(v)
}

fn team_text(v: &Value) -> String {
    let reported = v["reported"].as_u64().unwrap_or(0);
    if v["totals"].is_null() {
        return format!(
            "team: {reported} of the members who share their totals reported since {}; totals \
             appear when at least {MIN_REPORTERS} did.\n",
            v["since"].as_str().unwrap_or("")
        );
    }
    let t = |k: &str| v["totals"][k].as_u64().unwrap_or(0);
    format!(
        "team: {reported} members reported over {} days since {}: {} notes shown, {} follow-ups \
         avoided, about {} min and {} tokens saved (an estimate, totals only)\n",
        v["days"].as_u64().unwrap_or(0),
        v["since"].as_str().unwrap_or(""),
        t("shown"),
        t("avoided"),
        t("est_minutes"),
        t("est_tokens"),
    )
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
    /// `event.origin = 'local'`: a call this machine's agents made.
    local: bool,
    /// `event.member`: the author of a team row.
    member: Option<String>,
}

fn load_calls(conn: &Connection) -> anyhow::Result<Vec<Call>> {
    let mut st = conn.prepare(
        "SELECT id, tool_use_id, created_at, session_id, agent_id, tool, url_norm, query, status, \
                duration_ms, COALESCE(length(summary), 0), bytes, origin, member \
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
            local: r.get::<_, String>(12)? == "local",
            member: r.get(13)?,
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
fn repeats(calls: &[&Call], fetch: bool) -> (i64, i64, i64, i64) {
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

/// This machine's member id from `team.toml`; `None` outside a team.
pub(crate) fn own_member_id() -> Option<String> {
    let dir = crate::paths::data_dir().ok()?;
    let text = std::fs::read_to_string(dir.join(super::where_::TEAM_TOML)).ok()?;
    let v: toml::Value = toml::from_str(&text).ok()?;
    v.get("member_id")?.as_str().map(str::to_string)
}

/// Item sums of one origin (or of everything): the fields of `stats --savings`.
#[derive(Default, Clone)]
struct Acc {
    shown: i64,
    avoided: i64,
    followed: i64,
    ms: f64,
    chars: f64,
    overhead: f64,
    bytes: i64,
    cost: f64,
    conf_n: i64,
    conf_ms: f64,
    conf_chars: f64,
    conf_bytes: i64,
    conf_cost: f64,
}

/// One avoided item's counterfactual: (label 2, ms, tokens, page bytes, cost).
type ItemCosts = (bool, f64, f64, i64, f64);

impl Acc {
    fn add(&mut self, costs: &[ItemCosts]) {
        for &(two, d, t, page, c) in costs {
            self.cost += c;
            self.ms += d;
            self.chars += t;
            self.bytes += page;
            if two {
                self.conf_bytes += page;
                self.conf_cost += c;
                self.conf_n += 1;
                self.conf_ms += d;
                self.conf_chars += t;
            }
        }
    }

    /// The fields `stats --savings` has always printed for the notes (today's fields).
    fn json(&self, pricing: &crate::config::Pricing) -> Value {
        json!({
            "shown": self.shown,
            "avoided": self.avoided,
            "followed_up": self.followed,
            "time_saved_ms": self.ms,
            "tokens_saved": self.chars,
            "overhead_tokens": self.overhead,
            "net_tokens": self.chars - self.overhead,
            "est_cost": self.cost,
            "overhead_cost": self.overhead * pricing.main_input_per_mtok / 1e6,
            "net_cost": (pricing.main_input_per_mtok > 0.0)
                .then(|| self.cost - self.overhead * pricing.main_input_per_mtok / 1e6),
            "est_bytes_not_fetched": self.bytes,
            "est_summariser_tokens": self.bytes / 4,
            "confirmed": {
                "items": self.conf_n,
                "time_saved_ms": self.conf_ms,
                "tokens_saved": self.conf_chars,
                "est_bytes_not_fetched": self.conf_bytes,
                "est_summariser_tokens": self.conf_bytes / 4,
                "est_cost": self.conf_cost,
            },
        })
    }
}

/// What one pass over the shown injections found.
struct SavingsCore {
    total: Acc,
    /// `[from your records, from teammates' records]`.
    by_origin: [Acc; 2],
    /// Quota block inputs: the cost of every avoided non-Codex item, and the proven part.
    quota_estimated: f64,
    quota_proven: f64,
    codex: i64,
    local_calls: Vec<Call>,
}

/// The counterfactual over the injections created in `[since_ms, until_ms)`. An avoided item is a
/// shown note whose call was not repeated by the same session and agent afterwards; its cost is the
/// median of the same call's history among this machine's own calls (`origin = 'local'`: what the
/// call would have cost here). Each injection is also split by the origin of its items
/// (`injection_item.origin`; a record of your own other machine counts as yours).
fn savings_core(
    conn: &Connection,
    pricing: &crate::config::Pricing,
    since_ms: Option<i64>,
    until_ms: Option<i64>,
) -> anyhow::Result<SavingsCore> {
    let own = own_member_id();
    let all = load_calls(conn)?;
    let by_id: HashMap<i64, &Call> = all.iter().map(|c| (c.id, c)).collect();
    let calls: Vec<&Call> = all.iter().filter(|c| c.local).collect();
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
         FROM injection WHERE mode IN ('inject','deny') AND created_at >= ?1 AND created_at < ?2 \
         ORDER BY created_at, id",
    )?;
    let injections: Vec<ShownInjection> = st
        .query_map(
            [since_ms.unwrap_or(i64::MIN), until_ms.unwrap_or(i64::MAX)],
            |r| {
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
            },
        )?
        .collect::<rusqlite::Result<_>>()?;
    // `event_id` is NULL once the record was deleted (RVT1 m15): the item keeps its origin.
    let mut items = conn.prepare(
        "SELECT position, event_id, origin FROM injection_item WHERE injection_id = ?1 \
         ORDER BY position",
    )?;

    // Per tool: median over this machine's ok events up to the injection, used only when an item
    // has no history of its own (the item's own history stops at the injection too, RVQ0 m5).
    let fallback = |fetch: bool, at: i64| {
        medians(
            calls
                .iter()
                .copied()
                .filter(|c| c.ok && c.is_fetch == fetch && c.at <= at),
        )
    };
    let fallback_bytes = |at: i64| {
        median_bytes(
            calls
                .iter()
                .copied()
                .filter(|c| c.ok && c.is_fetch && c.at <= at),
        )
    };

    let mut total = Acc::default();
    let mut by_origin = [Acc::default(), Acc::default()];
    let (mut quota_estimated, mut quota_proven, mut codex) = (0.0_f64, 0.0_f64, 0_i64);
    for (id, at, session, agent, tool_use_id, rendered, mode, is_codex) in &injections {
        total.shown += 1;
        total.overhead += *rendered as f64 / 4.0;
        let rows: Vec<(i64, Option<i64>, String)> = items
            .query_map([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        // (origin index, followed up, costs) per item that still has its record.
        let mut seen: Vec<(usize, bool, Option<ItemCosts>)> = Vec::new();
        for (position, event_id, origin) in &rows {
            let src = event_id.and_then(|e| by_id.get(&e).copied());
            let mut idx = usize::from(origin == "team");
            if let (Some(s), Some(me)) = (src, &own) {
                if s.member.as_deref() == Some(me.as_str()) {
                    idx = 0;
                }
            }
            let Some(src) = src else {
                seen.push((idx, false, None));
                continue;
            };
            let Some(key) = &src.key else {
                seen.push((idx, false, None));
                continue;
            };
            let recalled = all_calls.get(key.as_str()).is_some_and(|v| {
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
                let own_pages = median_bytes(
                    by_key
                        .get(key.as_str())
                        .map(|v| v.iter().copied().filter(|e| e.at <= *at))
                        .into_iter()
                        .flatten(),
                );
                own_pages.or_else(|| fallback_bytes(*at)).unwrap_or(0)
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
            seen.push((
                idx,
                recalled,
                Some((
                    labelled2.contains(&(*id, *position)),
                    d.unwrap_or(0) as f64,
                    c.unwrap_or(0) as f64 / 4.0,
                    page,
                    item_cost(pricing, src.is_fetch, page, c.unwrap_or(0) as f64 / 4.0),
                )),
            ));
        }
        let costs_of = |only: Option<usize>| -> Vec<ItemCosts> {
            seen.iter()
                .filter(|(i, _, _)| only.is_none_or(|o| o == *i))
                .filter_map(|(_, _, c)| *c)
                .collect()
        };
        let recalled_in = |only: Option<usize>| {
            seen.iter()
                .any(|(i, r, _)| *r && only.is_none_or(|o| o == *i))
        };
        // The injection as a whole.
        if recalled_in(None) {
            total.followed += 1;
        } else {
            total.avoided += 1;
            if *is_codex {
                codex += 1;
            }
            let costs = costs_of(None);
            total.add(&costs);
            if !*is_codex {
                for &(two, _, _, _, c) in &costs {
                    quota_estimated += c;
                    if two || mode == "deny" {
                        quota_proven += c;
                    }
                }
            }
        }
        // The same injection once per origin it shows; the rendered overhead is shared by items.
        for (o, acc) in by_origin.iter_mut().enumerate() {
            let n_o = seen.iter().filter(|(i, _, _)| *i == o).count();
            if n_o == 0 {
                continue;
            }
            acc.shown += 1;
            acc.overhead += *rendered as f64 / 4.0 * n_o as f64 / seen.len() as f64;
            if recalled_in(Some(o)) {
                acc.followed += 1;
            } else {
                acc.avoided += 1;
                acc.add(&costs_of(Some(o)));
            }
        }
    }
    Ok(SavingsCore {
        total,
        by_origin,
        quota_estimated,
        quota_proven,
        codex,
        local_calls: all.into_iter().filter(|c| c.local).collect(),
    })
}

/// The totals of the shown injections of one UTC day, for the daily `stats` record:
/// (notes shown, avoided follow-ups, estimated minutes, estimated tokens).
#[cfg(feature = "sync")]
pub(crate) fn day_totals(
    conn: &Connection,
    pricing: &crate::config::Pricing,
    day_start_ms: i64,
) -> anyhow::Result<(u64, u64, u64, u64)> {
    let core = savings_core(
        conn,
        pricing,
        Some(day_start_ms),
        Some(day_start_ms + 86_400_000),
    )?;
    let t = &core.total;
    Ok((
        u64::try_from(t.shown).unwrap_or(0),
        u64::try_from(t.avoided).unwrap_or(0),
        (t.ms / 60_000.0).round().max(0.0) as u64,
        t.chars.round().max(0.0) as u64,
    ))
}

/// Estimated savings (see [`savings_core`]), with the ceilings, the quota block and the split by
/// origin (`by_origin.local`, `by_origin.team`: the fields of the notes, no ceilings).
fn savings(conn: &Connection, since: Option<&str>, projects: &Path) -> anyhow::Result<Value> {
    let since_ms = since.map(super::parse_date).transpose()?;
    let pricing = crate::config::load(&crate::paths::config_path()?)?.pricing;
    let core = savings_core(conn, &pricing, since_ms, None)?;
    let calls: Vec<&Call> = core.local_calls.iter().collect();
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
        core.quota_estimated,
        core.quota_proven,
        core.codex,
        &pricing,
        projects,
        super::now_ms(),
    );
    let mut out = core.total.json(&pricing);
    out["since"] = json!(since);
    out["pricing"] = json!({
        "currency": pricing.currency,
        "summariser_input_per_mtok": pricing.summariser_input_per_mtok,
        "summariser_output_per_mtok": pricing.summariser_output_per_mtok,
        "search_fee_per_call": pricing.search_fee_per_call,
        "main_input_per_mtok": pricing.main_input_per_mtok,
    });
    out["ceiling"] = json!({
        "repeat_fetches": ceiling(true, rf_n, rf_ms, rf_chars, rf_bytes),
        "repeat_searches": ceiling(false, rs_n, rs_ms, rs_chars, rs_bytes),
    });
    out["by_origin"] = json!({
        "local": core.by_origin[0].json(&pricing),
        "team": core.by_origin[1].json(&pricing),
    });
    out["quota"] = quota;
    Ok(out)
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
    let mut cost_paths: Vec<Vec<&str>> = vec![
        vec![],
        vec!["confirmed"],
        vec!["ceiling", "repeat_fetches"],
        vec!["ceiling", "repeat_searches"],
    ];
    // Notes from teammates' records: the avoided and confirmed lines are split by origin
    // (without any, the table is the one it always was).
    if num(v, &["by_origin", "team", "shown"]) > 0.0 {
        let mut split = Vec::new();
        let mut split_paths: Vec<Vec<&str>> = Vec::new();
        for (head, which) in [("avoided", "avoided"), ("confirmed", "confirmed")] {
            for (name, origin) in [
                ("from your records", "local"),
                ("from teammates' records", "team"),
            ] {
                let base = ["by_origin", origin];
                let cells = |path: &[&str]| {
                    let at = |k: &str| {
                        let mut p = base.to_vec();
                        p.extend_from_slice(path);
                        p.push(k);
                        num(v, &p)
                    };
                    (
                        minutes(at("time_saved_ms")),
                        kilo(at("tokens_saved")),
                        at("est_bytes_not_fetched"),
                        at("est_summariser_tokens"),
                    )
                };
                let (path, items): (&[&str], f64) = if which == "avoided" {
                    (&[], num(v, &["by_origin", origin, "avoided"]))
                } else {
                    (
                        &["confirmed"],
                        num(v, &["by_origin", origin, "confirmed", "items"]),
                    )
                };
                let c = cells(path);
                split.push(row(
                    &format!("  {head} {name}"),
                    items,
                    &[&c.0, &c.1],
                    Some((c.2, c.3)),
                ));
                let mut p = base.to_vec();
                p.extend_from_slice(path);
                split_paths.push(p);
            }
        }
        // After "avoided" and after "confirmed", the two lines of each.
        let mut it = split.into_iter();
        let mut pit = split_paths.into_iter();
        let (a1, a2) = (it.next().unwrap(), it.next().unwrap());
        let (c1, c2) = (it.next().unwrap(), it.next().unwrap());
        let (pa1, pa2) = (pit.next().unwrap(), pit.next().unwrap());
        let (pc1, pc2) = (pit.next().unwrap(), pit.next().unwrap());
        let tail: Vec<_> = rows.split_off(2);
        let tail_paths: Vec<_> = cost_paths.split_off(2);
        rows.truncate(1);
        cost_paths.truncate(1);
        rows.extend([a1, a2]);
        cost_paths.extend([pa1, pa2]);
        rows.push(row(
            "confirmed (label 2)",
            num(v, &["confirmed", "items"]),
            &[&confirmed.0, &confirmed.1],
            Some((confirmed.2, confirmed.3)),
        ));
        cost_paths.push(vec!["confirmed"]);
        rows.extend([c1, c2]);
        cost_paths.extend([pc1, pc2]);
        rows.extend(tail);
        cost_paths.extend(tail_paths);
    }
    for (r, path) in rows.iter_mut().zip(&cost_paths) {
        let mut p = path.clone();
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
    if num(v, &["by_origin", "team", "shown"]) > 0.0 {
        o.push_str(
            "  by origin: an injection that shows notes from both counts once under each; records \
             from your other machines count as yours\n",
        );
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

/// `sync_state` key: the last UTC day (days since 1970-01-01) whose `stats` record was queued.
#[cfg(feature = "sync")]
const STATS_DAY: &str = "stats_day";

/// Queues the daily `stats` record of this member for every finished UTC day since the last one
/// (at most 7), and keeps the totals in `sync_state.team_stats.{member}.{day}` like a pulled one,
/// so `awm stats --team` counts this member too. Nothing happens unless the machine is in a team
/// and `team.share_stats` is on.
///
/// Trigger (TM14 decision): `awm sync` calls this before every run, and the `stats_day` marker
/// makes it queue once per finished day. A trigger inside `awm stats` would report only for
/// members who happen to run it, and the "at least 3 members reported" rule would rarely be met;
/// the sync runs without anyone asking, spawned by the hooks. The record covers the previous
/// complete UTC day, so a day's totals are never sent twice or half-finished.
#[cfg(feature = "sync")]
pub fn queue_daily_record(env: &crate::sync::Env) -> anyhow::Result<usize> {
    use crate::db::{self, Role, VersionCheck};
    use crate::sync::{push, state};

    let dir = &env.data_dir;
    if !env.config.team.share_stats || !state::configured(dir) {
        return Ok(0);
    }
    let mut conn = db::open(&dir.join(crate::paths::DB_FILE), Role::Cli)?;
    if !matches!(db::check_version(&conn)?, VersionCheck::Current) {
        return Ok(0);
    }
    let ident = state::Identity::load(dir)?;
    if ident.key.epoch_keys.is_empty() {
        return Ok(0);
    }
    let ring = ident.ring()?;
    let now = env.now_ms.unwrap_or_else(super::now_ms);
    let today = now.div_euclid(86_400_000);
    let from = (state::get_i64(&conn, STATS_DAY)?.unwrap_or(today - 2) + 1).max(today - 7);
    let member = ident.team.member_id.to_string();
    let mut queued = 0;
    for day in from..today {
        let (shown, avoided, est_minutes, est_tokens) =
            day_totals(&conn, &env.config.pricing, day * 86_400_000)?;
        let record = awm_proto::wire::StatsPlaintext {
            schema: crate::sync::payload::SCHEMA,
            day: super::fmt_day(day * 86_400_000),
            shown,
            avoided,
            est_minutes,
            est_tokens,
        };
        push::queue_stats(&mut conn, &ident, &ring, &record, now)?;
        state::set(
            &conn,
            &team_stats_key(&member, &record.day),
            &serde_json::to_string(&record)?,
        )?;
        state::set(&conn, STATS_DAY, &day.to_string())?;
        queued += 1;
    }
    Ok(queued)
}
