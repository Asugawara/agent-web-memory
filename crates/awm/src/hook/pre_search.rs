//! PreToolUse WebSearch (Claude Code) and `webrun` (Codex): optional deny of a repeated
//! search (QD1 §5.1).
//!
//! `short_circuit.query = "shadow"` (the default) logs a `shadow_deny` row; `"on"` denies.
//! A deny needs an earlier WebSearch record of any other agent (a sibling, another session
//! or project, the other coding agent) within `query_window_minutes` whose query has the
//! same token set, with status ok and a non-empty sanitised finding. The caller's own
//! earlier search never counts. One deny per (session, agent, token set), three per agent.

use rusqlite::{params, Connection};

use super::{append_canary, canary_line, deny_json, Env, Injection, Verdict};
use crate::config::{Mode, ShortCircuitMode};
use crate::matching::{self, Hit};
use crate::normalize::token_set;
use crate::note::{Channel, Note, Relation};
use crate::record::codex_query;
use crate::render::{self, plain_label};
use crate::{redact, sanitize};

const EVENT: &str = "PreToolUse";
/// Fewer tokens than this never match (QD1 §5.1 step 3).
const MIN_TOKENS: usize = 3;
/// Denies (or shadow denies) per (session, agent).
const MAX_PER_AGENT: i64 = 3;
/// Rows scanned by [`find_repeat`], newest first.
const SCAN_LIMIT: i64 = 2000;
const AGENT_TYPE_CAP: usize = 24;
const CANARY_REASON: &str =
    "agent-web-memory: canary deny. Run the same search again; it will not be blocked again.";

/// What the configuration allows: global `mode = "shadow"` turns a deny into a shadow deny.
fn effective_mode(env: &Env) -> ShortCircuitMode {
    match (env.config.mode, env.config.short_circuit.query) {
        (Mode::Shadow, ShortCircuitMode::On) => ShortCircuitMode::Shadow,
        (_, m) => m,
    }
}

fn is_filter(v: Option<&serde_json::Value>) -> bool {
    use serde_json::Value;
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// The query text of a plain search, or `None` for a domain-filtered Claude Code search
/// and for a Codex call that is not just `search_query` (QD1 §5.1 step 2).
pub fn search_text(input: &super::HookInput) -> Option<String> {
    let ti = &input.tool_input;
    if input.tool_name == "webrun" {
        let obj = ti.as_object()?;
        if obj
            .keys()
            .any(|k| k != "search_query" && k != "response_length")
        {
            return None;
        }
        return codex_query(ti);
    }
    if is_filter(ti.get("allowed_domains")) || is_filter(ti.get("blocked_domains")) {
        return None;
    }
    input.tool_input_str("query").map(str::to_string)
}

/// An earlier search with the same token set.
#[derive(Debug, Clone)]
pub struct Repeat {
    pub hit: Hit,
    /// `event.agent` of the earlier record: `claude` or `codex`.
    pub agent: String,
}

pub fn handle(env: &Env, conn: &Connection) -> anyhow::Result<Verdict> {
    let input = &env.input;
    let forced = std::env::var("AWM_CANARY_DENY").is_ok_and(|v| v == "1");
    let mode = effective_mode(env);
    if mode == ShortCircuitMode::Off && !forced {
        return Ok(Verdict::quiet("no_match"));
    }
    let text = search_text(input);
    let (text, key) = match text {
        Some(t) => {
            let (clean, _) = redact::redact(&t, &env.config.capture.redact_terms);
            let key = token_set(&clean);
            (t, key)
        }
        None => (String::new(), Vec::new()),
    };
    let searchable = key.len() >= MIN_TOKENS;
    if !searchable && !forced {
        return Ok(Verdict::quiet("no_match"));
    }
    // In a subagent a real deny also needs `short_circuit.subagents`; a forced canary deny does not.
    let denies = forced
        || (mode == ShortCircuitMode::On
            && (!env.is_subagent() || env.config.short_circuit.subagents));
    let log_mode = if denies { "deny" } else { "shadow_deny" };
    let trigger = env.trigger_text(&text);
    if already_denied(env, conn, log_mode, &key)?
        || denies_for_agent(env, conn, log_mode)? >= MAX_PER_AGENT
    {
        return Ok(Verdict::quiet("skipped"));
    }

    let start = std::time::Instant::now();
    let window_ms = i64::from(env.config.short_circuit.query_window_minutes) * 60_000;
    let repeat = if searchable {
        find_repeat(env, conn, &key, window_ms)?
    } else {
        None
    };
    let search_ms = super::elapsed_ms(start);
    if repeat.is_none() && !forced {
        return Ok(Verdict {
            search_ms: Some(search_ms),
            ..Verdict::quiet("no_match")
        });
    }

    let ref_id = env.new_ref();
    let mut items = Vec::new();
    let mut reason = match &repeat {
        Some(r) => {
            let opts = env.match_opts(conn)?;
            let note = matching::to_note(conn, &r.hit, &opts)?;
            items.push((r.hit.event_id, 1.0));
            let caller_is_codex = input.tool_name == "webrun";
            let where_ = where_text(&note, &r.agent, caller_is_codex);
            render::deny_reason_search(&note, &env.render_ctx(Channel::Query, &ref_id), &where_)
        }
        None => CANARY_REASON.to_string(),
    };
    if let (true, Some(line)) = (denies, canary_line(EVENT)) {
        append_canary(&mut reason, &line);
    }
    let shown = denies.then(|| reason.clone());
    Ok(Verdict {
        output: shown.as_deref().map(deny_json),
        outcome: if denies { "denied" } else { "shadow" },
        search_ms: Some(search_ms),
        injection: Some(Injection {
            hook: EVENT,
            channel: Channel::Query,
            mode: log_mode,
            tool_use_id: input.tool_use_id.clone(),
            trigger_text: Some(trigger),
            cutoff: None,
            rendered_chars: reason.chars().count(),
            rendered: shown,
            ref_id,
            items,
        }),
    })
}

/// The newest usable search of another agent within `window_ms` whose token set is `key`.
pub fn find_repeat(
    env: &Env,
    conn: &Connection,
    key: &[String],
    window_ms: i64,
) -> anyhow::Result<Option<Repeat>> {
    let mut st = conn.prepare_cached(
        "SELECT e.id, e.query, e.summary, e.agent FROM event e \
         WHERE e.tool = 'WebSearch' AND e.created_at >= ?1 AND e.status = 'ok' \
           AND e.quarantined = 0 AND e.summary IS NOT NULL \
           AND (e.origin = 'local' OR e.member = ?6) \
           AND NOT (e.session_id = ?2 AND e.agent_id IS ?3) \
           AND (?4 IS NULL OR e.tool_use_id != ?4) \
           AND NOT EXISTS (SELECT 1 FROM tombstone t \
                           WHERE t.kind = 'tool_use_id' AND t.value = e.tool_use_id) \
         ORDER BY e.created_at DESC, e.id DESC LIMIT ?5",
    )?;
    let mut rows = st.query(params![
        env.started_at_ms - window_ms,
        env.input.session_id,
        env.input.agent_id,
        env.input.tool_use_id,
        SCAN_LIMIT,
        matching::own_member_id()
    ])?;
    while let Some(r) = rows.next()? {
        let query: Option<String> = r.get(1)?;
        let Some(query) = query else { continue };
        if token_set(&query) != key {
            continue;
        }
        let summary: String = r.get(2)?;
        if sanitize::excerpt(&summary, 200).text.is_empty()
            || sanitize::line_text(&query, 120).text.is_empty()
        {
            continue;
        }
        return Ok(Some(Repeat {
            hit: Hit {
                event_id: r.get(0)?,
                score: 1.0,
                seen: 1,
            },
            agent: r.get(3)?,
        }));
    }
    Ok(None)
}

/// The same (session, agent) already has a query row of this log mode whose token set is `key`
/// (the full redacted query, not the 200-character trigger text). The token set of a row is
/// that of the earlier search it denied (`event.query` of its item); a row without an item
/// (a canary deny) falls back to its trigger text.
pub fn already_denied(
    env: &Env,
    conn: &Connection,
    mode: &str,
    key: &[String],
) -> anyhow::Result<bool> {
    let mut st = conn.prepare_cached(
        "SELECT COALESCE(e.query, i.trigger_text) FROM injection i \
         LEFT JOIN injection_item ii ON ii.injection_id = i.id AND ii.position = 1 \
         LEFT JOIN event e ON e.id = ii.event_id \
         WHERE i.hook = 'PreToolUse' AND i.channel = 'query' \
         AND i.mode = ?1 AND i.session_id = ?2 AND i.agent_id IS ?3",
    )?;
    let rows = st.query_map(
        params![mode, env.input.session_id, env.input.agent_id],
        |r| r.get::<_, Option<String>>(0),
    )?;
    for row in rows {
        if row?.is_some_and(|t| token_set(&t) == key) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Query rows of this log mode the (session, agent) already has.
pub fn denies_for_agent(env: &Env, conn: &Connection, mode: &str) -> anyhow::Result<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM injection WHERE hook = 'PreToolUse' AND channel = 'query' \
         AND mode = ?1 AND session_id = ?2 AND agent_id IS ?3",
        params![mode, env.input.session_id, env.input.agent_id],
        |r| r.get(0),
    )?)
}

/// `{where}` of the reason (QD1 §5.2): who ran the earlier search, and the other coding agent if it differs.
pub fn where_text(note: &Note, earlier_agent: &str, caller_is_codex: bool) -> String {
    let mut out = match &note.relation {
        Relation::OtherSubagent { agent_type } => {
            let t = plain_label(agent_type, AGENT_TYPE_CAP);
            if t.is_empty() {
                "in this session by a subagent".to_string()
            } else {
                format!("in this session by a {t} subagent")
            }
        }
        Relation::MainAgent => "in this session by the main agent".to_string(),
        Relation::SameProject => "in another session of this project".to_string(),
        Relation::OtherProject => "in another project".to_string(),
        Relation::OwnDevice => "on your other machine".to_string(),
        // A teammate's record never triggers a deny (`find_repeat`); the text keeps the match total.
        Relation::Teammate { .. } => "by a teammate".to_string(),
    };
    let earlier_is_codex = earlier_agent == "codex";
    if earlier_is_codex != caller_is_codex {
        out.push_str(if earlier_is_codex {
            " (Codex)"
        } else {
            " (Claude Code)"
        });
    }
    out
}
