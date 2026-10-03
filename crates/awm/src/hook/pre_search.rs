//! PreToolUse WebSearch (Claude Code) and `webrun` (Codex): an optional deny of a search that
//! earlier research already answers (amendment 2 of DENY, 2026-10-03).
//!
//! `short_circuit.query = "on"` (the default) runs the matching of the query channel
//! (`matching::query_channel` at `calibrate::cutoff_query`) read-only on the search text. When
//! earlier records score at or above the cutoff, the search is denied once with up to
//! `inject.max_notes` of them in the reason, and the retry passes. Any earlier usable record
//! counts: the caller's own agent, a sibling, another session or project, the owner's other
//! device (a teammate's never), within `short_circuit.query_window_days`. One deny per
//! (session, agent, trigger text). BM25 is a similarity match, not an equality: its measured
//! precision is 0.52 strict at the median cutoff (MB T2).

use rusqlite::{params, Connection};

use super::{append_canary, canary_line, deny_json, Env, Injection, Verdict};
use crate::config::ShortCircuitMode;
use crate::matching::{self, calibrate};
use crate::note::{Channel, Note, Relation};
use crate::record::codex_query;
use crate::render::{self, plain_label};
use crate::{redact, sanitize};

const EVENT: &str = "PreToolUse";
const AGENT_TYPE_CAP: usize = 24;
const CANARY_REASON: &str =
    "agent-web-memory: canary deny. Run the same search again; it will not be blocked again.";

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

/// Earlier usable records that match `text` at or above the calibrated cutoff, best first, at
/// most `inject.max_notes`, each with its score. Read-only use of the query channel.
pub fn find_similar(env: &Env, conn: &Connection, text: &str) -> anyhow::Result<Vec<(Note, f64)>> {
    let cutoff = calibrate::cutoff_query(conn)?;
    let mut opts = env.match_opts(conn)?;
    // The caller's own earlier research counts as well.
    opts.exclude_same_agent = false;
    let window_ms = i64::from(env.config.short_circuit.query_window_days) * 86_400_000;
    let since = env.started_at_ms - window_ms;
    let max = env.config.inject.max_notes as usize;
    let mut found = Vec::new();
    for hit in matching::query_channel(conn, text, cutoff, &opts)? {
        let note = matching::to_note(conn, &hit, &opts)?;
        let usable = note.created_at_ms >= since
            && !matches!(note.relation, Relation::Teammate { .. })
            && (note.tool != crate::note::Tool::WebFetch || note.http_code == Some(200))
            && note
                .summary
                .as_deref()
                .is_some_and(|s| !sanitize::excerpt(s, 200).text.is_empty());
        if usable {
            found.push((note, hit.score));
            if found.len() >= max {
                break;
            }
        }
    }
    Ok(found)
}

pub fn handle(env: &Env, conn: &Connection) -> anyhow::Result<Verdict> {
    let input = &env.input;
    let forced = std::env::var("AWM_CANARY_DENY").is_ok_and(|v| v == "1");
    if env.config.short_circuit.query == ShortCircuitMode::Off && !forced {
        return Ok(Verdict::quiet("no_match"));
    }
    let text = search_text(input);
    if text.is_none() && !forced {
        return Ok(Verdict::quiet("no_match"));
    }
    let text = text.unwrap_or_default();
    let trigger = env.trigger_text(&text);
    if already_denied(env, conn, &trigger)? {
        return Ok(Verdict::quiet("skipped"));
    }

    let start = std::time::Instant::now();
    let (clean, _) = redact::redact(&text, &env.config.capture.redact_terms);
    let notes = if clean.trim().is_empty() {
        Vec::new()
    } else {
        find_similar(env, conn, &clean)?
    };
    let search_ms = super::elapsed_ms(start);

    let ref_id = env.new_ref();
    let retry = if input.tool_name == "webrun" {
        "If this does not answer your question, run the same search again; it will not be blocked again."
    } else {
        "If this does not answer your question, call WebSearch again with the same query; it will not be blocked again."
    };
    let only: Vec<Note> = notes.iter().map(|(n, _)| n.clone()).collect();
    let rendered = if only.is_empty() {
        None
    } else {
        let ctx = env.render_ctx(Channel::Query, &ref_id);
        render::deny_reason_matches(&only, &ctx, retry)
    };
    let (mut reason, items) = match rendered {
        Some((reason, ids)) => {
            let items = ids
                .iter()
                .map(|id| {
                    let score = notes
                        .iter()
                        .find(|(n, _)| n.event_id == *id)
                        .map_or(0.0, |(_, sc)| *sc);
                    (*id, score)
                })
                .collect::<Vec<(i64, f64)>>();
            (reason, items)
        }
        None if forced => (CANARY_REASON.to_string(), Vec::new()),
        None => {
            return Ok(Verdict {
                search_ms: Some(search_ms),
                ..Verdict::quiet("no_match")
            })
        }
    };
    if let Some(line) = canary_line(EVENT) {
        append_canary(&mut reason, &line);
    }
    Ok(Verdict {
        output: Some(deny_json(&reason)),
        outcome: "denied",
        search_ms: Some(search_ms),
        injection: Some(Injection {
            hook: EVENT,
            channel: Channel::Query,
            mode: "deny",
            tool_use_id: input.tool_use_id.clone(),
            trigger_text: Some(trigger),
            cutoff: None,
            rendered_chars: reason.chars().count(),
            rendered: Some(reason),
            ref_id,
            items,
        }),
    })
}

/// The same (session, agent) already has a query deny for this trigger text.
fn already_denied(env: &Env, conn: &Connection, trigger: &str) -> anyhow::Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT 1 FROM injection WHERE hook = 'PreToolUse' AND channel = 'query' \
             AND mode = 'deny' AND session_id = ?1 AND agent_id IS ?2 AND trigger_text = ?3 LIMIT 1",
        )?
        .exists(params![env.input.session_id, env.input.agent_id, trigger])?)
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
