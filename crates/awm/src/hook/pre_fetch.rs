//! PreToolUse WebFetch: optional short-circuit (plan-v2 §4.6).
//!
//! `short_circuit.mode = "shadow"` logs a `shadow_deny` row; `"on"` denies. A deny
//! needs a sibling fetch: another agent of the same session, same `url_norm`,
//! status ok, code 200, within `window_minutes`. The caller's own fetch never counts.

use rusqlite::{params, Connection, OptionalExtension};

use super::{canary_line, deny_json, Env, HookArgs, Injection, Verdict};
use crate::config::{Mode, ShortCircuitMode};
use crate::matching::{self, Hit};
use crate::note::{Channel, Relation};
use crate::record::redact_url;
use crate::render;

const EVENT: &str = "PreToolUse";

pub fn run(_args: HookArgs) -> anyhow::Result<()> {
    super::run_sync("pre-fetch", handle);
    Ok(())
}

/// What the configuration allows: global `mode = "shadow"` turns a deny into a shadow deny.
fn effective_mode(env: &Env) -> ShortCircuitMode {
    match (env.config.mode, env.config.short_circuit.mode) {
        (Mode::Shadow, ShortCircuitMode::On) => ShortCircuitMode::Shadow,
        (_, m) => m,
    }
}

fn handle(env: &Env, conn: &Connection) -> anyhow::Result<Verdict> {
    let input = &env.input;
    let forced = std::env::var("AWM_CANARY_DENY").is_ok_and(|v| v == "1");
    let mode = effective_mode(env);
    if input.tool_name != "WebFetch" || (mode == ShortCircuitMode::Off && !forced) {
        return Ok(Verdict::quiet("no_match"));
    }
    // The stored `url_norm` comes from the redacted URL; look up the same form.
    let terms = &env.config.capture.redact_terms;
    let Some((_, norm)) = input
        .tool_input_str("url")
        .and_then(|u| redact_url(u, terms))
    else {
        return Ok(Verdict::quiet("no_match"));
    };
    let start = std::time::Instant::now();
    let sibling = find_sibling(env, conn, &norm)?;
    let search_ms = super::elapsed_ms(start);
    if sibling.is_none() && !forced {
        return Ok(Verdict {
            search_ms: Some(search_ms),
            ..Verdict::quiet("no_match")
        });
    }
    // In a subagent a real deny also needs `short_circuit.subagents`; a forced canary deny does not.
    let denies = mode == ShortCircuitMode::On || forced;
    let log_mode = if denies { "deny" } else { "shadow_deny" };
    if denies && env.is_subagent() && !env.config.short_circuit.subagents && !forced {
        return Ok(Verdict {
            search_ms: Some(search_ms),
            ..Verdict::quiet("no_match")
        });
    }
    let trigger = env.trigger_text(&norm);
    if already_logged(env, conn, log_mode, &trigger)? {
        return Ok(Verdict {
            search_ms: Some(search_ms),
            ..Verdict::quiet("no_match")
        });
    }

    let ref_id = env.new_ref();
    let mut items = Vec::new();
    let mut reason = match &sibling {
        Some(hit) => {
            let opts = env.match_opts(conn)?;
            let note = matching::to_note(conn, hit, &opts)?;
            let who = match &note.relation {
                Relation::OtherSubagent { agent_type } => format!("a {agent_type} subagent"),
                _ => "the main agent".to_string(),
            };
            items.push((hit.event_id, hit.score));
            render::deny_reason(&note, &env.render_ctx(Channel::Url, &ref_id), &who)
        }
        None => "agent-web-memory: canary deny. Call WebFetch again with the same URL; it will not be blocked again."
            .to_string(),
    };
    if let (true, Some(line)) = (denies, canary_line(EVENT)) {
        reason.push('\n');
        reason.push_str(&line);
    }
    let shown = denies.then(|| reason.clone());
    Ok(Verdict {
        output: shown.as_deref().map(deny_json),
        outcome: if denies { "denied" } else { "shadow" },
        search_ms: Some(search_ms),
        injection: Some(Injection {
            hook: EVENT,
            channel: Channel::Url,
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

/// The newest fetch of `norm` by another agent of this session within the window.
fn find_sibling(env: &Env, conn: &Connection, norm: &str) -> anyhow::Result<Option<Hit>> {
    let window_ms = i64::from(env.config.short_circuit.window_minutes) * 60_000;
    let id: Option<i64> = conn
        .query_row(
            "SELECT e.id FROM event e \
             WHERE e.tool = 'WebFetch' AND e.url_norm = ?1 AND e.session_id = ?2 \
               AND NOT (e.agent_id IS ?3) AND e.status = 'ok' AND e.http_code = 200 \
               AND e.created_at >= ?4 AND e.quarantined = 0 \
               AND (?5 IS NULL OR e.tool_use_id != ?5) \
               AND NOT EXISTS (SELECT 1 FROM tombstone t \
                               WHERE t.kind = 'tool_use_id' AND t.value = e.tool_use_id) \
             ORDER BY e.created_at DESC, e.id DESC LIMIT 1",
            params![
                norm,
                env.input.session_id,
                env.input.agent_id,
                env.started_at_ms - window_ms,
                env.input.tool_use_id
            ],
            |r| r.get(0),
        )
        .optional()?;
    Ok(id.map(|event_id| Hit {
        event_id,
        score: 1.0,
        seen: 1,
    }))
}

/// This (session, agent) was already denied (or shadow-denied) this URL.
fn already_logged(env: &Env, conn: &Connection, mode: &str, trigger: &str) -> anyhow::Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM injection WHERE hook = 'PreToolUse' AND mode = ?1 \
             AND session_id = ?2 AND agent_id IS ?3 AND trigger_text = ?4 LIMIT 1",
            params![mode, env.input.session_id, env.input.agent_id, trigger],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}
