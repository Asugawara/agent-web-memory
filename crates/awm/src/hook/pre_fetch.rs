//! PreToolUse entry point (`awm hook pre-fetch`), dispatching on `tool_name`.
//!
//! `WebFetch`: a per-URL cache (plan-v2 §4.6). With `short_circuit.mode = "on"` (the default) a
//! fetch is denied when awm holds a usable earlier fetch of the same `url_norm` within
//! `short_circuit.window_days`, whoever made it: the caller itself, a sibling agent, another
//! session or project, the owner's other device. Usable means status ok with code 200, or a dead
//! end with an HTTP code (202, 3xx, 4xx except 429: such a URL never succeeded on a repeat), not
//! quarantined, not tombstoned; a teammate's row never counts. The newest usable row decides the
//! kind: a coded dead end says the URL returned that code. Otherwise the reason carries one earlier
//! answer, the one FTS5 BM25 ranks best for the call's own prompt among the URL's ok rows (ties,
//! a missing prompt, a prompt without tokens and rows without an FTS row keep the newest); the
//! retry passes (once per session, agent and URL).
//!
//! `WebSearch` (Claude Code) and `webrun` (Codex) go to [`super::pre_search`].

use rusqlite::{params, Connection, OptionalExtension};

use super::{append_canary, canary_line, deny_json, Env, HookArgs, Injection, Verdict};
use crate::config::ShortCircuitMode;
use crate::matching::{self, Hit};
use crate::note::{Channel, Relation, Status};
use crate::record::redact_url;
use crate::render::{self, plain_label};

const EVENT: &str = "PreToolUse";
const AGENT_TYPE_CAP: usize = 24;

pub fn run(_args: HookArgs) -> anyhow::Result<()> {
    super::run_sync("pre-fetch", handle);
    Ok(())
}

fn handle(env: &Env, conn: &Connection) -> anyhow::Result<Verdict> {
    match env.input.tool_name.as_str() {
        "WebFetch" => handle_fetch(env, conn),
        "WebSearch" | "webrun" => super::pre_search::handle(env, conn),
        _ => Ok(Verdict::quiet("no_match")),
    }
}

fn handle_fetch(env: &Env, conn: &Connection) -> anyhow::Result<Verdict> {
    let input = &env.input;
    let forced = std::env::var("AWM_CANARY_DENY").is_ok_and(|v| v == "1");
    if env.config.short_circuit.mode == ShortCircuitMode::Off && !forced {
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
    let cached = find_cached(env, conn, &norm)?;
    let search_ms = super::elapsed_ms(start);
    if cached.is_none() && !forced {
        return Ok(Verdict {
            search_ms: Some(search_ms),
            ..Verdict::quiet("no_match")
        });
    }
    let trigger = env.trigger_text(&norm);
    if already_logged(env, conn, &trigger)? {
        return Ok(Verdict {
            search_ms: Some(search_ms),
            ..Verdict::quiet("no_match")
        });
    }

    let ref_id = env.new_ref();
    let mut items = Vec::new();
    let mut reason = match &cached {
        Some(c) => {
            let opts = env.match_opts(conn)?;
            let note = matching::to_note(conn, &c.hit, &opts)?;
            let who = who_text(&note.relation, c.own);
            items.push((c.hit.event_id, c.hit.score));
            let ctx = env.render_ctx(Channel::Url, &ref_id);
            if note.status == Status::DeadEnd {
                render::deny_reason_dead_url(&note, &ctx, &who)
            } else {
                render::deny_reason(&note, &ctx, &who, c.candidates)
            }
        }
        None => "agent-web-memory: canary deny. Call WebFetch again with the same URL; it will not be blocked again."
            .to_string(),
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
            channel: Channel::Url,
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

/// `{who}` of the reason: who made the earlier fetch. `own` is the caller's own earlier fetch
/// (same session and agent).
fn who_text(relation: &Relation, own: bool) -> String {
    if own {
        return "you, earlier in this session".to_string();
    }
    match relation {
        Relation::OtherSubagent { agent_type } => {
            let t = plain_label(agent_type, AGENT_TYPE_CAP);
            if t.is_empty() {
                "a subagent".to_string()
            } else {
                format!("a {t} subagent")
            }
        }
        Relation::MainAgent => "the main agent".to_string(),
        Relation::SameProject => "another session of this project".to_string(),
        Relation::OtherProject => "another session".to_string(),
        Relation::OwnDevice => "your other machine".to_string(),
        // A teammate's record never triggers a deny (`find_cached`); the text keeps the match total.
        Relation::Teammate { .. } => "a teammate".to_string(),
    }
}

/// The earlier fetch a deny hands over.
struct Cached {
    hit: Hit,
    /// Made by the caller itself (same session and agent).
    own: bool,
    /// Earlier answers (status ok) the choice was made among; 1 when there was no choice.
    candidates: usize,
}

/// Most usable rows read per deny.
const CANDIDATE_LIMIT: usize = 20;

struct Candidate {
    id: i64,
    own: bool,
    ok: bool,
}

/// The usable fetches of `norm` within the window, by any agent of the owner (the same agent, a
/// sibling, another session or project, the owner's other device), newest first, at most
/// [`CANDIDATE_LIMIT`]. Usable: status ok with code 200, or a dead end with an HTTP code that is
/// 202, 3xx, or 4xx but not 429 (such a URL rarely succeeds on a repeat); 429,
/// 5xx, a dead end without a code and a refusal never count. The newest row decides the kind of
/// deny; for a cached answer the ok row BM25 ranks best for the call's prompt ([`best_match`]) is
/// the one handed over (the newest on a tie or when nothing can be ranked).
fn find_cached(env: &Env, conn: &Connection, norm: &str) -> anyhow::Result<Option<Cached>> {
    let window_ms = i64::from(env.config.short_circuit.window_days) * 86_400_000;
    let mut st = conn.prepare_cached(
        "SELECT e.id, (e.origin = 'local' AND e.session_id = ?2 AND e.agent_id IS ?3), \
                e.status = 'ok' FROM event e \
         WHERE e.tool = 'WebFetch' AND e.url_norm = ?1 \
           AND ((e.status = 'ok' AND e.http_code = 200) \
             OR (e.status = 'dead_end' AND (e.http_code = 202 \
                 OR (e.http_code BETWEEN 300 AND 499 AND e.http_code != 429)))) \
           AND e.created_at >= ?4 AND e.quarantined = 0 \
           AND (e.origin = 'local' OR e.member = ?6) \
           AND (?5 IS NULL OR e.tool_use_id != ?5) \
           AND NOT EXISTS (SELECT 1 FROM tombstone t \
                           WHERE t.kind = 'tool_use_id' AND t.value = e.tool_use_id) \
         ORDER BY e.created_at DESC, e.id DESC LIMIT ?7",
    )?;
    let rows = st.query_map(
        params![
            norm,
            env.input.session_id,
            env.input.agent_id,
            env.started_at_ms - window_ms,
            env.input.tool_use_id,
            matching::own_member_id(),
            CANDIDATE_LIMIT as i64
        ],
        |r| {
            Ok(Candidate {
                id: r.get(0)?,
                own: r.get(1)?,
                ok: r.get(2)?,
            })
        },
    )?;
    let mut all = Vec::new();
    for r in rows {
        all.push(r?);
    }
    let Some(newest) = all.first() else {
        return Ok(None);
    };
    if !newest.ok {
        // A coded dead end decides: the dead-URL deny, rendered from that row.
        return Ok(Some(Cached {
            hit: Hit {
                event_id: newest.id,
                score: 1.0,
                seen: 1,
            },
            own: newest.own,
            candidates: 1,
        }));
    }
    let oks: Vec<&Candidate> = all.iter().filter(|c| c.ok).collect();
    let (best, score) = if oks.len() > 1 {
        best_match(conn, env.input.tool_input_str("prompt"), &oks)?
    } else {
        (0, 1.0)
    };
    let chosen = oks[best];
    // `Hit.seen` is the size of a note's group, not a candidate count; it stays 1.
    Ok(Some(Cached {
        hit: Hit {
            event_id: chosen.id,
            score,
            seen: 1,
        },
        own: chosen.own,
        candidates: oks.len(),
    }))
}

/// Index in `oks` (newest first) of the candidate whose FTS document (fetch prompt, URL, start of
/// the answer) BM25 ranks best for `prompt`, with its score (negated bm25, as the query channel
/// stores it). Idf comes from the whole index. `+rowid` keeps SQLite from pushing the rowid list into
/// FTS5, which would re-run the MATCH once per id (19 ms for 20 ids against 2 ms on a
/// test copy); bm25 is then computed only for the rows that pass the filter. The
/// first, newest candidate and a score of 0.0 when nothing can be ranked: no prompt, no token in
/// it, or none of the candidates matched (a missing FTS row scores nothing).
fn best_match(
    conn: &Connection,
    prompt: Option<&str>,
    oks: &[&Candidate],
) -> anyhow::Result<(usize, f64)> {
    // A prompt of one-character tokens only ("a", "1") carries no signal and would match noise.
    let usable = prompt.filter(|p| {
        crate::normalize::words(p)
            .iter()
            .any(|w| w.chars().count() >= 2)
    });
    let Some(expr) = usable.and_then(matching::fts::match_expr) else {
        return Ok((0, 0.0));
    };
    let marks = vec!["?"; oks.len()].join(",");
    let mut st = conn.prepare_cached(&format!(
        "SELECT rowid, bm25(event_fts) FROM event_fts WHERE event_fts MATCH ?1 AND +rowid IN ({marks})"
    ))?;
    let args = std::iter::once(rusqlite::types::Value::Text(expr))
        .chain(oks.iter().map(|c| rusqlite::types::Value::Integer(c.id)));
    let mut ranked: Vec<(i64, f64)> = Vec::new();
    for row in st.query_map(rusqlite::params_from_iter(args), |r| {
        Ok((r.get(0)?, r.get(1)?))
    })? {
        ranked.push(row?);
    }
    // Lowest bm25 is the most relevant; a strict comparison keeps the newest on a tie.
    let mut best: Option<(usize, f64)> = None;
    for (i, c) in oks.iter().enumerate() {
        if let Some(&(_, b)) = ranked.iter().find(|(id, _)| *id == c.id) {
            if best.is_none_or(|(_, lowest)| b < lowest) {
                best = Some((i, b));
            }
        }
    }
    Ok(best.map_or((0, 0.0), |(i, b)| (i, -b)))
}

/// This (session, agent) was already denied this URL.
fn already_logged(env: &Env, conn: &Connection, trigger: &str) -> anyhow::Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM injection WHERE hook = 'PreToolUse' AND mode = 'deny' \
             AND channel = 'url' AND session_id = ?1 AND agent_id IS ?2 AND trigger_text = ?3 LIMIT 1",
            params![env.input.session_id, env.input.agent_id, trigger],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}
