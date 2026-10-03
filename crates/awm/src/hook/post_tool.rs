//! PostToolUse WebSearch and WebFetch: notes arrive with the tool result (plan-v2 §3.1, §5.1).

use rusqlite::Connection;

use super::{deliver, elapsed_ms, Delivery, Env, HookArgs, Verdict};
use crate::matching::{self, calibrate};
use crate::normalize::norm_url;
use crate::note::Channel;
use crate::record::codex_query;

const EVENT: &str = "PostToolUse";

pub fn run(_args: HookArgs) -> anyhow::Result<()> {
    super::run_sync("post-tool", handle);
    Ok(())
}

fn handle(env: &Env, conn: &Connection) -> anyhow::Result<Verdict> {
    let input = &env.input;
    let channels = &env.config.channels;
    let opts = env.match_opts(conn)?;
    let search_start = std::time::Instant::now();
    let (channel, hits, trigger, cutoff) = match input.tool_name.as_str() {
        "WebFetch" => {
            let mut found = None;
            if channels.url {
                if let Some(norm) = input.tool_input_str("url").and_then(norm_url) {
                    let hits = matching::url_channel(conn, &norm, &opts)?;
                    if !hits.is_empty() {
                        found = Some((Channel::Url, hits, norm, None));
                    }
                }
            }
            let prompt = input.tool_input_str("prompt").unwrap_or_default();
            if found.is_none() && channels.query && !prompt.is_empty() {
                let cutoff = calibrate::cutoff_query(conn)?;
                let hits = matching::query_channel(conn, prompt, cutoff, &opts)?;
                found = Some((Channel::Query, hits, prompt.to_string(), Some(cutoff)));
            }
            match found {
                Some(f) => f,
                None => return Ok(Verdict::quiet("no_match")),
            }
        }
        "WebSearch" => {
            let query = input.tool_input_str("query").unwrap_or_default();
            if !channels.query || query.is_empty() {
                return Ok(Verdict::quiet("no_match"));
            }
            let cutoff = calibrate::cutoff_query(conn)?;
            let hits = matching::query_channel(conn, query, cutoff, &opts)?;
            (Channel::Query, hits, query.to_string(), Some(cutoff))
        }
        // Codex web search: the query channel on the joined `q` values.
        "webrun" => {
            let query = codex_query(&input.tool_input).unwrap_or_default();
            if !channels.query || query.is_empty() {
                return Ok(Verdict::quiet("no_match"));
            }
            let cutoff = calibrate::cutoff_query(conn)?;
            let hits = matching::query_channel(conn, &query, cutoff, &opts)?;
            (Channel::Query, hits, query, Some(cutoff))
        }
        _ => return Ok(Verdict::quiet("no_match")),
    };
    deliver(
        env,
        conn,
        Delivery {
            event: EVENT,
            channel,
            hits,
            trigger_text: Some(env.trigger_text(&trigger)),
            cutoff,
            search_ms: elapsed_ms(search_start),
            opts: &opts,
        },
    )
}
