//! UserPromptSubmit: gate, prompt_url inject, prompt_bm25 inject (plan-v2 §3.4, §5.1).

use rusqlite::Connection;

use super::{deliver, elapsed_ms, Delivery, Env, HookArgs, Verdict};
use crate::config::PromptBm25;
use crate::gate::{self, Gate};
use crate::matching::{self, calibrate};
use crate::note::Channel;

const EVENT: &str = "UserPromptSubmit";
/// The bench setting: only the start of a long prompt is matched (§3.1).
const BM25_PROMPT_CHARS: usize = 1_000;

pub fn run(_args: HookArgs) -> anyhow::Result<()> {
    super::run_sync("prompt", handle);
    Ok(())
}

fn handle(env: &Env, conn: &Connection) -> anyhow::Result<Verdict> {
    // The hook does not fire inside subagents (§5.1); a payload with an agent id is not ours.
    if env.is_subagent() {
        return Ok(Verdict::quiet("gated"));
    }
    let prompt = env.input.prompt.clone().unwrap_or_default();
    let channels = &env.config.channels;
    let opts = env.match_opts(conn)?;
    let search_start = std::time::Instant::now();
    let (channel, hits, cutoff) =
        match gate::gate(&prompt, channels.prompt_bm25 == PromptBm25::Inject) {
            Gate::Skip(_) => return Ok(Verdict::quiet("gated")),
            Gate::PromptUrl(_) => {
                if !channels.prompt_url {
                    return Ok(Verdict::quiet("gated"));
                }
                let hits = matching::prompt_url_channel(conn, &prompt, &opts)?;
                (Channel::PromptUrl, hits, None)
            }
            Gate::PromptBm25 => {
                let text: String = prompt.chars().take(BM25_PROMPT_CHARS).collect();
                let cutoff = calibrate::cutoff_prompt(conn)?;
                let hits = matching::query_channel(conn, &text, cutoff, &opts)?;
                (Channel::PromptBm25, hits, Some(cutoff))
            }
        };
    deliver(
        env,
        conn,
        Delivery {
            event: EVENT,
            channel,
            hits,
            trigger_text: Some(env.trigger_text(&prompt)),
            cutoff,
            search_ms: elapsed_ms(search_start),
            opts: &opts,
        },
    )
}
