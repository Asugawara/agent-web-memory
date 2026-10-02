//! `awm search`: runs the url or query channel with the default cutoffs.

use serde_json::json;

use crate::config;
use crate::matching::{self, calibrate, Hit, MatchOpts};
use crate::normalize::norm_url;
use crate::note::{Channel, Relation, RenderCtx};
use crate::paths;
use crate::render;

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Search text, or a URL with --url
    pub text: String,
    /// Treat the text as a URL and use the url channel
    #[arg(long)]
    pub url: bool,
    /// Notes to show (1-3)
    #[arg(long, default_value_t = 3)]
    pub limit: usize,
    /// Print JSON rows instead of notes
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let conn = super::open_db()?;
    let opts = MatchOpts {
        limit: args.limit.clamp(1, matching::MAX_HITS),
        ..MatchOpts::default()
    };
    let (channel, hits) = if args.url {
        let norm = norm_url(&args.text)
            .ok_or_else(|| anyhow::anyhow!("not a usable URL: {}", args.text))?;
        (Channel::Url, matching::url_channel(&conn, &norm, &opts)?)
    } else {
        let cutoff = calibrate::cutoff_query(&conn)?;
        (
            Channel::Query,
            matching::query_channel(&conn, &args.text, cutoff, &opts)?,
        )
    };
    // An explicit query shows teammates' notes whatever `team.show` says; a muted handle is marked.
    let mute = config::load(&paths::config_path()?)?.team.mute;
    if args.json {
        println!("{}", rows_json(&conn, &hits, &opts, &mute)?);
        return Ok(());
    }
    let mut notes = Vec::new();
    for hit in &hits {
        notes.push(matching::to_note(&conn, hit, &opts)?);
    }
    let muted: Vec<String> = notes
        .iter()
        .filter_map(|n| match &n.relation {
            Relation::Teammate { handle, .. } if is_muted(handle, &mute) => Some(handle.clone()),
            _ => None,
        })
        .collect();
    let ctx = RenderCtx {
        channel,
        now_ms: super::now_ms(),
        utc_offset_min: 0,
        ref_id: "00000000".to_string(),
        max_notes: opts.limit,
    };
    match render::render(&notes, &ctx) {
        Some(r) => {
            let mut text = r.text;
            for h in &muted {
                let label = render::plain_label(h, 24);
                text = text.replace(
                    &format!("teammate @{label}, "),
                    &format!("teammate @{label} (muted), "),
                );
            }
            println!("{text}");
        }
        None => println!("No matching notes."),
    }
    Ok(())
}

fn is_muted(handle: &str, mute: &[String]) -> bool {
    mute.iter().any(|m| m.trim_start_matches('@') == handle)
}

fn rows_json(
    conn: &rusqlite::Connection,
    hits: &[Hit],
    opts: &MatchOpts,
    mute: &[String],
) -> anyhow::Result<serde_json::Value> {
    let mut rows = Vec::new();
    for hit in hits {
        let n = matching::to_note(conn, hit, opts)?;
        let (origin, member): (String, Option<String>) = conn.query_row(
            "SELECT origin, member FROM event WHERE id = ?1",
            [n.event_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (relation, handle, muted) = match &n.relation {
            Relation::Teammate { handle, .. } => {
                let h = if handle.is_empty() { "unknown" } else { handle };
                ("teammate", Some(h.to_string()), is_muted(handle, mute))
            }
            Relation::OwnDevice => ("own_device", None, false),
            _ => ("own", None, false),
        };
        let mut row = json!({
            "event_id": n.event_id,
            "tool": n.tool.as_db_str(),
            "created_at": n.created_at_ms,
            "score": n.score,
            "seen": n.seen,
            "url": n.url,
            "query": n.searched,
            "fetch_prompt": n.asked,
            "status": n.status.as_db_str(),
            "http_code": n.http_code,
            "summary": n.summary,
            "origin": origin,
            "member": member,
            "handle": handle,
            "relation": relation,
        });
        if muted {
            row["muted"] = json!(true);
        }
        rows.push(row);
    }
    Ok(serde_json::Value::Array(rows))
}
