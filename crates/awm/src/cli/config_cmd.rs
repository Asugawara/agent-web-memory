//! `awm config get|set|list`.

use crate::config;
use crate::paths;

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub command: Sub,
}

impl Default for Args {
    fn default() -> Self {
        Args { command: Sub::List }
    }
}

#[derive(clap::Subcommand, Debug)]
pub enum Sub {
    /// Print one value
    Get { key: String },
    /// Change one value
    Set { key: String, value: String },
    /// Print every value
    List,
}

const KEYS: &[&str] = &[
    "mode",
    "notify",
    "channels.url",
    "channels.query",
    "channels.prompt_url",
    "channels.prompt_bm25",
    "short_circuit.mode",
    "short_circuit.window_days",
    "short_circuit.query",
    "short_circuit.query_window_days",
    "short_circuit.query_min_score",
    "inject.max_notes",
    "hooks.deadline_ms",
    "capture.exclude_hosts",
    "capture.redact_terms",
    "review.daily_limit",
    "pricing.currency",
    "pricing.summariser_input_per_mtok",
    "pricing.summariser_output_per_mtok",
    "pricing.search_fee_per_call",
    "pricing.main_input_per_mtok",
    "quota.capture",
    "quota.retention_days",
    "team.auto_sync",
    "team.sync_interval_s",
    "team.show",
    "team.mute",
    "team.share_all_projects",
    "team.exclude_hosts",
    "team.summary_chars",
    "team.share_stats",
    "team.auto_approve",
    "team.push_delay_s",
];

pub fn run(args: Args) -> anyhow::Result<()> {
    let path = paths::config_path()?;
    let mut cfg = config::load(&path)?;
    for w in &cfg.warnings {
        eprintln!("awm: {w}");
    }
    match args.command {
        Sub::Get { key } => {
            let v = cfg
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("unknown configuration key: {key}"))?;
            println!("{v}");
        }
        Sub::List => {
            for key in KEYS {
                println!("{key} = {}", cfg.get(key).unwrap_or_default());
            }
        }
        Sub::Set { key, value } => {
            cfg.set(&key, &value)?;
            cfg.warnings.clear();
            cfg.save(&path)?;
            println!("{key} = {}", cfg.get(&key).unwrap_or_default());
            if key == "team.auto_approve" && matches!(value.as_str(), "devices" | "all") {
                println!("{}", auto_approve_risk(&value));
            }
            if key == "channels.prompt_bm25" && value != "off" {
                println!(
                    "Note: matching prompts keep their first 200 characters in the local log."
                );
            }
        }
    }
    Ok(())
}

/// The one line `awm config set team.auto_approve devices|all` prints (RVT2 m3).
fn auto_approve_risk(value: &str) -> String {
    let who = if value == "all" {
        "a device or member"
    } else {
        "a new device of yours"
    };
    format!(
        "Warning: with {value}, {who} that joins is approved at the next sync without anyone \
         comparing the 6-digit code, so whoever gets a leaked invite string first is let in \
         and receives every epoch key."
    )
}
