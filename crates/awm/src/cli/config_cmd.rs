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
    "short_circuit.window_minutes",
    "short_circuit.subagents",
    "short_circuit.query",
    "short_circuit.query_window_minutes",
    "inject.max_notes",
    "inject.max_per_agent",
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
            if key == "channels.prompt_bm25" && value != "off" {
                println!(
                    "Note: matching prompts keep their first 200 characters in the local log."
                );
            }
        }
    }
    Ok(())
}
