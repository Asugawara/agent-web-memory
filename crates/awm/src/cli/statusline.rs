//! `awm statusline`: records usage-limit samples (plan-quota §4.2).
//!
//! Never a hook, but it takes the silent path of `main::run_hook`: exit 0 always.
//! It never opens the database and has no network code.

use std::io::{Read, Write};
use std::time::Duration;

use clap::Parser;
use serde_json::Value;

use crate::config::{self, Mode};
use crate::deadline::Watchdog;
use crate::quota::{self, sample::Sample, store};

const MAX_STDIN: u64 = 1 << 20;
const DEADLINE: Duration = Duration::from_millis(100);

#[derive(Parser, Debug)]
pub struct Args {
    /// Print nothing
    #[arg(long)]
    pub quiet: bool,
}

fn debug_enabled() -> bool {
    std::env::var_os("AWM_DEBUG").is_some_and(|v| v == "1")
}

fn now_ms() -> i64 {
    std::env::var("AWM_TEST_NOW_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(super::now_ms)
}

/// The JSON on stdin; `None` when it is empty, over 1 MiB or not JSON.
fn read_input() -> Option<Value> {
    let mut buf = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_STDIN + 1)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.is_empty() || buf.len() as u64 > MAX_STDIN {
        return None;
    }
    serde_json::from_slice(&buf).ok()
}

/// The `quota` directory when a sample may be written: the data dir exists, the
/// config parses, `mode` is not `off` and `quota.capture` is not `false`.
fn sample_dir() -> Option<std::path::PathBuf> {
    let data = crate::paths::data_dir().ok()?;
    if !data.is_dir() {
        return None;
    }
    let cfg = config::load(&data.join(crate::paths::CONFIG_FILE)).ok()?;
    (cfg.mode != Mode::Off && cfg.quota.capture).then(|| data.join(quota::DIR))
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let watchdog = Watchdog::start(DEADLINE, || {});
    let input = read_input();
    let now = now_ms();
    let sample = input.as_ref().and_then(|v| Sample::from_statusline(v, now));
    let dir = sample.as_ref().and_then(|_| sample_dir());

    if let Some(ms) = std::env::var("AWM_TEST_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        std::thread::sleep(Duration::from_millis(ms));
    }
    if !watchdog.commit() {
        loop {
            std::thread::park();
        }
    }

    if let (Some(dir), Some(sample)) = (dir, &sample) {
        if let Err(e) = store::record(&dir, sample) {
            if debug_enabled() {
                eprintln!("awm statusline: {e}");
            }
        }
    }
    if !args.quiet {
        if let Some(v) = &input {
            let line = short_line(v, now.div_euclid(1000));
            let _ = writeln!(std::io::stdout(), "{line}");
        }
    }
    Ok(())
}

/// `5h 24% (2h10m) · 7d 41% (3d4h)`; an absent window is omitted.
pub fn short_line(v: &Value, now_s: i64) -> String {
    let limits = v.get("rate_limits");
    let parts: Vec<String> = [("5h", "five_hour"), ("7d", "seven_day")]
        .into_iter()
        .filter_map(|(label, key)| {
            let w = quota::sample::window(limits?.get(key)?)?;
            Some(format!(
                "{label} {}% ({})",
                w.p.round() as i64,
                remaining(w.r - now_s)
            ))
        })
        .collect();
    parts.join(" · ")
}

fn remaining(secs: i64) -> String {
    let mins = secs.max(0) / 60;
    let (d, h, m) = (mins / 1440, mins % 1440 / 60, mins % 60);
    if d > 0 {
        format!("{d}d{h}h")
    } else if h > 0 {
        format!("{h}h{m}m")
    } else {
        format!("{m}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_formats_days_hours_minutes() {
        assert_eq!(remaining(2 * 3600 + 10 * 60), "2h10m");
        assert_eq!(remaining(3 * 86400 + 4 * 3600 + 59), "3d4h");
        assert_eq!(remaining(59 * 60 + 59), "59m");
        assert_eq!(remaining(-10), "0m");
    }
}
