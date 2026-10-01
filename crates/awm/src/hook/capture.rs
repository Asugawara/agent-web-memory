//! Async PostToolUse capture hook: stores the record and prints nothing.

use std::io::Read;

use super::HookArgs;
use crate::capture::{self, CaptureOpts};
use crate::{config, paths};

/// Never fails: every error path exits 0 (plan-v2 §5.4). With `AWM_DEBUG=1`
/// errors go to stderr.
pub fn run(_args: HookArgs) -> anyhow::Result<()> {
    if let Err(e) = capture_stdin() {
        if std::env::var_os("AWM_DEBUG").is_some_and(|v| v == "1") {
            eprintln!("awm capture: {e:#}");
        }
    }
    Ok(())
}

fn capture_stdin() -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(&input) else {
        return Ok(());
    };
    let data_dir = paths::data_dir()?;
    if !data_dir.join(paths::DB_FILE).is_file() {
        return Ok(());
    }
    // A configuration that cannot be read might hold `mode = "off"` or exclusions: record nothing.
    let config = config::load(&paths::config_path()?)?;
    let now_ms = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let opts = CaptureOpts {
        data_dir,
        config,
        now_ms: i64::try_from(now_ms).unwrap_or(i64::MAX),
    };
    capture::run(&payload, &opts)?;
    Ok(())
}
