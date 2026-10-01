//! Async PostToolUse capture hook: stores the record and prints nothing.

use std::io::Read;

use super::HookArgs;
use crate::capture::{self, CaptureOpts, CaptureOutcome};
use crate::db::{self, Role};
use crate::matching::calibrate;
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
    let db_path = data_dir.join(paths::DB_FILE);
    if !db_path.is_file() {
        return Ok(());
    }
    // A configuration that cannot be read might hold `mode = "off"` or exclusions: record nothing.
    let config = config::load(&paths::config_path()?)?;
    // Recording declined (§5.4): `meta.consent.record` must be `yes`. A database that cannot be
    // read right now (locked) is not a refusal: `capture::run` spools the payload.
    if let Ok(conn) = db::open(&db_path, Role::HookRead) {
        if let Ok(false) = super::recording_consented(&conn) {
            return Ok(());
        }
    }
    let opts = CaptureOpts {
        data_dir,
        config,
        now_ms: super::now_ms(),
    };
    if capture::run(&payload, &opts)? == CaptureOutcome::Captured {
        // §3.3 step 6: the record count has doubled since the last calibration.
        let conn = db::open(&db_path, Role::Capture)?;
        if calibrate::should_recalibrate(&conn)? {
            calibrate::run(&conn)?;
        }
    }
    Ok(())
}
