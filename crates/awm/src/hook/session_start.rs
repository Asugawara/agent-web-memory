//! SessionStart: `systemMessage` notices only, never model context (plan-v2 §5.1, §5.4).

use std::time::Instant;

use super::{now_ms, parse_input, system_message_json, version_notice, HookArgs, RunMeta};
use crate::config::{self, Mode};
use crate::db::{self, Role};
use crate::paths;

/// S2 (plan-v2 §2.2).
pub const NOT_SET_UP: &str = "agent-web-memory: not set up yet, nothing is recorded. Run: awm init";
const DB_ERROR: &str = "agent-web-memory: error reading the database. Run: awm doctor";

pub fn run(args: HookArgs) -> anyhow::Result<()> {
    let started = Instant::now();
    let started_at_ms = now_ms();
    let mut text = String::new();
    let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut text);
    let session_id = parse_input(&text)
        .map(|i| i.session_id)
        .filter(|s| !s.is_empty());
    let Ok(data_dir) = paths::data_dir() else {
        return Ok(());
    };
    // A configuration that cannot be read might hold `mode = "off"`: say nothing.
    let Ok(config) = config::load(&data_dir.join(paths::CONFIG_FILE)) else {
        return Ok(());
    };
    let db_path = data_dir.join(paths::DB_FILE);
    let meta = RunMeta {
        db_path: db_path.clone(),
        hook: "session-start",
        session_id,
        agent_kind: "main",
        started_at_ms,
        started,
    };
    if config.mode == Mode::Off {
        meta.log_standalone("off", None);
        return Ok(());
    }
    if !db_path.is_file() {
        println!("{}", system_message_json(NOT_SET_UP));
        return Ok(());
    }
    let mut notices: Vec<String> = Vec::new();
    match db::open(&db_path, Role::HookRead) {
        Ok(conn) => {
            match db::check_version(&conn) {
                Ok(check) => notices.extend(version_notice(check)),
                Err(_) => notices.push(DB_ERROR.to_string()),
            }
            notices.extend(plugin_notice(args.plugin_version.as_deref()));
            if notices.is_empty() {
                meta.log_standalone("no_match", None);
            } else {
                meta.log_standalone("skipped", None);
            }
        }
        // A busy database says nothing: the next hook will find it free.
        Err(e) if super::is_busy(&e) => {}
        Err(_) => notices.push(DB_ERROR.to_string()),
    }
    if !notices.is_empty() {
        println!("{}", system_message_json(&notices.join("\n")));
    }
    Ok(())
}

/// `major.minor` of a version string.
fn minor_of(v: &str) -> Option<(u32, u32)> {
    let mut parts = v.trim().split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

/// The plugin and the binary differ in major or minor version (§5.4).
fn plugin_notice(plugin: Option<&str>) -> Option<String> {
    let plugin = plugin?;
    let binary = env!("CARGO_PKG_VERSION");
    let (p, b) = (minor_of(plugin)?, minor_of(binary)?);
    (p != b).then(|| {
        format!(
            "agent-web-memory: plugin {plugin} needs awm {plugin}; found {binary}. Upgrade awm."
        )
    })
}
