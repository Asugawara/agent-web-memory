//! Detached `awm sync --once --quiet` spawn from hooks (plan-v3-team §3.3, §4.1 item 4, §4.6; TM13).
//!
//! Starts a process and opens no socket: nothing here (or in a hook path) may call the HTTP client.
//! Called from `hook/session_start.rs` and `hook/capture.rs` only, after their own commit or
//! `hook_run` row (RVT0 m11); the prompt, pre-fetch, pre-search and post-tool hooks never spawn.
//!
//! The recipe is SP1's `setsid` form: a new session, stdio on the null device, the `Child`
//! dropped and never waited for. The hook must exit at once afterwards: Claude Code kills the
//! process tree of a hook that is still alive when its `timeout` expires.

use std::path::Path;
use std::process::{Command, Stdio};

use crate::config::Config;
use crate::db::{self, Role, VersionCheck};
use crate::paths;

/// `sync_state.last_spawn`: Unix milliseconds of the last spawn, as decimal text. Written here
/// only (the engine never writes it, `sync::state`).
pub const LAST_SPAWN: &str = "last_spawn";

/// The arguments of the child: `awm sync --once --quiet` (§4.6).
const CHILD_ARGS: [&str; 3] = ["sync", "--once", "--quiet"];

/// True when `team.toml` and `team.key` are both in the data directory (this machine is in a
/// team). Duplicates `sync::state::configured`, which exists only with the `sync` feature.
fn configured(dir: &Path) -> bool {
    dir.join("team.toml").is_file() && dir.join("team.key").is_file()
}

/// Spawns `awm sync --once --quiet` detached when the debounce allows (§3.3). Returns whether
/// a child was started. Never fails and never waits.
pub fn maybe_spawn(data_dir: &Path, config: &Config, now_ms: i64) -> bool {
    maybe_spawn_with(data_dir, config, now_ms, spawn_sync)
}

/// [`maybe_spawn`] with the launcher replaced (tests).
///
/// Returns at once, without opening the database, unless a team is configured and
/// `team.auto_sync` is on; then it opens the database and returns unless the schema is current
/// and `sync_state.last_spawn` is older than `team.sync_interval_s` (0 means every time). A
/// `last_spawn` in the future counts as expired. `last_spawn` is written before the launcher
/// runs, so two hooks of one moment start one child; a database that cannot be written right
/// now (locked) starts none.
pub fn maybe_spawn_with(
    data_dir: &Path,
    config: &Config,
    now_ms: i64,
    launch: impl FnOnce() -> std::io::Result<()>,
) -> bool {
    if !config.team.auto_sync || !configured(data_dir) {
        return false;
    }
    let Ok(conn) = db::open(&data_dir.join(paths::DB_FILE), Role::HookRead) else {
        return false;
    };
    if !matches!(db::check_version(&conn), Ok(VersionCheck::Current)) {
        return false;
    }
    let last: Option<i64> = conn
        .query_row(
            "SELECT value FROM sync_state WHERE key = ?1",
            [LAST_SPAWN],
            |r| r.get::<_, String>(0),
        )
        .ok()
        .and_then(|v| v.trim().parse().ok());
    let interval_ms = i64::from(config.team.sync_interval_s) * 1_000;
    let due = match last {
        Some(t) if t <= now_ms => now_ms - t >= interval_ms,
        _ => true,
    };
    if !due {
        return false;
    }
    let written = conn.execute(
        "INSERT INTO sync_state (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![LAST_SPAWN, now_ms.to_string()],
    );
    if written.is_err() {
        return false;
    }
    drop(conn);
    launch().is_ok()
}

/// Starts `awm sync --once --quiet` in a new session with stdio on the null device.
fn spawn_sync() -> std::io::Result<()> {
    let exe = child_program()?;
    spawn_detached(&exe, &CHILD_ARGS)
}

/// The program to run: this binary. Debug builds (tests) honour `AWM_TEST_SYNC_EXE`, a stand-in
/// that takes the same arguments; a release build never reads the variable.
fn child_program() -> std::io::Result<std::path::PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("AWM_TEST_SYNC_EXE").filter(|p| !p.is_empty()) {
        return Ok(p.into());
    }
    std::env::current_exe()
}

/// Runs `program args` detached (SP1): new session, null stdio, the child is not waited for.
pub fn spawn_detached(program: &Path, args: &[&str]) -> std::io::Result<()> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        extern "C" {
            fn setsid() -> i32;
        }
        // SAFETY: `setsid` is async-signal-safe and touches no memory of this process.
        unsafe {
            cmd.pre_exec(|| {
                if setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
    }
    // The `Child` is dropped on purpose: the hook exits at once and init reaps the child.
    cmd.spawn().map(drop)
}
