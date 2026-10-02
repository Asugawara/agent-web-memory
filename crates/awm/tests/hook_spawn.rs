//! `sync::spawn::maybe_spawn` (plan-v3-team §3.3, TM13): the debounce, the guards, the detached
//! child that survives its hook, and the hooks that may and may not spawn.
//!
//! The end-to-end tests run the binary with `AWM_TEST_SYNC_EXE` (debug builds only) pointing at a
//! stand-in that records its arguments and, a second later, a marker file.

use std::cell::Cell;
use std::path::{Path, PathBuf};

use awm::config::Config;
use awm::db::{self, Role};
use awm::sync::spawn::{maybe_spawn_with, LAST_SPAWN};
use rusqlite::Connection;

const NOW: i64 = 1_790_000_000_000;

struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    /// A data directory with a current database and, when `team`, `team.toml` and `team.key`.
    fn new(team: bool) -> Home {
        let home = Home {
            dir: tempfile::tempdir().unwrap(),
        };
        let mut conn = db::open(&home.db_path(), Role::Cli).unwrap();
        db::migrate(&mut conn).unwrap();
        conn.execute_batch(
            "INSERT INTO meta (key, value) VALUES ('consent.record', 'yes'), \
             ('cutoff.query', '0'), ('cutoff.prompt', '0')",
        )
        .unwrap();
        if team {
            home.join_team();
        }
        home
    }

    fn join_team(&self) {
        std::fs::write(
            self.path().join("team.toml"),
            "member_id = \"11111111-1111-4111-8111-111111111111\"\n",
        )
        .unwrap();
        std::fs::write(self.path().join("team.key"), "{}").unwrap();
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn db_path(&self) -> PathBuf {
        self.path().join("awm.db")
    }

    fn conn(&self) -> Connection {
        db::open(&self.db_path(), Role::Cli).unwrap()
    }

    fn last_spawn(&self) -> Option<String> {
        self.conn()
            .query_row(
                "SELECT value FROM sync_state WHERE key = ?1",
                [LAST_SPAWN],
                |r| r.get(0),
            )
            .ok()
    }

    fn set_last_spawn(&self, value: &str) {
        self.conn()
            .execute(
                "INSERT INTO sync_state (key, value) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [LAST_SPAWN, value],
            )
            .unwrap();
    }
}

fn config(interval_s: u32) -> Config {
    let mut c = Config::default();
    c.team.sync_interval_s = interval_s;
    c
}

/// Calls `maybe_spawn_with` and reports how often the launcher ran.
fn call(home: &Home, config: &Config, now_ms: i64) -> usize {
    let launched = Cell::new(0);
    let returned = maybe_spawn_with(home.path(), config, now_ms, || {
        launched.set(launched.get() + 1);
        Ok(())
    });
    assert_eq!(returned, launched.get() == 1);
    launched.get()
}

// ---- the debounce and the guards ----

#[test]
fn no_team_configured_returns_without_touching_the_database() {
    // No team files, and a database path that holds garbage: it must not even be opened.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("awm.db"), b"not a database").unwrap();
    let launched = Cell::new(false);
    let returned = maybe_spawn_with(dir.path(), &config(0), NOW, || {
        launched.set(true);
        Ok(())
    });
    assert!(!returned && !launched.get());
    assert_eq!(
        std::fs::read(dir.path().join("awm.db")).unwrap(),
        b"not a database"
    );
    assert!(!dir.path().join("awm.db-wal").exists());

    // One of the two files is not a team either.
    let half = Home::new(false);
    std::fs::write(half.path().join("team.toml"), "").unwrap();
    assert_eq!(call(&half, &config(0), NOW), 0);
    assert_eq!(half.last_spawn(), None);
}

#[test]
fn a_schema_that_is_not_current_returns() {
    let home = Home::new(false);
    home.join_team();
    // Back to schema 2: no sync_state table, and the binary must leave the database alone.
    let dir = tempfile::tempdir().unwrap();
    let mut conn = db::open(&dir.path().join("awm.db"), Role::Cli).unwrap();
    db::migrate_with(&mut conn, &db::MIGRATIONS[..2]).unwrap();
    drop(conn);
    std::fs::write(dir.path().join("team.toml"), "").unwrap();
    std::fs::write(dir.path().join("team.key"), "{}").unwrap();
    let launched = Cell::new(false);
    let returned = maybe_spawn_with(dir.path(), &config(0), NOW, || {
        launched.set(true);
        Ok(())
    });
    assert!(!returned && !launched.get());
}

#[test]
fn a_missing_database_returns() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("team.toml"), "").unwrap();
    std::fs::write(dir.path().join("team.key"), "{}").unwrap();
    let launched = Cell::new(false);
    assert!(!maybe_spawn_with(dir.path(), &config(0), NOW, || {
        launched.set(true);
        Ok(())
    }));
    assert!(!launched.get());
    assert!(
        !dir.path().join("awm.db").exists(),
        "a hook never creates it"
    );
}

#[test]
fn the_first_call_spawns_and_writes_last_spawn() {
    let home = Home::new(true);
    assert_eq!(call(&home, &config(60), NOW), 1);
    assert_eq!(home.last_spawn(), Some(NOW.to_string()));
}

#[test]
fn a_call_within_the_interval_returns() {
    let home = Home::new(true);
    assert_eq!(call(&home, &config(60), NOW), 1);
    assert_eq!(call(&home, &config(60), NOW + 1), 0);
    assert_eq!(call(&home, &config(60), NOW + 59_999), 0);
    assert_eq!(home.last_spawn(), Some(NOW.to_string()), "unchanged");
    assert_eq!(call(&home, &config(60), NOW + 60_000), 1);
    assert_eq!(home.last_spawn(), Some((NOW + 60_000).to_string()));
}

#[test]
fn an_interval_of_zero_spawns_every_time() {
    let home = Home::new(true);
    for i in 0..3 {
        assert_eq!(call(&home, &config(0), NOW), 1, "call {i}");
    }
}

#[test]
fn a_last_spawn_in_the_future_counts_as_expired() {
    let home = Home::new(true);
    home.set_last_spawn(&(NOW + 3_600_000).to_string());
    assert_eq!(call(&home, &config(60), NOW), 1);
    assert_eq!(home.last_spawn(), Some(NOW.to_string()));
    home.set_last_spawn("garbage");
    assert_eq!(call(&home, &config(60), NOW + 1), 1);
}

#[test]
fn team_auto_sync_false_never_spawns() {
    let home = Home::new(true);
    let mut c = config(0);
    c.team.auto_sync = false;
    assert_eq!(call(&home, &c, NOW), 0);
    assert_eq!(home.last_spawn(), None);
}

#[test]
fn a_failed_launch_still_returns_false() {
    let home = Home::new(true);
    let r = maybe_spawn_with(home.path(), &config(0), NOW, || {
        Err(std::io::Error::other("no such program"))
    });
    assert!(!r);
}

#[test]
fn a_locked_database_spawns_nothing() {
    let home = Home::new(true);
    let locker = Connection::open(home.db_path()).unwrap();
    locker
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO meta (key, value) VALUES ('lock-test', '1');")
        .unwrap();
    assert_eq!(call(&home, &config(0), NOW), 0);
    locker.execute_batch("ROLLBACK").unwrap();
    assert_eq!(call(&home, &config(0), NOW), 1);
}

// ---- the sources: who may call the spawn ----

#[test]
fn only_session_start_and_capture_call_the_spawn() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for file in [
        "hook/mod.rs",
        "hook/prompt.rs",
        "hook/pre_fetch.rs",
        "hook/pre_search.rs",
        "hook/post_tool.rs",
    ] {
        let text = std::fs::read_to_string(src.join(file)).unwrap();
        assert!(
            !text.contains("spawn::") && !text.contains("maybe_spawn"),
            "{file} must not spawn (plan-v3-team §3.3)"
        );
    }
    for file in ["hook/session_start.rs", "hook/capture.rs"] {
        let text = std::fs::read_to_string(src.join(file)).unwrap();
        assert!(text.contains("maybe_spawn"), "{file} spawns");
    }
}

#[test]
fn no_hook_source_reaches_the_network_modules() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for file in ["hook", "matching"] {
        for entry in std::fs::read_dir(src.join(file)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                assert!(
                    !text.contains("sync::http") && !text.contains("ureq"),
                    "{} must not reach the network",
                    path.display()
                );
            }
        }
    }
    let text = std::fs::read_to_string(src.join("sync/spawn.rs")).unwrap();
    assert!(!text.contains("sync::http") && !text.contains("ureq"));
}

// ---- the binary: a detached child that outlives its hook ----

#[cfg(all(unix, debug_assertions))]
mod binary {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use serde_json::{json, Value};

    /// A stand-in for `awm sync --once --quiet`: records its arguments at once and a marker one
    /// second later, and keeps nothing of its parent's stdio.
    fn stand_in(home: &Home) -> PathBuf {
        let path = home.path().join("fake-sync.sh");
        let marker = home.path().join("marker");
        let script = format!(
            "#!/bin/sh\necho \"$@\" > '{m}.args'\nps -o ppid= -p $$ > '{m}.ppid'\nsleep 1\necho done > '{m}.done'\n",
            m = marker.display()
        );
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(script.as_bytes()).unwrap();
        f.sync_all().unwrap();
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn run_hook(home: &Home, hook: &str, payload: &Value, sync_exe: &Path) -> Duration {
        let mut child = Command::new(env!("CARGO_BIN_EXE_awm"))
            .args(["hook", hook])
            .env("AWM_HOME", home.path())
            .env("AWM_TEST_SYNC_EXE", sync_exe)
            .env_remove("AWM_DEBUG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        let _ = child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes());
        // Waits for EOF on stdout and stderr: a child that kept them would hold this for a second.
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        start.elapsed()
    }

    fn fixture(name: &str) -> Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/hooks")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn wait_for(path: &Path, secs: u64) -> bool {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            if path.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        path.exists()
    }

    fn session_start_payload() -> Value {
        json!({"session_id": "sess-1", "hook_event_name": "SessionStart", "cwd": "/work/x"})
    }

    #[test]
    fn session_start_spawns_a_child_that_outlives_the_hook() {
        let home = Home::new(true);
        let script = stand_in(&home);
        let elapsed = run_hook(&home, "session-start", &session_start_payload(), &script);
        assert!(
            elapsed < Duration::from_millis(900),
            "the hook waited for the child: {elapsed:?}"
        );
        assert!(
            !home.path().join("marker.done").exists(),
            "the child was already done when the hook returned"
        );
        // The hook has exited; the child still finishes.
        assert!(wait_for(&home.path().join("marker.done"), 10));
        let args = std::fs::read_to_string(home.path().join("marker.args")).unwrap();
        assert_eq!(args.trim(), "sync --once --quiet");
        let ppid = std::fs::read_to_string(home.path().join("marker.ppid")).unwrap();
        assert!(
            ppid.trim() != std::process::id().to_string(),
            "not a child of the test"
        );
        assert!(home.last_spawn().is_some());
    }

    #[test]
    fn capture_spawns_after_a_captured_record() {
        let home = Home::new(true);
        let script = stand_in(&home);
        let payload = fixture("PostToolUse-WebFetch-plugin-3.json");
        let elapsed = run_hook(&home, "capture", &payload, &script);
        assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");
        assert_eq!(
            home.conn()
                .query_row("SELECT COUNT(*) FROM event", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert!(wait_for(&home.path().join("marker.done"), 10));
        assert!(home.last_spawn().is_some());
    }

    #[test]
    fn capture_of_nothing_does_not_spawn() {
        let home = Home::new(true);
        let script = stand_in(&home);
        run_hook(&home, "capture", &json!({"tool_name": "Read"}), &script);
        std::thread::sleep(Duration::from_millis(300));
        assert!(!home.path().join("marker.args").exists());
        assert_eq!(home.last_spawn(), None);
    }

    #[test]
    fn no_team_no_child() {
        let home = Home::new(false);
        let script = stand_in(&home);
        run_hook(&home, "session-start", &session_start_payload(), &script);
        run_hook(
            &home,
            "capture",
            &fixture("PostToolUse-WebFetch-plugin-3.json"),
            &script,
        );
        std::thread::sleep(Duration::from_millis(300));
        assert!(!home.path().join("marker.args").exists());
    }

    #[test]
    fn the_other_hooks_never_spawn() {
        let home = Home::new(true);
        let script = stand_in(&home);
        for (hook, payload) in [
            ("post-tool", fixture("PostToolUse-WebFetch-plugin-3.json")),
            ("pre-fetch", fixture("PreToolUse-WebFetch-plugin-4.json")),
            ("pre-fetch", fixture("PreToolUse-WebSearch-main-cc-1.json")),
            ("prompt", fixture("UserPromptSubmit-none-plugin-1.json")),
        ] {
            run_hook(&home, hook, &payload, &script);
        }
        std::thread::sleep(Duration::from_millis(300));
        assert!(!home.path().join("marker.args").exists());
        assert_eq!(home.last_spawn(), None);
    }

    #[test]
    fn the_debounce_holds_across_hook_processes() {
        let home = Home::new(true);
        let script = stand_in(&home);
        run_hook(&home, "session-start", &session_start_payload(), &script);
        assert!(wait_for(&home.path().join("marker.done"), 10));
        std::fs::remove_file(home.path().join("marker.args")).unwrap();
        run_hook(&home, "session-start", &session_start_payload(), &script);
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !home.path().join("marker.args").exists(),
            "second spawn within 60 s"
        );
    }
}
