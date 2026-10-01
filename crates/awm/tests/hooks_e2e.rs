//! End-to-end tests of the hook entry points: the built binary, stdin to stdout and the database.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use awm::capture::{self, CaptureOpts};
use awm::config::{Config, Mode, Notify, PromptBm25, ShortCircuitMode};
use awm::db::{self, Role};
use rusqlite::Connection;
use serde_json::{json, Value};

const DAY_MS: i64 = 86_400_000;

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/hooks")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Replaces top-level keys of a payload.
fn patch(mut v: Value, edits: &[(&str, Value)]) -> Value {
    for (k, val) in edits {
        v[*k] = val.clone();
    }
    v
}

/// The first start of a freshly built binary can take several hundred milliseconds
/// (the OS scans it); do that once before any test measures a time.
fn warm_up() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = Command::new(env!("CARGO_BIN_EXE_awm"))
            .arg("--version")
            .output();
    });
}

struct Home {
    dir: tempfile::TempDir,
}

struct Out {
    code: Option<i32>,
    stdout: String,
    elapsed: Duration,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| panic!("{e}: {:?}", self.stdout))
    }

    fn context(&self) -> String {
        self.json()["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap()
            .to_string()
    }
}

impl Home {
    /// A migrated database with recording consent, and the default configuration.
    fn new() -> Home {
        let home = Home::bare();
        let mut conn = db::open(&home.db_path(), Role::Cli).unwrap();
        db::migrate(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('consent.record', 'yes')",
            [],
        )
        .unwrap();
        // A tiny corpus never reaches the shipped default cutoff.
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('cutoff.query', '0'), ('cutoff.prompt', '0')",
            [],
        )
        .unwrap();
        home
    }

    /// An empty data directory: `awm init` never ran.
    fn bare() -> Home {
        Home {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }

    fn db_path(&self) -> PathBuf {
        self.dir.path().join("awm.db")
    }

    fn conn(&self) -> Connection {
        db::open(&self.db_path(), Role::Cli).unwrap()
    }

    fn count(&self, sql: &str) -> i64 {
        self.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn text(&self, sql: &str) -> String {
        self.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn config(&self, edit: impl FnOnce(&mut Config)) {
        let mut c = Config::default();
        edit(&mut c);
        c.save(&self.dir.path().join("config.toml")).unwrap();
    }

    /// Stores a payload as an earlier record, `age_ms` ago.
    fn seed(&self, payload: &Value, age_ms: i64) {
        let opts = CaptureOpts {
            data_dir: self.path(),
            config: Config::default(),
            now_ms: now_ms() - age_ms,
        };
        let out = capture::run(payload, &opts).unwrap();
        assert_eq!(out, capture::CaptureOutcome::Captured, "{payload}");
    }

    fn run(&self, hook: &str, stdin: &str, envs: &[(&str, &str)]) -> Out {
        warm_up();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_awm"));
        cmd.args(["hook", hook])
            .env("AWM_HOME", self.dir.path())
            .env_remove("AWM_CANARY")
            .env_remove("AWM_CANARY_DENY")
            .env_remove("AWM_TEST_DELAY_MS")
            .env_remove("AWM_DEBUG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let start = Instant::now();
        let mut child = cmd.spawn().unwrap();
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        let o = child.wait_with_output().unwrap();
        Out {
            code: o.status.code(),
            stdout: String::from_utf8(o.stdout).unwrap(),
            elapsed: start.elapsed(),
        }
    }

    fn hook(&self, hook: &str, payload: &Value) -> Out {
        self.run(hook, &payload.to_string(), &[])
    }

    fn hook_env(&self, hook: &str, payload: &Value, envs: &[(&str, &str)]) -> Out {
        self.run(hook, &payload.to_string(), envs)
    }
}

fn assert_silent(out: &Out) {
    assert_eq!(out.code, Some(0));
    assert_eq!(out.stdout, "");
}

/// The earlier fetch of https://example.com (fixture 3), made in another session.
fn seed_example_fetch(home: &Home) {
    home.seed(&fixture("PostToolUse-WebFetch-plugin-3.json"), 2 * DAY_MS);
}

/// A later fetch of the same URL in a new session.
fn new_fetch() -> Value {
    patch(
        fixture("PostToolUse-WebFetch-plugin-3.json"),
        &[
            ("session_id", json!("sess-new")),
            ("tool_use_id", json!("toolu_new")),
        ],
    )
}

/// An earlier search by another session, sharing words with fixture 8's query.
fn seed_search(home: &Home) {
    let payload = json!({
        "session_id": "sess-old", "cwd": "/work/other", "hook_event_name": "PostToolUse",
        "tool_name": "WebSearch", "tool_use_id": "toolu_old_search",
        "tool_input": {"query": "sqlite fts5 bm25 ranking weights tutorial"},
        "tool_response": {"query": "sqlite fts5 bm25 ranking weights tutorial", "results": [
            {"tool_use_id": "srv1", "content": [
                {"title": "FTS5 ranking", "url": "https://sqlite.org/fts5.html"}]},
            "FTS5 ranks rows with bm25 and lets you weight columns."
        ]}
    });
    home.seed(&payload, DAY_MS);
}

fn search_by_subagent() -> Value {
    fixture("PostToolUse-WebSearch-plugin-8.json")
}

#[test]
fn a_match_prints_notes_in_additional_context() {
    let home = Home::new();
    seed_example_fetch(&home);
    let out = home.hook("post-tool", &new_fetch());
    assert_eq!(out.code, Some(0));
    let v = out.json();
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PostToolUse");
    assert!(out.context().starts_with("<awm-notes"), "{}", out.context());
    assert!(out.context().contains("https://example.com"));
    // notify = first: S6 on the first injection of the session
    let msg = v["systemMessage"].as_str().unwrap();
    assert!(
        msg.starts_with("agent-web-memory: added 1 note(s) from your earlier research"),
        "{msg}"
    );
    assert!(msg.contains("awm log --ref "));
    assert_eq!(
        home.text("SELECT mode || '/' || channel || '/' || hook FROM injection"),
        "inject/url/PostToolUse"
    );
    assert_eq!(home.count("SELECT COUNT(*) FROM injection_item"), 1);
    let (outcome, search_ms): (String, Option<i64>) = home
        .conn()
        .query_row(
            "SELECT outcome, search_ms FROM hook_run WHERE hook = 'post-tool'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(outcome, "injected");
    assert!(search_ms.is_some());
}

#[test]
fn s6_is_sent_once_per_session_when_notify_is_first() {
    let home = Home::new();
    seed_example_fetch(&home);
    home.seed(
        &patch(
            fixture("PostToolUse-WebFetch-plugin-3.json"),
            &[
                ("tool_use_id", json!("toolu_other")),
                (
                    "tool_input",
                    json!({"url": "https://example.org/a", "prompt": "x"}),
                ),
            ],
        ),
        DAY_MS,
    );
    let first = home.hook("post-tool", &new_fetch());
    assert!(first.json().get("systemMessage").is_some());
    let second = patch(
        new_fetch(),
        &[
            ("tool_use_id", json!("toolu_new2")),
            (
                "tool_input",
                json!({"url": "https://example.org/a", "prompt": "x"}),
            ),
        ],
    );
    let out = home.hook("post-tool", &second);
    assert!(out.context().starts_with("<awm-notes"));
    assert!(out.json().get("systemMessage").is_none());
}

#[test]
fn no_match_prints_nothing_and_logs_no_match() {
    let home = Home::new();
    let out = home.hook("post-tool", &new_fetch());
    assert_silent(&out);
    assert_eq!(
        home.text("SELECT outcome FROM hook_run WHERE hook = 'post-tool'"),
        "no_match"
    );
    assert_eq!(home.count("SELECT COUNT(*) FROM injection"), 0);
}

#[test]
fn a_search_matches_through_the_query_channel_and_a_subagent_is_stored() {
    let home = Home::new();
    seed_search(&home);
    let out = home.hook("post-tool", &search_by_subagent());
    assert!(out.context().starts_with("<awm-notes"), "{}", out.stdout);
    assert_eq!(
        home.text("SELECT channel || '/' || agent_id FROM injection"),
        "query/a0000000000000001"
    );
    assert_eq!(
        home.text("SELECT agent_kind FROM hook_run WHERE hook = 'post-tool'"),
        "subagent"
    );
}

#[test]
fn a_fetch_without_a_url_match_falls_back_to_its_prompt() {
    let home = Home::new();
    seed_search(&home);
    let fetch = patch(
        new_fetch(),
        &[(
            "tool_input",
            json!({"url": "https://example.net/x", "prompt": "bm25 ranking weights in sqlite fts5"}),
        )],
    );
    let out = home.hook("post-tool", &fetch);
    assert!(out.context().starts_with("<awm-notes"), "{}", out.stdout);
    assert_eq!(home.text("SELECT channel FROM injection"), "query");
}

#[test]
fn the_same_record_is_not_shown_twice_to_one_agent() {
    let home = Home::new();
    seed_example_fetch(&home);
    assert!(home
        .hook("post-tool", &new_fetch())
        .context()
        .starts_with("<awm-notes"));
    let again = patch(new_fetch(), &[("tool_use_id", json!("toolu_new_again"))]);
    assert_silent(&home.hook("post-tool", &again));
}

#[test]
fn max_per_agent_caps_the_injections() {
    let home = Home::new();
    home.config(|c| c.inject.max_per_agent = 1);
    seed_example_fetch(&home);
    home.seed(
        &patch(
            fixture("PostToolUse-WebFetch-plugin-3.json"),
            &[
                ("tool_use_id", json!("toolu_b")),
                (
                    "tool_input",
                    json!({"url": "https://example.org/b", "prompt": "x"}),
                ),
            ],
        ),
        DAY_MS,
    );
    assert!(!home.hook("post-tool", &new_fetch()).stdout.is_empty());
    let second = patch(
        new_fetch(),
        &[
            ("tool_use_id", json!("toolu_new_b")),
            (
                "tool_input",
                json!({"url": "https://example.org/b", "prompt": "x"}),
            ),
        ],
    );
    assert_silent(&home.hook("post-tool", &second));
}

#[test]
fn shadow_mode_logs_a_shadow_row_and_prints_nothing() {
    let home = Home::new();
    home.config(|c| c.mode = Mode::Shadow);
    seed_example_fetch(&home);
    let out = home.hook("post-tool", &new_fetch());
    assert_silent(&out);
    assert_eq!(home.text("SELECT mode FROM injection"), "shadow");
    assert_eq!(home.count("SELECT COUNT(*) FROM injection_item"), 1);
    assert_eq!(
        home.text("SELECT outcome FROM hook_run WHERE hook = 'post-tool'"),
        "shadow"
    );
}

#[test]
fn mode_off_prints_nothing() {
    let home = Home::new();
    home.config(|c| c.mode = Mode::Off);
    seed_example_fetch(&home);
    assert_silent(&home.hook("post-tool", &new_fetch()));
    assert_eq!(home.count("SELECT COUNT(*) FROM injection"), 0);
}

#[test]
fn recording_declined_means_no_output() {
    let home = Home::new();
    seed_example_fetch(&home);
    home.conn()
        .execute(
            "UPDATE meta SET value = 'no' WHERE key = 'consent.record'",
            [],
        )
        .unwrap();
    assert_silent(&home.hook("post-tool", &new_fetch()));
    assert_eq!(
        home.count("SELECT COUNT(*) FROM hook_run WHERE hook = 'post-tool'"),
        0
    );
}

#[test]
fn canary_text_is_appended_when_awm_canary_is_set() {
    let home = Home::new();
    seed_example_fetch(&home);
    let out = home.hook_env("post-tool", &new_fetch(), &[("AWM_CANARY", "n0nce")]);
    let ctx = out.context();
    assert!(ctx.starts_with("<awm-notes"));
    assert!(ctx.ends_with("AWM-CANARY-PostToolUse-n0nce"), "{ctx}");
    assert!(home
        .text("SELECT rendered FROM injection")
        .contains("AWM-CANARY-PostToolUse-n0nce"));
}

#[test]
fn canary_alone_is_printed_when_nothing_matches() {
    let home = Home::new();
    let out = home.hook_env("post-tool", &new_fetch(), &[("AWM_CANARY", "n0nce")]);
    assert_eq!(out.context(), "AWM-CANARY-PostToolUse-n0nce");
}

#[test]
fn the_deadline_fires_before_a_slow_hook_prints() {
    let home = Home::new();
    seed_example_fetch(&home);
    let out = home.hook_env("post-tool", &new_fetch(), &[("AWM_TEST_DELAY_MS", "800")]);
    assert_silent(&out);
    assert!(
        out.elapsed < Duration::from_millis(790),
        "{:?}",
        out.elapsed
    );
    assert_eq!(
        home.text("SELECT outcome FROM hook_run WHERE hook = 'post-tool'"),
        "deadline"
    );
    assert_eq!(home.count("SELECT COUNT(*) FROM injection"), 0);
}

#[test]
fn a_locked_database_gives_no_output_within_600_ms() {
    let home = Home::new();
    seed_example_fetch(&home);
    // The exclusive locking mode keeps readers out, as a long migration would.
    let locker = Connection::open(home.db_path()).unwrap();
    locker
        .execute_batch(
            "PRAGMA locking_mode = EXCLUSIVE; BEGIN IMMEDIATE; \
             INSERT INTO meta (key, value) VALUES ('lock-test', '1');",
        )
        .unwrap();
    let out = home.hook("post-tool", &new_fetch());
    assert_silent(&out);
    assert!(
        out.elapsed < Duration::from_millis(600),
        "{:?}",
        out.elapsed
    );
    locker.execute_batch("ROLLBACK").unwrap();
    drop(locker);
    // Once the lock is gone the same call injects.
    let again = home.hook("post-tool", &new_fetch());
    assert!(again.context().starts_with("<awm-notes"));
}

fn sibling_fetch(agent: Option<(&str, &str)>, id: &str) -> Value {
    let mut edits = vec![
        ("session_id", json!("sess-pre")),
        ("tool_use_id", json!(id)),
    ];
    if let Some((agent_id, agent_type)) = agent {
        edits.push(("agent_id", json!(agent_id)));
        edits.push(("agent_type", json!(agent_type)));
    }
    patch(fixture("PostToolUse-WebFetch-plugin-3.json"), &edits)
}

fn pre_fetch(agent: Option<(&str, &str)>, id: &str) -> Value {
    let mut edits = vec![
        ("session_id", json!("sess-pre")),
        ("tool_use_id", json!(id)),
    ];
    if let Some((agent_id, agent_type)) = agent {
        edits.push(("agent_id", json!(agent_id)));
        edits.push(("agent_type", json!(agent_type)));
    }
    patch(fixture("PreToolUse-WebFetch-plugin-4.json"), &edits)
}

fn deny_reason(out: &Out) -> String {
    let v = out.json();
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn a_sibling_fetch_is_denied_once_when_short_circuit_is_on() {
    let home = Home::new();
    home.config(|c| c.short_circuit.mode = ShortCircuitMode::On);
    home.seed(
        &sibling_fetch(Some(("agent-a", "researcher")), "toolu_a"),
        60_000,
    );
    let first = home.hook("pre-fetch", &pre_fetch(None, "toolu_main_1"));
    let reason = deny_reason(&first);
    assert!(
        reason.starts_with("agent-web-memory: this URL was already fetched"),
        "{reason}"
    );
    assert!(reason.contains("researcher"));
    assert!(reason.contains("it will not be blocked again"));
    // The second attempt of the same agent for the same URL passes.
    assert_silent(&home.hook("pre-fetch", &pre_fetch(None, "toolu_main_2")));
    assert_eq!(
        home.count("SELECT COUNT(*) FROM injection WHERE mode = 'deny'"),
        1
    );
    assert_eq!(
        home.text("SELECT outcome FROM hook_run WHERE hook = 'pre-fetch' ORDER BY id LIMIT 1"),
        "denied"
    );
}

#[test]
fn the_default_short_circuit_mode_only_logs_a_shadow_deny() {
    let home = Home::new();
    home.seed(
        &sibling_fetch(Some(("agent-a", "researcher")), "toolu_a"),
        60_000,
    );
    let out = home.hook("pre-fetch", &pre_fetch(None, "toolu_main_1"));
    assert_silent(&out);
    assert_eq!(home.text("SELECT mode FROM injection"), "shadow_deny");
    assert_eq!(
        home.text("SELECT outcome FROM hook_run WHERE hook = 'pre-fetch'"),
        "shadow"
    );
    assert_eq!(home.count("SELECT COUNT(*) FROM injection_item"), 1);
}

#[test]
fn the_callers_own_earlier_fetch_never_triggers_a_deny() {
    let home = Home::new();
    home.config(|c| c.short_circuit.mode = ShortCircuitMode::On);
    home.seed(&sibling_fetch(None, "toolu_main_0"), 60_000);
    assert_silent(&home.hook("pre-fetch", &pre_fetch(None, "toolu_main_1")));
    assert_eq!(home.count("SELECT COUNT(*) FROM injection"), 0);
}

#[test]
fn a_subagent_is_denied_only_with_short_circuit_subagents() {
    let off = Home::new();
    off.config(|c| c.short_circuit.mode = ShortCircuitMode::On);
    off.seed(&sibling_fetch(None, "toolu_main_0"), 60_000);
    let sub = Some(("agent-b", "general-purpose"));
    assert_silent(&off.hook("pre-fetch", &pre_fetch(sub, "toolu_b_1")));

    let on = Home::new();
    on.config(|c| {
        c.short_circuit.mode = ShortCircuitMode::On;
        c.short_circuit.subagents = true;
    });
    on.seed(&sibling_fetch(None, "toolu_main_0"), 60_000);
    let reason = deny_reason(&on.hook("pre-fetch", &pre_fetch(sub, "toolu_b_1")));
    assert!(reason.contains("the main agent"));
    assert_eq!(
        on.text("SELECT agent_id FROM injection WHERE mode = 'deny'"),
        "agent-b"
    );
}

#[test]
fn an_old_sibling_fetch_outside_the_window_does_not_deny() {
    let home = Home::new();
    home.config(|c| c.short_circuit.mode = ShortCircuitMode::On);
    home.seed(
        &sibling_fetch(Some(("agent-a", "researcher")), "toolu_a"),
        31 * 60_000,
    );
    assert_silent(&home.hook("pre-fetch", &pre_fetch(None, "toolu_main_1")));
}

#[test]
fn awm_canary_deny_forces_a_deny() {
    let home = Home::new();
    let out = home.hook_env(
        "pre-fetch",
        &pre_fetch(None, "toolu_main_1"),
        &[("AWM_CANARY_DENY", "1"), ("AWM_CANARY", "n0nce")],
    );
    let reason = deny_reason(&out);
    assert!(reason.contains("AWM-CANARY-PreToolUse-n0nce"), "{reason}");
}

#[test]
fn a_task_notification_prompt_is_gated() {
    let home = Home::new();
    seed_example_fetch(&home);
    let out = home.hook("prompt", &fixture("UserPromptSubmit-none-plugin-8.json"));
    assert_silent(&out);
    assert_eq!(
        home.text("SELECT outcome FROM hook_run WHERE hook = 'prompt'"),
        "gated"
    );
}

#[test]
fn a_prompt_with_a_known_url_injects_and_keeps_200_characters() {
    let home = Home::new();
    seed_example_fetch(&home);
    let long = format!(
        "what did we learn from https://example.com last time? {}",
        "padding ".repeat(60)
    );
    let prompt = patch(
        fixture("UserPromptSubmit-none-plugin-1.json"),
        &[
            ("prompt", json!(long)),
            ("session_id", json!("sess-prompt")),
        ],
    );
    let out = home.hook("prompt", &prompt);
    let v = out.json();
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit");
    assert!(out.context().starts_with("<awm-notes"));
    assert_eq!(
        home.text("SELECT channel || '/' || hook FROM injection"),
        "prompt_url/UserPromptSubmit"
    );
    assert_eq!(
        home.count("SELECT COUNT(*) FROM injection WHERE length(trigger_text) = 200"),
        1
    );
}

#[test]
fn a_plain_prompt_is_a_shadow_match_unless_prompt_bm25_is_inject() {
    let text = "explain sqlite fts5 bm25 ranking weights for column scoring";
    let prompt = patch(
        fixture("UserPromptSubmit-none-plugin-1.json"),
        &[
            ("prompt", json!(text)),
            ("session_id", json!("sess-prompt")),
        ],
    );

    let off = Home::new();
    seed_search(&off);
    assert_silent(&off.hook("prompt", &prompt));
    assert_eq!(off.count("SELECT COUNT(*) FROM injection"), 0);
    assert_eq!(
        off.text("SELECT outcome FROM hook_run WHERE hook = 'prompt'"),
        "gated"
    );

    let shadow = Home::new();
    shadow.config(|c| c.channels.prompt_bm25 = PromptBm25::Shadow);
    seed_search(&shadow);
    assert_silent(&shadow.hook("prompt", &prompt));
    assert_eq!(
        shadow.text("SELECT channel || '/' || mode || '/' || cutoff FROM injection"),
        "prompt_bm25/shadow/0.0"
    );

    let inject = Home::new();
    inject.config(|c| {
        c.channels.prompt_bm25 = PromptBm25::Inject;
        c.notify = Notify::Never;
    });
    seed_search(&inject);
    let out = inject.hook("prompt", &prompt);
    assert!(out.context().starts_with("<awm-notes"));
    assert!(out.json().get("systemMessage").is_none());
}

#[test]
fn a_prompt_inside_a_subagent_is_ignored() {
    let home = Home::new();
    seed_example_fetch(&home);
    let prompt = patch(
        fixture("UserPromptSubmit-none-plugin-1.json"),
        &[
            ("prompt", json!("look at https://example.com again please")),
            ("agent_id", json!("agent-x")),
        ],
    );
    assert_silent(&home.hook("prompt", &prompt));
}

#[test]
fn without_a_database_every_hook_is_silent_and_creates_nothing() {
    let home = Home::bare();
    for (hook, payload) in [
        ("post-tool", new_fetch()),
        ("pre-fetch", pre_fetch(None, "toolu_1")),
        ("prompt", fixture("UserPromptSubmit-none-plugin-1.json")),
        ("capture", new_fetch()),
    ] {
        assert_silent(&home.hook(hook, &payload));
    }
    assert!(!home.db_path().exists());
}

#[test]
fn bad_or_empty_stdin_exits_zero_silently() {
    let home = Home::new();
    for hook in ["post-tool", "pre-fetch", "prompt", "capture"] {
        assert_silent(&home.run(hook, "", &[]));
        assert_silent(&home.run(hook, "not json {", &[]));
    }
    assert_eq!(home.count("SELECT COUNT(*) FROM hook_run"), 0);
}

#[test]
fn session_start_prints_notices_only() {
    // S2: the binary exists but `awm init` never ran.
    let bare = Home::bare();
    let out = bare.run("session-start", "{}", &[]);
    assert_eq!(out.code, Some(0));
    assert_eq!(
        out.json(),
        json!({"systemMessage": "agent-web-memory: not set up yet, nothing is recorded. Run: awm init"})
    );
    assert!(!bare.db_path().exists());

    // A current database: nothing to say.
    let home = Home::new();
    assert_silent(&home.run("session-start", "{}", &[]));

    // An older schema.
    home.conn()
        .execute("DELETE FROM schema_version", [])
        .unwrap();
    assert_eq!(
        home.run("session-start", "{}", &[]).json()["systemMessage"],
        "agent-web-memory: database needs an upgrade. Run: awm doctor"
    );

    // A newer schema.
    home.conn()
        .execute(
            "INSERT INTO schema_version (version, name, checksum, applied_at) VALUES (9, 'x', 'x', 0)",
            [],
        )
        .unwrap();
    assert_eq!(
        home.run("session-start", "{}", &[]).json()["systemMessage"],
        "agent-web-memory: database is from a newer awm (9). Upgrade awm."
    );
}

#[test]
fn session_start_reports_a_plugin_version_mismatch_and_honours_mode_off() {
    let home = Home::new();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_awm"));
    cmd.args(["hook", "session-start", "--plugin-version", "9.9.0"])
        .env("AWM_HOME", home.path())
        .stdin(Stdio::null());
    let o = cmd.output().unwrap();
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(v["systemMessage"]
        .as_str()
        .unwrap()
        .starts_with("agent-web-memory: plugin 9.9.0 needs awm"));

    home.config(|c| c.mode = Mode::Off);
    assert_silent(&home.run("session-start", "{}", &[]));
    let bare = Home::bare();
    bare.config(|c| c.mode = Mode::Off);
    assert_silent(&bare.run("session-start", "{}", &[]));
}

#[test]
fn capture_stores_one_event_and_prints_nothing() {
    let home = Home::new();
    let out = home.hook("capture", &fixture("PostToolUse-WebFetch-plugin-3.json"));
    assert_silent(&out);
    assert_eq!(home.count("SELECT COUNT(*) FROM event"), 1);
    assert_eq!(
        home.text("SELECT outcome FROM hook_run WHERE hook = 'capture'"),
        "captured"
    );
}

#[test]
fn capture_with_empty_stdin_records_nothing() {
    let home = Home::new();
    assert_silent(&home.run("capture", "", &[]));
    assert_eq!(home.count("SELECT COUNT(*) FROM event"), 0);
}

#[test]
fn capture_is_silent_when_recording_was_declined() {
    let home = Home::new();
    home.conn()
        .execute(
            "UPDATE meta SET value = 'no' WHERE key = 'consent.record'",
            [],
        )
        .unwrap();
    let out = home.hook("capture", &fixture("PostToolUse-WebFetch-plugin-3.json"));
    assert_silent(&out);
    assert_eq!(home.count("SELECT COUNT(*) FROM event"), 0);
    assert_eq!(home.count("SELECT COUNT(*) FROM hook_run"), 0);
}

#[test]
fn capture_recalibrates_when_the_record_count_has_doubled() {
    let home = Home::new();
    {
        let conn = home.conn();
        for i in 0..60 {
            conn.execute(
                "INSERT INTO event (tool_use_id, tool, session_id, cwd_hash, created_at, query, \
                 status, match_text, source) \
                 VALUES (?1, 'WebSearch', 's', 'h', ?2, ?3, 'ok', ?3, 'hook')",
                rusqlite::params![
                    format!("toolu_seed_{i}"),
                    1_700_000_000_000_i64 + i,
                    format!("seed query number {i} about topic{}", i % 7)
                ],
            )
            .unwrap();
        }
        conn.execute_batch(
            "INSERT INTO meta (key, value) VALUES ('calibrated_n', '25'), ('calibrated_at', '1')",
        )
        .unwrap();
    }
    let out = home.hook("capture", &fixture("PostToolUse-WebSearch-plugin-2.json"));
    assert_silent(&out);
    assert_eq!(home.count("SELECT COUNT(*) FROM event"), 61);
    let at: i64 = home
        .text("SELECT value FROM meta WHERE key = 'calibrated_at'")
        .parse()
        .unwrap();
    assert!(at > 1_000_000_000_000, "{at}");
    assert_eq!(
        home.text("SELECT value FROM meta WHERE key = 'calibrated_n'"),
        "61"
    );
}

#[test]
fn capture_does_not_recalibrate_below_the_doubling_point() {
    let home = Home::new();
    home.conn()
        .execute_batch(
            "INSERT INTO meta (key, value) VALUES ('calibrated_n', '5'), ('calibrated_at', '1')",
        )
        .unwrap();
    home.hook("capture", &fixture("PostToolUse-WebSearch-plugin-2.json"));
    assert_eq!(
        home.text("SELECT value FROM meta WHERE key = 'calibrated_at'"),
        "1"
    );
}

/// Seeds the database that `scripts/hook-latency.sh` measures: 3,000 synthetic records
/// plus near-copies of the PostToolUse fixtures (so that every replay has a match to find),
/// then calibrates. Does nothing unless `AWM_SEED_HOME` is set.
#[test]
#[ignore = "run by scripts/hook-latency.sh"]
fn seed_latency_db() {
    let Some(home) = std::env::var_os("AWM_SEED_HOME") else {
        return;
    };
    let dir = PathBuf::from(home);
    let mut conn = db::open(&dir.join("awm.db"), Role::Cli).unwrap();
    db::migrate(&mut conn).unwrap();
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('consent.record', 'yes') \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [],
    )
    .unwrap();
    let now = now_ms();
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = move |n: u64| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) % n
    };
    let tx = conn.transaction().unwrap();
    for i in 0..3000_i64 {
        let words: Vec<String> = (0..8).map(|_| format!("w{}", next(900))).collect();
        let text = words.join(" ");
        let (tool, query, url, url_norm) = if next(5) == 0 {
            let u = format!("https://docs.example.org/{}", next(600));
            ("WebFetch", None, Some(u.clone()), Some(u))
        } else {
            ("WebSearch", Some(text.clone()), None, None)
        };
        tx.execute(
            "INSERT INTO event (tool_use_id, tool, session_id, cwd_hash, created_at, query, url, \
             url_norm, fetch_prompt, status, summary, match_text, source) \
             VALUES (?1, ?2, ?3, 'h', ?4, ?5, ?6, ?7, ?8, 'ok', ?9, ?9, 'hook')",
            rusqlite::params![
                format!("toolu_synth_{i}"),
                tool,
                format!("sess-synth-{}", i % 40),
                now - (i + 1) * 60_000,
                query,
                url,
                url_norm,
                url.as_ref().map(|_| text.clone()),
                format!(
                    "{text} {}",
                    words.iter().rev().cloned().collect::<Vec<_>>().join(" ")
                )
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let opts = CaptureOpts {
        data_dir: dir.clone(),
        config: Config::default(),
        now_ms: now - DAY_MS,
    };
    for (i, name) in [
        "PostToolUse-WebSearch-plugin-2.json",
        "PostToolUse-WebSearch-settings-6.json",
        "PostToolUse-WebSearch-plugin-8.json",
        "PostToolUse-WebFetch-plugin-3.json",
    ]
    .iter()
    .enumerate()
    {
        let copy = patch(
            fixture(name),
            &[
                ("tool_use_id", json!(format!("toolu_fixture_copy_{i}"))),
                ("session_id", json!("sess-fixture-copy")),
                ("agent_id", Value::Null),
            ],
        );
        capture::run(&copy, &opts).unwrap();
    }
    awm::matching::calibrate::run(&conn).unwrap();
}
