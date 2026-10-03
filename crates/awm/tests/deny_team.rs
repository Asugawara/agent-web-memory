//! Team rows in the hooks (plan-v3-team §3.5, TM13): never a trigger of the URL deny or the
//! query deny, `OwnDevice` rows are, `team.mute` and `team.show`, the `same_repo` lookup, and a
//! shown record deleted remotely (NULL `injection_item.event_id`) does not silence later hooks.
//! Team rows are seeded by capturing a record and rewriting its origin columns.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use awm::capture::{self, CaptureOpts};
use awm::config::{Config, ShortCircuitMode};
use awm::db::{self, Role};
use awm::matching::{self, MatchOpts};
use awm::normalize::norm_url;
use awm::note::Relation;
use rusqlite::{params, Connection};
use serde_json::{json, Value};

mod support;
use support::now_ms;

const MIN_MS: i64 = 60_000;
const HOUR_MS: i64 = 60 * MIN_MS;
const OWN: &str = "11111111-1111-4111-8111-111111111111";
const ALF: &str = "22222222-2222-4222-8222-222222222222";
const QUERY: &str = "SQLite FTS5 bm25 column weights";

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/hooks")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Home {
        let home = Home {
            dir: tempfile::tempdir().unwrap(),
        };
        let mut conn = db::open(&home.db_path(), Role::Cli).unwrap();
        db::migrate(&mut conn).unwrap();
        conn.execute_batch(
            "INSERT INTO meta (key, value) VALUES ('consent.record', 'yes'), \
             ('cutoff.query', '0'), ('cutoff.prompt', '0'); \
             INSERT INTO team_member (member_id, handle, role, updated_at) \
             VALUES ('22222222-2222-4222-8222-222222222222', 'alf', 'member', 0), \
                    ('11111111-1111-4111-8111-111111111111', 'me', 'member', 0);",
        )
        .unwrap();
        home
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

    fn config(&self, edit: impl FnOnce(&mut Config)) {
        let mut c = Config::default();
        edit(&mut c);
        c.save(&self.dir.path().join("config.toml")).unwrap();
    }

    /// `team.toml` and `team.key` for the caller's member id (only `member_id` is read by hooks).
    fn join_team(&self) {
        std::fs::write(
            self.dir.path().join("team.toml"),
            format!("member_id = \"{OWN}\"\nhandle = \"me\"\n"),
        )
        .unwrap();
        std::fs::write(self.dir.path().join("team.key"), "{}").unwrap();
    }

    fn seed(&self, payload: &Value, age_ms: i64) -> i64 {
        let opts = CaptureOpts {
            data_dir: self.path(),
            config: Config::default(),
            now_ms: now_ms() - age_ms,
        };
        let out = capture::run(payload, &opts).unwrap();
        assert_eq!(out, capture::CaptureOutcome::Captured, "{payload}");
        self.conn()
            .query_row("SELECT MAX(id) FROM event", [], |r| r.get(0))
            .unwrap()
    }

    /// Turns a captured record into a pulled team row of `member` (TM5: `session_id = team:{member}`,
    /// no agent).
    fn make_team(&self, id: i64, member: &str, repo_key: Option<&str>) {
        self.conn()
            .execute(
                "UPDATE event SET origin = 'team', member = ?2, repo_key = ?3, \
                 session_id = 'team:' || ?2, agent_id = NULL, agent_type = NULL WHERE id = ?1",
                params![id, member, repo_key],
            )
            .unwrap();
    }

    fn hook(&self, hook: &str, payload: &Value) -> (Option<i32>, String) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_awm"))
            .args(["hook", hook])
            .env("AWM_HOME", self.dir.path())
            .env_remove("AWM_CANARY")
            .env_remove("AWM_CANARY_DENY")
            .env_remove("AWM_DEBUG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes());
        let o = child.wait_with_output().unwrap();
        (o.status.code(), String::from_utf8(o.stdout).unwrap())
    }
}

fn search_record(session: &str, id: &str, query: &str, cwd: &str) -> Value {
    json!({
        "session_id": session, "cwd": cwd, "hook_event_name": "PostToolUse",
        "tool_name": "WebSearch", "tool_use_id": id,
        "tool_input": {"query": query},
        "tool_response": {"query": query, "results": [
            {"tool_use_id": "srv1", "content": [
                {"title": "FTS5 ranking", "url": "https://sqlite.org/fts5.html"}]},
            "The bm25() function takes one weight per column; lower values are better."
        ]}
    })
}

fn pre_search(id: &str) -> Value {
    let mut v = fixture("PreToolUse-WebSearch-main-cc-1.json");
    v["tool_use_id"] = json!(id);
    v
}

fn fetch_record(session: &str, agent: Option<&str>, id: &str, url: &str) -> Value {
    let mut v = fixture("PostToolUse-WebFetch-plugin-3.json");
    v["session_id"] = json!(session);
    v["tool_use_id"] = json!(id);
    v["tool_input"] = json!({"url": url, "prompt": "Summarize the page"});
    if let Some(a) = agent {
        v["agent_id"] = json!(a);
        v["agent_type"] = json!("researcher");
    }
    v
}

fn pre_fetch(id: &str) -> Value {
    let mut v = fixture("PreToolUse-WebFetch-plugin-4.json");
    v["session_id"] = json!("sess-pre");
    v["tool_use_id"] = json!(id);
    v
}

fn query_on(home: &Home) {
    home.config(|c| c.short_circuit.query = ShortCircuitMode::On);
}

fn reason(stdout: &str) -> String {
    let v: Value = serde_json::from_str(stdout).unwrap_or_else(|e| panic!("{e}: {stdout:?}"));
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .to_string()
}

fn deny_rows(home: &Home) -> i64 {
    home.count("SELECT COUNT(*) FROM injection WHERE mode = 'deny'")
}

// ---- the query deny ----

#[test]
fn a_teammates_search_never_triggers_the_query_deny() {
    let home = Home::new();
    home.join_team();
    query_on(&home);
    let id = home.seed(&search_record("s-old", "t1", QUERY, "/work/x"), HOUR_MS);
    home.make_team(id, ALF, None);
    let (code, out) = home.hook("pre-fetch", &pre_search("toolu_1"));
    assert_eq!(code, Some(0));
    assert_eq!(out, "");
    assert_eq!(deny_rows(&home), 0);
}

#[test]
fn a_local_record_of_another_session_does_trigger_the_query_deny() {
    let home = Home::new();
    home.join_team();
    query_on(&home);
    home.seed(&search_record("s-old", "t1", QUERY, "/work/x"), HOUR_MS);
    let (_, out) = home.hook("pre-fetch", &pre_search("toolu_1"));
    assert!(
        reason(&out).contains("earlier research matches this search"),
        "{out}"
    );
}

#[test]
fn a_record_of_the_callers_other_machine_triggers_the_query_deny() {
    let home = Home::new();
    home.join_team();
    query_on(&home);
    let id = home.seed(&search_record("s-old", "t1", QUERY, "/work/x"), HOUR_MS);
    home.make_team(id, OWN, None);
    let (_, out) = home.hook("pre-fetch", &pre_search("toolu_1"));
    let r = reason(&out);
    assert!(r.contains("your other machine"), "{r}");
    assert_eq!(
        home.count("SELECT COUNT(*) FROM injection WHERE mode = 'deny'"),
        1
    );
}

// ---- the URL deny ----

#[test]
fn a_teammates_fetch_never_triggers_the_url_deny() {
    let home = Home::new();
    home.join_team();
    // The row even carries the caller's session and another agent: only `origin` can exclude it.
    let id = home.seed(
        &fetch_record("sess-pre", Some("agent-a"), "t1", "https://example.com"),
        MIN_MS,
    );
    home.conn()
        .execute(
            "UPDATE event SET origin = 'team', member = ?2 WHERE id = ?1",
            params![id, ALF],
        )
        .unwrap();
    let (code, out) = home.hook("pre-fetch", &pre_fetch("toolu_main"));
    assert_eq!(code, Some(0));
    assert_eq!(out, "");
    assert_eq!(deny_rows(&home), 0);
}

#[test]
fn a_local_sibling_fetch_does_trigger_the_url_deny() {
    let home = Home::new();
    home.join_team();
    home.seed(
        &fetch_record("sess-pre", Some("agent-a"), "t1", "https://example.com"),
        MIN_MS,
    );
    let (_, out) = home.hook("pre-fetch", &pre_fetch("toolu_main"));
    assert!(reason(&out).contains("already fetched"), "{out}");
}

#[test]
fn a_fetch_row_of_the_callers_other_machine_triggers_the_url_deny() {
    let home = Home::new();
    home.join_team();
    let id = home.seed(
        &fetch_record("sess-pre", None, "t1", "https://example.com"),
        MIN_MS,
    );
    // As a pulled row: the other machine's session, never the caller's own.
    home.make_team(id, OWN, None);
    let (_, out) = home.hook("pre-fetch", &pre_fetch("toolu_main"));
    let r = reason(&out);
    assert!(r.contains("by your other machine"), "{r}");
}

#[test]
fn a_teammates_pulled_fetch_row_never_denies() {
    let home = Home::new();
    home.join_team();
    let id = home.seed(
        &fetch_record("s-old", None, "t1", "https://example.com"),
        MIN_MS,
    );
    home.make_team(id, ALF, None);
    let (_, out) = home.hook("pre-fetch", &pre_fetch("toolu_main"));
    assert_eq!(out, "");
    assert_eq!(deny_rows(&home), 0);
}

// ---- relation, same_repo, mute and show ----

fn opts(cwd_hash: &str) -> MatchOpts {
    MatchOpts {
        caller_session: "caller".to_string(),
        caller_cwd_hash: cwd_hash.to_string(),
        exclude_same_agent: true,
        limit: 3,
        ..MatchOpts::default()
    }
}

const REPO_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REPO_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn relation_of(home: &Home, id: i64, caller_cwd: &str, own: Option<&str>) -> Relation {
    let conn = home.conn();
    let hit = matching::Hit {
        event_id: id,
        score: 1.0,
        seen: 1,
    };
    matching::to_note_as(&conn, &hit, &opts(caller_cwd), own)
        .unwrap()
        .relation
}

#[test]
fn same_repo_is_looked_up_through_the_project_table() {
    let home = Home::new();
    let id = home.seed(&search_record("s-old", "t1", QUERY, "/work/x"), HOUR_MS);
    home.make_team(id, ALF, Some(REPO_A));
    let conn = home.conn();
    conn.execute(
        "INSERT INTO project (cwd_hash, repo_key, updated_at) VALUES \
         ('cwd-same', ?1, 0), ('cwd-other', ?2, 0), ('cwd-nogit', NULL, 0)",
        params![REPO_A, REPO_B],
    )
    .unwrap();
    let teammate = |same_repo| Relation::Teammate {
        handle: "alf".to_string(),
        same_repo,
    };
    assert_eq!(
        relation_of(&home, id, "cwd-same", Some(OWN)),
        teammate(true)
    );
    assert_eq!(
        relation_of(&home, id, "cwd-other", Some(OWN)),
        teammate(false)
    );
    assert_eq!(
        relation_of(&home, id, "cwd-nogit", Some(OWN)),
        teammate(false)
    );
    assert_eq!(
        relation_of(&home, id, "cwd-unknown", Some(OWN)),
        teammate(false)
    );
}

#[test]
fn a_row_of_the_callers_own_member_id_is_the_other_machine() {
    let home = Home::new();
    let id = home.seed(&search_record("s-old", "t1", QUERY, "/work/x"), HOUR_MS);
    home.make_team(id, OWN, Some(REPO_A));
    assert_eq!(relation_of(&home, id, "c", Some(OWN)), Relation::OwnDevice);
}

#[test]
fn a_local_row_keeps_its_old_relations() {
    let home = Home::new();
    let id = home.seed(&search_record("s-old", "t1", QUERY, "/work/x"), HOUR_MS);
    assert_eq!(
        relation_of(&home, id, "c", Some(OWN)),
        Relation::OtherProject
    );
}

fn post_search(session: &str, id: &str) -> Value {
    let mut v = search_record(session, id, QUERY, "/work/y");
    v["tool_response"] = Value::Null;
    v
}

fn injected_context(stdout: &str) -> Option<String> {
    let v: Value = serde_json::from_str(stdout).ok()?;
    v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .map(str::to_string)
}

#[test]
fn a_teammates_note_is_injected_with_its_relation_and_the_team_preamble() {
    let home = Home::new();
    home.join_team();
    let id = home.seed(&search_record("s-old", "t1", QUERY, "/work/x"), HOUR_MS);
    home.make_team(id, ALF, None);
    let (_, out) = home.hook("post-tool", &post_search("sess-new", "toolu_new"));
    let text = injected_context(&out).unwrap_or_else(|| panic!("no context: {out:?}"));
    assert!(text.contains("teammate @alf, other repository"), "{text}");
    assert!(
        text.contains("Earlier web research by your agents and your teammates' agents."),
        "{text}"
    );
    assert_eq!(
        home.count("SELECT COUNT(*) FROM injection_item WHERE origin = 'team'"),
        1
    );
}

#[test]
fn team_mute_hides_one_handle_and_team_show_false_hides_all() {
    let muted = Home::new();
    muted.join_team();
    muted.config(|c| c.team.mute = vec!["alf".to_string()]);
    let id = muted.seed(&search_record("s-old", "t1", QUERY, "/work/x"), HOUR_MS);
    muted.make_team(id, ALF, None);
    let (_, out) = muted.hook("post-tool", &post_search("sess-new", "toolu_new"));
    assert_eq!(injected_context(&out), None, "{out}");
    assert_eq!(muted.count("SELECT COUNT(*) FROM injection_item"), 0);

    let hidden = Home::new();
    hidden.join_team();
    hidden.config(|c| c.team.show = false);
    let id = hidden.seed(&search_record("s-old", "t1", QUERY, "/work/x"), HOUR_MS);
    hidden.make_team(id, ALF, None);
    let (_, out) = hidden.hook("post-tool", &post_search("sess-new", "toolu_new"));
    assert_eq!(injected_context(&out), None, "{out}");

    // Another handle is not muted, and a record of the caller's other machine is never hidden.
    let other = Home::new();
    other.join_team();
    other.config(|c| {
        c.team.mute = vec!["zed".to_string()];
        c.team.show = true;
    });
    let id = other.seed(&search_record("s-old", "t1", QUERY, "/work/x"), HOUR_MS);
    other.make_team(id, ALF, None);
    let (_, out) = other.hook("post-tool", &post_search("sess-new", "toolu_new"));
    assert!(injected_context(&out).is_some(), "{out}");

    let own = Home::new();
    own.join_team();
    own.config(|c| c.team.show = false);
    let id = own.seed(&search_record("s-old", "t1", QUERY, "/work/x"), HOUR_MS);
    own.make_team(id, OWN, None);
    let (_, out) = own.hook("post-tool", &post_search("sess-new", "toolu_new"));
    let text = injected_context(&out).unwrap_or_else(|| panic!("no context: {out:?}"));
    assert!(text.contains("your other machine"), "{text}");
    assert!(
        text.contains("Earlier web research from this machine"),
        "only a teammate's note swaps the preamble: {text}"
    );
}

// ---- a shown record deleted remotely ----

#[test]
fn a_shown_record_deleted_remotely_does_not_silence_the_next_hooks() {
    let home = Home::new();
    home.join_team();
    // Two earlier records: A (shown first, then deleted by a remote deletion) and B.
    let a = home.seed(
        &fetch_record("s-old", None, "ta", "https://example.com/a"),
        2 * HOUR_MS,
    );
    home.seed(
        &fetch_record("s-old", None, "tb", "https://example.com/b"),
        HOUR_MS,
    );
    let first = home.hook(
        "post-tool",
        &fetch_record("sess-new", None, "toolu_1", "https://example.com/a"),
    );
    assert!(injected_context(&first.1).is_some(), "{:?}", first.1);
    // The deletion stream removes the record: `ON DELETE SET NULL` leaves a NULL item.
    home.conn()
        .execute("DELETE FROM event WHERE id = ?1", [a])
        .unwrap();
    assert_eq!(
        home.count("SELECT COUNT(*) FROM injection_item WHERE event_id IS NULL"),
        1
    );
    let second = home.hook(
        "post-tool",
        &fetch_record("sess-new", None, "toolu_2", "https://example.com/b"),
    );
    let text = injected_context(&second.1).unwrap_or_else(|| panic!("silenced: {:?}", second.1));
    assert!(text.contains("https://example.com/b"), "{text}");
    assert_eq!(
        home.count("SELECT COUNT(*) FROM hook_run WHERE outcome = 'error'"),
        0
    );
    // The URL of the deleted record has no note left to show.
    let norm = norm_url("https://example.com/a").unwrap();
    assert!(matching::url_channel(&home.conn(), &norm, &opts("c"))
        .unwrap()
        .is_empty());
}
