//! Read-side CLI: the built binary against a seeded database and synthetic transcripts.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use awm::db::{self, Role};
use rusqlite::{params, Connection};
use serde_json::{json, Value};

const BASE: i64 = 1_790_000_000_000;

struct Env {
    dir: tempfile::TempDir,
}

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Env {
    fn new() -> Env {
        let env = Env {
            dir: tempfile::tempdir().unwrap(),
        };
        std::fs::create_dir_all(env.home()).unwrap();
        let mut conn = db::open(&env.db_path(), Role::Cli).unwrap();
        db::migrate(&mut conn).unwrap();
        env
    }

    fn awm_home(&self) -> PathBuf {
        self.dir.path().join("awm")
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn db_path(&self) -> PathBuf {
        self.awm_home().join("awm.db")
    }

    fn conn(&self) -> Connection {
        db::open(&self.db_path(), Role::Cli).unwrap()
    }

    fn awm(&self, args: &[&str]) -> Out {
        self.awm_in(args, "")
    }

    fn awm_in(&self, args: &[&str], stdin: &str) -> Out {
        let mut child = Command::new(env!("CARGO_BIN_EXE_awm"))
            .args(args)
            .env("AWM_HOME", self.awm_home())
            .env("HOME", self.home())
            .env_remove("CODEX_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let o = child.wait_with_output().unwrap();
        Out {
            code: o.status.code(),
            stdout: String::from_utf8(o.stdout).unwrap(),
            stderr: String::from_utf8(o.stderr).unwrap(),
        }
    }
}

impl Out {
    fn ok(&self) -> &str {
        assert_eq!(self.code, Some(0), "stderr: {}", self.stderr);
        &self.stdout
    }
}

fn golden(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cli")
        .join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {name}"));
    assert_eq!(actual, want, "golden {name} differs");
}

struct Ev<'a> {
    id: i64,
    tool: &'a str,
    session: &'a str,
    agent: Option<&'a str>,
    at: i64,
    query: Option<&'a str>,
    url: Option<&'a str>,
    status: &'a str,
    source: &'a str,
}

fn ev<'a>(id: i64, tool: &'a str, session: &'a str, at: i64) -> Ev<'a> {
    Ev {
        id,
        tool,
        session,
        agent: None,
        at,
        query: None,
        url: None,
        status: "ok",
        source: "hook",
    }
}

fn insert(conn: &Connection, e: &Ev) {
    let norm = e.url.map(str::to_string);
    let text = e.query.or(e.url).unwrap_or("");
    conn.execute(
        "INSERT INTO event (id, tool_use_id, tool, session_id, agent_id, agent_type, cwd_hash, \
                            created_at, query, url, url_norm, fetch_prompt, http_code, status, \
                            summary, match_text, source) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'c1', ?7, ?8, ?9, ?10, ?11, 200, ?12, ?13, ?14, ?15)",
        params![
            e.id,
            format!("tu{}", e.id),
            e.tool,
            e.session,
            e.agent,
            e.agent.map(|_| "Explore"),
            e.at,
            e.query,
            e.url,
            norm,
            e.url.map(|_| "how are column weights passed"),
            e.status,
            "Weights are passed as extra arguments to bm25.",
            text,
            e.source
        ],
    )
    .unwrap();
}

fn injection(
    conn: &Connection,
    id: i64,
    mode: &str,
    channel: &str,
    session: &str,
    at: i64,
    items: &[(i64, f64)],
) {
    conn.execute(
        "INSERT INTO injection (id, ref, created_at, hook, channel, mode, session_id, tool_use_id, \
                                rendered_chars, latency_ms) \
         VALUES (?1, ?2, ?3, 'PostToolUse', ?4, ?5, ?6, ?7, 300, 10)",
        params![id, format!("{id:08x}"), at, channel, mode, session, format!("inj{id}")],
    )
    .unwrap();
    for (i, (event, score)) in items.iter().enumerate() {
        conn.execute(
            "INSERT INTO injection_item (injection_id, position, event_id, score) VALUES (?1, ?2, ?3, ?4)",
            params![id, i64::try_from(i + 1).unwrap(), event, score],
        )
        .unwrap();
    }
}

fn label(conn: &Connection, injection: i64, position: i64, label: &str) {
    conn.execute(
        "INSERT INTO outcome (injection_id, position, label, labelled_at) VALUES (?1, ?2, ?3, ?4)",
        params![injection, position, label, BASE],
    )
    .unwrap();
}

fn hook_run(conn: &Connection, hook: &str, total: i64, search: Option<i64>, outcome: &str) {
    conn.execute(
        "INSERT INTO hook_run (started_at, hook, session_id, agent_kind, total_ms, search_ms, outcome) \
         VALUES (?1, ?2, 's1', 'main', ?3, ?4, ?5)",
        params![BASE, hook, total, search, outcome],
    )
    .unwrap();
}

/// Four records, two injections, one label.
fn seed_basic(env: &Env) {
    let conn = env.conn();
    let mut e1 = ev(1, "WebSearch", "s1", BASE + 1_000);
    e1.query = Some("sqlite fts5 bm25 column weights");
    insert(&conn, &e1);
    conn.execute(
        "INSERT INTO result (event_id, rank, url, url_norm, title) \
         VALUES (1, 1, 'https://sqlite.org/fts5.html', 'https://sqlite.org/fts5.html', 'FTS5')",
        [],
    )
    .unwrap();
    let mut e2 = ev(2, "WebFetch", "s1", BASE + 2_000);
    e2.url = Some("https://sqlite.org/fts5.html");
    insert(&conn, &e2);
    let mut e3 = ev(3, "WebFetch", "s1", BASE + 3_000);
    e3.url = Some("https://docs.rs/rusqlite/latest/");
    e3.agent = Some("a1");
    e3.status = "dead_end";
    insert(&conn, &e3);
    let mut e4 = ev(4, "WebSearch", "s2", BASE + 4_000);
    e4.query = Some("rust clap derive subcommand example");
    e4.source = "import";
    insert(&conn, &e4);
    injection(&conn, 1, "inject", "url", "s2", BASE + 5_000, &[(2, 1.0)]);
    injection(
        &conn,
        2,
        "shadow",
        "query",
        "s2",
        BASE + 6_000,
        &[(1, 55.0)],
    );
    label(&conn, 1, 1, "2");
    conn.execute(
        "INSERT INTO import_source (path, head_sha256, file_size, file_mtime, events_found, events_inserted, status, imported_at) \
         VALUES ('/p/a.jsonl', 'h', 10, 1, 5, 4, 'ok', 1), ('/p/b.jsonl', 'h', 10, 1, 2, 0, 'partial', 1)",
        [],
    )
    .unwrap();
    hook_run(&conn, "post-tool", 10, Some(3), "injected");
    hook_run(&conn, "post-tool", 20, Some(5), "no_match");
    hook_run(&conn, "post-tool", 90, None, "deadline");
    hook_run(&conn, "capture", 30, None, "captured");
}

#[test]
fn log_lists_recent_events_newest_first() {
    let env = Env::new();
    seed_basic(&env);
    let out = env.awm(&["log"]);
    golden("log.txt", out.ok());
    let json = env.awm(&["log", "--json", "--limit", "2"]);
    let lines: Vec<Value> = json
        .ok()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["target"], "rust clap derive subcommand example");
}

#[test]
fn log_ref_shows_the_stored_injection() {
    let env = Env::new();
    seed_basic(&env);
    env.conn()
        .execute(
            "UPDATE injection SET rendered = 'the block' WHERE id = 1",
            [],
        )
        .unwrap();
    assert!(env
        .awm(&["log", "--ref", "00000001"])
        .ok()
        .contains("the block"));
    assert_ne!(env.awm(&["log", "--ref", "ffffffff"]).code, Some(0));
}

#[test]
fn search_finds_by_query_and_by_url() {
    let env = Env::new();
    seed_basic(&env);
    let by_url = env.awm(&["search", "--url", "https://sqlite.org/fts5.html", "--json"]);
    golden("search-url.json", by_url.ok());
    let by_query = env.awm(&["search", "sqlite fts5 bm25 column weights"]);
    // Default cutoff 42 is above a three-document score; a text search may print nothing.
    assert!(by_query.ok().contains("No matching notes.") || by_query.stdout.contains("<awm-notes"));
    let rendered = env.awm(&["search", "--url", "https://sqlite.org/fts5.html"]);
    assert!(rendered.ok().contains("<awm-notes"));
    assert!(rendered.stdout.contains("https://sqlite.org/fts5.html"));
    assert_ne!(env.awm(&["search", "--url", "not a url"]).code, Some(0));
}

#[test]
fn stats_default_golden() {
    let env = Env::new();
    seed_basic(&env);
    golden("stats.txt", env.awm(&["stats"]).ok());
    let v: Value = serde_json::from_str(env.awm(&["stats", "--json"]).ok()).unwrap();
    assert_eq!(v["injections"]["shown"], 1);
    // A row of an older version (mode shadow) is not counted and nothing reports it.
    assert!(v["injections"].get("would_have_shown").is_none());
    assert!(v["injections"].get("would_have_shown_by_channel").is_none());
    assert_eq!(v["injections"]["changed_next_step"], 1);
}

#[test]
fn stats_sections_golden() {
    let env = Env::new();
    seed_basic(&env);
    golden("stats-status.txt", env.awm(&["stats", "--status"]).ok());
    golden("stats-latency.txt", env.awm(&["stats", "--latency"]).ok());
    golden("stats-import.txt", env.awm(&["stats", "--import"]).ok());
}

#[test]
fn stats_value_matches_the_hand_computed_rate() {
    let env = Env::new();
    let conn = env.conn();
    // 10 hook-captured events.
    for i in 1..=10 {
        let mut e = ev(i, "WebFetch", "s1", BASE + i * 1_000);
        let url = format!("https://example.org/{i}");
        e.url = Some(&url);
        insert(&conn, &e);
    }
    // url channel: 2 items shown, both labelled, one is 2 -> 1/2 * 2 = 1.0
    injection(
        &conn,
        1,
        "inject",
        "url",
        "s2",
        BASE + 20_000,
        &[(1, 1.0), (2, 1.0)],
    );
    label(&conn, 1, 1, "2");
    label(&conn, 1, 2, "1");
    // query channel: 3 items shown, 2 labelled, one is 2 -> 1/2 * 3 = 1.5
    injection(
        &conn,
        2,
        "inject",
        "query",
        "s2",
        BASE + 21_000,
        &[(3, 50.0), (4, 50.0), (5, 50.0)],
    );
    label(&conn, 2, 1, "2");
    label(&conn, 2, 2, "0");
    // one deny labelled 2 -> +1
    injection(&conn, 3, "deny", "url", "s2", BASE + 22_000, &[(6, 1.0)]);
    label(&conn, 3, 1, "2");
    // (1.0 + 1.5 + 1) / 10 * 100 = 35.0; label-2 items 3 of 6 shown = 50.0%
    let v: Value = serde_json::from_str(env.awm(&["stats", "--value", "--json"]).ok()).unwrap();
    assert_eq!(v["value"]["per_100_captured"], "35.0");
    assert_eq!(v["value"]["label2_over_shown"], "50.0%");
    assert_eq!(v["value"]["labelled_2"], 3);
    assert_eq!(v["value"]["shown_items"], 6);
}

#[test]
fn stats_followups_counts_a_later_call_to_the_same_url() {
    let env = Env::new();
    let conn = env.conn();
    let mut e1 = ev(1, "WebFetch", "s1", BASE);
    e1.url = Some("https://example.org/a");
    insert(&conn, &e1);
    // Injection in s2 shows event 1; s2 then fetches the same URL 60 s later, and once more 10 min later.
    injection(&conn, 1, "inject", "url", "s2", BASE + 10_000, &[(1, 1.0)]);
    let mut e2 = ev(2, "WebFetch", "s2", BASE + 70_000);
    e2.url = Some("https://example.org/a");
    insert(&conn, &e2);
    injection(&conn, 2, "inject", "url", "s3", BASE + 10_000, &[(1, 1.0)]);
    let mut e3 = ev(3, "WebFetch", "s3", BASE + 700_000);
    e3.url = Some("https://example.org/a");
    insert(&conn, &e3);
    // The session of the earlier fetch itself fetches the URL again two hours later.
    injection(&conn, 3, "inject", "url", "s1", BASE + 20_000, &[(1, 1.0)]);
    let mut e4 = ev(4, "WebFetch", "s1", BASE + 2 * HOUR);
    e4.url = Some("https://example.org/a");
    insert(&conn, &e4);
    let v: Value = serde_json::from_str(env.awm(&["stats", "--followups", "--json"]).ok()).unwrap();
    let shown = &v["followups"]["shown"];
    assert_eq!(shown["injections"], 3);
    assert_eq!(shown["followed_in_session"], 3);
    assert_eq!(shown["followed_within_2_min"], 1);
    assert_eq!(
        shown["by_age"],
        json!({"within_2_min": 1, "within_30_min": 1, "within_24_h": 1, "later": 0})
    );
    assert_eq!(
        shown["by_who"],
        json!({"same_agent": 1, "sibling": 0, "other_session": 2})
    );
    assert!(v["followups"].get("would_have_shown").is_none());
}

/// Transcript with one injected call and what the agent did afterwards.
fn write_transcript(dir: &Path) -> (PathBuf, i64) {
    let path = dir.join("sess.jsonl");
    let lines = [
        json!({"type":"assistant","sessionId":"s2","timestamp":"2026-09-20T10:00:00.000Z",
               "message":{"role":"assistant","content":[{"type":"tool_use","id":"inj3","name":"WebSearch","input":{"query":"x"}}]}}),
        json!({"type":"user","sessionId":"s2","timestamp":"2026-09-20T10:00:03.000Z",
               "message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"inj3","content":"ok"}]}}),
        json!({"type":"assistant","sessionId":"s2","timestamp":"2026-09-20T10:00:10.000Z",
               "message":{"role":"assistant","content":[
                   {"type":"text","text":"I will use the earlier note about column weights."},
                   {"type":"tool_use","id":"n1","name":"WebFetch","input":{"url":"https://sqlite.org/other","prompt":"p"}}]}}),
        json!({"type":"assistant","sessionId":"s2","timestamp":"2026-09-20T10:00:20.000Z",
               "message":{"role":"assistant","content":[{"type":"tool_use","id":"n2","name":"WebSearch","input":{"query":"follow up query"}}]}}),
        json!({"type":"assistant","sessionId":"s2","timestamp":"2026-09-20T10:20:00.000Z",
               "message":{"role":"assistant","content":[{"type":"tool_use","id":"n3","name":"WebSearch","input":{"query":"much later query"}}]}}),
    ];
    let text: Vec<String> = lines.iter().map(Value::to_string).collect();
    std::fs::write(&path, text.join("\n") + "\n").unwrap();
    let at = time::OffsetDateTime::parse(
        "2026-09-20T10:00:03.000Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp()
        * 1000;
    (path, at)
}

#[test]
fn review_labels_items_from_scripted_input_and_shows_the_next_steps() {
    let env = Env::new();
    seed_basic(&env);
    let conn = env.conn();
    let (transcript, _) = write_transcript(env.dir.path());
    // Newest first: injection 3 (1 item), 2 (2 items), 1 (2 items).
    injection(
        &conn,
        3,
        "shadow",
        "query",
        "s2",
        BASE + 9_000,
        &[(1, 55.0)],
    );
    conn.execute(
        "UPDATE injection SET transcript_path = ?1 WHERE id = 3",
        [transcript.to_str().unwrap()],
    )
    .unwrap();
    injection(
        &conn,
        10,
        "inject",
        "url",
        "s9",
        BASE + 8_000,
        &[(2, 1.0), (1, 1.0)],
    );
    injection(
        &conn,
        11,
        "inject",
        "url",
        "s9",
        BASE + 7_000,
        &[(2, 1.0), (1, 1.0)],
    );
    let out = env.awm_in(&["review"], "2\n1\nh\nq\n");
    let text = out.ok().to_string();
    assert!(
        text.contains("next reply: I will use the earlier note about column weights."),
        "{text}"
    );
    assert!(text.contains("WebFetch https://sqlite.org/other"), "{text}");
    assert!(text.contains("WebSearch follow up query"), "{text}");
    assert!(!text.contains("much later query"), "{text}");
    assert!(text.contains("Labelled 3 of"), "{text}");
    let mut st = conn
        .prepare("SELECT injection_id, position, label FROM outcome WHERE injection_id != 1 ORDER BY injection_id, position")
        .unwrap();
    let rows: Vec<(i64, i64, String)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        rows,
        vec![
            (3, 1, "2".to_string()),
            (10, 1, "1".to_string()),
            (10, 2, "h".to_string())
        ]
    );
}

#[test]
fn review_accepts_several_keys_on_one_line_and_stops_at_end_of_input() {
    let env = Env::new();
    seed_basic(&env);
    let conn = env.conn();
    injection(
        &conn,
        3,
        "inject",
        "url",
        "s9",
        BASE + 9_000,
        &[(2, 1.0), (1, 1.0)],
    );
    let out = env.awm_in(&["review"], "21\n");
    out.ok();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM outcome", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 3); // the seeded label plus two
    let again = env.awm_in(&["review", "--limit", "1"], "");
    assert!(again.ok().contains("item 1/1"));
}

#[test]
fn report_contains_counts_only() {
    let env = Env::new();
    seed_basic(&env);
    let projects = env.dir.path().join("projects");
    std::fs::create_dir_all(&projects).unwrap();
    let out = env.awm(&["report", "--projects", projects.to_str().unwrap()]);
    let text = out.ok();
    assert!(text.contains("records: 4"), "{text}");
    let leak = regex::Regex::new(
        r"https?://|(^|[\s=])/[A-Za-z]|\\|sqlite|fts5|bm25|clap|rusqlite|docs\.rs|s1|s2|tu\d",
    )
    .unwrap();
    assert!(!leak.is_match(text), "report leaks text: {text}");
    assert!(!text.contains(env.dir.path().to_str().unwrap()));
}

/// Transcript with ten web tool uses in session `s1`.
fn write_ten_calls(dir: &Path) {
    let proj = dir.join("projects/-work-demo");
    std::fs::create_dir_all(&proj).unwrap();
    let mut lines = Vec::new();
    for i in 1..=10 {
        lines.push(
            json!({"type":"assistant","sessionId":"s1","timestamp":"2026-09-20T10:00:00.000Z",
               "message":{"role":"assistant","content":[{"type":"tool_use","id":format!("tu{i}"),"name":"WebSearch","input":{"query":format!("q{i}")}}]}})
            .to_string(),
        );
    }
    std::fs::write(proj.join("s1.jsonl"), lines.join("\n") + "\n").unwrap();
}

#[test]
fn doctor_coverage_prints_ninety_percent_for_nine_of_ten() {
    let env = Env::new();
    let conn = env.conn();
    for i in 1..=9 {
        let mut e = ev(i, "WebSearch", "s1", BASE + i * 1_000);
        let q = format!("q{i}");
        e.query = Some(&q);
        insert(&conn, &e);
    }
    write_ten_calls(env.dir.path());
    let projects = env.dir.path().join("projects");
    let out = env.awm(&[
        "doctor",
        "--coverage",
        "--projects",
        projects.to_str().unwrap(),
    ]);
    let text = out.ok();
    assert!(text.contains("capture coverage: 90.0% (9 of 10"), "{text}");
    assert!(text.contains("quick_check passed"), "{text}");
    assert!(text.contains("SQLite has FTS5"), "{text}");
}

#[test]
fn doctor_delivery_and_prompt_tags_read_the_transcripts() {
    let env = Env::new();
    seed_basic(&env);
    let proj = env.dir.path().join("projects/-work-demo");
    std::fs::create_dir_all(&proj).unwrap();
    let transcript = proj.join("s2.jsonl");
    let line = json!({"type":"attachment","attachment":{"type":"hook_additional_context",
        "content":["<awm-notes ref=\"00000001\" kind=\"reference-data\">"]}})
    .to_string();
    std::fs::write(&transcript, format!("{line}\n")).unwrap();
    env.conn()
        .execute(
            "UPDATE injection SET transcript_path = ?1 WHERE id = 1",
            [transcript.to_str().unwrap()],
        )
        .unwrap();
    let projects = env.dir.path().join("projects");
    let out = env.awm(&[
        "doctor",
        "--delivery",
        "--prompt-tags",
        "--projects",
        projects.to_str().unwrap(),
    ]);
    let text = out.ok();
    assert!(text.contains("delivery: 100.0% (1 of 1"), "{text}");
    assert!(text.contains("prompt tags: 1 occurrences"), "{text}");
}

#[test]
fn doctor_reports_a_missing_database() {
    let env = Env::new();
    std::fs::remove_file(env.db_path()).unwrap();
    let out = env.awm(&["doctor"]);
    assert_ne!(out.code, Some(0));
    assert!(out.stdout.contains("Run: awm init"));
}

#[test]
fn export_has_a_header_and_one_line_per_record() {
    let env = Env::new();
    seed_basic(&env);
    let out = env.awm(&["export"]);
    let lines: Vec<&str> = out.ok().lines().collect();
    assert_eq!(lines.len(), 4 + 1);
    let header: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(header["format"], "awm-export/0");
    let first: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(first["results"].as_array().unwrap().len(), 1);
    let file = env.dir.path().join("out.jsonl");
    env.awm(&["export", "--out", file.to_str().unwrap()]).ok();
    assert_eq!(std::fs::read_to_string(&file).unwrap().lines().count(), 5);
}

#[test]
fn codex_rows_are_tagged_in_log_stats_and_export() {
    let env = Env::new();
    seed_basic(&env);
    env.conn()
        .execute("UPDATE event SET agent = 'codex' WHERE id = 4", [])
        .unwrap();
    let log = env.awm(&["log"]).ok().to_string();
    let lines: Vec<&str> = log.lines().collect();
    assert!(
        lines[0].ends_with("  [codex] rust clap derive subcommand example"),
        "{log}"
    );
    assert!(lines[1..].iter().all(|l| !l.contains('[')), "{log}");
    let json: Value =
        serde_json::from_str(env.awm(&["log", "--json", "--limit", "1"]).ok().trim()).unwrap();
    assert_eq!(json["coding_agent"], "codex");
    assert_eq!(json["agent"], "main");

    assert!(env
        .awm(&["stats"])
        .ok()
        .starts_with("by agent: claude 3, codex 1\n"));
    let v: Value = serde_json::from_str(env.awm(&["stats", "--json"]).ok()).unwrap();
    assert_eq!(v["by_agent"], json!({"claude": 3, "codex": 1}));

    let export = env.awm(&["export"]).ok().to_string();
    let agents: Vec<String> = export
        .lines()
        .skip(1)
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["agent"].to_string())
        .collect();
    assert_eq!(
        agents,
        ["\"claude\"", "\"claude\"", "\"claude\"", "\"codex\""]
    );
}

#[test]
fn doctor_upgrades_a_v1_database_and_other_commands_wait_for_it() {
    let env = Env::new();
    std::fs::remove_file(env.db_path()).unwrap();
    {
        let mut conn = db::open(&env.db_path(), Role::Cli).unwrap();
        db::migrate_with(&mut conn, &db::MIGRATIONS[..1]).unwrap();
        conn.execute(
            "INSERT INTO event (tool_use_id, tool, session_id, cwd_hash, created_at, query, \
             status, match_text, source) VALUES ('tu1', 'WebSearch', 's1', 'h', 1, 'q', 'ok', \
             'q', 'hook')",
            [],
        )
        .unwrap();
    }
    let log = env.awm(&["log"]);
    assert_ne!(log.code, Some(0));
    assert!(
        log.stderr
            .contains("database needs an upgrade. Run: awm doctor"),
        "{}",
        log.stderr
    );

    let doctor = env.awm(&["doctor"]);
    let bak = env.awm_home().join("awm.db.bak-v1");
    assert!(bak.is_file());
    assert!(
        doctor
            .stdout
            .contains("database upgraded from schema version 1 to 4 (backup: ")
            && doctor.stdout.contains("/awm.db.bak-v1)"),
        "{}",
        doctor.stdout
    );
    let again = env.awm(&["doctor"]);
    assert!(
        again
            .stdout
            .contains("database schema version 4 is current"),
        "{}",
        again.stdout
    );
    let json: Value = serde_json::from_str(env.awm(&["log", "--json"]).ok().trim()).unwrap();
    assert_eq!(json["coding_agent"], "claude");
}

#[test]
fn reindex_rebuilds_the_search_index() {
    let env = Env::new();
    seed_basic(&env);
    assert!(env.awm(&["reindex"]).ok().contains("4 records"));
    assert!(env.awm(&["doctor"]).ok().contains("search index matches"));
}

#[test]
fn config_get_and_set_validate_the_keys() {
    let env = Env::new();
    assert_eq!(env.awm(&["config", "get", "mode"]).ok(), "inject\n");
    assert!(env
        .awm(&["config", "set", "mode", "off"])
        .ok()
        .contains("mode = off"));
    assert_eq!(env.awm(&["config", "get", "mode"]).ok(), "off\n");
    // Shadow mode and the keys of the per-agent cap and the subagent switch are gone.
    let refused = env.awm(&["config", "set", "mode", "shadow"]);
    assert_ne!(refused.code, Some(0));
    assert!(
        refused.stderr.contains("use inject or off"),
        "{}",
        refused.stderr
    );
    let refused = env.awm(&["config", "set", "short_circuit.subagents", "true"]);
    assert_ne!(refused.code, Some(0));
    assert!(refused.stderr.contains("was removed"), "{}", refused.stderr);
    assert_ne!(
        env.awm(&["config", "set", "inject.max_per_agent", "3"])
            .code,
        Some(0)
    );
    assert!(!env.awm(&["config", "list"]).ok().contains("max_per_agent"));
    assert!(!env.awm(&["config", "list"]).ok().contains("subagents"));
    assert_ne!(env.awm(&["config", "set", "mode", "loud"]).code, Some(0));
    assert_ne!(
        env.awm(&["config", "set", "inject.max_notes", "9"]).code,
        Some(0)
    );
    assert_ne!(env.awm(&["config", "get", "nope"]).code, Some(0));
    assert_eq!(env.awm(&["config", "get", "inject.max_notes"]).ok(), "3\n");
    assert!(env
        .awm(&["config", "set", "channels.prompt_bm25", "inject"])
        .ok()
        .contains("200 characters"));
}

#[test]
fn doctor_names_each_legacy_config_value_and_removed_key() {
    let env = Env::new();
    std::fs::write(
        env.awm_home().join("config.toml"),
        "mode = \"shadow\"\n[short_circuit]\nsubagents = true\n[inject]\nmax_per_agent = 5\n",
    )
    .unwrap();
    let out = env.awm(&["doctor"]);
    let text = format!("{}{}", out.stdout, out.stderr);
    assert!(
        text.contains("config: mode = \"shadow\" is read as \"inject\"; set it to inject or off"),
        "{text}"
    );
    assert!(
        text.contains("config: short_circuit.subagents was removed"),
        "{text}"
    );
    assert!(
        text.contains("config: inject.max_per_agent was removed"),
        "{text}"
    );
    // The hooks and `config list` keep working with the old file.
    assert_eq!(env.awm(&["config", "get", "mode"]).ok(), "inject\n");
}

#[test]
fn where_prints_the_locations() {
    let env = Env::new();
    let text = env.awm(&["where"]).ok().to_string();
    assert!(text.contains(env.awm_home().to_str().unwrap()));
    assert!(text.contains("awm.db"));
    assert!(text.contains("config.toml"));
}

#[test]
fn setup_refuses_without_yes_when_there_is_no_terminal_and_round_trips() {
    let env = Env::new();
    let settings = env.home().join(".claude/settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let original = json!({
        "theme": "dark",
        "hooks": {"PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}]}
    });
    std::fs::write(&settings, serde_json::to_string_pretty(&original).unwrap()).unwrap();
    let before = std::fs::read_to_string(&settings).unwrap();

    let refused = env.awm(&["setup", "--hooks-in-settings"]);
    assert_ne!(refused.code, Some(0));
    assert!(refused.stderr.contains("--yes"), "{}", refused.stderr);
    assert_eq!(std::fs::read_to_string(&settings).unwrap(), before);

    env.awm(&["setup", "--hooks-in-settings", "--yes"]).ok();
    let added: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(added["theme"], "dark");
    assert_eq!(
        added["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"],
        "awm hook prompt"
    );
    assert_eq!(added["hooks"]["PostToolUse"].as_array().unwrap().len(), 2);
    assert!(settings.with_extension("json.awm-backup").is_file());
    // Idempotent.
    assert!(env
        .awm(&["setup", "--hooks-in-settings", "--yes"])
        .ok()
        .contains("nothing to add"));

    assert_ne!(env.awm(&["setup", "--remove-hooks"]).code, Some(0));
    env.awm(&["setup", "--remove-hooks", "--yes"]).ok();
    let restored: Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(restored, original);
}

#[test]
fn setup_replaces_an_old_webfetch_pre_tool_use_group() {
    let env = Env::new();
    let settings = env.home().join(".claude/settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    let old = json!({"hooks": {"PreToolUse": [
        {"matcher": "WebFetch", "hooks": [
            {"type": "command", "command": "awm hook pre-fetch", "timeout": 5},
            {"type": "command", "command": "echo mine"}]},
        {"matcher": "WebFetch", "hooks": [{"type": "command", "command": "awm hook pre-fetch"}]},
    ]}});
    std::fs::write(&settings, serde_json::to_string_pretty(&old).unwrap()).unwrap();
    env.awm(&["setup", "--hooks-in-settings", "--yes"]).ok();
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
    let pre_fetch: Vec<&Value> = groups
        .iter()
        .flat_map(|g| g["hooks"].as_array().unwrap())
        .filter(|h| h["command"] == "awm hook pre-fetch")
        .collect();
    assert_eq!(pre_fetch.len(), 1, "{v}");
    let ours = groups
        .iter()
        .find(|g| g["hooks"][0]["command"] == "awm hook pre-fetch")
        .unwrap();
    assert_eq!(ours["matcher"], "WebFetch|WebSearch");
    // The user's own hook stays under its group.
    assert!(groups
        .iter()
        .any(|g| g["matcher"] == "WebFetch" && g["hooks"][0]["command"] == "echo mine"));
}

#[test]
fn setup_creates_the_settings_file_and_removes_the_empty_hooks_key() {
    let env = Env::new();
    let settings = env.home().join(".claude/settings.json");
    env.awm(&["setup", "--hooks-in-settings", "--yes"]).ok();
    assert!(settings.is_file());
    env.awm(&["setup", "--remove-hooks", "--yes"]).ok();
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(v, json!({}));
}

#[test]
fn setup_leaves_an_invalid_settings_file_alone() {
    let env = Env::new();
    let settings = env.home().join(".claude/settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(&settings, "{ not json").unwrap();
    assert_ne!(
        env.awm(&["setup", "--hooks-in-settings", "--yes"]).code,
        Some(0)
    );
    assert_eq!(std::fs::read_to_string(&settings).unwrap(), "{ not json");
}

fn codex_hooks_file(env: &Env) -> PathBuf {
    env.home().join(".codex/hooks.json")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn foreign_session_start() -> Value {
    json!({"hooks": {"SessionStart": [{"hooks": [
        {"command": "bash '/x/herdr.sh' session", "timeout": 10, "type": "command"}
    ]}]}})
}

#[test]
fn codex_setup_refuses_without_yes_and_leaves_the_file_alone() {
    let env = Env::new();
    let file = codex_hooks_file(&env);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, "{\"hooks\":{}}  \n").unwrap();
    let out = env.awm(&["setup", "--codex-hooks"]);
    assert_eq!(out.code, Some(2), "{}", out.stderr);
    assert!(out.stderr.contains("--yes"), "{}", out.stderr);
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "{\"hooks\":{}}  \n"
    );
    assert!(!file.with_extension("json.awm-backup").exists());
}

#[test]
fn codex_setup_creates_the_file_with_the_absolute_binary_path() {
    let env = Env::new();
    let file = codex_hooks_file(&env);
    let text = env
        .awm(&["setup", "--codex-hooks", "--yes"])
        .ok()
        .to_string();
    assert!(text.contains("/hooks"), "{text}");
    let v = read_json(&file);
    let exe = env!("CARGO_BIN_EXE_awm");
    let cmd = |name: &str| format!("{exe} hook {name}");
    assert_eq!(
        v["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"],
        cmd("prompt")
    );
    assert_eq!(
        v["hooks"]["SessionStart"][0]["hooks"][0]["command"],
        cmd("session-start")
    );
    assert_eq!(v["hooks"]["PreToolUse"][0]["matcher"], "webrun");
    assert_eq!(
        v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        cmd("pre-fetch")
    );
    let post = &v["hooks"]["PostToolUse"][0];
    assert_eq!(post["matcher"], "webrun");
    assert_eq!(post["hooks"][0]["command"], cmd("post-tool"));
    assert_eq!(post["hooks"][0]["timeout"], 5);
    assert_eq!(post["hooks"][1]["command"], cmd("capture"));
    assert_eq!(post["hooks"][1]["timeout"], 30);
    assert!(post["hooks"][1].get("async").is_none());
}

#[test]
fn codex_setup_keeps_a_foreign_session_start_hook_and_is_idempotent() {
    let env = Env::new();
    let file = codex_hooks_file(&env);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(
        &file,
        serde_json::to_string_pretty(&foreign_session_start()).unwrap(),
    )
    .unwrap();
    env.awm(&["setup", "--codex-hooks", "--yes"]).ok();
    let v = read_json(&file);
    let groups = v["hooks"]["SessionStart"].as_array().unwrap();
    assert_eq!(groups.len(), 2);
    assert_eq!(
        groups[0]["hooks"][0]["command"],
        "bash '/x/herdr.sh' session"
    );
    assert!(groups[1]["hooks"][0]["command"]
        .as_str()
        .unwrap()
        .ends_with(" hook session-start"));
    assert!(file.with_extension("json.awm-backup").is_file());
    assert!(env
        .awm(&["setup", "--codex-hooks", "--yes"])
        .ok()
        .contains("nothing to add"));
    assert_eq!(read_json(&file), v);
}

#[test]
fn codex_setup_remove_restores_the_foreign_only_file() {
    let env = Env::new();
    let file = codex_hooks_file(&env);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(
        &file,
        serde_json::to_string_pretty(&foreign_session_start()).unwrap(),
    )
    .unwrap();
    env.awm(&["setup", "--codex-hooks", "--yes"]).ok();
    assert_eq!(env.awm(&["setup", "--remove-codex-hooks"]).code, Some(2));
    env.awm(&["setup", "--remove-codex-hooks", "--yes"]).ok();
    assert_eq!(read_json(&file), foreign_session_start());
    // Nothing but awm entries: the empty hooks key goes too.
    let env = Env::new();
    env.awm(&["setup", "--codex-hooks", "--yes"]).ok();
    env.awm(&["setup", "--remove-codex-hooks", "--yes"]).ok();
    assert_eq!(read_json(&codex_hooks_file(&env)), json!({}));
}

#[test]
fn codex_setup_leaves_an_invalid_file_alone() {
    let env = Env::new();
    let file = codex_hooks_file(&env);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, "{ not json").unwrap();
    for args in [
        ["setup", "--codex-hooks", "--yes"],
        ["setup", "--remove-codex-hooks", "--yes"],
    ] {
        let out = env.awm(&args);
        assert_ne!(out.code, Some(0));
        assert!(out.stderr.contains("not valid JSON"), "{}", out.stderr);
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "{ not json");
}

#[test]
fn commands_need_an_initialised_database() {
    let env = Env::new();
    std::fs::remove_file(env.db_path()).unwrap();
    for cmd in ["log", "stats", "export", "reindex", "report"] {
        let out = env.awm(&[cmd]);
        assert_ne!(out.code, Some(0), "{cmd}");
        assert!(out.stderr.contains("awm init"), "{cmd}: {}", out.stderr);
    }
}

/// Three past fetches of A (4, 8, 20 s; 400, 800, 1200 chars; 4000, 8000, 20000 bytes), two
/// injections showing A, and a fourth ok fetch of A with no `bytes`.
fn seed_savings(env: &Env) -> Connection {
    let conn = env.conn();
    for (id, ms, chars, bytes) in [
        (1, 4_000, 400, 4_000),
        (2, 8_000, 800, 8_000),
        (3, 20_000, 1_200, 20_000),
    ] {
        let mut e = ev(id, "WebFetch", "s0", BASE + id * 1_000);
        e.url = Some("https://example.org/a");
        insert(&conn, &e);
        conn.execute(
            "UPDATE event SET duration_ms = ?1, summary = ?2, bytes = ?3 WHERE id = ?4",
            params![ms, "x".repeat(chars), bytes, id],
        )
        .unwrap();
    }
    // Injection 1 (s1, 800 chars): never followed up. Injection 2 (s2, 400 chars): followed up 30 s later.
    injection(&conn, 1, "inject", "url", "s1", BASE + 100_000, &[(1, 1.0)]);
    injection(&conn, 2, "inject", "url", "s2", BASE + 200_000, &[(1, 1.0)]);
    conn.execute("UPDATE injection SET rendered_chars = 800 WHERE id = 1", [])
        .unwrap();
    conn.execute("UPDATE injection SET rendered_chars = 400 WHERE id = 2", [])
        .unwrap();
    let mut e4 = ev(4, "WebFetch", "s2", BASE + 230_000);
    e4.url = Some("https://example.org/a");
    insert(&conn, &e4);
    conn.execute("UPDATE event SET duration_ms = 1000 WHERE id = 4", [])
        .unwrap();
    label(&conn, 1, 1, "2");
    conn
}

#[test]
fn stats_savings_matches_hand_computed_numbers() {
    let env = Env::new();
    seed_savings(&env);
    // Injection 1 avoided: median of 4, 8, 20 s is 8 s = 0.1 min; median 800 chars / 4 = 200 tokens.
    // Overhead (800 + 400) / 4 = 300, net -100. Repeats of A: events 2, 3, 4 (8 + 20 + 1 s,
    // 800 + 1200 + 46 chars). Page bytes: median of 4000, 8000, 20000 is 8000 (event 4 has NULL
    // bytes and is ignored), so 8.0 KB and 8000 / 4 = 2000 summariser tokens; the same for the
    // confirmed item. Repeat fetches: 8000 + 20000 + 0 (event 4) = 28000 bytes, 7000 tokens.
    // Net with the summariser: 2000 + 200 - 300 = 1900 = 1.9k; the main-model part is -100 = -0.1k.
    let text = env.awm(&["stats", "--savings"]).ok().to_string();
    let want = "\
savings: an estimate of what did not happen, not a measurement

                            items     time  tokens  page bytes  summariser    cost
  avoided (est.)                1  0.1 min    0.2k      8.0 KB     <= 2.0k  <$0.01
  confirmed (label 2)           1  0.1 min    0.2k      8.0 KB     <= 2.0k  <$0.01
  ceiling: repeat fetches       3  0.5 min    0.5k     28.0 KB     <= 7.0k   $0.01
  ceiling: repeat searches      0  0.0 min    0.0k           -           -   $0.00

  tokens saved, net: <= 1.9k = summariser <= 2.0k + main model -0.1k; est. cost <$0.01
  main model: 0.2k of summaries not read - 0.3k of notes shown
  shown 2 = avoided 1 + followed up 1

";
    assert!(text.starts_with(want), "got:\n{text}");
    let note = text.strip_prefix(want).unwrap();
    assert!(
        note.starts_with("  tokens: main-model context, summary chars / 4. page bytes:"),
        "{note}"
    );
    assert!(
        note.lines().all(|l| l.len() <= 100 && l.starts_with("  ")),
        "{note}"
    );
    assert!(!text.contains("since"), "{text}");
    let v: Value = serde_json::from_str(env.awm(&["stats", "--savings", "--json"]).ok()).unwrap();
    let s = &v["savings"];
    assert_eq!(s["shown"], 2);
    assert_eq!(s["avoided"], 1);
    assert_eq!(s["followed_up"], 1);
    assert_eq!(s["time_saved_ms"], 8_000.0);
    assert_eq!(s["tokens_saved"], 200.0);
    assert_eq!(s["overhead_tokens"], 300.0);
    assert_eq!(s["net_tokens"], -100.0);
    assert_eq!(s["net_tokens_with_summariser"], 1_900.0);
    assert_eq!(s["confirmed"]["items"], 1);
    assert_eq!(s["confirmed"]["time_saved_ms"], 8_000.0);
    assert_eq!(s["confirmed"]["tokens_saved"], 200.0);
    assert_eq!(s["ceiling"]["repeat_fetches"]["count"], 3);
    assert_eq!(s["ceiling"]["repeat_fetches"]["duration_ms"], 29_000);
    assert_eq!(s["ceiling"]["repeat_fetches"]["tokens"], 511.5);
    assert_eq!(s["ceiling"]["repeat_searches"]["count"], 0);
    assert_eq!(s["est_bytes_not_fetched"], 8_000);
    assert_eq!(s["est_summariser_tokens"], 2_000);
    assert_eq!(s["confirmed"]["est_bytes_not_fetched"], 8_000);
    assert_eq!(s["confirmed"]["est_summariser_tokens"], 2_000);
    assert_eq!(s["ceiling"]["repeat_fetches"]["bytes"], 28_000);
    assert_eq!(s["ceiling"]["repeat_fetches"]["summariser_tokens"], 7_000);
    assert_eq!(s["ceiling"]["repeat_searches"]["bytes"], 0);
    // Default rates ($1/M in, $5/M out). Avoided and confirmed: 2000 summariser tokens * 1/1e6
    // + 200 summary tokens * 5/1e6 = 0.002 + 0.001. Repeat fetches: 7000 * 1/1e6 + 511.5 * 5/1e6
    // = 0.007 + 0.0025575. No search is repeated.
    let near = |got: &Value, want: f64| {
        assert!(
            (got.as_f64().unwrap() - want).abs() < 1e-9,
            "{got} != {want}"
        )
    };
    near(&s["est_cost"], 0.003);
    near(&s["confirmed"]["est_cost"], 0.003);
    near(&s["ceiling"]["repeat_fetches"]["est_cost"], 0.0095575);
    near(&s["ceiling"]["repeat_searches"]["est_cost"], 0.0);
    assert!(s["net_cost"].is_null());
    assert_eq!(s["pricing"]["currency"], "USD");
    assert_eq!(s["pricing"]["search_fee_per_call"], 0.01);
    assert_eq!(s["pricing"]["main_input_per_mtok"], 0.0);
}

fn write_pricing(env: &Env, toml: &str) {
    std::fs::write(env.awm_home().join("config.toml"), toml).unwrap();
}

#[test]
fn stats_savings_prices_main_tokens_when_the_rate_is_set() {
    let env = Env::new();
    seed_savings(&env);
    write_pricing(
        &env,
        "[pricing]\nsummariser_input_per_mtok = 1000.0\nmain_input_per_mtok = 3.0\n",
    );
    // Avoided: 2000 * 1000/1e6 = 2.0, + 200 * 5/1e6 = 0.001, + main 200 * 3/1e6 = 0.0006 -> 2.0016.
    // Overhead 300 * 3/1e6 = 0.0009, net 2.0007. Repeat fetches: 7.0 + 0.0025575 + 511.5 * 3/1e6.
    let text = env.awm(&["stats", "--savings"]).ok().to_string();
    assert!(
        text.contains(
            "  avoided (est.)                1  0.1 min    0.2k      8.0 KB     <= 2.0k  $2.00\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "  tokens saved, net: <= 1.9k = summariser <= 2.0k + main model -0.1k; est. cost $2.00, \
             net $2.00 after pricing the note overhead\n"
        ),
        "{text}"
    );
    assert!(text.contains("<= 7.0k  $7.00\n"), "{text}");
    let v: Value = serde_json::from_str(env.awm(&["stats", "--savings", "--json"]).ok()).unwrap();
    let s = &v["savings"];
    assert!((s["est_cost"].as_f64().unwrap() - 2.0016).abs() < 1e-9);
    assert!((s["net_cost"].as_f64().unwrap() - 2.0007).abs() < 1e-9);
    assert_eq!(s["pricing"]["main_input_per_mtok"], 3.0);
}

#[test]
fn stats_savings_search_fee_can_be_zero() {
    let env = Env::new();
    let conn = env.conn();
    for id in 1..=2 {
        let mut e = ev(id, "WebSearch", "s0", BASE + id * 1_000);
        e.query = Some("bm25 column weights");
        insert(&conn, &e);
    }
    // One repeated search: the default fee of 0.01 per call, then none.
    let row = "  ceiling: repeat searches      1  0.0 min    0.0k           -           -  ";
    let text = env.awm(&["stats", "--savings"]).ok().to_string();
    assert!(text.contains(&format!("{row}$0.01\n")), "{text}");
    write_pricing(&env, "[pricing]\nsearch_fee_per_call = 0\n");
    let text = env.awm(&["stats", "--savings"]).ok().to_string();
    assert!(text.contains(&format!("{row}$0.00\n")), "{text}");
}

#[test]
fn stats_savings_avoided_search_adds_no_page_bytes() {
    let env = Env::new();
    let conn = env.conn();
    let mut e = ev(1, "WebSearch", "s0", BASE + 1_000);
    e.query = Some("bm25 column weights");
    insert(&conn, &e);
    // Even a recorded size must not count: a search reads no page.
    conn.execute("UPDATE event SET bytes = 9999 WHERE id = 1", [])
        .unwrap();
    injection(
        &conn,
        1,
        "inject",
        "query",
        "s1",
        BASE + 100_000,
        &[(1, 1.0)],
    );
    let v: Value = serde_json::from_str(env.awm(&["stats", "--savings", "--json"]).ok()).unwrap();
    assert_eq!(v["savings"]["avoided"], 1);
    assert_eq!(v["savings"]["est_bytes_not_fetched"], 0);
    assert_eq!(v["savings"]["est_summariser_tokens"], 0);
    // Searches only: the net is exact, so no `<=` before it, and the summariser part is `<= 0k`.
    let text = env.awm(&["stats", "--savings"]).ok().to_string();
    let line = text
        .lines()
        .find(|l| l.starts_with("  tokens saved, net: "))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(!line.starts_with("  tokens saved, net: <="), "{line}");
    assert!(line.contains(" = summariser <= 0k + main model "), "{line}");
    assert_eq!(
        v["savings"]["net_tokens_with_summariser"],
        v["savings"]["net_tokens"]
    );
}

#[test]
fn stats_savings_since_limits_the_injections_but_not_the_ceiling() {
    let env = Env::new();
    seed_savings(&env);
    // No injection is on or after BASE + 30 days.
    let day = |ms: i64| {
        let t = time::OffsetDateTime::from_unix_timestamp(ms / 1000).unwrap();
        format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day())
    };
    let late = day(BASE + 86_400_000 * 30);
    let v: Value = serde_json::from_str(
        env.awm(&["stats", "--savings", "--since", &late, "--json"])
            .ok(),
    )
    .unwrap();
    assert_eq!(v["savings"]["shown"], 0);
    assert_eq!(v["savings"]["avoided"], 0);
    assert_eq!(v["savings"]["ceiling"]["repeat_fetches"]["count"], 3);
    assert_eq!(v["savings"]["est_bytes_not_fetched"], 0);
    assert_eq!(v["savings"]["ceiling"]["repeat_fetches"]["bytes"], 28_000);
    let text = env
        .awm(&["stats", "--savings", "--since", &late])
        .ok()
        .to_string();
    assert!(text.contains("  No notes shown yet.\n"), "{text}");
    assert!(
        text.contains(&format!("  since {late} (ceilings use the whole record)\n")),
        "{text}"
    );
    assert!(
        text.contains(
            "  ceiling: repeat fetches       3  0.5 min    0.5k     28.0 KB     <= 7.0k  $0.01\n"
        ),
        "{text}"
    );
    let early = day(BASE);
    let v: Value = serde_json::from_str(
        env.awm(&["stats", "--savings", "--since", &early, "--json"])
            .ok(),
    )
    .unwrap();
    assert_eq!(v["savings"]["shown"], 2);
    assert!(!env
        .awm(&["stats", "--savings", "--since", "soon"])
        .stderr
        .is_empty());
}

#[test]
fn stats_savings_on_an_empty_database() {
    let env = Env::new();
    let text = env.awm(&["stats", "--savings"]).ok().to_string();
    assert!(text.contains("No notes shown yet."), "{text}");
    assert!(
        text.contains(
            "  ceiling: repeat fetches       0  0.0 min    0.0k      0.0 KB       <= 0k  $0.00\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "  ceiling: repeat searches      0  0.0 min    0.0k           -           -  $0.00\n"
        ),
        "{text}"
    );
    assert!(!text.contains("since"), "{text}");
}

#[test]
fn stats_savings_text_uses_m_for_a_million_tokens_or_more() {
    let env = Env::new();
    let conn = env.conn();
    for (id, bytes) in [(1, 4_000), (2, 8_000_000)] {
        let mut e = ev(id, "WebFetch", "s0", BASE + id * 1_000);
        e.url = Some("https://example.org/big");
        insert(&conn, &e);
        conn.execute(
            "UPDATE event SET bytes = ?1 WHERE id = ?2",
            params![bytes, id],
        )
        .unwrap();
    }
    let text = env.awm(&["stats", "--savings"]).ok().to_string();
    assert!(
        text.contains(
            "  ceiling: repeat fetches       1  0.0 min    0.0k      8.0 MB     <= 2.0M  $2.00\n"
        ),
        "{text}"
    );
}

const HOUR: i64 = 3_600_000;

#[allow(clippy::too_many_arguments)]
fn qd_injection(
    conn: &Connection,
    id: i64,
    mode: &str,
    channel: &str,
    who: (&str, Option<&str>),
    tool_use_id: &str,
    transcript: Option<&str>,
    at: i64,
    trigger: &str,
    item: i64,
) {
    conn.execute(
        "INSERT INTO injection (id, ref, created_at, hook, channel, mode, session_id, agent_id, \
                                tool_use_id, transcript_path, trigger_text, rendered, \
                                rendered_chars, latency_ms) \
         VALUES (?1, ?2, ?3, 'PreToolUse', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 300, 5)",
        params![
            id,
            format!("{id:08x}"),
            at,
            channel,
            mode,
            who.0,
            who.1,
            tool_use_id,
            transcript,
            trigger,
            (mode == "deny").then_some("agent-web-memory: stored reason text")
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO injection_item (injection_id, position, event_id, score) VALUES (?1, 1, ?2, 1.0)",
        params![id, item],
    )
    .unwrap();
}

fn qd_search(conn: &Connection, id: i64, session: &str, agent: Option<&str>, at: i64, q: &str) {
    let mut e = ev(id, "WebSearch", session, at);
    e.agent = agent;
    e.query = Some(q);
    insert(conn, &e);
}

/// Six query rows around five searches; see docs/reports/QD2b.md for the hand computation.
fn seed_query_denies(env: &Env) {
    let conn = env.conn();
    let q = "sqlite fts5 bm25 weights";
    qd_search(&conn, 1, "s_old1", None, BASE, q); // A: project c1
    qd_search(&conn, 2, "s_old2", None, BASE, q); // B: project c2
    qd_search(&conn, 3, "s_codex", None, BASE, q); // C: Codex, project c3
    qd_search(&conn, 4, "sc", None, BASE, q); // D: the caller session's main agent, c1
    conn.execute("UPDATE event SET cwd_hash = 'c2' WHERE id = 2", [])
        .unwrap();
    conn.execute(
        "UPDATE event SET cwd_hash = 'c3', agent = 'codex' WHERE id = 3",
        [],
    )
    .unwrap();
    // R: the retry of denial 2, 60 s after it (BASE + 11 min), words reordered.
    qd_search(
        &conn,
        5,
        "sc",
        None,
        BASE + 660_000,
        "weights BM25 fts5 sqlite",
    );
    let t = "weights bm25 fts5 sqlite";
    let sc = ("sc", None);
    qd_injection(
        &conn,
        1,
        "shadow_deny",
        "query",
        sc,
        "q1",
        None,
        BASE + HOUR,
        t,
        1,
    );
    qd_injection(
        &conn,
        2,
        "deny",
        "query",
        sc,
        "q2",
        None,
        BASE + 600_000,
        t,
        2,
    );
    qd_injection(
        &conn,
        3,
        "shadow_deny",
        "query",
        ("sc", Some("a1")),
        "q3",
        None,
        BASE + 25 * HOUR,
        t,
        4,
    );
    qd_injection(
        &conn,
        4,
        "deny",
        "query",
        sc,
        "q4",
        None,
        BASE + 2 * HOUR,
        t,
        3,
    );
    qd_injection(
        &conn,
        5,
        "shadow_deny",
        "query",
        ("s_unknown", None),
        "q5",
        None,
        BASE + 300_000,
        t,
        1,
    );
    qd_injection(
        &conn,
        6,
        "deny",
        "query",
        sc,
        "exec-6",
        Some("/home/u/.codex/s.jsonl"),
        BASE + HOUR,
        t,
        3,
    );
    label(&conn, 1, 1, "2");
    label(&conn, 2, 1, "2");
    label(&conn, 4, 1, "1");
    label(&conn, 5, 1, "h");
}

#[test]
fn stats_reports_query_deny_with_hand_computed_numbers() {
    let env = Env::new();
    seed_query_denies(&env);
    // Denies 2, 4 and 6 score 1.0 (below 30); move two of them into the 40-60 and 60+ buckets.
    env.conn()
        .execute(
            "UPDATE injection_item SET score = CASE injection_id WHEN 4 THEN 45.0 ELSE 65.0 END \
             WHERE injection_id IN (4, 6)",
            [],
        )
        .unwrap();
    let v: Value = serde_json::from_str(env.awm(&["stats", "--json"]).ok()).unwrap();
    let q = &v["query_deny"];
    assert_eq!(
        q["cutoff_used"],
        json!({"value": 55.0, "source": "calibrated"})
    );
    let b = &q["by_top_score"];
    assert_eq!(b["<30"]["denies"], 1);
    assert_eq!(b["30-40"]["denies"], 0);
    assert_eq!(b["40-60"]["denies"], 1);
    assert_eq!(b["60+"]["denies"], 1);
    let researched: i64 = ["<30", "30-40", "40-60", "60+"]
        .iter()
        .map(|k| b[*k]["researched"].as_i64().unwrap())
        .sum();
    assert_eq!(researched, 1);
    // Rows of an older version (mode shadow_deny) stay in the breakdowns below; only real denies
    // are counted as denied.
    assert!(q.get("shadow").is_none());
    assert_eq!(q["denied"].as_i64(), Some(3));
    assert_eq!(q["by_agent_kind"], json!({"main": 5, "subagent": 1}));
    assert_eq!(
        q["by_relation"],
        json!({"same_agent": 0, "sibling": 1, "other_session_same_project": 1, "other_project": 2,
               "other_session_project_unknown": 1, "other_coding_agent": 1})
    );
    assert_eq!(q["by_age"], json!({"within_30_min": 2, "within_24_h": 5}));
    assert_eq!(q["labels"], json!({"2": 2, "1": 1, "0": 0, "h": 1}));
    assert_eq!(q["per_100_searches"], "60.00");
    assert_eq!(
        q["research_after_deny"],
        json!({"denies": 3, "researched": 1, "share": "33.3%"})
    );
    let text = env.awm(&["stats"]).ok().to_string();
    assert!(
        text.contains("query_deny:") && text.contains("per_100_searches: 60.00"),
        "{text}"
    );
}

#[test]
fn refetch_after_deny_counts_url_denies_only() {
    let env = Env::new();
    seed_query_denies(&env);
    let conn = env.conn();
    let mut f = ev(20, "WebFetch", "s_x", BASE);
    f.url = Some("https://example.org/a");
    insert(&conn, &f);
    qd_injection(
        &conn,
        20,
        "deny",
        "url",
        ("s_u", None),
        "u1",
        None,
        BASE + 10_000,
        "https://example.org/a",
        20,
    );
    let mut g = ev(21, "WebFetch", "s_u", BASE + 70_000);
    g.url = Some("https://example.org/a");
    insert(&conn, &g);
    let v: Value = serde_json::from_str(env.awm(&["stats", "--json"]).ok()).unwrap();
    // Three query denies exist; only the one URL deny is in the denominator.
    assert_eq!(
        v["injections"]["refetch_after_deny"],
        json!({"denies": 1, "refetched": 1, "share": "100.0%"})
    );
    assert_eq!(v["query_deny"]["denied"], 3);
}

#[test]
fn review_shows_a_query_deny_without_a_stored_reason_rebuilt_and_accepts_a_label() {
    let env = Env::new();
    let conn = env.conn();
    qd_search(&conn, 1, "s_old1", None, BASE, "sqlite fts5 bm25 weights");
    qd_injection(
        &conn,
        1,
        "shadow_deny",
        "query",
        ("sc", None),
        "q1",
        None,
        BASE + HOUR,
        "weights bm25 fts5 sqlite",
        1,
    );
    qd_injection(
        &conn,
        2,
        "deny",
        "query",
        ("sc", None),
        "q2",
        None,
        BASE + 2 * HOUR,
        "weights bm25 fts5 sqlite",
        1,
    );
    let out = env.awm_in(&["review"], "h\n2\n");
    let text = out.ok().to_string();
    assert!(
        text.contains("query deny: in another project, 2 h ago"),
        "{text}"
    );
    assert!(
        text.contains("agent-web-memory: stored reason text"),
        "{text}"
    );
    assert!(
        text.contains("query deny: in another project, 1 h ago"),
        "{text}"
    );
    assert!(
        text.contains("agent-web-memory: earlier research matching this search is attached as additional context."),
        "{text}"
    );
    assert!(text.contains("\nWeights are passed"), "{text}");
    assert!(
        text.contains("query deny labels: 2 the earlier finding covered"),
        "{text}"
    );
    assert!(text.contains("Labelled 2 of 2"), "{text}");
    let labels: String = conn
        .query_row(
            "SELECT group_concat(injection_id || label) FROM (SELECT * FROM outcome ORDER BY injection_id)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(labels, "12,2h");
}

#[test]
fn config_list_shows_team_keys() {
    let env = Env::new();
    let list = env.awm(&["config", "list"]).ok().to_string();
    for line in [
        "team.auto_sync = true\n",
        "team.sync_interval_s = 60\n",
        "team.show = true\n",
        "team.mute = \n",
        "team.share_all_projects = false\n",
        "team.exclude_hosts = \n",
        "team.summary_chars = 1000\n",
        "team.share_stats = false\n",
        "team.auto_approve = none\n",
        "team.push_delay_s = 0\n",
    ] {
        assert!(list.contains(line), "{line:?} missing from {list}");
    }
}

#[test]
fn team_sync_and_cloud_are_stubs_that_exit_2() {
    let env = Env::new();
    // With the `sync` feature `awm sync` is a real command (see the test below).
    #[cfg(not(feature = "sync"))]
    let subs = ["team", "sync", "cloud"];
    #[cfg(feature = "sync")]
    let subs = ["team", "cloud"];
    for sub in subs {
        let out = env.awm(&[sub]);
        assert_eq!(out.code, Some(2), "{sub}");
    }
}

#[cfg(feature = "sync")]
#[test]
fn sync_outside_a_team_exits_1() {
    let env = Env::new();
    let out = env.awm(&["sync"]);
    assert_eq!(out.code, Some(1), "stderr: {}", out.stderr);
    assert!(out.stderr.contains("not in a team"), "{}", out.stderr);
}
#[test]
fn stats_savings_fallback_median_ignores_later_calls() {
    // RVQ0 m5. The shown item (event 1, ok, no duration) has no durations of its own; ok fetches
    // of other urls last 2 s before the note and 60 s and 70 s after it. The fallback median
    // is over the calls up to the note: 2 s, not 60 s.
    let env = Env::new();
    let conn = env.conn();
    for (id, url, at, ms) in [
        (1, "https://example.org/item", BASE + 1_000, None),
        (2, "https://example.org/b", BASE + 2_000, Some(2_000)),
        (3, "https://example.org/c", BASE + 200_000, Some(60_000)),
        (4, "https://example.org/d", BASE + 210_000, Some(70_000)),
    ] {
        let mut e = ev(id, "WebFetch", "s0", at);
        e.url = Some(url);
        insert(&conn, &e);
        conn.execute(
            "UPDATE event SET duration_ms = ?1 WHERE id = ?2",
            params![ms, id],
        )
        .unwrap();
    }
    injection(&conn, 1, "inject", "url", "s1", BASE + 100_000, &[(1, 1.0)]);
    let v: Value = serde_json::from_str(env.awm(&["stats", "--savings", "--json"]).ok()).unwrap();
    assert_eq!(v["savings"]["avoided"], 1);
    assert_eq!(v["savings"]["time_saved_ms"], 2_000.0);
}

// ---- stats per repository and per directory (STATS2) -----------------------------------------

struct Where {
    repo: PathBuf,
    a: PathBuf,
    b: PathBuf,
    plain: PathBuf,
}

fn cwd_row(conn: &Connection, path: &Path, root: Option<&Path>) -> String {
    let p = path.to_string_lossy().into_owned();
    let hash = awm::record::sha256_hex(&p);
    conn.execute(
        "INSERT INTO cwd (cwd_hash, path, repo_root, updated_at) VALUES (?1, ?2, ?3, 1)",
        params![hash, p, root.map(|r| r.to_string_lossy().into_owned())],
    )
    .unwrap();
    hash
}

/// Two directories of one fake repository (`a`, `b`) and one outside git (`plain`), a sibling
/// directory whose name starts like the repository's, and records and notes in each:
/// events 1, 2 and 4 in `a` and `b` (`a`: 1 and 4), event 3 in `plain`, event 5 nowhere known;
/// injections 1 (inject, `a`), 2 (deny, `b`, refetched), 3 (inject, `plain`).
fn seed_where(env: &Env) -> Where {
    let base = env.dir.path();
    let repo = base.join("repo");
    let (a, b) = (repo.join("a"), repo.join("b"));
    let plain = base.join("plain");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    for d in [&a, &b, &plain] {
        std::fs::create_dir_all(d).unwrap();
    }
    let conn = env.conn();
    let (ha, hb) = (
        cwd_row(&conn, &a, Some(&repo)),
        cwd_row(&conn, &b, Some(&repo)),
    );
    let hp = cwd_row(&conn, &plain, None);
    cwd_row(&conn, &base.join("repo-sibling"), None);
    let mut e1 = ev(1, "WebFetch", "s1", BASE + 1_000);
    e1.url = Some("https://example.org/a");
    insert(&conn, &e1);
    let mut e2 = ev(2, "WebFetch", "s2", BASE + 2_000);
    e2.url = Some("https://example.org/b");
    insert(&conn, &e2);
    let mut e3 = ev(3, "WebSearch", "s3", BASE + 3_000);
    e3.query = Some("rust clap derive");
    insert(&conn, &e3);
    let mut e4 = ev(4, "WebFetch", "s1", BASE + 4_000);
    e4.url = Some("https://example.org/c");
    insert(&conn, &e4);
    let mut e5 = ev(5, "WebSearch", "s9", BASE + 5_000);
    e5.query = Some("lost directory");
    insert(&conn, &e5);
    for (id, hash) in [
        (1, &ha),
        (2, &hb),
        (3, &hp),
        (4, &ha),
        (5, &"zz".to_string()),
    ] {
        conn.execute(
            "UPDATE event SET cwd_hash = ?1 WHERE id = ?2",
            params![hash, id],
        )
        .unwrap();
    }
    conn.execute(
        "UPDATE event SET duration_ms = 4000, bytes = 8000 WHERE tool = 'WebFetch'",
        [],
    )
    .unwrap();
    injection(&conn, 1, "inject", "url", "s1", BASE + 10_000, &[(1, 1.0)]);
    injection(&conn, 2, "deny", "url", "s2", BASE + 11_000, &[(2, 1.0)]);
    injection(
        &conn,
        3,
        "inject",
        "query",
        "s3",
        BASE + 12_000,
        &[(3, 60.0)],
    );
    for (id, hash) in [(1, &ha), (2, &hb), (3, &hp)] {
        conn.execute(
            "UPDATE injection SET cwd_hash = ?1 WHERE id = ?2",
            params![hash, id],
        )
        .unwrap();
    }
    // The deny of injection 2 was followed by a fetch of the same URL in the same session.
    let mut e6 = ev(6, "WebFetch", "s2", BASE + 20_000);
    e6.url = Some("https://example.org/b");
    insert(&conn, &e6);
    conn.execute("UPDATE event SET cwd_hash = ?1 WHERE id = 6", [&hb])
        .unwrap();
    // Out of scope for `--repo`, one of each kind the scope clauses must keep out: a URL deny that
    // was refetched (injection 4, event 7, fetched again as event 8) in `plain`, a label `2` on the
    // inject of injection 3, and a PreToolUse query deny (injection 5) on the search of event 3.
    let mut e7 = ev(7, "WebFetch", "s7", BASE + 6_000);
    e7.url = Some("https://example.org/p");
    insert(&conn, &e7);
    injection(&conn, 4, "deny", "url", "s7", BASE + 13_000, &[(7, 1.0)]);
    let mut e8 = ev(8, "WebFetch", "s7", BASE + 21_000);
    e8.url = Some("https://example.org/p");
    insert(&conn, &e8);
    label(&conn, 3, 1, "2");
    qd_injection(
        &conn,
        5,
        "deny",
        "query",
        ("s3", None),
        "inj5",
        None,
        BASE + 14_000,
        "rust clap derive",
        3,
    );
    conn.execute(
        "UPDATE event SET cwd_hash = ?1, duration_ms = 4000, bytes = 8000 WHERE id IN (7, 8)",
        [&hp],
    )
    .unwrap();
    conn.execute(
        "UPDATE injection SET cwd_hash = ?1 WHERE id IN (4, 5)",
        [&hp],
    )
    .unwrap();
    Where { repo, a, b, plain }
}

fn json_of(out: &Out) -> Value {
    serde_json::from_str(out.ok()).unwrap()
}

fn tmpl(env: &Env, text: &str) -> String {
    let base = env.dir.path().to_string_lossy().into_owned();
    let canon = std::fs::canonicalize(env.dir.path())
        .unwrap()
        .to_string_lossy()
        .into_owned();
    text.replace(&canon, "<TMP>").replace(&base, "<TMP>")
}

#[test]
fn stats_by_repo_groups_the_directories_of_a_checkout() {
    let env = Env::new();
    let w = seed_where(&env);
    let out = env.awm(&["stats", "--by", "repo", "--json"]);
    let v = json_of(&out);
    let rows = v["by_repo"].as_array().unwrap();
    let repo = w.repo.to_string_lossy().into_owned();
    let plain = format!("(no repository) {}", w.plain.display());
    let want = [
        (repo.as_str(), 4, 1, 1, 1),
        (plain.as_str(), 3, 1, 2, 1),
        ("(unknown)", 1, 0, 0, 0),
        ("total", 8, 2, 3, 2),
    ];
    assert_eq!(rows.len(), want.len(), "{v}");
    for (row, (label, records, notes, denied, refetch)) in rows.iter().zip(want) {
        assert_eq!(row["repo"], label, "{v}");
        assert_eq!(row["records"], records, "{label}");
        assert_eq!(row["notes"], notes, "{label}");
        assert_eq!(row["denied"], denied, "{label}");
        assert_eq!(row["refetch_after_deny"], refetch, "{label}");
    }
    // The record whose directory no transcript names is reported once, on stderr.
    assert!(
        out.stderr.contains(
            "awm stats: 0 injections and 1 records could not be placed (no transcript or record names their directory)"
        ),
        "{}",
        out.stderr
    );
    let text = env.awm(&["stats", "--by", "repo"]);
    golden("stats-by-repo.txt", &tmpl(&env, text.ok()));
}

#[test]
fn stats_by_dir_lists_every_directory_and_text_ends_with_the_label() {
    let env = Env::new();
    let w = seed_where(&env);
    let v = json_of(&env.awm(&["stats", "--by", "dir", "--json"]));
    let rows = v["by_dir"].as_array().unwrap();
    let labels: Vec<&str> = rows.iter().map(|r| r["dir"].as_str().unwrap()).collect();
    let (a, b, plain) = (
        w.a.to_string_lossy().into_owned(),
        w.b.to_string_lossy().into_owned(),
        w.plain.to_string_lossy().into_owned(),
    );
    // notes desc, then records desc, then name; the sibling directory has nothing and is not listed.
    assert_eq!(
        labels,
        [plain.as_str(), a.as_str(), b.as_str(), "(unknown)", "total"]
    );
    assert_eq!(rows[0]["records"], 3);
    assert_eq!(rows[1]["records"], 2);
    assert_eq!(rows[0]["notes"], 1);
    assert_eq!(rows[2]["denied"], 1);
    let text = env.awm(&["stats", "--by", "dir"]);
    let text = text.ok();
    assert!(
        text.lines().next().unwrap().ends_with("directory"),
        "{text}"
    );
    assert!(text.lines().last().unwrap().ends_with("  total"), "{text}");
    assert!(text.contains(&a), "{text}");
}

#[test]
fn stats_by_repo_with_savings_has_one_row_per_group_and_a_total() {
    let env = Env::new();
    let w = seed_where(&env);
    let v = json_of(&env.awm(&["stats", "--by", "repo", "--savings", "--json"]));
    let rows = v["by_repo"].as_array().unwrap();
    // `(unknown)` has no injection and is not listed; the total is the sum of the rows.
    assert_eq!(rows.len(), 3, "{v}");
    // The search note avoids the $0.01 search fee, more than the fetch notes' summariser cost.
    assert_eq!(
        rows[0]["repo"],
        format!("(no repository) {}", w.plain.display())
    );
    assert_eq!(rows[1]["repo"], w.repo.to_string_lossy().as_ref());
    assert_eq!(rows[1]["shown"], 2);
    let sum = |k: &str| {
        rows[..2]
            .iter()
            .map(|r| r[k].as_f64().unwrap())
            .sum::<f64>()
    };
    for k in [
        "shown",
        "avoided",
        "net_tokens",
        "summariser_tokens",
        "cost",
    ] {
        assert!(
            (rows[2][k].as_f64().unwrap() - sum(k)).abs() < 1e-9,
            "{k}: {v}"
        );
    }
    assert_eq!(rows[2]["repo"], "total");
    assert_eq!(rows[2]["shown"], 5);
    assert_eq!(rows[2]["currency"], "USD");
    assert!(rows[0]["cost"].as_f64().unwrap() >= rows[1]["cost"].as_f64().unwrap());
    let global = json_of(&env.awm(&["stats", "--savings", "--json"]));
    assert_eq!(global["savings"]["shown"], rows[2]["shown"]);
    assert_eq!(global["savings"]["avoided"], rows[2]["avoided"]);
    let text = env.awm(&["stats", "--by", "repo", "--savings"]);
    let text = text.ok();
    assert!(text.lines().next().unwrap().contains("avoided"), "{text}");
    assert!(
        text.lines().next().unwrap().ends_with("repository"),
        "{text}"
    );
}

#[test]
fn stats_repo_scopes_every_section_to_the_checkout() {
    let env = Env::new();
    let w = seed_where(&env);
    let repo = w.repo.to_string_lossy().into_owned();
    // Any directory of the repository names it; the sibling `repo-sibling` is not part of it.
    let v = json_of(&env.awm(&["stats", "--repo", &w.a.to_string_lossy(), "--json"]));
    assert_eq!(
        v["scope"],
        json!({"kind": "repo", "path": repo, "directories": 2})
    );
    assert_eq!(v["by_agent"]["claude"], 4);
    assert_eq!(v["injections"]["shown"], 2);
    assert_eq!(v["injections"]["shown_by_channel"], json!({"url": 2}));
    assert_eq!(v["injections"]["refetch_after_deny"]["denies"], 1);
    assert_eq!(v["injections"]["refetch_after_deny"]["refetched"], 1);
    // The out-of-scope deny (refetched), label and query deny in `plain` stay out.
    assert_eq!(v["injections"]["deny_by_kind"]["cached"], 1);
    assert_eq!(v["injections"]["accepted"], 0);
    assert_eq!(v["query_deny"]["denied"], 0);
    let all = json_of(&env.awm(&["stats", "--json"]));
    assert_eq!(all["injections"]["deny_by_kind"]["cached"], 2);
    assert_eq!(all["injections"]["refetch_after_deny"]["denies"], 2);
    assert_eq!(all["injections"]["accepted"], 1);
    assert_eq!(all["query_deny"]["denied"], 1);
    let text = env.awm(&["stats", "--repo", &repo]);
    assert_eq!(
        text.ok().lines().next().unwrap(),
        format!("scope: repo {repo} (2 directories)")
    );
    let status = json_of(&env.awm(&["stats", "--repo", &repo, "--status", "--json"]));
    assert_eq!(status["status"]["ok"], 4);
    let value = json_of(&env.awm(&["stats", "--repo", &repo, "--value", "--json"]));
    assert_eq!(value["value"]["shown_items"], 2);
    assert_eq!(value["value"]["labelled_2"], 0);
    let follow = json_of(&env.awm(&["stats", "--repo", &repo, "--followups", "--json"]));
    assert_eq!(follow["followups"]["shown"]["injections"], 2);
    assert_eq!(follow["followups"]["shown"]["followed_in_session"], 1);
    let s = json_of(&env.awm(&["stats", "--repo", &repo, "--savings", "--json"]));
    assert_eq!(s["savings"]["shown"], 2);
    assert_eq!(s["savings"]["ceiling"]["repeat_fetches"]["count"], 1);
    let all = json_of(&env.awm(&["stats", "--value", "--followups", "--savings", "--json"]));
    assert_eq!(all["value"]["labelled_2"], 1);
    assert_eq!(all["followups"]["shown"]["followed_in_session"], 2);
    assert_eq!(all["savings"]["ceiling"]["repeat_fetches"]["count"], 2);
    // A repository nothing was recorded in is an empty scope, not an error.
    let other = env.dir.path().join("empty-repo");
    std::fs::create_dir_all(other.join(".git")).unwrap();
    let v = json_of(&env.awm(&["stats", "--repo", &other.to_string_lossy(), "--json"]));
    assert_eq!(v["scope"]["directories"], 0);
    assert_eq!(v["injections"]["shown"], 0);
    assert_eq!(v["by_agent"]["claude"], 0);
}

#[test]
fn stats_dir_takes_the_directory_and_everything_under_it() {
    let env = Env::new();
    let w = seed_where(&env);
    let canon = |p: &Path| {
        std::fs::canonicalize(p)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    };
    let v = json_of(&env.awm(&["stats", "--dir", &w.repo.to_string_lossy(), "--json"]));
    assert_eq!(
        v["scope"],
        json!({"kind": "dir", "path": canon(&w.repo), "directories": 2})
    );
    assert_eq!(v["injections"]["shown"], 2);
    let v = json_of(&env.awm(&["stats", "--dir", &w.b.to_string_lossy(), "--json"]));
    assert_eq!(v["scope"]["directories"], 1);
    assert_eq!(v["injections"]["shown"], 1);
    assert_eq!(v["by_agent"]["claude"], 2);
    let text = env.awm(&["stats", "--dir", &w.plain.to_string_lossy()]);
    assert_eq!(
        text.ok().lines().next().unwrap(),
        format!("scope: dir {} (1 directory)", canon(&w.plain))
    );
    golden(
        "stats-dir.txt",
        &tmpl(
            &env,
            env.awm(&["stats", "--dir", &w.repo.to_string_lossy()]).ok(),
        ),
    );
}

#[test]
fn stats_scope_and_breakdown_flags_conflict_and_a_repo_needs_git() {
    let env = Env::new();
    let w = seed_where(&env);
    for args in [
        &["stats", "--by", "repo", "--repo", "."][..],
        &["stats", "--by", "dir", "--dir", "."],
        &["stats", "--repo", ".", "--dir", "."],
        &["stats", "--repo", ".", "--latency"],
        &["stats", "--dir", ".", "--team"],
        &["stats", "--by", "repo", "--status"],
        &["stats", "--by", "dir", "--import"],
    ] {
        let out = env.awm(args);
        assert_eq!(out.code, Some(2), "{args:?}: {}", out.stderr);
        assert!(
            out.stderr.contains("cannot be used with"),
            "{args:?}: {}",
            out.stderr
        );
    }
    let out = env.awm(&["stats", "--repo", &w.plain.to_string_lossy()]);
    assert_ne!(out.code, Some(0));
    assert!(
        out.stderr.contains(&format!(
            "{} is not inside a git repository; use --dir",
            w.plain.display()
        )),
        "{}",
        out.stderr
    );
}

#[test]
fn stats_by_dir_since_counts_only_the_newer_records_and_notes() {
    let env = Env::new();
    let w = seed_where(&env);
    let conn = env.conn();
    let ha = awm::record::sha256_hex(&w.a.to_string_lossy());
    let new = BASE + 86_400_000 * 40;
    let mut e = ev(20, "WebFetch", "s20", new);
    e.url = Some("https://example.org/new");
    insert(&conn, &e);
    injection(&conn, 20, "inject", "url", "s20", new + 1_000, &[(20, 1.0)]);
    conn.execute("UPDATE event SET cwd_hash = ?1 WHERE id = 20", [&ha])
        .unwrap();
    conn.execute("UPDATE injection SET cwd_hash = ?1 WHERE id = 20", [&ha])
        .unwrap();
    let a = w.a.to_string_lossy().into_owned();
    let row_of = |v: &Value| {
        v["by_dir"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["dir"] == a.as_str())
            .cloned()
            .unwrap()
    };
    let all = row_of(&json_of(&env.awm(&["stats", "--by", "dir", "--json"])));
    assert_eq!(
        (all["records"].clone(), all["notes"].clone()),
        (json!(3), json!(2))
    );
    let t = time::OffsetDateTime::from_unix_timestamp((BASE + 86_400_000 * 30) / 1000).unwrap();
    let since = format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day());
    let v = json_of(&env.awm(&["stats", "--by", "dir", "--since", &since, "--json"]));
    let new = row_of(&v);
    assert_eq!(
        (new["records"].clone(), new["notes"].clone()),
        (json!(1), json!(1))
    );
    let total = v["by_dir"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(total["records"], 1);
    assert_eq!(total["denied"], 0);
}

#[test]
fn stats_repo_outside_git_fails_before_the_backfill_writes_anything() {
    let env = Env::new();
    let w = seed_where(&env);
    let counts = || {
        let conn = env.conn();
        let n = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap();
        (
            n("SELECT COUNT(*) FROM cwd"),
            n("SELECT COUNT(*) FROM meta WHERE key LIKE 'cwd.walked.%'"),
        )
    };
    let before = counts();
    let out = env.awm(&["stats", "--repo", &w.plain.to_string_lossy()]);
    assert_ne!(out.code, Some(0));
    assert_eq!(counts(), before);
    // The same database does write its memo when the command is valid (event 5 stays unplaced).
    env.awm(&["stats", "--by", "repo"]).ok();
    assert_ne!(counts(), before);
}
