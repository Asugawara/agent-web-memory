//! Deletion (plan-v2 §6.4): forget, purge, quarantine, uninstall.
//!
//! Records come from a synthetic transcript through `import::import_all`, so the
//! "re-import does not restore it" checks use the real import path. Raw-bytes
//! checks read `awm.db` and `awm.db-wal` with `std::fs::read` after
//! `wal_checkpoint(TRUNCATE)` from a fresh connection.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use awm::config::Config;
use awm::db::{self, Role};
use awm::forget::{self, Io, Outcome, PurgeArgs, QuarantineArgs};
use awm::import::{self, ImportOpts, ImportSummary};
use awm::matching::{self, MatchOpts};
use awm::record::sha256_hex;
use rusqlite::{params, Connection};
use serde_json::{json, Value};

/// 2026-09-21T12:26:40Z.
const NOW: i64 = 1_790_000_000_000;
/// Unique token in the forgotten URL's host; appears nowhere else.
const TOKEN: &str = "zqxforgettoken";
const URL: &str = "https://zqxforgettoken.example.com/docs";
/// Unique token in the records of 2026-09-01, removed by `purge --before 2026-09-10`.
const OLD_TOKEN: &str = "zqxoldpurgetoken";

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let env = Env { _dir: dir, root };
        std::fs::create_dir_all(env.projects().join("-work-forget")).unwrap();
        std::fs::write(env.transcript(), transcript()).unwrap();
        std::fs::create_dir_all(env.data()).unwrap();
        let mut conn = db::open(&env.db_path(), Role::Cli).unwrap();
        db::migrate(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('consent.record', 'yes')",
            [],
        )
        .unwrap();
        drop(conn);
        let s = env.import();
        assert_eq!(s.records_inserted, 6, "{s:?}");
        env
    }

    fn projects(&self) -> PathBuf {
        self.root.join("projects")
    }

    fn transcript(&self) -> PathBuf {
        self.projects().join("-work-forget/sess-f.jsonl")
    }

    fn data(&self) -> PathBuf {
        self.root.join("awm")
    }

    fn db_path(&self) -> PathBuf {
        self.data().join("awm.db")
    }

    fn conn(&self) -> Connection {
        db::open(&self.db_path(), Role::Cli).unwrap()
    }

    fn import(&self) -> ImportSummary {
        import::import_all(&ImportOpts {
            projects_dir: self.projects(),
            codex_dir: None,
            data_dir: self.data(),
            config: Config::default(),
            only_ids: None,
            now_ms: NOW,
        })
        .unwrap()
    }

    /// Forgets which files were read, so the next import rescans the transcript from 0.
    fn reimport(&self) -> ImportSummary {
        self.conn()
            .execute("DELETE FROM import_source", [])
            .unwrap();
        self.import()
    }

    fn count(&self, sql: &str) -> i64 {
        self.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn id_of(&self, tool_use_id: &str) -> i64 {
        self.conn()
            .query_row(
                "SELECT id FROM event WHERE tool_use_id = ?1",
                [tool_use_id],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn exists(&self, tool_use_id: &str) -> bool {
        self.count(&format!(
            "SELECT COUNT(*) FROM event WHERE tool_use_id = '{tool_use_id}'"
        )) == 1
    }

    /// An injection row with items; returns its ref.
    fn inject(
        &self,
        ref_id: &str,
        created_at: i64,
        tool_use_id: Option<&str>,
        trigger: Option<&str>,
        rendered: &str,
        items: &[i64],
    ) {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO injection (ref, created_at, hook, channel, mode, session_id, \
             tool_use_id, trigger_text, rendered, rendered_chars, latency_ms) \
             VALUES (?1, ?2, 'PostToolUse', 'query', 'inject', 'sess-later', ?3, ?4, ?5, ?6, 5)",
            params![
                ref_id,
                created_at,
                tool_use_id,
                trigger,
                rendered,
                rendered.len() as i64
            ],
        )
        .unwrap();
        let injection = conn.last_insert_rowid();
        for (i, e) in items.iter().enumerate() {
            conn.execute(
                "INSERT INTO injection_item (injection_id, position, event_id, score) \
                 VALUES (?1, ?2, ?3, 1.0)",
                params![injection, i as i64 + 1, e],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO outcome (injection_id, position, label, labelled_at) \
                 VALUES (?1, ?2, '1', ?3)",
                params![injection, i as i64 + 1, NOW],
            )
            .unwrap();
        }
    }

    fn hook_run(&self, started_at: i64) {
        self.conn()
            .execute(
                "INSERT INTO hook_run (started_at, hook, session_id, agent_kind, total_ms, outcome) \
                 VALUES (?1, 'post-tool', 'sess-f', 'main', 3, 'no_match')",
                [started_at],
            )
            .unwrap();
    }

    /// Backup and spool files that every deletion must remove.
    fn leftovers(&self) {
        std::fs::write(self.data().join("awm.db.bak-v1"), format!("old copy {URL}")).unwrap();
        std::fs::create_dir_all(self.data().join("spool")).unwrap();
        std::fs::write(
            self.data().join("spool/1790000000000-toolu_x.json"),
            format!("{{\"url\": \"{URL}\"}}"),
        )
        .unwrap();
    }

    fn assert_leftovers_gone(&self) {
        assert!(!self.data().join("awm.db.bak-v1").exists());
        assert_eq!(
            std::fs::read_dir(self.data().join("spool"))
                .unwrap()
                .count(),
            0
        );
    }

    /// Raw bytes of `awm.db` and `awm.db-wal` after a checkpoint from a new connection.
    fn raw_contains(&self, token: &str) -> bool {
        let conn = self.conn();
        let (busy, _, _): (i64, i64, i64) = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(busy, 0);
        drop(conn);
        let needle = token.as_bytes();
        let mut found = false;
        for name in ["awm.db", "awm.db-wal"] {
            let path = self.data().join(name);
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if bytes.windows(needle.len()).any(|w| w == needle) {
                found = true;
            }
        }
        found
    }

    fn run<T>(
        &self,
        terminal: bool,
        input: &str,
        f: impl FnOnce(&mut Io<'_>) -> anyhow::Result<T>,
    ) -> (T, String) {
        let mut input = input.as_bytes();
        let mut out = Vec::new();
        let r = {
            let mut io = Io {
                data_dir: self.data(),
                terminal,
                input: &mut input,
                out: &mut out,
                now_ms: NOW,
            };
            f(&mut io).unwrap()
        };
        (r, String::from_utf8(out).unwrap())
    }

    fn forget(&self, args: forget::Args) -> (Outcome, String) {
        self.run(false, "", |io| forget::run_forget(&args, io))
    }

    fn awm(&self, args: &[&str]) -> (Option<i32>, String, String) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_awm"))
            .args(args)
            .env("AWM_HOME", self.data())
            .env("HOME", self.root.join("home"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"y\n").unwrap();
        let o = child.wait_with_output().unwrap();
        (
            o.status.code(),
            String::from_utf8(o.stdout).unwrap(),
            String::from_utf8(o.stderr).unwrap(),
        )
    }

    /// Every row of the tables a command could change, as text.
    fn snapshot(&self) -> String {
        let conn = self.conn();
        let mut s = String::new();
        for sql in [
            "SELECT id, tool_use_id, quarantined, COALESCE(quarantine_reason, ''), match_text, \
             COALESCE(summary, '') FROM event ORDER BY id",
            "SELECT event_id, rank, url, COALESCE(title, '') FROM result ORDER BY event_id, rank",
            "SELECT id, ref FROM injection ORDER BY id",
            "SELECT injection_id, position, event_id FROM injection_item ORDER BY 1, 2",
            "SELECT injection_id, position, label FROM outcome ORDER BY 1, 2",
            "SELECT id FROM hook_run ORDER BY id",
            "SELECT kind, value FROM tombstone ORDER BY 1, 2",
            "SELECT key, value FROM meta ORDER BY key",
        ] {
            let mut st = conn.prepare(sql).unwrap();
            let n = st.column_count();
            let rows = st
                .query_map([], |r| {
                    let mut cols = Vec::new();
                    for i in 0..n {
                        let v: rusqlite::types::Value = r.get(i)?;
                        cols.push(format!("{v:?}"));
                    }
                    Ok(cols.join("|"))
                })
                .unwrap();
            for row in rows {
                s.push_str(&row.unwrap());
                s.push('\n');
            }
            s.push_str("--\n");
        }
        s
    }
}

fn line(v: Value) -> String {
    let mut s = serde_json::to_string(&v).unwrap();
    s.push('\n');
    s
}

/// One tool call: the assistant `tool_use` line and the user line with its result.
fn call(ts: &str, ts_result: &str, id: &str, name: &str, input: Value, result: Value) -> String {
    let base = |t: &str| json!({"sessionId": "sess-f", "cwd": "/work/forget", "timestamp": t});
    let mut a = base(ts);
    a["type"] = json!("assistant");
    a["message"] = json!({"role": "assistant", "content": [
        {"type": "text", "text": "Checking."},
        {"type": "tool_use", "id": id, "name": name, "input": input}
    ]});
    let mut u = base(ts_result);
    u["type"] = json!("user");
    u["message"] = json!({"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": id, "content": [{"type": "text", "text": "tool output"}]}
    ]});
    u["toolUseResult"] = result;
    line(a) + &line(u)
}

fn fetch(ts: &str, id: &str, url: &str, prompt: &str, answer: &str) -> String {
    call(
        ts,
        ts,
        id,
        "WebFetch",
        json!({"url": url, "prompt": prompt}),
        json!({"bytes": 900, "code": 200, "codeText": "OK", "result": answer, "durationMs": 800, "url": url}),
    )
}

fn search(ts: &str, id: &str, query: &str, results: Value, summary: &str) -> String {
    call(
        ts,
        ts,
        id,
        "WebSearch",
        json!({"query": query}),
        json!({"query": query, "results": [{"tool_use_id": "srvtoolu_1", "content": results}, summary], "durationSeconds": 1.5}),
    )
}

/// Six records: two on 2026-09-01 (`OLD_TOKEN`), four on 2026-09-20, of which
/// `toolu_f1` fetched `URL` and `toolu_s1` listed it and mentions it in its summary.
fn transcript() -> String {
    let mut t = String::new();
    t += &search(
        "2026-09-01T09:00:00.000Z",
        "toolu_old_s",
        &format!("{OLD_TOKEN} release notes"),
        json!([{"title": "Release notes", "url": "https://old.example.net/notes"}]),
        "Old release notes.",
    );
    t += &fetch(
        "2026-09-01T09:05:00.000Z",
        "toolu_old_f",
        "https://old.example.net/notes",
        &format!("what changed in {OLD_TOKEN}"),
        "Many things changed.",
    );
    t += &search(
        "2026-09-20T10:00:00.000Z",
        "toolu_s1",
        "rust crate install guide",
        json!([
            {"title": "Install guide", "url": URL},
            {"title": "Crate docs", "url": "https://other.example.org/crate"}
        ]),
        &format!(
            "The guide at {URL} explains installation; see also https://other.example.org/crate."
        ),
    );
    t += &fetch(
        "2026-09-20T10:01:00.000Z",
        "toolu_f1",
        URL,
        "how do I install it",
        "The guide covers the installation steps for the crate.",
    );
    t += &fetch(
        "2026-09-20T10:02:00.000Z",
        "toolu_f2",
        "https://other.example.org/crate",
        "what does the crate do",
        "It parses configuration files.",
    );
    t += &search(
        "2026-09-20T10:03:00.000Z",
        "toolu_s2",
        "configuration file formats",
        json!([{"title": "TOML", "url": "https://toml.example.io/"}]),
        "TOML is a configuration file format.",
    );
    t
}

fn ms(date: &str) -> i64 {
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    time::Date::parse(date, &fmt)
        .unwrap()
        .midnight()
        .assume_utc()
        .unix_timestamp()
        * 1000
}

fn fts(env: &Env, term: &str) -> i64 {
    env.conn()
        .query_row(
            "SELECT COUNT(*) FROM event_fts WHERE event_fts MATCH ?1",
            [term],
            |r| r.get(0),
        )
        .unwrap()
}

/// Rows of `event`, `result` and `injection` whose text holds `needle`.
fn mentions(env: &Env, needle: &str) -> i64 {
    let like = format!("%{needle}%");
    env.conn()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM event WHERE COALESCE(query, '') || COALESCE(url, '') \
                     || COALESCE(url_norm, '') || COALESCE(fetch_prompt, '') || COALESCE(summary, '') \
                     || match_text || COALESCE(quarantine_reason, '') LIKE ?1) \
                  + (SELECT COUNT(*) FROM result WHERE url || url_norm || COALESCE(title, '') LIKE ?1) \
                  + (SELECT COUNT(*) FROM injection WHERE COALESCE(trigger_text, '') \
                     || COALESCE(rendered, '') LIKE ?1) \
                  + (SELECT COUNT(*) FROM tombstone WHERE value LIKE ?1) \
                  + (SELECT COUNT(*) FROM meta WHERE value LIKE ?1)",
            [like],
            |r| r.get(0),
        )
        .unwrap()
}

fn forget_url(url: &str) -> forget::Args {
    forget::Args {
        target: Some(url.to_string()),
        yes: true,
        ..forget::Args::default()
    }
}

#[test]
fn forget_url_removes_every_trace_and_reimport_does_not_restore_it() {
    let env = Env::new();
    let (f1, s1, f2) = (
        env.id_of("toolu_f1"),
        env.id_of("toolu_s1"),
        env.id_of("toolu_f2"),
    );
    let rendered = format!("<awm-notes ref=\"aaaa0001\">\n[1] fetch\n    url: {URL}\n</awm-notes>");
    env.inject(
        "aaaa0001",
        NOW,
        Some("toolu_later1"),
        Some("install it"),
        &rendered,
        &[f1],
    );
    env.inject(
        "aaaa0002",
        NOW,
        Some("toolu_later2"),
        Some("crate guide"),
        "<awm-notes>search</awm-notes>",
        &[s1],
    );
    env.inject(
        "aaaa0003",
        NOW,
        Some("toolu_later3"),
        Some(&format!("{URL} again")),
        "<awm-notes>x</awm-notes>",
        &[f2],
    );
    env.inject(
        "aaaa0004",
        NOW,
        Some("toolu_later4"),
        Some("toml"),
        "<awm-notes>toml</awm-notes>",
        &[f2],
    );
    env.leftovers();
    assert!(mentions(&env, TOKEN) > 0);
    assert!(fts(&env, TOKEN) > 0);
    assert!(
        env.raw_contains(TOKEN),
        "the raw-bytes check must see the token before forgetting"
    );

    let (outcome, out) = env.forget(forget_url("https://ZQXFORGETTOKEN.example.com/docs/#intro"));
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(
        out.contains("Deleted 1 record(s), 1 result row(s), 3 injection log entries"),
        "{out}"
    );
    assert!(
        out.contains("Removed the URL from 1 kept record(s)."),
        "{out}"
    );
    assert!(
        out.contains("Tombstoned 1 tool_use id(s) and 1 URL hash."),
        "{out}"
    );
    assert!(out.contains("Deleted 1 backup(s):"), "{out}");
    assert!(out.contains("Deleted 1 spool file(s)"), "{out}");
    env.assert_leftovers_gone();

    assert_eq!(mentions(&env, TOKEN), 0);
    assert_eq!(fts(&env, TOKEN), 0);
    assert!(!env.raw_contains(TOKEN));
    // The search record stays, without the URL, and is still found by its other words.
    assert!(env.exists("toolu_s1") && env.exists("toolu_f2"));
    assert_eq!(
        env.count(&format!(
            "SELECT COUNT(*) FROM result WHERE event_id = {s1}"
        )),
        1
    );
    assert!(fts(&env, "installation") == 1 && fts(&env, "crate") >= 1);
    let summary: String = env
        .conn()
        .query_row("SELECT summary FROM event WHERE id = ?1", [s1], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(
        summary.contains("[forgotten url]") && summary.contains("https://other.example.org/crate"),
        "{summary}"
    );
    // Only the unrelated injection is left.
    let refs: Vec<String> = {
        let conn = env.conn();
        let mut st = conn.prepare("SELECT ref FROM injection").unwrap();
        st.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(refs, ["aaaa0004"]);
    assert_eq!(env.count("SELECT COUNT(*) FROM outcome"), 1);
    // The tombstone holds the hash, not the URL.
    let norm = awm::normalize::norm_url(URL).unwrap();
    assert_eq!(
        env.count(&format!(
            "SELECT COUNT(*) FROM tombstone WHERE kind = 'url_hash' AND value = '{}'",
            sha256_hex(&norm)
        )),
        1
    );
    assert_eq!(
        env.count(
            "SELECT COUNT(*) FROM tombstone WHERE kind = 'tool_use_id' AND value = 'toolu_f1'"
        ),
        1
    );
    assert_eq!(env.count("SELECT COUNT(*) FROM meta WHERE key NOT IN ('consent.record', 'cutoff.query', 'cutoff.prompt', 'calibrated_at', 'calibrated_n')"), 0);

    let again = env.reimport();
    assert_eq!(again.records_inserted, 0, "{again:?}");
    assert!(again.skipped_tombstone >= 1, "{again:?}");
    assert!(!env.exists("toolu_f1"));
    assert_eq!(mentions(&env, TOKEN), 0);
    assert!(!env.raw_contains(TOKEN));
}

#[test]
fn forget_url_with_nothing_stored_only_adds_the_tombstone() {
    let env = Env::new();
    let before = env.count("SELECT COUNT(*) FROM event");
    let (outcome, out) = env.forget(forget_url("https://never.example.com/x"));
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert_eq!(env.count("SELECT COUNT(*) FROM event"), before);
    assert_eq!(
        env.count("SELECT COUNT(*) FROM tombstone WHERE kind = 'url_hash'"),
        1
    );
    assert_eq!(mentions(&env, "never.example.com"), 0);
}

#[test]
fn forget_rejects_text_that_is_not_a_url() {
    let env = Env::new();
    let err = env
        .run(false, "", |io| {
            Ok(forget::run_forget(&forget_url("not a url"), io))
        })
        .0
        .unwrap_err();
    assert!(err.to_string().contains("not a URL"), "{err}");
}

#[test]
fn forget_last_asks_on_a_terminal_and_deletes_the_newest_record() {
    let env = Env::new();
    let args = forget::Args {
        target: Some("last".into()),
        ..forget::Args::default()
    };
    let (outcome, out) = env.run(true, "n\n", |io| forget::run_forget(&args, io));
    assert_eq!(outcome, Outcome::Declined);
    assert!(
        out.contains("configuration file formats") && out.contains("Nothing changed."),
        "{out}"
    );
    assert!(env.exists("toolu_s2"));

    let (outcome, out) = env.run(true, "y\n", |io| forget::run_forget(&args, io));
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(
        out.contains("Forget 1 record(s) permanently? [y/N]"),
        "{out}"
    );
    assert!(!env.exists("toolu_s2"));
    assert_eq!(env.count("SELECT COUNT(*) FROM event"), 5);
    assert_eq!(fts(&env, "toml"), 0);
    assert!(!env.raw_contains("toml.example.io"));
    assert_eq!(env.reimport().records_inserted, 0);
    assert!(!env.exists("toolu_s2"));
}

#[test]
fn forget_id_removes_the_record_and_the_injections_it_triggered() {
    let env = Env::new();
    let f2 = env.id_of("toolu_f2");
    let s2 = env.id_of("toolu_s2");
    // An injection triggered by toolu_f2 (its fetch prompt is the trigger text).
    env.inject(
        "bbbb0001",
        NOW,
        Some("toolu_f2"),
        Some("what does the crate do"),
        "<awm-notes/>",
        &[s2],
    );
    let (outcome, out) = env.forget(forget::Args {
        id: Some(f2),
        yes: true,
        ..forget::Args::default()
    });
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(!env.exists("toolu_f2") && env.exists("toolu_s2"));
    assert_eq!(env.count("SELECT COUNT(*) FROM injection"), 0);
    assert_eq!(mentions(&env, "what does the crate do"), 0);
    assert!(!env.raw_contains("what does the crate do"));
    assert_eq!(env.reimport().records_inserted, 0);
    assert!(!env.exists("toolu_f2"));
}

#[test]
fn forget_ref_removes_exactly_the_records_of_that_injection() {
    let env = Env::new();
    let (f1, f2, s2, old_f) = (
        env.id_of("toolu_f1"),
        env.id_of("toolu_f2"),
        env.id_of("toolu_s2"),
        env.id_of("toolu_old_f"),
    );
    env.inject(
        "cccc0001",
        NOW,
        Some("toolu_t1"),
        Some("a"),
        "<awm-notes/>",
        &[f1, f2],
    );
    env.inject(
        "cccc0002",
        NOW,
        Some("toolu_t2"),
        Some("b"),
        "<awm-notes/>",
        &[s2],
    );
    env.inject(
        "cccc0003",
        NOW,
        Some("toolu_t3"),
        Some("c"),
        "<awm-notes/>",
        &[old_f, f2],
    );
    let before: Vec<String> = all_ids(&env);
    let (outcome, out) = env.forget(forget::Args {
        ref_id: Some("cccc0001".into()),
        yes: true,
        ..forget::Args::default()
    });
    assert_eq!(outcome, Outcome::Done, "{out}");
    let after = all_ids(&env);
    let gone: Vec<&String> = before.iter().filter(|i| !after.contains(i)).collect();
    assert_eq!(gone, ["toolu_f1", "toolu_f2"]);
    assert_eq!(after.len(), 4);
    // cccc0003 showed toolu_f2 as well, so it goes; cccc0002 stays.
    assert_eq!(
        env.count("SELECT COUNT(*) FROM injection WHERE ref = 'cccc0002'"),
        1
    );
    assert_eq!(env.count("SELECT COUNT(*) FROM injection"), 1);
    assert_eq!(
        env.count("SELECT COUNT(*) FROM tombstone WHERE kind = 'tool_use_id' AND value IN ('toolu_f1', 'toolu_f2')"),
        2
    );
    assert_eq!(env.count("SELECT COUNT(*) FROM tombstone"), 2);
    assert_eq!(env.reimport().records_inserted, 0);
    assert_eq!(all_ids(&env), after);

    let err = env
        .run(false, "", |io| {
            Ok(forget::run_forget(
                &forget::Args {
                    ref_id: Some("ffffffff".into()),
                    yes: true,
                    ..forget::Args::default()
                },
                io,
            ))
        })
        .0
        .unwrap_err();
    assert!(err.to_string().contains("no injection with ref"), "{err}");
}

fn all_ids(env: &Env) -> Vec<String> {
    let conn = env.conn();
    let mut st = conn
        .prepare("SELECT tool_use_id FROM event ORDER BY tool_use_id")
        .unwrap();
    st.query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn purge_before_removes_old_rows_and_sets_purged_before_in_ms() {
    let env = Env::new();
    let old_s = env.id_of("toolu_old_s");
    let f1 = env.id_of("toolu_f1");
    let old = ms("2026-09-01") + 3_600_000;
    env.inject(
        "dddd0001",
        old,
        Some("toolu_old_x"),
        Some(&format!("{OLD_TOKEN} notes")),
        "<awm-notes/>",
        &[old_s],
    );
    // A newer injection that showed an old record goes too.
    env.inject(
        "dddd0002",
        NOW,
        Some("toolu_new_x"),
        Some("notes"),
        "<awm-notes/>",
        &[old_s, f1],
    );
    env.inject(
        "dddd0003",
        NOW,
        Some("toolu_new_y"),
        Some("install"),
        "<awm-notes/>",
        &[f1],
    );
    env.hook_run(old);
    env.hook_run(old + 1);
    env.hook_run(NOW);
    env.leftovers();
    assert!(env.raw_contains(OLD_TOKEN));

    let args = PurgeArgs {
        before: Some("2026-09-10".into()),
        yes: true,
        ..PurgeArgs::default()
    };
    let (outcome, out) = env.run(false, "", |io| forget::run_purge_with(&args, io));
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(
        out.contains(
            "Before 2026-09-10 (00:00 UTC): 2 record(s), 2 injection log entries, 2 hook run(s)."
        ),
        "{out}"
    );
    assert!(
        out.contains(
            "Deleted 2 record(s), 1 result row(s), 2 injection log entries and 2 hook run(s)."
        ),
        "{out}"
    );
    env.assert_leftovers_gone();

    assert!(!env.exists("toolu_old_s") && !env.exists("toolu_old_f"));
    assert_eq!(env.count("SELECT COUNT(*) FROM event"), 4);
    assert_eq!(env.count("SELECT COUNT(*) FROM injection"), 1);
    assert_eq!(env.count("SELECT COUNT(*) FROM hook_run"), 1);
    assert_eq!(mentions(&env, OLD_TOKEN), 0);
    assert_eq!(mentions(&env, "old.example.net"), 0);
    assert_eq!(fts(&env, OLD_TOKEN), 0);
    assert!(!env.raw_contains(OLD_TOKEN));
    assert!(!env.raw_contains("old.example.net"));
    let value: String = env
        .conn()
        .query_row(
            "SELECT value FROM meta WHERE key = 'purged_before'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(value, ms("2026-09-10").to_string());

    let again = env.reimport();
    assert_eq!(again.records_inserted, 0, "{again:?}");
    assert_eq!(again.skipped_tombstone, 2, "{again:?}");
    assert!(!env.raw_contains(OLD_TOKEN));

    // An earlier date never moves purged_before back.
    let args = PurgeArgs {
        before: Some("2026-08-01".into()),
        yes: true,
        ..PurgeArgs::default()
    };
    env.run(false, "", |io| forget::run_purge_with(&args, io));
    let value: String = env
        .conn()
        .query_row(
            "SELECT value FROM meta WHERE key = 'purged_before'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(value, ms("2026-09-10").to_string());
}

#[test]
fn purge_before_refuses_a_future_date_and_a_bad_date() {
    let env = Env::new();
    for date in ["2027-01-01", "2026-13-01", "yesterday"] {
        let args = PurgeArgs {
            before: Some(date.into()),
            yes: true,
            ..PurgeArgs::default()
        };
        let (r, _) = env.run(false, "", |io| Ok(forget::run_purge_with(&args, io)));
        assert!(r.is_err(), "{date}");
    }
    assert_eq!(env.count("SELECT COUNT(*) FROM event"), 6);
    assert_eq!(
        env.count("SELECT COUNT(*) FROM meta WHERE key = 'purged_before'"),
        0
    );
}

#[test]
fn purge_all_removes_the_directory() {
    let env = Env::new();
    env.leftovers();
    std::fs::write(env.data().join("awm.db.bak-v1.tmp"), "x").unwrap();
    let (code, out, err) = env.awm(&["purge", "--all", "--yes"]);
    assert_eq!(code, Some(0), "{out}{err}");
    assert!(
        out.contains(&format!("Data directory: {} (", env.data().display())),
        "{out}"
    );
    assert!(
        out.contains(&format!("Deleted {} (", env.data().display())),
        "{out}"
    );
    assert!(out.contains("6 records)."), "{out}");
    assert!(!env.data().exists());

    let (code, out, _) = env.awm(&["purge", "--all", "--yes"]);
    assert_eq!(code, Some(0));
    assert!(out.contains("nothing to delete"), "{out}");
}

#[test]
fn purge_all_keeps_files_awm_did_not_create() {
    let env = Env::new();
    std::fs::write(env.data().join("notes.txt"), "mine").unwrap();
    let (outcome, out) = env.run(true, "y\n", |io| {
        forget::purge_all(io, false, "awm purge --all")
    });
    assert_eq!(outcome.0, Outcome::Foreign, "{out}");
    assert_eq!(outcome.0.exit_code(), 2);
    assert!(out.contains("notes.txt"), "{out}");
    assert!(!out.contains("[y/N]"), "{out}");
    assert!(env.db_path().exists());
    assert!(env.data().join("notes.txt").exists());
}

#[test]
fn every_command_refuses_without_a_terminal_and_changes_nothing() {
    let env = Env::new();
    let f1 = env.id_of("toolu_f1");
    env.inject(
        "eeee0001",
        NOW,
        Some("toolu_t"),
        Some("x"),
        "<awm-notes/>",
        &[f1],
    );
    env.conn()
        .execute(
            "UPDATE event SET quarantined = 1 WHERE tool_use_id = 'toolu_f2'",
            [],
        )
        .unwrap();
    env.leftovers();
    let before = env.snapshot();
    let f1s = f1.to_string();
    let cases: Vec<Vec<&str>> = vec![
        vec!["forget", "last"],
        vec!["forget", URL],
        vec!["forget", "--id", &f1s],
        vec!["forget", "--ref", "eeee0001"],
        vec!["purge", "--before", "2026-09-10"],
        vec!["purge", "--all"],
        vec!["quarantine", &f1s],
        vec!["quarantine", URL],
        vec!["unquarantine", "https://other.example.org/crate"],
        vec!["uninstall"],
    ];
    for args in cases {
        let (code, out, err) = env.awm(&args);
        assert_eq!(code, Some(2), "{args:?}: {out}{err}");
        assert!(
            out.contains("No terminal for confirmation; nothing changed. Re-run with --yes"),
            "{args:?}: {out}"
        );
        assert_eq!(env.snapshot(), before, "{args:?}");
        assert!(env.data().join("awm.db.bak-v1").exists(), "{args:?}");
        assert_eq!(
            std::fs::read_dir(env.data().join("spool")).unwrap().count(),
            1
        );
    }
    assert!(!env.awm(&["uninstall"]).1.contains("To finish:"));
}

#[test]
fn quarantine_makes_matching_skip_the_record_until_unquarantine() {
    let env = Env::new();
    let norm = awm::normalize::norm_url(URL).unwrap();
    let hits = |env: &Env| {
        matching::url_channel(
            &env.conn(),
            &norm,
            &MatchOpts {
                limit: 3,
                ..MatchOpts::default()
            },
        )
        .unwrap()
        .len()
    };
    assert_eq!(hits(&env), 1);
    let q = QuarantineArgs {
        target: URL.into(),
        yes: true,
    };
    let (outcome, out) = env.run(false, "", |io| forget::run_quarantine_with(&q, true, io));
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(out.contains("Quarantined 1 record(s)."), "{out}");
    assert_eq!(hits(&env), 0);
    assert_eq!(
        env.count("SELECT COUNT(*) FROM event WHERE quarantined = 1 AND quarantine_reason = 'awm quarantine'"),
        1
    );
    let (outcome, _) = env.run(false, "", |io| forget::run_quarantine_with(&q, true, io));
    assert_eq!(outcome, Outcome::Nothing);

    let id = env.id_of("toolu_f1").to_string();
    let u = QuarantineArgs {
        target: id,
        yes: false,
    };
    let (outcome, out) = env.run(true, "y\n", |io| forget::run_quarantine_with(&u, false, io));
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(out.contains("Unquarantine 1 record(s)? [y/N]"), "{out}");
    assert_eq!(hits(&env), 1);
    assert_eq!(
        env.count(
            "SELECT COUNT(*) FROM event WHERE quarantined = 1 OR quarantine_reason IS NOT NULL"
        ),
        0
    );
}

#[test]
fn review_x_quarantines_the_record_behind_the_note() {
    let env = Env::new();
    let f1 = env.id_of("toolu_f1");
    let f2 = env.id_of("toolu_f2");
    let conn = env.conn();
    conn.execute_batch(&format!(
        "INSERT INTO injection (ref, created_at, hook, channel, mode, session_id, rendered_chars, latency_ms) \
         VALUES ('ffff0001', {NOW}, 'PostToolUse', 'url', 'inject', 'sess-later', 0, 1); \
         INSERT INTO injection_item (injection_id, position, event_id, score) \
         VALUES (last_insert_rowid(), 1, {f1}, 1.0), (last_insert_rowid(), 2, {f2}, 1.0);"
    ))
    .unwrap();
    let mut out = Vec::new();
    awm::cli::review::run_with(&conn, 10, &mut "x\n2\n".as_bytes(), &mut out).unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains(&format!("Quarantined record #{f1}.")), "{out}");
    assert!(out.contains("Labelled 1 of 2 items."), "{out}");
    let q: Vec<(i64, i64)> = {
        let mut st = conn
            .prepare("SELECT id, quarantined FROM event WHERE id IN (?1, ?2) ORDER BY id")
            .unwrap();
        st.query_map([f1, f2], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(q, [(f1, 1), (f2, 0)]);
    assert_eq!(env.count("SELECT COUNT(*) FROM outcome"), 1);
}

#[test]
fn uninstall_deletes_the_data_dir_and_prints_the_remaining_steps() {
    let env = Env::new();
    let home = env.root.join("home");
    let exe = home.join(".local/bin/awm");
    let args = awm::cli::uninstall::Args { yes: true };
    let (outcome, out) = env.run(false, "", |io| {
        awm::cli::uninstall::run_with(&args, io, Some(&exe), Some(&home))
    });
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(!env.data().exists());
    let tail: Vec<&str> = out
        .lines()
        .skip_while(|l| !l.starts_with("Deleted "))
        .collect();
    assert!(
        tail[0].starts_with(&format!("Deleted {} (", env.data().display())),
        "{out}"
    );
    assert!(tail[0].ends_with(", 6 records)."), "{out}");
    assert_eq!(
        tail[1..],
        [
            "To finish:",
            "  claude plugin uninstall agent-web-memory@agent-web-memory",
            "  claude plugin marketplace remove agent-web-memory",
            "  rm ~/.local/bin/awm",
        ]
    );
}

#[test]
fn uninstall_names_the_binary_removal_for_the_install_method() {
    use awm::cli::uninstall::binary_removal;
    let home = Path::new("/Users/me");
    let cases = [
        ("/opt/homebrew/bin/awm", "brew uninstall awm"),
        ("/usr/local/Cellar/awm/0.1.0/bin/awm", "brew uninstall awm"),
        (
            "/Users/me/.cargo/bin/awm",
            "cargo uninstall agent-web-memory",
        ),
        ("/Users/me/.local/bin/awm", "rm ~/.local/bin/awm"),
        ("/usr/local/bin/awm", "rm /usr/local/bin/awm"),
    ];
    for (exe, want) in cases {
        assert_eq!(
            binary_removal(Some(Path::new(exe)), Some(home)),
            want,
            "{exe}"
        );
    }
    assert_eq!(binary_removal(None, None), "rm ~/.local/bin/awm");
}

// ---------------------------------------------------------------------------
// F2: RV3 B1-B4 and minors

fn capture_opts(env: &Env, now_ms: i64) -> awm::capture::CaptureOpts {
    awm::capture::CaptureOpts {
        data_dir: env.data(),
        config: Config::default(),
        now_ms,
    }
}

fn hook_fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/hooks")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn search_payload(id: &str, query: &str, results: Value, summary: &str) -> Value {
    json!({
        "session_id": "sess-hook", "cwd": "/work/forget", "hook_event_name": "PostToolUse",
        "tool_name": "WebSearch", "tool_use_id": id,
        "tool_input": {"query": query},
        "tool_response": {"query": query, "results": [
            {"tool_use_id": "srvtoolu_9", "content": results}, summary], "durationSeconds": 1.0}
    })
}

fn fetch_payload(id: &str, url: &str, prompt: &str, answer: &str) -> Value {
    json!({
        "session_id": "sess-hook", "cwd": "/work/forget", "hook_event_name": "PostToolUse",
        "tool_name": "WebFetch", "tool_use_id": id,
        "tool_input": {"url": url, "prompt": prompt},
        "tool_response": {"bytes": 10, "code": 200, "result": answer, "url": url, "durationMs": 5}
    })
}

/// `(rank, url_norm, title)` of a record's result rows.
fn results_of(env: &Env, tool_use_id: &str) -> Vec<(i64, String, String)> {
    let conn = env.conn();
    let mut st = conn
        .prepare(
            "SELECT r.rank, r.url_norm, COALESCE(r.title, '') FROM result r \
             JOIN event e ON e.id = r.event_id WHERE e.tool_use_id = ?1 ORDER BY r.rank",
        )
        .unwrap();
    st.query_map([tool_use_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn match_text_of(env: &Env, tool_use_id: &str) -> String {
    env.conn()
        .query_row(
            "SELECT match_text FROM event WHERE tool_use_id = ?1",
            [tool_use_id],
            |r| r.get(0),
        )
        .unwrap()
}

/// B1 (capture): a WebSearch captured after `forget <url>` keeps no result row
/// of the URL, the other rows are re-ranked 1..n and `match_text` drops its title.
#[test]
fn capture_after_forget_url_drops_the_search_result_row_of_the_url() {
    let env = Env::new();
    let forgotten = "https://sqlite.org/fts5.html";
    let (outcome, out) = env.forget(forget_url(forgotten));
    assert_eq!(outcome, Outcome::Done, "{out}");

    let payload = hook_fixture("PostToolUse-WebSearch-plugin-2.json");
    let id = payload["tool_use_id"].as_str().unwrap().to_string();
    let got = awm::capture::run(&payload, &capture_opts(&env, NOW)).unwrap();
    assert_eq!(got, awm::capture::CaptureOutcome::Captured);
    let rows = results_of(&env, &id);
    assert_eq!(rows.len(), 9, "{rows:?}");
    let norm = awm::normalize::norm_url(forgotten).unwrap();
    assert!(rows.iter().all(|r| r.1 != norm), "{rows:?}");
    let ranks: Vec<i64> = rows.iter().map(|r| r.0).collect();
    assert_eq!(ranks, (1..=9).collect::<Vec<i64>>());
    assert!(rows.iter().all(|r| r.2 != "SQLite FTS5 Extension"));
    let mt = match_text_of(&env, &id);
    assert!(!mt.contains("SQLite FTS5 Extension"), "{mt}");
    assert!(mt.contains("SQLite User Forum"), "{mt}");
    assert_eq!(mentions(&env, "sqlite.org/fts5.html"), 0);

    // A search that lists only forgotten URLs is skipped, as an all-private one is.
    let only = search_payload(
        "toolu_hook_only",
        "fts5 extension docs",
        json!([{"title": "SQLite FTS5 Extension", "url": "https://SQLITE.org/fts5.html#x"}]),
        "One result.",
    );
    let got = awm::capture::run(&only, &capture_opts(&env, NOW)).unwrap();
    assert_eq!(got, awm::capture::CaptureOutcome::Skipped("tombstone"));
    assert!(!env.exists("toolu_hook_only"));
}

/// B1 (import): a new transcript WebSearch that lists a forgotten URL is stored
/// without that row; one that lists only forgotten URLs is skipped.
#[test]
fn import_after_forget_url_drops_the_search_result_row_of_the_url() {
    let env = Env::new();
    let (outcome, out) = env.forget(forget_url(URL));
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert_eq!(mentions(&env, TOKEN), 0);

    let mut more = search(
        "2026-09-22T10:00:00.000Z",
        "toolu_s_new",
        "crate setup walkthrough",
        json!([
            {"title": "Walkthrough", "url": "https://walk.example.org/a"},
            {"title": format!("{TOKEN} guide"), "url": "https://ZQXFORGETTOKEN.example.com/docs/"},
            {"title": "Setup notes", "url": "https://setup.example.org/b"}
        ]),
        "The walkthrough and the setup notes cover it.",
    );
    more += &search(
        "2026-09-22T10:01:00.000Z",
        "toolu_s_only",
        "forgotten docs only",
        json!([{"title": format!("{TOKEN} docs"), "url": URL}]),
        "One result.",
    );
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(env.transcript())
        .unwrap();
    f.write_all(more.as_bytes()).unwrap();
    drop(f);

    let s = env.import();
    assert_eq!(s.records_inserted, 1, "{s:?}");
    assert_eq!(s.skipped_tombstone, 1, "{s:?}");
    assert!(env.exists("toolu_s_new") && !env.exists("toolu_s_only"));
    let rows = results_of(&env, "toolu_s_new");
    let urls: Vec<(i64, &str)> = rows.iter().map(|r| (r.0, r.1.as_str())).collect();
    assert_eq!(
        urls,
        [
            (
                1,
                awm::normalize::norm_url("https://walk.example.org/a")
                    .unwrap()
                    .as_str()
            ),
            (
                2,
                awm::normalize::norm_url("https://setup.example.org/b")
                    .unwrap()
                    .as_str()
            ),
        ]
    );
    assert!(!match_text_of(&env, "toolu_s_new").contains(TOKEN));
    assert_eq!(mentions(&env, TOKEN), 0);
    assert_eq!(fts(&env, TOKEN), 0);
    assert!(!env.raw_contains(TOKEN));
}

/// Answers `text` on the first read, after running `before` (B3: a record
/// stored while the question waits).
struct Answer<F: FnMut()> {
    before: Option<F>,
    text: &'static [u8],
}

impl<F: FnMut()> std::io::Read for Answer<F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::BufRead;
        let n = {
            let avail = self.fill_buf()?;
            let n = avail.len().min(buf.len());
            buf[..n].copy_from_slice(&avail[..n]);
            n
        };
        self.consume(n);
        Ok(n)
    }
}

impl<F: FnMut()> std::io::BufRead for Answer<F> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if let Some(mut f) = self.before.take() {
            f();
        }
        Ok(self.text)
    }

    fn consume(&mut self, n: usize) {
        self.text = &self.text[n..];
    }
}

fn run_answering<T>(
    env: &Env,
    before: impl FnMut(),
    f: impl FnOnce(&mut Io<'_>) -> anyhow::Result<T>,
) -> (T, String) {
    let mut input = Answer {
        before: Some(before),
        text: b"y\n",
    };
    let mut out = Vec::new();
    let r = {
        let mut io = Io {
            data_dir: env.data(),
            terminal: true,
            input: &mut input,
            out: &mut out,
            now_ms: NOW,
        };
        f(&mut io).unwrap()
    };
    (r, String::from_utf8(out).unwrap())
}

/// B3 (RV3 E8): a WebFetch of the URL stored while `forget <url>` waits for
/// its answer is deleted too.
#[test]
fn forget_url_also_deletes_a_record_stored_while_the_question_waited() {
    let env = Env::new();
    let race = "zqxracetoken";
    let opts = capture_opts(&env, NOW + 1);
    let args = forget::Args {
        target: Some(URL.into()),
        ..forget::Args::default()
    };
    let (outcome, out) = run_answering(
        &env,
        || {
            let p = fetch_payload(
                "toolu_race_f",
                "https://ZQXFORGETTOKEN.example.com/docs",
                &format!("{race} what is new"),
                &format!("The {race} release."),
            );
            assert_eq!(
                awm::capture::run(&p, &opts).unwrap(),
                awm::capture::CaptureOutcome::Captured
            );
        },
        |io| forget::run_forget(&args, io),
    );
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(
        !env.exists("toolu_race_f") && !env.exists("toolu_f1"),
        "{out}"
    );
    assert!(out.contains("Deleted 2 record(s)"), "{out}");
    assert_eq!(
        env.count("SELECT COUNT(*) FROM tombstone WHERE value = 'toolu_race_f'"),
        1
    );
    for token in [TOKEN, race] {
        assert_eq!(mentions(&env, token), 0, "{token}");
        assert_eq!(fts(&env, token), 0, "{token}");
        assert!(!env.raw_contains(token), "{token}");
    }
}

/// B3: a record older than the date stored while `purge --before` waits is deleted too.
#[test]
fn purge_before_also_deletes_a_record_stored_while_the_question_waited() {
    let env = Env::new();
    let race = "zqxoldracetoken";
    let opts = capture_opts(&env, ms("2026-09-02"));
    let args = PurgeArgs {
        before: Some("2026-09-10".into()),
        ..PurgeArgs::default()
    };
    let (outcome, out) = run_answering(
        &env,
        || {
            let p = fetch_payload(
                "toolu_old_race",
                "https://old.example.net/race",
                &format!("{race} notes"),
                "Old.",
            );
            assert_eq!(
                awm::capture::run(&p, &opts).unwrap(),
                awm::capture::CaptureOutcome::Captured
            );
        },
        |io| forget::run_purge_with(&args, io),
    );
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(!env.exists("toolu_old_race"), "{out}");
    assert!(out.contains("Deleted 3 record(s)"), "{out}");
    assert_eq!(mentions(&env, race), 0);
    assert_eq!(fts(&env, race), 0);
    assert!(!env.raw_contains(race));
}

/// B3: `forget --id` keeps the confirmed set; a record stored meanwhile stays.
#[test]
fn forget_id_deletes_only_the_confirmed_record() {
    let env = Env::new();
    let f1 = env.id_of("toolu_f1");
    let opts = capture_opts(&env, NOW + 1);
    let args = forget::Args {
        id: Some(f1),
        ..forget::Args::default()
    };
    let (outcome, out) = run_answering(
        &env,
        || {
            let p = fetch_payload("toolu_meanwhile", URL, "again", "Same page.");
            awm::capture::run(&p, &opts).unwrap();
        },
        |io| forget::run_forget(&args, io),
    );
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(!env.exists("toolu_f1") && env.exists("toolu_meanwhile"));
}

/// Raw bytes of `awm.db` and `awm.db-wal` as they are, without a checkpoint.
fn raw_now_contains(env: &Env, token: &str) -> bool {
    let needle = token.as_bytes();
    ["awm.db", "awm.db-wal"].iter().any(|name| {
        std::fs::read(env.data().join(name))
            .is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle))
    })
}

/// B4 (RV3 E5a): with another idle connection open, only `forget`'s own
/// `wal_checkpoint(TRUNCATE)` gets the old pages out of `awm.db` and `awm.db-wal`.
#[test]
fn forget_url_scrubs_the_files_while_another_connection_is_open() {
    let env = Env::new();
    let idle = env.conn();
    let _: i64 = idle
        .query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0))
        .unwrap();
    assert!(raw_now_contains(&env, TOKEN));
    let (outcome, out) = env.forget(forget_url(URL));
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(!out.contains("Warning"), "{out}");
    assert!(
        !raw_now_contains(&env, TOKEN),
        "awm.db or awm.db-wal still holds the token while another connection is open"
    );
    drop(idle);
}

/// m1 (RV3 E5b): a reader holds a transaction, so the checkpoint is busy; the
/// warning names both files and says when to re-run.
#[test]
fn forget_warns_about_both_files_when_the_checkpoint_is_busy() {
    let env = Env::new();
    let reader = env.conn();
    reader.execute_batch("BEGIN").unwrap();
    let _: i64 = reader
        .query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0))
        .unwrap();
    let (outcome, out) = env.forget(forget_url(URL));
    reader.execute_batch("COMMIT").unwrap();
    drop(reader);
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(out.contains("awm.db and awm.db-wal"), "{out}");
    assert!(out.contains("no Claude Code session is active"), "{out}");
    assert!(out.contains(&format!("awm forget '{URL}' --yes")), "{out}");
}

/// m2: a failure after the commit (here FTS `optimize`) still deletes backups
/// and spool files, prints what was deleted, then reports the error.
#[test]
fn a_failure_after_the_commit_still_deletes_backups_and_spool_files() {
    let env = Env::new();
    env.leftovers();
    // `optimize` rewrites the index into one segment and deletes the old ones;
    // the transaction itself only adds a segment.
    env.conn()
        .execute_batch(
            "CREATE TRIGGER fail_optimize BEFORE DELETE ON event_fts_data \
             WHEN EXISTS (SELECT 1 FROM tombstone WHERE kind = 'url_hash') \
             BEGIN SELECT RAISE(ABORT, 'injected optimize failure'); END;",
        )
        .unwrap();
    let mut out = Vec::new();
    let r = {
        let mut input: &[u8] = b"";
        let mut io = Io {
            data_dir: env.data(),
            terminal: false,
            input: &mut input,
            out: &mut out,
            now_ms: NOW,
        };
        forget::run_forget(&forget_url(URL), &mut io)
    };
    let out = String::from_utf8(out).unwrap();
    let err = r.expect_err(&out);
    // The injected failure hit `optimize`, after the commit.
    assert!(
        !env.exists("toolu_f1"),
        "the deletion was committed: {err:#}"
    );
    assert!(format!("{err:#}").contains("constraint failed"), "{err:#}");
    env.assert_leftovers_gone();
    assert!(out.contains("Deleted 1 record(s)"), "{out}");
    assert!(out.contains("Deleted 1 backup(s)"), "{out}");
}

/// m5 (RV3 E7f): a `spool` symlinked outside the data dir is not followed, and
/// only `*.json` files are deleted from a real spool dir.
#[test]
fn cleanup_skips_a_symlinked_spool_and_files_that_are_not_json() {
    let env = Env::new();
    let outside = env.root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("victim.json"), "{}").unwrap();
    std::os::unix::fs::symlink(&outside, env.data().join("spool")).unwrap();
    let (outcome, out) = env.forget(forget_url(URL));
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(outside.join("victim.json").exists(), "{out}");
    assert!(out.contains("Deleted 0 spool file(s)"), "{out}");

    std::fs::remove_file(env.data().join("spool")).unwrap();
    std::fs::create_dir(env.data().join("spool")).unwrap();
    std::fs::write(env.data().join("spool/1-toolu_a.json"), "{}").unwrap();
    std::fs::write(env.data().join("spool/keep.txt"), "mine").unwrap();
    let (outcome, out) = env.forget(forget_url("https://other.example.org/crate"));
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(!env.data().join("spool/1-toolu_a.json").exists());
    assert!(env.data().join("spool/keep.txt").exists());
    assert!(out.contains("Deleted 1 spool file(s)"), "{out}");
}

/// m9: the output says what deleting spool files means.
#[test]
fn deleting_spool_files_says_import_reads_them_again() {
    let env = Env::new();
    env.leftovers();
    let (outcome, out) = env.forget(forget_url(URL));
    assert_eq!(outcome, Outcome::Done, "{out}");
    assert!(out.contains("Deleted 1 spool file(s)"), "{out}");
    assert!(out.contains("pending captures"), "{out}");
    assert!(out.contains("awm import"), "{out}");
}

/// m6: when no record is deleted but kept search records change, the question says so.
#[test]
fn forget_url_question_names_the_kept_search_records() {
    let env = Env::new();
    let f1 = env.id_of("toolu_f1");
    env.forget(forget::Args {
        id: Some(f1),
        yes: true,
        ..forget::Args::default()
    });
    let args = forget::Args {
        target: Some(URL.into()),
        ..forget::Args::default()
    };
    let (outcome, out) = env.run(true, "n\n", |io| forget::run_forget(&args, io));
    assert_eq!(outcome, Outcome::Declined, "{out}");
    assert!(!out.contains("Forget 0 record(s)"), "{out}");
    assert!(
        out.contains("Remove it from 1 kept search record(s)"),
        "{out}"
    );
}

/// m7: the re-run hint quotes the target for a POSIX shell.
#[test]
fn the_rerun_hint_quotes_a_url_with_a_single_quote() {
    let env = Env::new();
    let (code, out, err) = env.awm(&["forget", "https://q.example.com/it's"]);
    assert_eq!(code, Some(2), "{out}{err}");
    assert!(
        out.contains(r"Re-run with --yes: awm forget 'https://q.example.com/it'\''s' --yes"),
        "{out}"
    );
}

/// B2 (RV3 E7a): foreign entries in the data dir stop `purge --all` before it deletes anything.
#[test]
fn purge_all_deletes_nothing_when_the_dir_holds_foreign_entries() {
    let env = Env::new();
    env.leftovers();
    std::fs::write(env.data().join("notes.txt"), "mine").unwrap();
    std::fs::write(
        env.data().join("config.toml"),
        "[package]\nname = \"mine\"\n",
    )
    .unwrap();
    std::fs::write(env.data().join("spool/precious.txt"), "mine").unwrap();
    for args in [
        &["purge", "--all", "--yes"][..],
        &["uninstall", "--yes"][..],
    ] {
        let (code, out, err) = env.awm(args);
        assert_eq!(code, Some(2), "{args:?}: {out}{err}");
        for name in ["notes.txt", "config.toml", "spool/precious.txt"] {
            assert!(out.contains(name), "{args:?}: {out}");
        }
        assert!(!out.contains("To finish:"), "{out}");
        assert!(env.db_path().exists());
        assert!(env.data().join("awm.db.bak-v1").exists());
        assert!(env.data().join("notes.txt").exists());
        assert_eq!(
            std::fs::read_to_string(env.data().join("config.toml")).unwrap(),
            "[package]\nname = \"mine\"\n"
        );
        assert!(env.data().join("spool/precious.txt").exists());
        assert!(env.data().join("spool/1790000000000-toolu_x.json").exists());
    }
}

/// B2 (RV3 E7b): symlinked `spool` and backup are removed as links; their targets stay.
#[test]
fn purge_all_removes_symlinks_but_not_their_targets() {
    let env = Env::new();
    let outside = env.root.join("outside");
    std::fs::create_dir_all(outside.join("spooldir")).unwrap();
    std::fs::write(outside.join("spooldir/precious.txt"), "mine").unwrap();
    std::fs::write(outside.join("spooldir/x.json"), "{}").unwrap();
    std::fs::write(outside.join("backup"), "mine").unwrap();
    std::os::unix::fs::symlink(outside.join("spooldir"), env.data().join("spool")).unwrap();
    std::os::unix::fs::symlink(outside.join("backup"), env.data().join("awm.db.bak-v1")).unwrap();
    // An awm config file is ours.
    std::fs::write(
        env.data().join("config.toml"),
        "mode = \"shadow\"\n\n[inject]\nmax_notes = 2\n",
    )
    .unwrap();
    let (code, out, err) = env.awm(&["purge", "--all", "--yes"]);
    assert_eq!(code, Some(0), "{out}{err}");
    assert!(!env.data().exists(), "{out}");
    assert!(outside.join("spooldir/precious.txt").exists());
    assert!(outside.join("spooldir/x.json").exists());
    assert_eq!(
        std::fs::read_to_string(outside.join("backup")).unwrap(),
        "mine"
    );
}

// ---------------------------------------------------------------------------
// QP: usage samples in `quota/` (plan-quota §5.2)

impl Env {
    fn quota(&self) -> PathBuf {
        self.data().join("quota")
    }

    /// A config with a `[quota]` table, a spool file and two sample files.
    fn with_quota_samples(&self) {
        std::fs::write(
            self.data().join("config.toml"),
            "mode = \"shadow\"\n\n[quota]\nretention_days = 30\n",
        )
        .unwrap();
        std::fs::create_dir_all(self.data().join("spool")).unwrap();
        std::fs::write(self.data().join("spool/x.json"), "{}").unwrap();
        std::fs::create_dir_all(self.quota()).unwrap();
        for m in ["2026-09", "2026-10"] {
            std::fs::write(self.quota().join(format!("samples-{m}.ndjson")), "{}\n").unwrap();
        }
    }
}

#[test]
fn purge_all_deletes_a_data_dir_with_quota_samples() {
    let env = Env::new();
    env.with_quota_samples();
    let (code, out, err) = env.awm(&["purge", "--all", "--yes"]);
    assert_eq!(code, Some(0), "{out}{err}");
    assert!(
        out.contains(&format!("Deleted {} (", env.data().display())),
        "{out}"
    );
    assert!(!env.data().exists(), "{out}");
}

#[test]
fn uninstall_deletes_quota_samples() {
    let env = Env::new();
    env.with_quota_samples();
    let (code, out, err) = env.awm(&["uninstall", "--yes"]);
    assert_eq!(code, Some(0), "{out}{err}");
    assert!(!env.data().exists(), "{out}");
    let tail: Vec<&str> = out
        .lines()
        .skip_while(|l| !l.starts_with("Deleted "))
        .skip(1)
        .collect();
    assert_eq!(tail.first(), Some(&"To finish:"), "{out}");
    assert!(
        tail.contains(&"  claude plugin uninstall agent-web-memory@agent-web-memory"),
        "{out}"
    );
}

#[test]
fn purge_all_deletes_an_empty_quota_dir() {
    let env = Env::new();
    std::fs::create_dir(env.quota()).unwrap();
    let (code, out, err) = env.awm(&["purge", "--all", "--yes"]);
    assert_eq!(code, Some(0), "{out}{err}");
    assert!(!env.data().exists(), "{out}");
}

#[test]
fn purge_all_refuses_an_unknown_file_inside_quota() {
    let env = Env::new();
    env.with_quota_samples();
    std::fs::write(env.quota().join("notes.txt"), "mine").unwrap();
    for args in [
        &["purge", "--all", "--yes"][..],
        &["uninstall", "--yes"][..],
    ] {
        let (code, out, err) = env.awm(args);
        assert_eq!(code, Some(2), "{args:?}: {out}{err}");
        assert!(
            out.contains("entries awm did not create: quota/notes.txt."),
            "{out}"
        );
        assert!(!out.contains("To finish:"), "{out}");
        assert!(env.db_path().exists());
        assert!(env.data().join("spool/x.json").exists());
        assert_eq!(
            std::fs::read_to_string(env.quota().join("notes.txt")).unwrap(),
            "mine"
        );
        for m in ["2026-09", "2026-10"] {
            assert!(env.quota().join(format!("samples-{m}.ndjson")).exists());
        }
    }
}

#[test]
fn purge_all_refuses_misnamed_files_and_directories_inside_quota() {
    type Make = fn(&Path, &Path);
    let cases: [(&str, Make); 4] = [
        ("samples-2026-13.ndjson", |q, _| {
            std::fs::write(q.join("samples-2026-13.ndjson"), "{}\n").unwrap()
        }),
        ("samples-2026-10.ndjson.tmp-1", |q, _| {
            std::fs::write(q.join("samples-2026-10.ndjson.tmp-1"), "{}\n").unwrap()
        }),
        ("samples-2026-08.ndjson", |q, _| {
            std::fs::create_dir(q.join("samples-2026-08.ndjson")).unwrap();
            std::fs::write(q.join("samples-2026-08.ndjson/inner"), "mine").unwrap();
        }),
        ("samples-2026-07.ndjson", |q, outside| {
            std::fs::write(outside, "mine").unwrap();
            std::os::unix::fs::symlink(outside, q.join("samples-2026-07.ndjson")).unwrap();
        }),
    ];
    for (name, make) in cases {
        let env = Env::new();
        env.with_quota_samples();
        let outside = env.root.join("samples-2026-07.ndjson");
        make(&env.quota(), &outside);
        let (code, out, err) = env.awm(&["purge", "--all", "--yes"]);
        assert_eq!(code, Some(2), "{name}: {out}{err}");
        assert!(
            out.contains(&format!("entries awm did not create: quota/{name}.")),
            "{name}: {out}"
        );
        assert!(env.db_path().exists(), "{name}");
        assert!(env.data().join("spool/x.json").exists(), "{name}");
        assert!(
            std::fs::symlink_metadata(env.quota().join(name)).is_ok(),
            "{name}"
        );
        for m in ["2026-09", "2026-10"] {
            assert!(
                env.quota().join(format!("samples-{m}.ndjson")).exists(),
                "{name}"
            );
        }
        if name == "samples-2026-08.ndjson" {
            assert!(env.quota().join("samples-2026-08.ndjson/inner").exists());
        }
        if name == "samples-2026-07.ndjson" {
            assert_eq!(std::fs::read_to_string(&outside).unwrap(), "mine");
        }
    }
}

#[test]
fn purge_all_removes_a_quota_symlink_but_not_its_target() {
    let env = Env::new();
    let outside = env.root.join("quotadir");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("samples-2026-10.ndjson"), "{}\n").unwrap();
    std::fs::write(outside.join("precious.txt"), "mine").unwrap();
    std::os::unix::fs::symlink(&outside, env.quota()).unwrap();
    let (code, out, err) = env.awm(&["purge", "--all", "--yes"]);
    assert_eq!(code, Some(0), "{out}{err}");
    assert!(!env.data().exists(), "{out}");
    assert_eq!(
        std::fs::read_to_string(outside.join("samples-2026-10.ndjson")).unwrap(),
        "{}\n"
    );
    assert_eq!(
        std::fs::read_to_string(outside.join("precious.txt")).unwrap(),
        "mine"
    );
}
