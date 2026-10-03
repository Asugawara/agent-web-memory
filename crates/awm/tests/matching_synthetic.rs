//! Matching on the 40-record synthetic corpus (plan-v2 §3.1, §3.6).

use std::path::Path;

use awm::capture::{self, CaptureOpts};
use awm::config::Config;
use awm::db::{self, Role};
use awm::matching::{self, calibrate, MatchOpts};
use awm::note::{Relation, Status, Tool};
use rusqlite::Connection;
use serde_json::Value;

fn load() -> (tempfile::TempDir, Connection) {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = db::open(&dir.path().join("awm.db"), Role::Cli).unwrap();
    db::migrate(&mut conn).unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus-synthetic.jsonl");
    for line in std::fs::read_to_string(path).unwrap().lines() {
        let payload: Value = serde_json::from_str(line).unwrap();
        let opts = CaptureOpts {
            data_dir: dir.path().to_path_buf(),
            config: Config::default(),
            now_ms: payload["awm_test_now_ms"].as_i64().unwrap(),
        };
        capture::run(&payload, &opts).unwrap();
    }
    (dir, conn)
}

fn opts() -> MatchOpts {
    MatchOpts {
        caller_session: "sess-x".to_string(),
        caller_cwd_hash: "none".to_string(),
        limit: 3,
        ..MatchOpts::default()
    }
}

fn id_of(conn: &Connection, tool_use_id: &str) -> i64 {
    conn.query_row(
        "SELECT id FROM event WHERE tool_use_id = ?1",
        [tool_use_id],
        |r| r.get(0),
    )
    .unwrap()
}

fn names(conn: &Connection, hits: &[matching::Hit]) -> Vec<String> {
    hits.iter()
        .map(|h| {
            conn.query_row(
                "SELECT tool_use_id FROM event WHERE id = ?1",
                [h.event_id],
                |r| r.get(0),
            )
            .unwrap()
        })
        .collect()
}

/// Cutoff of the tests: above the weak matches that stop-word-like tokens give.
const CUT: f64 = 5.0;

fn query_at(conn: &Connection, text: &str, cutoff: f64, o: &MatchOpts) -> Vec<String> {
    names(
        conn,
        &matching::query_channel(conn, text, cutoff, o).unwrap(),
    )
}

fn query(conn: &Connection, text: &str, o: &MatchOpts) -> Vec<String> {
    query_at(conn, text, CUT, o)
}

#[test]
fn corpus_loads_with_expected_statuses() {
    let (_d, c) = load();
    let n = |sql: &str| -> i64 { c.query_row(sql, [], |r| r.get(0)).unwrap() };
    assert_eq!(n("SELECT COUNT(*) FROM event"), 40);
    assert_eq!(n("SELECT COUNT(*) FROM event WHERE status = 'dead_end'"), 1);
    assert_eq!(n("SELECT COUNT(*) FROM event WHERE status = 'refusal'"), 1);
    assert_eq!(n("SELECT COUNT(*) FROM event WHERE quarantined = 1"), 0);
}

#[test]
fn twelve_queries_return_the_expected_ordered_results() {
    let (_d, c) = load();
    let cases: [(&str, &[&str]); 12] = [
        (
            "how do I size the tokio blocking thread pool",
            &["t01", "t29"],
        ),
        ("sqlite wal checkpoint busy timeout", &["t21", "t33"]),
        (
            "partial index in postgres with a where clause",
            &["t03", "t31"],
        ),
        ("kubernetes pod stuck in crashloopbackoff", &["t04", "t32"]),
        ("python asyncio gather with a timeout", &["t05"]),
        ("nginx limit_req burst nodelay", &["t08", "t34"]),
        ("git autosquash fixup commits", &["t09", "t35"]),
        ("css subgrid alignment", &["t10", "t37"]),
        (
            "redis streams pending entries consumer group",
            &["t11", "t36"],
        ),
        ("jwt refresh token rotation", &["t19"]),
        ("go context cancellation goroutine leak", &["t27", "t40"]),
        ("quantum chromodynamics lattice gauge", &[]),
    ];
    for (q, want) in cases {
        assert_eq!(query(&c, q, &opts()), want, "query: {q}");
    }
}

#[test]
fn rule1_never_the_callers_own_tool_use_id() {
    let (_d, c) = load();
    let mut o = opts();
    assert_eq!(
        query(&c, "sqlite wal checkpoint busy timeout", &o)[0],
        "t21"
    );
    o.caller_tool_use_id = Some("t21".to_string());
    let got = query(&c, "sqlite wal checkpoint busy timeout", &o);
    assert!(!got.contains(&"t21".to_string()), "{got:?}");
    assert_eq!(got[0], "t02");
    let url = matching::url_channel(&c, "https://sqlite.org/wal.html", &{
        let mut o = opts();
        o.caller_tool_use_id = Some("t33".to_string());
        o
    })
    .unwrap();
    assert_eq!(names(&c, &url), ["t30"]);
}

#[test]
fn rule2_never_the_callers_own_session_and_agent() {
    let (_d, c) = load();
    let mut o = opts();
    o.caller_session = "sess-a".to_string();
    o.exclude_same_agent = true;
    // sess-a main agent: its own records are out, the sess-a subagent's (t33) are in.
    let got = query(&c, "sqlite wal checkpoint busy timeout", &o);
    assert!(!got.contains(&"t21".to_string()), "{got:?}");
    assert!(got.contains(&"t02".to_string()));
    let url = matching::url_channel(&c, "https://sqlite.org/wal.html", &o).unwrap();
    assert_eq!(names(&c, &url), ["t33"]);
    // The subagent's view: its own record is out, the main agent's are in.
    o.caller_agent = Some("ag1".to_string());
    let got = query(&c, "docker multistage build cache mount", &o);
    assert!(!got.contains(&"t06".to_string()), "{got:?}");
    let url = matching::url_channel(&c, "https://sqlite.org/wal.html", &o).unwrap();
    assert_eq!(names(&c, &url), ["t30"]);
    // Off: nothing is excluded.
    o.exclude_same_agent = false;
    assert!(query(&c, "docker multistage build cache mount", &o).contains(&"t06".to_string()));
}

#[test]
fn rule3_never_quarantined_or_tombstoned_records() {
    let (_d, c) = load();
    c.execute(
        "UPDATE event SET quarantined = 1 WHERE tool_use_id = 't02'",
        [],
    )
    .unwrap();
    c.execute(
        "INSERT INTO tombstone (kind, value, created_at) VALUES ('tool_use_id', 't21', 0)",
        [],
    )
    .unwrap();
    let got = query(&c, "sqlite wal checkpoint busy timeout", &opts());
    assert!(
        !got.contains(&"t02".to_string()) && !got.contains(&"t21".to_string()),
        "{got:?}"
    );
    assert_eq!(got, ["t33"]);
    // A tombstoned URL hash hides every fetch of that URL, in both channels.
    c.execute(
        "INSERT INTO tombstone (kind, value, created_at) VALUES ('url_hash', ?1, 0)",
        [awm::record::sha256_hex("https://sqlite.org/wal.html")],
    )
    .unwrap();
    assert!(
        matching::url_channel(&c, "https://sqlite.org/wal.html", &opts())
            .unwrap()
            .is_empty()
    );
    let got = query(&c, "sqlite wal checkpoint busy timeout", &opts());
    assert!(
        !got.contains(&"t30".to_string()) && !got.contains(&"t33".to_string()),
        "{got:?}"
    );
}

#[test]
fn rule4_groups_by_url_norm_and_by_normalised_query() {
    let (_d, c) = load();
    // t30 and t33 share a url_norm (utm dropped); the newest, t33, is kept.
    let hits = matching::url_channel(&c, "https://sqlite.org/wal.html", &opts()).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(names(&c, &hits), ["t33"]);
    assert_eq!(hits[0].seen, 2);
    assert_eq!(hits[0].score, 1.0);
    // t02 and t21 are the same search after normalisation; the newest, t21, is kept.
    let hits =
        matching::query_channel(&c, "sqlite wal checkpoint busy timeout", 0.0, &opts()).unwrap();
    let first = &hits[0];
    assert_eq!(names(&c, &hits[..1]), ["t21"]);
    assert_eq!(first.seen, 2);
}

#[test]
fn rule5_never_a_shown_record_again() {
    let (_d, c) = load();
    let mut o = opts();
    o.shown_event_ids = vec![id_of(&c, "t21")];
    let got = query(&c, "sqlite wal checkpoint busy timeout", &o);
    // The group of t21 (t02, t21) counts as shown.
    assert!(
        !got.contains(&"t21".to_string()) && !got.contains(&"t02".to_string()),
        "{got:?}"
    );
    assert_eq!(got, ["t33"]);
    o.shown_event_ids = vec![id_of(&c, "t33")];
    assert!(matching::url_channel(&c, "https://sqlite.org/wal.html", &o)
        .unwrap()
        .is_empty());
}

#[test]
fn rule6_nothing_above_the_cutoff_is_nothing() {
    let (_d, c) = load();
    let hits =
        matching::query_channel(&c, "sqlite wal checkpoint busy timeout", 1e9, &opts()).unwrap();
    assert!(hits.is_empty());
    let best =
        matching::query_channel(&c, "sqlite wal checkpoint busy timeout", 0.0, &opts()).unwrap();
    let top = best[0].score;
    assert!(top > 0.0);
    // The cutoff is inclusive.
    let at =
        matching::query_channel(&c, "sqlite wal checkpoint busy timeout", top, &opts()).unwrap();
    assert_eq!(at.len(), 1);
    assert!(matching::query_channel(
        &c,
        "sqlite wal checkpoint busy timeout",
        top + 0.001,
        &opts()
    )
    .unwrap()
    .is_empty());
}

#[test]
fn limit_is_at_most_three_and_zero_gives_nothing() {
    let (_d, c) = load();
    let mut o = opts();
    let q = "how do I size the tokio blocking thread pool";
    o.limit = 10;
    assert_eq!(query_at(&c, q, 0.0, &o).len(), 3);
    o.limit = 1;
    assert_eq!(query_at(&c, q, 0.0, &o).len(), 1);
    o.limit = 0;
    assert!(query_at(&c, q, 0.0, &o).is_empty());
}

#[test]
fn query_channel_skips_dead_ends_and_refusals_but_url_channel_keeps_them() {
    let (_d, c) = load();
    let got = query(
        &c,
        "members area summarise page jwt json web token",
        &opts(),
    );
    assert!(
        !got.contains(&"t38".to_string()) && !got.contains(&"t39".to_string()),
        "{got:?}"
    );
    let hits = matching::url_channel(&c, "https://example.com/members/area", &opts()).unwrap();
    assert_eq!(names(&c, &hits), ["t38"]);
    let note = matching::to_note(&c, &hits[0], &opts()).unwrap();
    assert_eq!(note.status, Status::DeadEnd);
    assert_eq!(note.http_code, Some(403));
    let hits = matching::url_channel(&c, "https://jwt.io/introduction", &opts()).unwrap();
    assert_eq!(names(&c, &hits), ["t39"]);
}

#[test]
fn before_ms_only_returns_strictly_older_records() {
    let (_d, c) = load();
    let created: i64 = c
        .query_row(
            "SELECT created_at FROM event WHERE tool_use_id = 't21'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut o = opts();
    o.before_ms = Some(created);
    let got = query(&c, "sqlite wal checkpoint busy timeout", &o);
    assert!(
        !got.contains(&"t21".to_string()) && !got.contains(&"t33".to_string()),
        "{got:?}"
    );
    assert_eq!(got[0], "t02");
}

#[test]
fn to_note_sets_relation_and_search_url() {
    let (_d, c) = load();
    let mut o = opts();
    o.caller_session = "sess-a".to_string();
    o.caller_cwd_hash = awm::record::sha256_hex("/work/alpha");
    let note = |tool_use_id: &str, o: &MatchOpts| {
        let hit = matching::Hit {
            event_id: id_of(&c, tool_use_id),
            score: 2.5,
            seen: 0,
        };
        matching::to_note(&c, &hit, o).unwrap()
    };
    assert_eq!(note("t01", &o).relation, Relation::MainAgent);
    assert_eq!(
        note("t06", &o).relation,
        Relation::OtherSubagent {
            agent_type: "researcher".to_string()
        }
    );
    assert_eq!(note("t02", &o).relation, Relation::SameProject);
    assert_eq!(note("t03", &o).relation, Relation::OtherProject);
    let n = note("t01", &o);
    assert_eq!(n.tool, Tool::WebSearch);
    assert_eq!(n.seen, 1);
    assert_eq!(n.score, 2.5);
    assert_eq!(n.url.as_deref(), Some("https://docs.example.org/tokio/0"));
    assert_eq!(
        n.searched.as_deref(),
        Some("tokio spawn_blocking blocking thread pool size")
    );
    let f = note("t30", &o);
    assert_eq!(f.tool, Tool::WebFetch);
    assert_eq!(f.url.as_deref(), Some("https://sqlite.org/wal.html"));
    assert_eq!(
        f.asked.as_deref(),
        Some("when does checkpoint starvation happen")
    );
    // A search whose result URLs all fail url_ok has no URL.
    c.execute(
        "UPDATE result SET url = 'http://x.test/p' WHERE event_id = ?1",
        [id_of(&c, "t01")],
    )
    .unwrap();
    assert_eq!(note("t01", &o).url, None);
}

#[test]
fn prompt_url_channel_merges_two_urls_and_dedupes() {
    let (_d, c) = load();
    let prompt = "compare https://sqlite.org/wal.html?utm_medium=x, and (https://git-scm.com/docs/git-rebase). \
                  Again https://sqlite.org/wal.html";
    let hits = matching::prompt_url_channel(&c, prompt, &opts()).unwrap();
    // t33 (15 h ago) before t35 (205 h ago).
    assert_eq!(names(&c, &hits), ["t33", "t35"]);
    assert!(matching::prompt_url_channel(&c, "no links here", &opts())
        .unwrap()
        .is_empty());
    assert!(
        matching::prompt_url_channel(&c, "http://sqlite.org/wal.html", &opts())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn calibration_defaults_below_fifty_records_and_median_above() {
    let (_d, c) = load();
    // 40 records: defaults.
    let cal = calibrate::run(&c).unwrap();
    assert_eq!(cal.n, 40);
    assert_eq!(cal.cutoff_query, 42.0);
    assert_eq!(cal.cutoff_query_deny, 55.0);
    assert_eq!(calibrate::cutoff_query_deny(&c).unwrap(), 55.0);
    assert_eq!(cal.cutoff_prompt, Some(49.0));
    let (n, cut): (String, String) = c
        .query_row(
            "SELECT (SELECT value FROM meta WHERE key = 'calibrated_n'), \
                    (SELECT value FROM meta WHERE key = 'cutoff.query')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((n.as_str(), cut.as_str()), ("40", "42"));
    assert!(!calibrate::should_recalibrate(&c).unwrap());
    // Copy the corpus under new ids until there are 100 records: the median is measured.
    c.execute_batch(
        "INSERT INTO event (tool_use_id, tool, session_id, agent_id, agent_type, cwd_hash, created_at, \
           query, url, url_norm, fetch_prompt, http_code, status, summary, match_text, source) \
         SELECT tool_use_id || 'x', tool, session_id, agent_id, agent_type, cwd_hash, created_at + 1000, \
           query, url, url_norm, fetch_prompt, http_code, status, summary, match_text, source FROM event;",
    )
    .unwrap();
    c.execute_batch(
        "INSERT INTO event (tool_use_id, tool, session_id, agent_id, agent_type, cwd_hash, created_at, \
           query, url, url_norm, fetch_prompt, http_code, status, summary, match_text, source) \
         SELECT tool_use_id || 'y', tool, session_id, agent_id, agent_type, cwd_hash, created_at + 2000, \
           query, url, url_norm, fetch_prompt, http_code, status, summary, match_text, source FROM event \
         WHERE tool_use_id NOT LIKE '%x' LIMIT 20;",
    )
    .unwrap();
    assert!(calibrate::should_recalibrate(&c).unwrap());
    let cal = calibrate::run(&c).unwrap();
    assert_eq!(cal.n, 100);
    assert!(
        cal.cutoff_query > 0.0 && cal.cutoff_query != 42.0,
        "{cal:?}"
    );
    // The deny cutoff is the 75th percentile of the same scores: stored, and not below the median.
    assert!(
        cal.cutoff_query_deny >= cal.cutoff_query && cal.cutoff_query_deny != 55.0,
        "{cal:?}"
    );
    assert_eq!(
        calibrate::cutoff_query_deny(&c).unwrap(),
        cal.cutoff_query_deny
    );
    assert!(!calibrate::should_recalibrate(&c).unwrap());
    // The prompt cutoff is the 75th percentile and survives recalibration.
    calibrate::set_prompt_cutoff(&c, &[10.0, 20.0, 30.0, 40.0, 50.0]).unwrap();
    assert_eq!(calibrate::run(&c).unwrap().cutoff_prompt, Some(40.0));
    calibrate::set_prompt_cutoff(&c, &[]).unwrap();
    assert_eq!(calibrate::cutoff_prompt(&c).unwrap(), 40.0);
}
