//! What the existing commands gain in a team (plan-v3-team §4.9, §3.8, §4.7; TM14).
//!
//! Run: `cargo test -p agent-web-memory --features sync --test cli_team_existing`.
//!
//! Every test drives the built `awm` binary against a seeded database with local and team rows.
//! No network: a team machine is two files (`team.toml`, `team.key`) that name a closed port.

#![cfg(feature = "sync")]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use awm::db::{self, Role};
use awm::sync::state::{self, EpochKeyEntry, TeamKey, TeamToml};
use awm_proto::wire::{Id, Key32};
use rusqlite::{params, Connection};
use serde_json::{json, Value};

const BASE: i64 = 1_790_000_000_000;
const ALF: &str = "00000000-0000-4000-8000-0000000000a1";
const TEAM_SESSION: &str = "team:00000000-0000-4000-8000-0000000000a1";
const ME: &str = "00000000-0000-4000-8000-0000000000b2";

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

    fn json(&self, args: &[&str]) -> Value {
        serde_json::from_str(self.awm(args).ok()).unwrap()
    }

    /// Puts this machine in a team whose server is a closed port: `team.toml` and `team.key`.
    fn join_offline(&self, share_stats: bool) {
        let dir = self.awm_home();
        TeamToml {
            server_url: "http://127.0.0.1:9".into(),
            org_id: Id::new_v4(),
            member_id: Id::parse(ME).unwrap(),
            handle: "me".into(),
            device_id: Id::new_v4(),
            ca_file: None,
        }
        .save(&dir)
        .unwrap();
        TeamKey {
            device_token: "awm_t_TOKENSECRET_never_printed".into(),
            previous_device_token: None,
            device_secret: Key32([7; 32]),
            epoch_keys: vec![EpochKeyEntry {
                epoch: 0,
                key: Key32([9; 32]),
            }],
            pending_invites: Vec::new(),
            extra: Default::default(),
        }
        .save(&dir)
        .unwrap();
        if share_stats {
            std::fs::write(dir.join("config.toml"), "[team]\nshare_stats = true\n").unwrap();
        }
    }
}

impl Out {
    #[track_caller]
    fn ok(&self) -> &str {
        assert_eq!(self.code, Some(0), "stderr: {}", self.stderr);
        &self.stdout
    }
}

// ---------------------------------------------------------------------------------------------
// Seeding

struct Ev<'a> {
    id: i64,
    tool: &'a str,
    session: &'a str,
    at: i64,
    query: Option<&'a str>,
    url: Option<&'a str>,
    origin: &'a str,
    member: Option<&'a str>,
    duration_ms: Option<i64>,
    chars: usize,
    bytes: Option<i64>,
}

fn fetch<'a>(id: i64, url: &'a str, session: &'a str, at: i64) -> Ev<'a> {
    Ev {
        id,
        tool: "WebFetch",
        session,
        at,
        query: None,
        url: Some(url),
        origin: "local",
        member: None,
        duration_ms: None,
        chars: 0,
        bytes: None,
    }
}

fn insert(conn: &Connection, e: &Ev) {
    let text = e.query.or(e.url).unwrap_or("");
    let summary = if e.chars > 0 {
        "x".repeat(e.chars)
    } else {
        "Weights are passed as extra arguments to bm25.".to_string()
    };
    let team = e.origin == "team";
    conn.execute(
        "INSERT INTO event (id, tool_use_id, tool, session_id, cwd_hash, created_at, query, url, \
                            url_norm, status, summary, match_text, source, duration_ms, bytes, \
                            origin, member, sync_id, shareable) \
         VALUES (?1, ?2, ?3, ?4, 'c1', ?5, ?6, ?7, ?8, 'ok', ?9, ?10, 'hook', ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            e.id,
            if team {
                format!("team:{}", e.id)
            } else {
                format!("tu{}", e.id)
            },
            e.tool,
            e.session,
            e.at,
            e.query,
            e.url,
            e.url,
            summary,
            text,
            e.duration_ms,
            e.bytes,
            e.origin,
            e.member,
            team.then(|| format!("sync-{}", e.id)),
            if team { "full" } else { "no" },
        ],
    )
    .unwrap();
}

fn injection(conn: &Connection, id: i64, session: &str, at: i64, rendered: i64, items: &[i64]) {
    conn.execute(
        "INSERT INTO injection (id, ref, created_at, hook, channel, mode, session_id, tool_use_id, \
                                rendered_chars, latency_ms) \
         VALUES (?1, ?2, ?3, 'PostToolUse', 'url', 'inject', ?4, ?5, ?6, 10)",
        params![id, format!("{id:08x}"), at, session, format!("inj{id}"), rendered],
    )
    .unwrap();
    for (i, event) in items.iter().enumerate() {
        conn.execute(
            "INSERT INTO injection_item (injection_id, position, event_id, score) VALUES (?1, ?2, ?3, 1.0)",
            params![id, i64::try_from(i + 1).unwrap(), event],
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

/// Local fetches of A (4, 8, 20 s; 400, 800, 1,200 chars; 4,000, 8,000, 20,000 bytes), a teammate's
/// fetch of B and the same record once more (ids 10, 11), and a local fetch of B at +330 s.
///
/// ```text
/// inj 1  s1  +100 s  800 chars  [A local]                   not followed up
/// inj 2  s2  +200 s  400 chars  [B team]                    not followed up
/// inj 3  s3  +300 s  400 chars  [B team]                    followed up (local fetch of B +330 s)
/// inj 4  s4  +320 s  600 chars  [A local, B team]           not followed up
/// labels: 1/1 '2'; 2/1 '2'; 3/1 '0'; 4/1 '1'; 4/2 '2' with the loop marker
/// ```
fn seed(env: &Env) -> Connection {
    let conn = env.conn();
    conn.execute(
        "INSERT INTO team_member (member_id, handle, role, active, updated_at) \
         VALUES (?1, 'alf', 'member', 1, 1)",
        [ALF],
    )
    .unwrap();
    for (id, ms, chars, bytes) in [
        (1, 4_000, 400, 4_000),
        (2, 8_000, 800, 8_000),
        (3, 20_000, 1_200, 20_000),
    ] {
        let mut e = fetch(id, "https://example.org/a", "s0", BASE + id * 1_000);
        e.duration_ms = Some(ms);
        e.chars = chars;
        e.bytes = Some(bytes);
        insert(&conn, &e);
    }
    for id in [10, 11] {
        let mut e = fetch(id, "https://example.org/b", TEAM_SESSION, BASE + 50_000);
        e.origin = "team";
        e.member = Some(ALF);
        e.chars = 600;
        e.bytes = Some(12_000);
        insert(&conn, &e);
    }
    insert(
        &conn,
        &fetch(20, "https://example.org/b", "s3", BASE + 330_000),
    );
    injection(&conn, 1, "s1", BASE + 100_000, 800, &[1]);
    injection(&conn, 2, "s2", BASE + 200_000, 400, &[10]);
    injection(&conn, 3, "s3", BASE + 300_000, 400, &[10]);
    injection(&conn, 4, "s4", BASE + 320_000, 600, &[1, 10]);
    label(&conn, 1, 1, "2");
    label(&conn, 2, 1, "2");
    label(&conn, 3, 1, "0");
    label(&conn, 4, 1, "1");
    label(&conn, 4, 2, "2");
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('review.loop.4.2', '1')",
        [],
    )
    .unwrap();
    conn
}

fn near(got: &Value, want: f64) {
    assert!(
        (got.as_f64().unwrap() - want).abs() < 1e-9,
        "{got} != {want}"
    );
}

// ---------------------------------------------------------------------------------------------
// stats --savings, --value, --team

/// Every figure below is derived by hand from [`seed`].
///
/// Cost of one avoided item: summariser tokens `page / 4` at $1/M plus summary tokens at $5/M.
/// A (local history 4, 8, 20 s; 400, 800, 1,200 chars; 4,000, 8,000, 20,000 bytes): median 8 s,
/// 800 chars = 200 tokens, 8,000 bytes: 2,000 * 1e-6 + 200 * 5e-6 = $0.003. B has no local history
/// before an injection, so the fallback is the median over this machine's ok fetches up to the
/// injection (A's three, the teammate's rows do not count): the same 8 s, 200 tokens, 8,000 bytes,
/// $0.003.
///
/// inj 1: avoided (A). inj 2: avoided (B). inj 3: followed up (the local fetch of B at +330 s).
/// inj 4: two items, A local and B team, not followed up: avoided once per origin.
///
/// ```text
///              shown avoided followed  time(ms) tokens overhead  cost   confirmed
/// local          2      2       0        16000    400    275     0.006   1  (4/1 is '1': not 2)
/// team           3      2       1        16000    400    275     0.006   2  (2/1 and 4/2)
/// all            4      3       1        32000    800    550     0.012   3
/// ```
/// Overhead: inj 1 800/4 = 200 local; inj 2 and 3: 100 each team; inj 4: 600/4 = 150 split in
/// half, 75 each. Local confirmed: only 1/1 ('2'); 4/1 is label '1'.
#[test]
fn stats_savings_splits_every_item_line_by_origin() {
    let env = Env::new();
    seed(&env);
    let v = env.json(&["stats", "--savings", "--json"]);
    let s = &v["savings"];
    for (name, shown, avoided, followed, ms, tokens, overhead, cost, conf) in [
        ("local", 2, 2, 0, 16_000.0, 400.0, 275.0, 0.006, 1),
        ("team", 3, 2, 1, 16_000.0, 400.0, 275.0, 0.006, 2),
    ] {
        let o = &s["by_origin"][name];
        assert_eq!(o["shown"], shown, "{name}: {o}");
        assert_eq!(o["avoided"], avoided, "{name}: {o}");
        assert_eq!(o["followed_up"], followed, "{name}: {o}");
        assert_eq!(o["time_saved_ms"], ms, "{name}: {o}");
        assert_eq!(o["tokens_saved"], tokens, "{name}: {o}");
        assert_eq!(o["overhead_tokens"], overhead, "{name}: {o}");
        assert_eq!(o["net_tokens"], tokens - overhead, "{name}: {o}");
        near(&o["est_cost"], cost);
        assert_eq!(o["est_bytes_not_fetched"], 16_000, "{name}: {o}");
        assert_eq!(o["est_summariser_tokens"], 4_000, "{name}: {o}");
        assert_eq!(o["confirmed"]["items"], conf, "{name}: {o}");
        near(&o["confirmed"]["est_cost"], 0.003 * conf as f64);
        assert!(o["net_cost"].is_null());
    }
    // The totals keep their meaning (injections, not items).
    assert_eq!(s["shown"], 4);
    assert_eq!(s["avoided"], 3);
    assert_eq!(s["followed_up"], 1);
    assert_eq!(s["time_saved_ms"], 32_000.0);
    assert_eq!(s["tokens_saved"], 800.0);
    assert_eq!(s["overhead_tokens"], 550.0);
    near(&s["est_cost"], 0.012);
    assert_eq!(s["confirmed"]["items"], 3);
    // The ceiling counts this machine's repeated calls only: A's events 2 and 3, and no
    // teammate row (event 11 repeats 10).
    assert_eq!(s["ceiling"]["repeat_fetches"]["count"], 2);
    assert_eq!(s["ceiling"]["repeat_fetches"]["bytes"], 28_000);

    let text = env.awm(&["stats", "--savings"]).ok().to_string();
    assert!(
        text.contains("by origin: an injection that shows notes from both"),
        "{text}"
    );
    for line in [
        "avoided (est.)",
        "  avoided from your records",
        "  avoided from teammates' records",
        "  confirmed from your records",
        "  confirmed from teammates' records",
    ] {
        assert!(text.contains(line), "{line}: {text}");
    }
}

#[test]
fn stats_savings_without_teammate_notes_prints_the_table_it_always_did() {
    let env = Env::new();
    let conn = env.conn();
    let mut e = fetch(1, "https://example.org/a", "s0", BASE + 1_000);
    e.duration_ms = Some(4_000);
    e.chars = 400;
    e.bytes = Some(4_000);
    insert(&conn, &e);
    injection(&conn, 1, "s1", BASE + 100_000, 800, &[1]);
    let text = env.awm(&["stats", "--savings"]).ok().to_string();
    assert!(!text.contains("from your records"), "{text}");
    assert!(!text.contains("from teammates"), "{text}");
    let v = env.json(&["stats", "--savings", "--json"]);
    assert_eq!(v["savings"]["by_origin"]["team"]["shown"], 0);
    assert_eq!(v["savings"]["by_origin"]["local"]["shown"], 1);
}

/// `--value`: team rows are not "my captures". Items: inj 1 (1 local), 2 (1 team), 3 (1 team),
/// 4 (1 local, 1 team). Labels: 1/1 '2', 2/1 '2', 3/1 '0', 4/1 '1', 4/2 '2'. Hook-captured local
/// events: 1, 2, 3 and 20, so the denominator is 4 (the teammate's rows 10 and 11 have source
/// `hook` too and do not count).
///
/// ```text
///            shown labelled label2  over shown  over labelled  estimate  per 100
/// all          5      5        3       60.0%                   3/5*5=3.0  3.0*100/4 = 75.0
/// --origin local  2    2        1       50.0%                   1/2*2=1.0  25.0
/// --origin team   3    3        2       66.7%        66.7%      2/3*3=2.0  none; loops 1
/// ```
#[test]
fn stats_value_by_origin_gives_hand_computed_values() {
    let env = Env::new();
    seed(&env);
    let all = env.json(&["stats", "--value", "--json"])["value"].clone();
    assert_eq!(all["shown_items"], 5);
    assert_eq!(all["labelled_2"], 3);
    assert_eq!(all["label2_over_shown"], "60.0%");
    assert_eq!(all["captured_events"], 4);
    assert_eq!(all["per_100_captured"], "75.0");

    let local = env.json(&["stats", "--value", "--origin", "local", "--json"])["value"].clone();
    assert_eq!(local["origin"], "local");
    assert_eq!(local["shown_items"], 2);
    assert_eq!(local["labelled_2"], 1);
    assert_eq!(local["label2_over_shown"], "50.0%");
    assert_eq!(local["captured_events"], 4);
    assert_eq!(local["per_100_captured"], "25.0");

    let team = env.json(&["stats", "--value", "--origin", "team", "--json"])["value"].clone();
    assert_eq!(team["origin"], "team");
    assert_eq!(team["shown_items"], 3);
    assert_eq!(team["labelled"], 3);
    assert_eq!(team["labelled_2"], 2);
    assert_eq!(team["label2_over_shown"], "66.7%");
    assert_eq!(team["label2_over_labelled"], "66.7%");
    assert_eq!(team["label2_estimate"], "2.0");
    assert_eq!(team["loop_labelled"], 1);
    assert!(team["per_100_captured"].is_null());
    assert!(team["captured_events"].is_null());
}

/// 1,000 teammate rows change nothing about the numbers that mean "my captures" (RVT0 M15).
#[test]
fn a_thousand_team_rows_change_no_local_metric() {
    let plain = Env::new();
    let loaded = Env::new();
    for env in [&plain, &loaded] {
        let conn = env.conn();
        for i in 1..=60 {
            let mut e = Ev {
                id: i,
                tool: "WebSearch",
                session: "s0",
                at: BASE + i * 1_000,
                query: None,
                url: None,
                origin: "local",
                member: None,
                duration_ms: None,
                chars: 0,
                bytes: None,
            };
            let q = format!(
                "sqlite fts5 bm25 column weights topic{} ranking{}",
                i % 7,
                i % 5
            );
            e.query = Some(&q);
            insert(&conn, &e);
        }
        conn.execute("DELETE FROM meta WHERE key LIKE 'calibrated%'", [])
            .unwrap();
        injection(&conn, 1, "s1", BASE + 100_000, 400, &[1]);
        label(&conn, 1, 1, "2");
    }
    {
        // Newer than every local row, full of the same terms, from a teammate.
        let mut conn = loaded.conn();
        let tx = conn.transaction().unwrap();
        for i in 1..=1_000 {
            let q = format!(
                "sqlite fts5 bm25 column weights teammate{i} ranking{}",
                i % 3
            );
            let mut e = Ev {
                id: 1_000 + i,
                tool: "WebSearch",
                session: TEAM_SESSION,
                at: BASE + 1_000_000 + i,
                query: Some(&q),
                url: None,
                origin: "team",
                member: Some(ALF),
                duration_ms: None,
                chars: 0,
                bytes: None,
            };
            e.query = Some(&q);
            insert(&tx, &e);
        }
        tx.commit().unwrap();
    }
    assert_eq!(
        loaded
            .conn()
            .query_row("SELECT COUNT(*) FROM event", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1_060
    );

    // stats --value
    let a = plain.awm(&["stats", "--value", "--json"]).ok().to_string();
    let b = loaded.awm(&["stats", "--value", "--json"]).ok().to_string();
    assert_eq!(a, b);
    // The default section and the report count own records only.
    assert_eq!(
        plain.awm(&["stats", "--json"]).ok(),
        loaded.awm(&["stats", "--json"]).ok()
    );
    assert_eq!(
        plain.awm(&["stats", "--status", "--json"]).ok(),
        loaded.awm(&["stats", "--status", "--json"]).ok()
    );
    // `report` counts own records only: the lines about records and quarantine are the same.
    let report = |env: &Env| -> Vec<String> {
        env.awm(&["report"])
            .ok()
            .lines()
            .filter(|l| {
                l.contains("records")
                    || l.contains("quarantined")
                    || l.contains("main")
                    || l.contains("subagent")
                    || l.contains("Web")
            })
            .map(str::to_string)
            .collect()
    };
    let (ra, rb) = (report(&plain), report(&loaded));
    assert_eq!(ra, rb);
    assert!(
        ra.iter().any(|l| l.contains("records") && l.contains("60")),
        "{ra:?}"
    );

    // calibrate: the same cutoff, from the same 60 records, although teammates' text is indexed
    let cut = |env: &Env| {
        let out = env.awm(&["calibrate"]).ok().to_string();
        assert!(out.contains("records       60"), "{out}");
        out
    };
    let (ca, cb) = (cut(&plain), cut(&loaded));
    assert_eq!(ca, cb);
    assert!(!ca.contains("defaults in use"), "{ca}");
    // ... and the scratch copy is gone; it was made in tmp/ (RVT3 F7).
    assert!(loaded.awm_home().join("tmp").is_dir());
    let leftovers: Vec<_> = [loaded.awm_home(), loaded.awm_home().join("tmp")]
        .iter()
        .flat_map(|d| std::fs::read_dir(d).unwrap().flatten())
        .filter(|e| e.file_name().to_string_lossy().contains("calibrate"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // forget last: the newest local record, not the newest record
    let fa = plain.awm(&["forget", "last"]);
    let fb = loaded.awm(&["forget", "last"]);
    assert_eq!(fa.stdout, fb.stdout);
    assert_eq!(fa.code, fb.code);
    assert!(
        fb.stdout.contains("topic0") || fb.stdout.contains("ranking"),
        "{}",
        fb.stdout
    );
    assert!(!fb.stdout.contains("teammate"), "{}", fb.stdout);
    // doctor --coverage counts own hook records only
    let projects = loaded.dir.path().join("projects");
    std::fs::create_dir_all(&projects).unwrap();
    let cov = |env: &Env| {
        let out = env
            .awm(&[
                "doctor",
                "--coverage",
                "--projects",
                projects.to_str().unwrap(),
            ])
            .stdout;
        out.lines().skip(1).collect::<Vec<_>>().join("\n")
    };
    assert_eq!(cov(&plain), cov(&loaded));
}

/// `--team`: totals only, and only when at least 3 members reported.
#[test]
fn stats_team_sums_daily_records_only_when_three_members_reported() {
    let env = Env::new();
    let conn = env.conn();
    let day = |n: i64| awm_day(BASE + n * 86_400_000);
    let put = |member: &str, d: &str, shown: u64, avoided: u64, minutes: u64, tokens: u64| {
        conn.execute(
            "INSERT INTO sync_state (key, value) VALUES (?1, ?2)",
            params![
                format!("team_stats.{member}.{d}"),
                json!({"schema": 1, "day": d, "shown": shown, "avoided": avoided,
                       "est_minutes": minutes, "est_tokens": tokens})
                .to_string()
            ],
        )
        .unwrap();
    };
    // The window starts 30 days before now: use days near today.
    let today = awm_day(now_ms());
    let _ = day;
    put("m1", &today, 10, 4, 7, 900);
    put("m2", &today, 5, 1, 2, 100);
    let two = env.awm(&["stats", "--team"]).ok().to_string();
    assert!(
        two.contains("2 of the members") && two.contains("at least 3"),
        "{two}"
    );
    let v = env.json(&["stats", "--team", "--json"]);
    assert_eq!(v["team"]["reported"], 2);
    assert!(v["team"]["totals"].is_null());
    // The sums are not printed under the threshold.
    assert!(!two.contains("15"), "{two}");

    put("m3", &today, 1, 1, 1, 50);
    put("m1", "2020-01-01", 999, 999, 999, 999); // outside the window
    let v = env.json(&["stats", "--team", "--json"]);
    assert_eq!(v["team"]["reported"], 3);
    assert_eq!(
        v["team"]["totals"],
        json!({"shown": 16, "avoided": 6, "est_minutes": 10, "est_tokens": 1050})
    );
    let text = env.awm(&["stats", "--team"]).ok().to_string();
    assert!(
        text.contains("3 members reported") && text.contains("16 notes shown"),
        "{text}"
    );
    // Totals only: no member id in the output.
    assert!(
        !text.contains("m1") && !v.to_string().contains("m1"),
        "{text}"
    );
    // `--since` moves the window start.
    let v = env.json(&["stats", "--team", "--since", "2019-01-01", "--json"]);
    assert_eq!(v["team"]["totals"]["shown"], 1015);
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// `YYYY-MM-DD` (UTC) of a time in milliseconds.
fn awm_day(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

// ---------------------------------------------------------------------------------------------
// review

#[test]
fn review_labels_teammate_notes_and_offers_flag_on_h() {
    let env = Env::new();
    seed(&env);
    // Without a flag: every unlabelled item, teammates' labelled like own. Inject two new ones.
    let conn = env.conn();
    injection(&conn, 5, "s5", BASE + 500_000, 300, &[10]);
    injection(&conn, 6, "s6", BASE + 600_000, 300, &[1]);
    drop(conn);
    // `--origin team`: only teammates' notes, newest first: injection 5. h, then q.
    let out = env.awm_in(&["review", "--origin", "team"], "h\n");
    let text = out.ok().to_string();
    assert!(text.contains("from: teammate @alf"), "{text}");
    assert!(text.contains("awm team flag 10"), "{text}");
    assert!(!text.contains("ref 00000006"), "{text}");
    assert!(
        text.contains("L label 2 and it avoided a multi-step research loop"),
        "{text}"
    );
    let label: String = env
        .conn()
        .query_row(
            "SELECT label FROM outcome WHERE injection_id = 5",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(label, "h");

    // A local note takes no L, and no flag offer for h.
    let out = env.awm_in(&["review", "--origin", "local"], "l\nh\n");
    let text = out.ok().to_string();
    assert!(
        text.contains("Key L is only for notes from teammates."),
        "{text}"
    );
    assert!(!text.contains("awm team flag"), "{text}");
}

#[test]
fn review_key_l_stores_label_2_and_the_loop_marker_that_value_counts() {
    let env = Env::new();
    let conn = env.conn();
    conn.execute(
        "INSERT INTO team_member (member_id, handle, role, active, updated_at) VALUES (?1, 'alf', 'member', 1, 1)",
        [ALF],
    )
    .unwrap();
    for id in 1..=3 {
        let mut e = fetch(id, "https://example.org/b", TEAM_SESSION, BASE + id);
        e.origin = "team";
        e.member = Some(ALF);
        insert(&conn, &e);
        injection(&conn, id, "s1", BASE + 1_000 * id, 100, &[id]);
    }
    drop(conn);
    // Newest first: injection 3 gets L, 2 gets 2, 1 gets 1.
    let out = env.awm_in(&["review", "--origin", "team"], "l\n2\n1\n");
    assert!(
        out.ok().contains("Labelled 3 of 3 items."),
        "{}",
        out.stdout
    );
    let rows: Vec<(i64, String)> = env
        .conn()
        .prepare("SELECT injection_id, label FROM outcome ORDER BY injection_id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows, [(1, "1".into()), (2, "2".into()), (3, "2".into())]);
    let v = env.json(&["stats", "--value", "--origin", "team", "--json"])["value"].clone();
    assert_eq!(v["labelled"], 3);
    assert_eq!(v["labelled_2"], 2);
    assert_eq!(v["loop_labelled"], 1);
}

/// `awm search` (TM13b, TM30 F5): the relation, origin, member and handle of every row.
fn seed_search(env: &Env) {
    env.join_offline(false);
    let conn = env.conn();
    conn.execute(
        "INSERT INTO team_member (member_id, handle, role, active, updated_at) \
         VALUES (?1, 'alf', 'member', 1, 1)",
        [ALF],
    )
    .unwrap();
    insert(&conn, &fetch(1, "https://example.org/a", "s0", BASE));
    let mut t = fetch(10, "https://example.org/b", TEAM_SESSION, BASE);
    t.origin = "team";
    t.member = Some(ALF);
    insert(&conn, &t);
    let mut o = fetch(11, "https://example.org/c", "team:own", BASE);
    o.origin = "team";
    o.member = Some(ME);
    insert(&conn, &o);
}

#[test]
fn search_json_has_origin_member_handle_and_relation() {
    let env = Env::new();
    seed_search(&env);
    let a = env.json(&["search", "--url", "https://example.org/a", "--json"]);
    assert_eq!(a[0]["origin"], "local");
    assert_eq!(a[0]["relation"], "own");
    assert!(a[0]["member"].is_null() && a[0]["handle"].is_null(), "{a}");
    let b = env.json(&["search", "--url", "https://example.org/b", "--json"]);
    assert_eq!(b[0]["origin"], "team");
    assert_eq!(b[0]["member"], ALF);
    assert_eq!(b[0]["handle"], "alf");
    assert_eq!(b[0]["relation"], "teammate");
    assert!(b[0].get("muted").is_none(), "{b}");
    let c = env.json(&["search", "--url", "https://example.org/c", "--json"]);
    assert_eq!(c[0]["origin"], "team");
    assert_eq!(c[0]["member"], ME);
    assert!(c[0]["handle"].is_null(), "{c}");
    assert_eq!(c[0]["relation"], "own_device");
}

#[test]
fn search_text_shows_the_relation_and_the_team_preamble_only_for_team_notes() {
    let env = Env::new();
    seed_search(&env);
    let b = env.awm(&["search", "--url", "https://example.org/b"]);
    let b = b.ok();
    assert!(b.contains("teammate @alf, other repository"), "{b}");
    assert!(b.contains("your agents and your teammates' agents"), "{b}");
    let c = env.awm(&["search", "--url", "https://example.org/c"]);
    let c = c.ok();
    assert!(c.contains("your other machine"), "{c}");
    let a = env.awm(&["search", "--url", "https://example.org/a"]);
    let a = a.ok();
    assert!(!a.contains("teammate"), "{a}");
    assert!(a.contains("Earlier web research from this machine"), "{a}");
}

#[test]
fn search_marks_a_muted_handle_and_ignores_team_show() {
    let env = Env::new();
    seed_search(&env);
    std::fs::write(
        env.awm_home().join("config.toml"),
        "[team]\nshow = false\nmute = [\"@alf\"]\n",
    )
    .unwrap();
    let b = env.awm(&["search", "--url", "https://example.org/b"]);
    assert!(b.ok().contains("teammate @alf (muted), "), "{}", b.stdout);
    let j = env.json(&["search", "--url", "https://example.org/b", "--json"]);
    assert_eq!(j[0]["muted"], true);
}

#[test]
fn review_shows_the_handle_of_a_teammate_item() {
    let env = Env::new();
    seed(&env);
    injection(&env.conn(), 5, "s5", BASE + 500_000, 300, &[10]);
    let out = env.awm_in(&["review", "--origin", "team"], "q\n");
    assert!(out.ok().contains("from: teammate @alf"), "{}", out.stdout);
}

/// `--origin team` has no daily cap: 12 notes are all shown, while the default stays at 10.
#[test]
fn review_origin_team_shows_every_teammate_note_without_the_daily_cap() {
    let env = Env::new();
    let conn = env.conn();
    for id in 1..=12 {
        let mut e = fetch(id, "https://example.org/b", TEAM_SESSION, BASE + id);
        e.origin = "team";
        e.member = Some(ALF);
        insert(&conn, &e);
        injection(&conn, id, "s1", BASE + 1_000 * id, 100, &[id]);
    }
    drop(conn);
    let capped = env.awm_in(&["review"], "q\n");
    assert!(capped.ok().contains("item 1/10"), "{}", capped.stdout);
    let all = env.awm_in(&["review", "--origin", "team"], "q\n");
    assert!(all.ok().contains("item 1/12"), "{}", all.stdout);
}

/// A deleted teammate record leaves the item with `event_id` NULL (migration 0003). The CLI
/// readers of `injection_item.event_id` tolerate it (RVT1 m15).
#[test]
fn review_and_stats_tolerate_a_null_event_id_after_a_deletion() {
    let env = Env::new();
    let conn = env.conn();
    conn.execute(
        "INSERT INTO team_member (member_id, handle, role, active, updated_at) VALUES (?1, 'alf', 'member', 1, 1)",
        [ALF],
    )
    .unwrap();
    let mut e = fetch(10, "https://example.org/b", TEAM_SESSION, BASE);
    e.origin = "team";
    e.member = Some(ALF);
    insert(&conn, &e);
    injection(&conn, 1, "s1", BASE + 1_000, 100, &[10]);
    conn.execute("DELETE FROM event WHERE id = 10", []).unwrap();
    let (event_id, origin): (Option<i64>, String) = conn
        .query_row("SELECT event_id, origin FROM injection_item", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((event_id, origin.as_str()), (None, "team"));
    drop(conn);

    let v = env.json(&["stats", "--savings", "--json"]);
    assert_eq!(v["savings"]["by_origin"]["team"]["shown"], 1);
    assert_eq!(v["savings"]["by_origin"]["team"]["time_saved_ms"], 0.0);
    env.awm(&["stats", "--followups"]).ok();
    env.awm(&["stats"]).ok();
    let out = env.awm_in(&["review", "--origin", "team"], "x\n");
    let text = out.ok().to_string();
    assert!(text.contains("the record was deleted"), "{text}");
    assert!(text.contains("The record was already deleted."), "{text}");
    assert!(text.contains("Labelled 0 of 1 items."), "{text}");
    let out = env.awm_in(&["review", "--origin", "team"], "2\n");
    assert!(
        out.ok().contains("Labelled 1 of 1 items."),
        "{}",
        out.stdout
    );
    let label: String = env
        .conn()
        .query_row("SELECT label FROM outcome", [], |r| r.get(0))
        .unwrap();
    assert_eq!(label, "2");
    // The default review lists the same item as well.
    let env2 = Env::new();
    let conn = env2.conn();
    insert(&conn, &fetch(1, "https://example.org/a", "s0", BASE));
    injection(&conn, 1, "s1", BASE + 1_000, 100, &[1]);
    conn.execute("UPDATE injection_item SET event_id = NULL", [])
        .unwrap();
    drop(conn);
    assert!(env2.awm_in(&["review"], "s\n").ok().contains("item 1/1"));
}

// ---------------------------------------------------------------------------------------------
// log, export

#[test]
fn log_tags_team_rows_and_filters_by_origin_and_shared() {
    let env = Env::new();
    let conn = env.conn();
    conn.execute(
        "INSERT INTO team_member (member_id, handle, role, active, updated_at) VALUES (?1, 'alf', 'member', 1, 1)",
        [ALF],
    )
    .unwrap();
    insert(
        &conn,
        &fetch(1, "https://example.org/mine-private", "s0", BASE + 1),
    );
    insert(
        &conn,
        &fetch(2, "https://example.org/mine-shared", "s0", BASE + 2),
    );
    conn.execute(
        "UPDATE event SET sync_id = 'rec-2', shareable = 'full' WHERE id = 2",
        [],
    )
    .unwrap();
    let mut t = fetch(3, "https://example.org/theirs", TEAM_SESSION, BASE + 3);
    t.origin = "team";
    t.member = Some(ALF);
    insert(&conn, &t);
    drop(conn);

    let all = env.awm(&["log"]).ok().to_string();
    let line = all.lines().find(|l| l.contains("theirs")).unwrap();
    assert!(line.contains("@alf https://example.org/theirs"), "{all}");
    assert!(
        all.lines()
            .filter(|l| l.contains("mine-"))
            .all(|l| !l.contains('@')),
        "{all}"
    );

    let team = env.awm(&["log", "--origin", "team"]).ok().to_string();
    assert_eq!(team.lines().count(), 1, "{team}");
    let local = env.awm(&["log", "--origin", "local"]).ok().to_string();
    assert_eq!(local.lines().count(), 2, "{local}");
    assert!(!local.contains("theirs"));
    let shared = env.awm(&["log", "--shared"]).ok().to_string();
    assert_eq!(shared.lines().count(), 1, "{shared}");
    assert!(shared.contains("mine-shared"));
    assert_ne!(
        env.awm(&["log", "--shared", "--origin", "team"]).code,
        Some(0)
    );

    let json: Vec<Value> = env
        .awm(&["log", "--json"])
        .ok()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(json[0]["origin"], "team");
    assert_eq!(json[0]["handle"], "alf");
    assert_eq!(json[1]["origin"], "local");
}

#[test]
fn export_has_origin_and_shareable_and_teammates_only_with_include_team() {
    let env = Env::new();
    seed(&env);
    let plain = env.awm(&["export"]).ok().to_string();
    let lines: Vec<Value> = plain
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines[0]["format"], "awm-export/0");
    // 4 local rows: 1, 2, 3 and 20; the two teammate rows (10, 11) are absent.
    assert_eq!(lines.len() - 1, 4);
    for l in &lines[1..] {
        assert_eq!(l["origin"], "local", "{l}");
        assert_eq!(l["shareable"], "no", "{l}");
    }
    // Scan the raw output: not a trace of a teammate's row.
    assert!(!plain.contains("\"team\""), "{plain}");
    assert!(!plain.contains("team:"), "{plain}");

    let with = env.awm(&["export", "--include-team"]).ok().to_string();
    let lines: Vec<Value> = with
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines[0]["format"], "awm-export/0");
    assert_eq!(lines.len() - 1, 6);
    let team: Vec<&Value> = lines[1..]
        .iter()
        .filter(|l| l["origin"] == "team")
        .collect();
    assert_eq!(team.len(), 2);
    assert_eq!(team[0]["shareable"], "full");
    // --out takes the flag too.
    let file = env.dir.path().join("out.jsonl");
    let msg = env.awm(&["export", "--include-team", "--out", file.to_str().unwrap()]);
    assert!(msg.ok().contains("Exported 6 records"), "{}", msg.stdout);
}

// ---------------------------------------------------------------------------------------------
// doctor, where, uninstall, config

#[test]
fn doctor_has_a_team_section_only_in_a_team_and_is_unchanged_otherwise() {
    let env = Env::new();
    let before = env.awm(&["doctor"]);
    let before_text = before.ok().to_string();
    assert!(
        !before_text.to_lowercase().contains("team"),
        "{before_text}"
    );
    for line in before_text.lines() {
        assert!(
            line.starts_with("data dir: ")
                || line.starts_with("[ok]")
                || line.starts_with("[warn]"),
            "{line}"
        );
    }

    env.join_offline(false);
    let out = env.awm(&["doctor"]);
    let text = out.stdout.clone();
    for want in [
        "[ok]   team: @me",
        "[warn] team server not reachable",
        "[warn] team token not checked",
        "[ok]   team protocol: not fetched yet",
        "[ok]   team key epochs present up to 0",
        "[warn] team approval: approved by the server, but the roster holds no verified approval",
        "[ok]   team last sync: never",
        "[ok]   team outbox: 0 item(s) waiting to be sent",
    ] {
        assert!(text.contains(want), "{want}\n{text}");
    }
    assert_eq!(out.code, Some(0), "{text}{}", out.stderr);
    // The part before the team lines is the old output, line for line.
    let old: Vec<&str> = before_text.lines().collect();
    let new: Vec<&str> = text.lines().collect();
    for (i, l) in old.iter().enumerate() {
        assert_eq!(&new[i], l, "line {i}");
    }
    // No token, key or secret in anything it printed.
    assert!(!text.contains("TOKENSECRET") && !out.stderr.contains("TOKENSECRET"));

    // Facts from sync_state: min_client, skips, drops, outbox, backoff, newer schema, restore.
    let conn = env.conn();
    for (k, v) in [
        ("info_json", r#"{"protocols":[1],"min_client":"0.2.0"}"#),
        ("skipped.credential_url", "2"),
        ("dropped.malformed", "3"),
        ("newer_schema", "1"),
        ("server_restored_before_join", "1"),
        ("backoff_until", "4102444800000"),
        ("last_error", "the server did not answer (refused)"),
    ] {
        conn.execute(
            "INSERT INTO sync_state (key, value) VALUES (?1, ?2)",
            params![k, v],
        )
        .unwrap();
    }
    conn.execute("INSERT INTO sync_outbox (kind, ref, created_at) VALUES ('record', 'rec:1', 1), ('flag', 'flag:1', 1)", [])
        .unwrap();
    drop(conn);
    let text = env.awm(&["doctor"]).stdout;
    for want in [
        "[ok]   team protocol 1, min_client 0.2.0",
        "[warn] team sync backoff until",
        "[warn] team last error: the server did not answer (refused)",
        "[ok]   team outbox: 2 item(s) waiting to be sent",
        "[warn] team kept local in the last run: credential_url 2",
        "[warn] team dropped from teammates since joining: malformed 3",
        "[warn] team: a teammate's record needs a newer awm",
        "[warn] team: the server was restored from a backup older than this device's join",
    ] {
        assert!(text.contains(want), "{want}\n{text}");
    }

    // Device-id collision (RVT0 m7): the push's refusal text becomes an explanation and a failure.
    env.conn()
        .execute(
            "UPDATE sync_state SET value = 'the server holds another record at rec 3 of this device''s stream: this data directory was copied to another machine. Take a new device id with a device invite (awm doctor explains)' WHERE key = 'last_error'",
            [],
        )
        .unwrap();
    let out = env.awm(&["doctor"]);
    assert_ne!(out.code, Some(0));
    assert!(
        out.stdout.contains("[fail] team device id collision"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("awm team add-device"), "{}", out.stdout);

    // Leaving the team (the files gone) gives the old output again.
    std::fs::remove_file(env.awm_home().join("team.toml")).unwrap();
    std::fs::remove_file(env.awm_home().join("team.key")).unwrap();
    assert_eq!(env.awm(&["doctor"]).stdout, before_text);
}

#[test]
fn where_prints_team_toml_and_team_key_in_a_team() {
    let env = Env::new();
    let plain = env.awm(&["where"]).ok().to_string();
    assert!(!plain.contains("team"), "{plain}");
    env.join_offline(false);
    let text = env.awm(&["where"]).ok().to_string();
    let dir = env.awm_home();
    assert!(
        text.contains(&format!("team:     {}", dir.join("team.toml").display())),
        "{text}"
    );
    assert!(
        text.contains(&format!("team key: {}", dir.join("team.key").display())),
        "{text}"
    );
    assert!(!text.contains("TOKENSECRET"));
}

#[test]
fn uninstall_offers_team_leave_first_and_shows_the_prompt() {
    use awm::forget::{Io, Outcome};
    let env = Env::new();
    env.join_offline(false);
    let run = |terminal: bool, input: &str, yes: bool| {
        let mut out = Vec::new();
        let mut inp = input.as_bytes();
        let args = awm::cli::uninstall::Args { yes };
        let outcome = {
            let mut io = Io {
                data_dir: env.awm_home(),
                terminal,
                input: &mut inp,
                out: &mut out,
                now_ms: BASE,
            };
            awm::cli::uninstall::run_with(&args, &mut io, None, Some(&env.home())).unwrap()
        };
        (outcome, String::from_utf8(out).unwrap())
    };
    let (outcome, text) = run(true, "n\n", false);
    assert_eq!(outcome, Outcome::Declined, "{text}");
    assert!(
        text.starts_with(
            "This machine is in a team. Run awm team leave first (awm team leave --delete"
        ),
        "{text}"
    );
    assert!(
        text.contains("Continue and delete the data directory without leaving the team? [y/N] "),
        "{text}"
    );
    assert!(text.contains("Nothing changed."), "{text}");
    assert!(env.awm_home().join("team.toml").exists());
    // Without a terminal and without --yes nothing is asked and nothing changes.
    let (outcome, text) = run(false, "", false);
    assert_ne!(outcome, Outcome::Done, "{text}");
    assert!(text.starts_with("This machine is in a team."), "{text}");
    assert!(env.awm_home().join("awm.db").exists());
    // `--yes` still prints the offer, then goes on: `forget::ours()` knows the team files
    // (TM11), so the directory is deleted with them.
    let (outcome, text) = run(false, "", true);
    assert!(text.contains("This machine is in a team."), "{text}");
    assert_eq!(outcome, Outcome::Done, "{text}");
    assert!(!env.awm_home().exists(), "{text}");
}

#[test]
fn config_list_shows_every_team_key_with_its_default() {
    let env = Env::new();
    let text = env.awm(&["config", "list"]).ok().to_string();
    for line in [
        "team.auto_sync = true",
        "team.sync_interval_s = 60",
        "team.show = true",
        "team.mute = ",
        "team.share_all_projects = false",
        "team.exclude_hosts = ",
        "team.summary_chars = 1000",
        "team.share_stats = false",
        "team.auto_approve = none",
        "team.push_delay_s = 0",
    ] {
        assert!(
            text.lines().any(|l| l == line.trim_end() || l == line),
            "{line}: {text}"
        );
    }
}

#[test]
fn config_set_team_keys_validates_and_a_bad_value_writes_nothing() {
    let env = Env::new();
    let path = env.awm_home().join("config.toml");
    let bad: &[(&str, &str)] = &[
        ("team.sync_interval_s", "-1"),
        ("team.sync_interval_s", "soon"),
        ("team.summary_chars", "2001"),
        ("team.summary_chars", "-5"),
        ("team.auto_approve", "everyone"),
        ("team.mute", "alf,Bob"),
        ("team.mute", "alf,two words"),
        ("team.mute", "abcdefghijklmnopqrstuvwxyz"),
        ("team.exclude_hosts", "https://example.org"),
        ("team.exclude_hosts", "example.org/path"),
        ("team.exclude_hosts", "-bad.example"),
        ("team.exclude_hosts", "a..b"),
        ("team.push_delay_s", "-3"),
        ("team.share_stats", "yes"),
        ("team.auto_sync", "1"),
        ("team.show", "maybe"),
        ("team.share_all_projects", "TRUE"),
    ];
    for (key, value) in bad {
        let out = env.awm(&["config", "set", "--", key, value]);
        assert_ne!(out.code, Some(0), "{key}={value}");
        assert!(out.stderr.contains(key), "{key}={value}: {}", out.stderr);
        assert!(!path.exists(), "{key}={value} wrote the file");
    }
    // A rejected handle is never echoed back.
    let out = env.awm(&["config", "set", "team.mute", "alf,Secret_Org_Handle!"]);
    assert!(!out.stderr.contains("Secret_Org_Handle"), "{}", out.stderr);

    for (key, value, shown) in [
        ("team.sync_interval_s", "0", "0"),
        ("team.sync_interval_s", "300", "300"),
        ("team.summary_chars", "2000", "2000"),
        ("team.auto_approve", "all", "all"),
        ("team.mute", "alf, @bob-2,c_3", "alf,bob-2,c_3"),
        (
            "team.exclude_hosts",
            "Docs.Example.com, intranet",
            "docs.example.com,intranet",
        ),
        ("team.push_delay_s", "900", "900"),
        ("team.share_stats", "true", "true"),
        ("team.auto_sync", "false", "false"),
        ("team.show", "false", "false"),
        ("team.share_all_projects", "true", "true"),
    ] {
        let out = env.awm(&["config", "set", key, value]);
        assert!(
            out.ok().starts_with(&format!("{key} = {shown}")),
            "{key}: {}",
            out.stdout
        );
        assert_eq!(env.awm(&["config", "get", key]).ok().trim(), shown);
    }
    // `devices` and `all` carry one warning line on that set: a leaked invite string is let in
    // without the code comparison (RVT2 m3); `none`, the default, prints none.
    for value in ["devices", "all"] {
        let out = env.awm(&["config", "set", "team.auto_approve", value]);
        let text = out.ok().to_string();
        let warnings: Vec<_> = text.lines().filter(|l| l.starts_with("Warning:")).collect();
        assert_eq!(warnings.len(), 1, "{value}: {text}");
        assert!(warnings[0].contains("without anyone comparing"), "{text}");
        assert!(warnings[0].contains("leaked invite string"), "{text}");
    }
    let out = env.awm(&["config", "set", "team.auto_approve", "none"]);
    let text = out.ok().to_string();
    assert_eq!(text.trim(), "team.auto_approve = none", "{text}");
}

// ---------------------------------------------------------------------------------------------
// The daily stats record

/// `awm sync` queues one `stats` record per finished day when `team.share_stats` is on
/// (the trigger decision of TM14): the record is queued, kept as the member's own row of
/// `--team`, and the day marker stops a second one.
#[test]
fn the_daily_stats_record_is_queued_once_per_day_only_with_share_stats() {
    let off = Env::new();
    off.join_offline(false);
    let _ = off.awm(&["sync", "--once"]);
    assert_eq!(
        count(
            &off.conn(),
            "SELECT COUNT(*) FROM sync_outbox WHERE kind = 'stats'"
        ),
        0
    );

    let env = Env::new();
    env.join_offline(true);
    // Yesterday's injections: 2 shown, one avoided follow-up.
    let conn = env.conn();
    let yesterday = (now_ms() / 86_400_000 - 1) * 86_400_000;
    let mut e = fetch(1, "https://example.org/a", "s0", yesterday - 1_000_000);
    e.duration_ms = Some(60_000);
    e.chars = 400;
    e.bytes = Some(4_000);
    insert(&conn, &e);
    injection(&conn, 1, "s1", yesterday + 1_000, 100, &[1]);
    injection(&conn, 2, "s2", yesterday + 2_000, 100, &[1]);
    // The second was followed up by the same session 30 s later.
    insert(
        &conn,
        &fetch(2, "https://example.org/a", "s2", yesterday + 32_000),
    );
    drop(conn);
    let _ = env.awm(&["sync", "--once"]);
    let conn = env.conn();
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM sync_outbox WHERE kind = 'stats'"
        ),
        1
    );
    // Hand-computed: shown 2, avoided 1 (injection 1), 60 s = 1 minute, 400 chars / 4 = 100 tokens.
    let key = format!("team_stats.{ME}.{}", awm_day(yesterday));
    let stored: String = conn
        .query_row("SELECT value FROM sync_state WHERE key = ?1", [&key], |r| {
            r.get(0)
        })
        .unwrap();
    let v: Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(
        v,
        json!({"schema": 1, "day": awm_day(yesterday), "shown": 2, "avoided": 1,
               "est_minutes": 1, "est_tokens": 100})
    );
    drop(conn);
    let _ = env.awm(&["sync", "--once"]);
    assert_eq!(
        count(
            &env.conn(),
            "SELECT COUNT(*) FROM sync_outbox WHERE kind = 'stats'"
        ),
        1
    );
    // The sealed record holds no plaintext.
    let blob: Vec<u8> = env
        .conn()
        .query_row("SELECT blob FROM sync_own WHERE tag = 'stats'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(!String::from_utf8_lossy(&blob).contains("est_minutes"));
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn the_state_module_exports_what_these_tests_build() {
    // Keeps the imports honest if `sync::state` moves.
    let _ = state::TEAM_TOML;
}
