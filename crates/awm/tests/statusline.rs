//! `awm statusline`: the built binary against a temporary data dir.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use awm::quota::store;
use serde_json::Value;

/// 2026-10-02T00:00:00Z in ms; the month file is `samples-2026-10.ndjson`.
const NOW: &str = "1790899200000";

struct Env {
    dir: tempfile::TempDir,
}

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/statusline")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}

impl Env {
    /// A set-up data dir (it exists, as after `awm init`).
    fn new() -> Env {
        let env = Env::bare();
        std::fs::create_dir_all(env.home()).unwrap();
        env
    }

    /// An `AWM_HOME` that does not exist.
    fn bare() -> Env {
        Env {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("awm")
    }

    fn quota(&self) -> PathBuf {
        self.home().join("quota")
    }

    fn month_file(&self) -> PathBuf {
        self.quota().join("samples-2026-10.ndjson")
    }

    fn run(&self, args: &[&str], stdin: &[u8], extra: &[(&str, &str)]) -> Out {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_awm"));
        cmd.arg("statusline")
            .args(args)
            .env("AWM_HOME", self.home())
            .env("AWM_TEST_NOW_MS", NOW)
            .env_remove("AWM_DEBUG")
            .env_remove("AWM_TEST_DELAY_MS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().unwrap();
        // The child may exit before it reads everything (a deadline, a big input).
        let _ = child.stdin.take().unwrap().write_all(stdin);
        let o = child.wait_with_output().unwrap();
        Out {
            code: o.status.code(),
            stdout: String::from_utf8(o.stdout).unwrap(),
            stderr: String::from_utf8(o.stderr).unwrap(),
        }
    }

    fn quiet(&self, stdin: &str) -> Out {
        self.run(&["--quiet"], stdin.as_bytes(), &[])
    }

    fn lines(&self) -> Vec<Value> {
        std::fs::read_to_string(self.month_file())
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn files(&self) -> Vec<String> {
        std::fs::read_dir(self.quota())
            .map(|d| {
                d.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn assert_silent_ok(o: &Out) {
    assert_eq!(o.code, Some(0), "stderr: {}", o.stderr);
    assert_eq!(o.stdout, "");
    assert_eq!(o.stderr, "");
}

fn with_cost(json: &str, cost: f64) -> String {
    let mut v: Value = serde_json::from_str(json).unwrap();
    v["cost"]["total_cost_usd"] = serde_json::json!(cost);
    v.to_string()
}

#[test]
fn records_the_documented_payload() {
    let env = Env::new();
    assert_silent_ok(&env.quiet(&fixture("full.json")));
    let lines = env.lines();
    assert_eq!(lines.len(), 1);
    let l = &lines[0];
    assert_eq!(l["v"], 1);
    assert_eq!(l["t"], NOW.parse::<i64>().unwrap());
    assert_eq!(l["sid"], "abc123...");
    assert_eq!(l["model"], "claude-opus-5-5");
    assert_eq!(l["h5"]["p"], 23.5);
    assert_eq!(l["h5"]["r"], 1738425600);
    assert_eq!(l["d7"]["p"], 41.2);
    assert_eq!(l["d7"]["r"], 1738857600);
    assert_eq!(l["cost"], 0.01234);
    assert_eq!(l["dur"], 45000);
    let raw = std::fs::read_to_string(env.month_file()).unwrap();
    for leak in [
        "/current/working/directory",
        "/path/to",
        "/original/project/directory",
        "feature-xyz",
        "my-session",
        "security-reviewer",
        "pull/1234",
        "spend_limit",
    ] {
        assert!(!raw.contains(leak), "{leak} leaked: {raw}");
    }
}

#[test]
fn records_integer_percentages() {
    let env = Env::new();
    assert_silent_ok(&env.quiet(&fixture("integer.json")));
    let raw = std::fs::read_to_string(env.month_file()).unwrap();
    assert!(raw.contains(r#""p":24,"#), "{raw}");
    assert!(raw.contains(r#""p":41,"#), "{raw}");
}

#[test]
fn records_a_d7_only_sample() {
    let env = Env::new();
    assert_silent_ok(&env.quiet(&fixture("d7-only.json")));
    let lines = env.lines();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].get("h5").is_none());
    assert_eq!(lines[0]["d7"]["p"], 41.2);
}

#[test]
fn writes_nothing_without_rate_limits() {
    let env = Env::new();
    assert_silent_ok(&env.quiet(&fixture("no-limits.json")));
    assert!(env.files().is_empty());
    assert!(!env.quota().exists());
}

#[test]
fn writes_nothing_when_mode_is_off() {
    let env = Env::new();
    std::fs::write(env.home().join("config.toml"), "mode = \"off\"\n").unwrap();
    assert_silent_ok(&env.quiet(&fixture("full.json")));
    assert!(!env.quota().exists());
}

#[test]
fn writes_nothing_when_quota_capture_is_false() {
    let env = Env::new();
    std::fs::write(env.home().join("config.toml"), "[quota]\ncapture = false\n").unwrap();
    let o = env.run(&[], fixture("integer.json").as_bytes(), &[]);
    assert_eq!(o.code, Some(0));
    // The status line text is still printed.
    assert!(o.stdout.starts_with("5h 24% ("), "{}", o.stdout);
    assert!(!env.quota().exists());

    std::fs::write(env.home().join("config.toml"), "[quota]\ncapture = true\n").unwrap();
    assert_silent_ok(&env.quiet(&fixture("integer.json")));
    assert_eq!(env.lines().len(), 1);
}

#[test]
fn writes_nothing_when_the_config_does_not_parse() {
    let env = Env::new();
    std::fs::write(env.home().join("config.toml"), "mode = [\n").unwrap();
    assert_silent_ok(&env.quiet(&fixture("full.json")));
    assert!(!env.quota().exists());
}

#[test]
fn writes_nothing_before_awm_init() {
    let env = Env::bare();
    assert_silent_ok(&env.quiet(&fixture("full.json")));
    assert!(!env.home().exists());
}

#[test]
fn never_opens_the_database() {
    // awm.db is a directory: opening it as SQLite would fail.
    let env = Env::new();
    std::fs::create_dir(env.home().join("awm.db")).unwrap();
    assert_silent_ok(&env.quiet(&fixture("full.json")));
    assert_eq!(env.lines().len(), 1);

    // Another connection holds the write lock: no wait.
    let env = Env::new();
    let db = env.home().join("awm.db");
    let mut conn = awm::db::open(&db, awm::db::Role::Cli).unwrap();
    awm::db::migrate(&mut conn).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let start = Instant::now();
    assert_silent_ok(&env.quiet(&fixture("full.json")));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(env.lines().len(), 1);
    conn.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn deadline_writes_nothing() {
    let env = Env::new();
    // The first exec of a fresh binary can take hundreds of ms on macOS; warm it up.
    env.run(&["--help"], b"", &[]);
    let start = Instant::now();
    let o = env.run(
        &[],
        fixture("integer.json").as_bytes(),
        &[("AWM_TEST_DELAY_MS", "300")],
    );
    assert!(
        start.elapsed() < Duration::from_millis(300),
        "{:?}",
        start.elapsed()
    );
    assert_silent_ok(&o);
    assert!(env.files().is_empty());
}

#[test]
fn skips_an_unchanged_sample_of_the_same_session() {
    let env = Env::new();
    let full = fixture("full.json");
    env.quiet(&full);
    env.quiet(&full);
    assert_eq!(env.lines().len(), 1);
    env.quiet(&with_cost(&full, 0.5));
    assert_eq!(env.lines().len(), 2);
    let mut other: Value = serde_json::from_str(&full).unwrap();
    other["session_id"] = serde_json::json!("another");
    env.quiet(&other.to_string());
    assert_eq!(env.lines().len(), 3);
    // The newest line of the session is the one compared: back to the first values.
    env.quiet(&full);
    assert_eq!(env.lines().len(), 4);
}

#[test]
fn never_fails() {
    let big = vec![b' '; (1 << 20) + 10];
    let mut over =
        br#"{"session_id":"s","rate_limits":{"five_hour":{"used_percentage":1,"resets_at":5}}}"#
            .to_vec();
    over.extend(vec![b' '; 1 << 20]);
    let inputs: [(&str, &[u8]); 4] = [
        ("invalid", b"not json {"),
        ("empty", b""),
        ("blank over limit", &big),
        ("valid over limit", &over),
    ];
    for (name, input) in inputs {
        let env = Env::new();
        let o = env.run(&["--quiet"], input, &[]);
        assert_silent_ok(&o);
        assert!(!env.quota().exists(), "{name}");
    }

    let env = Env::new();
    std::fs::write(env.quota(), "x").unwrap();
    assert_silent_ok(&env.quiet(&fixture("full.json")));
    assert!(env.quota().is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let env = Env::new();
        std::fs::set_permissions(env.home(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let o = env.quiet(&fixture("full.json"));
        std::fs::set_permissions(env.home(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_silent_ok(&o);
        assert!(!env.quota().exists());
    }
}

#[test]
fn prints_a_short_line_without_quiet() {
    let env = Env::new();
    let o = env.run(&[], fixture("integer.json").as_bytes(), &[]);
    assert_eq!(o.code, Some(0));
    assert!(o.stdout.starts_with("5h 24% ("), "{}", o.stdout);
    assert!(o.stdout.contains(" · 7d 41% ("), "{}", o.stdout);
    assert_eq!(o.stdout.lines().count(), 1);
    assert_eq!(o.stderr, "");
    // The line is printed even when no sample is written.
    let bare = Env::bare();
    let o = bare.run(&[], fixture("integer.json").as_bytes(), &[]);
    assert!(o.stdout.starts_with("5h 24% ("), "{}", o.stdout);
}

#[test]
fn short_line_has_the_remaining_time() {
    let mut v: Value = serde_json::from_str(&fixture("integer.json")).unwrap();
    // 2h10m before the 5h reset and 3d4h before the 7d reset.
    let now = 1738425600 - (2 * 3600 + 10 * 60);
    v["rate_limits"]["seven_day"]["resets_at"] = serde_json::json!(now + 3 * 86400 + 4 * 3600);
    assert_eq!(
        awm::cli::statusline::short_line(&v, now),
        "5h 24% (2h10m) · 7d 41% (3d4h)"
    );
    let d7: Value = serde_json::from_str(&fixture("d7-only.json")).unwrap();
    assert!(awm::cli::statusline::short_line(&d7, now).starts_with("7d 41% ("));
    let none: Value = serde_json::from_str(&fixture("no-limits.json")).unwrap();
    assert_eq!(awm::cli::statusline::short_line(&none, now), "");
}

#[test]
fn drops_out_of_range_values() {
    let env = Env::new();
    let mut v: Value = serde_json::from_str(&fixture("integer.json")).unwrap();
    v["rate_limits"]["five_hour"]["used_percentage"] = serde_json::json!(150);
    v["rate_limits"]["seven_day"]["resets_at"] = serde_json::json!(0);
    assert_silent_ok(&env.quiet(&v.to_string()));
    assert!(env.files().is_empty());

    v["rate_limits"]["seven_day"]["resets_at"] = serde_json::json!(1738857600);
    env.quiet(&v.to_string());
    let lines = env.lines();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].get("h5").is_none());
    assert!(lines[0].get("d7").is_some());

    let env = Env::new();
    v["rate_limits"]["five_hour"]["used_percentage"] = serde_json::json!(-1);
    v["rate_limits"]["seven_day"]["used_percentage"] = serde_json::json!(101);
    env.quiet(&v.to_string());
    assert!(env.files().is_empty());
}

#[cfg(unix)]
#[test]
fn files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    env.quiet(&fixture("full.json"));
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&env.quota()), 0o700);
    assert_eq!(mode(&env.month_file()), 0o600);
}

#[test]
fn help_still_prints() {
    let env = Env::new();
    let o = env.run(&["--help"], b"", &[]);
    assert_eq!(o.code, Some(0));
    assert!(o.stdout.contains("Usage:"), "{}", o.stdout);
    assert!(o.stdout.contains("--quiet"), "{}", o.stdout);
}

#[test]
fn read_all_sorts_and_skips_malformed_lines() {
    let env = Env::new();
    let dir = env.quota();
    std::fs::create_dir_all(&dir).unwrap();
    let line = |t: i64| format!(r#"{{"v":1,"t":{t},"sid":"s","h5":{{"p":1,"r":9}}}}"#);
    std::fs::write(
        dir.join("samples-2026-10.ndjson"),
        format!("{}\n{}\n{{\"v\":1,\"t\":3,\"sid\"", line(30), line(10)),
    )
    .unwrap();
    std::fs::write(
        dir.join("samples-2026-09.ndjson"),
        format!("garbage\n{}\n", line(20)),
    )
    .unwrap();
    std::fs::write(dir.join("notes.ndjson"), format!("{}\n", line(5))).unwrap();
    std::fs::write(
        dir.join("samples-2026-10.ndjson.tmp"),
        format!("{}\n", line(6)),
    )
    .unwrap();
    let ts: Vec<i64> = store::read_all(&dir).iter().map(|s| s.t).collect();
    assert_eq!(ts, [10, 20, 30]);
}

/// 2026-10-15T00:00:00Z: June ended 106 days before, July 75.
const OCT_15: &str = "1792022400000";

#[test]
fn prunes_month_files_past_retention() {
    let env = Env::new();
    let full = fixture("full.json");
    let at = |stdin: &str| {
        let o = env.run(
            &["--quiet"],
            stdin.as_bytes(),
            &[("AWM_TEST_NOW_MS", OCT_15)],
        );
        assert_silent_ok(&o);
    };
    at(&full);
    let q = env.quota();
    let outside = env.dir.path().join("outside-sample");
    std::fs::write(q.join("samples-2026-06.ndjson"), "june\n").unwrap();
    std::fs::write(q.join("samples-2026-07.ndjson"), "july\n").unwrap();
    std::fs::write(q.join("notes.txt"), "mine").unwrap();
    std::fs::write(q.join("samples-2026-06.ndjson.tmp"), "mine").unwrap();
    std::fs::create_dir(q.join("samples-2026-05.ndjson")).unwrap();
    std::fs::write(q.join("samples-2026-05.ndjson/inner"), "mine").unwrap();
    std::fs::write(&outside, "mine").unwrap();
    std::os::unix::fs::symlink(&outside, q.join("samples-2026-04.ndjson")).unwrap();

    // An unchanged sample writes nothing, so nothing is pruned.
    at(&full);
    assert!(q.join("samples-2026-06.ndjson").exists());

    at(&with_cost(&full, 0.5));
    assert!(!q.join("samples-2026-06.ndjson").exists());
    assert_eq!(
        std::fs::read_to_string(q.join("samples-2026-07.ndjson")).unwrap(),
        "july\n"
    );
    assert_eq!(
        std::fs::read_to_string(q.join("notes.txt")).unwrap(),
        "mine"
    );
    assert!(q.join("samples-2026-06.ndjson.tmp").exists());
    assert!(q.join("samples-2026-05.ndjson/inner").exists());
    let link = std::fs::symlink_metadata(q.join("samples-2026-04.ndjson")).unwrap();
    assert!(link.file_type().is_symlink());
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "mine");
    let month = std::fs::read_to_string(q.join("samples-2026-10.ndjson")).unwrap();
    assert_eq!(month.lines().count(), 2);
}

#[test]
fn retention_days_comes_from_config() {
    // 2026-10-11 and 2026-10-06: September ended 10 and 5 days before.
    for (now, kept) in [("1791676800000", false), ("1791244800000", true)] {
        let env = Env::new();
        std::fs::write(
            env.home().join("config.toml"),
            "[quota]\nretention_days = 7\n",
        )
        .unwrap();
        std::fs::create_dir_all(env.quota()).unwrap();
        let sept = env.quota().join("samples-2026-09.ndjson");
        std::fs::write(&sept, "sept\n").unwrap();
        let o = env.run(
            &["--quiet"],
            fixture("full.json").as_bytes(),
            &[("AWM_TEST_NOW_MS", now)],
        );
        assert_silent_ok(&o);
        assert_eq!(sept.exists(), kept, "now {now}");
        assert!(env.month_file().exists());
    }
}

/// A file that cannot be deleted (`chflags uchg`) does not stop the next one.
#[cfg(target_os = "macos")]
#[test]
fn prune_goes_on_after_a_file_it_cannot_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    let stuck = d.join("samples-2026-01.ndjson");
    std::fs::write(&stuck, "x\n").unwrap();
    std::fs::write(d.join("samples-2026-02.ndjson"), "x\n").unwrap();
    let flags = |f: &str| {
        let ok = Command::new("chflags")
            .arg(f)
            .arg(&stuck)
            .status()
            .unwrap()
            .success();
        assert!(ok, "chflags {f}");
    };
    flags("uchg");
    let n = store::prune(d, OCT_15.parse().unwrap(), 92);
    flags("nouchg");
    assert_eq!(n.unwrap(), 1);
    assert!(stuck.exists());
    assert!(!d.join("samples-2026-02.ndjson").exists());
}
