//! `awm serve check` (plan-v3-team §4.8.1; TM15): every line in its order and wording, `--json`,
//! `--external`, no `FAIL` on a fresh install, each `FAIL` and each `WARN` rule of §4.8.1 on a
//! install broken on purpose, and the exit codes 0 / 1 / 2.
//!
//! Run: `cargo test -p awm-server --features all --test serve_check` (the certificate cases need
//! the `acme` feature, the PgStore case `pg` and `AWM_TEST_PG_URL`).
//!
//! The checks read a real data directory and a real `SqliteStore`; the host facts (disk,
//! reboot flag, listeners) are injected through `HostFacts` and the clock is a number.

#![cfg(feature = "sqlite")]

#[path = "support/log.rs"]
mod capture;
#[path = "support/org.rs"]
mod fixtures;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use awm_proto::wire::{Id, Version};
use awm_server::backup::keys as bk;
use awm_server::check::{self, CheckInput, Health, HostFacts, Level, Report};
use awm_server::config::{self, Flags, Resolved};
use awm_server::http;
use awm_server::retention::{Clock, SystemClock};
use awm_server::serve::{self, Command, Invocation, Io, Settings};
use awm_server::store::Store;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use axum::Router;
use capture::Capture;
use fixtures::b64;
use serde_json::{json, Value};
use tower::ServiceExt;

// ---------------------------------------------------------------------------------------------
// Helpers

const CLIENT: &str = "awm/0.2.0 proto/1 redact/3";
/// 2030-01-01T00:00:00Z.
const JAN1_2030: i64 = 1_893_456_000;
const DAY: i64 = 86_400;

fn scratch(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "chk-{tag}-{}-{nanos}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&p).unwrap();
    chmod(&p, 0o700);
    p
}

fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn settings() -> Settings {
    Settings {
        version: Version::new(0, 2, 0),
        env: Arc::new(|_| None),
        log: Arc::new(Capture::default()),
        clock: Arc::new(SystemClock),
        grace: Duration::from_secs(1),
    }
}

fn data_flags(data: &Path) -> Flags {
    Flags {
        data: Some(data.to_path_buf()),
        listen: Some("127.0.0.1:0".into()),
        ..Flags::default()
    }
}

fn resolve(flags: &Flags) -> Resolved {
    config::resolve(flags, &|_| None).expect("a valid configuration")
}

async fn send(
    router: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (u16, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("awm-client", CLIENT);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let body = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };
    let mut req = b.body(body).unwrap();
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        "203.0.113.5".parse::<IpAddr>().unwrap(),
        40_000,
    )));
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A data directory with an organisation: admin `alf` and, when `members` is set, `kit`.
/// Returns the admin's device token.
async fn org_in(data: &Path, members: &[&str]) -> String {
    let r = resolve(&data_flags(data));
    let store = serve::open_store(&r).await.unwrap();
    let state = http::AppState::new(
        store.clone(),
        r.server_config(Version::new(0, 2, 0), Version::new(0, 2, 0)),
    );
    let router = http::router(state);
    let t = awm_server::auth::issue_bootstrap(&*store, SystemClock.now())
        .await
        .unwrap();
    let (s, j) = send(
        &router,
        "POST",
        "/v1/bootstrap",
        None,
        Some(json!({
            "bootstrap_token": t.as_str(), "org_id": Id::new_v4().to_string(), "handle": "alf",
            "device_id": Id::new_v4().to_string(), "device_pubkey": b64(&[1u8; 32]),
        })),
    )
    .await;
    assert_eq!(s, 200);
    let admin = j["device_token"].as_str().unwrap().to_string();
    for handle in members {
        let (s, inv) = send(
            &router,
            "POST",
            "/v1/invites",
            Some(&admin),
            Some(json!({"kind": "member", "handle": handle, "role": "member"})),
        )
        .await;
        assert_eq!(s, 200);
        let device = Id::new_v4();
        let (s, _) = send(
            &router,
            "POST",
            "/v1/join",
            None,
            Some(json!({
                "invite_id": inv["invite_id"], "invite_token": inv["invite_token"],
                "handle": handle, "device_id": device.to_string(),
                "device_pubkey": b64(&[2u8; 32]), "join_mac": b64(&[3u8; 32]),
            })),
        )
        .await;
        assert_eq!(s, 200);
        let wraps =
            json!({"wraps": [{"epoch": 0, "wrap": b64(&[0x5a; 140]), "auth": b64(&[0xa0; 32])}]});
        let (s, _) = send(
            &router,
            "POST",
            &format!("/v1/devices/{device}/approve"),
            Some(&admin),
            Some(wraps),
        )
        .await;
        assert_eq!(s, 204);
    }
    admin
}

fn clean_facts() -> HostFacts {
    HostFacts {
        reboot_required: false,
        disk_free_pct: Some(71),
        public_listeners: Some(vec!["22/tcp".into()]),
        port80_open: false,
    }
}

async fn input(r: Resolved, now: i64) -> CheckInput {
    let store = serve::open_store(&r).await.unwrap();
    CheckInput {
        resolved: r,
        store,
        now,
        version: "0.2.0".into(),
        release_floor: Version::new(0, 2, 0),
        env: Vec::new(),
        facts: clean_facts(),
        health: Health::Status(200),
        external: None,
    }
}

fn level_of(r: &Report, name: &str) -> Level {
    r.line(name)
        .unwrap_or_else(|| panic!("no {name} line in\n{}", r.render()))
        .level
}

fn text_of<'a>(r: &'a Report, name: &str) -> &'a str {
    &r.line(name).unwrap().text
}

const NAMES: [&str; 11] = [
    "listen",
    "tls",
    "files",
    "database",
    "backup",
    "versions",
    "tokens",
    "credentials",
    "limits",
    "retention",
    "health",
];

/// Marks the backup as healthy at `now`.
async fn healthy_backup(store: &dyn Store, now: i64) {
    for (k, v) in [
        (bk::LAST_OK_AT, now - 30),
        (bk::LAST_FULL_AT, now - 3_600),
        (bk::VERIFY_OK_AT, now - DAY),
    ] {
        store.meta_set(k.into(), v.to_string()).await.unwrap();
    }
}

// ---------------------------------------------------------------------------------------------
// The lines and the fresh install

#[tokio::test]
async fn a_fresh_install_prints_every_line_in_order_and_no_fail() {
    let dir = scratch("fresh").join("awm");
    // Create the database the way `init` does, then run the command with a server up.
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = serve::run_async(
        Invocation {
            flags: data_flags(&dir),
            command: Command::Init { print_hash: false },
            settings: settings(),
        },
        &mut Io {
            out: &mut out,
            err: &mut err,
            tty: false,
        },
    )
    .await;
    assert_eq!(code, 0);
    let server = serve::start(&resolve(&data_flags(&dir)), &settings())
        .await
        .unwrap();
    let port = server.addrs[0].port();

    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = serve::run_async(
        Invocation {
            flags: Flags {
                listen: Some(format!("127.0.0.1:{port}")),
                ..data_flags(&dir)
            },
            command: Command::Check {
                json: false,
                external: false,
            },
            settings: settings(),
        },
        &mut Io {
            out: &mut out,
            err: &mut err,
            tty: false,
        },
    )
    .await;
    let text = String::from_utf8(out).unwrap();
    assert_eq!(
        code,
        1,
        "warnings only (no backup, no admin yet):\n{text}\n{}",
        String::from_utf8_lossy(&err)
    );
    assert!(!text.contains("FAIL"), "{text}");
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        lines[0].starts_with("awm serve check  (awm 0.2.0, proto 1, store sqlite ")
            && lines[0].ends_with("server.db)"),
        "{}",
        lines[0]
    );
    let names: Vec<&str> = lines
        .iter()
        .skip(1)
        .filter(|l| !l.starts_with(' ') && !l.starts_with("result:"))
        .map(|l| l[6..].split_whitespace().next().unwrap())
        .collect();
    assert_eq!(names, NAMES, "{text}");
    assert!(text.contains("OK    listen       127.0.0.1:"), "{text}");
    assert!(
        text.contains("(plain, loopback only), no other listener of this process"),
        "{text}"
    );
    assert!(
        text.contains("OK    tls          none: loopback only"),
        "{text}"
    );
    assert!(
        text.contains("OK    database     integrity ok, schema 1,"),
        "{text}"
    );
    assert!(
        text.contains("OK    versions     min_client 0.2.0 (release floor 0.2.0)"),
        "{text}"
    );
    assert!(text.contains("OK    credentials  no key file"), "{text}");
    assert!(
        text.contains("OK    limits       per-IP and per-token limits on; trusted proxies: none"),
        "{text}"
    );
    assert!(text.contains("OK    health       /healthz 200"), "{text}");
    // The two-line NO BACKUP TARGET warning, verbatim (§4.8.1).
    assert!(
        text.contains(
            "WARN  backup       NO BACKUP TARGET: a disk loss destroys membership, invites, key wraps and every record\n                   no member still holds; set --backup gs://... (docs/self-host.md#backup)\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("WARN  tokens       no admin yet: run awm serve init"),
        "{text}"
    );
    assert!(text.ends_with("result: 2 warnings, 0 failures\n"), "{text}");

    // --json: the same as objects.
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = serve::run_async(
        Invocation {
            flags: Flags {
                listen: Some(format!("127.0.0.1:{port}")),
                ..data_flags(&dir)
            },
            command: Command::Check {
                json: true,
                external: false,
            },
            settings: settings(),
        },
        &mut Io {
            out: &mut out,
            err: &mut err,
            tty: false,
        },
    )
    .await;
    assert_eq!(code, 1);
    let v: Value = serde_json::from_slice(&out).unwrap();
    let checks = v["checks"].as_array().unwrap();
    assert_eq!(
        checks
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        NAMES
    );
    assert!(checks
        .iter()
        .all(|c| c["level"] != "FAIL" && c["text"].is_string()));
    assert_eq!(
        (v["warnings"].as_u64(), v["failures"].as_u64()),
        (Some(2), Some(0))
    );
    server.stop(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_missing_database_is_a_fail_and_check_creates_nothing() {
    let dir = scratch("nodb").join("never");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = serve::run_async(
        Invocation {
            flags: data_flags(&dir),
            command: Command::Check {
                json: false,
                external: false,
            },
            settings: settings(),
        },
        &mut Io {
            out: &mut out,
            err: &mut err,
            tty: false,
        },
    )
    .await;
    assert_eq!(code, 2);
    assert!(String::from_utf8(out).unwrap().contains("FAIL  database"));
    assert!(!dir.exists(), "check does not create the database");
}

#[tokio::test]
async fn exit_codes_follow_the_worst_line() {
    let dir = scratch("exit");
    let now = SystemClock.now();
    // All OK: a backup target in good state, two admins, a clean host, a healthy server.
    org_in(&dir, &["kit"]).await;
    let store = serve::open_store(&resolve(&data_flags(&dir)))
        .await
        .unwrap();
    awm_server_promote(&dir, "kit").await;
    healthy_backup(&*store, now).await;
    let mut r = resolve(&data_flags(&dir));
    r.backup = Some("gs://example-bucket/awm".into());
    let report = check::run(&input(r.clone(), now).await).await;
    assert_eq!(report.exit_code(), 0, "{}", report.render());
    assert_eq!(
        report.render().lines().last().unwrap(),
        "result: 0 warnings, 0 failures"
    );
    // One WARN: exit 1.
    let mut i = input(r.clone(), now).await;
    i.facts.reboot_required = true;
    assert_eq!(check::run(&i).await.exit_code(), 1);
    // One FAIL (and a WARN): exit 2.
    i.facts.disk_free_pct = Some(5);
    i.health = Health::Status(503);
    let report = check::run(&i).await;
    assert_eq!(report.exit_code(), 2, "{}", report.render());
    assert_eq!(
        (report.warnings(), report.failures()),
        (1, 1),
        "the reboot note shares the failing health line"
    );
}

async fn awm_server_promote(dir: &Path, handle: &str) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = serve::run_async(
        Invocation {
            flags: data_flags(dir),
            command: Command::Promote {
                handle: handle.into(),
            },
            settings: settings(),
        },
        &mut Io {
            out: &mut out,
            err: &mut err,
            tty: false,
        },
    )
    .await;
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
}

// ---------------------------------------------------------------------------------------------
// FAIL rules

#[tokio::test]
async fn fail_a_public_listener_without_tls() {
    let dir = scratch("fail-listen");
    let mut r = resolve(&data_flags(&dir));
    r.listen = vec!["0.0.0.0:8787".parse().unwrap()];
    let report = check::run(&input(r, SystemClock.now()).await).await;
    assert_eq!(
        level_of(&report, "listen"),
        Level::Fail,
        "{}",
        report.render()
    );
    assert!(text_of(&report, "listen").contains("plain HTTP on a public address"));
    assert_eq!(level_of(&report, "tls"), Level::Fail);
    assert_eq!(report.exit_code(), 2);
    // Behind a TLS proxy the same address is fine.
    let mut r = resolve(&data_flags(&dir));
    r.listen = vec!["0.0.0.0:8080".parse().unwrap()];
    r.behind_tls_proxy = true;
    r.cloud_run = true;
    let report = check::run(&input(r, SystemClock.now()).await).await;
    assert_eq!(
        level_of(&report, "listen"),
        Level::Ok,
        "{}",
        report.render()
    );
    assert!(text_of(&report, "limits").contains("cloud-run (last X-Forwarded-For entry)"));
}

#[tokio::test]
async fn fail_files_readable_by_others() {
    let dir = scratch("fail-files");
    let r = resolve(&data_flags(&dir));
    let i = input(r, SystemClock.now()).await; // creates server.db 0600 in a 0700 directory
    assert_eq!(level_of(&check::run(&i).await, "files"), Level::Ok);
    let text = text_of(&check::run(&i).await, "files").to_string();
    assert!(
        text.contains("server.db 0600") && text.contains("owner "),
        "{text}"
    );
    for (path, mode) in [(dir.clone(), 0o755), (dir.join("server.db"), 0o644)] {
        let was = std::fs::metadata(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        chmod(&path, mode);
        let report = check::run(&i).await;
        assert_eq!(
            level_of(&report, "files"),
            Level::Fail,
            "{mode:o}: {}",
            report.render()
        );
        assert!(text_of(&report, "files").contains("readable by others"));
        chmod(&path, was.permissions().mode() & 0o777);
    }
    // An ACME key that others can read.
    let acme = dir.join("acme");
    std::fs::create_dir_all(&acme).unwrap();
    chmod(&acme, 0o700);
    std::fs::write(acme.join("key.pem"), "x").unwrap();
    chmod(&acme.join("key.pem"), 0o644);
    let report = check::run(&i).await;
    assert_eq!(level_of(&report, "files"), Level::Fail);
    assert!(
        text_of(&report, "files").contains("acme/key.pem"),
        "{}",
        report.render()
    );
}

#[tokio::test]
async fn fail_an_integrity_failure() {
    let dir = scratch("fail-integrity");
    let r = resolve(&data_flags(&dir));
    org_in(&dir, &["kit"]).await;
    let i = input(r, SystemClock.now()).await;
    i.store.checkpoint().await.unwrap();
    assert_eq!(level_of(&check::run(&i).await, "database"), Level::Ok);
    // Overwrite a page in the middle of the file behind the open store.
    use std::io::{Seek, SeekFrom, Write};
    let db = dir.join("server.db");
    let len = std::fs::metadata(&db).unwrap().len();
    assert!(len > 3 * 4096);
    let mut f = std::fs::OpenOptions::new().write(true).open(&db).unwrap();
    f.seek(SeekFrom::Start(4096)).unwrap();
    f.write_all(&vec![0xff; (len - 4096) as usize]).unwrap();
    drop(f);
    let report = check::run(&i).await;
    assert_eq!(
        level_of(&report, "database"),
        Level::Fail,
        "{}",
        report.render()
    );
    assert!(
        text_of(&report, "database").contains("integrity check failed"),
        "{}",
        report.render()
    );
    assert_eq!(report.exit_code(), 2);
}

#[tokio::test]
async fn fail_the_backup_rules() {
    let dir = scratch("fail-backup");
    let now = JAN1_2030;
    let mut r = resolve(&data_flags(&dir));
    r.backup = Some("file:///var/backup/awm".into());
    let i = input(r, now).await;
    let st = &*i.store;
    // No full snapshot at all within 48 h.
    let report = check::run(&i).await;
    assert_eq!(
        level_of(&report, "backup"),
        Level::Fail,
        "{}",
        report.render()
    );
    assert!(text_of(&report, "backup").contains("no full snapshot within 48 h"));
    // A snapshot 47 h old is fine; 49 h old fails.
    healthy_backup(st, now).await;
    st.meta_set(bk::LAST_FULL_AT.into(), (now - 47 * 3_600).to_string())
        .await
        .unwrap();
    assert_eq!(level_of(&check::run(&i).await, "backup"), Level::Ok);
    st.meta_set(bk::LAST_FULL_AT.into(), (now - 49 * 3_600).to_string())
        .await
        .unwrap();
    assert_eq!(level_of(&check::run(&i).await, "backup"), Level::Fail);
    // Uploads failing for more than an hour fail; for 59 minutes they do not.
    healthy_backup(st, now).await;
    st.meta_set(bk::ERROR.into(), "the bucket is unreachable".into())
        .await
        .unwrap();
    st.meta_set(bk::FAILING_SINCE.into(), (now - 59 * 60).to_string())
        .await
        .unwrap();
    assert_eq!(level_of(&check::run(&i).await, "backup"), Level::Ok);
    st.meta_set(bk::FAILING_SINCE.into(), (now - 61 * 60).to_string())
        .await
        .unwrap();
    let report = check::run(&i).await;
    assert_eq!(level_of(&report, "backup"), Level::Fail);
    assert!(text_of(&report, "backup").contains("failing for more than 1 h"));
}

#[tokio::test]
async fn fail_min_client_below_the_release_floor() {
    let dir = scratch("fail-versions");
    org_in(&dir, &[]).await;
    let r = resolve(&data_flags(&dir));
    let mut i = input(r, SystemClock.now()).await;
    assert_eq!(level_of(&check::run(&i).await, "versions"), Level::Ok);
    // The organisation keeps min_client 0.2.0; this release's floor is 0.3.0.
    i.release_floor = Version::new(0, 3, 0);
    let report = check::run(&i).await;
    assert_eq!(
        level_of(&report, "versions"),
        Level::Fail,
        "{}",
        report.render()
    );
    assert!(
        text_of(&report, "versions").contains("min_client 0.2.0 is below the release floor 0.3.0")
    );
}

#[tokio::test]
async fn fail_when_healthz_answers_an_error() {
    let dir = scratch("fail-health");
    let mut i = input(resolve(&data_flags(&dir)), SystemClock.now()).await;
    i.health = Health::Status(503);
    assert_eq!(level_of(&check::run(&i).await, "health"), Level::Fail);
    i.health = Health::Unreachable("cannot connect".into());
    assert_eq!(level_of(&check::run(&i).await, "health"), Level::Warn);
}

// ---------------------------------------------------------------------------------------------
// WARN rules

#[tokio::test]
async fn warn_no_verify_within_30_days() {
    let dir = scratch("warn-verify");
    let now = JAN1_2030;
    let mut r = resolve(&data_flags(&dir));
    r.backup = Some("file:///var/backup/awm".into());
    let i = input(r, now).await;
    healthy_backup(&*i.store, now).await;
    assert_eq!(level_of(&check::run(&i).await, "backup"), Level::Ok);
    let ok = text_of(&check::run(&i).await, "backup").to_string();
    assert!(
        ok.starts_with("file:///var/backup/awm, last upload"),
        "{ok}"
    );
    i.store
        .meta_set(bk::VERIFY_OK_AT.into(), (now - 31 * DAY).to_string())
        .await
        .unwrap();
    let report = check::run(&i).await;
    assert_eq!(
        level_of(&report, "backup"),
        Level::Warn,
        "{}",
        report.render()
    );
    assert!(text_of(&report, "backup").contains("no successful --verify within 30 days"));
    i.store
        .meta_set(bk::VERIFY_OK_AT.into(), (now - 29 * DAY).to_string())
        .await
        .unwrap();
    assert_eq!(level_of(&check::run(&i).await, "backup"), Level::Ok);
}

#[tokio::test]
async fn warn_one_admin_and_devices_unseen_for_90_days() {
    let dir = scratch("warn-tokens");
    let now = SystemClock.now();
    org_in(&dir, &["kit"]).await;
    let r = resolve(&data_flags(&dir));
    let mut i = input(r, now).await;
    let report = check::run(&i).await;
    assert_eq!(
        level_of(&report, "tokens"),
        Level::Warn,
        "{}",
        report.render()
    );
    assert!(
        text_of(&report, "tokens").contains("1 admin (promote a second: awm serve promote HANDLE)"),
        "{}",
        report.render()
    );
    assert!(text_of(&report, "tokens").contains("0 devices unseen for 90 d"));
    assert!(text_of(&report, "tokens").contains("0 open invites"));
    awm_server_promote(&dir, "kit").await;
    assert_eq!(level_of(&check::run(&i).await, "tokens"), Level::Ok);
    // 89 days later nothing has been seen for 89 days; at 91 days both devices are unseen.
    i.now = now + 89 * DAY;
    assert_eq!(level_of(&check::run(&i).await, "tokens"), Level::Ok);
    i.now = now + 91 * DAY;
    let report = check::run(&i).await;
    assert_eq!(level_of(&report, "tokens"), Level::Warn);
    assert!(
        text_of(&report, "tokens").contains("2 devices unseen for 90 d"),
        "{}",
        report.render()
    );
}

#[tokio::test]
async fn warn_a_key_file_in_the_environment_and_host_conditions() {
    let dir = scratch("warn-host");
    let mut i = input(resolve(&data_flags(&dir)), SystemClock.now()).await;
    i.env = vec![(
        "GOOGLE_APPLICATION_CREDENTIALS".into(),
        "/secrets/key.json".into(),
    )];
    let report = check::run(&i).await;
    assert_eq!(level_of(&report, "credentials"), Level::Warn);
    assert!(text_of(&report, "credentials").contains("GOOGLE_APPLICATION_CREDENTIALS"));
    assert!(
        !report.render().contains("/secrets/key.json"),
        "names only, never values"
    );
    i.env.clear();
    assert_eq!(level_of(&check::run(&i).await, "credentials"), Level::Ok);

    // /var/run/reboot-required.
    i.facts.reboot_required = true;
    let report = check::run(&i).await;
    assert_eq!(level_of(&report, "health"), Level::Warn);
    assert!(text_of(&report, "health").contains("reboot is pending"));
    i.facts.reboot_required = false;

    // Disk below 20% free: 19 warns, 20 does not.
    i.facts.disk_free_pct = Some(19);
    let report = check::run(&i).await;
    assert_eq!(
        level_of(&report, "database"),
        Level::Warn,
        "{}",
        report.render()
    );
    assert!(text_of(&report, "database").contains("disk 19% free (below 20%)"));
    i.facts.disk_free_pct = Some(20);
    assert_eq!(level_of(&check::run(&i).await, "database"), Level::Ok);

    // Host listeners are printed; an unreadable list says so.
    i.facts.public_listeners = Some(vec!["22/tcp".into(), "443/tcp".into()]);
    assert!(text_of(&check::run(&i).await, "listen")
        .contains("host listeners on public addresses: 22/tcp, 443/tcp"));
    i.facts.public_listeners = None;
    assert!(text_of(&check::run(&i).await, "listen").contains("not probed"));
}

#[tokio::test]
async fn host_facts_collect_does_not_fail_on_this_system() {
    let dir = scratch("facts");
    let f = HostFacts::collect(Some(&dir));
    if let Some(p) = f.disk_free_pct {
        assert!(p <= 100);
    }
    // Reading the real system twice gives the same shape.
    assert_eq!(
        f.public_listeners.is_some(),
        HostFacts::collect(Some(&dir)).public_listeners.is_some()
    );
}

// ---------------------------------------------------------------------------------------------
// Certificates (TLS lines and --external)

#[cfg(feature = "acme")]
mod tls_lines {
    use super::*;
    use awm_server::check::External;
    use awm_server::tls::cache::{AcmeCache, AcmeState};

    /// A self-signed certificate valid from 2030-01-01 for `days`, written to `{data}/acme`.
    fn seed(data: &Path, name: &str, days: i64) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2030, 1, 1);
        let (y, m, d) = ymd_after_2030(days);
        params.not_after = rcgen::date_time_ymd(y, m, d);
        let cert = params.self_signed(&key).unwrap();
        AcmeCache::open(&data.join("acme"))
            .unwrap()
            .save_cert(&cert.pem(), &key.serialize_pem())
            .unwrap();
    }

    /// 2030-01-01 plus `days` (at most a few months; 2030 is not a leap year).
    fn ymd_after_2030(days: i64) -> (i32, u8, u8) {
        const LEN: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let (mut left, mut month) = (days, 0usize);
        while left >= LEN[month] {
            left -= LEN[month];
            month += 1;
        }
        (2030, month as u8 + 1, left as u8 + 1)
    }

    fn tls_resolved(data: &Path, domain: &str) -> Resolved {
        resolve(&Flags {
            domain: Some(domain.into()),
            listen: Some("127.0.0.1:443".into()),
            ..data_flags(data)
        })
    }

    #[tokio::test]
    async fn fail_a_certificate_expiring_within_7_days_or_2_for_shortlived() {
        let dir = scratch("fail-expiry");
        seed(&dir, "awm.example.com", 30);
        let mut i = input(tls_resolved(&dir, "awm.example.com"), JAN1_2030 + 10 * DAY).await;
        // 20 days left: fine, and the text shows the days, the challenge and the cache modes.
        let report = check::run(&i).await;
        assert_eq!(level_of(&report, "tls"), Level::Ok, "{}", report.render());
        let t = text_of(&report, "tls");
        assert!(
            t.starts_with("acme tls-alpn-01, awm.example.com, expires in 20 d"),
            "{t}"
        );
        assert!(t.contains("cache 0700/0600"), "{t}");
        // 8 days left: still fine. 6 days: FAIL.
        i.now = JAN1_2030 + 22 * DAY;
        assert_eq!(level_of(&check::run(&i).await, "tls"), Level::Ok);
        i.now = JAN1_2030 + 24 * DAY;
        let report = check::run(&i).await;
        assert_eq!(level_of(&report, "tls"), Level::Fail, "{}", report.render());
        assert!(text_of(&report, "tls").contains("FAIL within 7 d"));
        // An IP certificate (shortlived) fails only within 2 days: 3 days left is fine.
        let dir = scratch("fail-expiry-ip");
        seed(&dir, "203.0.113.7", 5);
        let mut i = input(tls_resolved(&dir, "203.0.113.7"), JAN1_2030 + 2 * DAY).await;
        assert_eq!(level_of(&check::run(&i).await, "tls"), Level::Ok);
        i.now = JAN1_2030 + 4 * DAY;
        let report = check::run(&i).await;
        assert_eq!(level_of(&report, "tls"), Level::Fail, "{}", report.render());
        assert!(text_of(&report, "tls").contains("FAIL within 2 d"));
        // No certificate at all.
        let dir = scratch("fail-nocert");
        let i = input(tls_resolved(&dir, "awm.example.com"), JAN1_2030).await;
        assert_eq!(level_of(&check::run(&i).await, "tls"), Level::Fail);
    }

    #[tokio::test]
    async fn fail_an_acme_error_older_than_a_day_and_warn_for_a_newer_one() {
        let dir = scratch("fail-acme-error");
        seed(&dir, "awm.example.com", 90);
        let now = JAN1_2030 + 10 * DAY;
        let i = input(tls_resolved(&dir, "awm.example.com"), now).await;
        let cache = AcmeCache::open(&dir.join("acme")).unwrap();
        let mut state = AcmeState {
            last_error: Some("new order: rate limited".into()),
            last_error_at: Some(now - 3_600),
            failures: 2,
            ari_start: Some(now + 20 * DAY),
            ari_end: Some(now + 23 * DAY),
            ..AcmeState::default()
        };
        cache.save_state(&state).unwrap();
        let report = check::run(&i).await;
        assert_eq!(level_of(&report, "tls"), Level::Warn, "{}", report.render());
        assert!(text_of(&report, "tls").contains("under a day"));
        assert!(
            text_of(&report, "tls").contains("ARI window 2030-01-31..2030-02-03"),
            "{}",
            text_of(&report, "tls")
        );
        state.last_error_at = Some(now - DAY - 1);
        cache.save_state(&state).unwrap();
        let report = check::run(&i).await;
        assert_eq!(level_of(&report, "tls"), Level::Fail, "{}", report.render());
        assert!(text_of(&report, "tls").contains("more than a day"));
        // A cleared error is fine again.
        cache.save_state(&AcmeState::default()).unwrap();
        assert_eq!(level_of(&check::run(&i).await, "tls"), Level::Ok);
    }

    #[tokio::test]
    async fn warn_port_80_open_while_the_challenge_is_tls_alpn_01() {
        let dir = scratch("warn-port80");
        seed(&dir, "awm.example.com", 90);
        let mut i = input(tls_resolved(&dir, "awm.example.com"), JAN1_2030 + DAY).await;
        assert_eq!(level_of(&check::run(&i).await, "tls"), Level::Ok);
        i.facts.port80_open = true;
        let report = check::run(&i).await;
        assert_eq!(level_of(&report, "tls"), Level::Warn, "{}", report.render());
        assert!(text_of(&report, "tls").contains("port 80 is open"));
        // With http-01 an open port 80 is expected.
        let dir = scratch("port80-http01");
        seed(&dir, "awm.example.com", 90);
        let mut r = tls_resolved(&dir, "awm.example.com");
        r.acme.as_mut().unwrap().challenge = config::Challenge::Http01;
        let mut i = input(r, JAN1_2030 + DAY).await;
        i.facts.port80_open = true;
        assert_eq!(level_of(&check::run(&i).await, "tls"), Level::Ok);
    }

    /// A CA and a leaf for `localhost`, as files in `dir`.
    fn make_pki(dir: &Path) -> PathBuf {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let cache = AcmeCache::open(&dir.join("acme")).unwrap();
        cache
            .save_cert(
                &format!("{}{}", leaf.pem(), ca.pem()),
                &leaf_key.serialize_pem(),
            )
            .unwrap();
        let ca_path = dir.join("ca.pem");
        std::fs::write(&ca_path, ca.pem()).unwrap();
        ca_path
    }

    #[tokio::test]
    async fn external_fetches_v1_info_over_https_from_this_host() {
        let dir = scratch("external");
        let ca = make_pki(&dir);
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let flags = Flags {
            data: Some(dir.clone()),
            domain: Some("localhost".into()),
            listen: Some(format!("127.0.0.1:{port}")),
            acme_directory: Some("https://127.0.0.1:9/dir".into()),
            acme_ca_file: Some(ca.clone()),
            ..Flags::default()
        };
        let server = serve::start(&resolve(&flags), &settings())
            .await
            .expect("the cached certificate is served");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = serve::run_async(
            Invocation {
                flags: flags.clone(),
                command: Command::Check {
                    json: false,
                    external: true,
                },
                settings: settings(),
            },
            &mut Io {
                out: &mut out,
                err: &mut err,
                tty: false,
            },
        )
        .await;
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains(&format!("OK    external     https://localhost:{port}/v1/info answered: server 0.2.0, protocols 1")),
            "{text}\n{}",
            String::from_utf8_lossy(&err)
        );
        assert!(
            text.contains("OK    health       /healthz 200"),
            "the local probe works over TLS too: {text}"
        );
        assert!(!text.contains("FAIL"), "{text}");
        assert_eq!(code, 1, "only the warnings of a new install");
        server.stop(Duration::from_secs(1)).await;

        // Nothing answers any more: the external line fails and so does the exit code.
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = serve::run_async(
            Invocation {
                flags: flags.clone(),
                command: Command::Check {
                    json: true,
                    external: true,
                },
                settings: settings(),
            },
            &mut Io {
                out: &mut out,
                err: &mut err,
                tty: false,
            },
        )
        .await;
        assert_eq!(code, 2, "{}", String::from_utf8_lossy(&out));
        let v: Value = serde_json::from_slice(&out).unwrap();
        let ext = v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "external")
            .unwrap();
        assert_eq!(ext["level"], "FAIL");
        // Without --domain there is no public name to fetch.
        let r = resolve(&data_flags(&scratch("external-nodomain")));
        let mut i = input(r, JAN1_2030).await;
        i.external = Some(External {
            url: "(no --domain)".into(),
            result: Err("needs --domain".into()),
        });
        assert_eq!(level_of(&check::run(&i).await, "external"), Level::Fail);
    }
}

// ---------------------------------------------------------------------------------------------
// PgStore

#[cfg(feature = "pg")]
#[path = "support/pg.rs"]
mod pg;

#[cfg(feature = "pg")]
#[tokio::test]
async fn pgstore_skips_the_host_lines_and_shows_no_fail() {
    let Some(env) = pg::PgEnv::new("check").await else {
        eprintln!("SKIP pgstore_skips_the_host_lines: AWM_TEST_PG_URL is not set");
        return;
    };
    let app: &'static str = Box::leak(env.app_url.clone().into_boxed_str());
    let envs: &'static [(&'static str, &'static str)] = Box::leak(Box::new([("AWM_DB", app)]));
    let flags = Flags {
        database_url_env: Some("AWM_DB".into()),
        listen: Some("127.0.0.1:0".into()),
        ..Flags::default()
    };
    let r = config::resolve(&flags, &|k| {
        envs.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| v.to_string())
    })
    .unwrap();
    let report = check::run(&input(r, SystemClock.now()).await).await;
    assert!(
        report.header.ends_with("store postgres)"),
        "{}",
        report.header
    );
    assert_eq!(level_of(&report, "files"), Level::Ok);
    assert!(
        text_of(&report, "files").starts_with("not applicable"),
        "{}",
        report.render()
    );
    assert!(
        text_of(&report, "database").starts_with("postgres answers"),
        "{}",
        report.render()
    );
    assert_eq!(report.failures(), 0, "{}", report.render());

    // RVT2 M4: with --database-insecure-network the database line warns.
    let r = config::resolve(
        &Flags {
            database_insecure_network: true,
            ..flags
        },
        &|k| {
            envs.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        },
    )
    .unwrap();
    let report = check::run(&input(r, SystemClock.now()).await).await;
    assert_eq!(
        level_of(&report, "database"),
        Level::Warn,
        "{}",
        report.render()
    );
    assert!(
        text_of(&report, "database").contains("--database-insecure-network"),
        "{}",
        report.render()
    );
    assert_eq!(report.failures(), 0, "{}", report.render());
}
