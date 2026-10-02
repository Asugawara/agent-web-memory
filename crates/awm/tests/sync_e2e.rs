//! The sync client against a real in-process server (plan-v3-team §4.6, TM10).
//!
//! Run: `cargo test -p agent-web-memory --features sync,serve --test sync_e2e`.
//!
//! Each test starts its own server (`awm_server::http::embedded`, a loopback port picked by the
//! OS, a `SqliteStore` in a scratch directory) and one or more machines ("nodes"), each with its
//! own data directory (what `AWM_HOME` names), database, `team.toml` and `team.key`. The harness
//! plays the part of `awm team create/join/approve` (TM12's stubs): it bootstraps the organisation
//! through `POST /v1/bootstrap` and `awm_proto::keys`, invites, joins, and lets the admin's
//! engine approve through `Opts::approve`. A "forger" is a member whose records the test seals by
//! hand, to give the pull-side checks input no honest client would send.

#![cfg(all(feature = "sync", feature = "serve"))]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use awm::config::{AutoApprove, Config};
use awm::db::{self, Role};
use awm::record::sha256_hex;
use awm::sync::http::{own_version, Client};
use awm::sync::state::{self, Identity, PendingInvite, TeamKey, TeamToml};
use awm::sync::{push, roster};
use awm::sync::{Env, Opts, Outcome, Report};
use awm_proto::crypto::{open_record, seal_record, RecordAd};
use awm_proto::keys::{accept_join, DeviceKeys, Invite, KeyRing, RosterEntry, Wrap, ROSTER_TAG};
use awm_proto::wire::{Id, Key32, KeysResponse, RosterPlaintext, B64};
use awm_server::auth;
use awm_server::http::embedded::{self, Embedded};
use awm_server::http::{AppState, LogSink, ServerConfig};
use awm_server::store::sqlite::SqliteStore;
use awm_server::store::Store;
use rusqlite::Connection;
use serde_json::{json, Value};

mod support;
use support::{bare, coded, Proxy};

// ---------------------------------------------------------------------------------------------
// The server

#[derive(Default)]
struct Capture(Mutex<Vec<String>>);

impl LogSink for Capture {
    fn line(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_string());
    }
}

fn unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn now_ms() -> i64 {
    unix_secs() * 1_000
}

struct Srv {
    store: Arc<SqliteStore>,
    emb: Option<Embedded>,
    addr: SocketAddr,
    dir: tempfile::TempDir,
    logs: Arc<Capture>,
    snaps: AtomicUsize,
}

fn server_config() -> ServerConfig {
    let v = own_version();
    let mut c = ServerConfig::new(v.clone(), v);
    // Tests push thousands of records and run many syncs a minute.
    c.limits.records_per_day = 1_000_000;
    c.limits.requests_per_minute = 1_000_000;
    c.limits.request_burst = 1_000_000;
    c.limits.anonymous_per_minute = 1_000_000;
    c.limits.joins_per_hour = 1_000;
    c
}

impl Srv {
    fn start() -> Srv {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SqliteStore::open(&dir.path().join("data")).unwrap());
        let logs = Arc::new(Capture::default());
        let emb = embedded::spawn(Srv::state(&store, &logs)).unwrap();
        Srv {
            store,
            addr: emb.addr(),
            emb: Some(emb),
            dir,
            logs,
            snaps: AtomicUsize::new(0),
        }
    }

    fn state(store: &Arc<SqliteStore>, logs: &Arc<Capture>) -> AppState {
        AppState::new(store.clone() as Arc<dyn Store>, server_config()).with_log_sink(logs.clone())
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn anonymous(&self) -> Client {
        Client::new(&self.url(), None, None).unwrap()
    }

    /// Stops the server (connections are refused afterwards).
    fn stop(&mut self) {
        if let Some(mut e) = self.emb.take() {
            e.stop();
        }
    }

    /// Starts the stopped server again on the same address and store.
    fn resume(&mut self) {
        let emb = embedded::spawn_on(self.addr, Srv::state(&self.store, &self.logs)).unwrap();
        self.emb = Some(emb);
    }

    fn snapshot(&self) -> PathBuf {
        let n = self.snaps.fetch_add(1, Ordering::SeqCst);
        let dest = self.dir.path().join(format!("snap-{n}.db"));
        embedded::block_on(self.store.snapshot(dest.clone())).unwrap();
        dest
    }

    /// Replaces the server with the copy in `snap` under a new generation, as
    /// `awm serve restore` does (sync-v1 §11).
    fn restore(&mut self, snap: &Path) {
        self.stop();
        let data = self.dir.path().join("data");
        for f in ["server.db", "server.db-wal", "server.db-shm"] {
            let _ = std::fs::remove_file(data.join(f));
        }
        std::fs::copy(snap, data.join("server.db")).unwrap();
        let store = Arc::new(SqliteStore::open(&data).unwrap());
        embedded::block_on(store.renew_generation(unix_secs())).unwrap();
        self.store = store;
        self.resume();
    }

    fn bootstrap_token(&self) -> String {
        embedded::block_on(auth::issue_bootstrap(&*self.store, unix_secs()))
            .unwrap()
            .as_str()
            .to_string()
    }

    fn log_text(&self) -> String {
        self.logs.0.lock().unwrap().join("\n")
    }

    /// A server that withholds the rotation flag (compromised, or rolled back by its operator):
    /// clears `rotation_needed` in its database (RVT2 M3).
    fn withhold_rotation(&self) {
        let conn = Connection::open(self.dir.path().join("data").join("server.db")).unwrap();
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        conn.execute("UPDATE org SET rotation_needed = 0", [])
            .unwrap();
    }
}

// ---------------------------------------------------------------------------------------------
// A machine

const CWD: &str = "/work/shared-project";

fn cwd_hash() -> String {
    sha256_hex(CWD)
}

struct Node {
    dir: tempfile::TempDir,
    handle: String,
    cfg: Config,
}

fn yes(_: AutoApprove, _: bool) -> bool {
    true
}

impl Node {
    /// A data directory with a migrated database and a share rule for the shared project.
    fn blank(handle: &str) -> Node {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = db::open(&dir.path().join("awm.db"), Role::Cli).unwrap();
        db::migrate(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO share_rule (kind, value, created_at) VALUES ('cwd', ?1, 0)",
            [cwd_hash()],
        )
        .unwrap();
        Node {
            dir,
            handle: handle.to_string(),
            cfg: Config::default(),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn conn(&self) -> Connection {
        db::open(&self.path().join("awm.db"), Role::Cli).unwrap()
    }

    fn env(&self) -> Env {
        Env {
            data_dir: self.path().to_path_buf(),
            config: self.cfg.clone(),
            now_ms: None,
        }
    }

    fn ident(&self) -> Identity {
        Identity::load(self.path()).unwrap()
    }

    fn client(&self) -> Client {
        let i = self.ident();
        Client::new(&i.team.server_url, Some(&i.key.device_token), None).unwrap()
    }

    fn opts(&self) -> Opts {
        Opts {
            approve: Some(yes),
            ..Opts::default()
        }
    }

    fn try_sync(&self, opts: &Opts) -> anyhow::Result<Outcome> {
        awm::sync::run(&self.env(), opts)
    }

    /// One run that must finish.
    fn sync(&self) -> Report {
        match self.try_sync(&self.opts()).unwrap() {
            Outcome::Done(r) => r,
            other => panic!("the run did not finish: {other:?}"),
        }
    }

    fn count(&self, sql: &str) -> i64 {
        self.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn text(&self, sql: &str) -> String {
        self.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn state(&self, key: &str) -> Option<String> {
        state::get(&self.conn(), key).unwrap()
    }

    /// A local WebFetch row in the shared project; returns its `event.id`.
    fn capture_fetch(&self, n: u32, url: &str, prompt: &str, summary: &str) -> i64 {
        let conn = self.conn();
        let norm = awm::normalize::norm_url(url).unwrap();
        conn.execute(
            "INSERT INTO event (tool_use_id, tool, session_id, cwd_hash, created_at, url, url_norm, \
               fetch_prompt, status, summary, match_text, source) \
             VALUES (?1, 'WebFetch', ?2, ?3, ?4, ?5, ?6, ?7, 'ok', ?8, ?9, 'hook')",
            rusqlite::params![
                format!("toolu_{}_{n}", self.handle),
                format!("sess-{}-private", self.handle),
                cwd_hash(),
                now_ms() - 1_000,
                url,
                norm,
                prompt,
                summary,
                format!("{url} {prompt} {summary}"),
            ],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn team_rows(&self) -> i64 {
        self.count("SELECT COUNT(*) FROM event WHERE origin = 'team'")
    }

    fn url_hits(&self, url: &str) -> usize {
        let norm = awm::normalize::norm_url(url).unwrap();
        let opts = awm::matching::MatchOpts {
            limit: 3,
            ..Default::default()
        };
        awm::matching::url_channel(&self.conn(), &norm, &opts)
            .unwrap()
            .len()
    }
}

/// Writes `team.toml` and `team.key` of a machine.
fn write_identity(
    node: &Node,
    url: &str,
    org: Id,
    (member, device): (Id, Id),
    token: &str,
    keys: &DeviceKeys,
    ring: &KeyRing,
) {
    TeamToml {
        server_url: url.to_string(),
        org_id: org,
        member_id: member,
        handle: node.handle.clone(),
        device_id: device,
        ca_file: None,
    }
    .save(node.path())
    .unwrap();
    let mut key = TeamKey {
        device_token: token.to_string(),
        previous_device_token: None,
        device_secret: Key32(*keys.secret_bytes()),
        epoch_keys: Vec::new(),
        pending_invites: Vec::new(),
        extra: Default::default(),
    };
    key.set_ring(ring);
    key.save(node.path()).unwrap();
}

/// `awm team create`: the first admin, bootstrapped on the server, with the genesis roster entry
/// queued (the node's first sync pushes it).
fn create_org(srv: &Srv, handle: &str) -> Node {
    let node = Node::blank(handle);
    let keys = DeviceKeys::generate().unwrap();
    let device = Id::new_v4();
    let (ring, nonce) = KeyRing::create(*device.as_uuid(), &keys.public).unwrap();
    let org = Id::from(ring.org());
    let resp: Value = srv
        .anonymous()
        .post(
            "/v1/bootstrap",
            &json!({
                "bootstrap_token": srv.bootstrap_token(),
                "org_id": org,
                "handle": handle,
                "device_id": device,
                "device_pubkey": Key32(keys.public),
            }),
        )
        .unwrap();
    let member = Id::parse(resp["member_id"].as_str().unwrap()).unwrap();
    write_identity(
        &node,
        &srv.url(),
        org,
        (member, device),
        resp["device_token"].as_str().unwrap(),
        &keys,
        &ring,
    );
    let ident = node.ident();
    let mut conn = node.conn();
    push::queue_roster_entry(
        &mut conn,
        &ident,
        &ring,
        &RosterEntry::Genesis {
            member_id: *member.as_uuid(),
            handle: handle.to_string(),
            device_id: *device.as_uuid(),
            device_pub: keys.public,
            org_nonce: nonce,
            created_at: unix_secs(),
        },
        now_ms(),
    )
    .unwrap();
    node
}

/// `awm team invite` and `awm team join`, then the admin's engine approves (`Opts::approve`) and
/// the new device takes its wraps (`accept_join`).
fn add_member(srv: &Srv, admin: &Node, handle: &str, role: &str) -> Node {
    let ai = admin.ident();
    let inv: Value = admin
        .client()
        .post(
            "/v1/invites",
            &json!({"kind": "member", "handle": handle, "role": role}),
        )
        .unwrap();
    let invite = Invite::create(
        *ai.team.org_id.as_uuid(),
        inv["invite_id"].as_str().unwrap(),
        inv["invite_token"].as_str().unwrap(),
        handle,
    )
    .unwrap();
    let mut key = ai.key.clone();
    key.pending_invites.push(PendingInvite {
        invite: invite.encode(),
        kind: "member".into(),
        member_id: None,
        role: Some(role.into()),
    });
    key.save(admin.path()).unwrap();

    let keys = DeviceKeys::generate().unwrap();
    let device = Id::new_v4();
    let joined: Value = srv
        .anonymous()
        .post(
            "/v1/join",
            &json!({
                "invite_id": inv["invite_id"],
                "invite_token": inv["invite_token"],
                "handle": handle,
                "device_id": device,
                "device_pubkey": Key32(keys.public),
                "join_mac": Key32(invite.join_mac(*device.as_uuid(), &keys.public)),
            }),
        )
        .unwrap();
    let token = joined["device_token"].as_str().unwrap().to_string();
    let member = Id::parse(joined["member_id"].as_str().unwrap()).unwrap();

    let report = admin.sync();
    assert_eq!(report.approvals, 1, "the admin approved the join");

    let c = Client::new(&srv.url(), Some(&token), None).unwrap();
    let resp: KeysResponse = c.get("/v1/keys").unwrap();
    let wraps: Vec<Wrap> = resp
        .wraps
        .iter()
        .map(|w| Wrap {
            device_id: *device.as_uuid(),
            epoch: w.epoch,
            approver_device: *w.created_by.as_uuid(),
            blob: w.wrap.0.clone(),
            auth: w.auth.0,
        })
        .collect();
    let ring = accept_join(&invite, *device.as_uuid(), &keys, &wraps).unwrap();
    let node = Node::blank(handle);
    write_identity(
        &node,
        &srv.url(),
        Id::from(ring.org()),
        (member, device),
        &token,
        &keys,
        &ring,
    );
    node
}

/// A new organisation with `admin` and one member `bob`, both synced once.
fn org_of_two() -> (Srv, Node, Node) {
    let srv = Srv::start();
    let a = create_org(&srv, "ann");
    a.sync();
    let b = add_member(&srv, &a, "bob", "member");
    b.sync();
    (srv, a, b)
}

// ---------------------------------------------------------------------------------------------
// Records written by hand (a teammate's client that does not follow the rules)

fn rec_plaintext(url: &str, summary: &str, created_at: i64) -> Value {
    json!({
        "schema": 1,
        "tool": "WebFetch",
        "url": url,
        "status": "ok",
        "summary": summary,
        "results": [],
        "agent": "claude",
        "source": "hook",
        "created_at": created_at,
        "share": "full",
    })
}

fn seal_forged(ident: &Identity, ring: &KeyRing, idx: u64, id: Id, plain: &[u8]) -> Vec<u8> {
    let epoch = ring.current_epoch();
    seal_record(
        ring.current(),
        &push::own_ad(ident, ring, "rec", idx, id, epoch),
        plain,
    )
    .unwrap()
}

fn push_blobs(node: &Node, items: Vec<(u64, Id, Vec<u8>)>) {
    let epoch = node.ident().ring().unwrap().current_epoch();
    let records: Vec<Value> = items
        .into_iter()
        .map(|(idx, id, blob)| json!({"tag": "rec", "idx": idx, "id": id, "epoch": epoch, "blob": B64(blob)}))
        .collect();
    let _: Value = node
        .client()
        .post("/v1/records", &json!({ "records": records }))
        .unwrap();
}

/// A member who never runs the engine: the author of hand-made records.
fn forger(srv: &Srv, admin: &Node) -> Node {
    add_member(srv, admin, "mallory", "member")
}

// ---------------------------------------------------------------------------------------------
// Tests

#[test]
fn a_record_captured_by_a_appears_in_bs_search_with_a_handle_and_no_private_field() {
    let (srv, a, b) = org_of_two();
    let url = "https://docs.example.org/guide/start";
    a.capture_fetch(
        1,
        url,
        "how do I reach me@example.org about this",
        "The guide explains setup in three steps.",
    );
    let r = a.sync();
    assert_eq!(r.pushed, 1);
    assert_eq!(
        a.text("SELECT shareable FROM event WHERE origin = 'local'"),
        "full"
    );
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE pushed_at IS NOT NULL"),
        1
    );
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE sync_idx = 0 AND sync_id IS NOT NULL"),
        1
    );
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 0);

    let r = b.sync();
    assert_eq!(r.pulled, 1);
    assert_eq!(b.url_hits(url), 1, "the teammate's note matches by URL");
    let member = a.ident().team.member_id.to_string();
    assert_eq!(
        b.text("SELECT member FROM event WHERE origin = 'team'"),
        member
    );
    assert_eq!(
        b.text("SELECT session_id FROM event WHERE origin = 'team'"),
        format!("team:{member}")
    );
    assert_eq!(
        b.text("SELECT cwd_hash FROM event WHERE origin = 'team'"),
        ""
    );
    assert_eq!(
        b.count("SELECT COUNT(*) FROM event WHERE origin = 'team' AND agent_id IS NOT NULL"),
        0
    );
    let asked = b.text("SELECT COALESCE(fetch_prompt, '') FROM event WHERE origin = 'team'");
    assert!(!asked.contains("me@example.org"), "{asked}");
    assert!(!asked.is_empty());
    assert_eq!(
        b.text("SELECT team_member.handle FROM team_member WHERE member_id = (SELECT member FROM event WHERE origin = 'team')"),
        "ann"
    );
    // B's own rows are not sent back to B.
    assert_eq!(
        b.count("SELECT COUNT(*) FROM event WHERE origin = 'local'"),
        0
    );
    // The server's request log holds no token and no record text.
    let log = srv.log_text();
    assert!(!log.is_empty());
    for secret in [
        a.ident().key.device_token,
        b.ident().key.device_token,
        "docs.example.org".to_string(),
        "setup in three steps".to_string(),
    ] {
        assert!(!log.contains(&secret), "{secret}");
    }
}

const URL_A: &str = "https://docs.example.org/guide/start";

/// The roster side of `awm team remove`: the server call and the signed `revoke` entry.
fn remove_member(admin: &Node, member: Id) {
    remove_member_at(admin, member, unix_secs());
}

/// [`remove_member`] with the revocation dated `revoked_at` (the revoking admin's clock).
fn remove_member_at(admin: &Node, member: Id, revoked_at: i64) {
    admin.client().remove_member(member).unwrap();
    queue_revoke(admin, member, revoked_at);
}

/// Only the signed `revoke` entry, dated `revoked_at`.
fn queue_revoke(admin: &Node, member: Id, revoked_at: i64) {
    let ident = admin.ident();
    let ring = ident.ring().unwrap();
    let mut conn = admin.conn();
    push::queue_roster_entry(
        &mut conn,
        &ident,
        &ring,
        &RosterEntry::Revoke {
            member_id: *member.as_uuid(),
            device_id: None,
            revoked_at,
            by_device_id: *ident.team.device_id.as_uuid(),
        },
        now_ms(),
    )
    .unwrap();
}

/// The `created_at` of the `epoch` entry for `epoch` in a node's stored roster records.
fn epoch_created_at(node: &Node, epoch: u32) -> Option<i64> {
    let ring = node.ident().ring().unwrap();
    for b in roster::blobs(&node.conn()).unwrap() {
        let ad = RecordAd {
            org: ring.org(),
            member: b.member,
            device: b.device,
            tag: ROSTER_TAG.to_string(),
            idx: b.idx,
            record_id: b.record_id,
            epoch: b.epoch,
        };
        let Ok(plain) = open_record(&ring, &ad, &b.blob) else {
            continue;
        };
        let p: RosterPlaintext = serde_json::from_slice(&plain).unwrap();
        if let RosterEntry::Epoch {
            epoch: e,
            created_at,
            ..
        } = p.entry
        {
            if e == epoch {
                return Some(created_at);
            }
        }
    }
    None
}

/// The epochs the server holds a wrap of for `device`.
fn wrap_epochs(srv: &Srv, device: Id) -> Vec<u32> {
    let mut v: Vec<u32> = embedded::block_on(srv.store.keys(device))
        .unwrap()
        .wraps
        .iter()
        .map(|w| w.epoch)
        .collect();
    v.sort_unstable();
    v
}

/// A run of the admin against a server that withholds `rotation_needed`.
fn sync_withheld(srv: &Srv, node: &Node) -> Report {
    srv.withhold_rotation();
    node.sync()
}

fn rows_of(conn: &Connection, sql: &str) -> Vec<String> {
    let mut st = conn.prepare(sql).unwrap();
    st.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

// --- lock, backoff, dead server, --quiet ------------------------------------------------------

#[test]
fn a_second_concurrent_run_exits_at_once() {
    let (_srv, a, _b) = org_of_two();
    let lock = std::fs::File::options()
        .create(true)
        .write(true)
        .truncate(false)
        .open(a.path().join("sync.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let t = std::time::Instant::now();
    let out = a.try_sync(&a.opts()).unwrap();
    assert_eq!(out, Outcome::Locked);
    assert!(t.elapsed() < std::time::Duration::from_secs(1));
    drop(lock);
    assert!(matches!(a.try_sync(&a.opts()).unwrap(), Outcome::Done(_)));
}

#[test]
fn a_dead_server_fails_within_the_timeout_keeps_the_outbox_and_backs_off_1_2_4_minutes() {
    let (mut srv, a, _b) = org_of_two();
    a.capture_fetch(1, URL_A, "p", "a summary of the guide");
    // The record is queued and acknowledged, and the run dies before it notes that.
    let crash = Opts {
        crash_after_ack: true,
        ..a.opts()
    };
    assert!(a.try_sync(&crash).is_err());
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 1);
    assert_eq!(a.state(state::BACKOFF_LEVEL).as_deref(), Some("1"));
    srv.stop();
    let token = a.ident().key.device_token;

    let t = std::time::Instant::now();
    let err = a.try_sync(&a.opts()).unwrap_err();
    assert!(
        t.elapsed() < std::time::Duration::from_secs(35),
        "{:?}",
        t.elapsed()
    );
    assert!(!err.to_string().contains(&token));
    // Nothing is lost: the stored item is still there.
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 1);
    assert_eq!(
        a.count("SELECT COUNT(*) FROM sync_own WHERE tag = 'rec'"),
        1
    );
    assert_eq!(a.state(state::BACKOFF_LEVEL).as_deref(), Some("2"));
    let last = a.state(state::LAST_ERROR).unwrap();
    assert!(
        !last.contains(&token) && !last.contains("docs.example.org"),
        "{last}"
    );
    let until: i64 = a.state(state::BACKOFF_UNTIL).unwrap().parse().unwrap();
    assert!((until - now_ms() - 120_000).abs() < 5_000, "2 minutes");

    // A hook-started run waits the backoff out and exits 0; the user's own run does not.
    let hook = Opts {
        honour_backoff: true,
        ..a.opts()
    };
    assert!(matches!(
        a.try_sync(&hook).unwrap(),
        Outcome::BackedOff { .. }
    ));
    assert!(a.try_sync(&a.opts()).is_err());
    assert_eq!(a.state(state::BACKOFF_LEVEL).as_deref(), Some("3"));
    let until: i64 = a.state(state::BACKOFF_UNTIL).unwrap().parse().unwrap();
    assert!((until - now_ms() - 240_000).abs() < 5_000, "4 minutes");

    srv.resume();
    let r = a.sync();
    assert_eq!(r.pushed, 1);
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 0);
    assert_eq!(a.state(state::BACKOFF_LEVEL), None);
    assert_eq!(a.state(state::LAST_ERROR), None);
    assert!(a.state(state::LAST_OK).is_some());
}

#[test]
fn awm_sync_quiet_prints_nothing_and_exits_1_on_a_dead_server_then_0_in_the_backoff() {
    let (mut srv, a, _b) = org_of_two();
    srv.stop();
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_awm"))
            .args(["sync", "--once", "--quiet"])
            .env("AWM_HOME", a.path())
            .env_remove("AWM_DEBUG")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    };
    let first = run();
    assert_eq!(first.status.code(), Some(1));
    assert!(first.stdout.is_empty() && first.stderr.is_empty());
    let second = run();
    assert_eq!(second.status.code(), Some(0), "inside the backoff");
    assert!(second.stdout.is_empty() && second.stderr.is_empty());
    // Without --quiet the failure is printed, and no token is.
    let loud = std::process::Command::new(env!("CARGO_BIN_EXE_awm"))
        .args(["sync", "--once"])
        .env("AWM_HOME", a.path())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(loud.status.code(), Some(1));
    let text = String::from_utf8_lossy(&loud.stderr).to_string();
    assert!(!text.is_empty());
    assert!(!text.contains(&a.ident().key.device_token));
}

#[test]
fn a_run_below_the_schema_or_outside_a_team_does_not_touch_the_network() {
    let node = Node::blank("solo");
    let err = node.try_sync(&node.opts()).unwrap_err();
    assert!(err.to_string().contains("not in a team"), "{err}");
    // The binary: nothing in quiet mode.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_awm"))
        .args(["sync", "--once", "--quiet"])
        .env("AWM_HOME", node.path())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(out.stdout.is_empty() && out.stderr.is_empty());
}

#[test]
fn below_min_client_pushes_stop_and_the_state_says_so() {
    let (srv, a, _b) = org_of_two();
    let floor = own_version();
    embedded::block_on(srv.store.update_settings(
        awm_proto::wire::SettingsUpdate {
            retention_days: None,
            min_client: Some(awm_proto::wire::Version::new(9, 0, 0)),
            max_members: None,
            cancel_pending_retention: None,
        },
        floor,
        None,
        unix_secs(),
    ))
    .unwrap();
    a.capture_fetch(1, URL_A, "p", "a summary of the guide");
    // The cached `GET /v1/info` is an hour old at most; the status carries `min_client` too.
    let r = a.sync();
    assert_eq!(r.pushed, 0);
    assert!(r.push_blocked.is_some());
    assert_eq!(a.state(state::MIN_CLIENT_BLOCK).as_deref(), Some("9.0.0"));
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE pushed_at IS NOT NULL"),
        0
    );
    assert!(
        a.state(state::INFO_CACHED_AT).is_some(),
        "the info is cached"
    );
}

// --- pull-side checks --------------------------------------------------------------------------

#[test]
fn the_pull_side_checks_drop_quarantine_clamp_and_keep_the_cursor_moving() {
    let (srv, a, b) = org_of_two();
    let m = forger(&srv, &a);
    let now = unix_secs();
    let ok_url = "https://ok.example.org/page";
    let tomb_id = Id::new_v4();
    let forgotten = "https://forgotten.example.org/x";
    let token = format!("ghp_{}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");

    let ident = m.ident();
    let ring = ident.ring().unwrap();
    // `sealed_at` is the position the envelope is sealed for; it differs from `idx` only for the
    // record that must fail to open.
    let seal = |idx: u64, sealed_at: u64, id: Id, v: Value| {
        let plain = serde_json::to_vec(&v).unwrap();
        (idx, id, seal_forged(&ident, &ring, sealed_at, id, &plain))
    };
    let mut newer = rec_plaintext("https://newer.example.org/a", "x", now);
    newer["schema"] = json!(99);
    let secret_text = format!("use {token} to log in");
    let items = vec![
        seal(
            0,
            0,
            Id::new_v4(),
            rec_plaintext(ok_url, "fine text here", now),
        ),
        seal(
            1,
            1,
            Id::new_v4(),
            rec_plaintext("http://192.168.1.5/admin", "internal", now),
        ),
        seal(
            2,
            2,
            tomb_id,
            rec_plaintext("https://tomb.example.org/a", "x", now),
        ),
        seal(3, 3, Id::new_v4(), newer),
        // Sealed for another position: the envelope does not open here.
        seal(4, 77, Id::new_v4(), json!({})),
        seal(
            5,
            5,
            Id::new_v4(),
            rec_plaintext(
                "https://old.example.org/a",
                "ten years old",
                now - 10 * 365 * 86_400,
            ),
        ),
        seal(
            6,
            6,
            Id::new_v4(),
            rec_plaintext(
                "https://future.example.org/a",
                "far ahead",
                now + 10 * 365 * 86_400,
            ),
        ),
        seal(7, 7, Id::new_v4(), rec_plaintext(forgotten, "gone", now)),
        seal(
            8,
            8,
            Id::new_v4(),
            rec_plaintext("https://secret.example.org/a", &secret_text, now),
        ),
    ];
    push_blobs(&m, items);

    let conn = b.conn();
    conn.execute(
        "INSERT INTO tombstone (kind, value, created_at) VALUES ('tool_use_id', ?1, 0)",
        [format!("team:{tomb_id}")],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tombstone (kind, value, created_at) VALUES ('url_hash', ?1, 0)",
        [sha256_hex(&awm::normalize::norm_url(forgotten).unwrap())],
    )
    .unwrap();
    drop(conn);

    let r = b.sync();
    assert_eq!(r.dropped, 4, "{r:?}");
    assert_eq!(r.skipped_newer, 1);
    assert_eq!(r.quarantined, 1);
    let urls = rows_of(
        &b.conn(),
        "SELECT url FROM event WHERE origin = 'team' ORDER BY url",
    );
    assert_eq!(
        urls,
        vec![
            "https://future.example.org/a",
            ok_url,
            "https://old.example.org/a",
            "https://secret.example.org/a",
        ],
        "private host, tombstones, a wrong envelope and a newer schema are not stored"
    );
    // The cursor moved over every index, so the next run pulls nothing.
    let mid = m.ident().team.member_id;
    assert_eq!(
        b.count(&format!(
            "SELECT head_idx FROM sync_stream WHERE member_id = '{mid}' AND tag = 'rec'"
        )),
        8
    );
    assert_eq!(b.sync().pulled, 0);
    for k in [
        "dropped.private_host",
        "dropped.tombstone",
        "dropped.decrypt",
    ] {
        assert!(b.state(k).is_some(), "{k}");
    }
    assert_eq!(b.state(state::NEWER_SCHEMA).as_deref(), Some("1"));

    // The clamp: created_at stays within a day of the hour the server received the record.
    let lo = (now - 86_400 - 3_600) * 1_000;
    let hi = (now + 86_400 + 3_600) * 1_000;
    for u in ["https://old.example.org/a", "https://future.example.org/a"] {
        let at: i64 = b
            .conn()
            .query_row("SELECT created_at FROM event WHERE url = ?1", [u], |r| {
                r.get(0)
            })
            .unwrap();
        assert!((lo..=hi).contains(&at), "{u}: {at}");
    }

    // The secret shape: quarantined, the secret not stored, a flag pushed.
    let (q, summary): (i64, String) = b
        .conn()
        .query_row(
            "SELECT quarantined, COALESCE(summary, '') FROM event WHERE url = 'https://secret.example.org/a'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(q, 1);
    assert!(!summary.contains(&token), "{summary}");
    assert_eq!(
        b.count("SELECT COUNT(*) FROM sync_own WHERE tag = 'flag'"),
        1
    );
    assert_eq!(
        b.count("SELECT COUNT(*) FROM sync_outbox"),
        0,
        "the flag was sent"
    );
    assert_eq!(
        b.url_hits("https://secret.example.org/a"),
        0,
        "never matched"
    );
    assert!(b.state("quarantined").is_some());
}

#[test]
fn the_highest_policy_version_wins_over_a_later_older_record() {
    let (_srv, a, b) = org_of_two();
    let policy = |version: u64, term: &str| {
        serde_json::to_vec(&json!({
            "schema": 1, "version": version, "deny_hosts": [], "link_hosts": [],
            "terms": [term], "credential_params": [],
        }))
        .unwrap()
    };
    let queue = |n: &Node, version: u64, term: &str| {
        let ident = n.ident();
        let ring = ident.ring().unwrap();
        let mut conn = n.conn();
        push::queue_item(
            &mut conn,
            &ident,
            &ring,
            "policy",
            "policy",
            &policy(version, term),
            now_ms(),
        )
        .unwrap();
    };
    queue(&a, 1, "acme-secret");
    a.sync();
    b.sync();
    assert_eq!(b.state(state::POLICY_VERSION).as_deref(), Some("1"));
    assert!(b.state(state::POLICY_JSON).unwrap().contains("acme-secret"));
    queue(&a, 2, "project-x");
    a.sync();
    b.sync();
    assert_eq!(b.state(state::POLICY_VERSION).as_deref(), Some("2"));
    assert!(b.state(state::POLICY_JSON).unwrap().contains("project-x"));
    // An older version arriving later does not replace the newer one.
    queue(&a, 1, "stale");
    a.sync();
    b.sync();
    assert_eq!(b.state(state::POLICY_VERSION).as_deref(), Some("2"));
    assert!(!b.state(state::POLICY_JSON).unwrap().contains("stale"));
}

// --- push crash safety -------------------------------------------------------------------------

#[test]
fn a_client_killed_after_the_ack_resends_the_stored_blob_with_no_duplicate_also_after_a_rotation() {
    let (srv, a, b) = org_of_two();
    let c = add_member(&srv, &a, "carol", "member");
    c.sync();
    a.capture_fetch(1, URL_A, "p", "a summary of the guide");
    let crash = Opts {
        crash_after_ack: true,
        ..a.opts()
    };
    let err = a.try_sync(&crash).unwrap_err();
    assert!(err.to_string().contains("injected crash"));
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE pushed_at IS NOT NULL"),
        0
    );
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 1);
    let stored_epoch = a.count("SELECT epoch FROM sync_own WHERE tag = 'rec' AND idx = 0");
    assert_eq!(stored_epoch, 0);

    // The epoch moves on in between: carol is removed, the admin's next run rotates first.
    remove_member(&a, c.ident().team.member_id);
    let r = a.sync();
    assert!(r.rotated, "{r:?}");
    assert_eq!(a.ident().ring().unwrap().current_epoch(), 1);
    // The revoke entry, the epoch entry and the record: the stored blob went out again and
    // the server accepted it as a replay.
    assert_eq!(r.pushed, 3, "{r:?}");
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE pushed_at IS NOT NULL"),
        1
    );
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 0);
    assert!(a.state(state::LAST_ERROR).is_none());

    // One copy on the server: bob sees one row, at the epoch the blob was sealed under.
    let rb = b.sync();
    assert_eq!(rb.pulled, 1);
    assert_eq!(b.team_rows(), 1);
    assert_eq!(
        b.ident().ring().unwrap().current_epoch(),
        1,
        "bob took the new key"
    );
}

// --- approvals and rotation -------------------------------------------------------------------

#[test]
fn a_member_who_is_removed_gets_no_wrap_of_the_new_epoch_and_the_roster_shows_it() {
    let (srv, a, b) = org_of_two();
    let c = add_member(&srv, &a, "carol", "member");
    c.sync();
    let cid = c.ident().team.device_id;
    remove_member(&a, c.ident().team.member_id);
    let r = a.sync();
    assert!(r.rotated);
    let keys = embedded::block_on(srv.store.keys(cid)).unwrap();
    assert!(
        keys.wraps.iter().all(|w| w.epoch == 0),
        "no wrap of epoch 1 for carol"
    );
    let keys = embedded::block_on(srv.store.keys(b.ident().team.device_id)).unwrap();
    assert!(keys.wraps.iter().any(|w| w.epoch == 1));
    b.sync();
    assert_eq!(
        b.count("SELECT COUNT(*) FROM team_member WHERE handle = 'carol' AND active = 0"),
        1
    );
    assert!(c.try_sync(&c.opts()).is_err(), "carol's token is revoked");
}

#[test]
fn an_admin_rotates_after_a_removal_even_when_the_server_never_sets_rotation_needed() {
    let (srv, a, b) = org_of_two();
    let c = add_member(&srv, &a, "carol", "member");
    c.sync();
    let cid = c.ident().team.device_id;
    remove_member(&a, c.ident().team.member_id);
    srv.withhold_rotation();
    let status: Value = a.client().get("/v1/status").unwrap();
    assert_eq!(status["rotation_needed"], json!(false));
    let r = a.sync();
    assert!(
        r.rotated,
        "the admin's own roster asks for the rotation: {r:?}"
    );
    let keys = embedded::block_on(srv.store.keys(cid)).unwrap();
    assert!(
        keys.wraps.iter().all(|w| w.epoch == 0),
        "no wrap of epoch 1 for carol"
    );
    let keys = embedded::block_on(srv.store.keys(b.ident().team.device_id)).unwrap();
    assert!(keys.wraps.iter().any(|w| w.epoch == 1));
    assert_eq!(a.ident().ring().unwrap().current_epoch(), 1);
    // The revocation is now older than the current epoch: no second rotation.
    srv.withhold_rotation();
    assert!(!a.sync().rotated);
    assert_eq!(a.ident().ring().unwrap().current_epoch(), 1);
    // A member's client never rotates, whatever its roster holds.
    srv.withhold_rotation();
    assert!(!b.sync().rotated);
}

// FT3a (RVT3 F2, F6, §5): the client's own rotation check at epoch 1 and later. Each test
// withholds `rotation_needed`, so only `roster::revoked_since_current_epoch` decides.

/// (a) A device the epoch-1 entry lists is revoked afterwards, by an admin whose clock is ten
/// minutes behind: the revocation is dated before the entry, and the listed-device rule rotates.
#[test]
fn a_revoked_device_of_the_current_epoch_entry_rotates_whatever_the_revocations_date() {
    let (srv, a, b) = org_of_two();
    let c = add_member(&srv, &a, "carol", "member");
    c.sync();
    remove_member(&a, c.ident().team.member_id);
    assert!(sync_withheld(&srv, &a).rotated);
    let at = epoch_created_at(&a, 1).expect("the epoch-1 entry");
    b.sync();
    assert_eq!(wrap_epochs(&srv, b.ident().team.device_id), [0, 1]);

    remove_member_at(&a, b.ident().team.member_id, at - 600);
    let r = sync_withheld(&srv, &a);
    assert!(r.rotated, "bob is in the epoch-1 entry: {r:?}");
    assert_eq!(a.ident().ring().unwrap().current_epoch(), 2);
    assert_eq!(
        wrap_epochs(&srv, b.ident().team.device_id),
        [0, 1],
        "no wrap of epoch 2 for bob"
    );
    assert!(!sync_withheld(&srv, &a).rotated, "the next run is quiet");
    assert_eq!(a.ident().ring().unwrap().current_epoch(), 2);
}

/// (b) A device approved after the epoch-1 entry (it got epoch 1 with its approval wraps, the
/// entry does not list it) is revoked: the revocation is dated at or after the entry and rotates.
#[test]
fn a_device_approved_after_the_epoch_entry_and_revoked_rotates() {
    let (srv, a, b) = org_of_two();
    let c = add_member(&srv, &a, "carol", "member");
    c.sync();
    remove_member_at(&a, c.ident().team.member_id, unix_secs() - 10);
    assert!(sync_withheld(&srv, &a).rotated);
    let at = epoch_created_at(&a, 1).expect("the epoch-1 entry");
    b.sync();

    let d = add_member(&srv, &a, "dave", "member");
    assert_eq!(
        d.ident().ring().unwrap().current_epoch(),
        1,
        "dave holds epoch 1"
    );
    d.sync();
    remove_member(&a, d.ident().team.member_id);
    assert!(unix_secs() >= at);
    let r = sync_withheld(&srv, &a);
    assert!(r.rotated, "dave held the current key: {r:?}");
    assert_eq!(a.ident().ring().unwrap().current_epoch(), 2);
    assert_eq!(wrap_epochs(&srv, d.ident().team.device_id), [0, 1]);
    assert!(wrap_epochs(&srv, b.ident().team.device_id).contains(&2));
    assert!(!sync_withheld(&srv, &a).rotated, "the next run is quiet");
}

/// (c) A revocation that reaches the admin after the rotation but is dated before the epoch
/// entry, of a device the entry does not list: the key never reached that device, no rotation.
#[test]
fn a_revocation_dated_before_the_current_epoch_entry_asks_for_no_rotation() {
    let (srv, a, b) = org_of_two();
    let c = add_member(&srv, &a, "carol", "member");
    c.sync();
    let cm = c.ident().team.member_id;
    // The server removes carol and asks for the rotation; the signed revocation comes later.
    a.client().remove_member(cm).unwrap();
    assert!(a.sync().rotated);
    let at = epoch_created_at(&a, 1).expect("the epoch-1 entry");
    assert_eq!(wrap_epochs(&srv, c.ident().team.device_id), [0]);

    queue_revoke(&a, cm, at - 600);
    let r = sync_withheld(&srv, &a);
    assert!(!r.rotated, "{r:?}");
    assert_eq!(
        a.count("SELECT COUNT(*) FROM team_member WHERE handle = 'carol' AND active = 0"),
        1,
        "the revocation is applied"
    );
    assert_eq!(a.ident().ring().unwrap().current_epoch(), 1);
    assert!(!sync_withheld(&srv, &b).rotated);
}

/// (d) RVT3 F6: a revocation dated ten minutes ahead of the rotating admin's clock rotates once;
/// the entry is dated after it, so the next run is quiet instead of rotating every run.
#[test]
fn a_revocation_dated_ahead_of_the_rotating_admins_clock_rotates_exactly_once() {
    let (srv, a, b) = org_of_two();
    let c = add_member(&srv, &a, "carol", "member");
    c.sync();
    let ahead = unix_secs() + 600;
    remove_member_at(&a, c.ident().team.member_id, ahead);
    let r = a.sync();
    assert!(r.rotated, "{r:?}");
    assert_eq!(epoch_created_at(&a, 1), Some(ahead + 1));
    for _ in 0..2 {
        assert!(!sync_withheld(&srv, &a).rotated, "no second rotation");
    }
    assert_eq!(a.ident().ring().unwrap().current_epoch(), 1);
    b.sync();
    assert_eq!(b.ident().ring().unwrap().current_epoch(), 1);
    assert!(!sync_withheld(&srv, &b).rotated);
}

/// RVT3v V1: a revocation signed with a date far beyond the clock (`i64::MAX`, or ten years
/// ahead) causes one rotation; the next two runs, a second apart, are quiet.
fn a_far_dated_revocation_rotates_exactly_once(revoked_at: i64) {
    let (srv, a, b) = org_of_two();
    let c = add_member(&srv, &a, "carol", "member");
    c.sync();
    remove_member_at(&a, c.ident().team.member_id, revoked_at);
    let r = a.sync();
    assert!(r.rotated, "{r:?}");
    assert_eq!(a.ident().ring().unwrap().current_epoch(), 1);
    for _ in 0..2 {
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        assert!(!sync_withheld(&srv, &a).rotated, "no second rotation");
    }
    assert_eq!(a.ident().ring().unwrap().current_epoch(), 1);
    b.sync();
    assert!(!sync_withheld(&srv, &b).rotated);
    assert_eq!(b.ident().ring().unwrap().current_epoch(), 1);
}

#[test]
fn a_revocation_dated_i64_max_rotates_exactly_once() {
    a_far_dated_revocation_rotates_exactly_once(i64::MAX);
}

#[test]
fn a_revocation_dated_ten_years_ahead_rotates_exactly_once() {
    a_far_dated_revocation_rotates_exactly_once(unix_secs() + 10 * 365 * 86_400);
}

// FT3a (RVT3 F3): `roster_record` is only ever added to.
#[test]
fn a_stored_roster_record_is_never_replaced_by_a_later_one_at_the_same_place() {
    let n = Node::blank("ann");
    let conn = n.conn();
    let (m, d) = (Id::new_v4().to_string(), Id::new_v4().to_string());
    let first = Id::new_v4().to_string();
    assert!(roster::store_record(&conn, &m, &d, 0, &first, 0, b"first blob").unwrap());
    let other = Id::new_v4().to_string();
    assert!(!roster::store_record(&conn, &m, &d, 0, &other, 1, b"second blob").unwrap());
    let (id, epoch, blob): (String, u32, Vec<u8>) = conn
        .query_row(
            "SELECT record_id, epoch, blob FROM roster_record WHERE member_id = ?1 AND device_id = ?2 AND idx = 0",
            [&m, &d],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((id, epoch, blob), (first, 0, b"first blob".to_vec()));
    assert_eq!(n.count("SELECT COUNT(*) FROM roster_record"), 1);
}

// FT3a (RVT3 F4): the reading steps come before the push.
#[test]
fn a_new_devices_first_run_stores_the_roster_before_it_pushes_a_record() {
    let srv = Srv::start();
    let a = create_org(&srv, "ann");
    a.sync();
    let b = add_member(&srv, &a, "bob", "member");
    assert_eq!(b.count("SELECT COUNT(*) FROM roster_record"), 0);
    b.capture_fetch(1, URL_A, "p", "bob's first record");
    let from = srv.logs.0.lock().unwrap().len();
    let r = b.sync();
    assert_eq!(r.pushed, 1, "{r:?}");
    assert!(r.push_blocked.is_none(), "{r:?}");
    assert!(b.count("SELECT COUNT(*) FROM roster_record") > 0);
    let member = format!("member={}", b.ident().team.member_id);
    let lines: Vec<String> = srv.logs.0.lock().unwrap()[from..]
        .iter()
        .filter(|l| l.contains(&member))
        .cloned()
        .collect();
    let at = |path: &str| {
        lines
            .iter()
            .position(|l| l.contains(&format!("path={path} ")))
    };
    let records = at("/v1/records").unwrap_or_else(|| panic!("no push: {lines:#?}"));
    let pull = at("/v1/pull").unwrap_or_else(|| panic!("no pull: {lines:#?}"));
    assert!(pull < records, "{lines:#?}");
    if let Some(keys) = at("/v1/keys") {
        assert!(keys < records, "{lines:#?}");
    }
}

// FT3a (RVT3 F18): no write transaction of the record path holds more than 25 rows.
#[test]
fn a_pull_of_200_records_writes_at_most_25_rows_per_transaction() {
    let (srv, a, b) = org_of_two();
    let m = forger(&srv, &a);
    let ident = m.ident();
    let ring = ident.ring().unwrap();
    let now = unix_secs();
    let items: Vec<(u64, Id, Vec<u8>)> = (0..200u64)
        .map(|i| {
            let id = Id::new_v4();
            let plain = serde_json::to_vec(&rec_plaintext(
                &format!("https://rows.example.org/p/{i}"),
                &format!("record {i} about transaction sizes"),
                now,
            ))
            .unwrap();
            (i, id, seal_forged(&ident, &ring, i, id, &plain))
        })
        .collect();
    for chunk in items.chunks(100) {
        push_blobs(&m, chunk.to_vec());
    }
    let r = b.sync();
    assert_eq!(r.pulled, 200, "{r:?}");
    // The literal, not the constant: the test must fail when `CHUNK_ROWS` moves (RVT3v V6).
    assert!((1..=25).contains(&r.max_rows_per_txn), "{r:?}");
    assert!(r.apply_ms.len() >= 8, "{r:?}");
}

#[test]
fn a_pending_device_is_left_alone_when_the_decision_says_no() {
    let srv = Srv::start();
    let a = create_org(&srv, "ann");
    a.sync();
    let ai = a.ident();
    let inv: Value = a
        .client()
        .post(
            "/v1/invites",
            &json!({"kind": "member", "handle": "dan", "role": "member"}),
        )
        .unwrap();
    let invite = Invite::create(
        *ai.team.org_id.as_uuid(),
        inv["invite_id"].as_str().unwrap(),
        inv["invite_token"].as_str().unwrap(),
        "dan",
    )
    .unwrap();
    let mut key = ai.key.clone();
    key.pending_invites.push(PendingInvite {
        invite: invite.encode(),
        kind: "member".into(),
        member_id: None,
        role: Some("member".into()),
    });
    key.save(a.path()).unwrap();
    let keys = DeviceKeys::generate().unwrap();
    let device = Id::new_v4();
    let _: Value = srv
        .anonymous()
        .post(
            "/v1/join",
            &json!({
                "invite_id": inv["invite_id"], "invite_token": inv["invite_token"],
                "handle": "dan", "device_id": device, "device_pubkey": Key32(keys.public),
                "join_mac": Key32(invite.join_mac(*device.as_uuid(), &keys.public)),
            }),
        )
        .unwrap();
    fn no(_: AutoApprove, _: bool) -> bool {
        false
    }
    let opts = Opts {
        approve: Some(no),
        ..Opts::default()
    };
    let Outcome::Done(r) = a.try_sync(&opts).unwrap() else {
        panic!()
    };
    assert_eq!(r.approvals, 0);
    // A join whose MAC does not verify under the invite secret is never approved.
    assert_eq!(a.ident().key.pending_invites.len(), 1);
    let Outcome::Done(r) = a.try_sync(&a.opts()).unwrap() else {
        panic!()
    };
    assert_eq!(r.approvals, 1);
    assert!(a.ident().key.pending_invites.is_empty());
}

// --- re-seed -----------------------------------------------------------------------------------

#[test]
fn after_a_restore_with_a_new_generation_a_re_pushes_what_is_missing_and_a_deleted_one_as_a_marker()
{
    let (mut srv, a, b) = org_of_two();
    a.capture_fetch(
        1,
        "https://docs.example.org/one",
        "p",
        "the first record text",
    );
    a.sync();
    b.sync();
    assert_eq!(b.team_rows(), 1);
    let old_generation = a.state(state::GENERATION).unwrap();
    let snap = srv.snapshot();

    a.capture_fetch(
        2,
        "https://docs.example.org/two",
        "p",
        "the second record text",
    );
    let doomed = a.capture_fetch(
        3,
        "https://docs.example.org/three",
        "p",
        "the third record text",
    );
    a.sync();
    // The third is deleted on A (what `awm forget` and TM11 do) and the server learns of it.
    let sync_id: String = a
        .conn()
        .query_row("SELECT sync_id FROM event WHERE id = ?1", [doomed], |r| {
            r.get(0)
        })
        .unwrap();
    push::mark_deleted(&a.conn(), Id::parse(&sync_id).unwrap(), now_ms()).unwrap();
    a.conn()
        .execute(
            "INSERT INTO sync_outbox (kind, ref, created_at) VALUES ('delete', ?1, 0)",
            [&sync_id],
        )
        .unwrap();
    a.sync();

    srv.restore(&snap);
    let r = a.sync();
    assert!(r.reseeded, "{r:?}");
    assert_ne!(a.state(state::GENERATION).unwrap(), old_generation);
    // The server holds idx 1 as a record again and idx 2 as a marker.
    let rb = b.sync();
    assert_eq!(rb.pulled, 1, "{rb:?}");
    assert_eq!(b.url_hits("https://docs.example.org/two"), 1);
    assert_eq!(b.url_hits("https://docs.example.org/three"), 0);
    assert_eq!(b.team_rows(), 2);
    let aid = a.ident().team.member_id;
    assert_eq!(
        b.count(&format!(
            "SELECT head_idx FROM sync_stream WHERE member_id = '{aid}' AND tag = 'rec'"
        )),
        2
    );
    // Quiet afterwards: the restore is over, nothing is re-sent.
    assert!(!a.sync().reseeded);
    let status: Value = a.client().get("/v1/status").unwrap();
    assert_eq!(status["restore_pending"], json!(false));
}

#[test]
fn after_a_restore_to_before_a_removal_the_admin_re_removes_the_member_and_no_new_wrap_reaches_them(
) {
    let (mut srv, a, b) = org_of_two();
    let c = add_member(&srv, &a, "carol", "member");
    c.sync();
    let snap = srv.snapshot();
    let cid = c.ident().team.device_id;
    let cm = c.ident().team.member_id;
    remove_member(&a, cm);
    assert!(a.sync().rotated);
    b.sync();
    assert_eq!(b.ident().ring().unwrap().current_epoch(), 1);

    srv.restore(&snap);
    let member = embedded::block_on(srv.store.member(cm)).unwrap().unwrap();
    assert!(
        member.revoked_at.is_none(),
        "the backup predates the removal"
    );
    let r = a.sync();
    assert!(r.reseeded, "{r:?}");
    let member = embedded::block_on(srv.store.member(cm)).unwrap().unwrap();
    assert!(member.revoked_at.is_some(), "the admin re-removed carol");
    let keys = embedded::block_on(srv.store.keys(cid)).unwrap();
    assert!(
        keys.wraps.iter().all(|w| w.epoch == 0),
        "no wrap of epoch 1 reaches carol's device"
    );
    let keys = embedded::block_on(srv.store.keys(b.ident().team.device_id)).unwrap();
    assert!(
        keys.wraps.iter().any(|w| w.epoch == 1),
        "bob's wrap is back"
    );
    let status: Value = a.client().get("/v1/status").unwrap();
    assert_eq!(status["restore_pending"], json!(false));
    assert_eq!(status["current_epoch"], json!(1));
}

// --- 10,000 rows against concurrent hooks -----------------------------------------------------

#[test]
fn applying_10000_pulled_rows_loses_no_injection_row_of_200_concurrent_hook_runs() {
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    let (srv, a, b) = org_of_two();
    let m = forger(&srv, &a);
    let ident = m.ident();
    let ring = ident.ring().unwrap();
    let now = unix_secs();
    for batch in 0..100u64 {
        let items: Vec<(u64, Id, Vec<u8>)> = (batch * 100..batch * 100 + 100)
            .map(|i| {
                let id = Id::new_v4();
                let plain = serde_json::to_vec(&rec_plaintext(
                    &format!("https://bulk.example.org/p/{i}"),
                    &format!("record number {i} about bulk rows"),
                    now,
                ))
                .unwrap();
                (i, id, seal_forged(&ident, &ring, i, id, &plain))
            })
            .collect();
        push_blobs(&m, items);
    }

    // B's hooks need consent, and a record the hook payload matches.
    b.conn()
        .execute_batch(
            "INSERT INTO meta (key, value) VALUES ('consent.record', 'yes'); \
             INSERT INTO meta (key, value) VALUES ('cutoff.query', '0'), ('cutoff.prompt', '0');",
        )
        .unwrap();
    let fixture = |name: &str| -> Value {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/hooks")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    };
    let base = fixture("PostToolUse-WebFetch-plugin-3.json");
    awm::capture::run(
        &base,
        &awm::capture::CaptureOpts {
            data_dir: b.path().to_path_buf(),
            config: Config::default(),
            now_ms: now_ms() - 2 * 86_400_000,
        },
    )
    .unwrap();
    let injections_before = b.count("SELECT COUNT(*) FROM injection");

    let done = Arc::new(AtomicBool::new(false));
    let during = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let b_path = b.path().to_path_buf();
    let sync_thread = {
        let env = b.env();
        let opts = b.opts();
        let done = done.clone();
        std::thread::spawn(move || {
            let out = awm::sync::run(&env, &opts).unwrap();
            done.store(true, Ordering::SeqCst);
            out
        })
    };
    let hooks: Vec<_> = (0..8)
        .map(|t| {
            let base = base.clone();
            let path = b_path.clone();
            let done = done.clone();
            let during = during.clone();
            std::thread::spawn(move || {
                for k in 0..25 {
                    let mut payload = base.clone();
                    payload["session_id"] = json!(format!("sess-hook-{t}-{k}"));
                    payload["tool_use_id"] = json!(format!("toolu_hook_{t}_{k}"));
                    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_awm"))
                        .args(["hook", "post-tool"])
                        .env("AWM_HOME", &path)
                        .stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .unwrap();
                    {
                        use std::io::Write;
                        let _ = child
                            .stdin
                            .take()
                            .unwrap()
                            .write_all(payload.to_string().as_bytes());
                    }
                    let out = child.wait_with_output().unwrap();
                    assert_eq!(out.status.code(), Some(0));
                    if !done.load(Ordering::SeqCst) {
                        during.fetch_add(1, Ordering::SeqCst);
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            })
        })
        .collect();
    for h in hooks {
        h.join().unwrap();
    }
    let Outcome::Done(report) = sync_thread.join().unwrap() else {
        panic!("the sync did not finish")
    };
    let wall = started.elapsed();
    assert_eq!(report.pulled, 10_000, "{report:?}");
    assert_eq!(b.team_rows(), 10_000);
    let lost = 200 - (b.count("SELECT COUNT(*) FROM injection") - injections_before);
    eprintln!(
        "TM10 timings: pull of 10,000 rows {} ms (run {} ms), apply transactions: n={} p95={:?} ms max={:?} ms; \
         hook runs during the sync: {}; injection rows lost: {lost}",
        report.pull_ms,
        wall.as_millis(),
        report.apply_ms.len(),
        report.apply_p95_ms(),
        report.apply_ms.iter().max(),
        during.load(Ordering::SeqCst),
    );
    assert_eq!(lost, 0, "injection rows lost: {lost} of 200");
    assert!(
        during.load(Ordering::SeqCst) >= 100,
        "the hooks ran while the rows were applied"
    );
    assert!(
        report.apply_p95_ms().unwrap() <= 20 + 15,
        "short transactions"
    );
    assert!(
        (1..=25).contains(&report.max_rows_per_txn),
        "at most 25 rows per transaction (RVT3 F18): {}",
        report.max_rows_per_txn
    );
}

// --- FT5c (VF-B B6, B16) ----------------------------------------------------------------------

/// Points a node at a [`Proxy`].
fn via(proxy: &Proxy, n: &Node) {
    let mut team = n.ident().team;
    team.server_url = format!("http://{}", proxy.addr);
    team.save(n.path()).unwrap();
}

// B6 (sync-v1 §2.3): a 426 on the push itself, from a server whose `min_client` the status does not
// show (a floor raised after the cached info, or one behind a proxy), stops the pushes without
// failing the run: the outbox stays, the pull went on, and the next run pushes.
#[test]
fn a_426_on_the_push_stops_pushes_keeps_the_outbox_and_the_pull_going() {
    let (srv, a, b) = org_of_two();
    let proxy = Proxy::start(srv.addr);
    b.capture_fetch(1, URL_A, "p", "bob's summary of the guide");
    b.sync();
    a.capture_fetch(
        1,
        "https://docs.example.org/guide/second",
        "p",
        "ann's summary",
    );
    via(&proxy, &a);
    proxy.queue(Some(coded("426 Upgrade Required", "client_too_old")));
    let r = a.sync();
    assert_eq!(r.pushed, 0, "{r:?}");
    assert!(
        r.push_blocked.as_deref().is_some_and(|w| w.contains("426")),
        "{r:?}"
    );
    assert_eq!(a.team_rows(), 1, "bob's record was pulled in the same run");
    assert_eq!(
        a.count("SELECT COUNT(*) FROM sync_outbox"),
        1,
        "outbox intact"
    );
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE origin = 'local' AND pushed_at IS NOT NULL"),
        0
    );
    assert_eq!(a.state(state::LAST_ERROR), None, "the run did not fail");
    assert_eq!(a.state(state::BACKOFF_LEVEL), None);
    // The server accepts again: the same item goes out and nothing is lost.
    let r = a.sync();
    assert_eq!(r.pushed, 1, "{r:?}");
    assert_eq!(r.push_blocked, None);
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 0);
}

// A 426 with no awm error body (a proxy or WAF answering for the server) is no `client_too_old`:
// the run fails and the outbox stays, as for any other unknown failure.
#[test]
fn a_426_without_an_awm_body_fails_the_run_and_keeps_the_outbox() {
    let (srv, a, _b) = org_of_two();
    let proxy = Proxy::start(srv.addr);
    a.capture_fetch(1, URL_A, "p", "ann's summary");
    via(&proxy, &a);
    proxy.queue(Some(bare("426 Upgrade Required")));
    assert!(a.try_sync(&a.opts()).is_err());
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 1);
    assert!(a.state(state::LAST_ERROR).is_some());
}

/// The stored roster record of `node` that is the revoke entry for `member`.
fn revoke_record_of(node: &Node, member: Id) -> (String, String, i64) {
    let ring = node.ident().ring().unwrap();
    for b in roster::blobs(&node.conn()).unwrap() {
        let ad = RecordAd {
            org: ring.org(),
            member: b.member,
            device: b.device,
            tag: ROSTER_TAG.to_string(),
            idx: b.idx,
            record_id: b.record_id,
            epoch: b.epoch,
        };
        let Ok(plain) = open_record(&ring, &ad, &b.blob) else {
            continue;
        };
        let p: RosterPlaintext = serde_json::from_slice(&plain).unwrap();
        if matches!(p.entry, RosterEntry::Revoke { member_id, .. } if member_id == *member.as_uuid())
        {
            return (
                Id::from(b.member).to_string(),
                Id::from(b.device).to_string(),
                b.idx as i64,
            );
        }
    }
    panic!("no revoke entry for {member}");
}

// B16 (`roster.rs` `MIN(active, ..)` / `MAX(revoked, ..)`): a removal, once applied, never goes
// back, even when a later view of the roster (a stored record lost, a restored backup) says the
// member or device is active.
#[test]
fn a_member_or_device_marked_removed_stays_removed_when_a_later_roster_view_lacks_the_revocation() {
    let (_srv, a, b) = org_of_two();
    let bm = b.ident().team.member_id;
    let bd = b.ident().team.device_id;
    remove_member(&a, bm);
    a.sync();
    assert_eq!(
        a.count("SELECT COUNT(*) FROM team_member WHERE handle = 'bob' AND active = 0"),
        1
    );
    let revoked_devices =
        format!("SELECT COUNT(*) FROM team_device WHERE device_id = '{bd}' AND revoked = 1");
    assert_eq!(a.count(&revoked_devices), 1);

    // The revoke entry vanishes from the stored records: the roster now shows bob as active.
    let (m, d, idx) = revoke_record_of(&a, bm);
    a.conn()
        .execute(
            "DELETE FROM roster_record WHERE member_id = ?1 AND device_id = ?2 AND idx = ?3",
            rusqlite::params![m, d, idx],
        )
        .unwrap();
    let ident = a.ident();
    let ring = ident.ring().unwrap();
    let (view, _) = roster::verify_and_store(&a.conn(), &ring, now_ms()).unwrap();
    assert!(
        !view.member(*bm.as_uuid()).unwrap().revoked,
        "the view without the entry shows bob active"
    );
    assert_eq!(
        a.count("SELECT COUNT(*) FROM team_member WHERE handle = 'bob' AND active = 0"),
        1,
        "MIN(active): a removal is not undone"
    );
    assert_eq!(a.count(&revoked_devices), 1, "MAX(revoked): nor a device's");
}

// B16 (FT3a, the `>=` rule): a revocation dated exactly at the current epoch entry's `created_at`,
// of a device the entry does not list, rotates; the next run is quiet.
#[test]
fn a_revocation_dated_exactly_at_the_epoch_entry_rotates_once() {
    let (srv, a, b) = org_of_two();
    let c = add_member(&srv, &a, "carol", "member");
    c.sync();
    remove_member_at(&a, c.ident().team.member_id, unix_secs() - 10);
    assert!(sync_withheld(&srv, &a).rotated);
    let at = epoch_created_at(&a, 1).expect("the epoch-1 entry");
    b.sync();

    // Dave is approved after the epoch-1 entry, so it does not list him.
    let d = add_member(&srv, &a, "dave", "member");
    d.sync();
    remove_member_at(&a, d.ident().team.member_id, at);
    let r = sync_withheld(&srv, &a);
    assert!(r.rotated, "revoked_at == created_at counts: {r:?}");
    assert_eq!(a.ident().ring().unwrap().current_epoch(), 2);
    assert_eq!(
        epoch_created_at(&a, 2),
        Some(at.max(unix_secs()).max(at + 1))
    );
    assert!(!sync_withheld(&srv, &a).rotated, "the next run is quiet");
    assert_eq!(a.ident().ring().unwrap().current_epoch(), 2);
}

// B16 (`track_share_all`): the first run with `team.share_all_projects` on records the time, later
// runs keep it, a run with the switch off forgets it, and turning it on again starts a new window.
#[test]
fn share_all_since_is_written_by_the_first_run_with_the_switch_on_and_removed_when_it_is_off() {
    let (_srv, mut a, _b) = org_of_two();
    assert_eq!(a.state(state::SHARE_ALL_SINCE), None, "off by default");
    a.cfg.team.share_all_projects = true;
    let before = now_ms();
    a.sync();
    let first: i64 = a.state(state::SHARE_ALL_SINCE).unwrap().parse().unwrap();
    assert!(
        first >= before - 1_000 && first <= now_ms() + 1_000,
        "{first}"
    );
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    a.sync();
    assert_eq!(
        a.state(state::SHARE_ALL_SINCE),
        Some(first.to_string()),
        "a later run keeps the window's start"
    );
    a.cfg.team.share_all_projects = false;
    a.sync();
    assert_eq!(a.state(state::SHARE_ALL_SINCE), None);
    a.cfg.team.share_all_projects = true;
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    a.sync();
    let second: i64 = a.state(state::SHARE_ALL_SINCE).unwrap().parse().unwrap();
    assert!(second > first, "a new window starts: {first} < {second}");
}
