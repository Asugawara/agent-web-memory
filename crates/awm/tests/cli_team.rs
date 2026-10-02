//! `awm team` against a real in-process server (plan-v3-team §4.8, §5.1; TM12).
//!
//! Run: `cargo test -p agent-web-memory --features sync,serve --test cli_team`.
//!
//! Each test starts its own server (`awm_server::http::embedded` on a loopback port, a
//! `SqliteStore` in a scratch directory, a captured log sink) and drives the built `awm` binary
//! with one `AWM_HOME` per machine. Nothing else opens a socket except `Proxy`, a loopback forwarder
//! that stands in for a proxy or WAF in front of the server. Where a test needs a server that
//! withholds or forges something, it edits the server's database directly, as a compromised host
//! could.

#![cfg(all(feature = "sync", feature = "serve"))]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use awm::db::{self, Role};
use awm::record::sha256_hex;
use awm::sync::http::{own_version, Client};
use awm::sync::state::{self, Identity, PendingInvite, TeamKey, TeamToml};
use awm_proto::crypto::{open_record, seal_record, RecordAd, Secret32};
use awm_proto::keys::{self, EpochKey, Invite, KeyRing, RepoKey, RosterEntry};
use awm_proto::wire::{
    Handle, Id, InviteKind, Key32, PendingDevice, Role as WireRole, RosterPlaintext,
    SettingsUpdate, Tag, B64,
};
use awm_server::auth;
use awm_server::http::embedded::{self, Embedded};
use awm_server::http::{AppState, LogSink, ServerConfig};
use awm_server::store::sqlite::SqliteStore;
use awm_server::store::Store;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

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
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

struct Srv {
    store: Arc<SqliteStore>,
    emb: Option<Embedded>,
    addr: SocketAddr,
    dir: tempfile::TempDir,
    logs: Arc<Capture>,
}

fn server_config() -> ServerConfig {
    let v = own_version();
    let mut c = ServerConfig::new(v.clone(), v);
    c.limits.records_per_day = 1_000_000;
    c.limits.requests_per_minute = 1_000_000;
    c.limits.request_burst = 1_000_000;
    c.limits.anonymous_per_minute = 1_000_000;
    c.limits.joins_per_hour = 1_000;
    c
}

impl Srv {
    fn start() -> Srv {
        Srv::start_from(None)
    }

    /// A server, optionally on a copy of another server's canonical export (`team move`).
    fn start_from(db: Option<&Path>) -> Srv {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        if let Some(src) = db {
            std::fs::create_dir_all(&data).unwrap();
            std::fs::copy(src, data.join("server.db")).unwrap();
        }
        let store = Arc::new(SqliteStore::open(&data).unwrap());
        if db.is_some() {
            embedded::block_on(store.renew_generation(unix_secs())).unwrap();
        }
        let logs = Arc::new(Capture::default());
        let emb = embedded::spawn(Srv::state(&store, &logs)).unwrap();
        Srv {
            store,
            addr: emb.addr(),
            emb: Some(emb),
            dir,
            logs,
        }
    }

    fn state(store: &Arc<SqliteStore>, logs: &Arc<Capture>) -> AppState {
        AppState::new(store.clone() as Arc<dyn Store>, server_config()).with_log_sink(logs.clone())
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn stop(&mut self) {
        if let Some(mut e) = self.emb.take() {
            e.stop();
        }
    }

    fn resume(&mut self) {
        let emb = embedded::spawn_on(self.addr, Srv::state(&self.store, &self.logs)).unwrap();
        self.emb = Some(emb);
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

    fn log_len(&self) -> usize {
        self.logs.0.lock().unwrap().len()
    }

    fn db_path(&self) -> PathBuf {
        self.dir.path().join("data").join("server.db")
    }

    /// The bytes of the server database and its WAL and shared-memory files.
    fn db_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for suffix in ["", "-wal", "-shm"] {
            let p = PathBuf::from(format!("{}{suffix}", self.db_path().display()));
            if let Ok(b) = std::fs::read(&p) {
                out.extend(b);
            }
        }
        out
    }

    /// A direct connection to the server database (a compromised host).
    fn raw(&self) -> Connection {
        let c = Connection::open(self.db_path()).unwrap();
        c.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        c
    }

    fn roster_head(&self, member: Id, device: Id) -> i64 {
        embedded::block_on(
            self.store
                .stream_head(member, device, Tag::parse("roster").unwrap()),
        )
        .unwrap()
    }

    fn deleted_ids(&self) -> Vec<String> {
        embedded::block_on(self.store.deletions(0, 5_000))
            .unwrap()
            .entries
            .iter()
            .map(|e| e.record_id.to_string())
            .collect()
    }

    fn wrap_epochs(&self, device: Id) -> Vec<u32> {
        let mut v: Vec<u32> = embedded::block_on(self.store.keys(device))
            .unwrap()
            .wraps
            .iter()
            .map(|w| w.epoch)
            .collect();
        v.sort_unstable();
        v
    }

    fn settings(&self, update: SettingsUpdate) {
        embedded::block_on(
            self.store
                .update_settings(update, own_version(), None, unix_secs()),
        )
        .unwrap();
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------------------------
// A machine

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

struct Node {
    dir: tempfile::TempDir,
    home: tempfile::TempDir,
}

impl Node {
    fn new() -> Node {
        let dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let mut conn = db::open(&dir.path().join("awm.db"), Role::Cli).unwrap();
        db::migrate(&mut conn).unwrap();
        std::fs::create_dir_all(dir.path().join("proj")).unwrap();
        Node { dir, home }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn project(&self) -> PathBuf {
        std::fs::canonicalize(self.path().join("proj")).unwrap()
    }

    fn run(&self, args: &[&str]) -> Out {
        let o = Command::new(env!("CARGO_BIN_EXE_awm"))
            .args(args)
            .env("AWM_HOME", self.path())
            .env("HOME", self.home.path())
            .env_remove("CODEX_HOME")
            .env_remove("AWM_DEBUG")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        Out {
            code: o.status.code(),
            stdout: String::from_utf8(o.stdout).unwrap(),
            stderr: String::from_utf8(o.stderr).unwrap(),
        }
    }

    /// Runs and requires exit 0; returns stdout.
    #[track_caller]
    fn ok(&self, args: &[&str]) -> String {
        let o = self.run(args);
        assert_eq!(
            o.code,
            Some(0),
            "awm {args:?} failed\nstdout: {}\nstderr: {}",
            o.stdout,
            o.stderr
        );
        o.stdout
    }

    /// Runs and requires a failure; returns stderr.
    #[track_caller]
    fn refused(&self, args: &[&str]) -> String {
        let o = self.run(args);
        assert_ne!(
            o.code,
            Some(0),
            "awm {args:?} should be refused\nstdout: {}",
            o.stdout
        );
        o.stderr
    }

    fn json(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.ok(args)).unwrap()
    }

    fn conn(&self) -> Connection {
        db::open(&self.path().join("awm.db"), Role::Cli).unwrap()
    }

    fn ident(&self) -> Identity {
        Identity::load(self.path()).unwrap()
    }

    fn member(&self) -> Id {
        self.ident().team.member_id
    }

    fn device(&self) -> Id {
        self.ident().team.device_id
    }

    fn count(&self, sql: &str) -> i64 {
        self.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn state(&self, key: &str) -> Option<String> {
        state::get(&self.conn(), key).unwrap()
    }

    /// A local WebFetch row in this machine's project, captured now; returns its `event.id`.
    fn capture(&self, n: u32, url: &str, summary: &str) -> i64 {
        let conn = self.conn();
        let norm = awm::normalize::norm_url(url).unwrap();
        conn.execute(
            "INSERT INTO event (tool_use_id, tool, session_id, cwd_hash, created_at, url, url_norm, \
               fetch_prompt, status, summary, match_text, source) \
             VALUES (?1, 'WebFetch', 'sess-private', ?2, ?3, ?4, ?5, 'what does it say', 'ok', ?6, ?7, 'hook')",
            params![
                format!("toolu_{}_{n}", self.path().display()),
                sha256_hex(&self.project().to_string_lossy()),
                now_ms(),
                url,
                norm,
                summary,
                format!("{url} {summary}"),
            ],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn sync_id(&self, event: i64) -> String {
        self.conn()
            .query_row("SELECT sync_id FROM event WHERE id = ?1", [event], |r| {
                r.get(0)
            })
            .unwrap()
    }

    fn mode(&self, file: &str) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(self.path().join(file))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    fn status(&self) -> Value {
        self.json(&["team", "status", "--json"])
    }
}

// ---------------------------------------------------------------------------------------------
// Flows

fn create(srv: &Srv, handle: &str) -> Node {
    create_with(srv, handle, &srv.bootstrap_token())
}

fn create_with(srv: &Srv, handle: &str, token: &str) -> Node {
    let n = Node::new();
    let out = n.ok(&[
        "team",
        "create",
        &srv.url(),
        "--token",
        token,
        "--handle",
        handle,
    ]);
    assert!(out.contains("created organisation"), "{out}");
    n
}

/// The invite string of `awm team join URL --token X`.
fn token_of(srv: &Srv, out: &str) -> String {
    let prefix = format!("awm team join {} --token ", srv.url());
    let line = out.trim_end();
    assert!(!line.contains('\n'), "one line: {out}");
    line.strip_prefix(&prefix)
        .unwrap_or_else(|| panic!("not a join command: {out}"))
        .to_string()
}

fn invite(srv: &Srv, admin: &Node, handle: &str) -> String {
    token_of(srv, &admin.ok(&["team", "invite", "--handle", handle]))
}

fn code_of(join_out: &str) -> String {
    join_out
        .lines()
        .find_map(|l| l.strip_prefix("read this code to the person who invited you: "))
        .unwrap_or_else(|| panic!("no code: {join_out}"))
        .replace(' ', "")
}

/// A new machine that joins with `token`; returns it and the code it reads out.
fn join(srv: &Srv, token: &str) -> (Node, String) {
    let n = Node::new();
    let out = n.ok(&["team", "join", &srv.url(), "--token", token]);
    assert!(out.contains("waiting for approval"), "{out}");
    let code = code_of(&out);
    (n, code)
}

/// Invite, join, approve with the code, take the keys, sync once.
fn member(srv: &Srv, admin: &Node, handle: &str) -> Node {
    let t = invite(srv, admin, handle);
    let (n, code) = join(srv, &t);
    admin.ok(&["team", "approve", handle, "--code", &code]);
    n.ok(&["sync"]);
    assert_eq!(n.status()["approval"], "approved");
    n
}

fn share(n: &Node) {
    let p = n.project();
    n.ok(&["team", "share", p.to_str().unwrap()]);
}

/// The roster record at `idx` of a writer's stream, as the server holds it.
fn server_roster_row(srv: &Srv, member: Id, device: Id, idx: i64) -> (String, Vec<u8>) {
    srv.raw()
        .query_row(
            "SELECT id, blob FROM record WHERE member_id = ?1 AND device_id = ?2 AND tag = 'roster' AND idx = ?3",
            params![member.to_string(), device.to_string(), idx],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// create

#[test]
fn create_writes_private_files_and_the_first_sync_pushes_the_genesis_at_roster_0() {
    let srv = Srv::start();
    let boot = srv.bootstrap_token();
    let a = create_with(&srv, "ann", &boot);
    for f in ["team.toml", "team.key", "team.repo"] {
        assert_eq!(a.mode(f), 0o600, "{f}");
    }
    let team = TeamToml::load(a.path()).unwrap();
    assert_eq!(team.server_url, srv.url());
    assert_eq!(team.handle, "ann");
    let key = TeamKey::load(a.path()).unwrap();
    assert!(key
        .device_token
        .starts_with(&format!("awm_t_{}_", team.org_id)));
    assert_eq!(key.epoch_keys.len(), 1);
    assert_eq!(key.epoch_keys[0].epoch, 0);
    assert!(key.pending_invites.is_empty());
    let ring = key.ring(team.org_id).unwrap();
    assert_eq!(
        std::fs::read_to_string(a.path().join("team.repo")).unwrap(),
        ring.repo_key().encode()
    );

    // The genesis is queued at roster 0 under epoch 0, carries the nonce, and its device id,
    // key and nonce hash to the organisation id (the device key was made first).
    let (record_id, blob): (String, Vec<u8>) = a
        .conn()
        .query_row(
            "SELECT record_id, blob FROM sync_own WHERE tag = 'roster' AND idx = 0 AND epoch = 0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let plain = open_record(
        &ring,
        &RecordAd {
            org: *team.org_id.as_uuid(),
            member: *team.member_id.as_uuid(),
            device: *team.device_id.as_uuid(),
            tag: "roster".into(),
            idx: 0,
            record_id: *Id::parse(&record_id).unwrap().as_uuid(),
            epoch: 0,
        },
        &blob,
    )
    .unwrap();
    let RosterPlaintext {
        entry:
            RosterEntry::Genesis {
                device_id,
                device_pub,
                org_nonce,
                member_id,
                ..
            },
        ..
    } = serde_json::from_slice(&plain).unwrap()
    else {
        panic!("not a genesis");
    };
    assert_eq!(device_id, *team.device_id.as_uuid());
    assert_eq!(member_id, *team.member_id.as_uuid());
    assert_eq!(device_pub, key.device_keys().public);
    assert_eq!(
        keys::org_id(device_id, &device_pub, &org_nonce),
        *team.org_id.as_uuid()
    );
    assert_eq!(
        a.count("SELECT COUNT(*) FROM sync_outbox WHERE kind = 'roster' AND ref = 'roster:0'"),
        1
    );
    assert_eq!(srv.roster_head(team.member_id, team.device_id), -1);

    a.ok(&["sync"]);
    assert_eq!(srv.roster_head(team.member_id, team.device_id), 0);
    let epoch: i64 = srv
        .raw()
        .query_row(
            "SELECT epoch FROM record WHERE tag = 'roster' AND idx = 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(epoch, 0);
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 0);
    assert_eq!(a.status()["role"], "admin");

    // One organisation per data directory: create and join are refused before any request.
    let before = srv.log_len();
    let err = a.refused(&[
        "team",
        "create",
        &srv.url(),
        "--token",
        &boot,
        "--handle",
        "ann",
    ]);
    assert!(err.contains("already in an organisation"), "{err}");
    let t = invite(&srv, &a, "bob");
    let before_join = srv.log_len();
    let err = a.refused(&["team", "join", &srv.url(), "--token", &t]);
    assert!(err.contains("already in an organisation"), "{err}");
    assert_eq!(srv.log_len(), before_join, "no request");
    assert!(before <= before_join);
    // A used or wrong bootstrap token: refused, nothing written.
    let n = Node::new();
    let err = n.refused(&[
        "team",
        "create",
        &srv.url(),
        "--token",
        &boot,
        "--handle",
        "zed",
    ]);
    assert!(err.contains("bootstrap token"), "{err}");
    assert!(!n.path().join("team.toml").exists());
}

// ---------------------------------------------------------------------------------------------
// invite and join

#[test]
fn invite_prints_exactly_the_join_command_and_limits_expiry_and_members() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let o = a.run(&[
        "team",
        "invite",
        "--handle",
        "bob",
        "--admin",
        "--expires",
        "30d",
    ]);
    assert_eq!(o.code, Some(0), "{}", o.stderr);
    let t = token_of(&srv, &o.stdout);
    assert_eq!(
        o.stdout,
        format!("awm team join {} --token {t}\n", srv.url())
    );
    assert!(t.starts_with("awmi1_"));
    let key = TeamKey::load(a.path()).unwrap();
    assert_eq!(key.pending_invites.len(), 1);
    assert_eq!(key.pending_invites[0].invite, t);
    assert_eq!(key.pending_invites[0].kind, "member");
    assert_eq!(key.pending_invites[0].role.as_deref(), Some("admin"));

    // --expires above 30 days: refused before any request.
    let before = srv.log_len();
    let err = a.refused(&["team", "invite", "--handle", "cat", "--expires", "31d"]);
    assert!(err.contains("30d"), "{err}");
    assert_eq!(srv.log_len(), before);

    // max_members counts active members and open invites (ann + bob's invite = 2).
    srv.settings(SettingsUpdate {
        retention_days: None,
        min_client: None,
        max_members: Some(2),
        cancel_pending_retention: None,
    });
    let err = a.refused(&["team", "invite", "--handle", "cat"]);
    assert!(err.contains("max_members"), "{err}");
    assert_eq!(TeamKey::load(a.path()).unwrap().pending_invites.len(), 1);
}

#[test]
fn join_refuses_an_invite_whose_org_is_not_its_tokens_before_any_request() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let t = invite(&srv, &a, "bob");
    let real = Invite::parse(&t).unwrap();
    let forged = Invite::from_parts(
        *Id::new_v4().as_uuid(),
        &real.invite_id,
        &real.token,
        &real.handle,
        Secret32::from_bytes([7; 32]),
    )
    .unwrap()
    .encode();
    let b = Node::new();
    let before = srv.log_len();
    let err = b.refused(&["team", "join", &srv.url(), "--token", &forged]);
    assert!(err.contains("another organisation"), "{err}");
    assert_eq!(srv.log_len(), before, "no request was sent");
    assert!(!b.path().join("team.toml").exists());
    assert!(!b.path().join("team.key").exists());
    // The real invite still works.
    let out = b.ok(&["team", "join", &srv.url(), "--token", &t]);
    assert!(out.contains("waiting for approval"));
    // A second join with the same invite: 410.
    let c = Node::new();
    let err = c.refused(&["team", "join", &srv.url(), "--token", &t]);
    assert!(err.contains("used or expired"), "{err}");
}

#[test]
fn a_member_join_waits_for_the_code_compared_approval_and_no_secret_reaches_the_server() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let t = invite(&srv, &a, "bob");
    let secret = *Invite::parse(&t).unwrap().secret().expose();
    let (b, code) = join(&srv, &t);
    for f in ["team.toml", "team.key"] {
        assert_eq!(b.mode(f), 0o600, "{f}");
    }

    // Waiting: status and sync say so; nothing is pushed.
    let st = b.status();
    assert_eq!(st["role"], "pending");
    assert!(
        st["approval"].as_str().unwrap().contains(&code[..3]),
        "{st}"
    );
    let out = b.ok(&["sync"]);
    assert!(out.contains("waiting for an approval"), "{out}");

    // The admin sees the pending join with the same code, and approves only with it.
    let st = a.status();
    assert_eq!(st["pending"][0]["handle"], "bob");
    assert_eq!(
        st["pending"][0]["code"].as_str().unwrap().replace(' ', ""),
        code
    );
    let err = a.refused(&["team", "approve", "bob"]);
    assert!(err.contains("--code"), "{err}");
    let wrong = if code == "000000" { "111111" } else { "000000" };
    let err = a.refused(&["team", "approve", "bob", "--code", wrong]);
    assert!(err.contains("does not match"), "{err}");
    assert_eq!(b.status()["role"], "pending");
    let out = a.ok(&["team", "approve", "bob", "--code", &code]);
    assert!(out.contains("approved @bob"), "{out}");
    assert!(TeamKey::load(a.path()).unwrap().pending_invites.is_empty());

    // The joiner takes its keys (authenticated with S) and the roster names it.
    b.ok(&["sync"]);
    let st = b.status();
    assert_eq!(st["approval"], "approved", "{st}");
    assert_eq!(st["role"], "member");
    let key = TeamKey::load(b.path()).unwrap();
    assert_eq!(key.epoch_keys.len(), 1);
    assert!(!key.extra.contains_key("join_invite"));
    assert_eq!(b.mode("team.repo"), 0o600);
    assert_eq!(
        key.ring(b.ident().team.org_id)
            .unwrap()
            .current()
            .expose_secret(),
        TeamKey::load(a.path())
            .unwrap()
            .ring(a.ident().team.org_id)
            .unwrap()
            .current()
            .expose_secret()
    );

    // Bob shares a project; his record reaches Ann.
    share(&b);
    b.capture(
        1,
        "https://docs.example.org/guide",
        "The guide explains setup.",
    );
    let out = b.ok(&["sync"]);
    assert!(out.contains("pushed 1"), "{out}");
    a.ok(&["sync"]);
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE origin = 'team'"),
        1
    );

    // The invite secret, the device tokens and the epoch key appear in neither the server's
    // database nor its log nor any last_error.
    let db = srv.db_bytes();
    let log = srv.log_text();
    let s_b64 = B64(secret.to_vec());
    let s_text = serde_json::to_value(&s_b64).unwrap();
    let k0 = TeamKey::load(a.path()).unwrap().epoch_keys[0].key.0;
    let mut needles: Vec<Vec<u8>> = vec![
        secret.to_vec(),
        s_text.as_str().unwrap().as_bytes().to_vec(),
        t.as_bytes().to_vec(),
        k0.to_vec(),
        a.ident().key.device_token.into_bytes(),
        b.ident().key.device_token.into_bytes(),
    ];
    needles.push(b"setup".to_vec());
    for n in &needles {
        assert!(!contains(&db, n), "server db holds a secret");
        assert!(!contains(log.as_bytes(), n), "server log holds a secret");
        for node in [&a, &b] {
            let e = node.state("last_error").unwrap_or_default();
            assert!(!contains(e.as_bytes(), n));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// check_own_approval before the first push

#[test]
fn a_withheld_or_forged_approval_blocks_the_push_and_status_says_so() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let (am, ad) = (a.member(), a.device());

    // Withheld: the server drops Ann's approval of Bob (roster idx 1).
    let t = invite(&srv, &a, "bob");
    let (b, code) = join(&srv, &t);
    a.ok(&["team", "approve", "bob", "--code", &code]);
    assert_eq!(srv.roster_head(am, ad), 1);
    let saved: (String, i64, Option<i64>, i64, i64, Vec<u8>) = srv
        .raw()
        .query_row(
            "SELECT id, idx, epoch, size, received_at, blob FROM record \
             WHERE member_id = ?1 AND device_id = ?2 AND tag = 'roster' AND idx = 1",
            params![am.to_string(), ad.to_string()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .unwrap();
    srv.raw()
        .execute(
            "DELETE FROM record WHERE member_id = ?1 AND device_id = ?2 AND tag = 'roster' AND idx = 1",
            params![am.to_string(), ad.to_string()],
        )
        .unwrap();
    let st = b.status();
    assert_ne!(st["approval"], "approved", "{st}");
    share(&b);
    b.capture(1, "https://docs.example.org/withheld", "Nothing to see.");
    b.ok(&["sync"]);
    assert_eq!(
        b.count("SELECT COUNT(*) FROM event WHERE pushed_at IS NOT NULL"),
        0,
        "no push without a verified approval"
    );
    assert_eq!(
        b.count("SELECT COUNT(*) FROM sync_outbox WHERE kind = 'record'"),
        1
    );
    let st = b.status();
    assert!(
        st["push_blocked"]
            .as_str()
            .unwrap()
            .contains("no verified roster entry"),
        "{st}"
    );
    let text = b.ok(&["team", "status"]);
    assert!(text.contains("pushes        stopped"), "{text}");

    // The server serves the approval again: the next sync verifies it and pushes.
    srv.raw()
        .execute(
            "INSERT INTO record (member_id, device_id, tag, idx, id, epoch, size, received_at, blob) \
             VALUES (?1, ?2, 'roster', ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                am.to_string(),
                ad.to_string(),
                saved.1,
                saved.0,
                saved.2,
                saved.3,
                saved.4,
                saved.5
            ],
        )
        .unwrap();
    b.ok(&["sync"]);
    assert_eq!(
        b.count("SELECT COUNT(*) FROM event WHERE pushed_at IS NOT NULL"),
        1
    );
    assert_eq!(b.status()["approval"], "approved");

    // Forged: the server replaces Ann's approval of Carol with one sealed under a key it made.
    let t = invite(&srv, &a, "cat");
    let (c, code) = join(&srv, &t);
    a.ok(&["team", "approve", "cat", "--code", &code]);
    let (rid, _) = server_roster_row(&srv, am, ad, 2);
    let ci = TeamToml::load(c.path()).unwrap();
    let ck = TeamKey::load(c.path()).unwrap();
    let fake = serde_json::to_vec(&RosterPlaintext {
        schema: 1,
        entry: RosterEntry::Approve {
            member_id: *ci.member_id.as_uuid(),
            handle: "cat".into(),
            role: keys::Role::Member,
            kind: keys::ApprovalKind::Member,
            device_id: *ci.device_id.as_uuid(),
            device_pub: ck.device_keys().public,
            approved_at: unix_secs(),
            approver_device_id: *ad.as_uuid(),
        },
    })
    .unwrap();
    let server_key = EpochKey::generate(0).unwrap();
    let forged = seal_record(
        &server_key,
        &RecordAd {
            org: *ci.org_id.as_uuid(),
            member: *am.as_uuid(),
            device: *ad.as_uuid(),
            tag: "roster".into(),
            idx: 2,
            record_id: *Id::parse(&rid).unwrap().as_uuid(),
            epoch: 0,
        },
        &fake,
    )
    .unwrap();
    srv.raw()
        .execute(
            "UPDATE record SET blob = ?1 WHERE id = ?2",
            params![forged, rid],
        )
        .unwrap();
    let st = c.status();
    assert_ne!(st["approval"], "approved");
    share(&c);
    c.capture(1, "https://docs.example.org/forged", "Nothing here.");
    c.ok(&["sync"]);
    assert_eq!(
        c.count("SELECT COUNT(*) FROM event WHERE pushed_at IS NOT NULL"),
        0
    );
    assert!(c.status()["push_blocked"]
        .as_str()
        .unwrap()
        .contains("withheld or forged"));
}

// ---------------------------------------------------------------------------------------------
// add-device and approve

#[test]
fn an_own_device_waits_for_the_code_unless_auto_approve_is_devices_and_another_members_by_hand() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");

    // Ann's second machine. By default (team.auto_approve = none, RVT2 m3) a MAC that verifies
    // is not enough, since a leaked invite string makes one too: her first device approves it
    // only with the code the new machine prints.
    let o = a.run(&["team", "add-device"]);
    assert_eq!(o.code, Some(0), "{}", o.stderr);
    assert!(
        o.stderr.contains("awm team approve ann --code NNNNNN"),
        "{}",
        o.stderr
    );
    let t = token_of(&srv, &o.stdout);
    let (a2, code) = join(&srv, &t);
    assert_eq!(a2.member(), a.member());
    let out = a.ok(&["sync"]);
    assert!(out.contains("synced"), "{out}");
    assert_ne!(
        a2.status()["approval"],
        "approved",
        "own device: not automatic by default"
    );
    a.ok(&["team", "approve", "ann", "--code", &code]);
    a2.ok(&["sync"]);
    assert_eq!(a2.status()["approval"], "approved");
    assert_eq!(a2.status()["role"], "admin");

    // With the opt-in `devices`, her next machine is approved at the next sync after the MAC
    // verified.
    a.ok(&["config", "set", "team.auto_approve", "devices"]);
    let o = a.run(&["team", "add-device"]);
    assert!(
        o.stderr.contains("approves it at its next awm sync"),
        "{}",
        o.stderr
    );
    let (a3, _) = join(&srv, &token_of(&srv, &o.stdout));
    a.ok(&["sync"]);
    a3.ok(&["sync"]);
    assert_eq!(a3.status()["approval"], "approved");

    // --for is for admins, refused locally before any request.
    let before = srv.log_len();
    let err = b.refused(&["team", "add-device", "--for", "@ann"]);
    assert!(err.contains("admins"), "{err}");
    assert_eq!(srv.log_len(), before);

    // An admin's device invite for Bob, who lost his device: approved by hand, same member id.
    let t = token_of(&srv, &a.ok(&["team", "add-device", "--for", "@bob"]));
    let (b2, code) = join(&srv, &t);
    assert_eq!(b2.member(), b.member());
    a.ok(&["sync"]);
    assert_ne!(
        b2.status()["approval"],
        "approved",
        "not own: not automatic"
    );
    // Bob cannot approve it: the invite (and its secret) are on Ann's device.
    let err = b.refused(&["team", "approve", "bob", "--code", &code]);
    assert!(err.contains("another device"), "{err}");
    a.ok(&["team", "approve", "bob", "--code", &code]);
    b2.ok(&["sync"]);
    assert_eq!(b2.status()["approval"], "approved");
    // A member invites nobody.
    let err = b.refused(&["team", "invite", "--handle", "eve"]);
    assert!(err.contains("only admins"), "{err}");
}

#[test]
fn approval_takes_kind_and_member_from_the_local_record_and_never_approves_an_unknown_kind() {
    let pending = |kind| PendingDevice {
        device_id: Id::new_v4(),
        member_id: Id::new_v4(),
        handle: Handle::parse("bob").unwrap(),
        kind,
        invite_id: Id::new_v4(),
        device_pubkey: Key32([1; 32]),
        join_mac: Key32([2; 32]),
        joined_at: 0,
    };
    let own = Id::new_v4();
    let target = Id::new_v4();
    let record = |kind: &str, member: Option<Id>, role: Option<&str>| PendingInvite {
        invite: String::new(),
        kind: kind.into(),
        member_id: member.map(|m| m.to_string()),
        role: role.map(str::to_string),
    };
    let err = awm::team::approval_plan(
        &pending(InviteKind::Unknown),
        &record("member", None, None),
        own,
    )
    .unwrap_err();
    assert!(err.to_string().contains("unknown kind"));
    // The server says "member", the local record says "device" for Bob: device, Bob's id.
    let (kind, m, _) = awm::team::approval_plan(
        &pending(InviteKind::Member),
        &record("device", Some(target), None),
        own,
    )
    .unwrap();
    assert_eq!(kind, keys::ApprovalKind::Device);
    assert_eq!(m, target);
    // A member invite takes the role from the record.
    let p = pending(InviteKind::Device);
    let (kind, m, role) =
        awm::team::approval_plan(&p, &record("member", None, Some("admin")), own).unwrap();
    assert_eq!(kind, keys::ApprovalKind::Member);
    assert_eq!(m, p.member_id);
    assert_eq!(role, keys::Role::Admin);
}

// ---------------------------------------------------------------------------------------------
// members, extra_admins

#[test]
fn members_shows_roster_status_and_extra_admins_are_ignored_while_a_verified_admin_exists() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");
    let d = member(&srv, &a, "dan");
    a.ok(&["sync"]);
    d.ok(&["sync"]);
    let v = d.json(&["team", "members", "--json"]);
    let roles: Vec<(String, String)> = v["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["handle"].as_str().unwrap().to_string(),
                m["role"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(roles.contains(&("ann".into(), "admin".into())), "{v}");
    assert!(roles.contains(&("bob".into(), "member".into())), "{v}");
    assert!(v["members"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["devices"][0]["status"] == "verified"));
    let text = d.ok(&["team", "members"]);
    assert!(text.contains("(this device)"), "{text}");

    // The operator promotes Bob on the server; Bob (no roster admin) invites and approves Cat.
    embedded::block_on(
        srv.store
            .set_role(b.member(), WireRole::Admin, None, unix_secs()),
    )
    .unwrap();
    let t = invite(&srv, &b, "cat");
    let (c, code) = join(&srv, &t);
    b.ok(&["team", "approve", "cat", "--code", &code]);
    // Dan trusts Bob, but Ann is a verified admin: Bob's member approval is not accepted.
    d.ok(&["team", "members", "--trust-admin", "@bob"]);
    d.ok(&["sync"]);
    let v = d.json(&["team", "members", "--json"]);
    assert_eq!(v["extra_admins_ignored"], true, "{v}");
    let cat = v["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["handle"] == "cat")
        .unwrap()
        .clone();
    assert_eq!(cat["devices"][0]["status"], "unverified", "{v}");
    assert_eq!(d.status()["extra_admins_ignored"], true);
    // Cat's own roster check fails too: her pushes stay stopped.
    c.ok(&["sync"]);
    assert_ne!(c.status()["approval"], "approved");
    // Trusting someone the server does not list as admin is refused.
    let err = d.refused(&["team", "members", "--trust-admin", "@dan"]);
    assert!(err.contains("not an admin"), "{err}");
}

#[test]
fn extra_admins_apply_when_no_verified_admin_is_left() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");
    let d = member(&srv, &a, "dan");
    // The only roster admin is removed (an admin's own `revoke` of her member) and the operator
    // promotes Bob: the `awm serve promote` recovery.
    embedded::block_on(
        srv.store
            .set_role(b.member(), WireRole::Admin, None, unix_secs()),
    )
    .unwrap();
    {
        let ident = a.ident();
        let ring = ident.ring().unwrap();
        let mut conn = a.conn();
        awm::sync::push::queue_roster_entry(
            &mut conn,
            &ident,
            &ring,
            &RosterEntry::Revoke {
                member_id: *ident.team.member_id.as_uuid(),
                device_id: None,
                revoked_at: unix_secs(),
                by_device_id: *ident.team.device_id.as_uuid(),
            },
            now_ms(),
        )
        .unwrap();
    }
    a.ok(&["sync"]);
    let t = invite(&srv, &b, "cat");
    let (c, code) = join(&srv, &t);
    b.ok(&["team", "approve", "cat", "--code", &code]);
    d.ok(&["sync"]);
    let v = d.json(&["team", "members", "--json"]);
    let status_of = |v: &Value, h: &str| {
        v["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["handle"] == h)
            .unwrap()["devices"][0]["status"]
            .clone()
    };
    assert_eq!(status_of(&v, "cat"), "unverified", "without trust: {v}");
    d.ok(&["team", "members", "--trust-admin", "@bob"]);
    let v = d.json(&["team", "members", "--json"]);
    assert_eq!(v["extra_admins_ignored"], false, "{v}");
    assert_eq!(status_of(&v, "cat"), "verified", "with trust: {v}");
    let text = d.ok(&["team", "status"]);
    assert!(text.contains("decided by the server operator"), "{text}");
    // Cat's own machine trusts Bob too, and may then push.
    c.ok(&["team", "members", "--trust-admin", "@bob"]);
    c.ok(&["sync"]);
    assert_eq!(c.status()["approval"], "approved");
}

// ---------------------------------------------------------------------------------------------
// remove, rotate-key

#[test]
fn remove_revokes_the_member_and_rotates_wrapping_only_to_verified_devices() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");
    let c = member(&srv, &a, "cat");
    a.ok(&["sync"]);

    // Bob's second machine is approved by Bob's first, but the server withholds that roster
    // record from Ann: for her it is unverified.
    let t = token_of(&srv, &b.ok(&["team", "add-device"]));
    let (b2, code) = join(&srv, &t);
    b.ok(&["team", "approve", "bob", "--code", &code]);
    b2.ok(&["sync"]);
    assert_eq!(b2.status()["approval"], "approved");
    let (bm, bd) = (b.member(), b.device());
    let head = srv.roster_head(bm, bd);
    srv.raw()
        .execute(
            "DELETE FROM record WHERE member_id = ?1 AND device_id = ?2 AND tag = 'roster' AND idx = ?3",
            params![bm.to_string(), bd.to_string(), head],
        )
        .unwrap();

    // A member removes nobody; nobody removes themselves.
    let before = srv.log_len();
    let err = b.refused(&["team", "remove", "@cat"]);
    assert!(err.contains("only admins"), "{err}");
    let err = a.refused(&["team", "remove", "@ann"]);
    assert!(err.contains("leave"), "{err}");
    assert!(srv.log_len() >= before);

    let out = a.ok(&["team", "remove", "@cat"]);
    assert!(out.contains("removed @cat"), "{out}");
    assert!(out.contains("epoch 1"), "{out}");
    assert!(
        out.contains("1 device(s) without a verified roster entry"),
        "{out}"
    );
    assert_eq!(TeamKey::load(a.path()).unwrap().epoch_keys.len(), 2);
    assert_eq!(srv.wrap_epochs(b.device()), [0, 1]);
    assert_eq!(
        srv.wrap_epochs(c.device()),
        [0],
        "the removed member gets no new key"
    );
    assert_eq!(
        srv.wrap_epochs(b2.device()),
        [0],
        "an unverified device gets no new key"
    );
    // Cat's token is revoked.
    let err = c.refused(&["sync"]);
    assert!(err.contains("401"), "{err}");
    // Bob takes epoch 1 and still reads Ann's new records.
    b.ok(&["sync"]);
    assert_eq!(TeamKey::load(b.path()).unwrap().epoch_keys.len(), 2);
    share(&a);
    a.capture(1, "https://docs.example.org/after", "After the rotation.");
    a.ok(&["sync"]);
    b.ok(&["sync"]);
    assert_eq!(
        b.count("SELECT COUNT(*) FROM event WHERE origin = 'team'"),
        1
    );
    let roster = b.count("SELECT COUNT(*) FROM team_member WHERE handle = 'cat' AND active = 0");
    assert_eq!(roster, 1, "the roster shows the removal");

    // --delete-records also deletes the member's records.
    let d = member(&srv, &a, "dan");
    share(&d);
    let e = d.capture(1, "https://docs.example.org/dan", "Dan's note.");
    d.ok(&["sync"]);
    let id = d.sync_id(e);
    a.ok(&["team", "remove", "dan", "--delete-records"]);
    assert!(srv.deleted_ids().contains(&id));
    assert_eq!(TeamKey::load(a.path()).unwrap().epoch_keys.len(), 3);
}

#[test]
fn rotate_key_moves_verified_devices_to_the_next_epoch_and_is_for_admins() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");
    let err = b.refused(&["team", "rotate-key"]);
    assert!(err.contains("only admins"), "{err}");
    let out = a.ok(&["team", "rotate-key"]);
    assert!(out.contains("epoch 1"), "{out}");
    assert_eq!(srv.wrap_epochs(b.device()), [0, 1]);
    b.ok(&["sync"]);
    assert_eq!(b.status()["epoch"], 1);
    assert_eq!(
        srv.roster_head(a.member(), a.device()),
        2,
        "the epoch entry is pushed"
    );
}

// ---------------------------------------------------------------------------------------------
// share, unshare

#[test]
fn share_and_unshare_by_repository_directory_and_record() {
    let srv = Srv::start();
    // Outside an organisation: refused.
    let n = Node::new();
    let p = n.project();
    let err = n.refused(&["team", "share", p.to_str().unwrap()]);
    assert!(err.contains("inside an organisation"), "{err}");

    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");

    // A repository (and a worktree of it): one repo_key rule, project rows for both.
    let repo = a.path().join("widget");
    std::fs::create_dir_all(repo.join(".git/worktrees/w")).unwrap();
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(
        repo.join(".git/config"),
        "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = git@GitHub.com:acme/widget.git\n",
    )
    .unwrap();
    let wt = a.path().join("widget-w");
    std::fs::create_dir_all(&wt).unwrap();
    std::fs::write(
        wt.join(".git"),
        format!("gitdir: {}\n", repo.join(".git/worktrees/w").display()),
    )
    .unwrap();
    std::fs::write(repo.join(".git/worktrees/w/commondir"), "../..\n").unwrap();
    let rk = RepoKey::decode(&std::fs::read_to_string(a.path().join("team.repo")).unwrap())
        .unwrap()
        .repo_key("github.com/acme/widget");
    a.ok(&["team", "share", repo.join("src").to_str().unwrap()]);
    a.ok(&["team", "share", wt.to_str().unwrap()]);
    let conn = a.conn();
    let rules: Vec<(String, String)> = conn
        .prepare("SELECT kind, value FROM share_rule")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(rules, [("repo".to_string(), rk.clone())]);
    let mapped = a.count(&format!(
        "SELECT COUNT(*) FROM project WHERE repo_key = '{rk}' AND cwd_hash = '{}'",
        sha256_hex(&std::fs::canonicalize(&wt).unwrap().to_string_lossy())
    ));
    assert_eq!(mapped, 1);
    a.ok(&["team", "unshare", wt.to_str().unwrap()]);
    assert_eq!(a.count("SELECT COUNT(*) FROM share_rule"), 0);

    // A directory: cwd rules; records captured afterwards are pushed.
    share(&a);
    let e1 = a.capture(1, "https://docs.example.org/one", "One.");
    let e2 = a.capture(2, "https://docs.example.org/two", "Two.");
    a.ok(&["sync"]);
    let (id1, id2) = (a.sync_id(e1), a.sync_id(e2));
    b.ok(&["sync"]);
    assert_eq!(
        b.count("SELECT COUNT(*) FROM event WHERE origin = 'team'"),
        2
    );

    // --record: never shared again, deleted remotely.
    let out = a.ok(&["team", "unshare", "--record", &e1.to_string()]);
    assert!(out.contains("never be shared"), "{out}");
    assert!(srv.deleted_ids().contains(&id1));
    assert_eq!(
        a.count(&format!(
            "SELECT COUNT(*) FROM event WHERE id = {e1} AND shareable = 'never'"
        )),
        1
    );
    // A teammate's record: refused.
    let theirs = b.count("SELECT id FROM event WHERE origin = 'team' LIMIT 1");
    let err = b.refused(&["team", "unshare", "--record", &theirs.to_string()]);
    assert!(err.contains("teammate"), "{err}");

    // unshare PATH --delete: the rule goes and the project's shared records are deleted.
    let p = a.project();
    a.ok(&["team", "unshare", p.to_str().unwrap(), "--delete"]);
    assert_eq!(a.count("SELECT COUNT(*) FROM share_rule"), 0);
    assert!(srv.deleted_ids().contains(&id2));
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 0);
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE origin = 'local'"),
        2,
        "local rows stay"
    );
    b.ok(&["sync"]);
    assert_eq!(
        b.count("SELECT COUNT(*) FROM event WHERE origin = 'team'"),
        0
    );
    // Later captures there stay local.
    a.capture(3, "https://docs.example.org/three", "Three.");
    a.ok(&["sync"]);
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE pushed_at IS NOT NULL AND id > 2"),
        0
    );
}

// ---------------------------------------------------------------------------------------------
// status

#[test]
fn status_shows_server_membership_last_sync_outbox_skips_and_pending_approvals() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    let st = a.status();
    assert_eq!(st["reachable"], true);
    assert_eq!(st["last_ok"], Value::Null);
    assert_eq!(st["outbox"]["roster"], 1);
    a.ok(&["sync"]);
    share(&a);
    a.capture(1, "https://docs.example.org/ok", "Fine.");
    a.capture(
        2,
        "https://docs.example.org/leak?token=abc123",
        "With a token.",
    );
    a.ok(&["sync"]);
    let t = invite(&srv, &a, "bob");
    let (_b, code) = join(&srv, &t);
    let st = a.status();
    assert_eq!(st["server_url"], srv.url());
    assert_eq!(st["handle"], "ann");
    assert_eq!(st["role"], "admin");
    assert_eq!(st["approval"], "approved");
    assert!(st["last_ok"].is_string());
    assert_eq!(st["skipped"]["credential_url"], 1, "{st}");
    assert_eq!(st["pending"][0]["handle"], "bob");
    assert_eq!(
        st["pending"][0]["code"].as_str().unwrap().replace(' ', ""),
        code
    );
    assert_eq!(st["settings"]["retention_days"], 365);
    let text = a.ok(&["team", "status"]);
    for line in [
        "server ",
        "member ",
        "last sync ",
        "outbox ",
        "kept local ",
        "pending ",
        "retention ",
    ] {
        assert!(text.contains(line), "{line}: {text}");
    }
    // Offline: still answers, says unreachable.
    let mut srv = srv;
    srv.stop();
    let st = a.status();
    assert_eq!(st["reachable"], false);
    srv.resume();
    // Outside a team.
    let n = Node::new();
    assert_eq!(n.status()["in_team"], false);
}

// ---------------------------------------------------------------------------------------------
// leave, delete-mine, move

#[test]
fn leave_delete_is_refused_offline_and_leave_removes_the_team_from_the_machine() {
    let mut srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");
    share(&b);
    let e = b.capture(1, "https://docs.example.org/b", "Bob's note.");
    b.ok(&["sync"]);
    let id = b.sync_id(e);
    a.ok(&["sync"]);
    let token = b.ident().key.device_token;

    srv.stop();
    let err = b.refused(&["team", "leave", "--delete"]);
    assert!(err.contains("nothing was changed"), "{err}");
    assert!(b.path().join("team.toml").exists());
    assert!(b.path().join("team.key").exists());
    srv.resume();

    let out = b.ok(&["team", "leave", "--delete"]);
    assert!(out.contains("left the organisation"), "{out}");
    assert!(srv.deleted_ids().contains(&id));
    for f in ["team.toml", "team.key", "team.repo"] {
        assert!(!b.path().join(f).exists(), "{f}");
    }
    for t in [
        "team_member",
        "team_device",
        "sync_own",
        "sync_outbox",
        "roster_record",
        "sync_state",
        "share_rule",
    ] {
        assert_eq!(b.count(&format!("SELECT COUNT(*) FROM {t}")), 0, "{t}");
    }
    assert_eq!(
        b.count("SELECT COUNT(*) FROM event WHERE sync_id IS NOT NULL"),
        0
    );
    assert_eq!(
        b.count("SELECT COUNT(*) FROM event WHERE origin = 'local'"),
        1
    );
    let old = Client::new(&srv.url(), Some(&token), None).unwrap();
    assert_eq!(old.status().unwrap_err().status(), Some(401));
    // Ann's roster shows Bob's device revoked; Ann's local copy of Bob's record goes.
    a.ok(&["sync"]);
    assert_eq!(
        a.count("SELECT COUNT(*) FROM team_device WHERE revoked = 1"),
        1
    );
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE origin = 'team'"),
        0
    );
    // Out of the team, team commands say so.
    let err = b.refused(&["team", "invite", "--handle", "zed"]);
    assert!(err.contains("not in a team"), "{err}");

    // Plain leave keeps the records on the server.
    let c = member(&srv, &a, "cat");
    share(&c);
    let e = c.capture(1, "https://docs.example.org/c", "Cat's note.");
    c.ok(&["sync"]);
    let id = c.sync_id(e);
    c.ok(&["team", "leave"]);
    assert!(!srv.deleted_ids().contains(&id));
}

#[test]
fn delete_mine_deletes_every_own_shared_record_from_the_server() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");
    share(&b);
    let e1 = b.capture(1, "https://docs.example.org/1", "One.");
    let e2 = b.capture(2, "https://docs.example.org/2", "Two.");
    b.ok(&["sync"]);
    let ids = [b.sync_id(e1), b.sync_id(e2)];
    let out = b.ok(&["team", "delete-mine"]);
    assert!(out.contains("deleted 2"), "{out}");
    for id in &ids {
        assert!(srv.deleted_ids().contains(id));
    }
    assert_eq!(
        b.count("SELECT COUNT(*) FROM sync_own WHERE tag = 'rec' AND deleted = 1"),
        2
    );
    assert_eq!(
        b.count("SELECT COUNT(*) FROM tombstone WHERE value LIKE 'team:%'"),
        2
    );
    a.ok(&["sync"]);
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE origin = 'team'"),
        0
    );
}

#[test]
fn move_switches_to_the_new_server_rotates_the_token_and_re_seeds() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");
    share(&a);
    a.capture(1, "https://docs.example.org/before", "Before the move.");
    a.ok(&["sync"]);
    b.ok(&["sync"]);
    let export = srv.dir.path().join("export.db");
    embedded::block_on(srv.store.export_canonical(export.clone())).unwrap();
    // A record pushed to the old server after the export: the re-seed brings it over.
    a.capture(2, "https://docs.example.org/late", "After the export.");
    a.ok(&["sync"]);
    let new = Srv::start_from(Some(&export));

    let old_token = a.ident().key.device_token;
    let out = a.ok(&["team", "move", &new.url()]);
    assert!(out.contains("moved to"), "{out}");
    assert_eq!(a.ident().team.server_url, new.url());
    assert_ne!(a.ident().key.device_token, old_token);
    assert_eq!(
        a.ident().key.previous_device_token.as_deref(),
        Some(old_token.as_str())
    );
    let stale = Client::new(&new.url(), Some(&old_token), None).unwrap();
    assert_eq!(stale.status().unwrap_err().status(), Some(401));
    b.ok(&["team", "move", &new.url()]);
    b.ok(&["sync"]);
    assert_eq!(
        b.count("SELECT COUNT(*) FROM event WHERE origin = 'team'"),
        2
    );
    // Moving to the same URL again, or to a server of another organisation, is refused.
    let err = b.refused(&["team", "move", &new.url()]);
    assert!(err.contains("already uses"), "{err}");
    let other = Srv::start();
    let _z = create(&other, "zed");
    let err = b.refused(&["team", "move", &other.url()]);
    assert!(err.contains("does not know this device"), "{err}");
}

// ---------------------------------------------------------------------------------------------
// policy

#[test]
fn policy_set_by_an_admin_reaches_members_and_a_members_set_is_refused_before_any_request() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");
    let out = a.ok(&[
        "team",
        "policy",
        "set",
        "deny_hosts=evil.example,bad.example",
        "summary_chars=500",
        "retention_days=60",
        "max_members=50",
    ]);
    assert!(out.contains("policy version 1"), "{out}");
    assert!(
        out.contains("retention_days 365"),
        "a decrease waits: {out}"
    );
    let s = embedded::block_on(srv.store.org(unix_secs()))
        .unwrap()
        .unwrap();
    assert_eq!(s.settings.max_members, 50);
    b.ok(&["sync"]);
    let v = b.json(&["team", "policy", "show", "--json"]);
    assert_eq!(
        v["policy"]["deny_hosts"],
        json!(["evil.example", "bad.example"])
    );
    assert_eq!(v["policy"]["summary_chars"], 500);
    assert_eq!(v["settings"]["max_members"], 50);
    assert_eq!(v["settings"]["pending_retention"]["retention_days"], 60);

    let before = srv.log_len();
    for kv in ["deny_hosts=x.example", "retention_days=90", "max_members=3"] {
        let err = b.refused(&["team", "policy", "set", kv]);
        assert!(err.contains("admin setting"), "{err}");
    }
    assert_eq!(srv.log_len(), before, "refused before any request");
    let err = a.refused(&["team", "policy", "set", "retention_days=10"]);
    assert!(err.contains("at least 30"), "{err}");
    let err = a.refused(&["team", "policy", "set", "colour=red"]);
    assert!(err.contains("unknown policy key"), "{err}");
    // The member's run is not failed by a policy item it could not push (none was queued).
    assert_eq!(
        b.count("SELECT COUNT(*) FROM sync_outbox WHERE kind = 'policy'"),
        0
    );
}

// ---------------------------------------------------------------------------------------------
// audit, audit-log, flag

#[test]
fn audit_lists_offenders_by_handle_and_deletes_them_and_the_log_is_for_admins() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");
    // A pattern added after the pull: an admin names a new credential parameter, and the
    // records already shared with it are listed by handle, without their text.
    share(&b);
    let e = b.capture(
        1,
        "https://docs.example.org/page?sig_x=s3cr3tvalue",
        "A signed page.",
    );
    b.ok(&["sync"]);
    let leaked = b.sync_id(e);
    a.ok(&["sync"]);
    a.ok(&["team", "policy", "set", "credential_params=sig_x"]);
    let out = a.ok(&["team", "audit"]);
    assert!(
        out.contains(&format!("@bob  record {leaked}  credential_url")),
        "{out}"
    );
    assert!(!out.contains("s3cr3tvalue"), "no record text: {out}");
    let err = b.refused(&["team", "audit"]);
    assert!(err.contains("admins"), "{err}");
    a.ok(&["team", "audit", "--delete"]);
    assert!(srv.deleted_ids().contains(&leaked));
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE url LIKE '%sig_x%'"),
        0
    );
    assert!(a.ok(&["team", "audit"]).contains("no shared record fails"));

    let log = a.ok(&["team", "audit-log"]);
    assert!(log.contains("invite.create"), "{log}");
    let v = a.json(&["team", "audit-log", "--json"]);
    assert!(v["rows"].as_array().unwrap().len() > 3);
    let err = b.refused(&["team", "audit-log"]);
    assert!(err.contains("only admins"), "{err}");
}

#[test]
fn flag_pushes_an_encrypted_flag_record_about_a_teammates_note() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");
    share(&b);
    let mine = b.capture(1, "https://docs.example.org/flag", "Questionable.");
    b.ok(&["sync"]);
    a.ok(&["sync"]);
    let theirs = a.count("SELECT id FROM event WHERE origin = 'team'");
    a.ok(&[
        "team",
        "flag",
        &theirs.to_string(),
        "--reason",
        "looks wrong",
    ]);
    let head = embedded::block_on(srv.store.stream_head(
        a.member(),
        a.device(),
        Tag::parse("flag").unwrap(),
    ))
    .unwrap();
    assert_eq!(head, 0);
    assert!(!contains(&srv.db_bytes(), b"looks wrong"));
    let err = b.refused(&["team", "flag", &mine.to_string()]);
    assert!(err.contains("your own"), "{err}");
}

// ---------------------------------------------------------------------------------------------
// token, key

#[test]
fn token_rotate_replaces_the_token_and_keeps_the_previous_one() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let old = a.ident().key.device_token;
    let out = a.ok(&["team", "token", "rotate"]);
    assert!(!out.contains("awm_t_"), "the token is never printed: {out}");
    let key = a.ident().key;
    assert_ne!(key.device_token, old);
    assert_eq!(key.previous_device_token.as_deref(), Some(old.as_str()));
    let c = Client::new(&srv.url(), Some(&old), None).unwrap();
    assert_eq!(c.status().unwrap_err().status(), Some(401));
    a.ok(&["sync"]);
}

#[test]
fn key_import_restores_the_keys_and_refuses_a_foreign_or_forged_export() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");
    a.ok(&["team", "rotate-key"]);
    b.ok(&["sync"]);
    let export = a.ok(&["team", "key", "export"]).trim().to_string();
    assert!(export.starts_with("awmk1_"));

    // Bob's machine lost its keys.
    let mut key = TeamKey::load(b.path()).unwrap();
    let held = key.epoch_keys.clone();
    key.epoch_keys.truncate(1);
    key.save(b.path()).unwrap();
    std::fs::remove_file(b.path().join("team.repo")).unwrap();

    // Another organisation's export: refused, nothing written.
    let other = Srv::start();
    let z = create(&other, "zed");
    let foreign = z.ok(&["team", "key", "export"]).trim().to_string();
    let before = std::fs::read(b.path().join("team.key")).unwrap();
    let err = b.refused(&["team", "key", "import", &foreign]);
    assert!(err.contains("another organisation"), "{err}");
    // This organisation's id with keys that do not open its genesis: refused, nothing written.
    let fake = KeyRing::from_keys(
        *b.ident().team.org_id.as_uuid(),
        vec![EpochKey::generate(0).unwrap()],
    )
    .unwrap()
    .export_recovery();
    let err = b.refused(&["team", "key", "import", &fake]);
    assert!(err.contains("genesis"), "{err}");
    let err = b.refused(&["team", "key", "import", "awmk1_notvalid"]);
    assert!(err.contains("nothing was written"), "{err}");
    assert_eq!(std::fs::read(b.path().join("team.key")).unwrap(), before);
    assert!(!b.path().join("team.repo").exists());

    let out = b.ok(&["team", "key", "import", &export]);
    assert!(out.contains("up to epoch 1"), "{out}");
    let now = TeamKey::load(b.path()).unwrap().epoch_keys;
    assert_eq!(now.len(), held.len());
    for (x, y) in now.iter().zip(&held) {
        assert_eq!(x.key.0, y.key.0);
    }
    assert_eq!(b.mode("team.repo"), 0o600);
    assert_eq!(b.mode("team.key"), 0o600);
    b.ok(&["sync"]);
}

// ---------------------------------------------------------------------------------------------
// Files and what is printed

#[test]
fn team_key_is_never_printed_and_a_readable_team_key_is_refused() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let key = a.ident().key;
    let secret = serde_json::to_value(key.device_secret).unwrap();
    let k0 = serde_json::to_value(key.epoch_keys[0].key).unwrap();
    let mut outputs = String::new();
    for args in [
        vec!["team", "status"],
        vec!["team", "status", "--json"],
        vec!["team", "members"],
        vec!["team", "members", "--json"],
        vec!["team", "policy", "show"],
        vec!["where"],
    ] {
        let o = a.run(&args);
        outputs.push_str(&o.stdout);
        outputs.push_str(&o.stderr);
    }
    for needle in [
        key.device_token.as_str(),
        secret.as_str().unwrap(),
        k0.as_str().unwrap(),
    ] {
        assert!(!outputs.contains(needle));
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        a.path().join("team.key"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let err = a.refused(&["team", "status"]);
    assert!(err.contains("readable by other users"), "{err}");
}

#[test]
fn the_server_helper_reads_no_unknown_rows() {
    // Keeps `OptionalExtension` honest for the raw server queries above.
    let srv = Srv::start();
    let none: Option<i64> = srv
        .raw()
        .query_row("SELECT idx FROM record LIMIT 1", [], |r| r.get(0))
        .optional()
        .unwrap();
    assert_eq!(none, None);
}

/// TM29 finding 1: in a `sync,serve` build the help of `team`, `sync` and `serve` does not call
/// them unimplemented (the default build's stubs still do, `tests/cli.rs`).
#[test]
fn the_help_of_team_sync_and_serve_does_not_call_them_unimplemented() {
    let n = Node::new();
    let top = n.ok(&["--help"]);
    for (sub, first) in [
        ("team", "Team sync: membership and sharing"),
        ("sync", "Sync with the team server"),
        ("serve", "Run the team server"),
    ] {
        let line = top
            .lines()
            .find(|l| l.trim_start().starts_with(&format!("{sub} ")))
            .unwrap_or_else(|| panic!("{sub} missing from {top}"));
        assert!(line.contains(first), "{line}");
        assert!(!line.contains("not implemented"), "{line}");
        let help = n.ok(&[sub, "--help"]);
        assert_eq!(help.lines().next(), Some(first), "{help}");
    }
}

// ---------------------------------------------------------------------------------------------
// FT3a: awm sync --push-only, --pull-only, --status (RVT3 F5), rejected items (F17), the line
// after `pushed 0` (F21), one rotation per removal (F6)

/// Request paths of the server log from `from` on, for `member`.
fn paths_since(srv: &Srv, from: usize, member: Id) -> Vec<String> {
    let tag = format!("member={member}");
    srv.logs.0.lock().unwrap()[from..]
        .iter()
        .filter(|l| l.contains(&tag))
        .filter_map(|l| {
            let method = l.split("method=").nth(1)?.split(' ').next()?;
            let path = l.split("path=").nth(1)?.split(' ').next()?;
            Some(format!("{method} {path}"))
        })
        .collect()
}

#[test]
fn sync_push_only_and_pull_only_skip_the_other_phase_and_exclude_each_other() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");
    share(&a);
    share(&b);
    b.capture(1, "https://docs.example.org/bob", "Bob's note.");
    b.ok(&["sync"]);
    a.capture(1, "https://docs.example.org/ann", "Ann's note.");

    // --push-only: Ann's record goes out, Bob's stays on the server.
    let from = srv.log_len();
    let out = a.ok(&["sync", "--push-only"]);
    assert!(out.contains("synced: pushed 1, pulled 0"), "{out}");
    let paths = paths_since(&srv, from, a.member());
    assert!(paths.contains(&"POST /v1/records".to_string()), "{paths:?}");
    assert!(
        !paths
            .iter()
            .any(|p| p.contains("/v1/pull") || p.contains("/v1/deletions")),
        "{paths:?}"
    );
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE origin = 'team'"),
        0
    );

    // --pull-only: Bob's record comes in, Ann's new one stays queued here.
    a.capture(2, "https://docs.example.org/ann2", "Ann's second note.");
    let from = srv.log_len();
    let out = a.ok(&["sync", "--pull-only"]);
    assert!(out.contains("synced: pushed 0, pulled 1"), "{out}");
    let paths = paths_since(&srv, from, a.member());
    assert!(paths.contains(&"POST /v1/pull".to_string()), "{paths:?}");
    assert!(
        !paths
            .iter()
            .any(|p| p.contains("/v1/records") || p.contains("/v1/keys/rotate")),
        "{paths:?}"
    );
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE origin = 'team'"),
        1
    );
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE origin = 'local' AND pushed_at IS NULL"),
        1
    );

    // Both take the lock.
    let lock = std::fs::File::options()
        .create(true)
        .write(true)
        .truncate(false)
        .open(a.path().join("sync.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    for flag in ["--push-only", "--pull-only"] {
        let out = a.ok(&["sync", "--once", flag]);
        assert!(out.contains("another awm sync is running"), "{flag}: {out}");
    }
    drop(lock);

    // Not both, and --status with neither.
    for args in [
        &["sync", "--push-only", "--pull-only"][..],
        &["sync", "--status", "--push-only"][..],
        &["sync", "--status", "--pull-only"][..],
    ] {
        let o = a.run(args);
        assert_eq!(o.code, Some(2), "{args:?}: {}", o.stdout);
        assert!(
            o.stderr.contains("cannot be used with"),
            "{args:?}: {}",
            o.stderr
        );
    }
}

#[test]
fn sync_status_prints_what_team_status_prints_and_does_not_sync() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    share(&a);
    a.capture(1, "https://docs.example.org/waiting", "Waiting.");
    let last_ok = a.state("last_ok");
    let from = srv.log_len();
    let via_sync = a.ok(&["sync", "--status"]);
    let via_team = a.ok(&["team", "status"]);
    assert_eq!(via_sync, via_team);
    assert!(via_sync.contains("last sync "), "{via_sync}");
    let paths = paths_since(&srv, from, a.member());
    assert!(
        paths.iter().all(|p| p == "GET /v1/status"),
        "no sync: {paths:?}"
    );
    assert_eq!(a.state("last_ok"), last_ok);
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE pushed_at IS NOT NULL"),
        0
    );
    // Outside a team: the same text too.
    let n = Node::new();
    assert_eq!(n.ok(&["sync", "--status"]), n.ok(&["team", "status"]));
}

#[test]
fn a_single_item_the_server_refuses_is_dropped_counted_and_the_next_item_is_pushed() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    share(&a);
    // A stored item too large to ever go out (413 `too_large`, `blob`), queued before a normal
    // record: a flag whose stored blob was replaced by 1.1 MB (alone in its request).
    let ident = a.ident();
    let ring = ident.ring().unwrap();
    awm::sync::push::queue_item(
        &mut a.conn(),
        &ident,
        &ring,
        "flag",
        "flag",
        b"{}",
        now_ms(),
    )
    .unwrap();
    a.conn()
        .execute(
            "UPDATE sync_own SET blob = zeroblob(1100000) WHERE tag = 'flag' AND idx = 0",
            [],
        )
        .unwrap();
    let e = a.capture(1, "https://docs.example.org/after-the-big-one", "After.");
    let o = a.run(&["sync"]);
    assert_eq!(o.code, Some(0), "{}{}", o.stdout, o.stderr);
    assert!(
        o.stdout.contains("synced: pushed 1, pulled 0, rejected 1"),
        "{}",
        o.stdout
    );
    assert!(
        o.stderr.contains("the server refused flag 0") && o.stderr.contains("with 413"),
        "{}",
        o.stderr
    );
    assert!(
        a.count(&format!(
            "SELECT COUNT(*) FROM event WHERE id = {e} AND pushed_at IS NOT NULL"
        )) == 1
    );
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 0);
    assert_eq!(a.status()["dropped"]["push_rejected"], 1);
    // The flag stream holds a marker at idx 0, so the stream stays contiguous.
    let deleted: i64 = srv
        .raw()
        .query_row(
            "SELECT COUNT(*) FROM record WHERE member_id = ?1 AND tag = 'flag' AND idx = 0 AND blob IS NULL",
            [a.member().to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(deleted, 1);
    // The next run is clean.
    let out = a.ok(&["sync"]);
    assert!(!out.contains("rejected"), "{out}");
}

/// A forwarding HTTP proxy in front of a [`Srv`] that answers chosen `POST /v1/records` requests
/// itself (a proxy, WAF or load balancer in front of the server, RVT3v V2). One request per
/// connection. Each queued rule answers the next push: `None` forwards it, `Some(raw)` replies
/// with those bytes; with the queue empty everything is forwarded.
struct Proxy {
    addr: SocketAddr,
    rules: Arc<Mutex<std::collections::VecDeque<Option<String>>>>,
}

impl Proxy {
    fn start(upstream: SocketAddr) -> Proxy {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let rules: Arc<Mutex<std::collections::VecDeque<Option<String>>>> = Arc::default();
        let queue = rules.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut client) = conn else { continue };
                let queue = queue.clone();
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 65_536];
                    let head_end = loop {
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                        match client.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let len: usize = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    while buf.len() < head_end + len {
                        match client.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let is_push = head.starts_with("POST /v1/records ");
                    let rule = if is_push {
                        queue.lock().unwrap().pop_front().flatten()
                    } else {
                        None
                    };
                    if let Some(raw) = rule {
                        let _ = client.write_all(raw.as_bytes());
                        return;
                    }
                    let mut fwd: String = head
                        .lines()
                        .filter(|l| {
                            !l.is_empty() && !l.to_ascii_lowercase().starts_with("connection:")
                        })
                        .map(|l| format!("{l}\r\n"))
                        .collect();
                    fwd.push_str("Connection: close\r\n\r\n");
                    let Ok(mut up) = std::net::TcpStream::connect(upstream) else {
                        return;
                    };
                    let mut bytes = fwd.into_bytes();
                    bytes.extend_from_slice(&buf[head_end..head_end + len]);
                    let _ = up.write_all(&bytes);
                    let mut resp = Vec::new();
                    let _ = up.read_to_end(&mut resp);
                    let _ = client.write_all(&resp);
                });
            }
        });
        Proxy { addr, rules }
    }

    /// The next push is answered by `rule` (`None`: forwarded).
    fn queue(&self, rule: Option<String>) {
        self.rules.lock().unwrap().push_back(rule);
    }

    /// Points a node at this proxy.
    fn serve(&self, n: &Node) {
        let mut team = n.ident().team;
        team.server_url = format!("http://{}", self.addr);
        team.save(n.path()).unwrap();
    }
}

/// A reply with no awm error body, as a proxy sends it.
fn bare(status: &str) -> String {
    let body = "<html>refused</html>";
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A reply with an awm error body.
fn coded(status: &str, code: &str) -> String {
    let body = format!(r#"{{"error":"{code}","message":"test"}}"#);
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A node with a shared project and one captured record waiting, behind a [`Proxy`].
fn node_with_one_record_behind_a_proxy() -> (Srv, Proxy, Node) {
    let srv = Srv::start();
    let proxy = Proxy::start(srv.addr);
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    share(&a);
    a.capture(1, "https://docs.example.org/one", "One.");
    proxy.serve(&a);
    (srv, proxy, a)
}

const OWN_ROW: &str =
    "SELECT COUNT(*) FROM sync_own WHERE tag = 'rec' AND blob IS NOT NULL AND deleted = 0";

// RVT3v V2 (a): a 413 with no awm body is not the server refusing the item.
#[test]
fn a_413_without_an_awm_body_fails_the_run_and_keeps_the_item_for_the_next_run() {
    let (_srv, proxy, a) = node_with_one_record_behind_a_proxy();
    proxy.queue(Some(bare("413 Payload Too Large")));
    let o = a.run(&["sync"]);
    assert_ne!(o.code, Some(0), "{}{}", o.stdout, o.stderr);
    assert!(!o.stderr.contains("dropped"), "{}", o.stderr);
    assert_eq!(a.count(OWN_ROW), 1, "the sealed blob is still there");
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 1);
    assert_eq!(a.status()["dropped"]["push_rejected"], Value::Null);
    // The next run retries and pushes it.
    let out = a.ok(&["sync"]);
    assert!(out.contains("pushed 1"), "{out}");
    assert!(!out.contains("rejected"), "{out}");
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 0);
}

// RVT3v V2 (b): a 413 with an awm body drops the item (F17), and its sealed blob goes only after
// the marker's 200.
#[test]
fn a_413_with_an_awm_body_drops_the_item_and_clears_the_blob_after_the_marker_is_acknowledged() {
    let srv = Srv::start();
    let proxy = Proxy::start(srv.addr);
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    share(&a);
    let ident = a.ident();
    let ring = ident.ring().unwrap();
    awm::sync::push::queue_item(
        &mut a.conn(),
        &ident,
        &ring,
        "flag",
        "flag",
        b"{}",
        now_ms(),
    )
    .unwrap();
    a.conn()
        .execute(
            "UPDATE sync_own SET blob = zeroblob(1100000) WHERE tag = 'flag' AND idx = 0",
            [],
        )
        .unwrap();
    proxy.serve(&a);
    // The server's own 413 `too_large` answers the item; the marker then meets a 503 without a
    // body, so the run fails before the marker is acknowledged.
    proxy.queue(None);
    proxy.queue(Some(bare("503 Service Unavailable")));
    let o = a.run(&["sync"]);
    assert_ne!(o.code, Some(0), "{}{}", o.stdout, o.stderr);
    assert!(
        o.stderr.contains("the server refused flag 0") && o.stderr.contains("with 413"),
        "{}",
        o.stderr
    );
    let flag = "SELECT COUNT(*) FROM sync_own WHERE tag = 'flag' AND idx = 0 AND deleted = 1 AND blob IS NOT NULL";
    assert_eq!(a.count(flag), 1, "marker not acknowledged: the blob stays");
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 1);
    // The next run sends the marker; its 200 clears the blob and the outbox row.
    let out = a.ok(&["sync"]);
    assert!(
        !out.contains("rejected 1"),
        "counted once, not again: {out}"
    );
    assert_eq!(
        a.count("SELECT COUNT(*) FROM sync_own WHERE tag = 'flag' AND idx = 0 AND deleted = 1 AND blob IS NULL"),
        1
    );
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 0);
    let markers: i64 = srv
        .raw()
        .query_row(
            "SELECT COUNT(*) FROM record WHERE member_id = ?1 AND tag = 'flag' AND idx = 0 AND blob IS NULL",
            [a.member().to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(markers, 1);
}

// RVT3v V2 (c): a 403 with an awm code that is no refused write (`not_approved`) fails the run.
#[test]
fn a_403_with_a_code_that_is_not_a_refused_write_fails_the_run() {
    let (_srv, proxy, a) = node_with_one_record_behind_a_proxy();
    proxy.queue(Some(coded("403 Forbidden", "not_approved")));
    let o = a.run(&["sync"]);
    assert_ne!(o.code, Some(0), "{}{}", o.stdout, o.stderr);
    assert!(!o.stderr.contains("dropped"), "{}", o.stderr);
    assert_eq!(a.count(OWN_ROW), 1);
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 1);
    assert_eq!(a.status()["dropped"]["push_rejected"], Value::Null);
}

// RVT3v V9: only a full run is "the last successful sync".
#[test]
fn only_a_full_run_writes_last_ok() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    assert_eq!(a.state(state::LAST_OK), None);
    a.ok(&["sync", "--pull-only"]);
    assert_eq!(a.state(state::LAST_OK), None, "a pull-only run");
    a.ok(&["sync", "--push-only"]);
    assert_eq!(a.state(state::LAST_OK), None, "a push-only run");
    a.ok(&["sync"]);
    let full = a.state(state::LAST_OK).expect("a full run writes it");
    std::thread::sleep(std::time::Duration::from_millis(20));
    a.ok(&["sync", "--pull-only"]);
    a.ok(&["sync", "--push-only"]);
    assert_eq!(a.state(state::LAST_OK), Some(full));
}

#[test]
fn a_run_that_pushed_nothing_says_whether_anything_waits_and_when_the_last_sync_was() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    let out = a.ok(&["sync"]);
    assert!(out.contains("synced: pushed 1"), "the genesis: {out}");
    assert!(!out.contains("nothing waiting"), "{out}");
    let out = a.ok(&["sync"]);
    let line = out
        .lines()
        .find(|l| l.starts_with("nothing waiting; last successful sync "))
        .unwrap_or_else(|| panic!("{out}"));
    let secs: i64 = line
        .trim_start_matches("nothing waiting; last successful sync ")
        .trim_end_matches(" s ago")
        .parse()
        .unwrap_or_else(|_| panic!("{line}"));
    assert!((0..60).contains(&secs), "{line}");

    // A member's first run pushes nothing: no earlier sync.
    let t = invite(&srv, &a, "bob");
    let (b, code) = join(&srv, &t);
    a.ok(&["team", "approve", "bob", "--code", &code]);
    let out = b.ok(&["sync"]);
    assert!(
        out.contains("nothing waiting; no successful sync yet"),
        "{out}"
    );
}

#[test]
fn remove_rotates_exactly_once_and_a_later_sync_does_not_rotate_again() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    a.ok(&["sync"]);
    let b = member(&srv, &a, "bob");
    let _c = member(&srv, &a, "cat");
    a.ok(&["sync"]);
    let out = a.ok(&["team", "remove", "@cat"]);
    assert!(out.contains("rotated to epoch 1"), "{out}");
    for _ in 0..2 {
        // A server that withholds `rotation_needed`: only the client's own check decides.
        srv.raw()
            .execute("UPDATE org SET rotation_needed = 0", [])
            .unwrap();
        let out = a.ok(&["sync"]);
        assert!(!out.contains("rotated"), "{out}");
    }
    assert_eq!(TeamKey::load(a.path()).unwrap().epoch_keys.len(), 2);
    assert_eq!(srv.wrap_epochs(b.device()), [0, 1]);
}
