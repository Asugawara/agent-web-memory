//! The HTTP layer of sync protocol v1 (plan-v3-team §4.3, `docs/sync-v1.md`; TM8) against a
//! real `SqliteStore` in a scratch directory, through the router.
//!
//! Run: `cargo test -p awm-server --features sqlite --test api_v1`.
//!
//! Requests go through `Router::oneshot` with the peer address set as a `ConnectInfo`
//! extension; the clock is a counter the tests advance; request logs are captured by a sink.
//! The graceful-shutdown tests use a loopback listener on port 0 and a blocking `std` client.

#![cfg(feature = "sqlite")]

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use awm_proto::wire::{ErrorBody, ErrorCode, Id, Role, Version, B64};
use awm_server::auth;
use awm_server::http::{self, AppState, IpNet, LogSink, RetentionMode, ServerConfig};
use awm_server::store::sqlite::{open_connection, SqliteStore, DB_FILE};
use awm_server::store::{NewInvite, Store, StoreError};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request};
use axum::Router;
use serde_json::{json, Value};
use tower::ServiceExt;

// ---------------------------------------------------------------------------------------------
// Scratch directories, the clock, the log sink

const T0: i64 = 1_790_000_000 - 1_790_000_000 % 86_400 + 43_200; // noon UTC of a day
const DAY: i64 = 86_400;
const CLIENT: &str = "awm/0.2.0 proto/1 redact/3";

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "api-{tag}-{}-{nanos}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct Capture(Mutex<Vec<String>>);

impl LogSink for Capture {
    fn line(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_string());
    }
}

// ---------------------------------------------------------------------------------------------
// The server under test

/// Which retention runner a test server gets.
enum Runner {
    Given(http::RetentionRunner),
    /// TM9's runner over the server's store and the test clock.
    Clocked,
    /// Whatever `AppState::new` installs.
    Default,
}

/// The test clock as TM9's `retention::Clock`; a sleep returns at once.
struct TestClock(Arc<AtomicI64>);

impl awm_server::retention::Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
    fn sleep(
        &self,
        _secs: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::ready(()))
    }
}

struct Srv {
    store: Arc<SqliteStore>,
    state: AppState,
    router: Router,
    clock: Arc<AtomicI64>,
    logs: Arc<Capture>,
    retention_calls: Arc<AtomicU32>,
    data: PathBuf,
    _dir: TempDir,
}

fn base_config() -> ServerConfig {
    ServerConfig::new(Version::new(0, 2, 0), Version::new(0, 2, 0))
}

impl Srv {
    fn new() -> Srv {
        Srv::with(|_| {})
    }

    fn with(f: impl FnOnce(&mut ServerConfig)) -> Srv {
        Srv::build(f, None)
    }

    /// A server whose retention runner is `runner` (default: a counting stand-in).
    fn build(f: impl FnOnce(&mut ServerConfig), runner: Option<http::RetentionRunner>) -> Srv {
        let dir = TempDir::new("srv");
        let mut cfg = base_config();
        cfg.export_dir = dir.0.clone();
        f(&mut cfg);
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let runner = runner.unwrap_or_else(|| {
            Arc::new(move |_days| {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(7)
            })
        });
        let clock = Arc::new(AtomicI64::new(T0));
        Srv::assemble(
            dir,
            cfg,
            clock,
            Arc::new(Capture::default()),
            calls,
            Runner::Given(runner),
        )
    }

    /// A server whose retention runner is TM9's `retention::runner_with_clock` over its store
    /// and the test clock.
    fn real(f: impl FnOnce(&mut ServerConfig)) -> Srv {
        Srv::with_runner(f, Runner::Clocked)
    }

    /// A server that keeps `AppState::new`'s own default runner (`retention::runner`, which
    /// reads the system clock).
    fn default_runner(f: impl FnOnce(&mut ServerConfig)) -> Srv {
        Srv::with_runner(f, Runner::Default)
    }

    fn with_runner(f: impl FnOnce(&mut ServerConfig), runner: Runner) -> Srv {
        let dir = TempDir::new("srv");
        let mut cfg = base_config();
        cfg.export_dir = dir.0.clone();
        f(&mut cfg);
        let clock = Arc::new(AtomicI64::new(T0));
        Srv::assemble(
            dir,
            cfg,
            clock,
            Arc::new(Capture::default()),
            Arc::new(AtomicU32::new(0)),
            runner,
        )
    }

    /// Closes the store and opens a new `AppState` on the same `server.db`, with the same
    /// configuration, clock and a `retention::runner_with_clock`: a process restart.
    fn restart(self) -> Srv {
        let Srv {
            store,
            state,
            router,
            clock,
            logs,
            retention_calls,
            _dir,
            ..
        } = self;
        let cfg = (*state.config).clone();
        drop(router);
        drop(state);
        drop(store);
        Srv::assemble(_dir, cfg, clock, logs, retention_calls, Runner::Clocked)
    }

    fn assemble(
        dir: TempDir,
        cfg: ServerConfig,
        clock: Arc<AtomicI64>,
        logs: Arc<Capture>,
        calls: Arc<AtomicU32>,
        runner: Runner,
    ) -> Srv {
        let data = dir.0.join("data");
        let store = Arc::new(SqliteStore::open(&data).unwrap());
        let ck = clock.clone();
        let mut state = AppState::new(store.clone() as Arc<dyn Store>, cfg)
            .with_clock(Arc::new(move || ck.load(Ordering::SeqCst)))
            .with_log_sink(logs.clone());
        match runner {
            Runner::Given(runner) => state = state.with_retention_runner(runner),
            Runner::Clocked => {
                let r = awm_server::retention::runner_with_clock(
                    store.clone() as Arc<dyn Store>,
                    Arc::new(TestClock(clock.clone())),
                );
                state = state.with_retention_runner(Arc::new(r));
            }
            Runner::Default => {}
        }
        let router = http::router(state.clone());
        Srv {
            store,
            state,
            router,
            clock,
            logs,
            retention_calls: calls,
            data,
            _dir: dir,
        }
    }

    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn advance(&self, s: i64) {
        self.clock.fetch_add(s, Ordering::SeqCst);
    }

    async fn send(&self, r: R) -> Resp {
        let mut b = Request::builder().method(r.method.clone()).uri(&r.path);
        if let Some(t) = &r.token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        if let Some(c) = &r.client {
            b = b.header("awm-client", c);
        }
        for (k, v) in &r.headers {
            b = b.header(k, v);
        }
        if r.content_length {
            b = b.header("content-length", r.body.len());
        }
        let mut req = b.body(Body::from(r.body)).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(r.peer, 40_000)));
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        Resp {
            status,
            headers,
            body,
        }
    }

    fn log_lines(&self) -> Vec<String> {
        self.logs.0.lock().unwrap().clone()
    }

    // --- setup ------------------------------------------------------------------------------

    async fn bootstrap(&self) -> Who {
        let bt = auth::issue_bootstrap(&*self.store, self.now())
            .await
            .unwrap();
        let org = Id::new_v4();
        let device = Id::new_v4();
        let r = self
            .send(R::post("/v1/bootstrap").json(&json!({
                "bootstrap_token": bt.as_str(),
                "org_id": org.to_string(),
                "handle": "alf",
                "device_id": device.to_string(),
                "device_pubkey": b64(&[1u8; 32]),
            })))
            .await;
        assert_eq!(r.status, 200, "{}", r.text());
        let v = r.json();
        Who {
            token: v["device_token"].as_str().unwrap().to_string(),
            member: Id::parse(v["member_id"].as_str().unwrap()).unwrap(),
            device,
            org,
        }
    }

    async fn epoch(&self) -> u32 {
        self.store
            .org(self.now())
            .await
            .unwrap()
            .unwrap()
            .current_epoch
    }

    /// Invites, joins and approves a member (the admin holds the invite, so the approval is its).
    async fn add_member(&self, admin: &Who, handle: &str, role: &str) -> Who {
        let r = self
            .send(
                R::post("/v1/invites")
                    .auth(admin)
                    .json(&json!({"kind": "member", "handle": handle, "role": role})),
            )
            .await;
        assert_eq!(r.status, 200, "{}", r.text());
        let inv = r.json();
        let device = Id::new_v4();
        let r = self
            .send(R::post("/v1/join").json(&json!({
                "invite_id": inv["invite_id"],
                "invite_token": inv["invite_token"],
                "handle": handle,
                "device_id": device.to_string(),
                "device_pubkey": b64(&[2u8; 32]),
                "join_mac": b64(&[3u8; 32]),
            })))
            .await;
        assert_eq!(r.status, 200, "{}", r.text());
        let j = r.json();
        let who = Who {
            token: j["device_token"].as_str().unwrap().to_string(),
            member: Id::parse(j["member_id"].as_str().unwrap()).unwrap(),
            device,
            org: admin.org,
        };
        self.approve(admin, &who).await;
        who
    }

    async fn approve(&self, admin: &Who, who: &Who) {
        let e = self.epoch().await;
        let r = self
            .send(
                R::post(&format!("/v1/devices/{}/approve", who.device))
                    .auth(admin)
                    .json(&wraps(e)),
            )
            .await;
        assert_eq!(r.status, 204, "{}", r.text());
    }

    async fn push(&self, who: &Who, items: Vec<Value>) -> Resp {
        self.send(
            R::post("/v1/records")
                .auth(who)
                .json(&json!({ "records": items })),
        )
        .await
    }

    /// `n` record items of one tag from index `from`, with fresh ids.
    fn items(&self, tag: &str, from: u64, n: u64, epoch: u32, blob_len: usize) -> Vec<Value> {
        (0..n)
            .map(|i| {
                item(
                    tag,
                    from + i,
                    Id::new_v4(),
                    epoch,
                    blob_len,
                    (i % 200) as u8 + 3,
                )
            })
            .collect()
    }
}

struct Who {
    token: String,
    member: Id,
    device: Id,
    org: Id,
}

// --- requests and responses -----------------------------------------------------------------

struct R {
    method: Method,
    path: String,
    token: Option<String>,
    client: Option<String>,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
    peer: IpAddr,
    content_length: bool,
}

impl R {
    fn new(method: Method, path: &str) -> R {
        R {
            method,
            path: path.to_string(),
            token: None,
            client: Some(CLIENT.to_string()),
            body: Vec::new(),
            headers: Vec::new(),
            peer: "127.0.0.1".parse().unwrap(),
            content_length: false,
        }
    }
    fn get(path: &str) -> R {
        R::new(Method::GET, path)
    }
    fn post(path: &str) -> R {
        R::new(Method::POST, path)
    }
    fn put(path: &str) -> R {
        R::new(Method::PUT, path)
    }
    fn delete(path: &str) -> R {
        R::new(Method::DELETE, path)
    }
    fn auth(mut self, who: &Who) -> R {
        self.token = Some(who.token.clone());
        self
    }
    fn bearer(mut self, token: &str) -> R {
        self.token = Some(token.to_string());
        self
    }
    fn client(mut self, c: &str) -> R {
        self.client = Some(c.to_string());
        self
    }
    fn no_client(mut self) -> R {
        self.client = None;
        self
    }
    fn json(mut self, v: &Value) -> R {
        self.body = serde_json::to_vec(v).unwrap();
        self
    }
    fn raw(mut self, b: Vec<u8>) -> R {
        self.body = b;
        self
    }
    fn header(mut self, k: &str, v: &str) -> R {
        self.headers.push((k.to_string(), v.to_string()));
        self
    }
    fn from(mut self, ip: &str) -> R {
        self.peer = ip.parse().unwrap();
        self
    }
    fn with_length(mut self) -> R {
        self.content_length = true;
        self
    }
}

struct Resp {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.text()))
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body[..self.body.len().min(600)]).into_owned()
    }
    fn err(&self) -> ErrorBody {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not an error body ({e}): {}", self.text()))
    }
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    }
    /// Asserts the status and the error code.
    #[track_caller]
    fn expect_err(&self, status: u16, code: ErrorCode) -> ErrorBody {
        assert_eq!(self.status, status, "{}", self.text());
        let e = self.err();
        assert_eq!(e.error, code, "{}", self.text());
        e
    }
}

// --- wire helpers ---------------------------------------------------------------------------

fn b64(bytes: &[u8]) -> String {
    String::from(B64(bytes.to_vec()))
}

fn wraps(current: u32) -> Value {
    json!({"wraps": (0..=current).map(|e| json!({
        "epoch": e, "wrap": b64(&[0x5a; 140]), "auth": b64(&[0xa0 + e as u8; 32])
    })).collect::<Vec<_>>()})
}

/// An envelope-shaped blob of `len` bytes (`0x01`, then `seed`).
fn blob_bytes(len: usize, seed: u8) -> Vec<u8> {
    let mut v = vec![seed; len];
    if len > 0 {
        v[0] = 0x01;
    }
    v
}

fn item(tag: &str, idx: u64, id: Id, epoch: u32, blob_len: usize, seed: u8) -> Value {
    json!({
        "tag": tag, "idx": idx, "id": id.to_string(), "epoch": epoch,
        "blob": b64(&blob_bytes(blob_len, seed)),
    })
}

fn marker(tag: &str, idx: u64, id: Id) -> Value {
    json!({"tag": tag, "idx": idx, "id": id.to_string(), "deleted": true})
}

const SMALL: usize = 41 + 256;
const LARGEST: usize = 41 + 256 * 63; // 16,169

fn fixture(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../awm-proto/tests/fixtures/v1")
        .join(format!("{name}.json"));
    serde_json::from_slice(&std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())))
        .unwrap()
}

fn query_of(v: &Value) -> String {
    v.as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| match v {
            Value::String(s) => format!("{k}={s}"),
            other => format!("{k}={other}"),
        })
        .collect::<Vec<_>>()
        .join("&")
}

// --- shapes ---------------------------------------------------------------------------------

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Compares the field set and the types of a produced value with a fixture. Keys in `optional`
/// may be absent from the produced value; arrays of objects are compared against the union of
/// the fixture's elements (a key missing from some fixture element is optional).
fn shape_diff(got: &Value, fix: &Value, path: &str, optional: &[&str], out: &mut Vec<String>) {
    if kind(got) != kind(fix) {
        out.push(format!(
            "{path}: {} where the fixture has {}",
            kind(got),
            kind(fix)
        ));
        return;
    }
    match (got, fix) {
        (Value::Object(g), Value::Object(f)) => {
            for (k, gv) in g {
                match f.get(k) {
                    Some(fv) => shape_diff(gv, fv, &format!("{path}/{k}"), optional, out),
                    None => out.push(format!("{path}/{k}: field the fixture does not have")),
                }
            }
            for k in f.keys() {
                if !g.contains_key(k) && !optional.contains(&k.as_str()) {
                    out.push(format!("{path}/{k}: field missing"));
                }
            }
        }
        (Value::Array(g), Value::Array(f)) => {
            if f.is_empty() {
                return;
            }
            if g.is_empty() {
                out.push(format!("{path}: empty where the fixture has elements"));
                return;
            }
            if f.iter().all(Value::is_object) {
                // The union of the fixture's elements; keys not in every element are optional.
                let mut union = serde_json::Map::new();
                let mut opt: Vec<&str> = optional.to_vec();
                for e in f {
                    for (k, v) in e.as_object().unwrap() {
                        union.insert(k.clone(), v.clone());
                    }
                }
                for k in union.keys() {
                    if !f.iter().all(|e| e.get(k).is_some()) {
                        opt.push(k.as_str());
                    }
                }
                let union = Value::Object(union.clone());
                for (i, e) in g.iter().enumerate() {
                    shape_diff(e, &union, &format!("{path}/{i}"), &opt, out);
                }
            } else {
                for (i, e) in g.iter().enumerate() {
                    shape_diff(e, &f[0], &format!("{path}/{i}"), optional, out);
                }
            }
        }
        _ => {}
    }
}

#[track_caller]
fn assert_shape(name: &str, got: &Value, optional: &[&str]) {
    let fix = fixture(name);
    let mut out = Vec::new();
    shape_diff(got, &fix, "", optional, &mut out);
    assert!(out.is_empty(), "{name}: {out:#?}\n got: {got}");
}

// ---------------------------------------------------------------------------------------------
// Fixtures: every request replayed, every response shape produced

/// Seeds what the fixtures name by id: a second member (`4a5b…`) with a device (`c1d2…`), the
/// fixture's invite, and the fixture's generation.
fn seed_fixture_world(srv: &Srv) {
    let conn = open_connection(&srv.data.join(DB_FILE)).unwrap();
    conn.execute(
        "INSERT INTO member (id, handle, role, created_at) VALUES (?1, 'roy', 'member', 1)",
        rusqlite::params!["4a5b6c7d-8e9f-4a0b-9c1d-2e3f4a5b6c7d"],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO device (id, member_id, token_hash, pubkey, approved, created_at)
         VALUES (?1, ?2, ?3, ?4, 1, 1)",
        rusqlite::params![
            "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f",
            "4a5b6c7d-8e9f-4a0b-9c1d-2e3f4a5b6c7d",
            "ab".repeat(32),
            vec![9u8; 32],
        ],
    )
    .unwrap();
    conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'generation'",
        rusqlite::params!["a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"],
    )
    .unwrap();
}

#[tokio::test]
async fn every_request_fixture_is_replayed_and_every_response_shape_is_produced() {
    let srv = Srv::new();
    let mut table: Vec<(String, String, u16)> = Vec::new();
    macro_rules! row {
        ($name:expr, $what:expr, $resp:expr, $want:expr) => {{
            let r: Resp = $resp;
            assert_eq!(r.status, $want, "{}: {}", $name, r.text());
            table.push(($name.to_string(), $what.to_string(), r.status));
            r
        }};
    }

    // bootstrap.request: the fixture's token, org and device.
    let boot = fixture("bootstrap.request");
    let bt = boot["bootstrap_token"].as_str().unwrap();
    srv.store
        .set_bootstrap(auth::hash(bt), srv.now() + DAY)
        .await
        .unwrap();
    let r = row!(
        "bootstrap.request",
        "POST /v1/bootstrap",
        srv.send(R::post("/v1/bootstrap").json(&boot)).await,
        200
    );
    assert_shape("bootstrap.response", &r.json(), &[]);
    let admin = Who {
        token: r.json()["device_token"].as_str().unwrap().to_string(),
        member: Id::parse(r.json()["member_id"].as_str().unwrap()).unwrap(),
        device: Id::parse(boot["device_id"].as_str().unwrap()).unwrap(),
        org: Id::parse(boot["org_id"].as_str().unwrap()).unwrap(),
    };
    seed_fixture_world(&srv);

    // info
    let r = srv.send(R::get("/v1/info").no_client()).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("cache-control").as_deref(), Some("max-age=3600"));
    assert_shape("info.response", &r.json(), &[]);
    table.push(("(no request fixture)".into(), "GET /v1/info".into(), 200));

    // Epoch 1 (the push and approve fixtures name it).
    let rotate1 = json!({"epoch": 1, "wraps": [
        {"device_id": admin.device.to_string(), "wrap": b64(&[7u8; 140]), "auth": b64(&[8u8; 32])},
        {"device_id": "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f", "wrap": b64(&[7u8; 140]), "auth": b64(&[8u8; 32])},
    ]});
    let r = srv
        .send(R::post("/v1/keys/rotate").auth(&admin).json(&rotate1))
        .await;
    assert_eq!(r.status, 204, "{}", r.text());

    // Streams the push fixture continues: rec 0..=43 and roster 0..=2, under epoch 1.
    let r = srv.push(&admin, srv.items("rec", 0, 44, 1, SMALL)).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let r = srv.push(&admin, srv.items("roster", 0, 3, 1, SMALL)).await;
    assert_eq!(r.status, 200, "{}", r.text());

    // records.push.request
    let r = row!(
        "records.push.request",
        "POST /v1/records",
        srv.send(
            R::post("/v1/records")
                .auth(&admin)
                .json(&fixture("records.push.request"))
        )
        .await,
        200
    );
    assert_shape("records.push.response", &r.json(), &[]);
    assert_eq!(r.json()["accepted"], 3);

    // invites.request.member / .device
    let r = row!(
        "invites.request.member",
        "POST /v1/invites",
        srv.send(
            R::post("/v1/invites")
                .auth(&admin)
                .json(&fixture("invites.request.member"))
        )
        .await,
        200
    );
    assert_shape("invites.response", &r.json(), &[]);
    row!(
        "invites.request.device",
        "POST /v1/invites",
        srv.send(
            R::post("/v1/invites")
                .auth(&admin)
                .json(&fixture("invites.request.device"))
        )
        .await,
        200
    );

    // join.request: the fixture's invite id and token, stored by the store directly.
    let join = fixture("join.request");
    srv.store
        .create_invite(NewInvite {
            invite_id: Id::parse(join["invite_id"].as_str().unwrap()).unwrap(),
            token_hash: auth::hash(join["invite_token"].as_str().unwrap()),
            kind: awm_proto::wire::InviteKind::Member,
            handle: awm_proto::wire::Handle::parse("kit").unwrap(),
            role: Some(Role::Member),
            expires_at: srv.now() + DAY,
            by: awm_server::store::Actor {
                member_id: admin.member,
                device_id: admin.device,
                admin: true,
            },
            now: srv.now(),
        })
        .await
        .unwrap();
    // Reads the invite's org: the fixture's token names the fixture's org.
    let r = row!(
        "join.request",
        "POST /v1/join",
        srv.send(R::post("/v1/join").json(&join)).await,
        200
    );
    assert_shape("join.response", &r.json(), &[]);
    let kit_member = r.json()["member_id"].as_str().unwrap().to_string();

    // status (kit is pending, the streams exist), members, keys.
    let r = row!(
        "(none)",
        "GET /v1/status",
        srv.send(R::get("/v1/status").auth(&admin)).await,
        200
    );
    assert_shape("status.response", &r.json(), &["pending_retention"]);
    let r = row!(
        "(none)",
        "GET /v1/members",
        srv.send(R::get("/v1/members").auth(&admin)).await,
        200
    );
    assert_shape("members.response", &r.json(), &[]);
    let r = row!(
        "(none)",
        "GET /v1/keys",
        srv.send(R::get("/v1/keys").auth(&admin)).await,
        200
    );
    assert_shape("keys.response", &r.json(), &[]);

    // approve.request (epochs 0 and 1) for the fixture's joined device.
    row!(
        "approve.request",
        "POST /v1/devices/{id}/approve",
        srv.send(
            R::post(&format!(
                "/v1/devices/{}/approve",
                join["device_id"].as_str().unwrap()
            ))
            .auth(&admin)
            .json(&fixture("approve.request"))
        )
        .await,
        204
    );

    // records.query and pull.request on streams that do not exist, then on a real one.
    let q = fixture("records.query");
    let r = row!(
        "records.query",
        "GET /v1/records",
        srv.send(R::get(&format!("/v1/records?{}", query_of(&q))).auth(&admin))
            .await,
        200
    );
    assert_eq!(r.json()["head"], -1);
    row!(
        "pull.request",
        "POST /v1/pull",
        srv.send(
            R::post("/v1/pull")
                .auth(&admin)
                .json(&fixture("pull.request"))
        )
        .await,
        200
    );
    let own = format!(
        "/v1/records?member={}&device={}&tag=rec&from=43&limit=10",
        admin.member, admin.device
    );
    let r = srv.send(R::get(&own).auth(&admin)).await;
    assert_eq!(r.status, 200);
    assert_shape("records.response", &r.json(), &[]);
    let r = srv
        .send(R::post("/v1/pull").auth(&admin).json(&json!({
            "cursors": [
                {"member": admin.member.to_string(), "device": admin.device.to_string(), "tag": "rec", "from": 43},
                {"member": admin.member.to_string(), "device": admin.device.to_string(), "tag": "roster", "from": 3},
            ],
            "limit": 2
        })))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["more"], true);
    assert_shape("pull.response", &r.json(), &[]);

    // delete.request.ids: record 44 and marker 45 of the push fixture: 1 deleted, 1 already.
    let r = row!(
        "delete.request.ids",
        "POST /v1/delete",
        srv.send(
            R::post("/v1/delete")
                .auth(&admin)
                .json(&fixture("delete.request.ids"))
        )
        .await,
        200
    );
    assert_shape("delete.response", &r.json(), &[]);
    assert_eq!(r.json(), json!({"deleted": 1, "already": 1}));
    let r = srv
        .send(
            R::get(&format!(
                "/v1/deletions?{}",
                query_of(&fixture("deletions.query"))
            ))
            .auth(&admin),
        )
        .await;
    table.push((
        "deletions.query".into(),
        "GET /v1/deletions".into(),
        r.status,
    ));
    assert_eq!(r.status, 200);
    // The fixture's cursor (from 2) is past this stream's head 1: no entries, the head and oldest.
    assert_eq!(r.json()["entries"], json!([]));
    let r = srv.send(R::get("/v1/deletions?from=0").auth(&admin)).await;
    assert_eq!(r.status, 200);
    assert_shape("deletions.response", &r.json(), &[]);

    // delete.request.member (roy, who exists), then all_mine an hour later (1 a token an hour).
    row!(
        "delete.request.member",
        "POST /v1/delete",
        srv.send(
            R::post("/v1/delete")
                .auth(&admin)
                .json(&fixture("delete.request.member"))
        )
        .await,
        200
    );
    srv.advance(3_601);
    row!(
        "delete.request.all_mine",
        "POST /v1/delete",
        srv.send(
            R::post("/v1/delete")
                .auth(&admin)
                .json(&fixture("delete.request.all_mine"))
        )
        .await,
        200
    );

    // settings
    row!(
        "settings.put.request",
        "PUT /v1/org/settings",
        srv.send(
            R::put("/v1/org/settings")
                .auth(&admin)
                .json(&fixture("settings.put.request"))
        )
        .await,
        200
    );
    let r = srv.send(R::get("/v1/org/settings").auth(&admin)).await;
    assert_eq!(r.status, 200);
    assert_shape("settings.response", &r.json(), &[]);
    row!(
        "settings.put.request.cancel",
        "PUT /v1/org/settings",
        srv.send(
            R::put("/v1/org/settings")
                .auth(&admin)
                .json(&fixture("settings.put.request.cancel"))
        )
        .await,
        200
    );

    // audit
    let r = row!(
        "audit.query",
        "GET /v1/audit",
        srv.send(R::get(&format!("/v1/audit?{}", query_of(&fixture("audit.query")))).auth(&admin))
            .await,
        200
    );
    assert_shape("audit.response", &r.json(), &["actor", "target", "detail"]);

    // keys.rotate.request (epoch 2; the devices of the fixture are listed and active)
    row!(
        "keys.rotate.request",
        "POST /v1/keys/rotate",
        srv.send(
            R::post("/v1/keys/rotate")
                .auth(&admin)
                .json(&fixture("keys.rotate.request"))
        )
        .await,
        204
    );

    // members.role.request, members.remove.request
    row!(
        "members.role.request",
        "POST /v1/members/{id}/role",
        srv.send(
            R::post(&format!("/v1/members/{kit_member}/role"))
                .auth(&admin)
                .json(&fixture("members.role.request"))
        )
        .await,
        204
    );
    row!(
        "members.remove.request",
        "POST /v1/members/{id}/remove",
        srv.send(
            R::post("/v1/members/4a5b6c7d-8e9f-4a0b-9c1d-2e3f4a5b6c7d/remove")
                .auth(&admin)
                .json(&fixture("members.remove.request"))
        )
        .await,
        204
    );

    // restore.complete.request: the fixture's generation was seeded.
    row!(
        "restore.complete.request",
        "POST /v1/restore/complete",
        srv.send(
            R::post("/v1/restore/complete")
                .auth(&admin)
                .json(&fixture("restore.complete.request"))
        )
        .await,
        204
    );

    // token.rotate: last, the token changes.
    let r = row!(
        "(none)",
        "POST /v1/token/rotate",
        srv.send(R::post("/v1/token/rotate").auth(&admin)).await,
        200
    );
    assert_shape("token.rotate.response", &r.json(), &[]);
    let r = srv.send(R::get("/v1/status").auth(&admin)).await;
    assert_eq!(r.status, 401, "the old token stops at once");

    println!("\n| fixture | request | status |\n|---|---|---|");
    for (f, w, s) in &table {
        println!("| `{f}` | {w} | {s} |");
    }
}

#[tokio::test]
async fn every_request_fixture_name_is_covered() {
    // The replay above names each request fixture; this keeps the list in step with the directory.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../awm-proto/tests/fixtures/v1");
    let replayed = [
        "approve.request",
        "audit.query",
        "bootstrap.request",
        "delete.request.all_mine",
        "delete.request.ids",
        "delete.request.member",
        "deletions.query",
        "invites.request.device",
        "invites.request.member",
        "join.request",
        "keys.rotate.request",
        "members.remove.request",
        "members.role.request",
        "pull.request",
        "records.push.request",
        "records.query",
        "restore.complete.request",
        "settings.put.request",
        "settings.put.request.cancel",
    ];
    let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| {
            let stem = n.trim_end_matches(".json");
            (stem.ends_with(".request") || stem.contains(".request.") || stem.ends_with(".query"))
                && !stem.starts_with("plaintext.")
        })
        .map(|n| n.trim_end_matches(".json").to_string())
        .collect();
    on_disk.sort();
    let mut want: Vec<String> = replayed.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(on_disk, want);
}

// ---------------------------------------------------------------------------------------------
// Error fixtures: each code's shape is produced by the server

fn assert_error_shape(name: &str, got: &Value) {
    let fix = fixture(name);
    let mut a: Vec<&String> = got.as_object().unwrap().keys().collect();
    let mut b: Vec<&String> = fix.as_object().unwrap().keys().collect();
    a.sort();
    b.sort();
    assert_eq!(a, b, "{name}: {got}");
    let mut out = Vec::new();
    shape_diff(got, &fix, "", &[], &mut out);
    assert!(out.is_empty(), "{name}: {out:?}");
}

#[tokio::test]
async fn every_error_fixture_shape_is_produced() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    let mut seen: Vec<&str> = Vec::new();

    macro_rules! shape {
        ($fixture:expr, $resp:expr, $status:expr) => {{
            let r: Resp = $resp;
            assert_eq!(r.status, $status, "{}: {}", $fixture, r.text());
            assert_error_shape($fixture, &r.json());
            seen.push($fixture);
            r
        }};
    }

    shape!(
        "error.400.malformed",
        srv.send(R::post("/v1/pull").auth(&admin).raw(b"{".to_vec()))
            .await,
        400
    );
    shape!(
        "error.400.unknown_field",
        srv.send(
            R::post("/v1/records")
                .auth(&admin)
                .json(&json!({"records": [{"tag":"rec","idx":0,"id": Id::new_v4().to_string(), "deleted": true, "sig": "x"}]}))
        )
        .await,
        400
    );
    shape!(
        "error.400.invalid_value",
        srv.send(R::get("/v1/deletions?from=0&limit=0").auth(&admin))
            .await,
        400
    );
    shape!(
        "error.400.bad_client_header",
        srv.send(R::get("/v1/status").auth(&admin).no_client())
            .await,
        400
    );
    shape!(
        "error.401.unauthenticated",
        srv.send(R::get("/v1/status")).await,
        401
    );
    shape!(
        "error.403.forbidden",
        srv.send(R::get("/v1/audit?from=0").auth(&roy)).await,
        403
    );
    // A pending device.
    let inv = srv
        .send(
            R::post("/v1/invites")
                .auth(&admin)
                .json(&json!({"kind": "member", "handle": "kit", "role": "member"})),
        )
        .await
        .json();
    let kit_device = Id::new_v4();
    let j = srv
        .send(R::post("/v1/join").json(&json!({
            "invite_id": inv["invite_id"], "invite_token": inv["invite_token"], "handle": "kit",
            "device_id": kit_device.to_string(), "device_pubkey": b64(&[4u8; 32]), "join_mac": b64(&[5u8; 32]),
        })))
        .await
        .json();
    let pending_token = j["device_token"].as_str().unwrap().to_string();
    shape!(
        "error.403.not_approved",
        srv.send(R::get("/v1/members").bearer(&pending_token)).await,
        403
    );
    shape!(
        "error.404.not_found",
        srv.send(R::delete(&format!("/v1/invites/{}", Id::new_v4())).auth(&admin))
            .await,
        404
    );
    shape!(
        "error.409.device_conflict",
        srv.send(R::post("/v1/join").json(&json!({
            "invite_id": Id::new_v4().to_string(),
            "invite_token": inv["invite_token"], "handle": "kit",
            "device_id": kit_device.to_string(), "device_pubkey": b64(&[4u8; 32]), "join_mac": b64(&[5u8; 32]),
        })))
        .await,
        410 // the invite is used up first (§6 join): the conflict needs a fresh invite below
    );
    seen.pop();
    let inv2 = srv
        .send(
            R::post("/v1/invites")
                .auth(&admin)
                .json(&json!({"kind": "member", "handle": "mia", "role": "member"})),
        )
        .await
        .json();
    shape!(
        "error.409.device_conflict",
        srv.send(R::post("/v1/join").json(&json!({
            "invite_id": inv2["invite_id"], "invite_token": inv2["invite_token"], "handle": "mia",
            "device_id": kit_device.to_string(), "device_pubkey": b64(&[4u8; 32]), "join_mac": b64(&[5u8; 32]),
        })))
        .await,
        409
    );
    shape!(
        "error.410.invite_gone",
        srv.send(R::post("/v1/join").json(&json!({
            "invite_id": inv["invite_id"], "invite_token": inv["invite_token"], "handle": "kit",
            "device_id": Id::new_v4().to_string(), "device_pubkey": b64(&[4u8; 32]), "join_mac": b64(&[5u8; 32]),
        })))
        .await,
        410
    );
    shape!(
        "error.409.epoch_conflict",
        srv.send(
            R::post("/v1/keys/rotate")
                .auth(&admin)
                .json(&json!({"epoch": 5, "wraps": []}))
        )
        .await,
        409
    );
    shape!(
        "error.409.last_admin",
        srv.send(
            R::post(&format!("/v1/members/{}/role", admin.member))
                .auth(&admin)
                .json(&json!({"role": "member"}))
        )
        .await,
        409
    );

    // Push errors.
    let id0 = Id::new_v4();
    let r = srv
        .push(&admin, vec![item("rec", 0, id0, 0, SMALL, 5)])
        .await;
    assert_eq!(r.status, 200);
    shape!(
        "error.409.stream_conflict",
        srv.push(&admin, vec![item("rec", 0, Id::new_v4(), 0, SMALL, 5)])
            .await,
        409
    );
    shape!(
        "error.409.id_conflict",
        srv.push(&admin, vec![item("rec", 1, id0, 0, SMALL, 5)])
            .await,
        409
    );
    shape!(
        "error.409.stale_epoch",
        srv.push(&admin, vec![item("rec", 1, Id::new_v4(), 7, SMALL, 5)])
            .await,
        409
    );
    let gone = Id::new_v4();
    srv.send(
        R::post("/v1/delete")
            .auth(&admin)
            .json(&json!({"ids": [gone.to_string()]})),
    )
    .await;
    shape!(
        "error.410.deleted",
        srv.push(&admin, vec![item("rec", 1, gone, 0, SMALL, 5)])
            .await,
        410
    );
    shape!(
        "error.422.bad_envelope",
        srv.push(&admin, vec![item("rec", 1, Id::new_v4(), 0, 300, 5)])
            .await,
        422
    );
    shape!(
        "error.413.too_large",
        srv.send(
            R::post("/v1/records")
                .auth(&admin)
                .raw(vec![b' '; 1_600_000])
                .with_length()
        )
        .await,
        413
    );

    // 426, 429, 503.
    let r = srv
        .send(
            R::put("/v1/org/settings")
                .auth(&admin)
                .json(&json!({"min_client": "0.3.0"})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    shape!(
        "error.426.client_too_old",
        srv.push(&roy, vec![item("rec", 0, Id::new_v4(), 0, SMALL, 6)])
            .await,
        426
    );
    for _ in 0..30 {
        srv.send(R::get("/v1/info").no_client().from("203.0.113.1"))
            .await;
    }
    shape!(
        "error.429.rate_limited",
        srv.send(R::get("/v1/info").no_client().from("203.0.113.1"))
            .await,
        429
    );
    srv.store.renew_generation(srv.now()).await.unwrap();
    shape!(
        "error.503.restore_pending",
        srv.send(
            R::post("/v1/invites")
                .auth(&roy)
                .json(&json!({"kind": "device", "handle": "roy"}))
        )
        .await,
        503
    );

    // `payment_required` (cloud, TM21) and `maintenance` are not produced by this layer.
    let mut all: Vec<String> = std::fs::read_dir(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../awm-proto/tests/fixtures/v1"),
    )
    .unwrap()
    .map(|e| e.unwrap().file_name().into_string().unwrap())
    .filter(|n| n.starts_with("error."))
    .map(|n| n.trim_end_matches(".json").to_string())
    .collect();
    all.retain(|n| n != "error.402.payment_required" && n != "error.503.maintenance");
    all.sort();
    seen.sort();
    assert_eq!(all, seen.iter().map(|s| s.to_string()).collect::<Vec<_>>());
}

// ---------------------------------------------------------------------------------------------
// Authentication, authorisation, strictness

#[tokio::test]
async fn join_and_bootstrap_ignore_an_authorization_header_and_other_endpoints_need_one() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    // A (valid) device token on bootstrap and join changes nothing: they are anonymous.
    let r = srv
        .send(R::post("/v1/join").bearer("garbage").json(&json!({
            "invite_id": Id::new_v4().to_string(),
            "invite_token": format!("awm_i_{}_{}", admin.org, "A".repeat(42) + "A"),
            "handle": "kit", "device_id": Id::new_v4().to_string(),
            "device_pubkey": b64(&[1u8; 32]), "join_mac": b64(&[1u8; 32]),
        })))
        .await;
    r.expect_err(410, ErrorCode::InviteGone);
    for path in [
        "/v1/status",
        "/v1/members",
        "/v1/keys",
        "/v1/org/settings",
        "/v1/audit?from=0",
    ] {
        srv.send(R::get(path))
            .await
            .expect_err(401, ErrorCode::Unauthenticated);
    }
    srv.send(R::get("/v1/status").bearer("awm_t_nope"))
        .await
        .expect_err(401, ErrorCode::Unauthenticated);
    let _ = admin;
}

#[tokio::test]
async fn a_pending_device_reads_status_and_keys_and_nothing_else() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let inv = srv
        .send(
            R::post("/v1/invites")
                .auth(&admin)
                .json(&json!({"kind": "member", "handle": "kit", "role": "member"})),
        )
        .await
        .json();
    let j = srv
        .send(R::post("/v1/join").json(&json!({
            "invite_id": inv["invite_id"], "invite_token": inv["invite_token"], "handle": "kit",
            "device_id": Id::new_v4().to_string(), "device_pubkey": b64(&[4u8; 32]), "join_mac": b64(&[5u8; 32]),
        })))
        .await
        .json();
    let t = j["device_token"].as_str().unwrap();
    assert_eq!(srv.send(R::get("/v1/status").bearer(t)).await.status, 200);
    assert_eq!(srv.send(R::get("/v1/keys").bearer(t)).await.status, 200);
    for r in [
        srv.send(R::get("/v1/members").bearer(t)).await,
        srv.send(R::get("/v1/org/settings").bearer(t)).await,
        srv.send(
            R::post("/v1/pull")
                .bearer(t)
                .json(&json!({"cursors": [], "limit": 1})),
        )
        .await,
        srv.send(R::post("/v1/token/rotate").bearer(t)).await,
    ] {
        r.expect_err(403, ErrorCode::NotApproved);
    }
    srv.push_as(t, vec![item("rec", 0, Id::new_v4(), 0, SMALL, 5)])
        .await
        .expect_err(403, ErrorCode::NotApproved);
}

impl Srv {
    async fn push_as(&self, token: &str, items: Vec<Value>) -> Resp {
        self.send(
            R::post("/v1/records")
                .bearer(token)
                .json(&json!({"records": items})),
        )
        .await
    }
}

#[tokio::test]
async fn permissions_come_from_authz_through_every_endpoint() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    // Members: read yes, admin-only no.
    assert_eq!(srv.send(R::get("/v1/members").auth(&roy)).await.status, 200);
    srv.send(R::get("/v1/audit?from=0").auth(&roy))
        .await
        .expect_err(403, ErrorCode::Forbidden);
    srv.send(
        R::put("/v1/org/settings")
            .auth(&roy)
            .json(&json!({"max_members": 3})),
    )
    .await
    .expect_err(403, ErrorCode::Forbidden);
    srv.send(
        R::post("/v1/keys/rotate")
            .auth(&roy)
            .json(&json!({"epoch": 1, "wraps": []})),
    )
    .await
    .expect_err(403, ErrorCode::Forbidden);
    srv.send(
        R::post("/v1/restore/complete")
            .auth(&roy)
            .json(&json!({"generation": Id::new_v4().to_string()})),
    )
    .await
    .expect_err(403, ErrorCode::Forbidden);
    srv.send(R::get("/v1/export").auth(&roy))
        .await
        .expect_err(403, ErrorCode::Forbidden);
    srv.send(R::post(&format!("/v1/members/{}/remove", admin.member)).auth(&roy))
        .await
        .expect_err(403, ErrorCode::Forbidden);
    srv.send(
        R::post("/v1/delete")
            .auth(&roy)
            .json(&json!({"member": admin.member.to_string()})),
    )
    .await
    .expect_err(403, ErrorCode::Forbidden);
    // `policy` is an admin tag.
    srv.push(&roy, vec![item("policy", 0, Id::new_v4(), 0, SMALL, 5)])
        .await
        .expect_err(403, ErrorCode::Forbidden);
    assert_eq!(
        srv.push(&admin, vec![item("policy", 0, Id::new_v4(), 0, SMALL, 5)])
            .await
            .status,
        200
    );
    // Refusals with a token are audited (`auth::authorise`).
    let audit = srv
        .send(R::get("/v1/audit?from=0").auth(&admin))
        .await
        .json();
    assert!(audit["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["action"] == "authz.refused"));
}

#[tokio::test]
async fn an_authenticated_request_records_the_day_the_device_was_seen() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    srv.advance(5 * DAY);
    assert_eq!(
        srv.send(R::get("/v1/status").auth(&admin)).await.status,
        200
    );
    let d = srv.store.device(admin.device).await.unwrap().unwrap();
    assert_eq!(d.last_seen_day, Some(srv.now().div_euclid(DAY)));
}

#[tokio::test]
async fn unknown_fields_malformed_json_and_encodings_are_refused() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    // A body field, at depth.
    let r = srv
        .send(
            R::post("/v1/records")
                .auth(&admin)
                .json(&json!({"records": [], "x": 1})),
        )
        .await;
    assert_eq!(
        r.expect_err(400, ErrorCode::UnknownField).field.as_deref(),
        Some("/x")
    );
    let r = srv
        .send(R::post("/v1/pull").auth(&admin).json(&json!({
            "cursors": [{"member": Id::new_v4().to_string(), "device": Id::new_v4().to_string(),
                         "tag": "rec", "from": 0, "extra": 1}],
            "limit": 5
        })))
        .await;
    assert_eq!(
        r.expect_err(400, ErrorCode::UnknownField).field.as_deref(),
        Some("/cursors/0/extra")
    );
    // A query-string field.
    let r = srv
        .send(R::get("/v1/deletions?from=0&x=1").auth(&admin))
        .await;
    assert_eq!(
        r.expect_err(400, ErrorCode::UnknownField).field.as_deref(),
        Some("x")
    );
    // Malformed JSON, and a body that is not the schema.
    srv.send(
        R::post("/v1/pull")
            .auth(&admin)
            .raw(b"{\"cursors\":".to_vec()),
    )
    .await
    .expect_err(400, ErrorCode::Malformed);
    srv.send(
        R::post("/v1/pull")
            .auth(&admin)
            .json(&json!({"cursors": 5, "limit": 1})),
    )
    .await
    .expect_err(400, ErrorCode::Malformed);
    srv.send(R::get("/v1/deletions").auth(&admin))
        .await
        .expect_err(400, ErrorCode::Malformed);
    // Content-Encoding other than identity.
    srv.send(
        R::post("/v1/pull")
            .auth(&admin)
            .header("content-encoding", "gzip")
            .json(&json!({"cursors": [], "limit": 1})),
    )
    .await
    .expect_err(400, ErrorCode::Malformed);
    // A bad handle is `invalid_value /handle`.
    let r = srv
        .send(
            R::post("/v1/invites")
                .auth(&admin)
                .json(&json!({"kind": "member", "handle": "Not OK", "role": "member"})),
        )
        .await;
    assert_eq!(
        r.expect_err(400, ErrorCode::InvalidValue).field.as_deref(),
        Some("/handle")
    );
    // Unknown paths and wrong methods are 404 `not_found`; a path id that is not an id too.
    srv.send(R::get("/v2/info"))
        .await
        .expect_err(404, ErrorCode::NotFound);
    srv.send(R::delete("/v1/status").auth(&admin))
        .await
        .expect_err(404, ErrorCode::NotFound);
    srv.send(R::post("/v1/devices/not-an-id/revoke").auth(&admin))
        .await
        .expect_err(404, ErrorCode::NotFound);
}

// ---------------------------------------------------------------------------------------------
// Limits (§4.3.5; every row)

#[tokio::test]
async fn a_blob_above_16_kib_is_413_and_a_malformed_envelope_422() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    // 16,169 bytes (21,559 characters) is the largest valid envelope.
    assert_eq!(
        srv.push(&admin, vec![item("rec", 0, Id::new_v4(), 0, LARGEST, 5)])
            .await
            .status,
        200
    );
    // 16,385 bytes: 413 `blob` with the item's position.
    let e = srv
        .push(
            &admin,
            vec![
                item("rec", 1, Id::new_v4(), 0, SMALL, 5),
                item("rec", 2, Id::new_v4(), 0, 16_385, 5),
            ],
        )
        .await
        .expect_err(413, ErrorCode::TooLarge);
    assert_eq!(
        (e.limit.as_deref(), e.max, e.item),
        (Some("blob"), Some(16_384), Some(1))
    );
    // 16,170 to 16,384 bytes: within the blob limit, not an envelope length: 422.
    let e = srv
        .push(&admin, vec![item("rec", 1, Id::new_v4(), 0, 16_384, 5)])
        .await
        .expect_err(422, ErrorCode::BadEnvelope);
    assert_eq!(e.item, Some(0));
    // The version byte, and the length.
    let mut bad = item("rec", 1, Id::new_v4(), 0, SMALL, 5);
    bad["blob"] = json!(b64(&{
        let mut v = blob_bytes(SMALL, 5);
        v[0] = 2;
        v
    }));
    srv.push(&admin, vec![bad])
        .await
        .expect_err(422, ErrorCode::BadEnvelope);
    srv.push(&admin, vec![item("rec", 1, Id::new_v4(), 0, 296, 5)])
        .await
        .expect_err(422, ErrorCode::BadEnvelope);
    // Nothing of a failed request is stored.
    let s = srv.send(R::get("/v1/status").auth(&admin)).await.json();
    assert_eq!(s["streams"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_batch_above_100_records_or_1_5_mib_and_a_body_above_2_mib_are_413() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let e = srv
        .push(&admin, srv.items("rec", 0, 101, 0, SMALL))
        .await
        .expect_err(413, ErrorCode::TooLarge);
    assert_eq!(
        (e.limit.as_deref(), e.max),
        (Some("batch_records"), Some(100))
    );
    let r = srv.push(&admin, vec![]).await;
    assert_eq!(
        r.expect_err(400, ErrorCode::InvalidValue).field.as_deref(),
        Some("/records")
    );
    // 100 smallest envelopes fit.
    assert_eq!(
        srv.push(&admin, srv.items("rec", 0, 100, 0, SMALL))
            .await
            .status,
        200
    );

    // 80 envelopes of 16,169 bytes: 1.7 MB encoded, above 1.5 MiB and below 2 MiB.
    let big =
        serde_json::to_vec(&json!({"records": srv.items("rec", 100, 80, 0, LARGEST)})).unwrap();
    assert!(
        big.len() > 1_572_864 && big.len() < 2_097_152,
        "{}",
        big.len()
    );
    // By Content-Length (refused unread) and without it (read, then measured).
    for with_len in [true, false] {
        let mut r = R::post("/v1/records").auth(&admin).raw(big.clone());
        if with_len {
            r = r.with_length();
        }
        let e = srv.send(r).await.expect_err(413, ErrorCode::TooLarge);
        assert_eq!(
            (e.limit.as_deref(), e.max),
            (Some("batch_bytes"), Some(1_572_864))
        );
    }
    // 1.5 MiB exactly is not above the limit: the body is read and then fails as JSON padding
    // does not, so use a valid batch just under it.
    let under =
        serde_json::to_vec(&json!({"records": srv.items("rec", 100, 72, 0, LARGEST)})).unwrap();
    assert!(under.len() <= 1_572_864, "{}", under.len());
    assert_eq!(
        srv.send(R::post("/v1/records").auth(&admin).raw(under).with_length())
            .await
            .status,
        200
    );

    // Any request body above 2 MiB: 413 `body`, on any endpoint, with or without the header.
    let huge = vec![b' '; 2_097_152 + 1];
    for path in ["/v1/pull", "/v1/delete", "/v1/records"] {
        for with_len in [true, false] {
            let mut r = R::post(path).auth(&admin).raw(huge.clone());
            if with_len {
                r = r.with_length();
            }
            let e = srv.send(r).await.expect_err(413, ErrorCode::TooLarge);
            assert_eq!(
                (e.limit.as_deref(), e.max),
                (Some("body"), Some(2_097_152)),
                "{path}"
            );
        }
    }
}

#[tokio::test]
async fn pull_pages_are_limited_and_a_response_is_cut_before_8_mib() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let cursor = |tag: &str, from: u64| json!({"member": admin.member.to_string(), "device": admin.device.to_string(), "tag": tag, "from": from});
    // Limits on the request.
    for limit in [0, 501] {
        let r = srv
            .send(
                R::post("/v1/pull")
                    .auth(&admin)
                    .json(&json!({"cursors": [cursor("rec", 0)], "limit": limit})),
            )
            .await;
        assert_eq!(
            r.expect_err(400, ErrorCode::InvalidValue).field.as_deref(),
            Some("/limit")
        );
    }
    for q in ["limit=0", "limit=501"] {
        let r = srv
            .send(
                R::get(&format!(
                    "/v1/records?member={}&device={}&tag=rec&from=0&{q}",
                    admin.member, admin.device
                ))
                .auth(&admin),
            )
            .await;
        assert_eq!(
            r.expect_err(400, ErrorCode::InvalidValue).field.as_deref(),
            Some("limit")
        );
    }
    for q in ["limit=0", "limit=5001"] {
        srv.send(R::get(&format!("/v1/deletions?from=0&{q}")).auth(&admin))
            .await
            .expect_err(400, ErrorCode::InvalidValue);
    }
    srv.send(R::get("/v1/audit?from=0&limit=1001").auth(&admin))
        .await
        .expect_err(400, ErrorCode::InvalidValue);
    assert_eq!(
        srv.send(R::get("/v1/audit?from=0&limit=1000").auth(&admin))
            .await
            .status,
        200
    );
    assert_eq!(
        srv.send(R::get("/v1/deletions?from=0&limit=5000").auth(&admin))
            .await
            .status,
        200
    );
    // Cursors: none, duplicates, above 1,000.
    let r = srv
        .send(
            R::post("/v1/pull")
                .auth(&admin)
                .json(&json!({"cursors": [], "limit": 5})),
        )
        .await;
    assert_eq!(
        r.expect_err(400, ErrorCode::InvalidValue).field.as_deref(),
        Some("/cursors")
    );
    let r = srv
        .send(
            R::post("/v1/pull")
                .auth(&admin)
                .json(&json!({"cursors": [cursor("rec", 0), cursor("rec", 3)], "limit": 5})),
        )
        .await;
    assert_eq!(
        r.expect_err(400, ErrorCode::InvalidValue).field.as_deref(),
        Some("/cursors")
    );
    let many: Vec<Value> = (0..1001)
        .map(|i| json!({"member": Id::new_v4().to_string(), "device": Id::new_v4().to_string(), "tag": "rec", "from": i}))
        .collect();
    let e = srv
        .send(
            R::post("/v1/pull")
                .auth(&admin)
                .json(&json!({"cursors": many, "limit": 5})),
        )
        .await
        .expect_err(413, ErrorCode::TooLarge);
    assert_eq!(
        (e.limit.as_deref(), e.max),
        (Some("pull_cursors"), Some(1000))
    );
    // 1,000 cursors are served.
    let ok: Vec<Value> = many.into_iter().take(1000).collect();
    assert_eq!(
        srv.send(
            R::post("/v1/pull")
                .auth(&admin)
                .json(&json!({"cursors": ok, "limit": 5}))
        )
        .await
        .status,
        200
    );

    // 460 records of 16,169 bytes (about 21.6 KB each encoded): over 8 MiB in total.
    let mut idx = 0;
    while idx < 460 {
        let n = 70.min(460 - idx);
        let r = srv.push(&admin, srv.items("rec", idx, n, 0, LARGEST)).await;
        assert_eq!(r.status, 200, "{}", r.text());
        idx += n;
        srv.advance(1);
    }
    let r = srv
        .send(
            R::post("/v1/pull")
                .auth(&admin)
                .json(&json!({"cursors": [cursor("rec", 0)], "limit": 500})),
        )
        .await;
    assert_eq!(r.status, 200);
    assert!(r.body.len() <= 8_388_608, "{} bytes", r.body.len());
    let v = r.json();
    let got = v["streams"][0]["records"].as_array().unwrap().len();
    assert!(got > 300 && got < 460, "{got} records");
    assert_eq!(v["more"], true);
    assert_eq!(v["streams"][0]["head"], 459);
    // The same through GET /v1/records.
    let r = srv
        .send(
            R::get(&format!(
                "/v1/records?member={}&device={}&tag=rec&from=0&limit=500",
                admin.member, admin.device
            ))
            .auth(&admin),
        )
        .await;
    assert!(r.body.len() <= 8_388_608);
    assert!(r.json()["records"].as_array().unwrap().len() < 460);
}

#[tokio::test]
async fn delete_ids_above_1000_are_413() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let ids = |n: usize| (0..n).map(|_| Id::new_v4().to_string()).collect::<Vec<_>>();
    let e = srv
        .send(
            R::post("/v1/delete")
                .auth(&admin)
                .json(&json!({"ids": ids(1001)})),
        )
        .await
        .expect_err(413, ErrorCode::TooLarge);
    assert_eq!(
        (e.limit.as_deref(), e.max),
        (Some("delete_ids"), Some(1000))
    );
    let r = srv
        .send(
            R::post("/v1/delete")
                .auth(&admin)
                .json(&json!({"ids": ids(1000)})),
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"deleted": 1000, "already": 0}));
    // Ids, `all_mine` and `member` are exclusive, and `ids` is not empty.
    for body in [
        json!({"ids": []}),
        json!({"ids": ids(1), "all_mine": true}),
        json!({}),
    ] {
        srv.send(R::post("/v1/delete").auth(&admin).json(&body))
            .await
            .expect_err(400, ErrorCode::Malformed);
    }
}

#[tokio::test]
async fn more_than_5000_records_a_day_is_429_with_retry_after_markers_and_a_new_generation_exempt()
{
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    // One pre-deletion (an id the server has never seen) counts like a record (RVT2 M1).
    let in_flight = Id::new_v4();
    let r = srv
        .send(
            R::post("/v1/delete")
                .auth(&roy)
                .json(&json!({"ids": [in_flight.to_string()]})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    for b in 0..50u64 {
        let n = if b == 49 { 99 } else { 100 };
        let r = srv.push(&roy, srv.items("rec", b * 100, n, 0, SMALL)).await;
        assert_eq!(r.status, 200, "batch {b}: {}", r.text());
        // 60 requests a minute: stay inside the token limit.
        srv.advance(1);
    }
    let now = srv.now();
    let r = srv.push(&roy, srv.items("rec", 4999, 1, 0, SMALL)).await;
    let e = r.expect_err(429, ErrorCode::RateLimited);
    assert_eq!(e.limit.as_deref(), Some("records_per_day"));
    let until_midnight = (now - now.rem_euclid(DAY) + DAY - now) as u32;
    assert_eq!(e.retry_after_s, Some(until_midnight));
    assert_eq!(r.header("retry-after"), Some(until_midnight.to_string()));
    // A marker for an id the server knows (the pre-deleted one, filling its index) does not
    // count; a marker with a new id would add a deletion entry, so it counts (RVT2 M1).
    let r = srv.push(&roy, vec![marker("rec", 4999, in_flight)]).await;
    assert_eq!(r.status, 200, "{}", r.text());
    srv.push(&roy, vec![marker("rec", 5000, Id::new_v4())])
        .await
        .expect_err(429, ErrorCode::RateLimited);
    // The quota is per member: another member is not affected.
    assert_eq!(
        srv.push(&admin, srv.items("rec", 0, 1, 0, SMALL))
            .await
            .status,
        200
    );
    // The next UTC day starts again.
    srv.advance(until_midnight as i64 + 1);
    assert_eq!(
        srv.push(&roy, srv.items("rec", 5000, 1, 0, SMALL))
            .await
            .status,
        200
    );

    // A new generation: pushes of the next 24 hours do not count (an admin may push meanwhile).
    for b in 0..50u64 {
        let r = srv
            .push(&admin, srv.items("rec", 1 + b * 100, 100, 0, SMALL))
            .await;
        assert_eq!(r.status, 200, "batch {b}: {}", r.text());
        srv.advance(1);
    }
    srv.push(&admin, srv.items("rec", 5001, 1, 0, SMALL))
        .await
        .expect_err(429, ErrorCode::RateLimited);
    srv.store.renew_generation(srv.now()).await.unwrap();
    let r = srv.push(&admin, srv.items("rec", 5001, 1, 0, SMALL)).await;
    assert_eq!(r.status, 200, "inside the re-seed window: {}", r.text());
    srv.advance(DAY - 5);
    let r = srv.push(&admin, srv.items("rec", 5002, 1, 0, SMALL)).await;
    assert_eq!(r.status, 200, "{}", r.text());
}

#[tokio::test]
async fn requests_per_token_are_60_a_minute_with_a_burst_of_120() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    srv.advance(3_600); // refill what setup used
    for i in 0..120 {
        let r = srv.send(R::get("/v1/status").auth(&roy)).await;
        assert_eq!(r.status, 200, "request {i}");
    }
    let r = srv.send(R::get("/v1/status").auth(&roy)).await;
    let e = r.expect_err(429, ErrorCode::RateLimited);
    assert_eq!(e.retry_after_s, Some(1));
    assert_eq!(r.header("retry-after").as_deref(), Some("1"));
    // Another token has its own budget.
    assert_eq!(
        srv.send(R::get("/v1/status").auth(&admin)).await.status,
        200
    );
    // One token a second.
    srv.advance(1);
    assert_eq!(srv.send(R::get("/v1/status").auth(&roy)).await.status, 200);
    srv.send(R::get("/v1/status").auth(&roy))
        .await
        .expect_err(429, ErrorCode::RateLimited);
    srv.advance(60);
    assert_eq!(srv.send(R::get("/v1/status").auth(&roy)).await.status, 200);
}

#[tokio::test]
async fn unauthenticated_requests_are_30_a_minute_per_address_and_joins_10_an_hour() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    for i in 0..30 {
        assert_eq!(
            srv.send(R::get("/v1/info").no_client().from("203.0.113.1"))
                .await
                .status,
            200,
            "{i}"
        );
    }
    let r = srv
        .send(R::get("/v1/info").no_client().from("203.0.113.1"))
        .await;
    let e = r.expect_err(429, ErrorCode::RateLimited);
    assert_eq!(
        r.header("retry-after"),
        e.retry_after_s.map(|s| s.to_string())
    );
    assert!(e.retry_after_s.unwrap() >= 1);
    // Another address, and an unauthenticated 401 is counted too.
    assert_eq!(
        srv.send(R::get("/v1/info").no_client().from("203.0.113.2"))
            .await
            .status,
        200
    );
    for _ in 0..30 {
        srv.send(R::get("/v1/status").from("203.0.113.3"))
            .await
            .expect_err(401, ErrorCode::Unauthenticated);
    }
    srv.send(R::get("/v1/status").from("203.0.113.3"))
        .await
        .expect_err(429, ErrorCode::RateLimited);
    // Failed tokens count against the address too; valid tokens from it do not.
    for _ in 0..30 {
        srv.send(R::get("/v1/status").bearer("awm_t_x").from("203.0.113.4"))
            .await;
    }
    srv.send(R::get("/v1/status").bearer("awm_t_x").from("203.0.113.4"))
        .await
        .expect_err(429, ErrorCode::RateLimited);
    assert_eq!(
        srv.send(R::get("/v1/status").auth(&admin).from("203.0.113.4"))
            .await
            .status,
        200
    );
    // A minute later the address has its 30 again.
    srv.advance(60);
    assert_eq!(
        srv.send(R::get("/v1/info").no_client().from("203.0.113.1"))
            .await
            .status,
        200
    );

    // Joins: 10 an hour per address (the unknown invites are 410 each).
    let join = |ip: &str| {
        R::post("/v1/join").from(ip).json(&json!({
            "invite_id": Id::new_v4().to_string(),
            "invite_token": format!("awm_i_{}_{}", admin.org, "B".repeat(42) + "A"),
            "handle": "kit", "device_id": Id::new_v4().to_string(),
            "device_pubkey": b64(&[1u8; 32]), "join_mac": b64(&[1u8; 32]),
        }))
    };
    for i in 0..10 {
        srv.send(join("198.51.100.9"))
            .await
            .expect_err(410, ErrorCode::InviteGone);
        if i % 5 == 4 {
            srv.advance(60); // keep the 30-a-minute budget out of it
        }
    }
    let r = srv.send(join("198.51.100.9")).await;
    let e = r.expect_err(429, ErrorCode::RateLimited);
    assert!(e.retry_after_s.unwrap() > 60, "{:?}", e.retry_after_s);
    srv.send(join("198.51.100.10"))
        .await
        .expect_err(410, ErrorCode::InviteGone);
    srv.advance(3_600);
    srv.send(join("198.51.100.9"))
        .await
        .expect_err(410, ErrorCode::InviteGone);
}

#[tokio::test]
async fn an_ipv6_client_is_limited_on_its_64_not_on_each_address() {
    // RVT2 m5: rotating addresses inside one /64 gives no new budget.
    let srv = Srv::new();
    for i in 0..30u32 {
        let ip = format!("2001:db8:1:2::{:x}", i + 1);
        assert_eq!(
            srv.send(R::get("/v1/info").no_client().from(&ip))
                .await
                .status,
            200,
            "{ip}"
        );
    }
    srv.send(R::get("/v1/info").no_client().from("2001:db8:1:2:ffff::9"))
        .await
        .expect_err(429, ErrorCode::RateLimited);
    // Another /64 has its own budget; a v4-mapped address shares its IPv4 address's.
    assert_eq!(
        srv.send(R::get("/v1/info").no_client().from("2001:db8:1:3::1"))
            .await
            .status,
        200
    );
    for _ in 0..30 {
        srv.send(R::get("/v1/info").no_client().from("198.51.100.77"))
            .await;
    }
    srv.send(R::get("/v1/info").no_client().from("::ffff:198.51.100.77"))
        .await
        .expect_err(429, ErrorCode::RateLimited);
}

#[tokio::test]
async fn a_bad_token_with_a_bad_body_is_401_and_counted_until_the_address_gets_429() {
    // RVT2 B1: the token is checked before the body is read, so a malformed body does not skip
    // the failed-token budget of the address (30 a minute).
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let well_formed = format!("awm_t_{}_{}", admin.org, "B".repeat(42) + "A");
    for (n, token) in [(0u8, well_formed.as_str()), (1, "awm_t_x")] {
        let ip = format!("203.0.113.{}", 20 + n);
        let bad = |path: &str| {
            R::post(path)
                .bearer(token)
                .from(&ip)
                .raw(b"{not json".to_vec())
        };
        for i in 0..30 {
            let path = ["/v1/records", "/v1/delete", "/v1/pull"][i % 3];
            srv.send(bad(path))
                .await
                .expect_err(401, ErrorCode::Unauthenticated);
        }
        for path in ["/v1/records", "/v1/delete", "/v1/pull", "/v1/invites"] {
            let r = srv.send(bad(path)).await;
            let e = r.expect_err(429, ErrorCode::RateLimited);
            assert!(e.retry_after_s.unwrap() >= 1, "{path}");
        }
        // A valid token from the address still gets through, and its malformed body is 400.
        srv.send(
            R::post("/v1/records")
                .auth(&admin)
                .from(&ip)
                .raw(b"{".to_vec()),
        )
        .await
        .expect_err(400, ErrorCode::Malformed);
    }
}

#[tokio::test]
async fn pre_deletions_and_new_id_markers_count_against_the_daily_quota() {
    // RVT2 M1: ids the server has never seen add deletion entries like records add rows.
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    let fresh = |n: usize| -> Vec<String> { (0..n).map(|_| Id::new_v4().to_string()).collect() };
    let delete =
        |who: &Who, ids: Vec<String>| R::post("/v1/delete").auth(who).json(&json!({ "ids": ids }));
    let mut codes = Vec::new();
    for _ in 0..7 {
        let r = srv.send(delete(&roy, fresh(1_000))).await;
        if r.status == 429 {
            let e = r.expect_err(429, ErrorCode::RateLimited);
            assert_eq!(e.limit.as_deref(), Some("records_per_day"));
            let now = srv.now();
            assert_eq!(e.retry_after_s, Some((DAY - now.rem_euclid(DAY)) as u32));
        }
        codes.push(r.status);
        srv.advance(1);
    }
    assert_eq!(codes, [200, 200, 200, 200, 200, 429, 429]);
    // The quota is full: a record and a marker with a new id are refused too.
    srv.push(&roy, srv.items("rec", 0, 1, 0, SMALL))
        .await
        .expect_err(429, ErrorCode::RateLimited);
    srv.push(&roy, vec![marker("rec", 0, Id::new_v4())])
        .await
        .expect_err(429, ErrorCode::RateLimited);
    // A refused batch deleted nothing: the deletion stream holds the 5,000 accepted ids.
    assert_eq!(srv.store.deletion_heads().await.unwrap().head, 4_999);

    // Deleting records the server holds is not counted: kit fills the quota with 100 records
    // and 4,900 pre-deletions, then still deletes its own records.
    let kit = srv.add_member(&admin, "kit", "member").await;
    let held = srv.items("rec", 0, 100, 0, SMALL);
    let held_ids: Vec<String> = held
        .iter()
        .map(|v| v["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(srv.push(&kit, held).await.status, 200);
    for n in [1_000, 1_000, 1_000, 1_000, 900] {
        let r = srv.send(delete(&kit, fresh(n))).await;
        assert_eq!(r.status, 200, "{}", r.text());
        srv.advance(1);
    }
    srv.send(delete(&kit, fresh(1)))
        .await
        .expect_err(429, ErrorCode::RateLimited);
    let r = srv.send(delete(&kit, held_ids)).await;
    assert_eq!(r.status, 200, "{}", r.text());
    // The next UTC day starts again.
    srv.advance(DAY);
    assert_eq!(srv.send(delete(&roy, fresh(1))).await.status, 200);
}

#[tokio::test]
async fn a_pending_device_sees_nothing_of_others_in_its_status_and_an_approved_one_sees_all() {
    // RVT2 M2: a leaked invite lets its holder join, but not read who is in the team, what
    // they pushed, or which other devices wait.
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    assert_eq!(
        srv.push(&roy, srv.items("rec", 0, 3, 0, SMALL))
            .await
            .status,
        200
    );
    let gone = srv.items("rec", 3, 1, 0, SMALL);
    let gone_id = gone[0]["id"].as_str().unwrap().to_string();
    assert_eq!(srv.push(&roy, gone).await.status, 200);
    let r = srv
        .send(
            R::post("/v1/delete")
                .auth(&roy)
                .json(&json!({"ids": [gone_id]})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let kit = srv.join_pending(&admin, "kit", 6).await;
    let other = srv.join_pending(&admin, "mia", 7).await;

    let full = srv.send(R::get("/v1/status").auth(&admin)).await.json();
    assert_eq!(full["streams"].as_array().unwrap().len(), 1, "{full}");
    assert_eq!(full["pending"].as_array().unwrap().len(), 2, "{full}");
    assert_eq!(full["deletions"]["head"], 0);

    let r = srv.send(R::get("/v1/status").auth(&kit)).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let p = r.json();
    assert_eq!(p["approved"], false);
    assert_eq!(p["device_id"], kit.device.to_string());
    assert_eq!(p["member_id"], kit.member.to_string());
    assert_eq!(p["generation"], full["generation"]);
    assert_eq!(p["current_epoch"], full["current_epoch"]);
    assert_eq!(p["settings"]["min_client"], full["settings"]["min_client"]);
    assert_eq!(p["streams"], json!([]));
    assert_eq!(p["deletions"]["head"], -1);
    assert_eq!(p["settings"]["max_members"], 0);
    assert_eq!(p["rotation_needed"], false);
    let pending = p["pending"].as_array().unwrap();
    assert_eq!(pending.len(), 1, "{p}");
    assert_eq!(pending[0]["device_id"], kit.device.to_string());
    let text = r.text();
    for hidden in [
        roy.member.to_string(),
        roy.device.to_string(),
        other.device.to_string(),
        other.member.to_string(),
    ] {
        assert!(!text.contains(&hidden), "{hidden} in {text}");
    }
    // Same schema: the same fields, with empty or neutral values.
    let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(keys(&p), keys(&full));
    assert_eq!(keys(&p["settings"]), keys(&full["settings"]));

    // Approved, the same device sees the full status.
    srv.approve(&admin, &kit).await;
    let a = srv.send(R::get("/v1/status").auth(&kit)).await.json();
    assert_eq!(a["approved"], true);
    assert_eq!(a["streams"], full["streams"]);
    assert_eq!(a["deletions"], full["deletions"]);
    assert_eq!(a["settings"], full["settings"]);
}

impl Srv {
    /// A new member whose one device joined and waits for approval.
    async fn join_pending(&self, admin: &Who, handle: &str, seed: u8) -> Who {
        let inv = self
            .send(
                R::post("/v1/invites")
                    .auth(admin)
                    .json(&json!({"kind": "member", "handle": handle, "role": "member"})),
            )
            .await
            .json();
        let device = Id::new_v4();
        let j = self
            .send(R::post("/v1/join").json(&json!({
                "invite_id": inv["invite_id"], "invite_token": inv["invite_token"],
                "handle": handle, "device_id": device.to_string(),
                "device_pubkey": b64(&[seed; 32]), "join_mac": b64(&[seed; 32]),
            })))
            .await
            .json();
        Who {
            token: j["device_token"].as_str().unwrap().to_string(),
            member: Id::parse(j["member_id"].as_str().unwrap()).unwrap(),
            device,
            org: admin.org,
        }
    }

    async fn refusals_of(&self, who: &Who) -> usize {
        let audit = self.store.audit(0, 100_000).await.unwrap();
        audit
            .rows
            .iter()
            .filter(|r| {
                r.action == "authz.refused" && r.target.as_deref() == Some(&*who.device.to_string())
            })
            .count()
    }
}

#[tokio::test]
async fn a_pending_device_polling_adds_one_refusal_row_an_hour_not_one_a_request() {
    // RVT2 m1: a pending device that polls must not grow the audit log without bound.
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let kit = srv.join_pending(&admin, "kit", 6).await;
    for _ in 0..50 {
        srv.send(R::get("/v1/members").auth(&kit))
            .await
            .expect_err(403, ErrorCode::NotApproved);
        srv.advance(1);
    }
    assert_eq!(srv.refusals_of(&kit).await, 1);
    // Another pending device has its own row.
    let mia = srv.join_pending(&admin, "mia", 7).await;
    srv.send(R::get("/v1/members").auth(&mia))
        .await
        .expect_err(403, ErrorCode::NotApproved);
    assert_eq!(srv.refusals_of(&mia).await, 1);
    // An hour later, one more.
    srv.advance(3_600);
    for _ in 0..5 {
        srv.send(R::get("/v1/members").auth(&kit))
            .await
            .expect_err(403, ErrorCode::NotApproved);
    }
    assert_eq!(srv.refusals_of(&kit).await, 2);
    // An approved member's refusals are still audited one by one.
    let roy = srv.add_member(&admin, "roy", "member").await;
    for _ in 0..3 {
        srv.send(R::get("/v1/audit?from=0").auth(&roy))
            .await
            .expect_err(403, ErrorCode::Forbidden);
    }
    assert_eq!(srv.refusals_of(&roy).await, 3);
}

#[tokio::test]
async fn delete_by_all_mine_or_member_is_one_an_hour_per_token() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    assert_eq!(
        srv.send(
            R::post("/v1/delete")
                .auth(&roy)
                .json(&json!({"all_mine": true}))
        )
        .await
        .status,
        200
    );
    let r = srv
        .send(
            R::post("/v1/delete")
                .auth(&roy)
                .json(&json!({"all_mine": true})),
        )
        .await;
    let e = r.expect_err(429, ErrorCode::RateLimited);
    assert!(e.retry_after_s.unwrap() > 3_500);
    assert_eq!(
        r.header("retry-after"),
        e.retry_after_s.map(|s| s.to_string())
    );
    // By ids is not limited; the admin's token has its own hour.
    for _ in 0..3 {
        let r = srv
            .send(
                R::post("/v1/delete")
                    .auth(&roy)
                    .json(&json!({"ids": [Id::new_v4().to_string()]})),
            )
            .await;
        assert_eq!(r.status, 200);
    }
    assert_eq!(
        srv.send(
            R::post("/v1/delete")
                .auth(&admin)
                .json(&json!({"member": roy.member.to_string()}))
        )
        .await
        .status,
        200
    );
    srv.send(
        R::post("/v1/delete")
            .auth(&admin)
            .json(&json!({"member": roy.member.to_string()})),
    )
    .await
    .expect_err(429, ErrorCode::RateLimited);
    srv.advance(3_601);
    assert_eq!(
        srv.send(
            R::post("/v1/delete")
                .auth(&roy)
                .json(&json!({"all_mine": true}))
        )
        .await
        .status,
        200
    );
}

#[tokio::test]
async fn the_forwarded_address_counts_only_behind_a_trusted_proxy() {
    // Not trusted: X-Forwarded-For is ignored, so every client is the peer.
    let srv = Srv::new();
    for i in 0..30 {
        let r = srv
            .send(
                R::get("/v1/info")
                    .no_client()
                    .from("10.1.1.1")
                    .header("x-forwarded-for", &format!("198.51.100.{i}")),
            )
            .await;
        assert_eq!(r.status, 200);
    }
    srv.send(
        R::get("/v1/info")
            .no_client()
            .from("10.1.1.1")
            .header("x-forwarded-for", "198.51.100.99"),
    )
    .await
    .expect_err(429, ErrorCode::RateLimited);

    // Trusted: each forwarded client has its own budget, the proxy itself none.
    let srv = Srv::with(|c| c.trusted_proxies = vec!["10.0.0.0/8".parse::<IpNet>().unwrap()]);
    for _ in 0..30 {
        let r = srv
            .send(
                R::get("/v1/info")
                    .no_client()
                    .from("10.1.1.1")
                    .header("x-forwarded-for", "198.51.100.7"),
            )
            .await;
        assert_eq!(r.status, 200);
    }
    srv.send(
        R::get("/v1/info")
            .no_client()
            .from("10.1.1.1")
            .header("x-forwarded-for", "198.51.100.7"),
    )
    .await
    .expect_err(429, ErrorCode::RateLimited);
    let r = srv
        .send(
            R::get("/v1/info")
                .no_client()
                .from("10.1.1.1")
                .header("x-forwarded-for", "198.51.100.8"),
        )
        .await;
    assert_eq!(r.status, 200);
    // A peer outside the trusted range cannot choose its address.
    for i in 0..30 {
        srv.send(
            R::get("/v1/info")
                .no_client()
                .from("203.0.113.50")
                .header("x-forwarded-for", &format!("198.51.100.{i}")),
        )
        .await;
    }
    srv.send(
        R::get("/v1/info")
            .no_client()
            .from("203.0.113.50")
            .header("x-forwarded-for", "198.51.100.200"),
    )
    .await
    .expect_err(429, ErrorCode::RateLimited);
    // The log line carries the client address.
    assert!(srv
        .log_lines()
        .iter()
        .any(|l| l.contains("ip=198.51.100.7")));
}

// ---------------------------------------------------------------------------------------------
// 426 and the Awm-Client header

async fn raise_min_client(srv: &Srv, admin: &Who, v: &str) {
    let r = srv
        .send(
            R::put("/v1/org/settings")
                .auth(admin)
                .json(&json!({"min_client": v})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
}

#[tokio::test]
async fn a_client_below_min_client_gets_426_on_records_join_and_bootstrap_only() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    raise_min_client(&srv, &admin, "0.2.1").await;
    let old = "awm/0.2.0 proto/1 redact/3";
    let pre = "awm/0.2.1-rc.1 proto/1 redact/3 os/macos";
    let new = "awm/0.2.1 proto/1 redact/3";

    // POST /v1/records with a record: 426 with `min_client`.
    let push = |who: &Who, client: &str, items: Vec<Value>| {
        R::post("/v1/records")
            .auth(who)
            .client(client)
            .json(&json!({"records": items}))
    };
    let r = srv
        .send(push(
            &roy,
            old,
            vec![item("rec", 0, Id::new_v4(), 0, SMALL, 5)],
        ))
        .await;
    let e = r.expect_err(426, ErrorCode::ClientTooOld);
    assert_eq!(e.min_client, Some(Version::parse("0.2.1").unwrap()));
    // A pre-release sorts below its release.
    srv.send(push(
        &roy,
        pre,
        vec![item("rec", 0, Id::new_v4(), 0, SMALL, 5)],
    ))
    .await
    .expect_err(426, ErrorCode::ClientTooOld);
    // A mixed batch (a roster item and a record) is gated.
    srv.send(push(
        &roy,
        old,
        vec![
            item("roster", 0, Id::new_v4(), 0, SMALL, 5),
            item("rec", 0, Id::new_v4(), 0, SMALL, 5),
        ],
    ))
    .await
    .expect_err(426, ErrorCode::ClientTooOld);
    // Roster items and markers only: not gated (RVT1 m5).
    let r = srv
        .send(push(
            &roy,
            old,
            vec![item("roster", 0, Id::new_v4(), 0, SMALL, 5)],
        ))
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let r = srv
        .send(push(&roy, old, vec![marker("rec", 0, Id::new_v4())]))
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let r = srv
        .send(push(
            &roy,
            old,
            vec![
                marker("rec", 1, Id::new_v4()),
                item("roster", 1, Id::new_v4(), 0, SMALL, 5),
            ],
        ))
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    // The current client passes.
    assert_eq!(
        srv.send(push(
            &roy,
            new,
            vec![item("rec", 2, Id::new_v4(), 0, SMALL, 5)]
        ))
        .await
        .status,
        200
    );

    // POST /v1/join: gated against the organisation's min_client.
    let inv = srv
        .send(
            R::post("/v1/invites")
                .auth(&admin)
                .json(&json!({"kind": "member", "handle": "kit", "role": "member"})),
        )
        .await
        .json();
    let join = |client: &str| {
        R::post("/v1/join").client(client).json(&json!({
            "invite_id": inv["invite_id"], "invite_token": inv["invite_token"], "handle": "kit",
            "device_id": Id::new_v4().to_string(), "device_pubkey": b64(&[4u8; 32]), "join_mac": b64(&[5u8; 32]),
        }))
    };
    srv.send(join(old))
        .await
        .expect_err(426, ErrorCode::ClientTooOld);
    assert_eq!(srv.send(join(new)).await.status, 200);

    // Everything else continues for the old client.
    for r in [
        srv.send(R::get("/v1/status").auth(&roy).client(old)).await,
        srv.send(R::get("/v1/members").auth(&roy).client(old)).await,
        srv.send(R::get("/v1/keys").auth(&roy).client(old)).await,
        srv.send(
            R::post("/v1/pull")
                .auth(&roy)
                .client(old)
                .json(&json!({"cursors": [], "limit": 1})),
        )
        .await
        .into_ok_or_invalid(),
        srv.send(R::get("/v1/deletions?from=0").auth(&roy).client(old))
            .await,
        srv.send(
            R::post("/v1/delete")
                .auth(&roy)
                .client(old)
                .json(&json!({"ids": [Id::new_v4().to_string()]})),
        )
        .await,
        srv.send(R::get("/v1/org/settings").auth(&roy).client(old))
            .await,
        srv.send(R::get("/v1/audit?from=0").auth(&admin).client(old))
            .await,
        srv.send(R::post("/v1/token/rotate").auth(&roy).client(old))
            .await,
        srv.send(
            R::post(&format!("/v1/devices/{}/revoke", roy.device))
                .auth(&roy)
                .client(old),
        )
        .await,
    ] {
        assert!(r.status != 426, "{}", r.text());
        assert!(
            r.status < 300 || r.status == 401,
            "{}: {}",
            r.status,
            r.text()
        );
    }
}

impl Resp {
    /// A pull with no cursors is 400 `invalid_value`: not a 426, which is what the test asks.
    fn into_ok_or_invalid(self) -> Resp {
        assert_eq!(self.status, 400);
        Resp {
            status: 200,
            headers: self.headers,
            body: self.body,
        }
    }
}

#[tokio::test]
async fn bootstrap_is_gated_by_the_release_floor() {
    let srv = Srv::new();
    let bt = auth::issue_bootstrap(&*srv.store, srv.now()).await.unwrap();
    let body = json!({
        "bootstrap_token": bt.as_str(), "org_id": Id::new_v4().to_string(), "handle": "alf",
        "device_id": Id::new_v4().to_string(), "device_pubkey": b64(&[1u8; 32]),
    });
    let e = srv
        .send(
            R::post("/v1/bootstrap")
                .client("awm/0.1.9 proto/1 redact/3")
                .json(&body),
        )
        .await
        .expect_err(426, ErrorCode::ClientTooOld);
    assert_eq!(e.min_client, Some(Version::new(0, 2, 0)));
    assert_eq!(
        srv.send(R::post("/v1/bootstrap").json(&body)).await.status,
        200
    );
}

#[tokio::test]
async fn a_missing_or_malformed_awm_client_header_is_400() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let long = format!("awm/0.2.0 proto/1 redact/3 x/{}", "a".repeat(260));
    for bad in [
        "",
        "awm/0.2.0",
        "awm/0.2 proto/1 redact/3",
        "awm/0.2.0 proto/0 redact/3",
        "awm/0.2.0 redact/3 proto/1",
        "awm/0.2.0+build proto/1 redact/3",
        &long,
    ] {
        let r = srv
            .send(R::get("/v1/status").auth(&admin).client(bad))
            .await;
        r.expect_err(400, ErrorCode::BadClientHeader);
    }
    srv.send(R::get("/v1/status").auth(&admin).no_client())
        .await
        .expect_err(400, ErrorCode::BadClientHeader);
    srv.send(R::post("/v1/join").no_client().json(&json!({})))
        .await
        .expect_err(400, ErrorCode::BadClientHeader);
    // Extension tokens are ignored; `info` does not need the header, but refuses a bad one.
    let r = srv
        .send(
            R::get("/v1/status")
                .auth(&admin)
                .client("awm/0.3.0-rc.1 proto/2 redact/4 os/macos"),
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(srv.send(R::get("/v1/info").no_client()).await.status, 200);
    srv.send(R::get("/v1/info").client("nope"))
        .await
        .expect_err(400, ErrorCode::BadClientHeader);
}

// ---------------------------------------------------------------------------------------------
// The restore gate

#[tokio::test]
async fn while_a_restore_is_pending_non_admin_writes_get_503_and_admin_and_reads_continue() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    let old_gen = srv.send(R::get("/v1/info").no_client()).await.json()["generation"].clone();
    let inv = srv
        .send(
            R::post("/v1/invites")
                .auth(&admin)
                .json(&json!({"kind": "member", "handle": "kit", "role": "member"})),
        )
        .await
        .json();
    let kit_device = Id::new_v4();
    let kit = srv
        .send(R::post("/v1/join").json(&json!({
            "invite_id": inv["invite_id"], "invite_token": inv["invite_token"], "handle": "kit",
            "device_id": kit_device.to_string(), "device_pubkey": b64(&[4u8; 32]), "join_mac": b64(&[5u8; 32]),
        })))
        .await
        .json();
    let gen2 = srv.store.renew_generation(srv.now()).await.unwrap();

    // 503 with `generation` and `Retry-After`, on the four endpoints of §11.
    let check = |r: Resp| {
        let e = r.expect_err(503, ErrorCode::RestorePending);
        assert_eq!(e.generation, Some(gen2));
        assert_eq!(e.retry_after_s, Some(60));
        assert_eq!(r.header("retry-after").as_deref(), Some("60"));
    };
    check(
        srv.push(&roy, vec![item("rec", 0, Id::new_v4(), 0, SMALL, 5)])
            .await,
    );
    check(
        srv.send(
            R::post("/v1/invites")
                .auth(&roy)
                .json(&json!({"kind": "device", "handle": "roy"})),
        )
        .await,
    );
    check(
        srv.send(
            R::post(&format!("/v1/devices/{kit_device}/approve"))
                .auth(&roy)
                .json(&wraps(0)),
        )
        .await,
    );
    check(
        srv.send(R::post("/v1/join").json(&json!({
            "invite_id": Id::new_v4().to_string(), "invite_token": format!("awm_i_{}_{}", admin.org, "C".repeat(42) + "A"),
            "handle": "mia", "device_id": Id::new_v4().to_string(),
            "device_pubkey": b64(&[1u8; 32]), "join_mac": b64(&[1u8; 32]),
        })))
        .await,
    );
    // Reads, deletes, token rotation and revocation continue; a pending device still hits
    // `not_approved`, not 503.
    assert_eq!(srv.send(R::get("/v1/status").auth(&roy)).await.status, 200);
    assert_eq!(srv.send(R::get("/v1/members").auth(&roy)).await.status, 200);
    assert_eq!(
        srv.send(
            R::post("/v1/delete")
                .auth(&roy)
                .json(&json!({"ids": [Id::new_v4().to_string()]}))
        )
        .await
        .status,
        200
    );
    srv.send(
        R::post("/v1/records")
            .bearer(kit["device_token"].as_str().unwrap())
            .json(&json!({"records": [item("rec", 0, Id::new_v4(), 0, SMALL, 5)]})),
    )
    .await
    .expect_err(403, ErrorCode::NotApproved);
    // An admin pushes (its roster revocations and epoch records), invites and approves.
    let r = srv
        .push(&admin, vec![item("roster", 0, Id::new_v4(), 0, SMALL, 5)])
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    srv.approve(
        &admin,
        &Who {
            token: kit["device_token"].as_str().unwrap().to_string(),
            member: Id::parse(kit["member_id"].as_str().unwrap()).unwrap(),
            device: kit_device,
            org: admin.org,
        },
    )
    .await;

    // `info` and `status` carry the generation and the pending flag.
    let info = srv.send(R::get("/v1/info").no_client()).await.json();
    assert_eq!(info["generation"], json!(gen2.to_string()));
    assert_ne!(info["generation"], old_gen);
    let st = srv.send(R::get("/v1/status").auth(&roy)).await.json();
    assert_eq!(st["generation"], json!(gen2.to_string()));
    assert_eq!(st["restore_pending"], true);

    // Completing: a member cannot; another generation is 400; the current one is 204 (twice).
    srv.send(
        R::post("/v1/restore/complete")
            .auth(&roy)
            .json(&json!({"generation": gen2.to_string()})),
    )
    .await
    .expect_err(403, ErrorCode::Forbidden);
    let r = srv
        .send(
            R::post("/v1/restore/complete")
                .auth(&admin)
                .json(&json!({"generation": Id::new_v4().to_string()})),
        )
        .await;
    assert_eq!(
        r.expect_err(400, ErrorCode::InvalidValue).field.as_deref(),
        Some("/generation")
    );
    for _ in 0..2 {
        let r = srv
            .send(
                R::post("/v1/restore/complete")
                    .auth(&admin)
                    .json(&json!({"generation": gen2.to_string()})),
            )
            .await;
        assert_eq!(r.status, 204, "{}", r.text());
    }
    assert_eq!(
        srv.push(&roy, vec![item("rec", 0, Id::new_v4(), 0, SMALL, 5)])
            .await
            .status,
        200
    );
    let st = srv.send(R::get("/v1/status").auth(&roy)).await.json();
    assert_eq!(st["restore_pending"], false);
}

// ---------------------------------------------------------------------------------------------
// Push semantics end to end

#[tokio::test]
async fn push_semantics_through_the_router() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;

    // The bootstrap device's first push places `genesis` at (member, device, roster, 0).
    let e = srv
        .push(&admin, vec![item("roster", 1, Id::new_v4(), 0, SMALL, 5)])
        .await
        .expect_err(409, ErrorCode::StreamConflict);
    assert_eq!((e.item, e.head), (Some(0), Some(-1)));
    let genesis = Id::new_v4();
    let r = srv
        .push(&admin, vec![item("roster", 0, genesis, 0, SMALL, 9)])
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        r.json(),
        json!({"heads": [{"tag": "roster", "head": 0}], "accepted": 1, "replayed": 0})
    );

    // Idempotent replay: same (stream, idx, id), whatever the blob or epoch.
    let id = Id::new_v4();
    let a = item("rec", 0, id, 0, SMALL, 5);
    assert_eq!(srv.push(&admin, vec![a.clone()]).await.status, 200);
    let r = srv.push(&admin, vec![a.clone()]).await;
    assert_eq!(
        r.json(),
        json!({"heads": [{"tag": "rec", "head": 0}], "accepted": 0, "replayed": 1})
    );
    let again = item("rec", 0, id, 0, 41 + 512, 77);
    assert_eq!(srv.push(&admin, vec![again]).await.json()["replayed"], 1);

    // A marker at head + 1, then its replay.
    let m = Id::new_v4();
    let r = srv.push(&admin, vec![marker("rec", 1, m)]).await;
    assert_eq!(r.json()["heads"], json!([{"tag": "rec", "head": 1}]));
    assert_eq!(
        srv.push(&admin, vec![marker("rec", 1, m)]).await.json()["replayed"],
        1
    );

    // 409 `stream_conflict` with the head: another id at a stored index, and a gap.
    let e = srv
        .push(&admin, vec![item("rec", 1, Id::new_v4(), 0, SMALL, 5)])
        .await
        .expect_err(409, ErrorCode::StreamConflict);
    assert_eq!(e.head, Some(1));
    let e = srv
        .push(&admin, vec![item("rec", 5, Id::new_v4(), 0, SMALL, 5)])
        .await
        .expect_err(409, ErrorCode::StreamConflict);
    assert_eq!((e.item, e.head), (Some(0), Some(1)));
    // 409 `id_conflict`: an id stored at another position.
    let e = srv
        .push(&admin, vec![item("rec", 2, id, 0, SMALL, 5)])
        .await
        .expect_err(409, ErrorCode::IdConflict);
    assert_eq!(e.item, Some(0));
    // 409 `stale_epoch` with the current epoch; markers carry none.
    let e = srv
        .push(&admin, vec![item("rec", 2, Id::new_v4(), 3, SMALL, 5)])
        .await
        .expect_err(409, ErrorCode::StaleEpoch);
    assert_eq!((e.item, e.current_epoch), (Some(0), Some(0)));
    // 410 `deleted` lists every deleted id of the request; a marker for it passes.
    let d1 = Id::new_v4();
    let d2 = Id::new_v4();
    let r = srv
        .send(
            R::post("/v1/delete")
                .auth(&admin)
                .json(&json!({"ids": [d1.to_string(), d2.to_string()]})),
        )
        .await;
    assert_eq!(r.json()["deleted"], 2);
    let e = srv
        .push(
            &admin,
            vec![
                item("rec", 2, Id::new_v4(), 0, SMALL, 5),
                item("rec", 3, d1, 0, SMALL, 5),
                item("rec", 4, d2, 0, SMALL, 5),
            ],
        )
        .await
        .expect_err(410, ErrorCode::Deleted);
    assert_eq!(e.item, Some(1));
    let mut ids = e.ids.unwrap();
    ids.sort();
    let mut want = vec![d1, d2];
    want.sort();
    assert_eq!(ids, want);
    // Nothing of the failed request was stored (item 0 included): rec 2 is still free.
    let r = srv
        .push(
            &admin,
            vec![
                item("rec", 2, Id::new_v4(), 0, SMALL, 5),
                marker("rec", 3, d1),
            ],
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["accepted"], 2);
    // 422 `bad_envelope`.
    srv.push(&admin, vec![item("rec", 4, Id::new_v4(), 0, 100, 5)])
        .await
        .expect_err(422, ErrorCode::BadEnvelope);
    // A tag the server does not know: 400 `invalid_value` at the item.
    let r = srv
        .push(
            &admin,
            vec![
                item("rec", 4, Id::new_v4(), 0, SMALL, 5),
                item("nope", 0, Id::new_v4(), 0, SMALL, 5),
            ],
        )
        .await;
    assert_eq!(
        r.expect_err(400, ErrorCode::InvalidValue).field.as_deref(),
        Some("/records/1/tag")
    );
    // A push never names another member's stream: every item goes to the caller's own device.
    let roy = srv.add_member(&admin, "roy", "member").await;
    assert_eq!(
        srv.push(&roy, vec![item("rec", 0, Id::new_v4(), 0, SMALL, 5)])
            .await
            .json()["heads"],
        json!([{"tag": "rec", "head": 0}])
    );
    let s = srv.send(R::get("/v1/status").auth(&admin)).await.json();
    let streams = s["streams"].as_array().unwrap();
    assert!(streams
        .iter()
        .any(|x| x["member"] == json!(roy.member.to_string()) && x["tag"] == "rec"));
}

// ---------------------------------------------------------------------------------------------
// The other endpoints through the router

#[tokio::test]
async fn invites_approvals_revocations_keys_tokens_and_settings_work_end_to_end() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;

    // Members and devices.
    let m = srv.send(R::get("/v1/members").auth(&roy)).await.json();
    assert_eq!(m["members"].as_array().unwrap().len(), 2);
    // A member's device invite for themselves, joined and approved by that member.
    let inv = srv
        .send(
            R::post("/v1/invites")
                .auth(&roy)
                .json(&json!({"kind": "device", "handle": "roy"})),
        )
        .await;
    assert_eq!(inv.status, 200, "{}", inv.text());
    let inv = inv.json();
    let dev2 = Id::new_v4();
    let j = srv
        .send(R::post("/v1/join").json(&json!({
            "invite_id": inv["invite_id"], "invite_token": inv["invite_token"], "handle": "roy",
            "device_id": dev2.to_string(), "device_pubkey": b64(&[6u8; 32]), "join_mac": b64(&[7u8; 32]),
        })))
        .await
        .json();
    assert_eq!(
        j["member_id"],
        json!(roy.member.to_string()),
        "a device invite keeps the member id"
    );
    // Another admin (not the invite's creator) cannot approve; the creating member can.
    srv.send(
        R::post(&format!("/v1/devices/{dev2}/approve"))
            .auth(&admin)
            .json(&wraps(0)),
    )
    .await
    .expect_err(403, ErrorCode::Forbidden);
    let r = srv
        .send(
            R::post(&format!("/v1/devices/{dev2}/approve"))
                .auth(&roy)
                .json(&wraps(0)),
        )
        .await;
    assert_eq!(r.status, 204, "{}", r.text());
    // An approval with a missing epoch is 400 `/wraps`.
    // Revocation of the new device by its member; the revoked token stops.
    let r = srv
        .send(R::post(&format!("/v1/devices/{dev2}/revoke")).auth(&roy))
        .await;
    assert_eq!(r.status, 204);
    srv.send(R::get("/v1/status").bearer(j["device_token"].as_str().unwrap()))
        .await
        .expect_err(401, ErrorCode::Unauthenticated);
    let st = srv.send(R::get("/v1/status").auth(&admin)).await.json();
    assert_eq!(st["rotation_needed"], true);
    // A member cannot revoke another member's device.
    srv.send(R::post(&format!("/v1/devices/{}/revoke", admin.device)).auth(&roy))
        .await
        .expect_err(403, ErrorCode::Forbidden);

    // DELETE /v1/invites/{id}: idempotent, 404 for an unknown id.
    let inv =
        srv.send(R::post("/v1/invites").auth(&admin).json(
            &json!({"kind": "member", "handle": "kit", "role": "member", "expires_days": 3}),
        ))
        .await
        .json();
    let path = format!("/v1/invites/{}", inv["invite_id"].as_str().unwrap());
    assert_eq!(srv.send(R::delete(&path).auth(&admin)).await.status, 204);
    assert_eq!(srv.send(R::delete(&path).auth(&admin)).await.status, 204);
    srv.send(R::delete(&format!("/v1/invites/{}", Id::new_v4())).auth(&admin))
        .await
        .expect_err(404, ErrorCode::NotFound);
    srv.send(
        R::post("/v1/invites").auth(&admin).json(
            &json!({"kind": "member", "handle": "kit", "role": "member", "expires_days": 31}),
        ),
    )
    .await
    .expect_err(400, ErrorCode::InvalidValue);

    // Key rotation: current + 1 only; then pushes under epoch 0 are stale.
    let rot = |epoch: u32, devices: &[Id]| {
        json!({"epoch": epoch, "wraps": devices.iter().map(|d| json!({
            "device_id": d.to_string(), "wrap": b64(&[7u8; 140]), "auth": b64(&[8u8; 32])})).collect::<Vec<_>>()})
    };
    srv.send(
        R::post("/v1/keys/rotate")
            .auth(&admin)
            .json(&rot(5, &[admin.device])),
    )
    .await
    .expect_err(409, ErrorCode::EpochConflict);
    let r = srv
        .send(
            R::post("/v1/keys/rotate")
                .auth(&admin)
                .json(&rot(1, &[admin.device, roy.device])),
        )
        .await;
    assert_eq!(r.status, 204, "{}", r.text());
    srv.push(&roy, vec![item("rec", 0, Id::new_v4(), 0, SMALL, 5)])
        .await
        .expect_err(409, ErrorCode::StaleEpoch);
    assert_eq!(
        srv.push(&roy, vec![item("rec", 0, Id::new_v4(), 1, SMALL, 5)])
            .await
            .status,
        200
    );
    let keys = srv.send(R::get("/v1/keys").auth(&roy)).await.json();
    assert_eq!(keys["current_epoch"], 1);
    assert_eq!(keys["rotation_needed"], false);

    // Token rotation: the new token works, the old one does not.
    let t = srv
        .send(R::post("/v1/token/rotate").auth(&roy))
        .await
        .json();
    let new = t["device_token"].as_str().unwrap().to_string();
    assert_eq!(
        srv.send(R::get("/v1/status").bearer(&new)).await.status,
        200
    );
    srv.send(R::get("/v1/status").auth(&roy))
        .await
        .expect_err(401, ErrorCode::Unauthenticated);

    // Roles and removal: the last admin stays; a promoted member can be removed.
    srv.send(
        R::post(&format!("/v1/members/{}/role", admin.member))
            .auth(&admin)
            .json(&json!({"role": "member"})),
    )
    .await
    .expect_err(409, ErrorCode::LastAdmin);
    srv.send(R::post(&format!("/v1/members/{}/remove", admin.member)).auth(&admin))
        .await
        .expect_err(409, ErrorCode::LastAdmin);
    let r = srv
        .send(
            R::post(&format!("/v1/members/{}/remove", roy.member))
                .auth(&admin)
                .json(&json!({"delete_records": true})),
        )
        .await;
    assert_eq!(r.status, 204, "{}", r.text());
    srv.send(R::get("/v1/status").bearer(&new))
        .await
        .expect_err(401, ErrorCode::Unauthenticated);
    let dl = srv
        .send(R::get("/v1/deletions?from=0").auth(&admin))
        .await
        .json();
    assert_eq!(dl["entries"].as_array().unwrap().len(), 1);

    // Settings: `min_client` only rises; `retention_days` decreases are pending; an unknown
    // field is refused.
    let r = srv
        .send(
            R::put("/v1/org/settings")
                .auth(&admin)
                .json(&json!({"retention_days": 90})),
        )
        .await;
    assert_eq!(r.json()["pending_retention"]["retention_days"], 90);
    assert_eq!(r.json()["retention_days"], 365);
    srv.send(
        R::put("/v1/org/settings")
            .auth(&admin)
            .json(&json!({"retention_days": 10})),
    )
    .await
    .expect_err(400, ErrorCode::InvalidValue);
    srv.send(
        R::put("/v1/org/settings")
            .auth(&admin)
            .json(&json!({"min_client": "0.1.0"})),
    )
    .await
    .expect_err(400, ErrorCode::InvalidValue);
    srv.send(
        R::put("/v1/org/settings")
            .auth(&admin)
            .json(&json!({"nope": 1})),
    )
    .await
    .expect_err(400, ErrorCode::UnknownField);

    // Export: the canonical SQLite file, admin only; audited; the temporary file is gone.
    let r = srv.send(R::get("/v1/export").auth(&admin)).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.header("content-type").as_deref(),
        Some("application/vnd.sqlite3")
    );
    assert!(r.body.starts_with(b"SQLite format 3\0"));
    let left: Vec<_> = std::fs::read_dir(srv._dir.0.clone())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("awm-export-"))
        .collect();
    assert!(left.is_empty());
    let audit = srv
        .send(R::get("/v1/audit?from=0&limit=1000").auth(&admin))
        .await
        .json();
    assert!(audit["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["action"] == "export"));
}

// ---------------------------------------------------------------------------------------------
// Logs

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn request_logs_hold_no_blob_bytes_no_token_and_no_body() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    // A blob with a recognisable pattern.
    let mut raw = blob_bytes(SMALL, 0);
    for (i, b) in raw.iter_mut().enumerate().skip(1) {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    let text = b64(&raw);
    let id = Id::new_v4();
    let push =
        json!({"records": [{"tag":"rec","idx":0,"id": id.to_string(),"epoch":0,"blob": text}]});
    let r = srv
        .send(R::post("/v1/records").auth(&admin).json(&push))
        .await;
    assert_eq!(r.status, 200);
    // Failures that carry the blob: a conflict, a malformed body, an unknown field.
    srv.send(R::post("/v1/records").auth(&admin).json(&push))
        .await;
    let mut bad = push.clone();
    bad["x"] = json!(text);
    let r = srv
        .send(R::post("/v1/records").auth(&admin).json(&bad))
        .await;
    assert!(
        !contains(&r.body, text.as_bytes()),
        "error body echoes the blob"
    );
    let r = srv
        .send(
            R::post("/v1/records")
                .auth(&admin)
                .raw(format!("{{\"records\": \"{text}\"").into_bytes()),
        )
        .await;
    assert!(!contains(&r.body, text.as_bytes()));
    let r = srv
        .send(
            R::post("/v1/records")
                .auth(&admin)
                .raw(format!("{{\"records\": \"{text}\"}}").into_bytes()),
        )
        .await;
    assert!(!contains(&r.body, text.as_bytes()));
    srv.send(R::get("/v1/status").bearer("awm_t_wrong")).await;
    srv.send(R::get("/v1/status").auth(&admin)).await;

    let lines = srv.log_lines();
    let all = lines.join("\n");
    let secret = &admin.token[admin.token.len() - 43..];
    for needle in [text.as_str(), admin.token.as_str(), secret, "awm_b_"] {
        assert!(!all.contains(needle), "a log line holds {needle:?}:\n{all}");
    }
    for chunk in raw[1..].chunks(24).take(4) {
        assert!(!contains(all.as_bytes(), chunk));
    }
    assert!(!all.contains("Bearer"));

    // One line per request, in a fixed shape.
    let reqs: Vec<&String> = lines.iter().filter(|l| l.starts_with("request ")).collect();
    assert!(reqs.len() >= 8, "{all}");
    let line = reqs
        .iter()
        .find(|l| l.contains("method=POST path=/v1/records status=200"))
        .unwrap_or_else(|| panic!("{all}"));
    assert!(line.contains(" ms="));
    assert!(line.contains(&format!("member={}", admin.member)));
    // The token prefix: the organisation and the first 6 characters of the secret.
    assert!(
        line.contains(&format!("token=awm_t_{}_{}", admin.org, &secret[..6])),
        "{line}"
    );
    assert!(line.contains("client=0.2.0"));
    // Anonymous requests log `-`.
    let anon = reqs
        .iter()
        .find(|l| l.contains("path=/v1/bootstrap"))
        .unwrap();
    assert!(anon.contains("token=- member=-"), "{anon}");
    // The token of a failed authentication is logged by prefix only.
    assert!(reqs
        .iter()
        .any(|l| l.contains("status=401") && l.contains("token=-")));
    // Handles and ids of the organisation appear nowhere but the member id.
    assert!(!all.contains("alf"));
}

// ---------------------------------------------------------------------------------------------
// /healthz, the retention hooks, graceful shutdown

#[tokio::test]
async fn healthz_answers_200_without_authentication_or_client_header() {
    let srv = Srv::new();
    let r = srv.send(R::get("/healthz").no_client()).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"ok");
    // Not rate limited like members' requests: probes do not compete.
    for _ in 0..40 {
        assert_eq!(srv.send(R::get("/healthz").no_client()).await.status, 200);
    }
}

#[tokio::test]
async fn healthz_reuses_the_store_answer_for_a_second() {
    // RVT2 m6: an unauthenticated, unlimited route costs at most one store read a second.
    let srv = Srv::new();
    assert_eq!(srv.send(R::get("/healthz").no_client()).await.status, 200);
    let conn = open_connection(&srv.data.join(DB_FILE)).unwrap();
    conn.execute_batch("ALTER TABLE meta RENAME TO meta_gone;")
        .unwrap();
    // Inside the second, the cached answer: no store read.
    for _ in 0..100 {
        assert_eq!(srv.send(R::get("/healthz").no_client()).await.status, 200);
    }
    tokio::time::sleep(http::HEALTH_CACHE + std::time::Duration::from_millis(100)).await;
    let r = srv.send(R::get("/healthz").no_client()).await;
    assert_eq!(r.status, 503);
    assert_eq!(r.body, b"unavailable");
    conn.execute_batch("ALTER TABLE meta_gone RENAME TO meta;")
        .unwrap();
    tokio::time::sleep(http::HEALTH_CACHE + std::time::Duration::from_millis(100)).await;
    assert_eq!(srv.send(R::get("/healthz").no_client()).await.status, 200);
}

#[tokio::test]
async fn request_time_retention_runs_once_an_hour_through_the_runner() {
    let srv = Srv::with(|c| c.retention = RetentionMode::InRequests);
    let admin = srv.bootstrap().await; // one /v1 request has run the hook
    assert_eq!(srv.retention_calls.load(Ordering::SeqCst), 1);
    for _ in 0..5 {
        srv.send(R::get("/v1/status").auth(&admin)).await;
    }
    assert_eq!(srv.retention_calls.load(Ordering::SeqCst), 1);
    srv.advance(3_599);
    srv.send(R::get("/v1/status").auth(&admin)).await;
    assert_eq!(srv.retention_calls.load(Ordering::SeqCst), 1);
    srv.advance(1);
    srv.send(R::get("/v1/status").auth(&admin)).await;
    assert_eq!(srv.retention_calls.load(Ordering::SeqCst), 2);
    // `healthz` is not a /v1 request.
    srv.advance(7_200);
    srv.send(R::get("/healthz").no_client()).await;
    assert_eq!(srv.retention_calls.load(Ordering::SeqCst), 2);
    assert!(srv.log_lines().iter().any(|l| l == "retention removed=7"));

    // Off: no request triggers it.
    let off = Srv::new();
    let admin = off.bootstrap().await;
    off.advance(10_000);
    off.send(R::get("/v1/status").auth(&admin)).await;
    assert_eq!(off.retention_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_failing_or_panicking_retention_runner_does_not_fail_the_request() {
    for runner in [
        Arc::new(|_d: u32| Err(StoreError::Backend("disk".into()))) as http::RetentionRunner,
        // The TM1 stub is `todo!()` until TM9 lands: the default must not take a request down.
        Arc::new(|_d: u32| -> Result<u64, StoreError> { panic!("retention (§5.6)") }),
    ] {
        let srv = Srv::build(|c| c.retention = RetentionMode::InRequests, Some(runner));
        let admin = srv.bootstrap().await;
        let r = srv.send(R::get("/v1/status").auth(&admin)).await;
        assert_eq!(r.status, 200);
        assert!(srv
            .log_lines()
            .iter()
            .any(|l| l.starts_with("retention failed")));
    }
}

#[tokio::test]
async fn the_internal_retention_route_needs_its_token_and_runs_the_runner_once() {
    let token = "cloud-scheduler-secret";
    // Not configured: the route does not exist.
    let srv = Srv::new();
    srv.send(R::post("/internal/retention").no_client().bearer(token))
        .await
        .expect_err(404, ErrorCode::NotFound);

    let srv = Srv::with(|c| c.internal_token_hash = Some(auth::hash(token)));
    let admin = srv.bootstrap().await;
    srv.send(R::post("/internal/retention").no_client())
        .await
        .expect_err(401, ErrorCode::Unauthenticated);
    srv.send(R::post("/internal/retention").no_client().bearer("wrong"))
        .await
        .expect_err(401, ErrorCode::Unauthenticated);
    // A device token is not the scheduler's token.
    srv.send(R::post("/internal/retention").no_client().auth(&admin))
        .await
        .expect_err(401, ErrorCode::Unauthenticated);
    assert_eq!(srv.retention_calls.load(Ordering::SeqCst), 0);
    let r = srv
        .send(R::post("/internal/retention").no_client().bearer(token))
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json(), json!({"removed": 7}));
    assert_eq!(srv.retention_calls.load(Ordering::SeqCst), 1);
    // It is not part of /v1: the hook does not run for it, and GET is 404.
    srv.send(R::get("/internal/retention").no_client().bearer(token))
        .await
        .expect_err(404, ErrorCode::NotFound);
}

// --- TM9W: deletion and retention through the router (TM9's `delete` and `retention`) -------

fn ids_of(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .map(|i| i["id"].as_str().unwrap().to_string())
        .collect()
}

/// `n` bytes that start with the envelope version byte and are otherwise unique to `seed`.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut v = vec![0x01u8];
    while v.len() < n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push((x >> 24) as u8);
    }
    v
}

fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// `server.db` and its WAL, one after the other.
fn db_and_wal(srv: &Srv) -> Vec<u8> {
    let db = srv.data.join(DB_FILE);
    let mut wal = db.clone().into_os_string();
    wal.push("-wal");
    let mut out = std::fs::read(&db).unwrap();
    out.extend(std::fs::read(PathBuf::from(wal)).unwrap_or_default());
    out
}

/// The held (`true`) and deleted (`false`) positions of one stream, read as `admin`.
async fn stream_state(srv: &Srv, admin: &Who, of: &Who, tag: &str) -> Vec<bool> {
    let q = format!(
        "/v1/records?member={}&device={}&tag={tag}&from=0&limit=100",
        of.member, of.device
    );
    let r = srv.send(R::get(&q).auth(admin)).await;
    assert_eq!(r.status, 200, "{}", r.text());
    r.json()["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i.get("deleted") != Some(&json!(true)))
        .collect()
}

#[tokio::test]
async fn a_bulk_delete_writes_its_notice_and_the_hourly_limit_survives_a_restart() {
    let srv = Srv::real(|_| {});
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    let e = srv.epoch().await;
    assert_eq!(
        srv.push(&roy, srv.items("rec", 0, 2, e, SMALL))
            .await
            .status,
        200
    );
    let r = srv
        .send(
            R::post("/v1/delete")
                .auth(&roy)
                .json(&json!({"all_mine": true})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json(), json!({"deleted": 2, "already": 0}));
    let rows = srv.store.audit(0, 200).await.unwrap().rows;
    let notices: Vec<_> = rows
        .iter()
        .filter(|r| r.action == "delete.notice")
        .collect();
    assert_eq!(notices.len(), 1, "one notice row for the bulk delete");
    assert_eq!(notices[0].actor, Some(roy.member));
    assert_eq!(
        notices[0].target.as_deref(),
        Some(roy.device.to_string().as_str())
    );

    // A new process on the same server.db: the allowance is read from the audit log.
    let srv = srv.restart();
    srv.advance(60);
    let r = srv
        .send(
            R::post("/v1/delete")
                .auth(&roy)
                .json(&json!({"all_mine": true})),
        )
        .await;
    let body = r.expect_err(429, ErrorCode::RateLimited);
    assert_eq!(body.retry_after_s, Some(3_540));
    assert_eq!(r.header("retry-after").as_deref(), Some("3540"));
    // By ids is not limited, and the hour ends 3,600 s after the first bulk delete.
    assert_eq!(
        srv.send(
            R::post("/v1/delete")
                .auth(&roy)
                .json(&json!({"ids": [Id::new_v4().to_string()]}))
        )
        .await
        .status,
        200
    );
    srv.advance(3_540);
    let r = srv
        .send(
            R::post("/v1/delete")
                .auth(&roy)
                .json(&json!({"all_mine": true})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
}

#[tokio::test]
async fn delete_ids_naming_a_roster_record_is_400_on_ids_and_deletes_nothing() {
    let srv = Srv::real(|_| {});
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    let e = srv.epoch().await;
    let roster = srv.items("roster", 0, 2, e, SMALL);
    let recs = srv.items("rec", 0, 2, e, SMALL);
    assert_eq!(srv.push(&roy, roster.clone()).await.status, 200);
    assert_eq!(srv.push(&roy, recs.clone()).await.status, 200);
    let (roster, recs) = (ids_of(&roster), ids_of(&recs));
    for who in [&roy, &admin] {
        let r = srv
            .send(
                R::post("/v1/delete")
                    .auth(who)
                    .json(&json!({"ids": [recs[0], roster[1]]})),
            )
            .await;
        let body = r.expect_err(400, ErrorCode::InvalidValue);
        assert_eq!(body.field.as_deref(), Some("/ids"));
    }
    assert_eq!(
        stream_state(&srv, &admin, &roy, "roster").await,
        [true, true]
    );
    assert_eq!(stream_state(&srv, &admin, &roy, "rec").await, [true, true]);
    let dl = srv
        .send(R::get("/v1/deletions?from=0").auth(&admin))
        .await
        .json();
    assert!(dl["entries"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_200_delete_leaves_no_deleted_bytes_in_the_database_or_the_wal() {
    let srv = Srv::real(|_| {});
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    let e = srv.epoch().await;
    let (small, large, kept) = (noise(SMALL, 1), noise(LARGEST, 2), noise(SMALL, 3));
    let items: Vec<Value> = [(&small, 0u64), (&large, 1), (&kept, 2)]
        .iter()
        .map(|(b, i)| json!({"tag": "rec", "idx": i, "id": Id::new_v4().to_string(), "epoch": e, "blob": b64(b)}))
        .collect();
    assert_eq!(srv.push(&roy, items.clone()).await.status, 200);
    let windows = |b: &[u8]| -> Vec<Vec<u8>> {
        [100usize, 5_000, 12_000]
            .iter()
            .filter(|o| **o + 48 <= b.len())
            .map(|o| b[*o..*o + 48].to_vec())
            .collect()
    };
    let before = db_and_wal(&srv);
    for b in [&small, &large, &kept] {
        for w in windows(b) {
            assert!(contains_window(&before, &w), "positive control");
        }
    }
    let ids = [items[0]["id"].clone(), items[1]["id"].clone()];
    let r = srv
        .send(
            R::post("/v1/delete")
                .auth(&roy)
                .json(&json!({ "ids": ids })),
        )
        .await;
    assert_eq!(r.json(), json!({"deleted": 2, "already": 0}));
    let after = db_and_wal(&srv);
    for b in [&small, &large] {
        for w in windows(b) {
            assert!(!contains_window(&after, &w), "deleted bytes remain");
        }
    }
    for w in windows(&kept) {
        assert!(contains_window(&after, &w), "the neighbour stays");
    }
}

#[tokio::test]
async fn removing_a_member_with_delete_records_keeps_their_roster_records() {
    let srv = Srv::real(|_| {});
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    let e = srv.epoch().await;
    assert_eq!(
        srv.push(&roy, srv.items("roster", 0, 2, e, SMALL))
            .await
            .status,
        200
    );
    assert_eq!(
        srv.push(&roy, srv.items("rec", 0, 3, e, SMALL))
            .await
            .status,
        200
    );
    let r = srv
        .send(
            R::post(&format!("/v1/members/{}/remove", roy.member))
                .auth(&admin)
                .json(&json!({"delete_records": true})),
        )
        .await;
    assert_eq!(r.status, 204, "{}", r.text());
    assert_eq!(stream_state(&srv, &admin, &roy, "rec").await, [false; 3]);
    assert_eq!(
        stream_state(&srv, &admin, &roy, "roster").await,
        [true, true]
    );
    let dl = srv
        .send(R::get("/v1/deletions?from=0").auth(&admin))
        .await
        .json();
    assert_eq!(
        dl["entries"].as_array().unwrap().len(),
        3,
        "no roster entry"
    );
}

#[tokio::test]
async fn the_internal_route_runs_the_real_retention_once_an_hour() {
    let token = "cloud-scheduler-secret";
    let srv = Srv::real(|c| c.internal_token_hash = Some(auth::hash(token)));
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    let e = srv.epoch().await;
    assert_eq!(
        srv.push(&roy, srv.items("rec", 0, 3, e, SMALL))
            .await
            .status,
        200
    );
    assert_eq!(
        srv.push(&roy, srv.items("roster", 0, 1, e, SMALL))
            .await
            .status,
        200
    );
    let call = || srv.send(R::post("/internal/retention").no_client().bearer(token));
    srv.advance(400 * DAY);
    let r = call().await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json(), json!({"removed": 3}));
    assert_eq!(stream_state(&srv, &admin, &roy, "rec").await, [false; 3]);
    assert_eq!(stream_state(&srv, &admin, &roy, "roster").await, [true]);
    // The store-wide gate: a second call within the hour does nothing and writes nothing.
    srv.advance(3_599);
    assert_eq!(call().await.json(), json!({"removed": 0}));
    let audit = srv.store.audit(0, 200).await.unwrap().rows;
    assert_eq!(audit.iter().filter(|r| r.action == "retention").count(), 1);
    srv.advance(1);
    assert_eq!(call().await.json(), json!({"removed": 0}));
    let audit = srv.store.audit(0, 200).await.unwrap().rows;
    assert_eq!(audit.iter().filter(|r| r.action == "retention").count(), 2);
}

#[tokio::test]
async fn app_state_new_installs_the_store_runner_not_the_stub() {
    // The server clock runs 800 days behind the system clock, which the default runner reads.
    let token = "cloud-scheduler-secret";
    let srv = Srv::default_runner(|c| c.internal_token_hash = Some(auth::hash(token)));
    srv.advance(-800 * DAY);
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    let e = srv.epoch().await;
    assert_eq!(
        srv.push(&roy, srv.items("rec", 0, 2, e, SMALL))
            .await
            .status,
        200
    );
    let call = || srv.send(R::post("/internal/retention").no_client().bearer(token));
    let r = call().await;
    assert_eq!(r.status, 200, "the stub would answer 500: {}", r.text());
    assert_eq!(r.json(), json!({"removed": 2}));
    assert_eq!(call().await.json(), json!({"removed": 0}));
}

#[tokio::test]
async fn request_time_retention_runs_the_real_runner_off_the_request_thread() {
    let srv = Srv::real(|c| c.retention = RetentionMode::InRequests);
    let admin = srv.bootstrap().await;
    let roy = srv.add_member(&admin, "roy", "member").await;
    let e = srv.epoch().await;
    assert_eq!(
        srv.push(&roy, srv.items("rec", 0, 2, e, SMALL))
            .await
            .status,
        200
    );
    srv.advance(400 * DAY);
    assert_eq!(
        srv.send(R::get("/v1/status").auth(&admin)).await.status,
        200
    );
    assert!(srv.log_lines().iter().any(|l| l == "retention removed=2"));
    assert_eq!(srv.store.deletions(0, 10).await.unwrap().entries.len(), 2);
    // Within the hour no further run happens, in this process or in the store.
    srv.advance(60);
    srv.send(R::get("/v1/status").auth(&admin)).await;
    let audit = srv.store.audit(0, 200).await.unwrap().rows;
    assert_eq!(audit.iter().filter(|r| r.action == "retention").count(), 2);
}

// --- graceful shutdown ----------------------------------------------------------------------

fn blocking_get(addr: SocketAddr, path: &str) -> std::io::Result<String> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr)?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )?;
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    Ok(out)
}

fn with_slow_route(srv: &Srv, millis: u64) -> Router {
    async fn slow(axum::extract::State(ms): axum::extract::State<u64>) -> &'static str {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        "slow-done"
    }
    Router::new()
        .route("/slow", axum::routing::get(slow))
        .with_state(millis)
        .merge(http::router(srv.state.clone()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_shutdown_lets_in_flight_requests_finish_and_refuses_new_connections() {
    let srv = Srv::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let router = with_slow_route(&srv, 900);
    let server = tokio::spawn(http::serve_with_grace(
        listener,
        router,
        async move {
            let _ = rx.await;
        },
        std::time::Duration::from_secs(10),
    ));

    // /healthz works over a real socket.
    let h = tokio::task::spawn_blocking(move || blocking_get(addr, "/healthz"))
        .await
        .unwrap()
        .unwrap();
    assert!(h.starts_with("HTTP/1.1 200"), "{h}");

    let inflight = tokio::task::spawn_blocking(move || blocking_get(addr, "/slow"));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let t0 = std::time::Instant::now();
    tx.send(()).unwrap();
    // The server stops once the slow request is done, and not before.
    let r = tokio::time::timeout(std::time::Duration::from_secs(8), server)
        .await
        .expect("shutdown within the grace")
        .unwrap();
    r.unwrap();
    let waited = t0.elapsed();
    assert!(
        waited >= std::time::Duration::from_millis(400),
        "returned before the request finished: {waited:?}"
    );
    let body = inflight.await.unwrap().unwrap();
    assert!(
        body.starts_with("HTTP/1.1 200") && body.contains("slow-done"),
        "{body}"
    );
    // New connections are refused.
    assert!(std::net::TcpStream::connect(addr).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_does_not_wait_longer_than_its_grace_for_a_stuck_request() {
    let srv = Srv::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let router = with_slow_route(&srv, 30_000);
    let server = tokio::spawn(http::serve_with_grace(
        listener,
        router,
        async move {
            let _ = rx.await;
        },
        std::time::Duration::from_millis(400),
    ));
    let _stuck = tokio::task::spawn_blocking(move || blocking_get(addr, "/slow"));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let t0 = std::time::Instant::now();
    tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .expect("returns within the grace")
        .unwrap()
        .unwrap();
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(3),
        "{:?}",
        t0.elapsed()
    );
}

// ---------------------------------------------------------------------------------------------
// Responses

#[tokio::test]
async fn cache_control_hsts_and_retry_after_headers() {
    let srv = Srv::with(|c| c.hsts = true);
    let admin = srv.bootstrap().await;
    let r = srv.send(R::get("/v1/info").no_client()).await;
    assert_eq!(r.header("cache-control").as_deref(), Some("max-age=3600"));
    assert!(r.header("strict-transport-security").is_some());
    let r = srv.send(R::get("/v1/status").auth(&admin)).await;
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
    let r = srv.send(R::get("/v1/nope").auth(&admin)).await;
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
    // No HSTS unless this binary or the cloud terminates TLS.
    let plain = Srv::new();
    assert!(plain
        .send(R::get("/v1/info").no_client())
        .await
        .header("strict-transport-security")
        .is_none());
    // Every JSON response says so.
    assert_eq!(
        r.header("content-type").as_deref(),
        Some("application/json")
    );
}

#[tokio::test]
async fn an_internal_store_failure_is_a_bodiless_500_logged_without_row_values() {
    let srv = Srv::new();
    let admin = srv.bootstrap().await;
    // Break the store under the server: a table the status query reads.
    let conn = open_connection(&srv.data.join(DB_FILE)).unwrap();
    conn.execute_batch(
        "DROP TRIGGER IF EXISTS bl_audit_i; ALTER TABLE audit RENAME TO audit_gone;",
    )
    .unwrap();
    // `append_audit` runs for an export: it fails with a store error that is not a wire code.
    let r = srv.send(R::get("/v1/export").auth(&admin)).await;
    assert_eq!(r.status, 500, "{}", r.text());
    assert!(r.body.is_empty());
    let lines = srv.log_lines();
    let l = lines.iter().find(|l| l.contains("status=500")).unwrap();
    assert!(l.contains("error="), "{l}");
    assert!(!l.contains(&admin.token));
}
