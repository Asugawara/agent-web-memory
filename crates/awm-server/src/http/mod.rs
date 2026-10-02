//! HTTP routes of sync protocol v1 (plan-v3-team §4.3, `docs/sync-v1.md`), built on axum.
//!
//! [`router`] turns an [`AppState`] into the whole `/v1` API plus `/healthz` and the internal
//! retention route; [`serve`] runs it with a graceful shutdown. `awm serve` (TM15) wires the
//! two and builds the state; no handler lives anywhere else.
//!
//! Every handler follows one order (`docs/sync-v1.md` §9.1 for a push, the same shape for the
//! rest): [`Cx::open`] (headers, body size, `Awm-Client`, address rate limit), the body or
//! query parse, [`Cx::authenticate`] (`auth::authenticate` and the per-token limit), then
//! `auth::authorise` / an `auth` operation, which call `authz::require`. Handlers never look at a
//! role: permissions are `authz`'s alone.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use awm_proto::wire::Version;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::Router;

use crate::limits::{Limits, RateLimiter};
use crate::store::{OrgDefaults, Store, StoreError};

mod admin;
mod ctx;
pub mod embedded;
mod entry;
mod error;
mod health;
mod keys;
mod members;
mod net;
mod records;

pub use ctx::{Cx, LogCell};
pub use error::{parse_json, ApiError};
pub use net::{client_ip, IpNet};

// ---------------------------------------------------------------------------------------------
// State

/// Unix seconds. Tests pass a clock they advance.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Request-time retention: deletes at most one bounded batch for an organisation's
/// `retention_days` and returns how many records went. The default is TM9's
/// [`crate::retention::sweep`]; a test passes a counting stand-in.
pub type RetentionRunner = Arc<dyn Fn(u32) -> Result<u64, StoreError> + Send + Sync>;

/// Where request-log lines go. One line per request: method, path, status, duration, token
/// prefix, member id, client address, client version; never a body, a token or a blob.
pub trait LogSink: Send + Sync {
    fn line(&self, line: &str);
}

/// The default sink: standard error.
#[derive(Debug, Default, Clone, Copy)]
pub struct StderrLog;

impl LogSink for StderrLog {
    fn line(&self, line: &str) {
        eprintln!("{line}");
    }
}

/// Where retention runs (plan-v3-team §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionMode {
    /// A host runs it hourly itself; no request triggers it.
    Off,
    /// Cloud Run and self-host path A: one bounded batch inside an ordinary request, at most once
    /// an hour per instance.
    InRequests,
}

/// What `awm serve` (TM15) decides and hands over.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// `GET /v1/info` `server`.
    pub server_version: Version,
    /// The release floor: `GET /v1/info` `min_client`; the bootstrap gate; the lowest value an
    /// organisation's `min_client` may take.
    pub release_floor: Version,
    pub cloud: bool,
    /// The settings of a new organisation (`POST /v1/bootstrap`).
    pub org_defaults: OrgDefaults,
    /// Proxies whose `X-Forwarded-For` is believed (`server.toml` `trusted_proxies`).
    pub trusted_proxies: Vec<IpNet>,
    /// `Strict-Transport-Security` on every response, when this binary or the cloud terminates TLS.
    pub hsts: bool,
    /// Where `GET /v1/export` writes its temporary file.
    pub export_dir: PathBuf,
    pub retention: RetentionMode,
    /// SHA-256 hex of the token that authenticates `POST /internal/retention` (Cloud Scheduler);
    /// `None` leaves the route answering 404.
    pub internal_token_hash: Option<String>,
    /// `Retry-After` of a 503 `restore_pending`, in seconds.
    pub restore_retry_after_s: u32,
    pub limits: Limits,
}

impl ServerConfig {
    pub fn new(server_version: Version, release_floor: Version) -> ServerConfig {
        let limits = Limits::default();
        ServerConfig {
            org_defaults: OrgDefaults {
                retention_days: 365,
                min_client: release_floor.clone(),
                max_members: limits.max_members,
            },
            server_version,
            release_floor,
            cloud: false,
            trusted_proxies: Vec::new(),
            hsts: false,
            export_dir: std::env::temp_dir(),
            retention: RetentionMode::Off,
            internal_token_hash: None,
            restore_retry_after_s: 60,
            limits,
        }
    }
}

/// Everything a handler needs. Cheap to clone.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
    pub config: Arc<ServerConfig>,
    clock: Clock,
    log: Arc<dyn LogSink>,
    pub(crate) limiter: Arc<RateLimiter>,
    retention_runner: RetentionRunner,
    retention_last: Arc<Mutex<Option<i64>>>,
}

impl AppState {
    pub fn new(store: Arc<dyn Store>, config: ServerConfig) -> AppState {
        let retention_runner: RetentionRunner =
            Arc::new(crate::retention::runner(Arc::clone(&store)));
        AppState {
            store,
            config: Arc::new(config),
            clock: Arc::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
            }),
            log: Arc::new(StderrLog),
            limiter: Arc::new(RateLimiter::new()),
            retention_runner,
            retention_last: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_clock(mut self, clock: Clock) -> AppState {
        self.clock = clock;
        self
    }

    pub fn with_log_sink(mut self, sink: Arc<dyn LogSink>) -> AppState {
        self.log = sink;
        self
    }

    pub fn with_retention_runner(mut self, runner: RetentionRunner) -> AppState {
        self.retention_runner = runner;
        self
    }

    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Runs one retention batch for the organisation's `retention_days` (TM9's stub, on a
    /// blocking thread). `None` before the organisation exists.
    pub(crate) async fn run_retention(&self, now: i64) -> Result<Option<u64>, ApiError> {
        let Some(org) = self.store.org(now).await? else {
            return Ok(None);
        };
        let runner = self.retention_runner.clone();
        let days = org.settings.retention_days;
        match tokio::task::spawn_blocking(move || runner(days)).await {
            Ok(Ok(n)) => Ok(Some(n)),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(ApiError::internal("retention task failed".into())),
        }
    }

    /// The per-request retention hook: at most one run an hour, and only in
    /// [`RetentionMode::InRequests`]. A failure is logged and does not fail the request; the hour
    /// still counts, so a failing batch is not retried by every request.
    async fn retention_tick(&self) {
        if self.config.retention != RetentionMode::InRequests {
            return;
        }
        let now = self.now();
        {
            let mut last = self
                .retention_last
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if last.is_some_and(|t| now - t < 3_600) {
                return;
            }
            *last = Some(now);
        }
        match self.run_retention(now).await {
            Ok(Some(n)) => self.log.line(&format!("retention removed={n}")),
            Ok(None) => {}
            Err(e) => self.log.line(&format!(
                "retention failed status={}{}",
                e.status.as_u16(),
                e.log.map(|l| format!(" {l}")).unwrap_or_default()
            )),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Router

/// The whole HTTP surface: `/v1/*`, `GET /healthz`, `POST /internal/retention`.
pub fn router(state: AppState) -> Router {
    use admin::*;
    use entry::*;
    use health::*;
    use keys::*;
    use members::*;
    use records::*;

    Router::new()
        .route("/healthz", get(healthz))
        .route("/internal/retention", post(internal_retention))
        .route("/v1/info", get(info))
        .route("/v1/bootstrap", post(bootstrap))
        .route("/v1/join", post(join))
        .route("/v1/status", get(status))
        .route("/v1/records", post(push).get(get_records))
        .route("/v1/pull", post(pull))
        .route("/v1/deletions", get(deletions))
        .route("/v1/delete", post(delete_records))
        .route("/v1/members", get(list_members))
        .route("/v1/invites", post(create_invite))
        .route("/v1/invites/{id}", delete(revoke_invite))
        .route("/v1/devices/{id}/approve", post(approve_device))
        .route("/v1/devices/{id}/revoke", post(revoke_device))
        .route("/v1/members/{id}/remove", post(remove_member))
        .route("/v1/members/{id}/role", post(set_role))
        .route("/v1/keys", get(get_keys))
        .route("/v1/keys/rotate", post(rotate_keys))
        .route("/v1/token/rotate", post(rotate_token))
        .route("/v1/audit", get(audit))
        .route("/v1/org/settings", get(get_settings).put(put_settings))
        .route("/v1/restore/complete", post(complete_restore))
        .route("/v1/export", get(export))
        .fallback(not_found)
        .method_not_allowed_fallback(not_found)
        .layer(axum::middleware::from_fn_with_state(state.clone(), observe))
        .with_state(state)
}

async fn not_found() -> Response {
    ApiError::not_found("no such endpoint").into_response()
}

/// The outermost layer: the request-log line, `Cache-Control`, HSTS and the retention hook.
async fn observe(
    axum::extract::State(app): axum::extract::State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let cell = LogCell::default();
    req.extensions_mut().insert(cell.clone());
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let versioned = path.starts_with("/v1/");

    let mut resp = next.run(req).await;

    let h = resp.headers_mut();
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    if app.config.hsts {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }

    if versioned {
        app.retention_tick().await;
    }

    let fields = cell.snapshot();
    let mut line = format!(
        "request method={method} path={path} status={} ms={} token={} member={} ip={} client={}",
        resp.status().as_u16(),
        started.elapsed().as_millis(),
        fields.token.as_deref().unwrap_or("-"),
        fields
            .member
            .map(|m| m.to_string())
            .unwrap_or_else(|| "-".into()),
        fields
            .ip
            .map(|i| i.to_string())
            .unwrap_or_else(|| "-".into()),
        fields.client.as_deref().unwrap_or("-"),
    );
    if let Some(e) = resp.extensions().get::<error::ApiLog>() {
        line.push_str(&format!(" error={:?}", e.0));
    }
    app.log.line(&line);
    resp
}

// ---------------------------------------------------------------------------------------------
// Serving

/// How long [`serve`] lets in-flight requests finish after the shutdown signal.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

/// Serves `router` on `listener` until `shutdown` resolves, then stops accepting connections and
/// lets in-flight requests finish, for at most [`SHUTDOWN_GRACE`].
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    serve_with_grace(listener, router, shutdown, SHUTDOWN_GRACE).await
}

/// [`serve`] with an explicit grace period (tests use a short one).
pub async fn serve_with_grace(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
    grace: Duration,
) -> std::io::Result<()> {
    let (signalled_tx, signalled_rx) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown.await;
        let _ = signalled_tx.send(());
    });
    tokio::select! {
        r = server => r,
        _ = async {
            let _ = signalled_rx.await;
            tokio::time::sleep(grace).await;
        } => Ok(()),
    }
}

/// 204 No Content.
pub(crate) fn no_content() -> Response {
    let mut r = Response::new(axum::body::Body::empty());
    *r.status_mut() = StatusCode::NO_CONTENT;
    r
}

/// 200 with a JSON body.
pub(crate) fn json<T: serde::Serialize>(v: &T) -> Result<Response, ApiError> {
    let bytes = serde_json::to_vec(v).map_err(|e| ApiError::internal(format!("encode: {e}")))?;
    let mut r = Response::new(axum::body::Body::from(bytes));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(r)
}

/// Turns a handler's result into its response.
pub(crate) fn reply(r: Result<Response, ApiError>) -> Response {
    r.unwrap_or_else(ApiError::into_response)
}
