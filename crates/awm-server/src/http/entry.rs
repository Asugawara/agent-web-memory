//! The endpoints a device meets first: `info`, `bootstrap`, `join`, and `status` (the cursor
//! source of every sync run).

use awm_proto::wire::{
    limits, BootstrapRequest, DeletionHeads, ErrorCode, InfoResponse, JoinRequest, OrgSettings,
    StatusResponse, PROTOCOL_VERSION,
};
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue};
use axum::response::Response;
use serde_json::Value;

use super::ctx::{Cap, Class, Client, Cx};
use super::error::ApiError;
use super::{json, reply, AppState};
use crate::auth::{self, Caller};
use crate::authz::{self, Action};

/// `GET /v1/info`: anyone; cacheable for an hour.
pub(super) async fn info(State(app): State<AppState>, req: Request) -> Response {
    reply(info_inner(&app, req).await)
}

async fn info_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let _cx = Cx::open(app, req, Client::Optional, Class::Anonymous, Cap::Body)?;
    authz::require(&Caller::Anonymous, Action::Info)?;
    let state = app.store.restore_state().await?;
    let body = InfoResponse {
        protocols: vec![PROTOCOL_VERSION],
        server: app.config.server_version.clone(),
        cloud: app.config.cloud,
        generation: state.generation,
        min_client: app.config.release_floor.clone(),
        limits: app.config.limits.published(),
        features: Vec::new(),
    };
    let mut resp = json(&body)?;
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=3600"),
    );
    Ok(resp)
}

/// A handle that is not 1-24 characters of `[a-z0-9_-]` is 400 `invalid_value` (`/handle`,
/// `docs/sync-v1.md` §12); the typed parse would only say `malformed`.
pub(super) fn check_handle(body: &[u8]) -> Result<(), ApiError> {
    let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(body) else {
        return Ok(());
    };
    if let Some(Value::String(h)) = m.get("handle") {
        if awm_proto::wire::Handle::parse(h).is_err() {
            return Err(ApiError::invalid(
                "/handle",
                "handle must be 1-24 characters of [a-z0-9_-]",
            ));
        }
    }
    Ok(())
}

/// `POST /v1/bootstrap`: the bootstrap token in the body authenticates; no `Authorization`.
pub(super) async fn bootstrap(State(app): State<AppState>, req: Request) -> Response {
    reply(bootstrap_inner(&app, req).await)
}

async fn bootstrap_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(
        &app.clone(),
        req,
        Client::Required,
        Class::Anonymous,
        Cap::Body,
    )?;
    let bytes = cx.bytes(Cap::Body).await?;
    check_handle(&bytes)?;
    let body: BootstrapRequest = super::error::parse_json(&bytes)?;
    authz::require(&Caller::Anonymous, Action::Bootstrap)?;
    // There is no organisation yet: the gate is the release floor.
    cx.require_client_at_least(&app.config.release_floor)?;
    let resp = auth::bootstrap(&*app.store, body, app.config.org_defaults.clone(), cx.now).await?;
    json(&resp)
}

/// `POST /v1/join`: the invite token in the body authenticates; no `Authorization`.
pub(super) async fn join(State(app): State<AppState>, req: Request) -> Response {
    reply(join_inner(&app, req).await)
}

async fn join_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Join, Cap::Body)?;
    let bytes = cx.bytes(Cap::Body).await?;
    check_handle(&bytes)?;
    let body: JoinRequest = super::error::parse_json(&bytes)?;
    authz::require(&Caller::Anonymous, Action::Join)?;
    // A joiner has no token: while a restore is pending nobody may join.
    cx.restore_gate().await?;
    let min = cx.min_client().await?;
    cx.require_client_at_least(&min)?;
    let resp = auth::join(&*app.store, body, cx.now).await?;
    json(&resp)
}

/// `GET /v1/status`: the calling device's view; a pending device may read it.
pub(super) async fn status(State(app): State<AppState>, req: Request) -> Response {
    reply(status_inner(&app, req).await)
}

async fn status_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let caller = cx.authenticate().await?;
    cx.authorise(&caller, Action::Status).await?;
    let device = caller
        .device()
        .ok_or(ApiError::new(ErrorCode::Unauthenticated, "no device"))?;
    let status = app.store.status(device.device_id, cx.now).await?;
    if matches!(caller, Caller::Pending(_)) {
        return json(&for_pending(status));
    }
    json(&status)
}

/// The status a pending (unapproved) device gets (`docs/sync-v1.md` §6, RVT2 M2): `approved`,
/// `generation`, `current_epoch`, `min_client`, its own ids and role, and its own pending
/// entry. The response keeps its schema, so what a pending device may not see is empty or
/// neutral: no streams, an empty deletion stream, `rotation_needed` and `restore_pending`
/// false, no other pending device, and settings whose only real value is `min_client`
/// (`retention_days` the protocol minimum, `max_members` 0, no pending decrease). A client
/// reads only `approved` and `min_client` until it is approved.
pub(crate) fn for_pending(s: StatusResponse) -> StatusResponse {
    let own = s.device_id;
    StatusResponse {
        rotation_needed: false,
        restore_pending: false,
        settings: OrgSettings {
            retention_days: limits::RETENTION_DAYS_MIN,
            min_client: s.settings.min_client,
            max_members: 0,
            pending_retention: None,
        },
        streams: Vec::new(),
        deletions: DeletionHeads {
            head: -1,
            oldest: 0,
        },
        pending: s
            .pending
            .into_iter()
            .filter(|p| p.device_id == own)
            .collect(),
        ..s
    }
}
