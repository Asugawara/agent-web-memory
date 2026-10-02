//! `GET /healthz` and the internal retention route.

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use serde_json::json as value;

use super::ctx::{Cap, Class, Client, Cx};
use super::error::ApiError;
use super::{json, reply, AppState};
use crate::auth;
use awm_proto::wire::ErrorCode;

/// `GET /healthz`: 200 when the store answers, 503 when it does not; no auth, no body details,
/// and outside the protocol (no `Awm-Client`, no rate limit, so a probe never competes with
/// members).
pub(super) async fn healthz(State(app): State<AppState>) -> Response {
    let ok = app.store.restore_state().await.is_ok();
    let mut r = Response::new(axum::body::Body::from(if ok {
        "ok"
    } else {
        "unavailable"
    }));
    *r.status_mut() = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    r
}

/// `POST /internal/retention`: Cloud Scheduler's hourly call (plan-v3-team §6.1). It carries a
/// bearer token whose SHA-256 is `ServerConfig::internal_token_hash`; without that setting the
/// route does not exist. It runs TM9's retention runner once and nothing else.
pub(super) async fn internal_retention(State(app): State<AppState>, req: Request) -> Response {
    reply(retention_inner(&app, req).await)
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

async fn retention_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let Some(expected) = app.config.internal_token_hash.as_deref() else {
        return Err(ApiError::not_found("no such endpoint"));
    };
    let mut cx = Cx::open(app, req, Client::Optional, Class::Anonymous, Cap::Body)?;
    let presented = cx
        .header(header::AUTHORIZATION.as_str())
        .and_then(|h| h.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, t)| auth::hash(t));
    if !presented.is_some_and(|h| same(&h, expected)) {
        return Err(ApiError::new(
            ErrorCode::Unauthenticated,
            "unknown or missing token",
        ));
    }
    let _ = cx.bytes(Cap::Body).await?;
    let removed = app.run_retention(cx.now).await?.unwrap_or(0);
    json(&value!({ "removed": removed }))
}
