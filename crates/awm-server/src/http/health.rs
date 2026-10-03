//! `GET /healthz` and the internal retention route.

use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use serde_json::json as value;

use super::ctx::{Cap, Class, Client, Cx};
use super::error::ApiError;
use super::{json, AppState};
use crate::auth;
use awm_proto::wire::ErrorCode;

/// How long `GET /healthz` reuses the store's answer.
pub const HEALTH_CACHE: Duration = Duration::from_secs(1);

/// `GET /healthz`: 200 when the store answers, 503 when it does not; no auth, no body details,
/// and outside the protocol (no `Awm-Client`, no rate limit, so a probe never competes with
/// members). The store's answer is kept for [`HEALTH_CACHE`], so requests at line rate cost one
/// store read a second (RVT2 m6).
pub(super) async fn healthz(State(app): State<AppState>) -> Response {
    let cached = {
        let c = app.health.lock().unwrap_or_else(|p| p.into_inner());
        c.filter(|(at, _)| at.elapsed() < HEALTH_CACHE)
            .map(|(_, ok)| ok)
    };
    let ok = match cached {
        Some(ok) => ok,
        None => {
            let ok = app.store.restore_state().await.is_ok();
            *app.health.lock().unwrap_or_else(|p| p.into_inner()) = Some((Instant::now(), ok));
            ok
        }
    };
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

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// `POST /internal/retention`: Cloud Scheduler's hourly call (plan-v3-team §6.1). It carries a
/// bearer token whose SHA-256 is `ServerConfig::internal_token_hash`; without that setting the
/// route does not exist. It runs TM9's retention runner once and nothing else.
pub(super) async fn internal_retention(
    State(app): State<AppState>,
    req: Request,
) -> Result<Response, ApiError> {
    let Some(expected) = app.config.internal_token_hash.as_deref() else {
        return Err(ApiError::not_found("no such endpoint"));
    };
    let mut cx = Cx::open(&app, req, Client::Optional, Class::Anonymous, Cap::Body)?;
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
    let _ = cx.bytes().await?;
    let removed = app.run_retention(cx.now).await?.unwrap_or(0);
    json(&value!({ "removed": removed }))
}
