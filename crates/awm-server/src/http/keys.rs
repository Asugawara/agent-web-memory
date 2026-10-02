//! Epoch keys and the device token: `GET /v1/keys`, `POST /v1/keys/rotate`,
//! `POST /v1/token/rotate`.

use awm_proto::wire::RotateRequest;
use axum::extract::{Request, State};
use axum::response::Response;

use super::ctx::{Cap, Class, Client, Cx};
use super::error::ApiError;
use super::{json, no_content, reply, AppState};
use crate::auth;
use crate::authz::{self, Action};

/// `GET /v1/keys`: the calling device's wraps; a pending device may read them.
pub(super) async fn get_keys(State(app): State<AppState>, req: Request) -> Response {
    reply(keys_inner(&app, req).await)
}

async fn keys_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let caller = cx.authenticate().await?;
    cx.authorise(&caller, Action::Keys).await?;
    let device = caller
        .device()
        .ok_or_else(|| ApiError::from(authz::Refusal::Unauthenticated))?;
    json(&app.store.keys(device.device_id).await?)
}

/// `POST /v1/keys/rotate`.
pub(super) async fn rotate_keys(State(app): State<AppState>, req: Request) -> Response {
    reply(rotate_inner(&app, req).await)
}

async fn rotate_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let body: RotateRequest = cx.json(Cap::Body).await?;
    let caller = cx.authenticate().await?;
    cx.authorise(&caller, Action::RotateKeys).await?;
    let actor = caller
        .actor()
        .ok_or_else(|| ApiError::from(authz::Refusal::Forbidden))?;
    app.store
        .rotate_keys(body.epoch, body.wraps, actor, cx.now)
        .await?;
    Ok(no_content())
}

/// `POST /v1/token/rotate`: the old token stops at once.
pub(super) async fn rotate_token(State(app): State<AppState>, req: Request) -> Response {
    reply(token_inner(&app, req).await)
}

async fn token_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let caller = cx.authenticate().await?;
    json(&auth::rotate_token(&*app.store, &caller, cx.now).await?)
}
