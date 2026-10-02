//! Members, invites, approvals and removals. Each handler that changes who belongs to the
//! organisation calls the `auth` operation, which reads the facts it needs from the store and
//! calls `authz::require` itself.

use awm_proto::wire::{ApproveRequest, InviteRequest, MembersResponse, RemoveRequest, RoleRequest};
use axum::extract::{Path, Request, State};
use axum::response::Response;

use super::ctx::{path_id, Cap, Class, Client, Cx};
use super::entry::check_handle;
use super::error::{parse_json, ApiError};
use super::{json, no_content, reply, AppState};
use crate::auth;
use crate::authz::Action;
use crate::delete;

/// `GET /v1/members`.
pub(super) async fn list_members(State(app): State<AppState>, req: Request) -> Response {
    reply(list_inner(&app, req).await)
}

async fn list_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let caller = cx.authenticate().await?;
    cx.authorise(&caller, Action::Members).await?;
    json(&MembersResponse {
        members: app.store.members().await?,
    })
}

/// `POST /v1/invites`.
pub(super) async fn create_invite(State(app): State<AppState>, req: Request) -> Response {
    reply(create_invite_inner(&app, req).await)
}

async fn create_invite_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let bytes = cx.bytes(Cap::Body).await?;
    check_handle(&bytes)?;
    let body: InviteRequest = parse_json(&bytes)?;
    let caller = cx.authenticate().await?;
    cx.restore_gate_for(&caller).await?;
    json(&auth::create_invite(&*app.store, &caller, body, cx.now).await?)
}

/// `DELETE /v1/invites/{id}`.
pub(super) async fn revoke_invite(
    State(app): State<AppState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    reply(revoke_invite_inner(&app, &id, req).await)
}

async fn revoke_invite_inner(app: &AppState, id: &str, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let id = path_id(id)?;
    let caller = cx.authenticate().await?;
    auth::revoke_invite(&*app.store, &caller, id, cx.now).await?;
    Ok(no_content())
}

/// `POST /v1/devices/{id}/approve`.
pub(super) async fn approve_device(
    State(app): State<AppState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    reply(approve_inner(&app, &id, req).await)
}

async fn approve_inner(app: &AppState, id: &str, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let id = path_id(id)?;
    let body: ApproveRequest = cx.json(Cap::Body).await?;
    let caller = cx.authenticate().await?;
    cx.restore_gate_for(&caller).await?;
    auth::approve(&*app.store, &caller, id, body, cx.now).await?;
    Ok(no_content())
}

/// `POST /v1/devices/{id}/revoke`.
pub(super) async fn revoke_device(
    State(app): State<AppState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    reply(revoke_device_inner(&app, &id, req).await)
}

async fn revoke_device_inner(app: &AppState, id: &str, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let id = path_id(id)?;
    let caller = cx.authenticate().await?;
    auth::revoke_device(&*app.store, &caller, id, cx.now).await?;
    Ok(no_content())
}

/// `POST /v1/members/{id}/remove`.
pub(super) async fn remove_member(
    State(app): State<AppState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    reply(remove_inner(&app, &id, req).await)
}

async fn remove_inner(app: &AppState, id: &str, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let id = path_id(id)?;
    let body: RemoveRequest = cx.json_or_empty().await?;
    let caller = cx.authenticate().await?;
    delete::remove_member(
        &*app.store,
        &caller,
        id,
        body.delete_records.unwrap_or(false),
        cx.now,
    )
    .await?;
    Ok(no_content())
}

/// `POST /v1/members/{id}/role`.
pub(super) async fn set_role(
    State(app): State<AppState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    reply(set_role_inner(&app, &id, req).await)
}

async fn set_role_inner(app: &AppState, id: &str, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let id = path_id(id)?;
    let body: RoleRequest = cx.json(Cap::Body).await?;
    let caller = cx.authenticate().await?;
    auth::set_role(&*app.store, &caller, id, body.role, cx.now).await?;
    Ok(no_content())
}
