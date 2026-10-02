//! Organisation administration: the audit log, settings, `restore/complete`, and the export.

use awm_proto::wire::{AuditQuery, RestoreCompleteRequest, SettingsUpdate};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue};
use axum::response::Response;

use super::ctx::{Cap, Class, Client, Cx};
use super::error::ApiError;
use super::{json, no_content, reply, AppState};
use crate::authz::{self, Action};
use crate::store::AuditEntry;

/// `GET /v1/audit`.
pub(super) async fn audit(State(app): State<AppState>, req: Request) -> Response {
    reply(audit_inner(&app, req).await)
}

async fn audit_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let page = app.config.limits.audit_page;
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let q: AuditQuery = cx.query()?;
    let caller = cx.authenticate().await?;
    cx.authorise(&caller, Action::ReadAudit).await?;
    let limit = match q.limit {
        None => page,
        Some(n) if (1..=page).contains(&n) => n,
        Some(_) => {
            return Err(ApiError::invalid(
                "limit",
                "limit is 0 or above the page size",
            ))
        }
    };
    json(&app.store.audit(q.from, limit).await?)
}

/// `GET /v1/org/settings`.
pub(super) async fn get_settings(State(app): State<AppState>, req: Request) -> Response {
    reply(get_settings_inner(&app, req).await)
}

async fn get_settings_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let caller = cx.authenticate().await?;
    cx.authorise(&caller, Action::ReadSettings).await?;
    let org = app
        .store
        .org(cx.now)
        .await?
        .ok_or_else(|| ApiError::not_found("no organisation"))?;
    json(&org.settings)
}

/// `PUT /v1/org/settings`.
pub(super) async fn put_settings(State(app): State<AppState>, req: Request) -> Response {
    reply(put_settings_inner(&app, req).await)
}

async fn put_settings_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let caller = cx.authenticate().await?;
    // The widest settings write first, so a member's body is not read (RVT2 B1).
    cx.authorise(&caller, Action::WriteSettings { min_client: false })
        .await?;
    let update: SettingsUpdate = cx.json_or_empty().await?;
    let action = Action::WriteSettings {
        min_client: update.min_client.is_some(),
    };
    cx.authorise(&caller, action).await?;
    let settings = app
        .store
        .update_settings(
            update,
            app.config.release_floor.clone(),
            caller.actor(),
            cx.now,
        )
        .await?;
    json(&settings)
}

/// `POST /v1/restore/complete`: ends `restore_pending` for the current generation.
pub(super) async fn complete_restore(State(app): State<AppState>, req: Request) -> Response {
    reply(complete_restore_inner(&app, req).await)
}

async fn complete_restore_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let caller = cx.authenticate().await?;
    cx.authorise(&caller, Action::CompleteRestore).await?;
    let body: RestoreCompleteRequest = cx.json(Cap::Body).await?;
    let actor = caller
        .actor()
        .ok_or_else(|| ApiError::from(authz::Refusal::Forbidden))?;
    app.store
        .complete_restore(body.generation, actor, cx.now)
        .await?;
    Ok(no_content())
}

/// `GET /v1/export`: the organisation as the canonical SQLite file. The file is written to a
/// private temporary path, read, and removed before the response is sent; it is held in memory
/// for the response (no streaming body type is available without a new dependency).
pub(super) async fn export(State(app): State<AppState>, req: Request) -> Response {
    reply(export_inner(&app, req).await)
}

async fn export_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let caller = cx.authenticate().await?;
    cx.authorise(&caller, Action::Export).await?;

    let path = app.config.export_dir.join(format!(
        "awm-export-{}.sqlite",
        awm_proto::wire::Id::new_v4()
    ));
    let counts = app.store.export_canonical(path.clone()).await;
    let bytes = match &counts {
        Ok(_) => tokio::fs::read(&path).await,
        Err(_) => Ok(Vec::new()),
    };
    let _ = tokio::fs::remove_file(&path).await;
    let counts = counts?;
    let bytes = bytes.map_err(|e| ApiError::internal(format!("export read: {}", e.kind())))?;

    let rows: u64 = counts.0.iter().map(|(_, n)| n).sum();
    app.store
        .append_audit(AuditEntry {
            at: cx.now,
            actor: caller.device().map(|d| d.member_id),
            action: "export".into(),
            target: None,
            detail: Some(format!("rows={rows} bytes={}", bytes.len())),
        })
        .await?;

    let mut resp = Response::new(Body::from(bytes));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.sqlite3"),
    );
    Ok(resp)
}
