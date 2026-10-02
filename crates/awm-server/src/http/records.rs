//! Records and deletions: `POST /v1/records` (`docs/sync-v1.md` §9.1 steps 1-3 here, 4-5 in the
//! store), `GET /v1/records`, `POST /v1/pull`, `GET /v1/deletions`, `POST /v1/delete`.

use std::collections::HashSet;

use awm_proto::wire::{
    check_envelope, DeleteRequest, DeletionsQuery, KnownTag, PullRequest, PushItem, PushRequest,
    RecordsQuery,
};
use axum::extract::{Request, State};
use axum::response::Response;

use super::ctx::{Cap, Class, Client, Cx};
use super::error::ApiError;
use super::{json, reply, AppState};
use crate::authz::{self, Action};
use crate::delete;
use crate::store::PushBatch;

const DAY_S: i64 = 86_400;
/// Indexes stay below 2^53 (`docs/sync-v1.md` §1).
const MAX_IDX: u64 = 1 << 53;

/// `POST /v1/records`.
pub(super) async fn push(State(app): State<AppState>, req: Request) -> Response {
    reply(push_inner(&app, req).await)
}

async fn push_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let limits = &app.config.limits;
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Batch)?;

    // Step 1: the body.
    let body: PushRequest = cx.json(Cap::Batch).await?;
    let items = body.records;
    if items.is_empty() {
        return Err(ApiError::invalid(
            "/records",
            "a push has at least one item",
        ));
    }
    if items.len() > limits.batch_records {
        return Err(ApiError::too_large(
            "batch_records",
            limits.batch_records as u64,
            None,
        ));
    }
    if let Some(i) = items.iter().position(|it| it.idx() >= MAX_IDX) {
        return Err(ApiError::invalid(
            &format!("/records/{i}/idx"),
            "idx is too large",
        ));
    }

    // Step 2: the caller.
    let caller = cx.authenticate().await?;
    cx.authorise(&caller, Action::Push(KnownTag::Rec)).await?;
    cx.restore_gate_for(&caller).await?;
    if authz::push_needs_min_client(&items) {
        let min = cx.min_client().await?;
        cx.require_client_at_least(&min)?;
    }
    let mut tags = Vec::new();
    for (i, item) in items.iter().enumerate() {
        match item.tag().known() {
            Some(t) if !tags.contains(&t) => tags.push(t),
            Some(_) => {}
            None => {
                return Err(ApiError::invalid(
                    &format!("/records/{i}/tag"),
                    "tag is not one of rec, flag, stats, policy, roster",
                ))
            }
        }
    }
    for tag in tags {
        cx.authorise(&caller, Action::Push(tag)).await?;
    }
    let actor = caller
        .actor()
        .ok_or_else(|| ApiError::from(authz::Refusal::Forbidden))?;
    quota(&cx, &actor, &items).await?;

    // Step 3: each blob.
    for (i, item) in items.iter().enumerate() {
        if let PushItem::Record(r) = item {
            let n = r.blob.0.len();
            if n > limits.blob_bytes {
                return Err(ApiError::too_large(
                    "blob",
                    limits.blob_bytes as u64,
                    Some(i as u32),
                ));
            }
            if check_envelope(&r.blob.0).is_err() {
                return Err(ApiError::bad_envelope(i as u32));
            }
        }
    }

    // Steps 4 and 5.
    let resp = app
        .store
        .push(PushBatch {
            member_id: actor.member_id,
            device_id: actor.device_id,
            items,
            now: cx.now,
        })
        .await?;
    json(&resp)
}

/// The member's daily quota: 429 `rate_limited` (`records_per_day`) with `Retry-After` until
/// 00:00 UTC. Markers do not count, and neither does anything pushed in the 24 hours after a
/// new generation (the re-seed).
async fn quota(cx: &Cx, actor: &crate::store::Actor, items: &[PushItem]) -> Result<(), ApiError> {
    let records = items
        .iter()
        .filter(|i| matches!(i, PushItem::Record(_)))
        .count() as u64;
    if records == 0 {
        return Ok(());
    }
    let state = cx.app.store.restore_state().await?;
    if state.restored_at.is_some_and(|t| cx.now - t < DAY_S) {
        return Ok(());
    }
    let day_start = cx.now - cx.now.rem_euclid(DAY_S);
    let used = cx
        .app
        .store
        .pushed_since(actor.member_id, day_start)
        .await?;
    if used + records > u64::from(cx.app.config.limits.records_per_day) {
        let retry = (day_start + DAY_S - cx.now).max(1) as u32;
        return Err(ApiError::rate_limited(retry, Some("records_per_day")));
    }
    Ok(())
}

fn page_limit(limit: Option<u32>, max: u32, field: &str) -> Result<u32, ApiError> {
    match limit {
        None => Ok(max),
        Some(n) if (1..=max).contains(&n) => Ok(n),
        Some(_) => Err(ApiError::invalid(
            field,
            "limit is 0 or above the page size",
        )),
    }
}

/// `GET /v1/records`: one stream.
pub(super) async fn get_records(State(app): State<AppState>, req: Request) -> Response {
    reply(records_inner(&app, req).await)
}

async fn records_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let limits = &app.config.limits;
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let q: RecordsQuery = cx.query()?;
    let caller = cx.authenticate().await?;
    cx.authorise(&caller, Action::Pull).await?;
    let limit = page_limit(q.limit, limits.pull_records, "limit")?;
    if q.from >= MAX_IDX {
        return Err(ApiError::invalid("from", "from is too large"));
    }
    let out = app
        .store
        .records(
            q.member,
            q.device,
            q.tag,
            q.from,
            limit,
            limits.pull_response_bytes,
        )
        .await?;
    json(&out)
}

/// `POST /v1/pull`: up to 1,000 cursors.
pub(super) async fn pull(State(app): State<AppState>, req: Request) -> Response {
    reply(pull_inner(&app, req).await)
}

async fn pull_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let limits = &app.config.limits;
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let body: PullRequest = cx.json(Cap::Body).await?;
    if body.cursors.len() > limits.pull_cursors {
        return Err(ApiError::too_large(
            "pull_cursors",
            limits.pull_cursors as u64,
            None,
        ));
    }
    let caller = cx.authenticate().await?;
    cx.authorise(&caller, Action::Pull).await?;
    if body.cursors.is_empty() {
        return Err(ApiError::invalid(
            "/cursors",
            "a pull has at least one cursor",
        ));
    }
    let mut seen = HashSet::new();
    if !body
        .cursors
        .iter()
        .all(|c| seen.insert((c.member, c.device, c.tag.clone())))
    {
        return Err(ApiError::invalid("/cursors", "duplicate cursor"));
    }
    if let Some(i) = body.cursors.iter().position(|c| c.from >= MAX_IDX) {
        return Err(ApiError::invalid(
            &format!("/cursors/{i}/from"),
            "from is too large",
        ));
    }
    if !(1..=limits.pull_records).contains(&body.limit) {
        return Err(ApiError::invalid(
            "/limit",
            "limit is 0 or above the page size",
        ));
    }
    let out = app
        .store
        .pull(body.cursors, body.limit, limits.pull_response_bytes)
        .await?;
    json(&out)
}

/// `GET /v1/deletions`.
pub(super) async fn deletions(State(app): State<AppState>, req: Request) -> Response {
    reply(deletions_inner(&app, req).await)
}

async fn deletions_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let limits = &app.config.limits;
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let q: DeletionsQuery = cx.query()?;
    let caller = cx.authenticate().await?;
    cx.authorise(&caller, Action::Pull).await?;
    let limit = page_limit(q.limit, limits.deletions_page, "limit")?;
    if q.from >= MAX_IDX {
        return Err(ApiError::invalid("from", "from is too large"));
    }
    json(&app.store.deletions(q.from, limit).await?)
}

/// `POST /v1/delete`: by ids, `all_mine`, or (admins) by member.
pub(super) async fn delete_records(State(app): State<AppState>, req: Request) -> Response {
    reply(delete_inner(&app, req).await)
}

async fn delete_inner(app: &AppState, req: Request) -> Result<Response, ApiError> {
    let limits = &app.config.limits;
    let mut cx = Cx::open(app, req, Client::Required, Class::Token, Cap::Body)?;
    let body: DeleteRequest = cx.json(Cap::Body).await?;
    // Kept in front of `delete::run` (which checks the same cap after authorising): it rejects an
    // oversized list before the token lookup.
    if let DeleteRequest::Ids(ids) = &body {
        if ids.len() > limits.delete_ids {
            return Err(ApiError::too_large(
                "delete_ids",
                limits.delete_ids as u64,
                None,
            ));
        }
    }
    let caller = cx.authenticate().await?;
    json(&delete::run(&*app.store, &caller, body, cx.now).await?)
}
