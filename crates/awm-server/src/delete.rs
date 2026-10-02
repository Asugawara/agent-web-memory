//! Record deletion (plan-v3-team §3.6, §4.3.5, §5.6; `docs/sync-v1.md` §10): `POST /v1/delete`
//! and `awm team remove --delete-records`, over the store's primitives (TM6) and the
//! authorisation matrix (TM7).
//!
//! [`run`] adds to `Store::delete`:
//! - the permission (`auth::authorise` with `Action::Delete`, refusals audited) and a check
//!   that the caller's organisation is the store's (one organisation per store);
//! - 413 `too_large` (`delete_ids`) for more than 1,000 ids;
//! - `{all_mine}` and `{member}` at most once per hour per token (keyed on the device id, so a
//!   token rotation does not reset it): 429 `rate_limited` with `Retry-After`, read from the
//!   audit log, so the limit survives a restart; each one is audited a second time as a
//!   [`NOTICE_ACTION`] row, the notice admins read in their next `GET /v1/audit` (§4.3.5);
//! - `Store::checkpoint` after the deletion, so a 200 means the blobs' bytes have left the live
//!   database file and its WAL (`SqliteStore`: `secure_delete` plus `wal_checkpoint(TRUNCATE)`,
//!   §5.6). A failed checkpoint fails the request (500); the retry is idempotent by record id
//!   and checkpoints again.
//!
//! What the store guarantees underneath (TM6, TM9 F2): a record row is never deleted, only its
//! blob (the marker keeps the index and the id); record ownership is checked inside the
//! deleting transaction (403 for the whole request); `roster` records are never deleted
//! (crypto §7: every later joiner verifies the roster from the genesis), so the bulk scopes
//! skip them and `{ids}` naming one is refused with 400 `invalid_value` (`/ids`).
//!
//! Audit rows hold ids and counts only, never a blob or a handle (§5.5).

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Mutex;

use awm_proto::wire::{limits, DeleteRequest, DeleteResponse, ErrorBody, ErrorCode, Id};

use crate::auth::{self, AuthError, Caller};
use crate::authz::{Action, DeleteScope, Refusal};
use crate::store::{AuditEntry, Store, StoreError};

/// `{all_mine}` and `{member}` are limited to one per this many seconds per token (§4.3.5).
pub const BULK_INTERVAL_S: i64 = 3_600;

/// The audit action of the notice to admins that a bulk delete writes (§4.3.5). `target` is
/// the deleting device, `detail` the scope and the counts.
pub const NOTICE_ACTION: &str = "delete.notice";

// ---------------------------------------------------------------------------------------------
// Errors

/// A refused or failed deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteError {
    /// 401 `unauthenticated`, 403 `not_approved` or `forbidden` (the matrix, or a caller of
    /// another organisation).
    Refused(Refusal),
    /// The store's answer: 403 `forbidden` (another member's record, not an admin), 404
    /// (unknown member), 400 `invalid_value` (`/ids`: a roster record), 409 `last_admin`
    /// (removal), or a 500.
    Store(StoreError),
    /// 413 `too_large` with `limit: delete_ids`, `max: 1000`.
    TooManyIds { count: usize },
    /// 429 `rate_limited`: a bulk delete by this token within the hour.
    RateLimited { retry_after_s: u32 },
}

impl DeleteError {
    pub fn status(&self) -> u16 {
        match self {
            DeleteError::Refused(r) => r.status(),
            DeleteError::Store(e) => e.status(),
            DeleteError::TooManyIds { .. } => 413,
            DeleteError::RateLimited { .. } => 429,
        }
    }

    /// The error body (`docs/sync-v1.md` §13); `None` for a 500, which TM8 answers without a
    /// body.
    pub fn to_body(&self) -> Option<ErrorBody> {
        match self {
            DeleteError::Refused(r) => Some(r.to_body()),
            DeleteError::Store(e) => e.to_body(),
            DeleteError::TooManyIds { .. } => {
                let mut b = ErrorBody::new(ErrorCode::TooLarge, self.to_string());
                b.limit = Some("delete_ids".into());
                b.max = Some(limits::DELETE_IDS as u64);
                Some(b)
            }
            DeleteError::RateLimited { retry_after_s } => {
                let mut b = ErrorBody::new(ErrorCode::RateLimited, self.to_string());
                b.retry_after_s = Some(*retry_after_s);
                Some(b)
            }
        }
    }

    /// The `Retry-After` header value in seconds, for a 429.
    pub fn retry_after(&self) -> Option<u32> {
        match self {
            DeleteError::RateLimited { retry_after_s } => Some(*retry_after_s),
            _ => None,
        }
    }
}

impl fmt::Display for DeleteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeleteError::Refused(r) => fmt::Display::fmt(r, f),
            DeleteError::Store(e) => fmt::Display::fmt(e, f),
            DeleteError::TooManyIds { count } => write!(
                f,
                "{count} ids in one delete, at most {}",
                limits::DELETE_IDS
            ),
            DeleteError::RateLimited { retry_after_s } => write!(
                f,
                "one delete of all_mine or member per hour per token; retry in {retry_after_s} s"
            ),
        }
    }
}

impl std::error::Error for DeleteError {}

impl From<StoreError> for DeleteError {
    fn from(e: StoreError) -> DeleteError {
        DeleteError::Store(e)
    }
}

impl From<Refusal> for DeleteError {
    fn from(r: Refusal) -> DeleteError {
        DeleteError::Refused(r)
    }
}

impl From<AuthError> for DeleteError {
    fn from(e: AuthError) -> DeleteError {
        match e {
            AuthError::Refused(r) => DeleteError::Refused(r),
            AuthError::Store(e) => DeleteError::Store(e),
            AuthError::Random => DeleteError::Store(StoreError::Backend(
                "the system random source failed".into(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The TM1 stub, kept for its callers

/// The TM1 stub's signature, kept so that callers written against it still compile (TM8). It
/// has no store to act on and deletes nothing: use [`run`].
pub fn delete_record(_record_id: &str) -> Result<(), crate::store::StoreError> {
    Err(StoreError::Unsupported(
        "delete::delete_record has no store; use delete::run",
    ))
}

// ---------------------------------------------------------------------------------------------
// POST /v1/delete

/// `POST /v1/delete` for `caller` (`docs/sync-v1.md` §10.1). Checks, in order: the matrix
/// (401, 403), the caller's organisation (401), more than 1,000 ids (413), the bulk limit
/// (429); then `Store::delete` (ownership 403, unknown member 404, roster 400, idempotent by
/// id, pre-deletion of unknown ids), the notice row for a bulk delete, and the checkpoint.
pub async fn run(
    store: &dyn Store,
    caller: &Caller,
    req: DeleteRequest,
    now: i64,
) -> Result<DeleteResponse, DeleteError> {
    let scope = match &req {
        DeleteRequest::Ids(_) => DeleteScope::Ids,
        DeleteRequest::AllMine => DeleteScope::AllMine,
        DeleteRequest::Member(_) => DeleteScope::Member,
    };
    auth::authorise(store, caller, Action::Delete(scope), now).await?;
    let (Some(by), Some(device)) = (caller.actor(), caller.device().copied()) else {
        return Err(Refusal::Forbidden.into());
    };
    same_org(store, device.org_id, now).await?;
    if let DeleteRequest::Ids(ids) = &req {
        if ids.len() > limits::DELETE_IDS {
            return Err(DeleteError::TooManyIds { count: ids.len() });
        }
    }
    if scope == DeleteScope::Ids {
        let res = store.delete(req, by, now).await?;
        store.checkpoint().await?;
        return Ok(res);
    }
    // One bulk delete per token at a time in this process, so two concurrent requests cannot
    // both pass the check below; the second gets 429 as if the first had finished.
    let Some(_claim) = Claim::take(&BULK, device.device_id) else {
        return Err(DeleteError::RateLimited {
            retry_after_s: BULK_INTERVAL_S as u32,
        });
    };
    if let Some(last) = last_bulk_delete(store, device.device_id, now).await? {
        return Err(DeleteError::RateLimited {
            retry_after_s: retry_after(last, now),
        });
    }
    let detail_scope = match &req {
        DeleteRequest::Member(m) => format!("scope=member member={m}"),
        _ => "scope=all_mine".to_string(),
    };
    let res = store.delete(req, by, now).await?;
    store.checkpoint().await?;
    store
        .append_audit(AuditEntry {
            at: now,
            actor: Some(by.member_id),
            action: NOTICE_ACTION.into(),
            target: Some(device.device_id.to_string()),
            detail: Some(format!(
                "{detail_scope} deleted={} already={}",
                res.deleted, res.already
            )),
        })
        .await?;
    Ok(res)
}

/// `POST /v1/members/{id}/remove` with `delete_records` (`awm team remove @h
/// --delete-records`, §3.6): `auth::remove_member` (admin; revokes every token of the member,
/// sets `rotation_needed`, 409 `last_admin`, audited with the count), after the organisation
/// check, then the checkpoint when records were to be deleted. The member's `roster` records
/// stay (F2). Returns the number of records deleted.
pub async fn remove_member(
    store: &dyn Store,
    caller: &Caller,
    member_id: Id,
    delete_records: bool,
    now: i64,
) -> Result<u64, DeleteError> {
    auth::authorise(store, caller, Action::RemoveMember, now).await?;
    let device = caller.device().copied().ok_or(Refusal::Forbidden)?;
    same_org(store, device.org_id, now).await?;
    let n = auth::remove_member(store, caller, member_id, delete_records, now).await?;
    if delete_records {
        store.checkpoint().await?;
    }
    Ok(n)
}

/// The store holds one organisation; a caller of another one (a routing mistake in a
/// multi-tenant deployment) is 401 before anything is read or deleted.
async fn same_org(store: &dyn Store, org_id: Id, now: i64) -> Result<(), DeleteError> {
    match store.org(now).await? {
        Some(org) if org.org_id == org_id => Ok(()),
        _ => Err(Refusal::Unauthenticated.into()),
    }
}

/// The time of this device's last bulk delete within the hour before `now`, from the
/// [`NOTICE_ACTION`] rows of the audit log, read backwards from the head.
async fn last_bulk_delete(
    store: &dyn Store,
    device: Id,
    now: i64,
) -> Result<Option<i64>, StoreError> {
    let since = now - BULK_INTERVAL_S;
    let target = device.to_string();
    let page = i64::from(limits::AUDIT_PAGE);
    let mut end = store.audit(0, 1).await?.head;
    while end >= 0 {
        let from = (end - page + 1).max(0);
        let rows = store.audit(from as u64, limits::AUDIT_PAGE).await?.rows;
        let rows: Vec<_> = rows.into_iter().filter(|r| r.idx as i64 <= end).collect();
        let last = rows
            .iter()
            .filter(|r| {
                r.action == NOTICE_ACTION && r.target.as_deref() == Some(&target) && r.at > since
            })
            .map(|r| r.at)
            .max();
        if last.is_some() {
            return Ok(last);
        }
        if rows.iter().map(|r| r.at).min().is_none_or(|at| at <= since) {
            break;
        }
        end = from - 1;
    }
    Ok(None)
}

fn retry_after(last: i64, now: i64) -> u32 {
    u32::try_from((last + BULK_INTERVAL_S - now).max(1)).unwrap_or(u32::MAX)
}

// ---------------------------------------------------------------------------------------------
// In-process claims

/// Devices with a bulk delete in progress in this process.
static BULK: Mutex<BTreeSet<Id>> = Mutex::new(BTreeSet::new());

/// Membership of `key` in a set of in-progress operations, released on drop. Shared with
/// `retention` (one run per organisation at a time).
pub(crate) struct Claim {
    set: &'static Mutex<BTreeSet<Id>>,
    key: Id,
}

impl Claim {
    /// `None` when `key` is already claimed.
    pub(crate) fn take(set: &'static Mutex<BTreeSet<Id>>, key: Id) -> Option<Claim> {
        let inserted = set.lock().unwrap_or_else(|e| e.into_inner()).insert(key);
        // Built only when inserted: a `Claim` dropped here would release the holder's key.
        inserted.then(|| Claim { set, key })
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        let mut s = self.set.lock().unwrap_or_else(|e| e.into_inner());
        s.remove(&self.key);
    }
}
