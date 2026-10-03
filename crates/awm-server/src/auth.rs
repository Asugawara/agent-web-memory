//! Authentication (plan-v3-team §4.10, `docs/sync-v1.md` §3.2) and the operations whose
//! permission depends on stored state: bootstrap, join, invites, approval, revocation,
//! removal, role changes and token rotation.
//!
//! Tokens are generated here and only their SHA-256 (lower-case hex, [`hash`]) is handed to
//! the store; the plaintext of a device or invite token leaves the server once, in the
//! response that issues it. [`authenticate`] turns an `Authorization` header into a
//! [`Caller`]; every permission is then decided by [`crate::authz::require`], which the
//! operations below call (through [`authorise`]) after reading the facts an
//! [`crate::authz::Action`] needs from the store. The server cannot verify a join MAC or a
//! wrap (it never holds the invite secret `S`): it stores them as given and the clients verify
//! them (`docs/sync-v1-crypto.md` §4-§6).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use awm_proto::crypto::{OsRng, Secret32};
use awm_proto::wire::{
    limits, ApproveRequest, BootstrapRequest, BootstrapResponse, BootstrapToken, DeviceToken,
    ErrorBody, Id, InviteKind, InviteRequest, InviteResponse, InviteToken, JoinRequest,
    JoinResponse, Role, TokenRotateResponse,
};

use crate::authz::{self, Action, Refusal};
use crate::store::{
    checksum, valid_token_hash, Actor, AuditEntry, NewBootstrap, NewInvite, NewJoin, OrgDefaults,
    Store, StoreError,
};

/// A bootstrap token is valid for 24 hours (plan-v3-team §4.10).
pub const BOOTSTRAP_TTL_S: i64 = 86_400;

const DAY_S: i64 = 86_400;
/// Characters of the secret that request logs may keep (`docs/sync-v1.md` §3.2).
const LOG_PREFIX_CHARS: usize = 6;
/// `awm_t_` / `awm_i_` + 36-character organisation id + `_`.
const ORG_SECRET_AT: usize = 6 + 36 + 1;

// ---------------------------------------------------------------------------------------------
// Errors

/// A failed authentication or authenticated operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// 401 or 403, decided by [`authz::require`] or by [`authenticate`].
    Refused(Refusal),
    /// The store's answer (410 `invite_gone`, 400 `invalid_value`, 404, 409 `last_admin`, ...;
    /// `StoreError::status` and `to_body` give the response).
    Store(StoreError),
    /// The operating system's random source failed (500, no body).
    Random,
}

impl AuthError {
    pub fn status(&self) -> u16 {
        match self {
            AuthError::Refused(r) => r.status(),
            AuthError::Store(e) => e.status(),
            AuthError::Random => 500,
        }
    }

    /// The error body; `None` for a 500, which TM8 answers without a body and logs.
    pub fn to_body(&self) -> Option<ErrorBody> {
        match self {
            AuthError::Refused(r) => Some(r.to_body()),
            AuthError::Store(e) => e.to_body(),
            AuthError::Random => None,
        }
    }

    fn invalid(field: &str) -> AuthError {
        AuthError::Store(StoreError::InvalidValue {
            field: field.to_string(),
        })
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Refused(r) => fmt::Display::fmt(r, f),
            AuthError::Store(e) => fmt::Display::fmt(e, f),
            AuthError::Random => f.write_str("the system random source failed"),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<Refusal> for AuthError {
    fn from(r: Refusal) -> AuthError {
        AuthError::Refused(r)
    }
}

impl From<StoreError> for AuthError {
    fn from(e: StoreError) -> AuthError {
        AuthError::Store(e)
    }
}

// ---------------------------------------------------------------------------------------------
// Tokens

/// SHA-256 of a token as 64 lower-case hex characters: what the store keeps and looks up.
pub fn hash(token: &str) -> String {
    checksum(token.as_bytes())
}

fn secret() -> Result<Secret32, AuthError> {
    Secret32::random_with(&mut OsRng).map_err(|_| AuthError::Random)
}

/// A new device token `awm_t_{org}_{secret}`: 32 random bytes, unpadded base64url.
pub fn new_device_token(org: Id) -> Result<DeviceToken, AuthError> {
    Ok(DeviceToken::new(org, secret()?.expose()))
}

/// A new invite token `awm_i_{org}_{secret}` (the server's half of an invite).
pub fn new_invite_token(org: Id) -> Result<InviteToken, AuthError> {
    Ok(InviteToken::new(org, secret()?.expose()))
}

/// A new bootstrap token `awm_b_{secret}`.
pub fn new_bootstrap_token() -> Result<BootstrapToken, AuthError> {
    Ok(BootstrapToken::new(secret()?.expose()))
}

/// The kind of a presented token, from its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    Device,
    Invite,
    Bootstrap,
}

/// A presented token after [`parse`]: its kind, its organisation (none for a bootstrap token),
/// its hash and the log prefix. The plaintext is not kept.
#[derive(Clone, PartialEq, Eq)]
pub struct Presented {
    kind: TokenKind,
    org: Option<Id>,
    hash: String,
    log_prefix: String,
}

impl Presented {
    pub fn kind(&self) -> TokenKind {
        self.kind
    }

    /// The `{org}` part, read before any lookup (the cloud sets row-level security from it).
    pub fn org(&self) -> Option<Id> {
        self.org
    }

    /// SHA-256 hex of the whole token.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// What request logs keep: the organisation id and the first 6 characters of the secret
    /// (plan-v3-team §4.3.1 "token prefix").
    pub fn log_prefix(&self) -> &str {
        &self.log_prefix
    }
}

impl fmt::Debug for Presented {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Presented")
            .field("kind", &self.kind)
            .field("org", &self.org)
            .field("hash", &format_args!("{}…", &self.hash[..8]))
            .finish()
    }
}

/// Parses a token of any kind (`awm_t_`, `awm_i_`, `awm_b_`); anything else is 401.
pub fn parse_token(token: &str) -> Result<Presented, Refusal> {
    let bad = |_| Refusal::Unauthenticated;
    let (kind, org, secret_at) = if token.starts_with(DeviceToken::PREFIX) {
        let t = DeviceToken::parse(token).map_err(bad)?;
        (TokenKind::Device, Some(t.org()), ORG_SECRET_AT)
    } else if token.starts_with(InviteToken::PREFIX) {
        let t = InviteToken::parse(token).map_err(bad)?;
        (TokenKind::Invite, Some(t.org()), ORG_SECRET_AT)
    } else if token.starts_with(BootstrapToken::PREFIX) {
        BootstrapToken::parse(token).map_err(bad)?;
        (TokenKind::Bootstrap, None, BootstrapToken::PREFIX.len())
    } else {
        return Err(Refusal::Unauthenticated);
    };
    let org_text = org.map(|o| format!("{o}_")).unwrap_or_default();
    Ok(Presented {
        kind,
        org,
        hash: hash(token),
        log_prefix: format!(
            "{}{org_text}{}",
            &token[..6],
            &token[secret_at..secret_at + LOG_PREFIX_CHARS]
        ),
    })
}

/// Parses the value of an `Authorization` header, `Bearer <token>` (the scheme is
/// case-insensitive, RFC 9110 §11.1). Malformed values are 401 `unauthenticated`.
pub fn parse(header: &str) -> Result<Presented, Refusal> {
    let (scheme, token) = header.split_once(' ').ok_or(Refusal::Unauthenticated)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(Refusal::Unauthenticated);
    }
    parse_token(token)
}

// ---------------------------------------------------------------------------------------------
// Callers

/// An authenticated device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Device {
    pub org_id: Id,
    pub member_id: Id,
    pub device_id: Id,
}

/// The billing owner's web session (cloud). TM20 fills it; [`authenticate`] never returns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CloudOwner {
    pub org_id: Id,
}

/// Who makes a request. `Debug` prints ids only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Caller {
    /// No `Authorization` header (`info`, `bootstrap`, `join`).
    Anonymous,
    /// A device that joined and waits for approval.
    Pending(Device),
    /// An approved device of a member.
    Member(Device),
    /// An approved device of an admin.
    Admin(Device),
    /// The cloud's billing owner (TM20).
    CloudOwner(CloudOwner),
}

/// What the per-token and per-IP limits of plan-v3-team §4.3.5 and §4.11 key on (TM8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateKey {
    /// Unauthenticated: TM8 keys on the client address (30 per minute; joins 10 per hour).
    Address,
    /// A device token, by device id, so rotating the token does not reset its limits
    /// (60 per minute, burst 120; bulk deletes 1 per hour).
    Device(Id),
    /// The cloud owner's session (TM20).
    Owner(Id),
}

impl Caller {
    /// The device behind the token, approved or pending.
    pub fn device(&self) -> Option<&Device> {
        match self {
            Caller::Pending(d) | Caller::Member(d) | Caller::Admin(d) => Some(d),
            Caller::Anonymous | Caller::CloudOwner(_) => None,
        }
    }

    /// The store's `Actor` for an approved device (record ownership on delete, audit rows).
    pub fn actor(&self) -> Option<Actor> {
        match self {
            Caller::Member(d) | Caller::Admin(d) => Some(Actor {
                member_id: d.member_id,
                device_id: d.device_id,
                admin: matches!(self, Caller::Admin(_)),
            }),
            _ => None,
        }
    }

    pub fn rate_key(&self) -> RateKey {
        match self {
            Caller::Anonymous => RateKey::Address,
            Caller::Pending(d) | Caller::Member(d) | Caller::Admin(d) => {
                RateKey::Device(d.device_id)
            }
            Caller::CloudOwner(o) => RateKey::Owner(o.org_id),
        }
    }
}

/// Resolves the `Authorization` header of a request (`None` when absent) to a [`Caller`].
///
/// 401 for a malformed token, a token that is not a device token, an organisation the store
/// does not hold, an unknown hash, and a revoked device or member. The organisation is
/// compared before the hash lookup. A successful authentication records the day the device
/// was seen (the store writes once per day).
pub async fn authenticate(
    store: &dyn Store,
    header: Option<&str>,
    now: i64,
) -> Result<Caller, AuthError> {
    authenticate_with(store, header, now, || async {
        Ok(store.org(now).await?.map(|o| o.org_id))
    })
    .await
}

/// [`authenticate`] with the organisation id supplied by `org_id` (called only when a token is
/// presented and parses), so a request that reads the organisation anyway reads it once.
pub async fn authenticate_with<F, Fut>(
    store: &dyn Store,
    header: Option<&str>,
    now: i64,
    org_id: F,
) -> Result<Caller, AuthError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Option<Id>, StoreError>>,
{
    let Some(header) = header else {
        return Ok(Caller::Anonymous);
    };
    let presented = parse(header)?;
    if presented.kind != TokenKind::Device {
        return Err(Refusal::Unauthenticated.into());
    }
    let org_id = org_id().await?.ok_or(Refusal::Unauthenticated)?;
    if presented.org != Some(org_id) {
        return Err(Refusal::Unauthenticated.into());
    }
    let dev = store
        .auth_device(presented.hash)
        .await?
        .ok_or(Refusal::Unauthenticated)?;
    if dev.device_revoked || dev.member_revoked || dev.org_id != org_id {
        return Err(Refusal::Unauthenticated.into());
    }
    store
        .touch_device(dev.device_id, now.div_euclid(DAY_S))
        .await?;
    let d = Device {
        org_id: dev.org_id,
        member_id: dev.member_id,
        device_id: dev.device_id,
    };
    Ok(if !dev.approved {
        Caller::Pending(d)
    } else if dev.role == Role::Admin {
        Caller::Admin(d)
    } else {
        Caller::Member(d)
    })
}

/// [`authz::require`], plus the audit row of a refusal when a token was presented (pending,
/// member or admin device): actor = the member, target = the device, detail = the action and
/// the error code. Anonymous refusals are not audited (the request log has them), so a caller
/// without a token cannot grow the audit table. A pending device's `not_approved` refusals are
/// audited once per device and hour in this process (RVT2 m1): an unapproved device that keeps
/// polling adds at most 24 rows a day, not one per request.
pub async fn authorise(
    store: &dyn Store,
    caller: &Caller,
    action: Action,
    now: i64,
) -> Result<(), AuthError> {
    let Err(refusal) = authz::require(caller, action) else {
        return Ok(());
    };
    if let (Caller::Pending(d), Refusal::NotApproved) = (caller, refusal) {
        if !first_pending_refusal_this_hour(d.device_id, now) {
            return Err(refusal.into());
        }
    }
    if let Some(d) = caller.device() {
        let code = match refusal {
            Refusal::Unauthenticated => "unauthenticated",
            Refusal::NotApproved => "not_approved",
            Refusal::Forbidden => "forbidden",
        };
        store
            .append_audit(AuditEntry {
                at: now,
                actor: Some(d.member_id),
                action: "authz.refused".into(),
                target: Some(d.device_id.to_string()),
                detail: Some(format!("action={} error={code}", action.name())),
            })
            .await?;
    }
    Err(refusal.into())
}

/// Pending devices whose `not_approved` refusal was audited, with the time of that row.
static PENDING_AUDITED: Mutex<BTreeMap<Id, i64>> = Mutex::new(BTreeMap::new());

/// Whether `device` has no audited `not_approved` refusal within the hour before `now`; if so,
/// records `now` as its audited one. Entries older than an hour are dropped as it goes.
fn first_pending_refusal_this_hour(device: Id, now: i64) -> bool {
    const HOUR_S: i64 = 3_600;
    let mut m = PENDING_AUDITED.lock().unwrap_or_else(|e| e.into_inner());
    if m.len() > 10_000 {
        m.retain(|_, at| (0..HOUR_S).contains(&(now - *at)));
    }
    match m.get(&device) {
        Some(at) if (0..HOUR_S).contains(&(now - at)) => false,
        _ => {
            m.insert(device, now);
            true
        }
    }
}

/// The approved caller's actor after a successful [`authorise`].
fn actor_of(caller: &Caller) -> Result<Actor, AuthError> {
    caller.actor().ok_or(AuthError::Refused(Refusal::Forbidden))
}

// ---------------------------------------------------------------------------------------------
// Bootstrap

/// `awm serve init`: a new bootstrap token, valid for 24 hours, replacing an earlier one.
/// The store refuses (`NotEmpty`) once the organisation exists. Print the token once.
pub async fn issue_bootstrap(store: &dyn Store, now: i64) -> Result<BootstrapToken, AuthError> {
    let token = new_bootstrap_token()?;
    store
        .set_bootstrap(hash(token.as_str()), now + BOOTSTRAP_TTL_S)
        .await?;
    Ok(token)
}

/// Path A (Cloud Run, plan-v3-team §4.8.1): installs `AWM_BOOTSTRAP_SHA256` and
/// `AWM_BOOTSTRAP_EXPIRES` at start while no organisation exists. Returns whether it was
/// installed; once the first admin exists it is ignored. A value that is not 64 lower-case hex
/// characters is `InvalidValue`.
pub async fn install_bootstrap_hash(
    store: &dyn Store,
    sha256_hex: &str,
    expires_at: i64,
    now: i64,
) -> Result<bool, AuthError> {
    if !valid_token_hash(sha256_hex) {
        return Err(AuthError::invalid("AWM_BOOTSTRAP_SHA256"));
    }
    if store.org(now).await?.is_some() {
        return Ok(false);
    }
    match store
        .set_bootstrap(sha256_hex.to_string(), expires_at)
        .await
    {
        Ok(()) => Ok(true),
        // The first admin appeared between the two calls.
        Err(StoreError::NotEmpty) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// `POST /v1/bootstrap` (anonymous; the body's token authenticates): registers the
/// organisation, its first admin and that admin's approved device, and returns the device
/// token once.
///
/// A wrong, used or expired token, or an existing organisation, is 410 `invite_gone`; of two
/// concurrent uses one wins (the store compares and consumes in one transaction). The device's
/// first push is its `genesis` roster record at (member, device, `roster`, 0) under epoch 0:
/// the store binds the stream to the token, accepts only `idx = head + 1` and only the current
/// epoch, which stays 0 until the first rotation; the clients check the rest (B1,
/// `docs/sync-v1-crypto.md` §7).
pub async fn bootstrap(
    store: &dyn Store,
    req: BootstrapRequest,
    defaults: OrgDefaults,
    now: i64,
) -> Result<BootstrapResponse, AuthError> {
    let device_token = new_device_token(req.org_id)?;
    let member_id = store
        .bootstrap(NewBootstrap {
            bootstrap_token_hash: hash(req.bootstrap_token.as_str()),
            org_id: req.org_id,
            handle: req.handle,
            device_id: req.device_id,
            device_pubkey: req.device_pubkey,
            device_token_hash: hash(device_token.as_str()),
            defaults,
            now,
        })
        .await?;
    Ok(BootstrapResponse {
        org_id: req.org_id,
        member_id,
        device_id: req.device_id,
        device_token,
        role: Role::Admin,
    })
}

// ---------------------------------------------------------------------------------------------
// Joins and invites

/// `POST /v1/join` (anonymous; the invite token authenticates): stores the joining device,
/// its public key and its join MAC as given, pending until approval, and returns the device
/// token once.
///
/// 401 when the invite token's `{org}` is not this server's organisation; 410 `invite_gone`
/// for an unknown, used, revoked or expired invite; 400 `invalid_value` (`/handle`) when the
/// handle differs from the invite's; 409 `device_conflict` for a known device id.
pub async fn join(
    store: &dyn Store,
    req: JoinRequest,
    now: i64,
) -> Result<JoinResponse, AuthError> {
    let org = req.invite_token.org();
    let served = store.org(now).await?.ok_or(Refusal::Unauthenticated)?;
    if served.org_id != org {
        return Err(Refusal::Unauthenticated.into());
    }
    let device_token = new_device_token(org)?;
    let joined = store
        .join(NewJoin {
            invite_id: req.invite_id,
            invite_token_hash: hash(req.invite_token.as_str()),
            handle: req.handle,
            device_id: req.device_id,
            device_pubkey: req.device_pubkey,
            join_mac: req.join_mac,
            device_token_hash: hash(device_token.as_str()),
            now,
        })
        .await?;
    Ok(JoinResponse {
        org_id: joined.org_id,
        member_id: joined.member_id,
        device_id: req.device_id,
        device_token,
        pending: true,
    })
}

/// `POST /v1/invites`: an admin invites a member (any role) or a device of any member; a
/// member invites a device of their own. `kind: Unknown` is 400 `invalid_value` (`/kind`),
/// `expires_days` outside 1-30 is 400 (`/expires_days`). Returns the invite token once.
pub async fn create_invite(
    store: &dyn Store,
    caller: &Caller,
    req: InviteRequest,
    now: i64,
) -> Result<InviteResponse, AuthError> {
    let widest = Action::CreateInvite {
        kind: InviteKind::Device,
        for_self: true,
    };
    authorise(store, caller, widest, now).await?;
    if req.kind == InviteKind::Unknown {
        return Err(AuthError::invalid("/kind"));
    }
    let days = req.expires_days.unwrap_or(limits::INVITE_DAYS_DEFAULT);
    if !(1..=limits::INVITE_DAYS_MAX).contains(&days) {
        return Err(AuthError::invalid("/expires_days"));
    }
    let by = actor_of(caller)?;
    let for_self = req.kind == InviteKind::Device
        && store
            .member(by.member_id)
            .await?
            .is_some_and(|m| m.handle == req.handle);
    let action = Action::CreateInvite {
        kind: req.kind,
        for_self,
    };
    authorise(store, caller, action, now).await?;
    let org = caller.device().ok_or(Refusal::Forbidden)?.org_id;
    let invite_id = Id::new_v4();
    let invite_token = new_invite_token(org)?;
    let expires_at = now + i64::from(days) * DAY_S;
    store
        .create_invite(NewInvite {
            invite_id,
            token_hash: hash(invite_token.as_str()),
            kind: req.kind,
            handle: req.handle,
            role: req.role,
            expires_at,
            by,
            now,
        })
        .await?;
    Ok(InviteResponse {
        invite_id,
        invite_token,
        expires_at,
    })
}

/// `DELETE /v1/invites/{id}`: an admin, or the invite's creating member. 404 for an unknown id.
pub async fn revoke_invite(
    store: &dyn Store,
    caller: &Caller,
    invite_id: Id,
    now: i64,
) -> Result<(), AuthError> {
    let widest = Action::RevokeInvite {
        created_by_caller: true,
    };
    authorise(store, caller, widest, now).await?;
    let by = actor_of(caller)?;
    let invite = store.invite(invite_id).await?.ok_or(StoreError::NotFound)?;
    let action = Action::RevokeInvite {
        created_by_caller: invite.created_by_member == by.member_id,
    };
    authorise(store, caller, action, now).await?;
    Ok(store.revoke_invite(invite_id, by, now).await?)
}

// ---------------------------------------------------------------------------------------------
// Approval, revocation, removal, roles, token rotation

/// `POST /v1/devices/{id}/approve`: the invite's creating member approves, an admin for a
/// member invite or for another member's device invite, the member for their own device
/// invite. A device without an invite (the bootstrap device) or with an `Unknown` kind is
/// refused. The store keeps the wraps as given (the first per epoch stays) and checks that
/// every epoch is covered; it cannot verify them, the new device does (with `S`).
pub async fn approve(
    store: &dyn Store,
    caller: &Caller,
    device_id: Id,
    req: ApproveRequest,
    now: i64,
) -> Result<(), AuthError> {
    let widest = Action::Approve {
        kind: InviteKind::Device,
        created_by_caller: true,
        for_self: true,
    };
    authorise(store, caller, widest, now).await?;
    let by = actor_of(caller)?;
    let device = store.device(device_id).await?.ok_or(StoreError::NotFound)?;
    let invite = match device.invite_id {
        Some(id) => store.invite(id).await?,
        None => None,
    };
    let (kind, created_by_caller) = invite.map_or((InviteKind::Unknown, false), |i| {
        (i.kind, i.created_by_member == by.member_id)
    });
    let action = Action::Approve {
        kind,
        created_by_caller,
        for_self: device.member_id == by.member_id,
    };
    authorise(store, caller, action, now).await?;
    Ok(store.approve_device(device_id, req.wraps, by, now).await?)
}

/// `POST /v1/devices/{id}/revoke`: an admin any device, a member their own devices. The store
/// sets `rotation_needed`. 404 for an unknown device.
pub async fn revoke_device(
    store: &dyn Store,
    caller: &Caller,
    device_id: Id,
    now: i64,
) -> Result<(), AuthError> {
    let widest = Action::RevokeDevice { for_self: true };
    authorise(store, caller, widest, now).await?;
    let by = actor_of(caller)?;
    let device = store.device(device_id).await?.ok_or(StoreError::NotFound)?;
    let action = Action::RevokeDevice {
        for_self: device.member_id == by.member_id,
    };
    authorise(store, caller, action, now).await?;
    Ok(store.revoke_device(device_id, by, now).await?)
}

/// `POST /v1/members/{id}/remove` (admin): the store revokes every token of the member, sets
/// `rotation_needed`, refuses the last admin (409 `last_admin`) and audits. Returns the number
/// of records deleted with `delete_records`.
pub async fn remove_member(
    store: &dyn Store,
    caller: &Caller,
    member_id: Id,
    delete_records: bool,
    now: i64,
) -> Result<u64, AuthError> {
    authorise(store, caller, Action::RemoveMember, now).await?;
    let by = actor_of(caller)?;
    Ok(store
        .remove_member(member_id, delete_records, by, now)
        .await?)
}

/// `POST /v1/members/{id}/role`: an admin sets any role, the cloud owner only promotes. The
/// store refuses a change that leaves no admin (409 `last_admin`); `Unknown` is 400 (`/role`).
pub async fn set_role(
    store: &dyn Store,
    caller: &Caller,
    member_id: Id,
    role: Role,
    now: i64,
) -> Result<(), AuthError> {
    let widest = Action::SetRole { to: Role::Admin };
    authorise(store, caller, widest, now).await?;
    if role == Role::Unknown {
        return Err(AuthError::invalid("/role"));
    }
    authorise(store, caller, Action::SetRole { to: role }, now).await?;
    Ok(store.set_role(member_id, role, caller.actor(), now).await?)
}

/// `POST /v1/token/rotate`: a new token for the calling device; the old one stops at once.
pub async fn rotate_token(
    store: &dyn Store,
    caller: &Caller,
    now: i64,
) -> Result<TokenRotateResponse, AuthError> {
    authorise(store, caller, Action::RotateToken, now).await?;
    let device = *caller.device().ok_or(Refusal::Forbidden)?;
    let device_token = new_device_token(device.org_id)?;
    store
        .rotate_token(device.device_id, hash(device_token.as_str()), now)
        .await?;
    Ok(TokenRotateResponse { device_token })
}
