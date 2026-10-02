//! The authorisation matrix (plan-v3-team §4.3.3, `docs/sync-v1.md` §6-§7) as one function.
//!
//! [`require`] is the only place in the crate that decides whether a caller may do something.
//! It is pure: everything it needs about stored state (who created an invite, whose device a
//! request names) arrives as a parameter of the [`Action`], which `auth`'s operations fill
//! from the store before they call it. Handlers (TM8) call [`require`] (or
//! `auth::authorise`, which also writes the audit row of a refusal) with the `Action` of their
//! endpoint and never compare roles themselves.
//!
//! One rule needs stored state inside a transaction and is applied by the store with the
//! [`crate::store::Actor`] that [`crate::auth::Caller::actor`] builds: with `{ids}`, a member
//! deletes only its own member's records and an admin any (`Store::delete`, TM6). The
//! `Action::Delete(DeleteScope::Ids)` cell allows the request; the store refuses another
//! member's record with 403 `forbidden` for the whole request.

use std::fmt;

use awm_proto::wire::{ErrorBody, ErrorCode, InviteKind, KnownTag, PushItem, Role};

use crate::auth::Caller;

/// What a `POST /v1/delete` asks for (`docs/sync-v1.md` §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeleteScope {
    /// `{ids}`: own member's records for a member, any record for an admin (the store applies
    /// the ownership part, see the module comment).
    Ids,
    /// `{all_mine: true}`: every record of the caller's member.
    AllMine,
    /// `{member}`: every record of a named member (admin).
    Member,
}

/// One row of §4.3.3 (refined by `docs/sync-v1.md` §7), with the parameters a row needs.
///
/// "for_self" parameters compare the member a request is about with the caller's member;
/// "created_by_caller" compares an invite's creating member with the caller's member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// `GET /v1/info`: anyone.
    Info,
    /// `POST /v1/bootstrap`: anonymous, with the bootstrap token in the body (`auth::bootstrap`).
    Bootstrap,
    /// `POST /v1/join`: anonymous, with the invite in the body (`auth::join`).
    Join,
    /// `GET /v1/status`: the calling device's own status (pending devices too).
    Status,
    /// `GET /v1/keys`: the calling device's own wraps (pending devices too).
    Keys,
    /// `GET /v1/records`, `POST /v1/pull`, `GET /v1/deletions`.
    Pull,
    /// `GET /v1/members`.
    Members,
    /// `GET /v1/org/settings`.
    ReadSettings,
    /// `POST /v1/records` items of one tag, always into the caller's own device's stream (the
    /// server binds member and device to the token, so a push cannot name another stream).
    /// TM8 calls `require` once per distinct known tag of the batch.
    Push(KnownTag),
    /// `POST /v1/delete`.
    Delete(DeleteScope),
    /// `POST /v1/invites`. `for_self`: a `device` invite whose handle is the caller's own.
    CreateInvite { kind: InviteKind, for_self: bool },
    /// `DELETE /v1/invites/{id}`.
    RevokeInvite { created_by_caller: bool },
    /// `POST /v1/devices/{id}/approve`. `kind` is the stored invite's kind (`Unknown` when the
    /// device has no invite, as the bootstrap device); `for_self`: the device is the caller's
    /// member's.
    Approve {
        kind: InviteKind,
        created_by_caller: bool,
        for_self: bool,
    },
    /// `POST /v1/devices/{id}/revoke`. `for_self`: the device is the caller's member's.
    RevokeDevice { for_self: bool },
    /// `POST /v1/members/{id}/remove`.
    RemoveMember,
    /// `POST /v1/members/{id}/role` (`awm serve promote` is the operator's and passes no caller).
    SetRole { to: Role },
    /// `POST /v1/keys/rotate`.
    RotateKeys,
    /// `POST /v1/token/rotate` for the calling device.
    RotateToken,
    /// `PUT /v1/org/settings`. `min_client`: the update sets `min_client`.
    WriteSettings { min_client: bool },
    /// `GET /v1/audit`.
    ReadAudit,
    /// `POST /v1/restore/complete`.
    CompleteRestore,
    /// `GET /v1/export`.
    Export,
    /// Deleting the organisation (cloud web page, TM20).
    DeleteOrg,
}

impl Action {
    /// A stable name for audit rows and logs.
    pub fn name(&self) -> &'static str {
        match self {
            Action::Info => "info",
            Action::Bootstrap => "bootstrap",
            Action::Join => "join",
            Action::Status => "status",
            Action::Keys => "keys",
            Action::Pull => "pull",
            Action::Members => "members",
            Action::ReadSettings => "settings.read",
            Action::Push(KnownTag::Rec) => "push.rec",
            Action::Push(KnownTag::Flag) => "push.flag",
            Action::Push(KnownTag::Stats) => "push.stats",
            Action::Push(KnownTag::Policy) => "push.policy",
            Action::Push(KnownTag::Roster) => "push.roster",
            Action::Delete(DeleteScope::Ids) => "delete.ids",
            Action::Delete(DeleteScope::AllMine) => "delete.all_mine",
            Action::Delete(DeleteScope::Member) => "delete.member",
            Action::CreateInvite { .. } => "invite.create",
            Action::RevokeInvite { .. } => "invite.revoke",
            Action::Approve { .. } => "approve",
            Action::RevokeDevice { .. } => "device.revoke",
            Action::RemoveMember => "member.remove",
            Action::SetRole { .. } => "member.role",
            Action::RotateKeys => "keys.rotate",
            Action::RotateToken => "token.rotate",
            Action::WriteSettings { .. } => "settings.write",
            Action::ReadAudit => "audit.read",
            Action::CompleteRestore => "restore.complete",
            Action::Export => "export",
            Action::DeleteOrg => "org.delete",
        }
    }
}

/// Why [`require`] refused, with the status and body of `docs/sync-v1.md` §13.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// 401 `unauthenticated`: no usable token (anonymous where a token is needed; unknown,
    /// revoked, malformed or wrong-kind tokens are refused by `auth::authenticate` already).
    Unauthenticated,
    /// 403 `not_approved`: a pending device outside `info`, `status` and `keys`.
    NotApproved,
    /// 403 `forbidden`: the role or the relation to the object does not allow it.
    Forbidden,
}

impl Refusal {
    pub fn code(self) -> ErrorCode {
        match self {
            Refusal::Unauthenticated => ErrorCode::Unauthenticated,
            Refusal::NotApproved => ErrorCode::NotApproved,
            Refusal::Forbidden => ErrorCode::Forbidden,
        }
    }

    pub fn status(self) -> u16 {
        match self {
            Refusal::Unauthenticated => 401,
            Refusal::NotApproved | Refusal::Forbidden => 403,
        }
    }

    /// The error body TM8 sends.
    pub fn to_body(self) -> ErrorBody {
        ErrorBody::new(self.code(), self.to_string())
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refusal::Unauthenticated => "unknown, revoked or missing token",
            Refusal::NotApproved => "this device waits for approval",
            Refusal::Forbidden => "not allowed for this caller",
        })
    }
}

impl std::error::Error for Refusal {}

/// Fails unless `caller` may do `action` (plan-v3-team §4.3.3, `docs/sync-v1.md` §7).
///
/// Anonymous callers get [`Refusal::Unauthenticated`] outside `info`, `bootstrap` and `join`;
/// pending devices get [`Refusal::NotApproved`] outside `info`, `status` and `keys`; every
/// other refusal is [`Refusal::Forbidden`]. `bootstrap` and `join` are anonymous: TM8 does not
/// authenticate a header on them (`docs/sync-v1.md` §2.2), and a caller with a device token is
/// refused (fail closed if that wiring is wrong).
pub fn require(caller: &Caller, action: Action) -> Result<(), Refusal> {
    use Action::*;
    let allowed = match caller {
        Caller::Anonymous => match action {
            Info | Bootstrap | Join => true,
            _ => return Err(Refusal::Unauthenticated),
        },
        Caller::Pending(_) => match action {
            Info | Status | Keys => true,
            _ => return Err(Refusal::NotApproved),
        },
        Caller::Member(_) => match action {
            Info | Status | Keys | Pull | Members | ReadSettings | RotateToken => true,
            Push(tag) => tag != KnownTag::Policy,
            Delete(scope) => scope != DeleteScope::Member,
            CreateInvite { kind, for_self } => kind == InviteKind::Device && for_self,
            RevokeInvite { created_by_caller } => created_by_caller,
            Approve {
                kind,
                created_by_caller,
                for_self,
            } => kind == InviteKind::Device && created_by_caller && for_self,
            RevokeDevice { for_self } => for_self,
            Bootstrap
            | Join
            | RemoveMember
            | SetRole { .. }
            | RotateKeys
            | WriteSettings { .. }
            | ReadAudit
            | CompleteRestore
            | Export
            | DeleteOrg => false,
        },
        Caller::Admin(_) => match action {
            Info
            | Status
            | Keys
            | Pull
            | Members
            | ReadSettings
            | RotateToken
            | Push(_)
            | Delete(_)
            | RevokeInvite { .. }
            | RevokeDevice { .. }
            | RemoveMember
            | SetRole { .. }
            | RotateKeys
            | WriteSettings { .. }
            | ReadAudit
            | CompleteRestore
            | Export => true,
            CreateInvite { kind, .. } => kind != InviteKind::Unknown,
            // The approver must hold the invite secret `S`, so only the creating member's
            // devices can make wraps that verify; another admin is refused.
            Approve {
                kind,
                created_by_caller,
                ..
            } => kind != InviteKind::Unknown && created_by_caller,
            Bootstrap | Join | DeleteOrg => false,
        },
        Caller::CloudOwner(_) => match action {
            Info | Export | DeleteOrg => true,
            WriteSettings { min_client } => !min_client,
            SetRole { to } => to == Role::Admin,
            _ => false,
        },
    };
    if allowed {
        Ok(())
    } else {
        Err(Refusal::Forbidden)
    }
}

/// Whether the `Awm-Client` gate (426 below `min_client`, `docs/sync-v1.md` §2.3) applies to a
/// `POST /v1/records` batch: not when every item is a `roster` record or a marker (RVT1 m5),
/// so an old client can still publish revocations and epoch records and fill indexes after a
/// 410. The gate also applies to every `POST /v1/join` and `POST /v1/bootstrap`, and to no
/// other endpoint.
pub fn push_needs_min_client(items: &[PushItem]) -> bool {
    !items.iter().all(|item| match item {
        PushItem::Deleted(_) => true,
        PushItem::Record(r) => r.tag.known() == Some(KnownTag::Roster),
    })
}
