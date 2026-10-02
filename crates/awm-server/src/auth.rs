//! Device-token authentication (plan-v3-team §4.10).

/// The authenticated caller of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub member_id: String,
    pub device_id: String,
    pub is_admin: bool,
}

/// Resolves a bearer token to a caller; `None` when unknown, revoked or unapproved.
///
/// Implements plan-v3-team §4.10.
pub fn authenticate(_token: &str) -> Option<Caller> {
    todo!("authentication (§4.10)")
}
