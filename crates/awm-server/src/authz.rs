//! Role checks for endpoints (plan-v3-team §4.3).

use crate::auth::Caller;

/// What an endpoint needs from its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    Member,
    Admin,
}

/// Fails unless `caller` satisfies `need`.
///
/// Implements plan-v3-team §4.3.
pub fn require(_caller: &Caller, _need: Need) -> Result<(), crate::store::StoreError> {
    todo!("authorisation (§4.3)")
}
