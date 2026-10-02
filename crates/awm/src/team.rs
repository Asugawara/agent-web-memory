//! Team files (`team.toml`, `team.key`), invite strings and auto-approval
//! (plan-v3-team §4.7, §5.1). Scaffold (TM1): stubs only.

use crate::config::AutoApprove;

/// Whether a pending join or device is approved automatically under `policy`.
///
/// `is_own_device` is true for a new device of the caller's own member whose MAC verifies.
/// Implements plan-v3-team §4.7 `team.auto_approve` (TM12).
pub fn auto_approve(_policy: AutoApprove, _is_own_device: bool) -> bool {
    todo!("TM12: auto-approval")
}
