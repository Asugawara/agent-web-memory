//! Retention sweep (plan-v3-team §5.6).

/// Deletes blobs older than `retention_days`; returns how many were removed.
///
/// Implements plan-v3-team §5.6.
pub fn sweep(_retention_days: u32) -> Result<u64, crate::store::StoreError> {
    todo!("retention (§5.6)")
}
