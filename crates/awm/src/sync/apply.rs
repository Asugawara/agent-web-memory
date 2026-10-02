//! Applying pulled records and the deletion stream (plan-v3-team §4.6 step 6; TM11).

/// Applies the deletion stream: removes the local copies of deleted team records.
///
/// Implements plan-v3-team §4.6 step 6 (TM11).
pub fn deletions(_conn: &mut rusqlite::Connection) -> anyhow::Result<usize> {
    todo!("TM11: deletion stream")
}
