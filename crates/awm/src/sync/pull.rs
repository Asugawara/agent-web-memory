//! Pull step of `awm sync` (plan-v3-team §4.6 step 6; TM11).

/// Pulls teammates' records and applies them; returns the number applied.
///
/// Implements plan-v3-team §4.6 step 6.
pub fn run(_conn: &rusqlite::Connection) -> anyhow::Result<usize> {
    todo!("TM11: pull")
}
