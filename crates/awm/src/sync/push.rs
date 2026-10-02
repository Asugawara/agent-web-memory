//! Push step of `awm sync` (plan-v3-team §4.6 step 3; TM10).

/// Pushes eligible local rows in batches of at most 100; returns the number pushed.
///
/// Implements plan-v3-team §4.6 step 3.
pub fn run(_conn: &rusqlite::Connection) -> anyhow::Result<usize> {
    todo!("TM10: push")
}
