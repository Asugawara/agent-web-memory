//! Re-seeding after a server restore (plan-v3-team §3.9.5, §4.6 step 5; TM10).

/// Re-pushes own records above the server's heads when the `generation` changed.
///
/// Implements plan-v3-team §3.9.5.
pub fn run(_conn: &rusqlite::Connection, _server_generation: u64) -> anyhow::Result<()> {
    todo!("TM10: re-seed")
}
