//! Detached `awm sync --quiet` spawn from hooks (plan-v3-team §4.1 item 4, §4.6; TM13).
//! Starts a process and opens no socket.

/// Spawns `awm sync --quiet` detached when the debounce allows.
///
/// Implements plan-v3-team §4.6 (TM13).
pub fn maybe_spawn() {
    todo!("TM13: hook-side spawn")
}
