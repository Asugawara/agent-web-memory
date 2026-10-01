//! Internal hook deadline (plan-v2 §5.4).
//!
//! A thread sleeps for the deadline. If the main path has not called
//! [`Watchdog::commit`] by then, the thread runs a callback (which may record
//! `outcome = 'deadline'`) and exits the process with code 0, so nothing more is
//! written. Once `commit` has returned true the deadline can no longer fire, so a
//! JSON document that is being written is never cut.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

const RUNNING: u8 = 0;
const COMMITTED: u8 = 1;
const FIRED: u8 = 2;

#[derive(Debug, Clone)]
pub struct Watchdog {
    state: Arc<AtomicU8>,
}

impl Watchdog {
    /// Starts the timer. `on_deadline` runs on the watchdog thread just before the
    /// process exits; it must be quick and must not print.
    pub fn start<F>(limit: Duration, on_deadline: F) -> Watchdog
    where
        F: FnOnce() + Send + 'static,
    {
        let state = Arc::new(AtomicU8::new(RUNNING));
        let thread_state = Arc::clone(&state);
        std::thread::spawn(move || {
            std::thread::sleep(limit);
            if thread_state
                .compare_exchange(RUNNING, FIRED, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                on_deadline();
                std::process::exit(0);
            }
        });
        Watchdog { state }
    }

    /// Call immediately before printing. True: the output may be written and the
    /// deadline is disarmed. False: the deadline fired first and the process is
    /// about to exit; the caller must write nothing.
    pub fn commit(&self) -> bool {
        match self
            .state
            .compare_exchange(RUNNING, COMMITTED, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => true,
            Err(state) => state == COMMITTED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_before_the_deadline_succeeds_and_repeats() {
        let wd = Watchdog::start(Duration::from_secs(3600), || {});
        assert!(wd.commit());
        assert!(wd.commit());
    }
}
