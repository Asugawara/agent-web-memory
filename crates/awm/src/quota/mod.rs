//! Usage-limit samples recorded from Claude Code's status line (plan-quota §4-§5).

pub mod calibrate;
pub mod sample;
pub mod store;
pub mod totals;

/// Directory name of the samples inside the data dir.
pub const DIR: &str = "quota";
