//! Team sync engine (plan-v3-team §4.6, TM10). Scaffold (TM1): stubs only.
//!
//! Network code (`http`, `push`, `pull`) exists only with the `sync` feature and is reached
//! only from `cli/sync.rs`, never from hook, matching or render modules (§4.1 item 4).

pub mod apply;
pub mod eligible;
#[cfg(feature = "sync")]
pub mod http;
pub mod payload;
#[cfg(feature = "sync")]
pub mod pull;
#[cfg(feature = "sync")]
pub mod push;
pub mod reseed;
pub mod spawn;
pub mod state;
