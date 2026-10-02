//! Server for awm team sync: HTTP on axum and tokio, the `Store` trait with its
//! SQLite and Postgres implementations, authentication, limits, built-in TLS and backup.
//!
//! Scaffold (TM1): every module is a stub with its public signatures; later tasks fill them.
//! Backends and TLS/backup targets are cargo features (plan-v3-team §4.1) so tests can build one at a time.

pub mod auth;
pub mod authz;
pub mod backup;
pub mod check;
pub mod config;
pub mod delete;
pub mod http;
pub mod limits;
pub mod retention;
pub mod store;
#[cfg(feature = "acme")]
pub mod tls;
