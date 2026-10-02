//! agent-web-memory: local memory of past Web research for coding agents.

#[cfg(feature = "bench")]
pub mod bench;
pub mod capture;
pub mod cli;
pub mod config;
pub mod db;
pub mod deadline;
pub mod forget;
pub mod gate;
pub mod hook;
pub mod hosts;
pub mod import;
pub mod init;
pub mod matching;
pub mod normalize;
pub mod note;
pub mod paths;
pub mod quota;
pub mod record;
pub mod redact;
pub mod render;
pub mod sanitize;
