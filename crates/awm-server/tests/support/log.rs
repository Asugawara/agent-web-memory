//! A `LogSink` that keeps every line, shared by `api_v1.rs`, `serve_check.rs`,
//! `serve_config.rs` and `serve_tls.rs` through `#[path = "support/log.rs"] mod capture;`.

#![allow(dead_code)]

use std::sync::Mutex;

use awm_server::http::LogSink;

#[derive(Default)]
pub struct Capture(pub Mutex<Vec<String>>);

impl LogSink for Capture {
    fn line(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_string());
    }
}

impl Capture {
    /// Every line, joined by newlines.
    pub fn text(&self) -> String {
        self.0.lock().unwrap().join("\n")
    }
}
