//! FTS5 MATCH expressions (port of `match_expr` in `spikes/match-bench/src/methods/fts5.rs`).

use std::collections::HashSet;

use crate::normalize::words;

/// Most unique tokens in one expression.
pub const MAX_TOKENS: usize = 64;

/// Up to 64 unique normalised tokens, each quoted, joined by `OR`.
/// `None` when the text has no token.
pub fn match_expr(text: &str) -> Option<String> {
    let mut seen = HashSet::new();
    let quoted: Vec<String> = words(text)
        .into_iter()
        .filter(|t| seen.insert(t.clone()))
        .take(MAX_TOKENS)
        .map(|t| format!("\"{t}\""))
        .collect();
    if quoted.is_empty() {
        None
    } else {
        Some(quoted.join(" OR "))
    }
}
