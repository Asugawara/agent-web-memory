//! URLs in free text.

use regex::Regex;
use std::sync::OnceLock;

/// Most URLs taken from one prompt.
pub const MAX_PROMPT_URLS: usize = 5;

fn re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)https://[^\s<>"'`\]\)\}]+"#).expect("static regex"))
}

/// Up to five distinct `https://` URLs of `text`, in order, without trailing punctuation.
pub fn extract_urls(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for m in re().find_iter(text) {
        let u = m.as_str().trim_end_matches(['.', ',', ';', ':', '!', '?']);
        if u.len() > "https://".len() && !out.iter().any(|o| o == u) {
            out.push(u.to_string());
            if out.len() == MAX_PROMPT_URLS {
                break;
            }
        }
    }
    out
}
