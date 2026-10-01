//! UserPromptSubmit gate (plan-v2 §3.4).

use crate::matching::url::extract_urls;
use crate::normalize::words;

/// Prompts that start with one of these tags are machine turns.
pub const MACHINE_PREFIXES: &[&str] = &["<task-notification>"];
/// Fewer content words than this skips the prompt.
pub const MIN_CONTENT_WORDS: usize = 4;

const STOP_WORDS: &[&str] = &[
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "had", "her", "was", "one",
    "our", "out", "has", "his", "how", "its", "who", "did", "get", "may", "this", "that", "with",
    "have", "from", "they", "will", "would", "there", "their", "what", "about", "which", "when",
    "make", "like", "just", "please", "could", "any", "then", "than", "into", "some", "does",
    "been", "your",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    Skip(&'static str),
    /// The `https://` URLs found in the prompt.
    PromptUrl(Vec<String>),
    PromptBm25,
}

fn is_cjk_char(c: char) -> bool {
    matches!(c,
        '\u{3040}'..='\u{30FF}' | '\u{3400}'..='\u{4DBF}' | '\u{4E00}'..='\u{9FFF}'
        | '\u{AC00}'..='\u{D7AF}' | '\u{F900}'..='\u{FAFF}')
}

/// Words of 3 or more characters outside the stop list, plus CJK runs of 2 or more.
pub fn content_words(prompt: &str) -> usize {
    words(prompt)
        .iter()
        .filter(|w| {
            let n = w.chars().count();
            if w.chars().next().is_some_and(is_cjk_char) {
                n >= 2
            } else {
                n >= 3 && !STOP_WORDS.contains(&w.as_str())
            }
        })
        .count()
}

pub fn gate(prompt: &str, prompt_bm25_enabled: bool) -> Gate {
    let head = prompt.trim_start();
    if MACHINE_PREFIXES.iter().any(|p| head.starts_with(p)) {
        return Gate::Skip("machine prompt");
    }
    let urls = extract_urls(prompt);
    if !urls.is_empty() {
        return Gate::PromptUrl(urls);
    }
    if content_words(prompt) < MIN_CONTENT_WORDS {
        return Gate::Skip("too few content words");
    }
    if prompt_bm25_enabled {
        Gate::PromptBm25
    } else {
        Gate::Skip("prompt_bm25 is off")
    }
}
