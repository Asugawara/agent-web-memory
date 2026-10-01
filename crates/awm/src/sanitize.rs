//! Sanitiser for text that is injected into a model's context (plan-v2 §4.3.1).
//!
//! `kept_share` is measured after step 6 and before the cap of step 7, on
//! non-whitespace characters, so that a long benign text cut to the cap is not
//! mistaken for a heavily filtered one.

use crate::hosts;
use regex::Regex;
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;
use url::Url;

/// Verbs that open an instruction; a sentence starting with one is dropped.
pub const IMPERATIVE_VERBS: &[&str] = &[
    "ignore",
    "disregard",
    "forget",
    "run",
    "execute",
    "call",
    "open",
    "visit",
    "click",
    "download",
    "install",
    "fetch",
    "search",
    "send",
    "post",
    "upload",
    "tell",
    "say",
    "reply",
    "write",
    "delete",
    "copy",
    "paste",
    "print",
    "output",
    "reveal",
    "follow",
    "obey",
    "pretend",
    "switch",
    "curl",
    "wget",
    "sudo",
    "remove",
    "rm",
    "cat",
    "echo",
    "respond",
    "override",
    "bypass",
    "disable",
    "enable",
    "modify",
    "navigate",
    "deploy",
    "grant",
    "eval",
    "exec",
    "kill",
    "drop",
    "submit",
    "show",
    "give",
    "create",
    "edit",
    "read",
    "load",
    "move",
    "save",
    "forward",
    "leak",
    "dump",
];

/// Phrases that mark an injection attempt (lower case).
pub const MARKERS: &[&str] = &[
    "ignore previous",
    "ignore all",
    "ignore the above",
    "disregard",
    "system prompt",
    "you are now",
    "developer mode",
    "jailbreak",
    "act as",
    "new instructions",
    "the user wants",
    "the user has asked",
    "system:",
    "assistant:",
    "user:",
    "<|",
    "[inst]",
    "~/.ssh",
    "id_rsa",
    ".env",
    "exfiltrat",
];

const DIRECTIVES: &[&str] = &[
    "you must",
    "you should",
    "you need to",
    "make sure",
    "remember to",
    "always",
    "never",
    "do not",
    "don't",
];

/// Stands in for `<|` while angle brackets are stripped, so the marker survives.
const LT_PIPE: char = '\u{E000}';

#[derive(Debug, Clone, PartialEq)]
pub struct Sanitized {
    pub text: String,
    pub kept_share: f32,
    pub markers: Vec<&'static str>,
}

struct Patterns {
    fence: Regex,
    image: Regex,
    link: Regex,
    tag: Regex,
    scheme_url: Regex,
    www_url: Regex,
    heading: Regex,
    quote: Regex,
    bullet: Regex,
    ordered: Regex,
    rule: Regex,
    long_run: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| {
        let re = |s: &str| Regex::new(s).expect("valid sanitiser pattern");
        Patterns {
            fence: re(r"(?s)(?:```|~~~).*?(?:```|~~~|\z)"),
            image: re(r"!\[[^\]]*\]\([^)]*\)"),
            link: re(r"\[([^\]]*)\]\([^)]*\)"),
            tag: re(r"</?[A-Za-z!][^>]*>"),
            scheme_url: re(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+"),
            www_url: re(r"(?i)\bwww\.\S+"),
            heading: re(r"^#{1,6}\s+"),
            quote: re(r"^(?:>\s*)+"),
            bullet: re(r"^[-*+]\s+"),
            ordered: re(r"^\d+[.)]\s+"),
            rule: re(r"^[\s|:*_-]{3,}$"),
            long_run: re(r"[A-Za-z0-9+/]{40,}={0,2}"),
        }
    })
}

/// Unicode category Cf (format characters: zero-width, bidi controls, ...).
fn is_cf(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x08E2 | 0x180E
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F
        | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// Step 1: NFKC, then drop Cc (except newline and tab) and Cf.
fn normalise(text: &str) -> String {
    text.nfkc()
        .filter(|&c| (c == '\n' || c == '\t' || !c.is_control()) && !is_cf(c))
        .collect()
}

/// Keep `s` when it is not a whole-text horizontal rule or table separator.
fn strip_block_markup(line: &str) -> Option<String> {
    let p = patterns();
    let t = line.trim();
    if t.is_empty() || p.rule.is_match(t) {
        return None;
    }
    let t = p.heading.replace(t, "");
    let t = p.quote.replace(&t, "");
    let t = p.bullet.replace(&t, "");
    let t = p.ordered.replace(&t, "");
    Some(t.replace('|', " "))
}

/// Replace `scheme://...` and `www....` with `[link removed]`, keeping trailing punctuation.
fn remove_links(text: &str) -> String {
    let p = patterns();
    let repl = |c: &regex::Captures| {
        let m = &c[0];
        let body = m.trim_end_matches(['.', ',', ';', ':', ')', '!', '?', '\'', '"']);
        format!("[link removed]{}", &m[body.len()..])
    };
    let s = p.scheme_url.replace_all(text, repl);
    p.www_url.replace_all(&s, repl).into_owned()
}

fn contains_marker(hay: &str, marker: &str) -> bool {
    let word_start = marker.chars().next().is_some_and(char::is_alphanumeric);
    let phrase = marker.contains(' ');
    hay.match_indices(marker).any(|(i, _)| {
        let before_ok = !word_start
            || !hay[..i]
                .chars()
                .next_back()
                .is_some_and(char::is_alphanumeric);
        let after_ok = !phrase
            || !hay[i + marker.len()..]
                .chars()
                .next()
                .is_some_and(char::is_alphanumeric);
        before_ok && after_ok
    })
}

fn find_markers(lower: &str) -> Vec<&'static str> {
    MARKERS
        .iter()
        .copied()
        .filter(|m| contains_marker(lower, m))
        .collect()
}

fn first_word(s: &str) -> (&str, &str) {
    let end = s
        .char_indices()
        .find(|&(_, c)| !(c.is_alphabetic() || c == '\''))
        .map_or(s.len(), |(i, _)| i);
    (&s[..end], &s[end..])
}

fn starts_with_imperative(lower: &str) -> bool {
    let mut rest = lower.trim_start();
    loop {
        let (w, after) = first_word(rest);
        let skip = match w {
            "please" | "now" | "then" => true,
            "first" => after.starts_with(','),
            _ => false,
        };
        if !skip {
            return IMPERATIVE_VERBS.contains(&w);
        }
        rest = after.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
    }
}

fn starts_with_directive(lower: &str) -> bool {
    let t = lower.trim_start();
    DIRECTIVES.iter().any(|d| {
        t.starts_with(d)
            && !t[d.len()..]
                .chars()
                .next()
                .is_some_and(char::is_alphanumeric)
    })
}

fn split_sentences(text: &str, split_newlines: bool) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    for (i, &c) in chars.iter().enumerate() {
        match c {
            '\n' if split_newlines => out.push(std::mem::take(&mut cur)),
            '\u{3002}' => {
                cur.push(c);
                out.push(std::mem::take(&mut cur));
            }
            '.' | '!' | '?' => {
                cur.push(c);
                if chars.get(i + 1).is_none_or(|n| n.is_whitespace()) {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn non_ws(s: &str) -> usize {
    s.chars().filter(|c| !c.is_whitespace()).count()
}

/// Step 7: cut at a word boundary so that the result, `...` included, has at most `cap` characters.
fn truncate(text: &str, cap: usize) -> String {
    if text.chars().count() <= cap {
        return text.to_string();
    }
    let keep = cap.saturating_sub(3);
    let head: String = text.chars().take(keep).collect();
    let cut = match head.rfind(char::is_whitespace) {
        Some(i) if i > 0 => &head[..i],
        _ => head.as_str(),
    };
    let cut = cut.trim_end_matches(|c: char| c.is_whitespace() || ",;:".contains(c));
    format!("{cut}...")
}

fn run(text: &str, cap: usize, single_line: bool) -> Sanitized {
    let p = patterns();
    // 1
    let s = normalise(text);
    let in_chars = non_ws(&s);
    // 2
    let s = p.fence.replace_all(&s, " ");
    let s = if single_line {
        s.replace('\n', " ")
    } else {
        s.into_owned()
    };
    // 3
    let blocks: Vec<String> = s.split('\n').filter_map(strip_block_markup).collect();
    let s = blocks.join("\n");
    let s = p.image.replace_all(&s, "");
    let s = p.link.replace_all(&s, "$1");
    let s = s.replace("<|", &format!("{LT_PIPE}|"));
    let s = p.tag.replace_all(&s, " ");
    let s: String = s
        .replace("**", "")
        .replace("__", "")
        .replace("~~", "")
        .chars()
        .filter(|&c| !matches!(c, '*' | '`' | '<' | '>'))
        .collect();
    // 4
    let s = remove_links(&s);
    // 5
    let mut markers: Vec<&'static str> = Vec::new();
    let mut kept: Vec<String> = Vec::new();
    for sentence in split_sentences(&s, !single_line) {
        let t = sentence.trim();
        if t.is_empty() {
            continue;
        }
        let lower = t
            .to_lowercase()
            .replace('\u{2019}', "'")
            .replace(LT_PIPE, "<");
        let found = find_markers(&lower);
        let drop =
            !found.is_empty() || starts_with_imperative(&lower) || starts_with_directive(&lower);
        for m in found {
            if !markers.contains(&m) {
                markers.push(m);
            }
        }
        if !drop {
            kept.push(t.to_string());
        }
    }
    // 6
    let joined = kept.join(" ");
    let joined = p.long_run.replace_all(&joined, " ");
    let joined = joined.split_whitespace().collect::<Vec<_>>().join(" ");
    let kept_share = if in_chars == 0 {
        1.0
    } else {
        (non_ws(&joined) as f32 / in_chars as f32).clamp(0.0, 1.0)
    };
    // 7
    Sanitized {
        text: truncate(&joined, cap),
        kept_share,
        markers,
    }
}

/// Sanitise a multi-line text (a fetch answer or search summary) to at most `cap` characters.
pub fn excerpt(text: &str, cap: usize) -> Sanitized {
    run(text, cap, false)
}

/// Same pipeline for a single line (a fetch prompt or a query): newlines become spaces.
pub fn line(text: &str, cap: usize) -> Sanitized {
    run(text, cap, true)
}

/// A reason to quarantine the source record, or `None`.
pub fn quarantine_reason(s: &Sanitized) -> Option<String> {
    if !s.markers.is_empty() {
        return Some(format!("marker phrase: {}", s.markers.join(", ")));
    }
    if s.kept_share < 0.30 {
        return Some(format!(
            "sanitiser kept only {:.0}% of the text",
            s.kept_share * 100.0
        ));
    }
    None
}

/// True for an `https://` URL that is safe to show (§4.3.1 step 9).
pub fn url_ok(url: &str) -> bool {
    if url.chars().count() > 120 || !url.is_ascii() {
        return false;
    }
    if url
        .chars()
        .any(|c| c.is_ascii_control() || c.is_whitespace() || matches!(c, '<' | '>' | '"'))
    {
        return false;
    }
    if !url[..url.len().min(8)].eq_ignore_ascii_case("https://") {
        return false;
    }
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || hosts::is_private(&parsed, &[])
    {
        return false;
    }
    let readable = format!("{} {}", parsed.path(), parsed.query().unwrap_or(""))
        .to_lowercase()
        .replace("%20", " ")
        .replace(['-', '_', '+', '/'], " ");
    let readable = readable.split_whitespace().collect::<Vec<_>>().join(" ");
    !MARKERS.iter().any(|m| contains_marker(&readable, m))
}
