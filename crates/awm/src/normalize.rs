//! URL and query normalisation used for exact URL matching and query comparison.
//!
//! Ported from `spikes/match-bench/src/normalize.rs` (`bigrams`, `tokens`,
//! `ja2_extend` and the Jaccard helpers were dropped). One deliberate change:
//! `norm_url` returns `None` for text that is not a URL with a host instead of
//! a lower-cased copy of the input.

use unicode_normalization::UnicodeNormalization;
use url::Url;

/// Normalise a URL: keep the scheme, lower-case the host, drop the fragment,
/// drop `utm_*`, `gclid` and `fbclid` parameters, sort the remaining
/// parameters and drop a trailing slash. Returns `None` when the text does not
/// parse as a URL or has no host.
pub fn norm_url(s: &str) -> Option<String> {
    let u = Url::parse(s.trim()).ok()?;
    let host = u.host_str().filter(|h| !h.is_empty())?.to_lowercase();
    let mut params: Vec<(String, String)> = u
        .query_pairs()
        .filter(|(k, _)| {
            let k = k.to_lowercase();
            !(k.starts_with("utm_") || k == "gclid" || k == "fbclid")
        })
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    params.sort();
    let mut out = format!("{}://{}", u.scheme(), host);
    if let Some(p) = u.port() {
        out.push_str(&format!(":{p}"));
    }
    out.push_str(u.path().trim_end_matches('/'));
    if !params.is_empty() {
        let q: Vec<String> = params
            .iter()
            .map(|(k, v)| {
                if v.is_empty() {
                    k.clone()
                } else {
                    format!("{k}={v}")
                }
            })
            .collect();
        out.push('?');
        out.push_str(&q.join("&"));
    }
    Some(out)
}

fn is_cjk(c: char) -> bool {
    matches!(c,
        '\u{3040}'..='\u{309F}'
        | '\u{30A0}'..='\u{30FF}'
        | '\u{3400}'..='\u{4DBF}'
        | '\u{4E00}'..='\u{9FFF}'
        | '\u{F900}'..='\u{FAFF}')
}

fn clean(s: &str) -> String {
    let n: String = s.nfkc().collect::<String>().to_lowercase();
    n.chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect()
}

/// Whitespace-split words after NFKC, lower-casing and punctuation stripping.
/// A CJK run is one word and is split from adjacent non-CJK text.
pub fn words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for w in clean(s).split_whitespace() {
        let mut cur = String::new();
        let mut cur_cjk = false;
        for c in w.chars() {
            let k = is_cjk(c);
            if !cur.is_empty() && k != cur_cjk {
                out.push(std::mem::take(&mut cur));
            }
            cur_cjk = k;
            cur.push(c);
        }
        if !cur.is_empty() {
            out.push(cur);
        }
    }
    out
}

/// Canonical query string for exact comparison: the words joined by single spaces.
pub fn norm_query(s: &str) -> String {
    words(s).join(" ")
}
