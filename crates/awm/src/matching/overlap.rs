//! Token overlap of two prompts, for choosing among several stored answers of one URL.

use std::collections::HashSet;

/// Tokens of at least this many characters count.
const MIN_TOKEN_CHARS: usize = 2;

/// Lowercased alphanumeric tokens of `text`, at least two characters, deduplicated. Text without
/// spaces (CJK) stays one token per unbroken run.
fn tokens(text: &str) -> HashSet<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.chars().count() >= MIN_TOKEN_CHARS)
        .map(str::to_string)
        .collect()
}

/// Jaccard similarity of the token sets of `a` and `b`; `None` when either set is empty.
pub fn prompt_overlap(a: &str, b: &str) -> Option<f64> {
    let (a, b) = (tokens(a), tokens(b));
    if a.is_empty() || b.is_empty() {
        return None;
    }
    let both = a.intersection(&b).count();
    Some(both as f64 / (a.len() + b.len() - both) as f64)
}

/// Index of the stored prompt closest to `current`; the first (newest) one on a tie, when
/// `current` is missing or has no tokens, or when no stored prompt can be scored. The overlap of
/// the chosen one is 0.0 when it could not be scored.
pub fn closest_prompt<'a>(
    current: Option<&str>,
    stored: impl IntoIterator<Item = Option<&'a str>>,
) -> (usize, f64) {
    let mut best = (0, 0.0);
    let mut first = true;
    for (i, s) in stored.into_iter().enumerate() {
        let score = match (current, s) {
            (Some(c), Some(s)) => prompt_overlap(c, s),
            _ => None,
        };
        if first {
            best = (i, score.unwrap_or(0.0));
            first = false;
        } else if let Some(sc) = score {
            if sc > best.1 {
                best = (i, sc);
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_prompts_overlap_fully_and_case_and_punctuation_do_not_matter() {
        assert_eq!(
            prompt_overlap("Install the CLI", "install, the cli!"),
            Some(1.0)
        );
    }

    #[test]
    fn overlap_is_jaccard_over_distinct_tokens() {
        // {rate, limits, api} vs {rate, limits, pricing}: 2 / 4.
        assert_eq!(
            prompt_overlap("rate limits api api", "Rate-limits pricing"),
            Some(0.5)
        );
        assert_eq!(prompt_overlap("alpha beta", "gamma delta"), Some(0.0));
    }

    #[test]
    fn one_character_tokens_and_empty_sets_cannot_be_scored() {
        assert_eq!(prompt_overlap("a b c", "a b c"), None);
        assert_eq!(prompt_overlap("", "word"), None);
        assert_eq!(prompt_overlap("word", "?!"), None);
    }

    #[test]
    fn unspaced_cjk_text_is_a_single_token() {
        assert_eq!(
            prompt_overlap("\u{6599}\u{91d1}\u{8868}\u{3092}\u{6559}\u{3048}\u{3066}", "\u{6599}\u{91d1}\u{8868}\u{3092}\u{6559}\u{3048}\u{3066}"),
            Some(1.0)
        );
        assert_eq!(prompt_overlap("\u{6599}\u{91d1}\u{8868}\u{3092}\u{6559}\u{3048}\u{3066}", "\u{6599}\u{91d1}\u{8868}"), Some(0.0));
    }

    #[test]
    fn the_closest_stored_prompt_wins_and_ties_keep_the_newest() {
        let stored = [
            Some("pricing tiers"),
            Some("install steps for linux"),
            Some("install steps"),
        ];
        // Newest first: index 2 matches best.
        assert_eq!(closest_prompt(Some("install steps"), stored), (2, 1.0));
        // A tie keeps the first.
        let tie = [Some("install steps"), Some("steps install")];
        assert_eq!(closest_prompt(Some("install steps"), tie), (0, 1.0));
        // Nothing shared: the newest, with overlap 0.
        assert_eq!(closest_prompt(Some("zebra"), stored), (0, 0.0));
    }

    #[test]
    fn a_missing_prompt_falls_back_to_the_newest() {
        let stored = [Some("pricing"), Some("install")];
        assert_eq!(closest_prompt(None, stored), (0, 0.0));
        assert_eq!(closest_prompt(Some("?"), stored), (0, 0.0));
        assert_eq!(
            closest_prompt(Some("install"), [None, Some("install")]),
            (1, 1.0)
        );
        assert_eq!(
            closest_prompt(Some("install"), [Some("pricing"), None]),
            (0, 0.0)
        );
    }
}
