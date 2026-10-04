//! BM25 over a handful of candidate documents, with idf from the candidates themselves.
//!
//! The URL deny ranks the stored answers of one URL (at most 20, already read by one indexed
//! query). Nothing beyond them is read: no SQL, no index. FTS5's `bm25()` is computed only while
//! walking the doclists of the query terms, and even a document-frequency lookup in the index
//! (`fts5vocab`) walks them (measured in docs/reports/DENY6.md), so both cost more as the corpus
//! grows; this scorer's cost depends on the prompt length and the candidate count only.
//!
//! Formula (Lucene's `BM25Similarity`, with local statistics):
//! `idf = ln(1 + (N - n + 0.5) / (n + 0.5))`, `k1 = 1.2`, `b = 0.75`, and per document
//! `sum over query terms of idf * tf * (k1 + 1) / (tf + k1 * (1 - b + b * dl / avgdl))`.
//!
//! Why not FTS5's `ln((N - n + 0.5) / (n + 0.5))` floored at `1e-6`: with `N` this small it
//! degenerates. For `N = 2` every term is floored (`n = 1` gives `ln 1 = 0`), for `N = 3` a term in
//! two candidates is floored, and the ranking then follows tf and length instead of the terms that
//! tell the answers apart. The Lucene form is always positive and needs no floor: for `N = 2`,
//! `n = 1` weighs 0.69 and `n = 2` weighs 0.18, so a distinguishing term counts about four times a
//! shared one.
//!
//! Deviations from `bm25(event_fts)`:
//! - `N` is the number of candidates, `n` the number of candidates whose text holds the term, and
//!   `avgdl` the mean candidate length, not the statistics of the whole index. A term present in
//!   every candidate (page boilerplate that every stored answer of the URL shares) weighs little,
//!   and the terms that tell the answers apart weigh more. Corpus-wide rarity is not used.
//! - Terms come from [`crate::normalize::words`] (NFKC, lower case, every non-alphanumeric
//!   character is a separator), the tokens `fts::match_expr` sends to FTS5, here of 2 or more
//!   characters; documents are tokenised the same way, so there is no `unicode61` mismatch (the
//!   index also folds diacritics, this scorer does not).
//! - The score is positive (higher is better), not the negated value of the query channel.

use std::collections::{HashMap, HashSet};

use super::fts::MAX_TOKENS;
use crate::normalize::words;

const K1: f64 = 1.2;
const B: f64 = 0.75;

/// Index of the best document among `docs` (the first on a tie) and its score, or `None` when
/// nothing can be ranked: no term of 2 or more characters in `prompt`, no term in any document, or
/// every document scoring 0.0.
pub fn rank(prompt: &str, docs: &[&str]) -> Option<(usize, f64)> {
    let terms = query_terms(prompt);
    if terms.is_empty() || docs.is_empty() {
        return None;
    }
    best(&score_all(&terms, docs))
}

/// Unique lower-case terms of 2 or more characters, in order, at most [`MAX_TOKENS`].
pub fn query_terms(prompt: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    words(prompt)
        .into_iter()
        .filter(|t| t.chars().count() >= 2 && seen.insert(t.clone()))
        .take(MAX_TOKENS)
        .collect()
}

/// Lucene's idf: always positive, decreasing in `n`.
fn idf(n_docs: usize, n: usize) -> f64 {
    (1.0 + (n_docs as f64 - n as f64 + 0.5) / (n as f64 + 0.5)).ln()
}

/// Score of every document for `terms`; a term in no document scores nothing.
fn score_all(terms: &[String], docs: &[&str]) -> Vec<f64> {
    let tokens: Vec<Vec<String>> = docs.iter().map(|d| words(d)).collect();
    let tfs: Vec<HashMap<&str, usize>> = tokens
        .iter()
        .map(|doc| {
            let mut tf = HashMap::new();
            for t in doc {
                *tf.entry(t.as_str()).or_default() += 1;
            }
            tf
        })
        .collect();
    let avgdl = tokens.iter().map(Vec::len).sum::<usize>() as f64 / docs.len() as f64;
    // Terms are summed in query order: a map's order would change the rounding, and with it a tie.
    let idfs: Vec<(&str, f64)> = terms
        .iter()
        .filter_map(|t| {
            let n = tfs.iter().filter(|tf| tf.contains_key(t.as_str())).count();
            (n > 0).then(|| (t.as_str(), idf(docs.len(), n)))
        })
        .collect();
    tokens
        .iter()
        .zip(&tfs)
        .map(|(doc, tf)| {
            if avgdl == 0.0 {
                return 0.0;
            }
            let norm = K1 * (1.0 - B + B * doc.len() as f64 / avgdl);
            idfs.iter()
                .filter_map(|(t, idf)| {
                    let f = *tf.get(t)? as f64;
                    Some(idf * f * (K1 + 1.0) / (f + norm))
                })
                .sum()
        })
        .collect()
}

/// First index of the highest score; `None` when no score is above 0.0.
fn best(scores: &[f64]) -> Option<(usize, f64)> {
    let mut best: Option<(usize, f64)> = None;
    for (i, &s) in scores.iter().enumerate() {
        if s > 0.0 && best.is_none_or(|(_, top)| s > top) {
            best = Some((i, s));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms(t: &[&str]) -> Vec<String> {
        t.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn idf_is_the_lucene_form() {
        assert!((idf(2, 1) - 2f64.ln()).abs() < 1e-12);
        assert!((idf(2, 2) - (1.0 + 0.5 / 2.5f64).ln()).abs() < 1e-12);
        assert!((idf(20, 1) - (1.0 + 19.5 / 1.5f64).ln()).abs() < 1e-12);
        assert!((idf(20, 20) - (1.0 + 0.5 / 20.5f64).ln()).abs() < 1e-12);
    }

    #[test]
    fn idf_is_positive_and_strictly_decreasing_in_n() {
        for n_docs in 1..=20 {
            let mut prev = f64::INFINITY;
            for n in 1..=n_docs {
                let v = idf(n_docs, n);
                assert!(v > 0.0 && v < prev, "N={n_docs} n={n}");
                prev = v;
            }
        }
    }

    #[test]
    fn a_term_in_every_candidate_weighs_little_and_the_rare_term_decides() {
        // "page" is in all four, "rare" in one: the rare term decides although "page" repeats.
        let docs = [
            "page page page a",
            "page b c d",
            "page rare c d",
            "page e f g",
        ];
        let (i, _) = rank("page rare", &docs).unwrap();
        assert_eq!(i, 2);
        let page = score_all(&terms(&["page"]), &docs);
        let rare = score_all(&terms(&["rare"]), &docs);
        assert!(rare[2] > 3.0 * page[1]);
    }

    #[test]
    fn with_two_candidates_the_distinguishing_term_beats_a_higher_tf_of_a_shared_one() {
        // "page" is in both (tf 1 against 4), "alpha" only in the first, which is also longer.
        let docs = ["page alpha x y z w v u", "page page page page"];
        assert_eq!(rank("page alpha", &docs).unwrap().0, 0);
    }

    #[test]
    fn tf_saturates() {
        // Same length (4 tokens each); "cat" in two of five candidates, so its idf is positive.
        let docs = [
            "cat x y z",
            "cat cat y z",
            "cat cat cat z",
            "p q r s",
            "t u v w",
        ];
        let s = score_all(&terms(&["cat"]), &docs);
        assert!(s[0] < s[1] && s[1] < s[2]);
        assert!(s[1] - s[0] > s[2] - s[1]);
    }

    #[test]
    fn a_rarer_shared_term_outranks_a_common_one() {
        let docs = [
            "common a b",
            "rare a b",
            "common c d",
            "common e f",
            "g h i",
            "j k l",
        ];
        let s = score_all(&terms(&["common", "rare"]), &docs);
        assert!(s[1] > s[0]);
    }

    #[test]
    fn the_longer_document_with_the_same_tf_ranks_lower() {
        let docs = ["cat a b c d e f g", "cat a", "x y", "z w"];
        let s = score_all(&terms(&["cat"]), &docs);
        assert!(s[1] > s[0]);
    }

    #[test]
    fn a_tie_keeps_the_first_and_zero_scores_rank_nothing() {
        assert_eq!(best(&[1.5, 1.5, 0.2]), Some((0, 1.5)));
        assert_eq!(best(&[0.0, 0.0]), None);
        assert_eq!(best(&[]), None);
        assert_eq!(score_all(&terms(&["cat"]), &["", ""]), vec![0.0, 0.0]);
    }

    #[test]
    fn identical_documents_tie_exactly_whatever_the_term_count() {
        let t: Vec<String> = (0..30).map(|i| format!("t{i}")).collect();
        let doc: String = t.iter().map(|t| format!("{t} ")).collect();
        let others = ["t1 zz", "t2 yy"];
        for _ in 0..50 {
            let s = score_all(&t, &[&doc, &doc, &doc, others[0], others[1]]);
            assert!(s[0] == s[1] && s[1] == s[2]);
        }
    }

    #[test]
    fn query_terms_are_lower_case_unique_and_two_characters_or_more() {
        assert_eq!(
            query_terms("The Cat, the cat! a 1 x-ray"),
            ["the", "cat", "ray"]
        );
        assert!(query_terms("?!... a b 1").is_empty());
        let long: String = (0..100).map(|i| format!("tok{i} ")).collect();
        assert_eq!(query_terms(&long).len(), MAX_TOKENS);
    }

    #[test]
    fn rank_picks_the_document_sharing_the_distinguishing_term() {
        let docs = [
            "pricing tiers monthly cost",
            "installation steps linux",
            "release notes",
        ];
        assert_eq!(rank("which pricing tiers exist", &docs).unwrap().0, 0);
        assert_eq!(rank("linux installation", &docs).unwrap().0, 1);
    }

    #[test]
    fn nothing_to_rank_gives_none() {
        let docs = ["alpha beta", "gamma delta"];
        assert_eq!(rank("a ?! 1", &docs), None);
        // Terms that appear in no candidate.
        assert_eq!(rank("zzzz yyyy", &docs), None);
        assert_eq!(rank("alpha", &["", ""]), None);
        assert_eq!(rank("alpha", &[]), None);
    }
}
