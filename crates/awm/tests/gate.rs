//! UserPromptSubmit gate (plan-v2 §3.4).
//!
//! The CJK prompts below hold real CJK characters inside string literals: the
//! gate counts CJK runs, so they cannot be replaced by placeholders.

use awm::gate::{content_words, gate, Gate};

fn bm25(p: &str) -> Gate {
    gate(p, true)
}

fn skip(p: &str) -> bool {
    matches!(gate(p, true), Gate::Skip(_))
}

#[test]
fn task_notification_is_skipped_first() {
    let p =
        "<task-notification><task-id>a1</task-id><status>completed</status></task-notification>";
    assert_eq!(gate(p, true), Gate::Skip("machine prompt"));
    assert_eq!(
        gate(&format!("  \n{p}"), true),
        Gate::Skip("machine prompt")
    );
    // The tag wins over a URL in the same prompt.
    let with_url = "<task-notification>see https://example.com/a for details</task-notification>";
    assert_eq!(gate(with_url, true), Gate::Skip("machine prompt"));
    // Only a prefix counts.
    assert_ne!(
        gate(
            "please explain what a <task-notification> tag does in this log",
            true
        ),
        Gate::Skip("machine prompt")
    );
}

#[test]
fn single_words_and_short_commands_are_skipped() {
    for p in [
        "yes",
        "continue",
        "fix the test",
        "ok thanks",
        "go ahead",
        "",
        "   ",
        "run it",
    ] {
        assert!(skip(p), "{p:?}");
    }
}

#[test]
fn three_content_words_skip_and_four_pass() {
    assert_eq!(content_words("refactor parser module"), 3);
    assert!(skip("refactor parser module"));
    assert_eq!(content_words("refactor parser module carefully"), 4);
    assert_eq!(bm25("refactor parser module carefully"), Gate::PromptBm25);
}

#[test]
fn stop_words_and_short_words_do_not_count() {
    assert_eq!(content_words("what about this and that with the one"), 0);
    assert_eq!(content_words("it is an ox up to me"), 0);
    assert!(skip("what about this and that with the one"));
}

#[test]
fn two_urls_go_to_the_url_channel() {
    let p = "compare https://sqlite.org/wal.html and https://git-scm.com/docs/git-rebase please";
    assert_eq!(
        gate(p, true),
        Gate::PromptUrl(vec![
            "https://sqlite.org/wal.html".to_string(),
            "https://git-scm.com/docs/git-rebase".to_string()
        ])
    );
}

#[test]
fn url_gate_ignores_the_prompt_bm25_setting_and_word_count() {
    assert_eq!(
        gate("https://example.com/a", false),
        Gate::PromptUrl(vec!["https://example.com/a".to_string()])
    );
}

#[test]
fn trailing_punctuation_is_not_part_of_the_url() {
    assert_eq!(
        bm25("is https://example.com/docs, (or https://example.org/x.) the same?"),
        Gate::PromptUrl(vec![
            "https://example.com/docs".to_string(),
            "https://example.org/x".to_string()
        ])
    );
}

#[test]
fn at_most_five_urls_and_duplicates_once() {
    let p = "https://a.example/1 https://a.example/2 https://a.example/3 https://a.example/1 \
             https://a.example/4 https://a.example/5 https://a.example/6";
    let Gate::PromptUrl(urls) = bm25(p) else {
        panic!("not a url gate");
    };
    assert_eq!(urls.len(), 5);
    assert_eq!(urls[4], "https://a.example/5");
}

#[test]
fn plain_http_is_not_a_url_for_the_gate() {
    assert!(matches!(
        bm25("fetch http://example.org/page and summarize the stuff"),
        Gate::PromptBm25
    ));
    assert!(skip("http://example.org/a"));
}

#[test]
fn long_question_goes_to_prompt_bm25_when_enabled() {
    let p = "How do I configure the SQLite busy timeout when several processes write to the same database file?";
    assert_eq!(gate(p, true), Gate::PromptBm25);
    assert_eq!(gate(p, false), Gate::Skip("prompt_bm25 is off"));
}

#[test]
fn uppercase_and_punctuation_do_not_change_the_count() {
    assert_eq!(
        content_words("REFACTOR!!! parser... (module); carefully?"),
        4
    );
}

#[test]
fn cjk_runs_of_two_or_more_characters_count() {
    // 4 runs split by punctuation.
    let p = "\u{307e}\u{305a}\u{3001}\u{30c7}\u{30fc}\u{30bf}\u{30d9}\u{30fc}\u{30b9}\u{3092}\u{958b}\u{3044}\u{3066}\u{3001}\u{691c}\u{7d22}\u{3092}\u{5b9f}\u{884c}\u{3057}\u{3001}\u{7d50}\u{679c}\u{3092}\u{78ba}\u{8a8d}\u{3057}\u{307e}\u{3059}";
    assert_eq!(content_words(p), 4);
    assert_eq!(gate(p, true), Gate::PromptBm25);
    // A single run is one word.
    assert!(skip("\u{304a}\u{9858}\u{3044}\u{3057}\u{307e}\u{3059}"));
    assert!(skip("\u{306f}\u{3044}"));
    // Single characters do not count.
    assert_eq!(content_words("\u{3042}\u{3001}\u{3044}\u{3001}\u{3046}\u{3001}\u{3048}"), 0);
}

#[test]
fn mixed_cjk_and_english_prompts_count_both() {
    assert_eq!(content_words("SQLite \u{306e} WAL \u{30e2}\u{30fc}\u{30c9} \u{306b}\u{3064}\u{3044}\u{3066}"), 4);
    assert_eq!(bm25("SQLite \u{306e} WAL \u{30e2}\u{30fc}\u{30c9} \u{306b}\u{3064}\u{3044}\u{3066}"), Gate::PromptBm25);
    assert!(skip("fix \u{30c6}\u{30b9}\u{30c8}"));
}

#[test]
fn a_cjk_prompt_with_a_url_goes_to_the_url_channel() {
    assert_eq!(
        bm25("\u{3053}\u{308c}\u{3092}\u{8aad}\u{3093}\u{3067} https://example.com/ja \u{8981}\u{7d04}\u{3057}\u{3066}"),
        Gate::PromptUrl(vec!["https://example.com/ja".to_string()])
    );
}

#[test]
fn multi_line_prompt_with_code_is_counted_by_words() {
    let p =
        "Why does this fail?\n```\ncargo test --locked\n```\nThe linker reports undefined symbols";
    assert_eq!(bm25(p), Gate::PromptBm25);
}
