use awm::normalize::{norm_query, norm_url, token_set, words};

#[test]
fn url_cases() {
    let cases: &[(&str, Option<&str>)] = &[
        ("https://Example.COM/Path", Some("https://example.com/Path")),
        (
            "https://example.com/a#section",
            Some("https://example.com/a"),
        ),
        (
            "https://example.com/a?utm_source=x",
            Some("https://example.com/a"),
        ),
        (
            "https://example.com/a?utm_source=x&utm_medium=y&utm_campaign=z",
            Some("https://example.com/a"),
        ),
        (
            "https://example.com/a?gclid=abc",
            Some("https://example.com/a"),
        ),
        (
            "https://example.com/a?fbclid=abc",
            Some("https://example.com/a"),
        ),
        (
            "https://example.com/a?b=2&a=1",
            Some("https://example.com/a?a=1&b=2"),
        ),
        ("https://example.com/a/", Some("https://example.com/a")),
        ("https://Example.com/", Some("https://example.com")),
        (
            "https://example.com/a?q=rust&utm_term=k",
            Some("https://example.com/a?q=rust"),
        ),
        ("https://example.com:443/a", Some("https://example.com/a")),
        (
            "https://example.com:8443/a",
            Some("https://example.com:8443/a"),
        ),
        ("http://example.com/a", Some("http://example.com/a")),
        (
            "https://example.com/a?flag",
            Some("https://example.com/a?flag"),
        ),
        (
            "https://example.com/a?UTM_Source=x&id=7",
            Some("https://example.com/a?id=7"),
        ),
        (
            "https://example.com/a?b=1#frag",
            Some("https://example.com/a?b=1"),
        ),
        ("  https://example.com/a  ", Some("https://example.com/a")),
        (
            "https://example.com/a%20b",
            Some("https://example.com/a%20b"),
        ),
        (
            "http://www.datypic.com/sc/ooxml/t-a_ST_PositiveCoordinate.html",
            Some("http://www.datypic.com/sc/ooxml/t-a_ST_PositiveCoordinate.html"),
        ),
        (
            "https://example.com/a?utm_source=x#top",
            Some("https://example.com/a"),
        ),
        (
            "https://example.com/a/b/c/?z=1&y=2&x=3",
            Some("https://example.com/a/b/c?x=3&y=2&z=1"),
        ),
        (
            "https://sub.Example.com/A?Id=1",
            Some("https://sub.example.com/A?Id=1"),
        ),
        // The spike returned a lower-cased copy for these; the product returns None.
        ("Not A Url/", None),
        ("", None),
        ("mailto:someone@example.com", None),
        ("file:///etc/hosts", None),
        ("example.com/no-scheme", None),
        ("http://[::1]:8080/a/", Some("http://[::1]:8080/a")),
    ];
    assert!(cases.len() >= 23);
    for (input, want) in cases {
        assert_eq!(norm_url(input).as_deref(), *want, "input: {input}");
    }
}

#[test]
fn url_equivalence_classes() {
    assert_eq!(
        norm_url("https://a.com/x?b=1&a=2&utm_source=n"),
        norm_url("https://A.com/x/?a=2&b=1#h")
    );
    assert_ne!(norm_url("https://a.com/x"), norm_url("https://a.com/y"));
}

#[test]
fn url_normalisation_is_idempotent() {
    let once = norm_url("https://Example.com/a/?z=1&utm_source=x&a=2#f").unwrap();
    assert_eq!(norm_url(&once).as_deref(), Some(once.as_str()));
}

#[test]
fn query_cases() {
    let cases: &[(&str, &str)] = &[
        ("Hello World", "hello world"),
        ("Hello, World!", "hello world"),
        (
            "\u{FF21}\u{FF22}\u{FF23}\u{3000}\u{FF11}\u{FF12}\u{FF13}",
            "abc 123",
        ),
        ("RUST Async Runtime", "rust async runtime"),
        ("foo-bar_baz", "foo bar baz"),
        ("  many   spaces\there ", "many spaces here"),
        ("\"exact phrase\"", "exact phrase"),
        ("", ""),
        ("?!.,;:", ""),
        ("gpt-5.6 luna", "gpt 5 6 luna"),
        ("https://x.com/a?b=c", "https x com a b c"),
        ("Caf\u{E9} Au Lait", "caf\u{E9} au lait"),
        ("\u{FF76}\u{FF85}", "\u{30AB}\u{30CA}"),
        (
            "SQLite FTS5 bm25 column weights",
            "sqlite fts5 bm25 column weights",
        ),
        ("C++ vs Rust", "c vs rust"),
        ("node.js 20.x", "node js 20 x"),
        ("a\nb\r\nc", "a b c"),
        (
            "\u{691C}\u{7D22}\u{30A8}\u{30F3}\u{30B8}\u{30F3}",
            "\u{691C}\u{7D22}\u{30A8}\u{30F3}\u{30B8}\u{30F3}",
        ),
        (
            "Rust\u{3067}\u{691C}\u{7D22}",
            "rust \u{3067}\u{691C}\u{7D22}",
        ),
    ];
    assert!(cases.len() >= 17);
    for (input, want) in cases {
        assert_eq!(norm_query(input), *want, "input: {input}");
    }
}

#[test]
fn mixed_script_split() {
    assert_eq!(
        words("Rust\u{3067}\u{691C}\u{7D22}"),
        vec!["rust".to_string(), "\u{3067}\u{691C}\u{7D22}".to_string()]
    );
}

#[test]
fn query_normalisation_is_idempotent() {
    let once = norm_query("Hello,  World!!");
    assert_eq!(norm_query(&once), once);
}

#[test]
fn token_set_ignores_case_order_punctuation_and_repeats() {
    let a = token_set("SQLite FTS5: bm25 column weights");
    assert_eq!(a, token_set("weights, column BM25 (fts5) sqlite sqlite"));
    assert_eq!(a, ["bm25", "column", "fts5", "sqlite", "weights"]);
    // An added word changes the set.
    assert_ne!(a, token_set("sqlite fts5 bm25 column weights 2026"));
    assert!(token_set("  ...  ").is_empty());
}

#[test]
fn token_set_splits_cjk_runs_and_a_codex_join_is_one_set() {
    assert_eq!(
        token_set("rust\u{3067}\u{691c}\u{7d22}"),
        ["rust", "\u{3067}\u{691c}\u{7d22}"]
    );
    assert_eq!(token_set("b query | a query"), ["a", "b", "query"]);
    assert_eq!(token_set("a query | b query"), token_set("b query a query"));
}
