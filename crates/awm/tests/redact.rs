use awm::redact::redact;

fn run(text: &str) -> (String, u32) {
    redact(text, &[])
}

#[test]
fn secret_shapes_are_redacted() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let asia = format!("ASIA{}", "IOSFODNN7EXAMPLE");
    let gcp = format!("AIzaSy{}", "0123456789abcdefghijklmnopqrstuvw");
    assert_eq!(gcp.len(), 39);
    let ghp = format!("ghp_{}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
    let gho = format!("gho_{}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
    let ghs = format!("ghs_{}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
    let pat = "github_pat_11ABCDEFG0abcdefghij_klmnopqrstuvwxyz0123456789";
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let pem =
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc\n-----END RSA PRIVATE KEY-----";
    // (input, expected output, expected count)
    let cases: Vec<(String, String, u32)> = vec![
        (format!("id {aws} ok"), "id [redacted:aws-key] ok".into(), 1),
        (
            format!("id {asia} ok"),
            "id [redacted:aws-key] ok".into(),
            1,
        ),
        (format!("k={gcp}"), "k=[redacted:gcp-key]".into(), 1),
        (
            format!("use {gcp} now"),
            "use [redacted:gcp-key] now".into(),
            1,
        ),
        (format!("t {ghp}"), "t [redacted:github-token]".into(), 1),
        (format!("t {gho}"), "t [redacted:github-token]".into(), 1),
        (format!("t {ghs}"), "t [redacted:github-token]".into(), 1),
        (format!("t {pat}"), "t [redacted:github-token]".into(), 1),
        (
            "xoxb-123456789012-abcdefghijkl".into(),
            "[redacted:slack-token]".into(),
            1,
        ),
        (
            "xoxp-123456789012-abcdefghijkl".into(),
            "[redacted:slack-token]".into(),
            1,
        ),
        (format!("Bearer {jwt}"), "Bearer [redacted:jwt]".into(), 1),
        (
            format!("before\n{pem}\nafter"),
            "before\n[redacted:pem]\nafter".into(),
            1,
        ),
        (
            "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----".into(),
            "[redacted:pem]".into(),
            1,
        ),
        (
            "password=hunter2hunter2".into(),
            "password=[redacted:secret-assignment]".into(),
            1,
        ),
        (
            "API_KEY: sk-live-abcdef123".into(),
            "API_KEY: [redacted:secret-assignment]".into(),
            1,
        ),
        (
            r#"{"token":"abcdefghijkl"}"#.into(),
            r#"{"token":"[redacted:secret-assignment]"}"#.into(),
            1,
        ),
        (
            "mail me at jane.doe+x@example.co.uk please".into(),
            "mail me at [redacted:email] please".into(),
            1,
        ),
        (
            "host 192.168.0.12:8080 up".into(),
            "host [redacted:ipv4]:8080 up".into(),
            1,
        ),
        (
            "see /Users/alice/dev/app/src/main.rs".into(),
            "see [redacted:home-path]/dev/app/src/main.rs".into(),
            1,
        ),
        (
            "cd /home/bob/work".into(),
            "cd [redacted:home-path]/work".into(),
            1,
        ),
        (
            "wrote /private/tmp/claude-1/x/out.txt done".into(),
            "wrote [redacted:temp-path] done".into(),
            1,
        ),
        (
            "wrote /tmp/a/b.log".into(),
            "wrote [redacted:temp-path]".into(),
            1,
        ),
        (
            "in /var/folders/zz/abc/T/x".into(),
            "in [redacted:temp-path]".into(),
            1,
        ),
        (
            "two 10.0.0.1 and 10.0.0.2".into(),
            "two [redacted:ipv4] and [redacted:ipv4]".into(),
            2,
        ),
    ];
    assert!(cases.len() >= 20);
    for (input, want, count) in cases {
        let (out, n) = run(&input);
        assert_eq!((out.as_str(), n), (want.as_str(), count), "input: {input}");
    }
}

#[test]
fn user_terms_are_redacted_case_insensitively() {
    let terms = vec![
        "Project Falcon".to_string(),
        String::new(),
        "acme".to_string(),
    ];
    let (out, n) = redact("About project falcon at ACME and Acme.", &terms);
    assert_eq!(
        out,
        "About [redacted:term] at [redacted:term] and [redacted:term]."
    );
    assert_eq!(n, 3);
}

#[test]
fn look_alikes_survive() {
    let cases = [
        "deadbeefdeadbeef",                   // 16 hex chars, not a key
        "XAKIAIOSFODNN7EXAMPLE",              // AKIA inside a longer word
        "AKIAIOSFODNN7EXAMPLEEXTRA",          // longer than 20 characters
        "AKIA1234",                           // too short
        "version 1.2.3 released",             // three-part version
        "version 1.2.3.4.5 released",         // five-part version, not an address
        "address 256.1.1.1 is invalid",       // octet out of range
        "user@localhost",                     // no TLD: not treated as an email
        "key=short",                          // value under 8 characters
        "token: abc",                         // value under 8 characters
        "ghp_tooshort",                       // GitHub prefix with a short body
        "eyJ.a.b",                            // JWT look-alike with tiny segments
        "/tmpfoo/bar and /usr/local/bin",     // not temp paths
        "see https://example.com/Users/page", // /Users inside a URL path
        "-----BEGIN CERTIFICATE-----",        // certificates are public
        "The monkeys ate bananas",            // plain prose
    ];
    assert!(cases.len() >= 10);
    for input in cases {
        assert_eq!(run(input), (input.to_string(), 0), "input: {input}");
    }
}

#[test]
fn redaction_is_idempotent() {
    let (once, n) = run("token=abcdefgh12 from /Users/a/x and 1.2.3.4");
    assert_eq!(n, 3);
    assert_eq!(run(&once), (once.clone(), 0));
}
