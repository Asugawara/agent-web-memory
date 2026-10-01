use awm::hosts::{host_matches, is_private};
use url::Url;

fn private(url: &str, globs: &[&str]) -> bool {
    let globs: Vec<String> = globs.iter().map(|s| s.to_string()).collect();
    is_private(&Url::parse(url).unwrap(), &globs)
}

#[test]
fn private_hosts() {
    let cases = [
        "http://localhost:3000/a",
        "https://wiki.corp/x",
        "https://nas.home.arpa/",
        "https://printer.local/",
        "https://db.internal/status",
        "https://router.lan/",
        "http://10.1.2.3/",
        "http://172.16.0.1/",
        "http://172.31.255.255/",
        "http://192.168.1.10/",
        "http://127.0.0.1:8080/",
        "http://169.254.169.254/latest/meta-data",
        "http://100.64.0.1/",
        "http://[::1]/",
        "http://[fd12:3456::1]/",
        "http://[fe80::1]/",
        "http://[::ffff:10.0.0.1]/",
        "ftp://example.com/file",
        "file:///etc/hosts",
        "https://LOCALHOST/",
    ];
    for u in cases {
        assert!(private(u, &[]), "should be private: {u}");
    }
}

#[test]
fn public_hosts() {
    let cases = [
        "https://example.com/",
        "https://docs.rs/url",
        "http://172.32.0.1/",
        "http://172.15.255.255/",
        "http://100.128.0.1/",
        "http://100.63.255.255/",
        "http://8.8.8.8/",
        "http://[2001:4860:4860::8888]/",
        "https://notlocal.example.org/",
        "https://localhost.example.com/",
    ];
    for u in cases {
        assert!(!private(u, &[]), "should be public: {u}");
    }
}

#[test]
fn exclude_globs() {
    assert!(private("https://wiki.example.com/p", &["wiki.example.com"]));
    assert!(private(
        "https://a.b.example.corp.net/",
        &["*.example.corp.net"]
    ));
    assert!(private("https://WIKI.Example.com/p", &["wiki.EXAMPLE.com"]));
    assert!(!private("https://example.com/", &["*.example.com"]));
    assert!(!private(
        "https://wiki.example.com.evil.io/",
        &["wiki.example.com"]
    ));
    assert!(!private("https://example.com/", &[""]));
}

#[test]
fn glob_matching() {
    assert!(host_matches("a.example.corp", "*.example.corp"));
    assert!(host_matches("a.b.example.corp", "*.example.corp"));
    assert!(!host_matches("example.corp", "*.example.corp"));
    assert!(host_matches("EXAMPLE.com", "example.COM"));
    assert!(host_matches("anything", "*"));
    assert!(host_matches("wiki-1.example.com", "wiki-*.example.*"));
    assert!(!host_matches("wiki.example.com", "wiki"));
    assert!(!host_matches("example.com", ""));
}
