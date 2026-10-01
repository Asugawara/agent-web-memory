//! Redaction of secrets and personal data before anything is stored (plan-v2 §4.3).
//!
//! Every match becomes `[redacted:{kind}]`. Order: PEM blocks, JWTs, provider
//! keys, secret assignments, emails, IPv4 addresses, home paths, temp paths,
//! user terms. Over-redaction is preferred to leaking: prose such as
//! `key: something` is redacted when the value has 8 or more non-space
//! characters. An address without a TLD (`user@localhost`) is not an email and
//! is left unchanged.

use regex::{Captures, Regex};
use std::sync::OnceLock;

struct Patterns {
    pem: Regex,
    jwt: Regex,
    aws: Regex,
    gcp: Regex,
    github: Regex,
    slack: Regex,
    assignment: Regex,
    email: Regex,
    ipv4: Regex,
    home: Regex,
    temp: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| {
        let re = |s: &str| Regex::new(s).expect("valid redaction pattern");
        Patterns {
            pem: re(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
            jwt: re(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
            aws: re(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
            gcp: re(r"\bAIza[0-9A-Za-z_-]{35}"),
            github: re(r"\b(?:gh[pos]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
            slack: re(r"\bxox[abpr]-[A-Za-z0-9-]{10,}"),
            assignment: re(
                r#"(?i)((?:api_key|key|secret|token|password|passwd)["']?\s*[=:]\s*["']?)([^\s"']{8,})"#,
            ),
            email: re(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
            ipv4: re(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b",
            ),
            home: re(r#"(^|[^\w.-])/(?:Users|home)/[^/\s"']+"#),
            temp: re(
                r#"(^|[^\w.-])(/private/tmp|/private/var/folders|/tmp|/var/folders)((?:/[^\s"']*)?)"#,
            ),
        }
    })
}

fn marker(kind: &str) -> String {
    format!("[redacted:{kind}]")
}

/// Replace every match of `re` with the marker for `kind`; returns the new text.
fn plain(re: &Regex, text: &str, kind: &str, count: &mut u32) -> String {
    re.replace_all(text, |_: &Captures| {
        *count += 1;
        marker(kind)
    })
    .into_owned()
}

/// Redact secrets, emails, IPv4 addresses, home and temp paths and `user_terms`.
/// Returns the redacted text and the number of replacements.
pub fn redact(text: &str, user_terms: &[String]) -> (String, u32) {
    let p = patterns();
    let mut n = 0u32;
    let mut s = plain(&p.pem, text, "pem", &mut n);
    s = plain(&p.jwt, &s, "jwt", &mut n);
    s = plain(&p.aws, &s, "aws-key", &mut n);
    s = plain(&p.gcp, &s, "gcp-key", &mut n);
    s = plain(&p.github, &s, "github-token", &mut n);
    s = plain(&p.slack, &s, "slack-token", &mut n);
    s = p
        .assignment
        .replace_all(&s, |c: &Captures| {
            if c[2].starts_with("[redacted:") {
                return c[0].to_string();
            }
            n += 1;
            format!("{}{}", &c[1], marker("secret-assignment"))
        })
        .into_owned();
    s = plain(&p.email, &s, "email", &mut n);
    s = redact_ipv4(&s, &mut n);
    s = p
        .home
        .replace_all(&s, |c: &Captures| {
            n += 1;
            format!("{}{}", &c[1], marker("home-path"))
        })
        .into_owned();
    let src = s.clone();
    s = p
        .temp
        .replace_all(&src, |c: &Captures| {
            let whole = c.get(0).expect("whole match");
            // A bare `/tmp` followed by a word character is a different name (`/tmpfoo`).
            if c[3].is_empty()
                && src[whole.end()..]
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_alphanumeric() || ch == '_')
            {
                return c[0].to_string();
            }
            n += 1;
            format!("{}{}", &c[1], marker("temp-path"))
        })
        .into_owned();
    for term in user_terms.iter().filter(|t| !t.is_empty()) {
        if let Ok(re) = Regex::new(&format!("(?i){}", regex::escape(term))) {
            s = plain(&re, &s, "term", &mut n);
        }
    }
    (s, n)
}

/// IPv4 redaction that leaves dotted numbers inside longer version-like strings
/// (`1.2.3.4.5`) alone.
fn redact_ipv4(text: &str, n: &mut u32) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in patterns().ipv4.find_iter(text) {
        let before_dot =
            m.start() >= 2 && b[m.start() - 1] == b'.' && b[m.start() - 2].is_ascii_digit();
        let after_dot =
            m.end() + 1 < b.len() && b[m.end()] == b'.' && b[m.end() + 1].is_ascii_digit();
        if before_dot || after_dot {
            continue;
        }
        out.push_str(&text[last..m.start()]);
        out.push_str(&marker("ipv4"));
        last = m.end();
        *n += 1;
    }
    out.push_str(&text[last..]);
    out
}
