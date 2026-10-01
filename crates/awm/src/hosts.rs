//! Private-host detection: URLs that must never be captured (plan-v2 §4.3).

use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

const PRIVATE_SUFFIXES: [&str; 5] = [".local", ".internal", ".corp", ".lan", ".home.arpa"];

/// True when the URL must not be captured: a non-http(s) scheme, `localhost`
/// (and `*.localhost`), names under `.local`, `.internal`, `.corp`, `.lan` or
/// `.home.arpa`, private, loopback, link-local and shared-address IP literals
/// (an IPv4-mapped IPv6 literal is judged by its IPv4 address), or a host that
/// matches one of `exclude_globs`.
pub fn is_private(url: &Url, exclude_globs: &[String]) -> bool {
    if !matches!(url.scheme(), "http" | "https") {
        return true;
    }
    let host_text = match url.host() {
        None => return true,
        Some(Host::Ipv4(ip)) => {
            if private_v4(ip) {
                return true;
            }
            ip.to_string()
        }
        Some(Host::Ipv6(ip)) => {
            if private_v6(ip) {
                return true;
            }
            ip.to_string()
        }
        Some(Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_lowercase();
            if d.is_empty()
                || d == "localhost"
                || d.ends_with(".localhost")
                || PRIVATE_SUFFIXES.iter().any(|s| d.ends_with(s))
            {
                return true;
            }
            d
        }
    };
    exclude_globs.iter().any(|g| host_matches(&host_text, g))
}

fn private_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 10
        || a == 127
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
        || (a == 100 && (64..=127).contains(&b))
}

fn private_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return private_v4(v4);
    }
    let first = ip.segments()[0];
    ip == Ipv6Addr::LOCALHOST || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
}

/// Case-insensitive glob match of a whole host name; `*` matches any run of
/// characters (dots included). An empty glob matches nothing.
pub fn host_matches(host: &str, glob: &str) -> bool {
    if glob.is_empty() {
        return false;
    }
    let h: Vec<char> = host.to_lowercase().chars().collect();
    let g: Vec<char> = glob.to_lowercase().chars().collect();
    let (mut hi, mut gi) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while hi < h.len() {
        if gi < g.len() && g[gi] == '*' {
            star = Some((gi, hi));
            gi += 1;
        } else if gi < g.len() && g[gi] == h[hi] {
            gi += 1;
            hi += 1;
        } else if let Some((sg, sh)) = star {
            gi = sg + 1;
            hi = sh + 1;
            star = Some((sg, sh + 1));
        } else {
            return false;
        }
    }
    while gi < g.len() && g[gi] == '*' {
        gi += 1;
    }
    gi == g.len()
}
