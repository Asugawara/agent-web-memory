//! Shared by the sync tests: a forwarding HTTP proxy that answers chosen pushes itself.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// A forwarding HTTP proxy in front of a test server that answers chosen `POST /v1/records` requests
/// itself (a proxy, WAF or load balancer in front of the server, RVT3v V2). One request per
/// connection. Each queued rule answers the next push: `None` forwards it, `Some(raw)` replies
/// with those bytes; with the queue empty everything is forwarded.
pub struct Proxy {
    pub addr: SocketAddr,
    rules: Arc<Mutex<std::collections::VecDeque<Option<String>>>>,
}

impl Proxy {
    pub fn start(upstream: SocketAddr) -> Proxy {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let rules: Arc<Mutex<std::collections::VecDeque<Option<String>>>> = Arc::default();
        let queue = rules.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut client) = conn else { continue };
                let queue = queue.clone();
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 65_536];
                    let head_end = loop {
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                        match client.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let len: usize = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    while buf.len() < head_end + len {
                        match client.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let is_push = head.starts_with("POST /v1/records ");
                    let rule = if is_push {
                        queue.lock().unwrap().pop_front().flatten()
                    } else {
                        None
                    };
                    if let Some(raw) = rule {
                        let _ = client.write_all(raw.as_bytes());
                        return;
                    }
                    let mut fwd: String = head
                        .lines()
                        .filter(|l| {
                            !l.is_empty() && !l.to_ascii_lowercase().starts_with("connection:")
                        })
                        .map(|l| format!("{l}\r\n"))
                        .collect();
                    fwd.push_str("Connection: close\r\n\r\n");
                    let Ok(mut up) = std::net::TcpStream::connect(upstream) else {
                        return;
                    };
                    let mut bytes = fwd.into_bytes();
                    bytes.extend_from_slice(&buf[head_end..head_end + len]);
                    let _ = up.write_all(&bytes);
                    let mut resp = Vec::new();
                    let _ = up.read_to_end(&mut resp);
                    let _ = client.write_all(&resp);
                });
            }
        });
        Proxy { addr, rules }
    }

    /// The next push is answered by `rule` (`None`: forwarded).
    pub fn queue(&self, rule: Option<String>) {
        self.rules.lock().unwrap().push_back(rule);
    }
}

/// A reply with no awm error body, as a proxy sends it.
pub fn bare(status: &str) -> String {
    let body = "<html>refused</html>";
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A reply with an awm error body.
pub fn coded(status: &str, code: &str) -> String {
    let body = format!(r#"{{"error":"{code}","message":"test"}}"#);
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}
