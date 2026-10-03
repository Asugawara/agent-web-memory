//! Shared by the team tests: the clock helpers, a forwarding HTTP proxy that answers chosen
//! pushes itself, and (with `sync` and `serve`) the in-process test server and the machine
//! harness that drives the built `awm` binary.
//!
//! Each suite adds its own helpers as `impl support::Srv { .. }` and `impl support::Node { .. }`
//! blocks (the suites are separate crates, so a type of this module is local to each of them).

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// Unix seconds now.
pub fn unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Unix milliseconds now.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

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

#[cfg(all(feature = "sync", feature = "serve"))]
#[allow(unused_imports)]
pub use harness::*;

/// The in-process server and the machine of the team suites.
#[cfg(all(feature = "sync", feature = "serve"))]
mod harness {
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use awm::db::{self, Role};
    use awm::record::sha256_hex;
    use awm::sync::http::{own_version, Client};
    use awm::sync::state::{self, Identity};
    use awm_server::auth;
    use awm_server::http::embedded::{self, Embedded};
    use awm_server::http::{AppState, LogSink, ServerConfig};
    use awm_server::store::sqlite::SqliteStore;
    use awm_server::store::Store;
    use rusqlite::{params, Connection};

    use super::{now_ms, unix_secs};

    /// The server's log lines.
    #[derive(Default)]
    pub struct Capture(pub Mutex<Vec<String>>);

    impl LogSink for Capture {
        fn line(&self, line: &str) {
            self.0.lock().unwrap().push(line.to_string());
        }
    }

    /// The daily record quota most suites run under (no limit in practice).
    pub const QUOTA: u32 = 1_000_000;

    /// A server configuration with the rate limits out of the way: tests push thousands of
    /// records and run many syncs a minute.
    pub fn server_config(records_per_day: u32) -> ServerConfig {
        let v = own_version();
        let mut c = ServerConfig::new(v.clone(), v);
        c.limits.records_per_day = records_per_day;
        c.limits.requests_per_minute = 1_000_000;
        c.limits.request_burst = 1_000_000;
        c.limits.anonymous_per_minute = 1_000_000;
        c.limits.joins_per_hour = 1_000;
        c
    }

    pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
    }

    /// `awm_server::http::embedded` on a loopback port over a `SqliteStore` in a scratch
    /// directory, with a captured log.
    pub struct Srv {
        pub store: Arc<SqliteStore>,
        pub emb: Option<Embedded>,
        pub addr: SocketAddr,
        pub dir: tempfile::TempDir,
        pub logs: Arc<Capture>,
        pub snaps: AtomicUsize,
    }

    impl Srv {
        pub fn start() -> Srv {
            Srv::start_from(None)
        }

        /// A server, optionally on a copy of another server's canonical export (`team move`).
        pub fn start_from(db: Option<&Path>) -> Srv {
            let dir = tempfile::tempdir().unwrap();
            let data = dir.path().join("data");
            if let Some(src) = db {
                std::fs::create_dir_all(&data).unwrap();
                std::fs::copy(src, data.join("server.db")).unwrap();
            }
            let store = Arc::new(SqliteStore::open(&data).unwrap());
            if db.is_some() {
                embedded::block_on(store.renew_generation(unix_secs())).unwrap();
            }
            let logs = Arc::new(Capture::default());
            let emb = embedded::spawn(Srv::state(&store, &logs, QUOTA)).unwrap();
            Srv {
                store,
                addr: emb.addr(),
                emb: Some(emb),
                dir,
                logs,
                snaps: AtomicUsize::new(0),
            }
        }

        pub fn state(store: &Arc<SqliteStore>, logs: &Arc<Capture>, quota: u32) -> AppState {
            AppState::new(store.clone() as Arc<dyn Store>, server_config(quota))
                .with_log_sink(logs.clone())
        }

        pub fn url(&self) -> String {
            format!("http://{}", self.addr)
        }

        pub fn anonymous(&self) -> Client {
            Client::new(&self.url(), None, None).unwrap()
        }

        /// Stops the server (connections are refused afterwards).
        pub fn stop(&mut self) {
            if let Some(mut e) = self.emb.take() {
                e.stop();
            }
        }

        /// Starts the stopped server again on the same address and store, with a daily record
        /// quota. The address can stay busy for a moment after `stop()` under load, so binding
        /// is retried up to 20 times, 100 ms apart.
        pub fn resume_with(&mut self, quota: u32) {
            let mut attempt = 0;
            let emb = loop {
                attempt += 1;
                match embedded::spawn_on(self.addr, Srv::state(&self.store, &self.logs, quota)) {
                    Ok(emb) => break emb,
                    Err(e) if attempt >= 20 => panic!("cannot bind {} again: {e}", self.addr),
                    Err(_) => std::thread::sleep(Duration::from_millis(100)),
                }
            };
            self.emb = Some(emb);
        }

        pub fn resume(&mut self) {
            self.resume_with(QUOTA);
        }

        pub fn snapshot(&self) -> PathBuf {
            let n = self.snaps.fetch_add(1, Ordering::SeqCst) + 1;
            let dest = self.dir.path().join(format!("snap-{n}.db"));
            embedded::block_on(self.store.snapshot(dest.clone())).unwrap();
            dest
        }

        /// Replaces the server with the copy in `snap` under a new generation, as `awm serve
        /// restore` does (sync-v1 §11).
        pub fn restore(&mut self, snap: &Path) {
            self.stop();
            let data = self.dir.path().join("data");
            for f in ["server.db", "server.db-wal", "server.db-shm"] {
                let _ = std::fs::remove_file(data.join(f));
            }
            std::fs::copy(snap, data.join("server.db")).unwrap();
            let store = Arc::new(SqliteStore::open(&data).unwrap());
            embedded::block_on(store.renew_generation(unix_secs())).unwrap();
            self.store = store;
            self.resume();
        }

        pub fn bootstrap_token(&self) -> String {
            embedded::block_on(auth::issue_bootstrap(&*self.store, unix_secs()))
                .unwrap()
                .as_str()
                .to_string()
        }

        pub fn log_text(&self) -> String {
            self.logs.0.lock().unwrap().join("\n")
        }

        pub fn db_path(&self) -> PathBuf {
            self.dir.path().join("data").join("server.db")
        }

        /// The bytes of the server database and its WAL and shared-memory files.
        pub fn db_bytes(&self) -> Vec<u8> {
            let mut out = Vec::new();
            for suffix in ["", "-wal", "-shm"] {
                let p = PathBuf::from(format!("{}{suffix}", self.db_path().display()));
                if let Ok(b) = std::fs::read(&p) {
                    out.extend(b);
                }
            }
            out
        }

        /// A direct connection to the server database (a compromised host).
        pub fn raw(&self) -> Connection {
            let c = Connection::open(self.db_path()).unwrap();
            c.busy_timeout(Duration::from_secs(5)).unwrap();
            c
        }

        pub fn deleted_ids(&self) -> Vec<String> {
            embedded::block_on(self.store.deletions(0, 5_000))
                .unwrap()
                .entries
                .iter()
                .map(|e| e.record_id.to_string())
                .collect()
        }
    }

    /// What one run of the `awm` binary printed.
    pub struct Out {
        pub code: Option<i32>,
        pub stdout: String,
        pub stderr: String,
    }

    impl Out {
        pub fn all(&self) -> String {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }

    /// One machine: a data directory (what `AWM_HOME` names) with a migrated database, and a
    /// home directory, driven through the built `awm` binary.
    pub struct Node {
        pub dir: tempfile::TempDir,
        pub home: tempfile::TempDir,
        /// Where `project()` lives: in the data directory, or in the home directory (so that
        /// `purge --all` finds only awm's files).
        project_in_home: bool,
    }

    impl Node {
        /// A machine whose project directory is in its data directory.
        pub fn new() -> Node {
            Node::build(false)
        }

        /// A machine whose project directory is in its home directory, outside the data
        /// directory.
        pub fn new_apart() -> Node {
            Node::build(true)
        }

        fn build(project_in_home: bool) -> Node {
            let dir = tempfile::tempdir().unwrap();
            let home = tempfile::tempdir().unwrap();
            let mut conn = db::open(&dir.path().join("awm.db"), Role::Cli).unwrap();
            db::migrate(&mut conn).unwrap();
            let node = Node {
                dir,
                home,
                project_in_home,
            };
            std::fs::create_dir_all(node.project_dir()).unwrap();
            node
        }

        /// A copy of `other`'s data directory taken now (the same device, as a process that
        /// read its state earlier sees it).
        pub fn copy_of(other: &Node) -> Node {
            let dir = tempfile::tempdir().unwrap();
            let home = tempfile::tempdir().unwrap();
            for e in std::fs::read_dir(other.path()).unwrap().flatten() {
                if e.file_type().unwrap().is_file() {
                    std::fs::copy(e.path(), dir.path().join(e.file_name())).unwrap();
                }
            }
            let node = Node {
                dir,
                home,
                project_in_home: other.project_in_home,
            };
            std::fs::create_dir_all(node.project_dir()).unwrap();
            node
        }

        pub fn path(&self) -> &Path {
            self.dir.path()
        }

        fn project_dir(&self) -> PathBuf {
            if self.project_in_home {
                self.home.path().join("proj")
            } else {
                self.path().join("proj")
            }
        }

        pub fn project(&self) -> PathBuf {
            std::fs::canonicalize(self.project_dir()).unwrap()
        }

        /// The `awm` binary with this machine's environment.
        fn command(&self, args: &[&str]) -> Command {
            let mut c = Command::new(env!("CARGO_BIN_EXE_awm"));
            c.args(args)
                .env("AWM_HOME", self.path())
                .env("HOME", self.home.path())
                .env_remove("CODEX_HOME")
                .env_remove("AWM_DEBUG")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            c
        }

        pub fn run(&self, args: &[&str]) -> Out {
            let o = self.command(args).stdin(Stdio::null()).output().unwrap();
            Out {
                code: o.status.code(),
                stdout: String::from_utf8(o.stdout).unwrap(),
                stderr: String::from_utf8(o.stderr).unwrap(),
            }
        }

        /// Runs with `input` on stdin.
        pub fn run_stdin(&self, args: &[&str], input: &str) -> Out {
            use std::io::Write;
            let mut child = self.command(args).stdin(Stdio::piped()).spawn().unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
            let o = child.wait_with_output().unwrap();
            Out {
                code: o.status.code(),
                stdout: String::from_utf8(o.stdout).unwrap(),
                stderr: String::from_utf8(o.stderr).unwrap(),
            }
        }

        /// Runs and requires exit 0; returns stdout.
        #[track_caller]
        pub fn ok(&self, args: &[&str]) -> String {
            let o = self.run(args);
            assert_eq!(
                o.code,
                Some(0),
                "awm {args:?} failed\nstdout: {}\nstderr: {}",
                o.stdout,
                o.stderr
            );
            o.stdout
        }

        pub fn conn(&self) -> Connection {
            db::open(&self.path().join("awm.db"), Role::Cli).unwrap()
        }

        pub fn ident(&self) -> Identity {
            Identity::load(self.path()).unwrap()
        }

        pub fn count(&self, sql: &str) -> i64 {
            self.conn().query_row(sql, [], |r| r.get(0)).unwrap()
        }

        pub fn state(&self, key: &str) -> Option<String> {
            state::get(&self.conn(), key).unwrap()
        }

        /// A local WebFetch row in this machine's project, captured now; returns its
        /// `event.id`.
        pub fn capture(&self, n: u32, url: &str, summary: &str) -> i64 {
            let conn = self.conn();
            let norm = awm::normalize::norm_url(url).unwrap();
            conn.execute(
                "INSERT INTO event (tool_use_id, tool, session_id, cwd_hash, created_at, url, url_norm, \
                   fetch_prompt, status, summary, match_text, source) \
                 VALUES (?1, 'WebFetch', 'sess-private', ?2, ?3, ?4, ?5, 'what does it say', 'ok', ?6, ?7, 'hook')",
                params![
                    format!("toolu_{}_{n}", self.path().display()),
                    sha256_hex(&self.project().to_string_lossy()),
                    now_ms(),
                    url,
                    norm,
                    summary,
                    format!("{url} {summary}"),
                ],
            )
            .unwrap();
            conn.last_insert_rowid()
        }

        pub fn sync_id(&self, event: i64) -> String {
            self.conn()
                .query_row("SELECT sync_id FROM event WHERE id = ?1", [event], |r| {
                    r.get(0)
                })
                .unwrap()
        }
    }
}
