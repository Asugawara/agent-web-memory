//! `awm serve check`: the configuration and store self-test (plan-v3-team §4.8.1).
//!
//! [`run`] turns a [`CheckInput`] (the resolved configuration, the store, the clock and a few
//! facts about this host) into a [`Report`]: one line per check, in the order and wording of
//! §4.8.1 (`listen`, `tls`, `files`, `database`, `backup`, `versions`, `tokens`,
//! `credentials`, `limits`, `retention`, `health`), `OK`, `WARN` or `FAIL`. The exit code is
//! 0 for all `OK`, 1 for at least one `WARN`, 2 for at least one `FAIL`.
//!
//! The probes that touch the host (disk, listeners, reboot flag) are in [`HostFacts`], which
//! the caller fills, so a test can break an install on purpose. No line holds a token, a key,
//! a database URL or record text.

use std::path::Path;
use std::sync::Arc;

use awm_proto::wire::{Role, Version};
use serde_json::json;

pub use crate::backup::Level;
use crate::backup::{self, target::key_file_env};
use crate::config::{Challenge, Resolved, StoreChoice};
use crate::retention;
use crate::store::{meta_keys, Store};
use crate::tls::cache::{AcmeCache, AcmeState};

const DAY_S: i64 = 86_400;
/// A certificate this close to `notAfter` is a `FAIL` (§4.8.1); 2 days for `shortlived`.
pub const EXPIRY_FAIL_DAYS: i64 = 7;
pub const EXPIRY_FAIL_DAYS_SHORTLIVED: i64 = 2;
/// An ACME error older than this is a `FAIL`.
pub const ACME_ERROR_FAIL_S: i64 = DAY_S;
/// A device unseen for this long is a `WARN`.
pub const UNSEEN_DAYS: i64 = 90;
/// Less free disk than this is a `WARN`.
pub const DISK_WARN_PCT: u8 = 20;

/// One check line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub level: Level,
    pub name: &'static str,
    /// May hold newlines: the lines after the first are indented under the first.
    pub text: String,
}

/// The whole report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub header: String,
    pub lines: Vec<Line>,
}

fn level_name(l: Level) -> &'static str {
    match l {
        Level::Ok => "OK",
        Level::Warn => "WARN",
        Level::Fail => "FAIL",
    }
}

impl Report {
    pub fn warnings(&self) -> usize {
        self.lines.iter().filter(|l| l.level == Level::Warn).count()
    }

    pub fn failures(&self) -> usize {
        self.lines.iter().filter(|l| l.level == Level::Fail).count()
    }

    /// 0 all `OK`, 1 at least one `WARN`, 2 at least one `FAIL`.
    pub fn exit_code(&self) -> i32 {
        if self.failures() > 0 {
            2
        } else if self.warnings() > 0 {
            1
        } else {
            0
        }
    }

    pub fn line(&self, name: &str) -> Option<&Line> {
        self.lines.iter().find(|l| l.name == name)
    }

    /// The text of §4.8.1.
    pub fn render(&self) -> String {
        let mut out = format!("{}\n", self.header);
        for l in &self.lines {
            let mut parts = l.text.split('\n');
            out.push_str(&format!(
                "{:<6}{:<13}{}\n",
                level_name(l.level),
                l.name,
                parts.next().unwrap_or("")
            ));
            for more in parts {
                out.push_str(&format!("{:19}{more}\n", ""));
            }
        }
        out.push_str(&format!(
            "result: {} warning{}, {} failure{}\n",
            self.warnings(),
            if self.warnings() == 1 { "" } else { "s" },
            self.failures(),
            if self.failures() == 1 { "" } else { "s" }
        ));
        out
    }

    /// The same as objects (`--json`).
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "header": self.header,
            "checks": self.lines.iter().map(|l| json!({
                "level": level_name(l.level),
                "name": l.name,
                "text": l.text.replace('\n', " "),
            })).collect::<Vec<_>>(),
            "warnings": self.warnings(),
            "failures": self.failures(),
        })
    }
}

/// Facts about this host that the checks read; [`HostFacts::collect`] probes the real one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFacts {
    /// `/var/run/reboot-required` exists.
    pub reboot_required: bool,
    /// Free space on the data directory's filesystem, in percent.
    pub disk_free_pct: Option<u8>,
    /// Listening TCP ports on public addresses (`22/tcp`), `None` where they cannot be read.
    pub public_listeners: Option<Vec<String>>,
    /// Something accepts connections on port 80 of this host.
    pub port80_open: bool,
}

impl HostFacts {
    pub fn collect(data: Option<&Path>) -> HostFacts {
        HostFacts {
            reboot_required: Path::new("/var/run/reboot-required").exists(),
            disk_free_pct: data.and_then(disk_free_pct),
            public_listeners: public_listeners(),
            port80_open: port_open(80),
        }
    }
}

/// `100 - Capacity` from `df -P`.
fn disk_free_pct(path: &Path) -> Option<u8> {
    let out = std::process::Command::new("df")
        .arg("-P")
        .arg(path)
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let used: u8 = text
        .lines()
        .nth(1)?
        .split_whitespace()
        .nth(4)?
        .trim_end_matches('%')
        .parse()
        .ok()?;
    Some(100u8.saturating_sub(used))
}

/// Listening sockets on non-loopback addresses, from `/proc/net/tcp{,6}` (Linux only).
fn public_listeners() -> Option<Vec<String>> {
    let mut ports = std::collections::BTreeSet::new();
    let mut any = false;
    for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        any = true;
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.get(3) != Some(&"0A") {
                continue; // not LISTEN
            }
            let Some((addr, port)) = f.get(1).and_then(|l| l.split_once(':')) else {
                continue;
            };
            let loopback = addr == "0100007F" || addr == "00000000000000000000000001000000";
            if !loopback {
                if let Ok(p) = u16::from_str_radix(port, 16) {
                    ports.insert(p);
                }
            }
        }
    }
    any.then(|| ports.into_iter().map(|p| format!("{p}/tcp")).collect())
}

fn port_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(200),
    )
    .is_ok()
}

/// What `GET /healthz` on the local listener answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    Status(u16),
    Unreachable(String),
}

/// What `--external` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct External {
    pub url: String,
    pub result: Result<String, String>,
}

/// Everything [`run`] needs.
pub struct CheckInput {
    pub resolved: Resolved,
    pub store: Arc<dyn Store>,
    pub now: i64,
    /// This binary's version, as printed in the header.
    pub version: String,
    pub release_floor: Version,
    /// The process environment (names only are printed).
    pub env: Vec<(String, String)>,
    pub facts: HostFacts,
    pub health: Health,
    pub external: Option<External>,
}

fn line(level: Level, name: &'static str, text: impl Into<String>) -> Line {
    Line {
        level,
        name,
        text: text.into(),
    }
}

fn worst(a: Level, b: Level) -> Level {
    a.max(b)
}

fn mode_of(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn owner_name(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata(path).ok()?.uid();
        if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
            for l in passwd.lines() {
                let f: Vec<&str> = l.split(':').collect();
                if f.get(2).and_then(|u| u.parse::<u32>().ok()) == Some(uid) {
                    return Some(f[0].to_string());
                }
            }
        }
        Some(format!("uid {uid}"))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// `YYYY-MM-DD HH:MM` in UTC.
pub fn fmt_utc(t: i64) -> String {
    let days = t.div_euclid(DAY_S);
    let rem = t.rem_euclid(DAY_S);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rem / 3_600,
        rem % 3_600 / 60
    )
}

fn fmt_day(t: i64) -> String {
    fmt_utc(t)[..10].to_string()
}

fn mb(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1_000_000.0)
}

/// Runs every check.
pub async fn run(input: &CheckInput) -> Report {
    let r = &input.resolved;
    let store_text = match &r.store {
        StoreChoice::Sqlite { data } => format!("sqlite {}", data.join("server.db").display()),
        StoreChoice::Postgres { .. } => "postgres".to_string(),
    };
    let header = format!(
        "awm serve check  (awm {}, proto {}, store {store_text})",
        input.version,
        awm_proto::wire::PROTOCOL_VERSION
    );
    let mut lines = vec![listen_line(input), tls_line(input)];
    lines.push(files_line(input));
    lines.push(database_line(input).await);
    lines.push(backup_line(input).await);
    lines.push(versions_line(input).await);
    lines.push(tokens_line(input).await);
    lines.push(credentials_line(input));
    lines.push(limits_line(input));
    lines.push(retention_line(input).await);
    lines.push(health_line(input));
    if let Some(e) = &input.external {
        lines.push(match &e.result {
            Ok(t) => line(Level::Ok, "external", format!("{} answered: {t}", e.url)),
            Err(m) => line(
                Level::Fail,
                "external",
                format!("{} did not answer from this host: {m}", e.url),
            ),
        });
    }
    Report { header, lines }
}

fn listen_line(input: &CheckInput) -> Line {
    let r = &input.resolved;
    let addrs = r
        .listen
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let public = r.listen.iter().any(|a| !a.ip().is_loopback());
    let host = match &input.facts.public_listeners {
        Some(l) if l.is_empty() => "host listeners on public addresses: none".to_string(),
        Some(l) => format!("host listeners on public addresses: {}", l.join(", ")),
        None => "host listeners not probed on this system".to_string(),
    };
    if public && !r.terminates_tls() && !r.behind_tls_proxy {
        return line(
            Level::Fail,
            "listen",
            format!(
                "{addrs} (plain HTTP on a public address): start with --domain or \
                 --behind-tls-proxy; {host}"
            ),
        );
    }
    let mode = if r.terminates_tls() {
        "tls"
    } else if r.behind_tls_proxy {
        "plain, behind a TLS proxy"
    } else {
        "plain, loopback only"
    };
    let extra = r
        .http01_listen
        .map(|a| format!(", http-01 challenge and redirect on {a}"))
        .unwrap_or_else(|| ", no other listener of this process".to_string());
    line(
        Level::Ok,
        "listen",
        format!("{addrs} ({mode}){extra}; {host}"),
    )
}

fn tls_line(input: &CheckInput) -> Line {
    let r = &input.resolved;
    let Some(domain) = &r.domain else {
        let text = if r.behind_tls_proxy {
            let mut trusted: Vec<String> = Vec::new();
            if r.cloud_run {
                trusted.push("cloud-run".into());
            }
            trusted.push(format!("{} CIDR range(s)", r.trusted_proxies.len()));
            format!(
                "terminated by the proxy in front (--behind-tls-proxy); trusted: {}",
                trusted.join(", ")
            )
        } else {
            "none: loopback only, TLS not needed".to_string()
        };
        let public = r.listen.iter().any(|a| !a.ip().is_loopback());
        let level = if public && !r.behind_tls_proxy {
            Level::Fail
        } else {
            Level::Ok
        };
        return line(level, "tls", text);
    };
    let challenge = r
        .acme
        .as_ref()
        .map_or(Challenge::TlsAlpn01, |a| a.challenge);
    let prefix = format!("acme {}, {}", challenge.as_str(), domain.name());
    let Some(dir) = r.acme_dir() else {
        return line(
            Level::Fail,
            "tls",
            format!("{prefix}: no ACME cache directory"),
        );
    };
    let cache = AcmeCache::peek(&dir);
    let Some(cert) = cache.as_ref().and_then(|c| c.load_cert().ok().flatten()) else {
        return line(
            Level::Fail,
            "tls",
            format!("{prefix}: no certificate in {} yet", dir.display()),
        );
    };
    let state: AcmeState = cache.as_ref().map(|c| c.load_state()).unwrap_or_default();
    let mut level = Level::Ok;
    let left = cert.info.not_after - input.now;
    let limit = if domain.is_ip() {
        EXPIRY_FAIL_DAYS_SHORTLIVED
    } else {
        EXPIRY_FAIL_DAYS
    };
    let mut text = format!("{prefix}, expires in {} d", left.div_euclid(DAY_S).max(0));
    if left <= limit * DAY_S {
        level = Level::Fail;
        text.push_str(&format!(" (renew now: FAIL within {limit} d of expiry)"));
    }
    if let (Some(s), Some(e)) = (state.ari_start, state.ari_end) {
        text.push_str(&format!(", ARI window {}..{}", fmt_day(s), fmt_day(e)));
    }
    let dir_mode = mode_of(&dir).map_or("-".into(), |m| format!("{m:04o}"));
    let file_mode =
        mode_of(&dir.join(crate::tls::cache::KEY_FILE)).map_or("-".into(), |m| format!("{m:04o}"));
    text.push_str(&format!(", cache {dir_mode}/{file_mode}"));
    if let (Some(err), Some(at)) = (&state.last_error, state.last_error_at) {
        let older = input.now - at > ACME_ERROR_FAIL_S;
        level = worst(level, if older { Level::Fail } else { Level::Warn });
        text.push_str(&format!(
            "; last ACME error {} ago: {err}",
            if older {
                "more than a day"
            } else {
                "under a day"
            }
        ));
    }
    if challenge == Challenge::TlsAlpn01 && input.facts.port80_open {
        level = worst(level, Level::Warn);
        text.push_str("; port 80 is open but tls-alpn-01 needs only 443: close it");
    }
    line(level, "tls", text)
}

fn files_line(input: &CheckInput) -> Line {
    let r = &input.resolved;
    let Some(data) = r.data_dir() else {
        return line(
            Level::Ok,
            "files",
            "not applicable: PgStore keeps no data files on this host",
        );
    };
    let mut level = Level::Ok;
    let mut parts: Vec<String> = Vec::new();
    let mut problems: Vec<String> = Vec::new();
    let mut record = |label: &str, path: &Path, show: bool| {
        if let Some(m) = mode_of(path) {
            if show {
                parts.push(format!("{label} {m:04o}"));
            }
            if m & 0o077 != 0 {
                problems.push(format!("{label} is readable by others ({m:04o})"));
            }
        }
    };
    record(&data.display().to_string(), data, true);
    record("server.db", &data.join("server.db"), true);
    if let Some(f) = &r.config_file {
        record("server.toml", f, true);
    }
    let acme = data.join(crate::config::ACME_DIR);
    record("acme/", &acme, false);
    if let Ok(rd) = std::fs::read_dir(&acme) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            record(&format!("acme/{name}"), &e.path(), false);
        }
    }
    if !problems.is_empty() {
        level = Level::Fail;
    }
    let mut text = parts.join(", ");
    if let Some(o) = owner_name(&data.join("server.db")).or_else(|| owner_name(data)) {
        text.push_str(&format!(", owner {o}"));
    }
    if !problems.is_empty() {
        text.push_str(&format!("; {}; run chmod 600 / 700", problems.join("; ")));
    }
    line(level, "files", text)
}

async fn database_line(input: &CheckInput) -> Line {
    let r = &input.resolved;
    match &r.store {
        StoreChoice::Sqlite { data } => {
            let db = data.join("server.db");
            if !db.is_file() {
                return line(
                    Level::Fail,
                    "database",
                    format!("no database at {}: run awm serve init", db.display()),
                );
            }
            let integrity = sqlite_integrity(&db);
            let schema = input
                .store
                .meta_get(meta_keys::SCHEMA_VERSION.into())
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| "?".into());
            let size = std::fs::metadata(&db)
                .map(|m| mb(m.len()))
                .unwrap_or_default();
            let mut level = Level::Ok;
            let mut text = match &integrity {
                Ok(()) => format!("integrity ok, schema {schema}, {size}"),
                Err(e) => {
                    level = Level::Fail;
                    format!("integrity check failed ({e}), schema {schema}, {size}")
                }
            };
            if let Some(free) = input.facts.disk_free_pct {
                text.push_str(&format!(", disk {free}% free"));
                if free < DISK_WARN_PCT {
                    level = worst(level, Level::Warn);
                    text.push_str(&format!(" (below {DISK_WARN_PCT}%)"));
                }
            }
            line(level, "database", text)
        }
        StoreChoice::Postgres { .. } => match input.store.restore_state().await {
            Ok(_) => line(
                Level::Ok,
                "database",
                "postgres answers; point-in-time recovery and deletion protection: not checked \
                 (Cloud SQL Admin API not queried)",
            ),
            Err(_) => line(Level::Fail, "database", "postgres does not answer"),
        },
    }
}

#[cfg(feature = "sqlite")]
fn sqlite_integrity(db: &Path) -> Result<(), String> {
    use rusqlite::{Connection, OpenFlags};
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("cannot open: {e}"))?;
    let rows: Vec<String> = conn
        .prepare("PRAGMA integrity_check")
        .and_then(|mut s| s.query_map([], |r| r.get::<_, String>(0))?.collect())
        .map_err(|e| format!("{e}"))?;
    if rows == ["ok"] {
        Ok(())
    } else {
        Err(format!("{} problem(s) reported", rows.len()))
    }
}

#[cfg(not(feature = "sqlite"))]
fn sqlite_integrity(_db: &Path) -> Result<(), String> {
    Ok(())
}

/// Open, unused, unrevoked invites that have not expired (`SqliteStore` only).
#[cfg(feature = "sqlite")]
fn open_invites(db: &Path, now: i64) -> Option<u64> {
    use rusqlite::{Connection, OpenFlags};
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    conn.query_row(
        "SELECT count(*) FROM invite \
          WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > ?1",
        [now],
        |r| r.get::<_, i64>(0),
    )
    .ok()
    .map(|n| n as u64)
}

#[cfg(not(feature = "sqlite"))]
fn open_invites(_db: &Path, _now: i64) -> Option<u64> {
    None
}

async fn backup_line(input: &CheckInput) -> Line {
    let status = match backup::status(&*input.store).await {
        Ok(s) => s,
        Err(_) => return line(Level::Fail, "backup", "the backup state cannot be read"),
    };
    let lines = status.check(input.resolved.backup.as_deref(), input.now);
    let mut level = Level::Ok;
    let mut texts = Vec::new();
    for l in lines {
        level = worst(level, l.level);
        texts.push(if l.text == backup::NO_TARGET {
            // The two-line form of §4.8.1.
            l.text
                .replacen("every record no member", "every record\nno member", 1)
        } else {
            l.text
        });
    }
    line(level, "backup", texts.join("\n"))
}

async fn versions_line(input: &CheckInput) -> Line {
    let floor = &input.release_floor;
    let org = input.store.org(input.now).await.ok().flatten();
    let (min, note) = match org {
        Some(o) => (o.settings.min_client, String::new()),
        None => (
            input
                .resolved
                .overrides
                .min_client
                .clone()
                .unwrap_or_else(|| floor.clone()),
            "; no organisation yet".to_string(),
        ),
    };
    if &min < floor {
        return line(
            Level::Fail,
            "versions",
            format!(
                "min_client {min} is below the release floor {floor}: raise it with awm team \
                 policy set min_client={floor}"
            ),
        );
    }
    line(
        Level::Ok,
        "versions",
        format!("min_client {min} (release floor {floor}){note}"),
    )
}

async fn tokens_line(input: &CheckInput) -> Line {
    let store = &*input.store;
    let Ok(org) = store.org(input.now).await else {
        return line(Level::Fail, "tokens", "the organisation cannot be read");
    };
    if org.is_none() {
        let pending = match (
            store.meta_get(meta_keys::BOOTSTRAP_HASH.into()).await,
            store.meta_get(meta_keys::BOOTSTRAP_EXPIRES.into()).await,
        ) {
            (Ok(Some(_)), Ok(Some(e))) => e.parse::<i64>().ok().filter(|t| *t > input.now),
            _ => None,
        };
        let text = match pending {
            Some(t) => format!(
                "no admin yet; a bootstrap token is valid until {} UTC (awm team create URL \
                 --token ...)",
                fmt_utc(t)
            ),
            None => "no admin yet: run awm serve init".to_string(),
        };
        return line(Level::Warn, "tokens", text);
    }
    let members = store.members().await.unwrap_or_default();
    let admins = members
        .iter()
        .filter(|m| m.active && m.role == Role::Admin)
        .count();
    let mut unseen = 0;
    for m in members.iter().filter(|m| m.active) {
        for d in m.devices.iter().filter(|d| d.approved && !d.revoked) {
            if let Ok(Some(row)) = store.device(d.device_id).await {
                let seen = row.last_seen_day.map_or(row.created_at, |d| d * DAY_S);
                if input.now - seen > UNSEEN_DAYS * DAY_S {
                    unseen += 1;
                }
            }
        }
    }
    let invites = match &input.resolved.store {
        StoreChoice::Sqlite { data } => open_invites(&data.join("server.db"), input.now)
            .map_or("open invites not counted".to_string(), |n| {
                format!("{n} open invite{}", if n == 1 { "" } else { "s" })
            }),
        StoreChoice::Postgres { .. } => "open invites not counted (PgStore)".to_string(),
    };
    let mut level = Level::Ok;
    let admin_text = if admins == 1 {
        level = Level::Warn;
        "1 admin (promote a second: awm serve promote HANDLE)".to_string()
    } else {
        format!("{admins} admins")
    };
    if unseen > 0 {
        level = worst(level, Level::Warn);
    }
    line(
        level,
        "tokens",
        format!(
            "{admin_text}; {unseen} device{} unseen for {UNSEEN_DAYS} d; {invites}",
            if unseen == 1 { "" } else { "s" }
        ),
    )
}

fn credentials_line(input: &CheckInput) -> Line {
    let found = key_file_env(input.env.iter().cloned());
    if !found.is_empty() {
        return line(
            Level::Warn,
            "credentials",
            format!(
                "a key file is configured ({}): use the attached service account or instance \
                 role instead and delete the key",
                found.join(", ")
            ),
        );
    }
    let gcs = input
        .resolved
        .backup
        .as_deref()
        .is_some_and(|b| b.starts_with("gs://"));
    line(
        Level::Ok,
        "credentials",
        if gcs {
            "no key file; Google identity from the metadata server"
        } else {
            "no key file"
        },
    )
}

fn limits_line(input: &CheckInput) -> Line {
    let r = &input.resolved;
    let trusted = if r.cloud_run {
        "cloud-run (last X-Forwarded-For entry)".to_string()
    } else if r.trusted_proxies.is_empty() {
        "none".to_string()
    } else {
        format!("{} CIDR range(s)", r.trusted_proxies.len())
    };
    line(
        Level::Ok,
        "limits",
        format!("per-IP and per-token limits on; trusted proxies: {trusted}"),
    )
}

async fn retention_line(input: &CheckInput) -> Line {
    let r = &input.resolved;
    let mode = if r.request_time_retention {
        "in requests, at most hourly"
    } else {
        "hourly"
    };
    let days = match input.store.org(input.now).await {
        Ok(Some(o)) => o.settings.retention_days,
        _ => r.overrides.retention_days.unwrap_or(365),
    };
    match retention::last_retention(&*input.store).await {
        Ok(Some(t)) => line(
            Level::Ok,
            "retention",
            format!("last run {} ({mode}), {days} d", fmt_utc(t)),
        ),
        Ok(None) => line(
            Level::Ok,
            "retention",
            format!("no run yet ({mode}), {days} d"),
        ),
        Err(_) => line(
            Level::Fail,
            "retention",
            "the retention state cannot be read",
        ),
    }
}

fn health_line(input: &CheckInput) -> Line {
    let mut line = match &input.health {
        Health::Status(200) => line(Level::Ok, "health", "/healthz 200"),
        Health::Status(s) => line(Level::Fail, "health", format!("/healthz {s}")),
        Health::Unreachable(why) => line(
            Level::Warn,
            "health",
            format!("/healthz not reachable ({why}): is the server running?"),
        ),
    };
    if input.facts.reboot_required {
        line.level = worst(line.level, Level::Warn);
        line.text.push_str(
            "; a reboot is pending (/var/run/reboot-required): restart the host when you can",
        );
    }
    line
}
