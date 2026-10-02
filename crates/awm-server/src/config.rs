//! `server.toml` and the `awm serve` flags (plan-v3-team §4.7, §4.8.1).
//!
//! [`resolve`] merges the flags over the file (a flag wins), reads the environment variables
//! the flags name, and applies every refusal of §4.8.1 (exit code 2) before anything is opened,
//! bound or created. The CLI crate fills [`Flags`] with clap; tests fill it directly.
//!
//! `server.toml` is flat: one `key = value` per line (string, integer, boolean or an array of
//! strings), `#` comments. This crate has no TOML dependency, so [`FileConfig::parse`] reads
//! exactly that subset and refuses anything else, tables included. No message here repeats a
//! value, only key names and line numbers: a database URL may sit in the file.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use awm_proto::wire::Version;

use crate::backup::Target;
use crate::http::{IpNet, RetentionMode, ServerConfig};
use crate::store::valid_token_hash;

/// Where the server listens when nothing says otherwise (loopback only).
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8787";
/// The file `--config` defaults to, inside the data directory.
pub const CONFIG_FILE: &str = "server.toml";
/// The ACME account and certificate directory inside the data directory (§3.9.3).
pub const ACME_DIR: &str = "acme";
/// Let's Encrypt production and staging directories.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
/// Wildcard-DNS services whose hostnames share one Let's Encrypt budget (§3.9.3, W25, W34).
pub const SHARED_SUFFIXES: &[&str] = &["sslip.io", "nip.io", "xip.io", "traefik.me"];
/// The scope key of the one organisation of a self-hosted `PgStore` (TM26: the key is not
/// `org.id`; a self-hosted server has exactly one organisation).
pub const SELF_HOST_SCOPE: &str = "00000000-0000-4000-8000-000000000001";

// ---------------------------------------------------------------------------------------------
// Errors and secrets

/// A refused configuration. `code` is the process exit code (2 for every §4.8.1 refusal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub code: i32,
    pub message: String,
}

impl ConfigError {
    /// Exit code 2: refused configuration.
    pub fn refused(message: impl Into<String>) -> ConfigError {
        ConfigError {
            code: 2,
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

/// A value that must never be printed: `Debug` hides it, `expose` returns it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Secret {
        Secret(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

// ---------------------------------------------------------------------------------------------
// The file

/// The keys of `server.toml` (§4.7); every flag of §4.8.1 plus the settings that have no flag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileConfig {
    pub domain: Option<String>,
    pub data: Option<String>,
    pub database_url: Option<Secret>,
    pub database_url_env: Option<String>,
    pub database_url_owner_env: Option<String>,
    pub database_insecure_network: Option<bool>,
    pub backup: Option<String>,
    pub listen: Option<String>,
    pub behind_tls_proxy: Option<bool>,
    pub trusted_proxies: Vec<String>,
    pub acme_email: Option<String>,
    pub acme_challenge: Option<String>,
    pub acme_directory: Option<String>,
    pub acme_staging: Option<bool>,
    pub acme_ca_file: Option<String>,
    pub acme_http_listen: Option<String>,
    pub retention_days: Option<u32>,
    pub min_client: Option<String>,
    pub max_members: Option<u32>,
    pub internal_token_sha256: Option<String>,
    pub requests_per_minute: Option<u32>,
    pub request_burst: Option<u32>,
    pub anonymous_per_minute: Option<u32>,
    pub joins_per_hour: Option<u32>,
    pub records_per_day: Option<u32>,
    pub request_timeout_s: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    List(Vec<String>),
}

impl FileConfig {
    /// Parses the flat subset of TOML described in the module docs. Unknown keys, tables,
    /// duplicate keys and values of the wrong type are refused (a typo must not silently
    /// weaken a setting).
    pub fn parse(text: &str) -> Result<FileConfig, ConfigError> {
        let mut out = FileConfig::default();
        let mut seen: Vec<String> = Vec::new();
        let mut lines = text.lines().enumerate();
        while let Some((n, raw)) = lines.next() {
            let n = n + 1;
            let line = strip_comment(raw).trim().to_string();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                return Err(bad(n, "tables are not supported: server.toml is flat"));
            }
            let Some((key, rest)) = line.split_once('=') else {
                return Err(bad(n, "expected `key = value`"));
            };
            let key = key.trim().to_string();
            let mut rest = rest.trim().to_string();
            // An array may continue over several lines.
            if rest.starts_with('[') && !array_closed(&rest) {
                for (_, more) in lines.by_ref() {
                    rest.push(' ');
                    rest.push_str(strip_comment(more).trim());
                    if array_closed(&rest) {
                        break;
                    }
                }
            }
            if seen.contains(&key) {
                return Err(bad(n, &format!("key `{key}` appears twice")));
            }
            let value = parse_value(&rest).map_err(|m| bad(n, &format!("`{key}`: {m}")))?;
            out.set(&key, value).map_err(|m| bad(n, &m))?;
            seen.push(key);
        }
        Ok(out)
    }

    fn set(&mut self, key: &str, v: Value) -> Result<(), String> {
        let string = |v: Value| match v {
            Value::Str(s) => Ok(s),
            _ => Err(format!("`{key}` must be a string")),
        };
        let boolean = |v: Value| match v {
            Value::Bool(b) => Ok(b),
            _ => Err(format!("`{key}` must be true or false")),
        };
        let number = |v: Value| match v {
            Value::Int(i) if (0..=i64::from(u32::MAX)).contains(&i) => Ok(i as u32),
            _ => Err(format!("`{key}` must be a non-negative integer")),
        };
        match key {
            "domain" => self.domain = Some(string(v)?),
            "data" => self.data = Some(string(v)?),
            "database_url" => self.database_url = Some(Secret(string(v)?)),
            "database_url_env" => self.database_url_env = Some(string(v)?),
            "database_url_owner_env" => self.database_url_owner_env = Some(string(v)?),
            "database_insecure_network" => self.database_insecure_network = Some(boolean(v)?),
            "backup" => self.backup = Some(string(v)?),
            "listen" => self.listen = Some(string(v)?),
            "behind_tls_proxy" => self.behind_tls_proxy = Some(boolean(v)?),
            "trusted_proxies" => match v {
                Value::List(l) => self.trusted_proxies = l,
                Value::Str(s) => self.trusted_proxies = vec![s],
                _ => return Err("`trusted_proxies` must be an array of strings".into()),
            },
            "acme_email" => self.acme_email = Some(string(v)?),
            "acme_challenge" => self.acme_challenge = Some(string(v)?),
            "acme_directory" => self.acme_directory = Some(string(v)?),
            "acme_staging" => self.acme_staging = Some(boolean(v)?),
            "acme_ca_file" => self.acme_ca_file = Some(string(v)?),
            "acme_http_listen" => self.acme_http_listen = Some(string(v)?),
            "retention_days" => self.retention_days = Some(number(v)?),
            "min_client" => self.min_client = Some(string(v)?),
            "max_members" => self.max_members = Some(number(v)?),
            "internal_token_sha256" => self.internal_token_sha256 = Some(string(v)?),
            "requests_per_minute" => self.requests_per_minute = Some(number(v)?),
            "request_burst" => self.request_burst = Some(number(v)?),
            "anonymous_per_minute" => self.anonymous_per_minute = Some(number(v)?),
            "joins_per_hour" => self.joins_per_hour = Some(number(v)?),
            "records_per_day" => self.records_per_day = Some(number(v)?),
            "request_timeout_s" => self.request_timeout_s = Some(number(v)?),
            other => return Err(format!("unknown key `{other}`")),
        }
        Ok(())
    }
}

fn bad(line: usize, what: &str) -> ConfigError {
    ConfigError::refused(format!("server.toml line {line}: {what}"))
}

/// `line` without a trailing `#` comment (a `#` inside quotes stays).
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' && q == '"' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                '#' => return &line[..i],
                _ => {}
            },
        }
    }
    line
}

fn array_closed(s: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in s.chars() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' && q == '"' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                ']' => return true,
                _ => {}
            },
        }
    }
    false
}

fn parse_string(s: &str) -> Result<(String, &str), String> {
    let mut chars = s.char_indices();
    let (_, q) = chars.next().ok_or("empty value")?;
    let mut out = String::new();
    let mut escaped = false;
    for (i, c) in chars {
        if escaped {
            out.push(match c {
                'n' => '\n',
                't' => '\t',
                '"' => '"',
                '\\' => '\\',
                _ => return Err("unsupported escape in a string".into()),
            });
            escaped = false;
        } else if c == '\\' && q == '"' {
            escaped = true;
        } else if c == q {
            return Ok((out, &s[i + c.len_utf8()..]));
        } else {
            out.push(c);
        }
    }
    Err("unterminated string".into())
}

fn parse_value(s: &str) -> Result<Value, String> {
    let s = s.trim();
    if s.starts_with('"') || s.starts_with('\'') {
        let (v, rest) = parse_string(s)?;
        if !rest.trim().is_empty() {
            return Err("unexpected text after the string".into());
        }
        return Ok(Value::Str(v));
    }
    if let Some(inner) = s.strip_prefix('[') {
        let mut rest = inner.trim_start();
        let mut items = Vec::new();
        loop {
            if let Some(after) = rest.strip_prefix(']') {
                if !after.trim().is_empty() {
                    return Err("unexpected text after the array".into());
                }
                return Ok(Value::List(items));
            }
            if !(rest.starts_with('"') || rest.starts_with('\'')) {
                return Err("arrays hold strings only".into());
            }
            let (item, after) = parse_string(rest)?;
            items.push(item);
            rest = after.trim_start();
            if let Some(after) = rest.strip_prefix(',') {
                rest = after.trim_start();
            } else if !rest.starts_with(']') {
                return Err("expected `,` or `]` in an array".into());
            }
        }
    }
    match s {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        _ => {}
    }
    s.parse::<i64>()
        .map(Value::Int)
        .map_err(|_| "expected a string, integer, boolean or array of strings".into())
}

// ---------------------------------------------------------------------------------------------
// Flags

/// The command line of `awm serve` (§4.8.1), before the file is merged. `None` and an empty
/// list mean "not given".
#[derive(Debug, Clone, Default)]
pub struct Flags {
    pub config: Option<PathBuf>,
    pub data: Option<PathBuf>,
    pub database_url: Option<Secret>,
    pub database_url_env: Option<String>,
    pub database_url_owner_env: Option<String>,
    /// `--database-insecure-network`: let `PgStore` connect without TLS to a TCP host outside
    /// loopback and the private ranges (RVT2 M4).
    pub database_insecure_network: bool,
    pub domain: Option<String>,
    pub backup: Option<String>,
    pub behind_tls_proxy: bool,
    pub trusted_proxies: Vec<String>,
    pub listen: Option<String>,
    pub acme_email: Option<String>,
    pub acme_challenge: Option<String>,
    pub acme_directory: Option<String>,
    pub acme_staging: bool,
    pub acme_ca_file: Option<PathBuf>,
    /// The listener of the HTTP-01 challenge (default `0.0.0.0:80`; the container recipe maps
    /// `80:8080`).
    pub acme_http_listen: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// The result

/// Which store the server opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreChoice {
    /// `SqliteStore` in `{data}/server.db`.
    Sqlite { data: PathBuf },
    /// `PgStore`: the application URL, and the owner URL when migrations should run.
    /// `insecure_network`: `--database-insecure-network` (RVT2 M4).
    Postgres {
        url: Secret,
        owner_url: Option<Secret>,
        insecure_network: bool,
    },
}

/// The identifier a certificate is requested for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Domain {
    Dns(String),
    Ip(IpAddr),
}

impl Domain {
    /// The name as it appears in the certificate and in `check`.
    pub fn name(&self) -> String {
        match self {
            Domain::Dns(d) => d.clone(),
            Domain::Ip(ip) => ip.to_string(),
        }
    }

    /// Whether the certificate is an IP-address certificate (`shortlived` profile, §3.9.3).
    pub fn is_ip(&self) -> bool {
        matches!(self, Domain::Ip(_))
    }
}

/// `--acme-challenge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Challenge {
    TlsAlpn01,
    Http01,
}

impl Challenge {
    pub fn as_str(self) -> &'static str {
        match self {
            Challenge::TlsAlpn01 => "tls-alpn-01",
            Challenge::Http01 => "http-01",
        }
    }
}

/// The ACME client settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeSettings {
    pub email: Option<String>,
    pub directory: String,
    pub staging: bool,
    pub ca_file: Option<PathBuf>,
    pub challenge: Challenge,
}

/// Settings that have no flag (`server.toml` only).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    pub retention_days: Option<u32>,
    pub min_client: Option<Version>,
    pub max_members: Option<u32>,
    pub requests_per_minute: Option<u32>,
    pub request_burst: Option<u32>,
    pub anonymous_per_minute: Option<u32>,
    pub joins_per_hour: Option<u32>,
    pub records_per_day: Option<u32>,
    pub request_timeout_s: Option<u32>,
}

/// A configuration that passed every refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub store: StoreChoice,
    /// The certificate identifier; `Some` means this binary terminates TLS.
    pub domain: Option<Domain>,
    /// Where the (TLS or plain) API listens.
    pub listen: Vec<SocketAddr>,
    /// The port-80 listener of `--acme-challenge http-01`.
    pub http01_listen: Option<SocketAddr>,
    pub acme: Option<AcmeSettings>,
    pub behind_tls_proxy: bool,
    pub trusted_proxies: Vec<IpNet>,
    /// `--trusted-proxy cloud-run`: the client is the last `X-Forwarded-For` entry.
    pub cloud_run: bool,
    /// Retention runs inside requests (Cloud Run) instead of an hourly task.
    pub request_time_retention: bool,
    pub backup: Option<String>,
    /// The file the settings came from, if any.
    pub config_file: Option<PathBuf>,
    pub overrides: Overrides,
    pub internal_token_hash: Option<String>,
}

impl Resolved {
    /// `{data}` for `SqliteStore`.
    pub fn data_dir(&self) -> Option<&Path> {
        match &self.store {
            StoreChoice::Sqlite { data } => Some(data),
            StoreChoice::Postgres { .. } => None,
        }
    }

    /// `{data}/acme`.
    pub fn acme_dir(&self) -> Option<PathBuf> {
        self.data_dir().map(|d| d.join(ACME_DIR))
    }

    /// Whether this binary terminates TLS (HSTS, port 443).
    pub fn terminates_tls(&self) -> bool {
        self.domain.is_some()
    }

    /// The `http::ServerConfig` for this configuration.
    pub fn server_config(&self, server_version: Version, release_floor: Version) -> ServerConfig {
        let mut c = ServerConfig::new(server_version, release_floor);
        let o = &self.overrides;
        if let Some(d) = o.retention_days {
            c.org_defaults.retention_days = d;
        }
        if let Some(v) = &o.min_client {
            c.org_defaults.min_client = v.clone();
        }
        if let Some(m) = o.max_members {
            c.org_defaults.max_members = m;
            c.limits.max_members = m;
        }
        if let Some(n) = o.requests_per_minute {
            c.limits.requests_per_minute = n;
        }
        if let Some(n) = o.request_burst {
            c.limits.request_burst = n;
        }
        if let Some(n) = o.anonymous_per_minute {
            c.limits.anonymous_per_minute = n;
        }
        if let Some(n) = o.joins_per_hour {
            c.limits.joins_per_hour = n;
        }
        if let Some(n) = o.records_per_day {
            c.limits.records_per_day = n;
        }
        if let Some(s) = o.request_timeout_s {
            c.request_timeout = Duration::from_secs(u64::from(s.max(1)));
        }
        c.trusted_proxies = self.trusted_proxies.clone();
        c.forwarded_last_entry = self.cloud_run;
        // RVT2 m10: behind a TLS-terminating proxy (Cloud Run included) clients reach the
        // server over HTTPS too, so the header applies.
        c.hsts = self.terminates_tls() || self.behind_tls_proxy;
        c.retention = if self.request_time_retention {
            RetentionMode::InRequests
        } else {
            RetentionMode::Off
        };
        c.internal_token_hash = self.internal_token_hash.clone();
        c
    }
}

// ---------------------------------------------------------------------------------------------
// Resolution

/// The environment variables `resolve` reads: the ones the flags name, and `PORT`.
pub type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Merges `file` under `flags` (a flag wins), reads the named environment variables and
/// applies every refusal of §4.8.1:
///
/// - a non-loopback `--listen` without `--domain` or `--behind-tls-proxy`;
/// - `--domain` with `--behind-tls-proxy`; `--behind-tls-proxy` without a trusted proxy;
/// - `--data` with a database URL; neither of them;
/// - a group- or world-readable `server.toml` (also an ACME directory or key, see
///   [`verify_files`]);
/// - an sslip.io-style or malformed `--domain`; `--domain` with a database URL (the ACME
///   cache needs `--data`);
/// - an invalid `--backup` URL, challenge, ACME directory, address, CIDR or setting.
///
/// Reads `server.toml` (the `--config` path, else `{data}/server.toml` when it exists) but
/// creates and opens nothing else.
pub fn resolve(flags: &Flags, env: Env<'_>) -> Result<Resolved, ConfigError> {
    // --- the file ---------------------------------------------------------------------------
    let (file, config_file) = load_file(flags)?;

    // --- store ------------------------------------------------------------------------------
    let data = flags
        .data
        .clone()
        .or_else(|| file.data.as_ref().map(PathBuf::from));
    let url_env = flags
        .database_url_env
        .clone()
        .or_else(|| file.database_url_env.clone());
    let url_direct = flags
        .database_url
        .clone()
        .or_else(|| file.database_url.clone());
    let owner_env = flags
        .database_url_owner_env
        .clone()
        .or_else(|| file.database_url_owner_env.clone());
    let has_url = url_env.is_some() || url_direct.is_some();
    let insecure = flags.database_insecure_network || file.database_insecure_network == Some(true);
    if insecure && !has_url {
        return Err(ConfigError::refused(
            "--database-insecure-network needs --database-url or --database-url-env",
        ));
    }
    if data.is_some() && has_url {
        return Err(ConfigError::refused(
            "--data and --database-url are exclusive: SqliteStore or PgStore, not both",
        ));
    }
    if url_env.is_some() && url_direct.is_some() {
        return Err(ConfigError::refused(
            "--database-url and --database-url-env are exclusive",
        ));
    }
    let store =
        match (data, has_url) {
            (Some(data), false) => StoreChoice::Sqlite { data },
            (None, true) => {
                let url = match (&url_direct, &url_env) {
                    (Some(u), _) => u.clone(),
                    (None, Some(name)) => {
                        Secret(env(name).filter(|v| !v.is_empty()).ok_or_else(|| {
                            ConfigError::refused(format!("environment variable {name} is not set"))
                        })?)
                    }
                    (None, None) => unreachable!("has_url"),
                };
                let owner_url = match &owner_env {
                    None => None,
                    Some(name) => Some(Secret(env(name).filter(|v| !v.is_empty()).ok_or_else(
                        || ConfigError::refused(format!("environment variable {name} is not set")),
                    )?)),
                };
                StoreChoice::Postgres {
                    url,
                    owner_url,
                    insecure_network: insecure,
                }
            }
            (None, false) => return Err(ConfigError::refused(
                "no store: give --data DIR (SqliteStore) or --database-url / --database-url-env \
                 (PgStore)",
            )),
            (Some(_), true) => unreachable!("checked above"),
        };
    if owner_env.is_some() && matches!(store, StoreChoice::Sqlite { .. }) {
        return Err(ConfigError::refused(
            "--database-url-owner-env needs --database-url or --database-url-env",
        ));
    }

    // --- mode -------------------------------------------------------------------------------
    let domain_text = flags.domain.clone().or_else(|| file.domain.clone());
    let behind = flags.behind_tls_proxy || file.behind_tls_proxy.unwrap_or(false);
    if domain_text.is_some() && behind {
        return Err(ConfigError::refused(
            "--domain and --behind-tls-proxy are exclusive: either this binary terminates TLS \
             or something in front of it does",
        ));
    }
    let domain = domain_text.as_deref().map(parse_domain).transpose()?;
    if domain.is_some() && matches!(store, StoreChoice::Postgres { .. }) {
        return Err(ConfigError::refused(
            "--domain needs --data: the ACME account and certificate live in {data}/acme \
             (use --behind-tls-proxy with a database URL)",
        ));
    }

    // --- trusted proxies --------------------------------------------------------------------
    let proxy_texts = if flags.trusted_proxies.is_empty() {
        file.trusted_proxies.clone()
    } else {
        flags.trusted_proxies.clone()
    };
    let mut trusted_proxies = Vec::new();
    let mut cloud_run = false;
    for t in &proxy_texts {
        if t == "cloud-run" {
            cloud_run = true;
        } else {
            trusted_proxies.push(t.parse::<IpNet>().map_err(|_| {
                ConfigError::refused(
                    "--trusted-proxy takes a CIDR range, an address or `cloud-run`".to_string(),
                )
            })?);
        }
    }
    if behind && trusted_proxies.is_empty() && !cloud_run {
        return Err(ConfigError::refused(
            "--behind-tls-proxy needs --trusted-proxy CIDR (repeatable) or --trusted-proxy \
             cloud-run: without it every client would share the proxy's address",
        ));
    }
    // RVT2 m4: the preset believes the last X-Forwarded-For entry whoever the peer is, which
    // only Google's front end makes true; off Cloud Run every client would choose its address.
    if cloud_run && env("K_SERVICE").filter(|v| !v.is_empty()).is_none() {
        return Err(ConfigError::refused(
            "--trusted-proxy cloud-run is only for Cloud Run (K_SERVICE is not set): elsewhere \
             name the proxy's address range with --trusted-proxy CIDR",
        ));
    }

    // --- listeners --------------------------------------------------------------------------
    let listen_text = flags.listen.clone().or_else(|| file.listen.clone());
    let port = env("PORT").filter(|p| !p.is_empty());
    let listen: Vec<SocketAddr> = if let Some(l) = &listen_text {
        let addr = parse_socket(l, "--listen")?;
        if domain.is_none() && !behind && !addr.ip().is_loopback() {
            return Err(ConfigError::refused(
                "--listen on a non-loopback address needs --domain (built-in TLS) or \
                 --behind-tls-proxy: the server never serves plain HTTP on a public address",
            ));
        }
        vec![addr]
    } else if domain.is_some() {
        vec![
            SocketAddr::from(([0, 0, 0, 0], 443)),
            SocketAddr::from(([0u16; 8], 443)),
        ]
    } else if behind && port.is_some() {
        let p: u16 = port
            .as_deref()
            .unwrap_or_default()
            .parse()
            .map_err(|_| ConfigError::refused("PORT is not a port number"))?;
        vec![SocketAddr::from(([0, 0, 0, 0], p))]
    } else {
        vec![parse_socket(DEFAULT_LISTEN, "--listen")?]
    };

    // --- ACME -------------------------------------------------------------------------------
    let challenge_text = flags
        .acme_challenge
        .clone()
        .or_else(|| file.acme_challenge.clone());
    let email = flags.acme_email.clone().or_else(|| file.acme_email.clone());
    let directory = flags
        .acme_directory
        .clone()
        .or_else(|| file.acme_directory.clone());
    let staging = flags.acme_staging || file.acme_staging.unwrap_or(false);
    let ca_file = flags
        .acme_ca_file
        .clone()
        .or_else(|| file.acme_ca_file.as_ref().map(PathBuf::from));
    let http_text = flags
        .acme_http_listen
        .clone()
        .or_else(|| file.acme_http_listen.clone());
    let acme_given = challenge_text.is_some()
        || email.is_some()
        || directory.is_some()
        || staging
        || ca_file.is_some()
        || http_text.is_some();
    if domain.is_none() && acme_given {
        return Err(ConfigError::refused(
            "the --acme-* flags need --domain (built-in TLS)",
        ));
    }
    let challenge = match challenge_text.as_deref() {
        None | Some("tls-alpn-01") => Challenge::TlsAlpn01,
        Some("http-01") => Challenge::Http01,
        Some(_) => {
            return Err(ConfigError::refused(
                "--acme-challenge is tls-alpn-01 or http-01 (DNS-01 is not offered)",
            ))
        }
    };
    if http_text.is_some() && challenge != Challenge::Http01 {
        return Err(ConfigError::refused(
            "the HTTP-01 listener needs --acme-challenge http-01",
        ));
    }
    if staging && directory.is_some() {
        return Err(ConfigError::refused(
            "--acme-staging and --acme-directory are exclusive",
        ));
    }
    let directory = match (directory, staging) {
        (Some(d), _) => {
            if !d.starts_with("https://") {
                return Err(ConfigError::refused(
                    "--acme-directory must be an https URL",
                ));
            }
            d
        }
        (None, true) => LETS_ENCRYPT_STAGING.to_string(),
        (None, false) => LETS_ENCRYPT.to_string(),
    };
    let http01_listen = if domain.is_some() && challenge == Challenge::Http01 {
        Some(parse_socket(
            http_text.as_deref().unwrap_or("0.0.0.0:80"),
            "--acme-http-listen",
        )?)
    } else {
        None
    };
    let acme = domain.as_ref().map(|_| AcmeSettings {
        email,
        directory,
        staging,
        ca_file,
        challenge,
    });

    // --- backup, settings -------------------------------------------------------------------
    let backup = flags.backup.clone().or_else(|| file.backup.clone());
    if let Some(b) = &backup {
        Target::parse(b).map_err(|e| ConfigError::refused(format!("--backup: {e}")))?;
    }
    let overrides = Overrides {
        retention_days: file.retention_days,
        min_client: file
            .min_client
            .as_deref()
            .map(|v| {
                Version::parse(v)
                    .map_err(|_| ConfigError::refused("server.toml `min_client` is not a version"))
            })
            .transpose()?,
        max_members: file.max_members,
        requests_per_minute: file.requests_per_minute,
        request_burst: file.request_burst,
        anonymous_per_minute: file.anonymous_per_minute,
        joins_per_hour: file.joins_per_hour,
        records_per_day: file.records_per_day,
        request_timeout_s: file.request_timeout_s,
    };
    if overrides.retention_days == Some(0) {
        return Err(ConfigError::refused(
            "server.toml `retention_days` must be at least 1",
        ));
    }
    if overrides.max_members == Some(0) {
        return Err(ConfigError::refused(
            "server.toml `max_members` must be at least 1",
        ));
    }
    let internal_token_hash = file.internal_token_sha256.clone();
    if let Some(h) = &internal_token_hash {
        if !valid_token_hash(h) {
            return Err(ConfigError::refused(
                "server.toml `internal_token_sha256` is not 64 lower-case hex characters",
            ));
        }
    }

    let request_time_retention = (behind && cloud_run) || port.is_some();
    Ok(Resolved {
        store,
        domain,
        listen,
        http01_listen,
        acme,
        behind_tls_proxy: behind,
        trusted_proxies,
        cloud_run,
        request_time_retention,
        backup,
        config_file,
        overrides,
        internal_token_hash,
    })
}

fn parse_socket(s: &str, flag: &str) -> Result<SocketAddr, ConfigError> {
    s.parse::<SocketAddr>().map_err(|_| {
        ConfigError::refused(format!(
            "{flag} takes an address and port such as 127.0.0.1:8787"
        ))
    })
}

/// Validates `--domain`: an IP literal, or a lower-case host name that is not under a shared
/// wildcard-DNS service.
pub fn parse_domain(text: &str) -> Result<Domain, ConfigError> {
    if let Ok(ip) = text.parse::<IpAddr>() {
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(ConfigError::refused(
                "--domain takes a public address or a host name",
            ));
        }
        return Ok(Domain::Ip(ip));
    }
    let name = text.trim_end_matches('.').to_ascii_lowercase();
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if name.is_empty() || name.len() > 253 || !name.split('.').all(label_ok) {
        return Err(ConfigError::refused(
            "--domain takes a host name (letters, digits, `-` and `.`) or an IP address, no \
             scheme, port or path",
        ));
    }
    for suffix in SHARED_SUFFIXES {
        if name == *suffix || name.ends_with(&format!(".{suffix}")) {
            return Err(ConfigError::refused(format!(
                "--domain under {suffix} is refused: wildcard-DNS services are not on the Public \
                 Suffix List, so every user shares one Let's Encrypt budget (50 certificates a \
                 week); use your own domain, or a plain IP address for an IP certificate"
            )));
        }
    }
    Ok(Domain::Dns(name))
}

fn load_file(flags: &Flags) -> Result<(FileConfig, Option<PathBuf>), ConfigError> {
    let path = match (&flags.config, &flags.data) {
        (Some(p), _) => Some(p.clone()),
        (None, Some(d)) => {
            let p = d.join(CONFIG_FILE);
            p.exists().then_some(p)
        }
        (None, None) => None,
    };
    let Some(path) = path else {
        return Ok((FileConfig::default(), None));
    };
    let meta = std::fs::metadata(&path).map_err(|e| {
        ConfigError::refused(format!("cannot read {}: {}", path.display(), io_kind(&e)))
    })?;
    if !meta.is_file() {
        return Err(ConfigError::refused(format!(
            "{} is not a file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(ConfigError::refused(format!(
                "{} is readable by group or others (mode {:04o}): it may hold a database URL; \
                 run chmod 600 on it",
                path.display(),
                mode
            )));
        }
    }
    let text = std::fs::read_to_string(&path).map_err(|e| {
        ConfigError::refused(format!("cannot read {}: {}", path.display(), io_kind(&e)))
    })?;
    Ok((FileConfig::parse(&text)?, Some(path)))
}

fn io_kind(e: &std::io::Error) -> String {
    e.kind().to_string()
}

// ---------------------------------------------------------------------------------------------
// File modes

/// What is wrong with the mode of `path`, if anything: `want_dir` expects 0700, a file 0600.
/// Any group or other bit is wrong; a stricter mode passes. Always `None` off Unix.
pub fn mode_problem(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).ok()?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some(format!(
                "{} is readable by group or others (mode {mode:04o})",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    None
}

/// The start-time file checks of §3.9.2 ("files"): the data directory, `server.db`,
/// `server.toml`, the ACME directory and every file in it must not be readable by group or
/// others. Missing files are fine. Exit 2 on the first problem.
pub fn verify_files(r: &Resolved) -> Result<(), ConfigError> {
    if let Some(p) = &r.config_file {
        if let Some(m) = mode_problem(p) {
            return Err(ConfigError::refused(m));
        }
    }
    if let Some(dir) = r.acme_dir() {
        if dir.is_dir() {
            if let Some(m) = mode_problem(&dir) {
                return Err(ConfigError::refused(m));
            }
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for entry in rd.flatten() {
                    if entry.path().is_file() {
                        if let Some(m) = mode_problem(&entry.path()) {
                            return Err(ConfigError::refused(format!(
                                "ACME key material: {m}; run chmod 600 on it"
                            )));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_parser_reads_the_flat_subset() {
        let c = FileConfig::parse(
            "# comment\n\
             domain = \"awm.example.com\"  # trailing\n\
             behind_tls_proxy = false\n\
             retention_days = 90\n\
             trusted_proxies = [\n  \"10.0.0.0/8\", # a\n  'cloud-run',\n]\n\
             backup = 'file:///var/backup#x'\n",
        )
        .unwrap();
        assert_eq!(c.domain.as_deref(), Some("awm.example.com"));
        assert_eq!(c.behind_tls_proxy, Some(false));
        assert_eq!(c.retention_days, Some(90));
        assert_eq!(c.trusted_proxies, ["10.0.0.0/8", "cloud-run"]);
        assert_eq!(c.backup.as_deref(), Some("file:///var/backup#x"));
    }

    #[test]
    fn the_parser_refuses_what_it_does_not_understand_without_echoing_values() {
        for bad in [
            "[section]\n",
            "nope = 1\n",
            "domain = 5\n",
            "domain = \"a\"\ndomain = \"b\"\n",
            "retention_days = -1\n",
            "database_url = \"postgres://u:hunter2@h/db\n",
        ] {
            let e = FileConfig::parse(bad).unwrap_err();
            assert_eq!(e.code, 2, "{bad}");
            assert!(!e.message.contains("hunter2"), "{}", e.message);
        }
    }
}
