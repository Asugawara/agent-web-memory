//! `awm serve ...` (plan-v3-team §4.8.1): the flags and subcommands, handed to
//! `awm_server::serve`. The only module that reaches `awm-server` (§4.1 item 4); compiled with
//! the `serve` feature.
//!
//! Every flag also reads an environment variable when the flag is absent (the container recipe
//! sets `AWM_DOMAIN` and friends): `AWM_CONFIG`, `AWM_DATA`, `AWM_DATABASE_URL_ENV`,
//! `AWM_DATABASE_URL_OWNER_ENV`, `AWM_DOMAIN`, `AWM_BACKUP`, `AWM_BEHIND_TLS_PROXY`,
//! `AWM_TRUSTED_PROXY` (comma-separated), `AWM_LISTEN`, `AWM_ACME_EMAIL`,
//! `AWM_ACME_CHALLENGE`, `AWM_ACME_DIRECTORY`, `AWM_ACME_STAGING`, `AWM_ACME_CA_FILE`,
//! `AWM_ACME_HTTP_LISTEN`. A flag wins over the variable, the variable over `server.toml`.
//! There is none for the database URL itself: name the variable that holds it.

use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::Context;
use awm_proto::wire::Version;
use awm_server::config::{Flags, Secret};
use awm_server::serve::{Command, Invocation, Io, Settings};

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(flatten)]
    inner: Box<Fields>,
}

#[derive(clap::Args, Debug)]
pub struct Fields {
    #[command(subcommand)]
    pub command: Option<Sub>,

    /// `server.toml` (default: `{data}/server.toml` when present); flags override the file
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// SqliteStore in DIR/server.db (created 0700 / 0600); exclusive with --database-url
    #[arg(long, global = true, value_name = "DIR")]
    pub data: Option<PathBuf>,
    /// PgStore; the URL is never logged (prefer --database-url-env)
    #[arg(long, global = true, value_name = "URL")]
    pub database_url: Option<String>,
    /// Name of the environment variable that holds the PgStore URL
    #[arg(long, global = true, value_name = "NAME")]
    pub database_url_env: Option<String>,
    /// Name of the environment variable that holds the owner URL (migrations)
    #[arg(long, global = true, value_name = "NAME")]
    pub database_url_owner_env: Option<String>,
    /// Built-in TLS: obtain and renew a certificate for HOST (a DNS name or an IP address)
    #[arg(long, global = true, value_name = "HOST")]
    pub domain: Option<String>,
    /// gs://BUCKET/PREFIX, s3://BUCKET/PREFIX or file:///PATH
    #[arg(long, global = true, value_name = "URL")]
    pub backup: Option<String>,
    /// Plain HTTP for a TLS terminator in front; needs --trusted-proxy
    #[arg(long, global = true)]
    pub behind_tls_proxy: bool,
    /// CIDR range of a trusted proxy, or `cloud-run` (repeatable)
    #[arg(long = "trusted-proxy", global = true, value_name = "CIDR")]
    pub trusted_proxy: Vec<String>,
    /// Listen address (default 127.0.0.1:8787; 0.0.0.0:443 with --domain)
    #[arg(long, global = true, value_name = "ADDR")]
    pub listen: Option<String>,
    /// Contact for the ACME account
    #[arg(long, global = true, value_name = "ADDR")]
    pub acme_email: Option<String>,
    /// tls-alpn-01 (default) or http-01
    #[arg(long, global = true, value_name = "TYPE")]
    pub acme_challenge: Option<String>,
    /// An ACME directory other than Let's Encrypt production
    #[arg(long, global = true, value_name = "URL")]
    pub acme_directory: Option<String>,
    /// Use Let's Encrypt staging
    #[arg(long, global = true)]
    pub acme_staging: bool,
    /// Extra CA certificate (PEM) to trust for the ACME server
    #[arg(long, global = true, value_name = "PEM")]
    pub acme_ca_file: Option<PathBuf>,
    /// Listener of the http-01 challenge (default 0.0.0.0:80)
    #[arg(long, global = true, value_name = "ADDR")]
    pub acme_http_listen: Option<String>,
}

#[derive(clap::Subcommand, Debug)]
pub enum Sub {
    /// Create the database and print a one-time bootstrap token
    Init {
        /// Print a token, its SHA-256 and its expiry; touch no database
        #[arg(long)]
        print_hash: bool,
    },
    /// Audit the configuration and the store (exit 0 all OK, 1 warnings, 2 failures)
    Check {
        #[arg(long)]
        json: bool,
        /// Also fetch https://DOMAIN/v1/info from this host
        #[arg(long)]
        external: bool,
    },
    /// A full snapshot (or canonical export) now
    Backup {
        /// Target URL or file (default: --backup)
        #[arg(long, value_name = "URL")]
        to: Option<String>,
        /// Restore the latest chain into a temporary directory and compare it
        #[arg(long)]
        verify: bool,
    },
    /// Restore a backup into --data or a database URL
    Restore {
        #[arg(long, value_name = "URL|FILE")]
        from: Option<String>,
        /// Unix seconds or RFC 3339
        #[arg(long, value_name = "TIME")]
        at: Option<String>,
        /// Replace an existing server.db (renamed to server.db.pre-restore-TIME)
        #[arg(long)]
        force: bool,
        /// Only change the generation (after a Cloud SQL restore or clone)
        #[arg(long)]
        mark_restored: bool,
    },
    /// Make a member an admin (admin recovery)
    Promote { handle: String },
    /// GET /healthz on the local listener; exit 0 or 1
    Healthcheck {
        #[arg(long, value_name = "URL")]
        url: Option<String>,
    },
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

fn truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

impl Fields {
    fn flags(&self) -> Flags {
        let from_env = |flag: &Option<String>, name: &str| flag.clone().or_else(|| env(name));
        let mut trusted = self.trusted_proxy.clone();
        if trusted.is_empty() {
            if let Some(v) = env("AWM_TRUSTED_PROXY") {
                trusted = v
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect();
            }
        }
        Flags {
            config: self
                .config
                .clone()
                .or_else(|| env("AWM_CONFIG").map(PathBuf::from)),
            data: self
                .data
                .clone()
                .or_else(|| env("AWM_DATA").map(PathBuf::from)),
            database_url: self.database_url.clone().map(Secret::new),
            database_url_env: from_env(&self.database_url_env, "AWM_DATABASE_URL_ENV"),
            database_url_owner_env: from_env(
                &self.database_url_owner_env,
                "AWM_DATABASE_URL_OWNER_ENV",
            ),
            domain: from_env(&self.domain, "AWM_DOMAIN"),
            backup: from_env(&self.backup, "AWM_BACKUP"),
            behind_tls_proxy: self.behind_tls_proxy
                || env("AWM_BEHIND_TLS_PROXY").is_some_and(|v| truthy(&v)),
            trusted_proxies: trusted,
            listen: from_env(&self.listen, "AWM_LISTEN"),
            acme_email: from_env(&self.acme_email, "AWM_ACME_EMAIL"),
            acme_challenge: from_env(&self.acme_challenge, "AWM_ACME_CHALLENGE"),
            acme_directory: from_env(&self.acme_directory, "AWM_ACME_DIRECTORY"),
            acme_staging: self.acme_staging || env("AWM_ACME_STAGING").is_some_and(|v| truthy(&v)),
            acme_ca_file: self
                .acme_ca_file
                .clone()
                .or_else(|| env("AWM_ACME_CA_FILE").map(PathBuf::from)),
            acme_http_listen: from_env(&self.acme_http_listen, "AWM_ACME_HTTP_LISTEN"),
        }
    }

    fn command(&self) -> Command {
        match &self.command {
            None => Command::Run,
            Some(Sub::Init { print_hash }) => Command::Init {
                print_hash: *print_hash,
            },
            Some(Sub::Check { json, external }) => Command::Check {
                json: *json,
                external: *external,
            },
            Some(Sub::Backup { to, verify }) => Command::Backup {
                to: to.clone(),
                verify: *verify,
            },
            Some(Sub::Restore {
                from,
                at,
                force,
                mark_restored,
            }) => Command::Restore {
                from: from.clone(),
                at: at.clone(),
                force: *force,
                mark_restored: *mark_restored,
            },
            Some(Sub::Promote { handle }) => Command::Promote {
                handle: handle.clone(),
            },
            Some(Sub::Healthcheck { url }) => Command::Healthcheck { url: url.clone() },
        }
    }
}

/// Runs the command and exits with the code of §4.8.1 when it is not 0.
pub fn run(args: Args) -> anyhow::Result<()> {
    let version = Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("the crate version is not a protocol version")?;
    let inv = Invocation {
        flags: args.inner.flags(),
        command: args.inner.command(),
        settings: Settings::system(version),
    };
    let tty = std::io::stdout().is_terminal();
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    let code = awm_server::serve::run(
        inv,
        &mut Io {
            out: &mut out,
            err: &mut err,
            tty,
        },
    );
    use std::io::Write;
    let _ = out.flush();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
