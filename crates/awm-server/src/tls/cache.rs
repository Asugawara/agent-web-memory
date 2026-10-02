//! `{data}/acme/`: the ACME account, the certificate and its key (plan-v3-team §3.9.3).
//!
//! The directory is 0700 and every file 0600, owned by the service user, written to a temporary
//! name created with mode 0600 and renamed into place (a crash leaves the old file or the new
//! one, never half of one). The directory is excluded from backups: `backup` writes only
//! `server.db` objects, never this directory. Loading refuses a group- or world-readable
//! directory or file, so a key that was ever exposed stops the start (exit 2).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::der::{pem_blocks, CertInfo};

pub const ACCOUNT_FILE: &str = "account.json";
pub const CERT_FILE: &str = "cert.pem";
pub const KEY_FILE: &str = "key.pem";
/// The ACME bookkeeping `awm serve check` reads (last error, backoff): no key material.
pub const STATE_FILE: &str = "state.json";

/// A cache problem. `Permissions` is a refused configuration (exit 2), the rest are I/O.
#[derive(Debug)]
pub enum CacheError {
    Permissions(String),
    Io(String),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::Permissions(m) | CacheError::Io(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for CacheError {}

fn io(what: &str, path: &Path, e: std::io::Error) -> CacheError {
    CacheError::Io(format!("{what} {}: {}", path.display(), e.kind()))
}

/// The certificate and key as stored.
#[derive(Debug, Clone)]
pub struct StoredCert {
    /// The chain, leaf first, as PEM.
    pub chain_pem: String,
    pub key_pem: String,
    /// The first certificate of the chain.
    pub info: CertInfo,
}

/// What `state.json` holds: enough for backoff across restarts and for `check`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeState {
    /// The last failure, without any URL or token in it.
    pub last_error: Option<String>,
    pub last_error_at: Option<i64>,
    /// Consecutive failures since the last success.
    pub failures: u32,
    /// No order before this time (Unix seconds).
    pub next_attempt_at: Option<i64>,
    /// The last time an order succeeded.
    pub last_ok_at: Option<i64>,
    /// The challenge type and directory host in use, for `check`.
    pub challenge: Option<String>,
    pub identifier: Option<String>,
    /// The ARI window of the installed certificate when it was last fetched.
    pub ari_start: Option<i64>,
    pub ari_end: Option<i64>,
}

/// The directory `{data}/acme`.
#[derive(Debug, Clone)]
pub struct AcmeCache {
    dir: PathBuf,
}

impl AcmeCache {
    /// Creates the directory with mode 0700 when missing and refuses one that others can read.
    pub fn open(dir: &Path) -> Result<AcmeCache, CacheError> {
        if !dir.exists() {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            b.create(dir).map_err(|e| io("cannot create", dir, e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| io("cannot set mode 0700 on", dir, e))?;
            }
        }
        if let Some(m) = crate::config::mode_problem(dir) {
            return Err(CacheError::Permissions(m));
        }
        Ok(AcmeCache {
            dir: dir.to_path_buf(),
        })
    }

    /// The cache at `dir` if it exists, without creating it and without judging its mode
    /// (`check` reports modes itself).
    pub fn peek(dir: &Path) -> Option<AcmeCache> {
        dir.is_dir().then(|| AcmeCache {
            dir: dir.to_path_buf(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn read(&self, name: &str) -> Result<Option<String>, CacheError> {
        let path = self.dir.join(name);
        if !path.exists() {
            return Ok(None);
        }
        if let Some(m) = crate::config::mode_problem(&path) {
            return Err(CacheError::Permissions(format!("{m}; run chmod 600 on it")));
        }
        std::fs::read_to_string(&path)
            .map(Some)
            .map_err(|e| io("cannot read", &path, e))
    }

    /// Writes `contents` to `name` with mode 0600 through a temporary file and a rename.
    fn write(&self, name: &str, contents: &str) -> Result<(), CacheError> {
        let path = self.dir.join(name);
        let tmp = self.dir.join(format!(".{name}.tmp"));
        let _ = std::fs::remove_file(&tmp);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|e| io("cannot create", &tmp, e))?;
        f.write_all(contents.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|e| io("cannot write", &tmp, e))?;
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| io("cannot set mode 0600 on", &tmp, e))?;
        }
        std::fs::rename(&tmp, &path).map_err(|e| io("cannot replace", &path, e))
    }

    /// `account.json`: the directory it belongs to and the credentials instant-acme gave.
    pub fn load_account(&self) -> Result<Option<String>, CacheError> {
        self.read(ACCOUNT_FILE)
    }

    pub fn save_account(&self, json: &str) -> Result<(), CacheError> {
        self.write(ACCOUNT_FILE, json)
    }

    /// The cached certificate, if both files are there and the certificate parses.
    pub fn load_cert(&self) -> Result<Option<StoredCert>, CacheError> {
        let (Some(chain_pem), Some(key_pem)) = (self.read(CERT_FILE)?, self.read(KEY_FILE)?) else {
            return Ok(None);
        };
        let Some(first) = pem_blocks(&chain_pem, "CERTIFICATE").into_iter().next() else {
            return Ok(None);
        };
        let Some(info) = CertInfo::parse(&first) else {
            return Ok(None);
        };
        Ok(Some(StoredCert {
            chain_pem,
            key_pem,
            info,
        }))
    }

    /// Key first, then certificate: a crash between them leaves a key without a certificate,
    /// which loads as "no certificate", never a certificate whose key is missing.
    pub fn save_cert(&self, chain_pem: &str, key_pem: &str) -> Result<(), CacheError> {
        self.write(KEY_FILE, key_pem)?;
        self.write(CERT_FILE, chain_pem)
    }

    pub fn load_state(&self) -> AcmeState {
        self.read(STATE_FILE)
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save_state(&self, state: &AcmeState) -> Result<(), CacheError> {
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| CacheError::Io(format!("cannot encode state: {e}")))?;
        self.write(STATE_FILE, &json)
    }
}
