//! `server.toml` and the `awm serve` flags (plan-v3-team §4.7, §4.8.1).

use serde::{Deserialize, Serialize};

/// The server configuration; flags override the file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub domain: Option<String>,
    pub data: Option<String>,
    pub database_url_env: Option<String>,
    pub backup: Option<String>,
    pub listen: Option<String>,
    pub behind_tls_proxy: bool,
    pub trusted_proxies: Vec<String>,
    pub acme_email: Option<String>,
    pub acme_challenge: Option<String>,
    pub acme_directory: Option<String>,
}
