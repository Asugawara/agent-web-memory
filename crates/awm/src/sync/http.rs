//! Blocking HTTP calls to the sync server through `ureq` (plan-v3-team §4.3, §4.6; TM10).
//!
//! One [`Client`] per run. Timeouts are 5 s to connect and 30 s for a whole request (§3.3).
//! The bearer token and every body stay out of error values: a [`CallError`] holds the HTTP
//! status and the protocol's error code, nothing the server or the client sent.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use awm_proto::wire::{
    ApproveRequest, DeleteRequest, DeleteResponse, DeletionsResponse, ErrorBody, ErrorCode, Id,
    InfoResponse, KeysResponse, MembersResponse, PullRequest, PullResponse, PushRequest,
    PushResponse, RemoveRequest, RestoreCompleteRequest, RotateRequest, StatusResponse,
    TokenRotateResponse,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use ureq::http::{Method, Request};

/// 5 s to connect (plan-v3-team §3.3).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 30 s for a request, response body included (§3.3).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// No response is read beyond this: the biggest is a pull page, 8 MiB.
const MAX_RESPONSE: u64 = 16 * 1024 * 1024;

/// The `Awm-Client` header of this build (`docs/sync-v1.md` §2.2).
pub fn client_header() -> String {
    format!(
        "awm/{} proto/{} redact/{}",
        env!("CARGO_PKG_VERSION"),
        awm_proto::wire::PROTOCOL_VERSION,
        crate::redact::VERSION
    )
}

/// This build's version, for the `min_client` comparison.
pub fn own_version() -> awm_proto::wire::Version {
    awm_proto::wire::Version::parse(env!("CARGO_PKG_VERSION"))
        .unwrap_or_else(|_| awm_proto::wire::Version::new(0, 0, 0))
}

/// Why a call failed.
#[derive(Debug, Clone)]
pub enum CallError {
    /// No answer: refused, timed out, TLS, a broken connection.
    Network(String),
    /// The server answered with a status outside 2xx.
    Api {
        status: u16,
        error: Option<Box<ErrorBody>>,
        retry_after: Option<u32>,
    },
    /// The answer did not have the shape of the protocol.
    Protocol(String),
}

impl CallError {
    pub fn status(&self) -> Option<u16> {
        match self {
            CallError::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The protocol error code, when the server sent one.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            CallError::Api { error, .. } => error.as_ref().map(|e| e.error),
            _ => None,
        }
    }

    pub fn body(&self) -> Option<&ErrorBody> {
        match self {
            CallError::Api { error, .. } => error.as_deref(),
            _ => None,
        }
    }

    pub fn retry_after(&self) -> Option<u32> {
        match self {
            CallError::Api { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    /// True for a failure that a later run may not hit again: no network, 429, 5xx.
    pub fn transient(&self) -> bool {
        match self {
            CallError::Network(_) => true,
            CallError::Api { status, .. } => *status == 429 || *status >= 500,
            CallError::Protocol(_) => false,
        }
    }
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallError::Network(why) => write!(f, "the server did not answer ({why})"),
            CallError::Api { status, error, .. } => match error {
                Some(e) => write!(f, "the server answered {status} {}", code_name(e.error)),
                None => write!(f, "the server answered {status}"),
            },
            CallError::Protocol(why) => write!(f, "unexpected answer from the server ({why})"),
        }
    }
}

impl std::error::Error for CallError {}

fn code_name(code: ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "error".to_string())
}

/// `https://...`, or `http://` to a loopback address only (`docs/sync-v1.md` §2.1).
pub fn check_url(url: &str) -> Result<String> {
    let parsed = url::Url::parse(url.trim()).context("the server URL is not a URL")?;
    match parsed.scheme() {
        "https" => {}
        "http" => {
            let loopback = match parsed.host() {
                Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                None => false,
            };
            if !loopback {
                bail!("the server URL must be https:// (http:// is for loopback only)");
            }
        }
        _ => bail!("the server URL must be https://"),
    }
    Ok(url.trim().trim_end_matches('/').to_string())
}

/// The connection to one server, with the device token when there is one.
#[derive(Clone)]
pub struct Client {
    agent: ureq::Agent,
    base: String,
    token: Option<String>,
    header: String,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client for `base_url`. `ca_file` is a PEM file with the CA of a server behind an
    /// internal CA (`team.ca_file`); without it the built-in web roots apply.
    pub fn new(base_url: &str, token: Option<&str>, ca_file: Option<&Path>) -> Result<Client> {
        let base = check_url(base_url)?;
        let mut tls = ureq::tls::TlsConfig::builder();
        if let Some(path) = ca_file {
            let pem = std::fs::read(path)
                .with_context(|| format!("cannot read the CA file {}", path.display()))?;
            let mut certs = Vec::new();
            for item in ureq::tls::parse_pem(&pem) {
                if let ureq::tls::PemItem::Certificate(c) =
                    item.map_err(|_| anyhow::anyhow!("the CA file is not valid PEM"))?
                {
                    certs.push(c);
                }
            }
            if certs.is_empty() {
                bail!("the CA file holds no certificate");
            }
            tls = tls.root_certs(ureq::tls::RootCerts::Specific(Arc::new(certs)));
        }
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(REQUEST_TIMEOUT))
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .tls_config(tls.build())
            .build()
            .into();
        Ok(Client {
            agent,
            base,
            token: token.map(str::to_string),
            header: client_header(),
        })
    }

    /// The same connection with another token.
    pub fn with_token(&self, token: Option<&str>) -> Client {
        Client {
            token: token.map(str::to_string),
            ..self.clone()
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<T, CallError> {
        let bytes = self.exchange(method, path, body)?;
        serde_json::from_slice(&bytes)
            .map_err(|_| CallError::Protocol("the body is not the expected JSON".into()))
    }

    fn exchange(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, CallError> {
        let mut b = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base))
            .header("Awm-Client", &self.header);
        if let Some(t) = &self.token {
            b = b.header("Authorization", format!("Bearer {t}"));
        }
        let resp = match body {
            Some(bytes) => {
                let req = b
                    .header("Content-Type", "application/json")
                    .body(bytes)
                    .map_err(|_| CallError::Protocol("cannot build the request".into()))?;
                self.agent.run(req)
            }
            None => {
                let req = b
                    .body(())
                    .map_err(|_| CallError::Protocol("cannot build the request".into()))?;
                self.agent.run(req)
            }
        }
        .map_err(|e| CallError::Network(short(&e)))?;
        let (parts, mut body) = resp.into_parts();
        let status = parts.status.as_u16();
        let retry_after = parts
            .headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u32>().ok());
        let bytes = body
            .with_config()
            .limit(MAX_RESPONSE)
            .read_to_vec()
            .map_err(|e| CallError::Network(short(&e)))?;
        if (200..300).contains(&status) {
            return Ok(bytes);
        }
        let error = serde_json::from_slice::<ErrorBody>(&bytes)
            .ok()
            .map(Box::new);
        let retry_after = retry_after.or_else(|| error.as_ref().and_then(|e| e.retry_after_s));
        Err(CallError::Api {
            status,
            error,
            retry_after,
        })
    }

    /// `GET path`, JSON answer.
    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, CallError> {
        self.call(Method::GET, path, None)
    }

    /// `POST path` with a JSON body, JSON answer.
    pub fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CallError> {
        self.call(Method::POST, path, Some(encode(body)?))
    }

    /// `POST path` with a JSON body, no answer body (204).
    pub fn post_unit<B: Serialize>(&self, path: &str, body: &B) -> Result<(), CallError> {
        self.exchange(Method::POST, path, Some(encode(body)?))
            .map(|_| ())
    }

    /// `POST path` without a body, no answer body (204).
    pub fn post_empty(&self, path: &str) -> Result<(), CallError> {
        self.exchange(Method::POST, path, None).map(|_| ())
    }

    pub fn info(&self) -> Result<InfoResponse, CallError> {
        self.with_token(None).get("/v1/info")
    }

    pub fn status(&self) -> Result<StatusResponse, CallError> {
        self.get("/v1/status")
    }

    pub fn push(&self, req: &PushRequest) -> Result<PushResponse, CallError> {
        self.post("/v1/records", req)
    }

    pub fn pull(&self, req: &PullRequest) -> Result<PullResponse, CallError> {
        self.post("/v1/pull", req)
    }

    pub fn deletions(&self, from: u64, limit: u32) -> Result<DeletionsResponse, CallError> {
        self.get(&format!("/v1/deletions?from={from}&limit={limit}"))
    }

    pub fn delete(&self, req: &DeleteRequest) -> Result<DeleteResponse, CallError> {
        self.post("/v1/delete", req)
    }

    pub fn members(&self) -> Result<MembersResponse, CallError> {
        self.get("/v1/members")
    }

    pub fn keys(&self) -> Result<KeysResponse, CallError> {
        self.get("/v1/keys")
    }

    pub fn rotate_keys(&self, req: &RotateRequest) -> Result<(), CallError> {
        self.post_unit("/v1/keys/rotate", req)
    }

    pub fn approve_device(&self, device: Id, req: &ApproveRequest) -> Result<(), CallError> {
        self.post_unit(&format!("/v1/devices/{device}/approve"), req)
    }

    pub fn revoke_device(&self, device: Id) -> Result<(), CallError> {
        self.post_empty(&format!("/v1/devices/{device}/revoke"))
    }

    pub fn remove_member(&self, member: Id) -> Result<(), CallError> {
        self.post_unit(
            &format!("/v1/members/{member}/remove"),
            &RemoveRequest {
                delete_records: None,
            },
        )
    }

    pub fn restore_complete(&self, generation: Id) -> Result<(), CallError> {
        self.post_unit(
            "/v1/restore/complete",
            &RestoreCompleteRequest { generation },
        )
    }

    pub fn rotate_token(&self) -> Result<TokenRotateResponse, CallError> {
        self.call(Method::POST, "/v1/token/rotate", None)
    }
}

fn encode<B: Serialize>(body: &B) -> Result<Vec<u8>, CallError> {
    serde_json::to_vec(body).map_err(|_| CallError::Protocol("cannot encode the request".into()))
}

/// A short description of a transport error: no URL, no header.
fn short(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Timeout(_) => "timed out".to_string(),
        ureq::Error::ConnectionFailed => "connection failed".to_string(),
        ureq::Error::HostNotFound => "host not found".to_string(),
        ureq::Error::Io(io) => format!("{:?}", io.kind()).to_lowercase(),
        other => {
            let text = other.to_string();
            text.chars().take(80).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_is_for_loopback_only() {
        assert!(check_url("https://awm.example.com/").is_ok());
        assert!(check_url("http://127.0.0.1:8080").is_ok());
        assert!(check_url("http://localhost:1").is_ok());
        assert!(check_url("http://[::1]:1").is_ok());
        assert!(check_url("http://awm.example.com").is_err());
        assert!(check_url("http://192.168.1.5").is_err());
        assert!(check_url("ftp://127.0.0.1").is_err());
    }

    #[test]
    fn the_client_header_has_the_three_tokens_in_order() {
        let h = client_header();
        assert!(awm_proto::wire::ClientHeader::parse(&h).is_ok(), "{h}");
    }
}
