//! The per-request context every handler starts from: headers checked, body size capped, the
//! client address and the rate limits applied, then authentication.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use awm_proto::wire::{ClientHeader, Id, Version, CLIENT_HEADER};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Query, Request};
use axum::http::request::Parts;
use axum::http::HeaderMap;

use super::error::{parse_json, query_error, ApiError};
use super::AppState;
use crate::auth::{self, AuthError, Caller};
use crate::authz::{self, Action, Refusal};
use crate::limits::{bucket_addr, RateKey};

/// What the request log learns about a request while a handler runs.
#[derive(Debug, Default, Clone)]
pub(crate) struct LogFields {
    pub token: Option<String>,
    pub member: Option<Id>,
    pub ip: Option<IpAddr>,
    pub client: Option<String>,
}

/// Shared between the logging layer and the handler.
#[derive(Debug, Default, Clone)]
pub struct LogCell(Arc<Mutex<LogFields>>);

impl LogCell {
    fn update(&self, f: impl FnOnce(&mut LogFields)) {
        f(&mut self.0.lock().unwrap_or_else(|p| p.into_inner()));
    }

    pub(crate) fn snapshot(&self) -> LogFields {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// Whether `Awm-Client` is needed (`docs/sync-v1.md` §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    Required,
    /// `GET /v1/info`: may be absent, and is refused only when present and malformed.
    Optional,
}

/// How a request is rate limited before it is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Carries a device token: limited per device after authentication, per address while its
    /// token fails.
    Token,
    /// No token: `info`, `bootstrap`, the internal route. Limited per address.
    Anonymous,
    /// `POST /v1/join`: per address, and 10 an hour.
    Join,
}

/// Which body size limit applies on top of the 2 MiB one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cap {
    Body,
    /// `POST /v1/records`: 1.5 MiB.
    Batch,
}

/// An opened request.
pub struct Cx {
    pub app: AppState,
    pub now: i64,
    pub ip: IpAddr,
    /// The parsed `Awm-Client` header (always present when it was required).
    pub client: Option<ClientHeader>,
    pub log: LogCell,
    parts: Parts,
    /// In a `Mutex` only so that `&Cx` is `Sync` (an axum `Body` is not).
    body: Mutex<Option<Body>>,
    auth_header: Option<String>,
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).map(|v| v.to_str().unwrap_or(""))
}

impl Cx {
    /// Checks everything that needs no body and no store: `Content-Encoding`, the declared body
    /// size, `Awm-Client`, and the per-address rate limit.
    pub fn open(
        app: &AppState,
        req: Request,
        client: Client,
        class: Class,
        cap: Cap,
    ) -> Result<Cx, ApiError> {
        let now = app.now();
        let (parts, body) = req.into_parts();
        let log = parts
            .extensions
            .get::<LogCell>()
            .cloned()
            .unwrap_or_default();

        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let forwarded = header_str(&parts.headers, "x-forwarded-for");
        let ip = if app.config.forwarded_last_entry {
            super::net::last_forwarded_entry(peer, forwarded)
        } else {
            super::net::client_ip(peer, forwarded, &app.config.trusted_proxies)
        };
        log.update(|f| f.ip = Some(ip));

        let limits = &app.config.limits;
        if let Some(enc) = header_str(&parts.headers, "content-encoding") {
            if !enc.trim().eq_ignore_ascii_case("identity") {
                return Err(ApiError::malformed("content-encoding must be identity"));
            }
        }
        let declared =
            header_str(&parts.headers, "content-length").and_then(|v| v.parse::<u64>().ok());
        if let Some(n) = declared {
            if n > limits.max_body_bytes as u64 {
                return Err(ApiError::too_large(
                    "body",
                    limits.max_body_bytes as u64,
                    None,
                ));
            }
            if cap == Cap::Batch && n > limits.batch_bytes as u64 {
                return Err(ApiError::too_large(
                    "batch_bytes",
                    limits.batch_bytes as u64,
                    None,
                ));
            }
        }

        let header = match parts.headers.get(CLIENT_HEADER) {
            None if client == Client::Required => {
                return Err(ApiError::bad_client_header("Awm-Client is missing"))
            }
            None => None,
            Some(v) => {
                let text = v
                    .to_str()
                    .map_err(|_| ApiError::bad_client_header("Awm-Client is not text"))?;
                let parsed = ClientHeader::parse(text)
                    .map_err(|e| ApiError::bad_client_header(&e.to_string()))?;
                log.update(|f| f.client = Some(parsed.awm.to_string()));
                Some(parsed)
            }
        };

        let auth_header = if class == Class::Token {
            header_str(&parts.headers, "authorization").map(str::to_string)
        } else {
            None
        };
        if let Some(h) = &auth_header {
            if let Ok(p) = auth::parse(h) {
                log.update(|f| f.token = Some(p.log_prefix().to_string()));
            }
        }

        // The address limits come before anything is read or looked up.
        let limiter = &app.limiter;
        let bucket = bucket_addr(ip);
        let over = |r: Result<(), u32>| r.map_err(|s| ApiError::rate_limited(s, None));
        match (class, &auth_header) {
            // A request with a token is limited per device once the token is known, and per
            // address while its token fails: a team behind one address shares no budget. An
            // address whose failed-token budget is empty gets 429 here for a header that cannot
            // be a device token; a well-formed one is decided by `authenticate`, before the
            // body is read (RVT2 B1).
            (Class::Token, Some(h)) => {
                if let Err(s) =
                    limiter.check(RateKey::FailedAuth(bucket), limits.anonymous_rule(), now)
                {
                    if !auth::parse(h).is_ok_and(|p| p.kind() == auth::TokenKind::Device) {
                        return Err(ApiError::rate_limited(s, None));
                    }
                }
            }
            (Class::Token | Class::Anonymous, _) => {
                over(limiter.take(RateKey::Anonymous(bucket), limits.anonymous_rule(), now))?
            }
            (Class::Join, _) => {
                over(limiter.take(RateKey::Anonymous(bucket), limits.anonymous_rule(), now))?;
                over(limiter.take(RateKey::Join(bucket), limits.join_rule(), now))?;
            }
        }

        Ok(Cx {
            app: app.clone(),
            now,
            ip,
            client: header,
            log,
            parts,
            body: Mutex::new(Some(body)),
            auth_header,
        })
    }

    pub fn path(&self) -> &str {
        self.parts.uri.path()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        header_str(&self.parts.headers, name)
    }

    /// The request body, read to at most 2 MiB (and 1.5 MiB for a batch).
    pub async fn bytes(&mut self, cap: Cap) -> Result<Bytes, ApiError> {
        let limits = &self.app.config.limits;
        let body = self
            .body
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .unwrap_or_else(Body::empty);
        let bytes = axum::body::to_bytes(body, limits.max_body_bytes)
            .await
            .map_err(|_| ApiError::too_large("body", limits.max_body_bytes as u64, None))?;
        if cap == Cap::Batch && bytes.len() > limits.batch_bytes {
            return Err(ApiError::too_large(
                "batch_bytes",
                limits.batch_bytes as u64,
                None,
            ));
        }
        Ok(bytes)
    }

    /// A JSON body of type `T`.
    pub async fn json<T: serde::de::DeserializeOwned>(&mut self, cap: Cap) -> Result<T, ApiError> {
        let bytes = self.bytes(cap).await?;
        parse_json(&bytes)
    }

    /// A JSON body, or `{}` when there is none (requests whose fields are all optional).
    pub async fn json_or_empty<T: serde::de::DeserializeOwned>(&mut self) -> Result<T, ApiError> {
        let bytes = self.bytes(Cap::Body).await?;
        if bytes.is_empty() {
            return parse_json(b"{}");
        }
        parse_json(&bytes)
    }

    /// The query string as `T` (unknown parameters are 400 `unknown_field`).
    pub fn query<T: serde::de::DeserializeOwned>(&self) -> Result<T, ApiError> {
        Query::<T>::try_from_uri(&self.parts.uri)
            .map(|q| q.0)
            .map_err(|e| query_error(&e.body_text()))
    }

    /// Resolves the `Authorization` header with `auth::authenticate` (401 for a bad token; it also
    /// records the day the device was seen), then applies the per-device request limit. Every
    /// handler calls it before it reads the body (RVT2 B1).
    ///
    /// A presented token costs the address one request of its 30 a minute *before* the store
    /// lookup, given back when the token authenticates: concurrent guesses cannot all run their
    /// lookups before one is counted. When the address has none left, a token that fails gets
    /// 429; one that authenticates still passes, so a team behind the address of a guesser keeps
    /// working.
    pub async fn authenticate(&mut self) -> Result<Caller, ApiError> {
        let header = self.auth_header.clone();
        let limits = &self.app.config.limits;
        let failed_key = RateKey::FailedAuth(bucket_addr(self.ip));
        let charged = match header {
            Some(_) => Some(
                self.app
                    .limiter
                    .take(failed_key, limits.anonymous_rule(), self.now),
            ),
            None => None,
        };
        match auth::authenticate(&*self.app.store, header.as_deref(), self.now).await {
            Ok(caller) => {
                if charged == Some(Ok(())) {
                    self.app.limiter.refund(failed_key, self.now);
                }
                if let Some(d) = caller.device() {
                    self.log.update(|f| f.member = Some(d.member_id));
                    // One token per device: keyed on the device, a rotation keeps the budget.
                    self.app
                        .limiter
                        .take(RateKey::Device(d.device_id), limits.token_rule(), self.now)
                        .map_err(|s| ApiError::rate_limited(s, None))?;
                }
                Ok(caller)
            }
            Err(e) => {
                // The failing token keeps the request it was charged; with none left, 429.
                if let Some(Err(s)) = charged {
                    if matches!(e, AuthError::Refused(Refusal::Unauthenticated)) {
                        return Err(ApiError::rate_limited(s, None));
                    }
                }
                if charged == Some(Ok(())) && !matches!(e, AuthError::Refused(_)) {
                    // A store failure is not the caller's guess.
                    self.app.limiter.refund(failed_key, self.now);
                }
                Err(e.into())
            }
        }
    }

    /// `auth::authorise`: `authz::require` plus the audit row of a refusal.
    pub async fn authorise(&self, caller: &Caller, action: Action) -> Result<(), ApiError> {
        Ok(auth::authorise(&*self.app.store, caller, action, self.now).await?)
    }

    /// 426 when the client is below `min`.
    pub fn require_client_at_least(&self, min: &Version) -> Result<(), ApiError> {
        match &self.client {
            Some(c) if c.below(min) => Err(ApiError::client_too_old(&c.awm, min)),
            _ => Ok(()),
        }
    }

    /// The organisation's `min_client`, or the release floor before there is an organisation.
    pub async fn min_client(&self) -> Result<Version, ApiError> {
        Ok(match self.app.store.org(self.now).await? {
            Some(org) => org.settings.min_client,
            None => self.app.config.release_floor.clone(),
        })
    }

    /// The restore gate for an authenticated caller (`docs/sync-v1.md` §11): it binds approved
    /// callers that `authz` would not let complete a restore, and nobody else (a pending device
    /// or an anonymous caller gets `authz`'s refusal instead).
    pub async fn restore_gate_for(&self, caller: &Caller) -> Result<(), ApiError> {
        if caller.actor().is_some() && authz::require(caller, Action::CompleteRestore).is_err() {
            self.restore_gate().await
        } else {
            Ok(())
        }
    }

    /// 503 `restore_pending` while a restore is pending.
    pub async fn restore_gate(&self) -> Result<(), ApiError> {
        let state = self.app.store.restore_state().await?;
        if state.restore_pending {
            return Err(ApiError::restore_pending(
                state.generation,
                self.app.config.restore_retry_after_s,
            ));
        }
        Ok(())
    }
}

/// Parses a `{id}` path segment; anything but a canonical id names no object.
pub fn path_id(segment: &str) -> Result<Id, ApiError> {
    Id::parse(segment).map_err(|_| ApiError::not_found("no such object"))
}
