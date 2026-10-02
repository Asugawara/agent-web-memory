//! The ACME client of the server (plan-v3-team §3.9.3): obtains and renews the certificate for
//! `--domain` over TLS-ALPN-01 (default) or HTTP-01 (opt-in), on instant-acme.
//!
//! - **Persistence**: the account (`account.json`), certificate and key live in `{data}/acme/`
//!   ([`super::cache`]); a restart installs the cached certificate and places no order.
//! - **Renewal** follows ACME Renewal Information (RFC 9773): the window comes from the CA's
//!   `renewalInfo` URL for the installed certificate, a random point in it is chosen once,
//!   and the new order carries `replaces`. Without ARI (an unreachable URL, a CA that has
//!   none) renewal falls back to two thirds of the certificate's lifetime.
//! - **Backoff**: after a failed order the next attempt waits 1, then 10, then 60 minutes
//!   (and 60 from then on), persisted in `state.json`, so a crash loop never burns the CA's
//!   five-failures-an-hour limit.
//! - **IP identifiers** order under the `shortlived` profile.
//! - **Time** comes from a [`Clock`] so tests move it; [`Acme::tick`] makes one decision and
//!   [`Acme::run`] loops it.
//!
//! ARI needs two plain HTTPS GETs (the directory and the `renewalInfo` URL) that instant-acme
//! does not expose without its `time` feature, so [`https_get`] does them with tokio-rustls
//! and the CA bundle named by `--acme-ca-file`, `SSL_CERT_FILE` or the usual system paths.
//! No message here holds a token or a key.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CertificateIdentifier, ChallengeType,
    Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::pki_types::{CertificateDer, ServerName};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::alpn::{certified_key, challenge_cert, CertSlot};
use super::cache::{AcmeCache, AcmeState, CacheError, StoredCert};
use super::der::{pem_blocks, CertInfo};
use crate::config::{Challenge, Domain};
use crate::retention::Clock;

/// Seconds to wait after the 1st, 2nd and later failed orders (§3.9.3).
pub const BACKOFF_S: [i64; 3] = [60, 600, 3_600];
/// The profile an IP-address certificate needs (§3.9.3).
pub const SHORTLIVED: &str = "shortlived";
/// How long one order may take from `newOrder` to the certificate.
const ORDER_TIMEOUT: Duration = Duration::from_secs(120);
/// The longest [`Acme::run`] sleeps before it looks again.
const MAX_SLEEP_S: i64 = 3_600;
/// Without ARI, renew when this fraction of the lifetime is used.
const FALLBACK_NUM: i64 = 2;
const FALLBACK_DEN: i64 = 3;

/// An ACME failure with a message that is safe to log and to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeError(pub String);

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AcmeError {}

impl From<CacheError> for AcmeError {
    fn from(e: CacheError) -> AcmeError {
        AcmeError(e.to_string())
    }
}

fn err(what: &str, e: impl std::fmt::Display) -> AcmeError {
    AcmeError(format!("{what}: {}", redact(&e.to_string())))
}

/// An error text without anything that looks like a URL query or a token.
fn redact(s: &str) -> String {
    let mut out: String = s
        .split_whitespace()
        .map(|w| {
            if w.contains("://") || w.starts_with("awm_") {
                "<url>"
            } else {
                w
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    out.truncate(400);
    out
}

/// What to obtain and where from.
#[derive(Debug, Clone)]
pub struct AcmeParams {
    pub identifier: Domain,
    pub directory: String,
    /// Extra trust root for the ACME server (a test CA such as Pebble's); also used for ARI.
    pub ca_file: Option<PathBuf>,
    pub email: Option<String>,
    pub challenge: Challenge,
}

/// HTTP-01 key authorizations by token, shared with the port-80 handler.
#[derive(Debug, Default)]
pub struct Http01Tokens(Mutex<BTreeMap<String, String>>);

impl Http01Tokens {
    pub fn new() -> Arc<Http01Tokens> {
        Arc::new(Http01Tokens::default())
    }

    pub fn set(&self, token: &str, key_authorization: &str) {
        if let Ok(mut m) = self.0.lock() {
            m.insert(token.to_string(), key_authorization.to_string());
        }
    }

    pub fn remove(&self, token: &str) {
        if let Ok(mut m) = self.0.lock() {
            m.remove(token);
        }
    }

    pub fn get(&self, token: &str) -> Option<String> {
        self.0.lock().ok()?.get(token).cloned()
    }
}

/// One order as the CA reflected it (tests and `check` read these).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderLog {
    pub at: i64,
    pub identifiers: Vec<String>,
    pub profile: Option<String>,
    pub replaces: Option<String>,
    /// The `newOrder` payload as serialised before it was signed and sent.
    pub sent: String,
    pub ok: bool,
}

/// The decision of one [`Acme::tick`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tick {
    /// The certificate is installed and renewal is due at `renew_at`.
    NotDue { renew_at: i64 },
    /// A new certificate was obtained and installed.
    Renewed,
    /// An order failed; the next attempt is not before `retry_at`.
    Failed { error: String, retry_at: i64 },
    /// A failure is cooling down.
    Backoff { retry_at: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Window {
    start: i64,
    end: i64,
    /// The point inside the window chosen to renew at.
    renew_at: i64,
    /// Ask the CA again after this time.
    recheck_at: i64,
}

struct Installed {
    info: CertInfo,
    window: Option<Window>,
}

struct Inner {
    account: Option<Account>,
    installed: Option<Installed>,
    state: AcmeState,
}

/// The ACME client: the account, the installed certificate and the renewal schedule.
pub struct Acme {
    params: AcmeParams,
    cache: AcmeCache,
    clock: Arc<dyn Clock>,
    slot: Arc<CertSlot>,
    http01: Arc<Http01Tokens>,
    inner: tokio::sync::Mutex<Inner>,
    orders: Mutex<Vec<OrderLog>>,
}

impl Acme {
    pub fn new(
        params: AcmeParams,
        cache: AcmeCache,
        clock: Arc<dyn Clock>,
        slot: Arc<CertSlot>,
        http01: Arc<Http01Tokens>,
    ) -> Acme {
        let mut state = cache.load_state();
        state.identifier = Some(params.identifier.name());
        state.challenge = Some(
            match params.challenge {
                Challenge::TlsAlpn01 => "tls-alpn-01",
                Challenge::Http01 => "http-01",
            }
            .to_string(),
        );
        Acme {
            params,
            cache,
            clock,
            slot,
            http01,
            inner: tokio::sync::Mutex::new(Inner {
                account: None,
                installed: None,
                state,
            }),
            orders: Mutex::new(Vec::new()),
        }
    }

    /// Every order this process placed, as the CA reflected it.
    pub fn orders(&self) -> Vec<OrderLog> {
        self.orders.lock().map(|o| o.clone()).unwrap_or_default()
    }

    /// The ARI window of the installed certificate (start, end, chosen renewal time).
    pub async fn window(&self) -> Option<(i64, i64, i64)> {
        let g = self.inner.lock().await;
        g.installed
            .as_ref()?
            .window
            .map(|w| (w.start, w.end, w.renew_at))
    }

    /// The installed certificate's `notAfter`.
    pub async fn not_after(&self) -> Option<i64> {
        self.inner
            .lock()
            .await
            .installed
            .as_ref()
            .map(|i| i.info.not_after)
    }

    fn record_state(&self, inner: &Inner) {
        if let Err(e) = self.cache.save_state(&inner.state) {
            eprintln!("acme: cannot write state.json: {e}");
        }
    }

    /// Installs the cached certificate, or orders one. `Ok(true)` when one came from the cache
    /// and `Ok(false)` when a new one was ordered. An error leaves the server without a
    /// certificate (exit 4) unless a cached one is still valid: that one is installed and the
    /// error is only stored for `check` and the next tick.
    pub async fn start(&self) -> Result<bool, AcmeError> {
        let now = self.clock.now();
        let mut g = self.inner.lock().await;
        if let Some(cached) = self.cache.load_cert()? {
            if cached.info.not_after > now && self.install(&mut g, &cached).is_ok() {
                return Ok(true);
            }
        }
        if let Some(t) = g.state.next_attempt_at.filter(|t| *t > now) {
            return Err(AcmeError(format!(
                "the last order failed and the next attempt is not before {} s from now \
                 (backoff 1, 10, 60 minutes)",
                t - now
            )));
        }
        match self.order(&mut g, now, None).await {
            Ok(()) => Ok(false),
            Err(e) => {
                self.fail(&mut g, now, &e);
                Err(e)
            }
        }
    }

    fn install(&self, g: &mut Inner, cert: &StoredCert) -> Result<(), AcmeError> {
        let key = certified_key(&cert.chain_pem, &cert.key_pem).map_err(AcmeError)?;
        self.slot.install(key);
        g.installed = Some(Installed {
            info: cert.info.clone(),
            window: None,
        });
        Ok(())
    }

    fn fail(&self, g: &mut Inner, now: i64, e: &AcmeError) -> i64 {
        g.state.failures = g.state.failures.saturating_add(1);
        let step = (g.state.failures as usize - 1).min(BACKOFF_S.len() - 1);
        let retry_at = now + BACKOFF_S[step];
        g.state.last_error = Some(e.0.clone());
        g.state.last_error_at = Some(now);
        g.state.next_attempt_at = Some(retry_at);
        self.record_state(g);
        retry_at
    }

    /// One decision of the renewal loop: look at the clock and the ARI window and renew if due.
    pub async fn tick(&self) -> Tick {
        let now = self.clock.now();
        let mut g = self.inner.lock().await;
        if let Some(t) = g.state.next_attempt_at.filter(|t| *t > now) {
            return Tick::Backoff { retry_at: t };
        }
        let Some(inst) = g.installed.as_ref() else {
            // No certificate at all: order one.
            return self.attempt(&mut g, now, None).await;
        };
        let mut window = inst.window;
        let info = inst.info.clone();
        if window.is_none_or(|w| now >= w.recheck_at) {
            window = self.fetch_window(&info, now).await.or(window);
            if let Some(i) = g.installed.as_mut() {
                i.window = window;
            }
            g.state.ari_start = window.map(|w| w.start);
            g.state.ari_end = window.map(|w| w.end);
            self.record_state(&g);
        }
        let renew_at = match window {
            Some(w) => w.renew_at,
            None => {
                info.not_before + (info.not_after - info.not_before) * FALLBACK_NUM / FALLBACK_DEN
            }
        };
        // Never let a certificate lapse because ARI said "later".
        let renew_at = renew_at.min(info.not_after - 3_600);
        if now < renew_at {
            return Tick::NotDue { renew_at };
        }
        let replaces = replaces_id(&info);
        self.attempt(&mut g, now, replaces).await
    }

    async fn attempt(
        &self,
        g: &mut Inner,
        now: i64,
        replaces: Option<CertificateIdentifier<'static>>,
    ) -> Tick {
        match self.order(g, now, replaces).await {
            Ok(()) => Tick::Renewed,
            Err(e) => {
                let retry_at = self.fail(g, now, &e);
                Tick::Failed {
                    error: e.0,
                    retry_at,
                }
            }
        }
    }

    /// Runs [`Acme::tick`] until `shutdown`, sleeping until the next decision is due.
    pub async fn run<F>(&self, shutdown: F)
    where
        F: Future<Output = ()> + Send,
    {
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            let now = self.clock.now();
            let wait = match self.tick().await {
                Tick::NotDue { renew_at } => renew_at - now,
                Tick::Renewed => MAX_SLEEP_S,
                Tick::Failed { retry_at, error } => {
                    eprintln!("acme: renewal failed: {error}");
                    retry_at - now
                }
                Tick::Backoff { retry_at } => retry_at - now,
            };
            let wait = wait.clamp(60, MAX_SLEEP_S) as u64;
            tokio::select! {
                biased;
                _ = &mut shutdown => break,
                _ = self.clock.sleep(wait) => {}
            }
        }
    }

    // --- ARI -----------------------------------------------------------------------------------

    /// The CA's renewal window for `info`, with a renewal time chosen inside it.
    async fn fetch_window(&self, info: &CertInfo, now: i64) -> Option<Window> {
        let id = replaces_id(info)?;
        let roots = root_store(self.params.ca_file.as_deref());
        let dir = https_get(&self.params.directory, &roots).await.ok()?;
        let dir: serde_json::Value = serde_json::from_slice(&dir.body).ok()?;
        let base = dir
            .get("renewalInfo")?
            .as_str()?
            .trim_end_matches('/')
            .to_string();
        let resp = https_get(&format!("{base}/{id}"), &roots).await.ok()?;
        if resp.status != 200 {
            return None;
        }
        let body: serde_json::Value = serde_json::from_slice(&resp.body).ok()?;
        let w = body.get("suggestedWindow")?;
        let start = rfc3339(w.get("start")?.as_str()?)?;
        let end = rfc3339(w.get("end")?.as_str()?)?;
        if end < start {
            return None;
        }
        let retry_after = resp
            .header("retry-after")
            .and_then(|v| v.trim().parse::<i64>().ok())
            .unwrap_or(6 * 3_600)
            .clamp(60, MAX_SLEEP_S * 6);
        // A window that began in the past means renew now; otherwise a uniformly random point.
        let renew_at = if start <= now {
            now
        } else {
            start + random_below((end - start + 1) as u64) as i64
        };
        Some(Window {
            start,
            end,
            renew_at,
            recheck_at: now + retry_after,
        })
    }

    // --- orders --------------------------------------------------------------------------------

    async fn account(&self, g: &mut Inner) -> Result<Account, AcmeError> {
        if let Some(a) = &g.account {
            return Ok(a.clone());
        }
        let builder = || match &self.params.ca_file {
            Some(p) => Account::builder_with_root(p),
            None => Account::builder(),
        };
        let stored = self.cache.load_account()?;
        if let Some(text) = stored {
            if let Ok(f) = serde_json::from_str::<AccountFile>(&text) {
                if f.directory == self.params.directory {
                    let account = builder()
                        .map_err(|e| err("acme client", e))?
                        .from_credentials(f.credentials)
                        .await
                        .map_err(|e| err("acme account", e))?;
                    g.account = Some(account.clone());
                    return Ok(account);
                }
            }
        }
        let contact: Vec<String> = self
            .params
            .email
            .iter()
            .map(|e| format!("mailto:{e}"))
            .collect();
        let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
        let (account, credentials) = builder()
            .map_err(|e| err("acme client", e))?
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.params.directory.clone(),
                None,
            )
            .await
            .map_err(|e| err("acme account", e))?;
        let json = serde_json::to_string(&AccountFile {
            directory: self.params.directory.clone(),
            credentials,
        })
        .map_err(|e| err("acme account", e))?;
        self.cache.save_account(&json)?;
        g.account = Some(account.clone());
        Ok(account)
    }

    /// Places one order and installs the certificate it yields.
    async fn order(
        &self,
        g: &mut Inner,
        now: i64,
        replaces: Option<CertificateIdentifier<'static>>,
    ) -> Result<(), AcmeError> {
        let account = self.account(g).await?;
        let name = self.params.identifier.name();
        let result = tokio::time::timeout(ORDER_TIMEOUT, self.order_inner(&account, now, replaces))
            .await
            .unwrap_or_else(|_| Err(AcmeError("the order timed out".into())));
        self.slot_cleanup(&name);
        let (chain, key) = result?;
        let info = pem_blocks(&chain, "CERTIFICATE")
            .into_iter()
            .next()
            .and_then(|d| CertInfo::parse(&d))
            .ok_or_else(|| AcmeError("the CA returned an unreadable certificate".into()))?;
        self.cache.save_cert(&chain, &key)?;
        let stored = StoredCert {
            chain_pem: chain,
            key_pem: key,
            info,
        };
        self.install(g, &stored)?;
        g.state.failures = 0;
        g.state.last_error = None;
        g.state.last_error_at = None;
        g.state.next_attempt_at = None;
        g.state.last_ok_at = Some(now);
        g.state.ari_start = None;
        g.state.ari_end = None;
        self.record_state(g);
        Ok(())
    }

    fn slot_cleanup(&self, name: &str) {
        self.slot.clear_challenge(name);
    }

    async fn order_inner(
        &self,
        account: &Account,
        now: i64,
        replaces: Option<CertificateIdentifier<'static>>,
    ) -> Result<(String, String), AcmeError> {
        let ident = match &self.params.identifier {
            Domain::Dns(d) => Identifier::Dns(d.clone()),
            Domain::Ip(ip) => Identifier::Ip(*ip),
        };
        let idents = [ident];
        let mut new = NewOrder::new(&idents);
        let is_ip = self.params.identifier.is_ip();
        if is_ip {
            new = new.profile(SHORTLIVED);
        }
        let replaces_text = replaces.as_ref().map(ToString::to_string);
        if let Some(r) = replaces {
            new = new.replaces(r);
        }
        let mut log = OrderLog {
            at: now,
            identifiers: vec![self.params.identifier.name()],
            profile: is_ip.then(|| SHORTLIVED.to_string()),
            replaces: replaces_text,
            sent: serde_json::to_string(&new).unwrap_or_default(),
            ok: false,
        };
        let outcome = self.order_steps(account, new).await;
        log.ok = outcome.is_ok();
        if let Ok((_, _, reflected)) = &outcome {
            // What the CA says it received, not what we meant to send.
            log.profile = reflected.0.clone();
            log.replaces = reflected.1.clone();
        }
        if let Ok(mut o) = self.orders.lock() {
            o.push(log);
        }
        outcome.map(|(chain, key, _)| (chain, key))
    }

    #[allow(clippy::type_complexity)]
    async fn order_steps(
        &self,
        account: &Account,
        new: NewOrder<'_>,
    ) -> Result<(String, String, (Option<String>, Option<String>)), AcmeError> {
        let mut order = account
            .new_order(&new)
            .await
            .map_err(|e| err("new order", e))?;
        let reflected = {
            let s = order.state();
            (
                s.profile.clone(),
                s.replaces.as_ref().map(ToString::to_string),
            )
        };
        let name = self.params.identifier.name();
        let mut tokens = Vec::new();
        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authz = result.map_err(|e| err("authorization", e))?;
                match authz.status {
                    AuthorizationStatus::Valid => continue,
                    AuthorizationStatus::Pending => {}
                    _ => return Err(AcmeError("an authorization is not usable".into())),
                }
                match self.params.challenge {
                    Challenge::TlsAlpn01 => {
                        let mut c = authz.challenge(ChallengeType::TlsAlpn01).ok_or_else(|| {
                            AcmeError("the CA offers no tls-alpn-01 challenge".into())
                        })?;
                        let digest = c.key_authorization().digest();
                        let key = challenge_cert(&self.params.identifier, digest.as_ref())
                            .map_err(AcmeError)?;
                        self.slot.set_challenge(&name, key);
                        c.set_ready().await.map_err(|e| err("challenge", e))?;
                    }
                    Challenge::Http01 => {
                        let mut c = authz.challenge(ChallengeType::Http01).ok_or_else(|| {
                            AcmeError("the CA offers no http-01 challenge".into())
                        })?;
                        let token = c.token.clone();
                        self.http01.set(&token, c.key_authorization().as_str());
                        tokens.push(token);
                        c.set_ready().await.map_err(|e| err("challenge", e))?;
                    }
                }
            }
        }
        let policy = RetryPolicy::new().timeout(ORDER_TIMEOUT);
        let ready = order.poll_ready(&policy).await;
        for t in &tokens {
            self.http01.remove(t);
        }
        match ready.map_err(|e| err("order", e))? {
            OrderStatus::Ready => {}
            _ => return Err(AcmeError("the CA refused the order".into())),
        }
        let key = rcgen::KeyPair::generate().map_err(|e| err("certificate key", e))?;
        let mut params =
            rcgen::CertificateParams::new(vec![name]).map_err(|e| err("certificate request", e))?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params
            .serialize_request(&key)
            .map_err(|e| err("certificate request", e))?;
        order
            .finalize_csr(csr.der())
            .await
            .map_err(|e| err("finalize", e))?;
        let chain = order
            .poll_certificate(&policy)
            .await
            .map_err(|e| err("certificate", e))?;
        Ok((chain, key.serialize_pem(), reflected))
    }
}

#[derive(Serialize, Deserialize)]
struct AccountFile {
    directory: String,
    credentials: AccountCredentials,
}

/// The ARI identifier of a certificate (RFC 9773 §4.1).
pub fn replaces_id(info: &CertInfo) -> Option<CertificateIdentifier<'static>> {
    use std::borrow::Cow;
    let aki = info.authority_key_id.as_ref()?;
    Some(CertificateIdentifier {
        authority_key_identifier: Cow::Owned(b64url(aki)),
        serial: Cow::Owned(b64url(&info.serial)),
    })
}

fn b64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(b.len() * 4 / 3 + 2);
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        if c.len() > 1 {
            out.push(A[(n >> 6) as usize & 63] as char);
        }
        if c.len() > 2 {
            out.push(A[n as usize & 63] as char);
        }
    }
    out
}

/// A uniformly distributed value in `0..n` from the system random source.
fn random_below(n: u64) -> u64 {
    use ring::rand::SecureRandom;
    if n <= 1 {
        return 0;
    }
    let rng = ring::rand::SystemRandom::new();
    // Rejection sampling keeps the distribution uniform.
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let mut b = [0u8; 8];
        if rng.fill(&mut b).is_err() {
            return 0;
        }
        let v = u64::from_le_bytes(b);
        if v < zone {
            return v % n;
        }
    }
}

/// An RFC 3339 time (`2026-10-02T14:00:00Z`, optionally with fractional seconds or an offset)
/// as Unix seconds.
pub fn rfc3339(s: &str) -> Option<i64> {
    let (date, time) = s.split_once(['T', 't'])?;
    let mut d = date.split('-');
    let (y, mo, da): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let (clock, offset) = if let Some(c) = time.strip_suffix(['Z', 'z']) {
        (c, 0)
    } else {
        let i = time.rfind(['+', '-'])?;
        let (c, o) = time.split_at(i);
        let sign = if o.starts_with('-') { -1 } else { 1 };
        let (oh, om) = o[1..].split_once(':')?;
        (
            c,
            sign * (oh.parse::<i64>().ok()? * 3_600 + om.parse::<i64>().ok()? * 60),
        )
    };
    let clock = clock.split('.').next()?;
    let mut t = clock.split(':');
    let (h, mi, se): (i64, i64, i64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    Some(super::der::days_from_civil(y, mo, da) * 86_400 + h * 3_600 + mi * 60 + se - offset)
}

// ---------------------------------------------------------------------------------------------
// A minimal HTTPS GET

/// A response of [`https_get`].
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The trust roots for ACME-side GETs: `ca_file` when given, else the first CA bundle found
/// (`SSL_CERT_FILE`, then the usual system paths).
pub fn root_store(ca_file: Option<&Path>) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = ca_file {
        candidates.push(p.to_path_buf());
    } else {
        if let Some(p) = std::env::var_os("SSL_CERT_FILE") {
            candidates.push(PathBuf::from(p));
        }
        for p in [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/cert.pem",
            "/etc/ssl/ca-bundle.pem",
        ] {
            candidates.push(PathBuf::from(p));
        }
    }
    for p in candidates {
        if let Ok(text) = std::fs::read_to_string(&p) {
            for der in pem_blocks(&text, "CERTIFICATE") {
                let _ = roots.add(CertificateDer::from(der));
            }
            if !roots.is_empty() {
                break;
            }
        }
    }
    roots
}

/// `GET url` over TLS with HTTP/1.0 (no chunked bodies), 20 s in all, at most 1 MiB.
pub async fn https_get(url: &str, roots: &rustls::RootCertStore) -> Result<Response, AcmeError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| AcmeError("not an https URL".into()))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (
            h.trim_matches(['[', ']']),
            p.parse::<u16>().map_err(|_| AcmeError("bad port".into()))?,
        ),
        _ => (authority.trim_matches(['[', ']']), 443),
    };
    let work = async {
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| err("tls", e))?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
        let name = ServerName::try_from(host.to_string()).map_err(|e| err("server name", e))?;
        let tcp = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|e| err("connect", e.kind()))?;
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(name, tcp)
            .await
            .map_err(|e| err("tls handshake", e.kind()))?;
        let req = format!(
            "GET {path} HTTP/1.0\r\nHost: {authority}\r\nUser-Agent: awm-server\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(req.as_bytes())
            .await
            .map_err(|e| err("write", e.kind()))?;
        let mut raw = Vec::new();
        let _ = (&mut tls).take(1 << 20).read_to_end(&mut raw).await;
        parse_response(&raw)
    };
    tokio::time::timeout(Duration::from_secs(20), work)
        .await
        .unwrap_or_else(|_| Err(AcmeError("request timed out".into())))
}

fn parse_response(raw: &[u8]) -> Result<Response, AcmeError> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| AcmeError("malformed HTTP response".into()))?;
    let head = std::str::from_utf8(&raw[..split])
        .map_err(|_| AcmeError("malformed HTTP response".into()))?;
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| AcmeError("malformed HTTP status line".into()))?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Ok(Response {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_times_parse() {
        assert_eq!(rfc3339("2026-01-02T03:04:05Z"), Some(1_767_323_045));
        assert_eq!(rfc3339("2026-01-02T03:04:05.678Z"), Some(1_767_323_045));
        assert_eq!(rfc3339("2026-01-02T05:04:05+02:00"), Some(1_767_323_045));
        assert_eq!(rfc3339("nope"), None);
    }

    #[test]
    fn base64url_matches_the_rfc_vectors() {
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn backoff_steps_are_one_ten_and_sixty_minutes() {
        assert_eq!(BACKOFF_S, [60, 600, 3_600]);
    }

    #[test]
    fn error_texts_lose_urls_and_tokens() {
        let t = redact("failed https://acme.example/new-order?token=abc and awm_t_x done");
        assert!(!t.contains("acme.example") && !t.contains("awm_t_"), "{t}");
    }
}
