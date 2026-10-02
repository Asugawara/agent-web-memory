//! The TLS side of the server: the certificate resolver that answers TLS-ALPN-01 (RFC 8737) and
//! serves the real certificate otherwise, the `rustls` configuration (TLS 1.2 and 1.3 only),
//! and the listener that hands finished TLS connections to axum (plan-v3-team §3.9.3, §4.1).
//!
//! A TLS-ALPN-01 validation connection offers the protocol `acme-tls/1`. For it the resolver
//! returns a throwaway certificate with the `acmeIdentifier` extension for the order in flight;
//! the connection is closed after the handshake and never reaches HTTP. Every other connection
//! gets the current certificate. Before the first certificate exists, those handshakes fail.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use super::der::pem_blocks;
use crate::config::Domain;

/// The ALPN protocol of the validation connection.
pub const ACME_TLS_1: &[u8] = b"acme-tls/1";
/// `id-pe-acmeIdentifier` (RFC 8737 §6.1).
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];
/// A client that has not finished its handshake after this long is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Handshakes in flight at once; beyond it new connections are dropped, not queued.
const MAX_HANDSHAKES: usize = 512;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Turns a PEM chain and a PKCS#8 PEM key into a rustls key.
pub fn certified_key(chain_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>, String> {
    let chain: Vec<CertificateDer<'static>> = pem_blocks(chain_pem, "CERTIFICATE")
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    if chain.is_empty() {
        return Err("no certificate in the chain".into());
    }
    let key = pem_blocks(key_pem, "PRIVATE KEY")
        .into_iter()
        .next()
        .ok_or("no PKCS#8 private key")?;
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key));
    let signing = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("unusable private key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(chain, signing)))
}

/// The throwaway certificate for one TLS-ALPN-01 validation: a self-signed certificate for
/// `identifier` with the critical `acmeIdentifier` extension holding the SHA-256 of the key
/// authorization.
pub fn challenge_cert(
    identifier: &Domain,
    key_authorization_digest: &[u8],
) -> Result<Arc<CertifiedKey>, String> {
    if key_authorization_digest.len() != 32 {
        return Err("the key authorization digest must be 32 bytes".into());
    }
    let mut params = rcgen::CertificateParams::new(vec![identifier.name()])
        .map_err(|e| format!("challenge certificate: {e}"))?;
    // extnValue = DER OCTET STRING (SIZE (32)); rcgen adds the outer OCTET STRING.
    let mut content = vec![0x04, 0x20];
    content.extend_from_slice(key_authorization_digest);
    let mut ext = rcgen::CustomExtension::from_oid_content(ACME_IDENTIFIER_OID, content);
    ext.set_criticality(true);
    params.custom_extensions.push(ext);
    let key = rcgen::KeyPair::generate().map_err(|e| format!("challenge key: {e}"))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("challenge certificate: {e}"))?;
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let signing = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| format!("challenge key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(
        vec![cert.der().clone()],
        signing,
    )))
}

/// The certificate the server presents, plus the challenge certificates of orders in flight.
#[derive(Default)]
pub struct CertSlot {
    current: RwLock<Option<Arc<CertifiedKey>>>,
    challenges: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for CertSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertSlot")
            .field("has_certificate", &self.has_certificate())
            .finish()
    }
}

impl CertSlot {
    pub fn new() -> Arc<CertSlot> {
        Arc::new(CertSlot::default())
    }

    pub fn has_certificate(&self) -> bool {
        self.current.read().map(|c| c.is_some()).unwrap_or(false)
    }

    /// Installs the certificate new connections get.
    pub fn install(&self, key: Arc<CertifiedKey>) {
        if let Ok(mut c) = self.current.write() {
            *c = Some(key);
        }
    }

    /// Registers the TLS-ALPN-01 certificate for `name` while an order is in flight.
    pub fn set_challenge(&self, name: &str, key: Arc<CertifiedKey>) {
        if let Ok(mut c) = self.challenges.write() {
            c.insert(name.to_ascii_lowercase(), key);
        }
    }

    pub fn clear_challenge(&self, name: &str) {
        if let Ok(mut c) = self.challenges.write() {
            c.remove(&name.to_ascii_lowercase());
        }
    }

    /// The certificate a client with this SNI and these ALPN protocols gets. `sni` is absent
    /// for an IP identifier (RFC 8738 §6 sends the reverse-DNS name), so one registered
    /// challenge answers any name.
    pub fn pick(&self, sni: Option<&str>, acme_alpn: bool) -> Option<Arc<CertifiedKey>> {
        if acme_alpn {
            let c = self.challenges.read().ok()?;
            if let Some(k) = sni.and_then(|s| c.get(&s.to_ascii_lowercase())) {
                return Some(k.clone());
            }
            return if c.len() == 1 {
                c.values().next().cloned()
            } else {
                None
            };
        }
        self.current.read().ok()?.clone()
    }
}

impl ResolvesServerCert for CertSlot {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let acme = hello
            .alpn()
            .is_some_and(|mut it| it.any(|p| p == ACME_TLS_1));
        self.pick(hello.server_name(), acme)
    }
}

/// The rustls server configuration: TLS 1.2 and 1.3 only, no client certificates, ALPN
/// `http/1.1` and `acme-tls/1`.
pub fn server_config(slot: Arc<CertSlot>) -> Result<Arc<rustls::ServerConfig>, String> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| format!("tls versions: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(slot);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec(), ACME_TLS_1.to_vec()];
    Ok(Arc::new(cfg))
}

/// Accepts TCP connections on every bound socket, finishes their TLS handshakes in tasks of
/// their own (a slow client never blocks the next one), drops validation connections, and
/// yields the rest to axum.
pub struct TlsListener {
    rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl TlsListener {
    pub fn new(
        listeners: Vec<TcpListener>,
        config: Arc<rustls::ServerConfig>,
    ) -> io::Result<TlsListener> {
        let local = listeners
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no listener"))?
            .local_addr()?;
        let (tx, rx) = mpsc::channel(64);
        let acceptor = TlsAcceptor::from(config);
        let permits = Arc::new(Semaphore::new(MAX_HANDSHAKES));
        let mut tasks = Vec::new();
        for l in listeners {
            let (tx, acceptor, permits) = (tx.clone(), acceptor.clone(), permits.clone());
            tasks.push(tokio::spawn(async move {
                loop {
                    let (tcp, peer) = match l.accept().await {
                        Ok(c) => c,
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        continue; // too many handshakes in flight: drop the connection
                    };
                    let (tx, acceptor) = (tx.clone(), acceptor.clone());
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = tcp.set_nodelay(true);
                        let Ok(Ok(tls)) =
                            tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await
                        else {
                            return;
                        };
                        if tls.get_ref().1.alpn_protocol() == Some(ACME_TLS_1) {
                            return; // a validation connection: the handshake was the answer
                        }
                        let _ = tx.send((tls, peer)).await;
                    });
                }
            }));
        }
        Ok(TlsListener { rx, local, tasks })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(c) => c,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}
