//! The TLS side of the server: the certificate resolver that answers TLS-ALPN-01 (RFC 8737) and
//! serves the real certificate otherwise, the `rustls` configuration (TLS 1.2 and 1.3 only),
//! and the listener that hands finished TLS connections to axum (plan-v3-team §3.9.3, §4.1).
//!
//! A TLS-ALPN-01 validation connection offers the protocol `acme-tls/1`. For it the resolver
//! returns a throwaway certificate with the `acmeIdentifier` extension for the order in flight;
//! the connection is closed after the handshake and never reaches HTTP. Every other connection
//! gets the current certificate. Before the first certificate exists, those handshakes fail.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
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
/// Handshakes in flight from one address (an IPv6 address by its /64), so one client cannot
/// take the global ones (RVT2 m9).
pub const MAX_HANDSHAKES_PER_ADDR: usize = 16;
/// Open connections from one address, handshake included.
pub const MAX_CONNECTIONS_PER_ADDR: usize = 128;
/// A connection on which nothing arrives for this long is closed: a client that sends its
/// request head slowly, or not at all, holds a connection for at most this long between bytes
/// (RVT2 m9; axum sets no hyper timer, so hyper's `header_read_timeout` is not available
/// without a new dependency). Longer than the handler timeout, so no response is cut.
pub const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Counts of handshakes and connections per client address.
#[derive(Debug, Default)]
pub struct AddrSlots {
    counts: std::sync::Mutex<HashMap<IpAddr, (usize, usize)>>,
}

/// One connection's place in [`AddrSlots`]; dropping it frees the place.
#[derive(Debug)]
pub struct AddrSlot {
    slots: Arc<AddrSlots>,
    key: IpAddr,
    handshaking: bool,
}

impl AddrSlots {
    /// A place for a new connection from `ip`, `None` when the address has
    /// [`MAX_HANDSHAKES_PER_ADDR`] handshakes or [`MAX_CONNECTIONS_PER_ADDR`] connections open.
    pub fn try_take(self: &Arc<Self>, ip: IpAddr) -> Option<AddrSlot> {
        let key = crate::limits::bucket_addr(ip);
        let mut m = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        let e = m.entry(key).or_insert((0, 0));
        if e.0 >= MAX_HANDSHAKES_PER_ADDR || e.1 >= MAX_CONNECTIONS_PER_ADDR {
            return None;
        }
        *e = (e.0 + 1, e.1 + 1);
        Some(AddrSlot {
            slots: Arc::clone(self),
            key,
            handshaking: true,
        })
    }

    /// (handshakes, connections) open from `ip`.
    pub fn open(&self, ip: IpAddr) -> (usize, usize) {
        let m = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        m.get(&crate::limits::bucket_addr(ip))
            .copied()
            .unwrap_or((0, 0))
    }
}

impl AddrSlot {
    /// The handshake finished: the connection no longer counts against the handshake cap.
    pub fn handshake_done(&mut self) {
        if std::mem::take(&mut self.handshaking) {
            let mut m = self.slots.counts.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(e) = m.get_mut(&self.key) {
                e.0 = e.0.saturating_sub(1);
            }
        }
    }
}

impl Drop for AddrSlot {
    fn drop(&mut self) {
        let mut m = self.slots.counts.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(e) = m.get_mut(&self.key) {
            if self.handshaking {
                e.0 = e.0.saturating_sub(1);
            }
            e.1 = e.1.saturating_sub(1);
            if *e == (0, 0) {
                m.remove(&self.key);
            }
        }
    }
}

/// A connection that holds its [`AddrSlot`] and fails a read that waits longer than its idle
/// timeout ([`READ_IDLE_TIMEOUT`]); hyper then closes it.
pub struct Guarded<T> {
    inner: T,
    _slot: Option<AddrSlot>,
    idle: Duration,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<T> Guarded<T> {
    pub fn new(inner: T, slot: Option<AddrSlot>, idle: Duration) -> Guarded<T> {
        Guarded {
            inner,
            _slot: slot,
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
        }
    }

    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    fn touch(&mut self) {
        let at = tokio::time::Instant::now() + self.idle;
        self.deadline.as_mut().reset(at);
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Guarded<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(r) => {
                if buf.filled().len() > before {
                    self.touch();
                }
                Poll::Ready(r)
            }
            Poll::Pending => match self.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no data from the client within the idle timeout",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Guarded<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(r, Poll::Ready(Ok(n)) if n > 0) {
            // A response is going out: the client's silence until it is read is not idleness.
            self.touch();
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

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
    rx: mpsc::Receiver<(Guarded<TlsStream<TcpStream>>, SocketAddr)>,
    local: SocketAddr,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    slots: Arc<AddrSlots>,
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
        let slots = Arc::new(AddrSlots::default());
        let mut tasks = Vec::new();
        for l in listeners {
            let (tx, acceptor, permits, slots) =
                (tx.clone(), acceptor.clone(), permits.clone(), slots.clone());
            tasks.push(tokio::spawn(async move {
                loop {
                    let (tcp, peer) = match l.accept().await {
                        Ok(c) => c,
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    // The address's caps first, then the global one; beyond either the
                    // connection is dropped, not queued.
                    let Some(mut slot) = slots.try_take(peer.ip()) else {
                        continue;
                    };
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        continue; // too many handshakes in flight: drop the connection
                    };
                    let (tx, acceptor) = (tx.clone(), acceptor.clone());
                    tokio::spawn(async move {
                        let permit = permit;
                        let _ = tcp.set_nodelay(true);
                        let Ok(Ok(tls)) =
                            tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await
                        else {
                            return;
                        };
                        drop(permit);
                        slot.handshake_done();
                        if tls.get_ref().1.alpn_protocol() == Some(ACME_TLS_1) {
                            return; // a validation connection: the handshake was the answer
                        }
                        let io = Guarded::new(tls, Some(slot), READ_IDLE_TIMEOUT);
                        let _ = tx.send((io, peer)).await;
                    });
                }
            }));
        }
        Ok(TlsListener {
            rx,
            local,
            tasks,
            slots,
        })
    }

    /// (handshakes, connections) open from `ip` (tests).
    pub fn open_from(&self, ip: IpAddr) -> (usize, usize) {
        self.slots.open(ip)
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
    type Io = Guarded<TlsStream<TcpStream>>;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_address_gets_at_most_16_handshakes_and_128_connections() {
        let slots = Arc::new(AddrSlots::default());
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let same_64: IpAddr = "2001:db8::ffff".parse().unwrap();
        let other: IpAddr = "192.0.2.9".parse().unwrap();
        let mut held: Vec<AddrSlot> = (0..MAX_HANDSHAKES_PER_ADDR)
            .map(|i| {
                let ip = if i % 2 == 0 { a } else { same_64 };
                slots.try_take(ip).unwrap()
            })
            .collect();
        // The /64 shares one cap; another address has its own.
        assert!(slots.try_take(same_64).is_none());
        assert!(slots.try_take(other).is_some());
        assert_eq!(
            slots.open(a),
            (MAX_HANDSHAKES_PER_ADDR, MAX_HANDSHAKES_PER_ADDR)
        );
        // Finished handshakes free the handshake cap but stay connections.
        for s in &mut held {
            s.handshake_done();
        }
        while held.len() < MAX_CONNECTIONS_PER_ADDR {
            let mut s = slots.try_take(a).unwrap();
            s.handshake_done();
            held.push(s);
        }
        assert!(slots.try_take(a).is_none());
        held.pop();
        assert!(slots.try_take(a).is_some());
        drop(held);
        assert_eq!(slots.open(a), (0, 0));
    }

    #[tokio::test]
    async fn a_connection_silent_past_its_idle_timeout_fails_its_read() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, server) = tokio::io::duplex(64);
        let mut g = Guarded::new(server, None, Duration::from_millis(150));
        let mut client = client;
        client.write_all(b"GET").await.unwrap();
        let mut buf = [0u8; 3];
        g.read_exact(&mut buf).await.unwrap();
        // Bytes within the timeout keep it open...
        tokio::time::sleep(Duration::from_millis(100)).await;
        client.write_all(b"x").await.unwrap();
        let mut one = [0u8; 1];
        g.read_exact(&mut one).await.unwrap();
        // ...silence beyond it ends it.
        let started = std::time::Instant::now();
        let e = g.read(&mut one).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(100));
        drop(client);
    }
}
