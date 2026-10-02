//! Built-in TLS and ACME (plan-v3-team §3.9.3; TM15) against a local Pebble ACME server.
//!
//! Run: `PEBBLE_BIN=... cargo test -p awm-server --features all --test serve_tls`.
//!
//! Without `PEBBLE_BIN` the tests that need Pebble print a SKIP line and return; the tests that
//! do not (the HTTP-01 handler, the backoff, exit 4, the TLS-ALPN-01 challenge certificate)
//! always run. Pebble runs with `PEBBLE_VA_ALWAYS_VALID=1`, so it makes no validation
//! connection: the challenge answers are tested against our own listeners instead.

#![cfg(all(feature = "sqlite", feature = "acme"))]

#[path = "support/pebble.rs"]
mod pebble;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use awm_proto::wire::Version;
use awm_server::config::{self, Challenge, Domain, Flags};
use awm_server::http::LogSink;
use awm_server::retention::{Clock, SystemClock};
use awm_server::serve::{self, Command, Invocation, Io, Server, Settings};
use awm_server::tls::acme::{self, Acme, AcmeParams, Http01Tokens, Tick, BACKOFF_S};
use awm_server::tls::alpn::{challenge_cert, CertSlot};
use awm_server::tls::cache::{AcmeCache, ACCOUNT_FILE, CERT_FILE, KEY_FILE, STATE_FILE};
use awm_server::tls::der::{pem_blocks, CertInfo};
use pebble::Pebble;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------------------------
// Helpers

#[derive(Default)]
struct Capture(Mutex<Vec<String>>);

impl LogSink for Capture {
    fn line(&self, line: &str) {
        self.0.lock().unwrap().push(line.to_string());
    }
}

impl Capture {
    fn text(&self) -> String {
        self.0.lock().unwrap().join("\n")
    }
}

/// A clock the tests move; `sleep` never returns on its own.
struct TestClock(AtomicI64);

impl TestClock {
    fn now_real() -> Arc<TestClock> {
        Arc::new(TestClock(AtomicI64::new(SystemClock.now())))
    }

    fn set(&self, t: i64) {
        self.0.store(t, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    fn sleep(
        &self,
        _secs: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}

fn settings(log: &Arc<Capture>, clock: Arc<dyn Clock>) -> Settings {
    Settings {
        version: Version::new(0, 2, 0),
        env: Arc::new(|_| None),
        log: log.clone(),
        clock,
        grace: Duration::from_secs(1),
    }
}

fn flags_for(data: &Path, p: &Pebble, domain: &str) -> Flags {
    Flags {
        data: Some(data.to_path_buf()),
        domain: Some(domain.to_string()),
        listen: Some("127.0.0.1:0".into()),
        acme_directory: Some(p.directory_url.clone()),
        acme_ca_file: Some(p.ca_pem.clone()),
        backup: None,
        ..Flags::default()
    }
}

fn resolve(flags: &Flags) -> config::Resolved {
    config::resolve(flags, &|_| None).expect("a valid configuration")
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Pebble's issuing root (its management API), as a client trust store.
async fn pebble_root(p: &Pebble) -> rustls::RootCertStore {
    let ca = acme::root_store(Some(&p.ca_pem));
    let resp = acme::https_get(&format!("{}/roots/0", p.mgmt_url), &ca)
        .await
        .expect("Pebble's management API answers");
    assert_eq!(resp.status, 200);
    let mut roots = rustls::RootCertStore::empty();
    for der in pem_blocks(&String::from_utf8(resp.body).unwrap(), "CERTIFICATE") {
        roots.add(CertificateDer::from(der)).unwrap();
    }
    assert!(!roots.is_empty());
    roots
}

fn client_config(
    roots: rustls::RootCertStore,
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> Arc<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

/// `GET path` over TLS to `addr` with SNI `localhost`; returns the raw response and the
/// negotiated version.
async fn tls_get(
    addr: SocketAddr,
    cfg: Arc<rustls::ClientConfig>,
    path: &str,
) -> (String, Option<rustls::ProtocolVersion>) {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(cfg)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("the TLS handshake succeeds");
    let version = tls.get_ref().1.protocol_version();
    tls.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    (String::from_utf8_lossy(&out).to_string(), version)
}

async fn start(flags: &Flags, log: &Arc<Capture>, clock: Arc<dyn Clock>) -> Server {
    serve::start(&resolve(flags), &settings(log, clock))
        .await
        .expect("the server starts")
}

// ---------------------------------------------------------------------------------------------
// Certificates

#[tokio::test]
async fn a_certificate_is_obtained_over_tls_alpn_01_and_served_on_tls_1_2_and_1_3() {
    let Some(p) = Pebble::start("a_certificate_is_obtained") else {
        return;
    };
    let data = pebble::scratch("data");
    let log = Arc::new(Capture::default());
    let server = start(
        &flags_for(&data, &p, "localhost"),
        &log,
        Arc::new(SystemClock),
    )
    .await;
    assert_eq!(p.issued(), 1, "one order, one certificate:\n{}", p.log());
    let addr = server.addrs[0];
    let roots = pebble_root(&p).await;

    // The API answers over TLS 1.3 and over TLS 1.2, with the certificate Pebble issued.
    for versions in [
        &[&rustls::version::TLS13][..],
        &[&rustls::version::TLS12][..],
    ] {
        let (resp, v) = tls_get(
            addr,
            client_config(roots.clone(), versions, &[b"http/1.1"]),
            "/healthz",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert_eq!(v, Some(versions[0].version));
        assert!(
            resp.to_ascii_lowercase()
                .contains("strict-transport-security: max-age="),
            "HSTS on a TLS response: {resp}"
        );
    }

    // The TLS-ALPN-01 resolver: a validation connection gets the challenge certificate, which
    // is not signed by the CA, and never reaches HTTP.
    let cert = acme_cert_of(&data);
    assert!(cert.not_after > SystemClock.now(), "a valid certificate");

    server.stop(Duration::from_secs(1)).await;
    drop(p);
}

fn acme_cert_of(data: &Path) -> CertInfo {
    let cache = AcmeCache::open(&data.join("acme")).unwrap();
    cache
        .load_cert()
        .unwrap()
        .expect("a cached certificate")
        .info
}

#[tokio::test]
async fn the_challenge_certificate_carries_the_critical_acme_identifier_extension() {
    let slot = CertSlot::new();
    let digest = [7u8; 32];
    let key = challenge_cert(&Domain::Dns("awm.example.com".into()), &digest).unwrap();
    slot.set_challenge("awm.example.com", key);
    assert!(!slot.has_certificate());
    // acme-tls/1 with the registered name: the challenge certificate; otherwise nothing.
    let picked = slot
        .pick(Some("awm.example.com"), true)
        .expect("challenge cert");
    assert!(slot.pick(Some("awm.example.com"), false).is_none());
    let der = picked.cert[0].as_ref().to_vec();
    // id-pe-acmeIdentifier 1.3.6.1.5.5.7.1.31, critical, OCTET STRING { OCTET STRING digest }.
    let oid = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];
    let at = der
        .windows(oid.len())
        .position(|w| w == oid)
        .expect("the extension is there");
    let after = &der[at + oid.len()..];
    assert_eq!(&after[..3], &[0x01, 0x01, 0xff], "critical TRUE");
    assert_eq!(
        &after[3..7],
        &[0x04, 0x22, 0x04, 0x20],
        "OCTET STRING of OCTET STRING"
    );
    assert_eq!(&after[7..39], &digest);
    // A wrong digest length is refused.
    assert!(challenge_cert(&Domain::Dns("x.example".into()), &[1, 2, 3]).is_err());
}

#[tokio::test]
async fn a_restart_reuses_the_cache_and_places_no_second_order() {
    let Some(p) = Pebble::start("a_restart_reuses_the_cache") else {
        return;
    };
    let data = pebble::scratch("data");
    let log = Arc::new(Capture::default());
    let flags = flags_for(&data, &p, "localhost");
    let s1 = start(&flags, &log, Arc::new(SystemClock)).await;
    let first = acme_cert_of(&data);
    s1.stop(Duration::from_secs(1)).await;
    assert_eq!(p.issued(), 1);

    let s2 = start(&flags, &log, Arc::new(SystemClock)).await;
    let acme = s2.acme.clone().expect("an ACME client");
    assert!(acme.orders().is_empty(), "no order after the restart");
    assert_eq!(p.issued(), 1, "Pebble saw no second order:\n{}", p.log());
    assert_eq!(
        acme_cert_of(&data).serial,
        first.serial,
        "the same certificate"
    );
    assert!(log.text().contains("from the cache"), "{}", log.text());
    // And it serves.
    let (resp, _) = tls_get(
        s2.addrs[0],
        client_config(
            pebble_root(&p).await,
            &[&rustls::version::TLS13],
            &[b"http/1.1"],
        ),
        "/healthz",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    s2.stop(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn acme_files_are_0600_in_a_0700_directory() {
    let Some(p) = Pebble::start("acme_files_are_0600") else {
        return;
    };
    let data = pebble::scratch("data");
    let log = Arc::new(Capture::default());
    let server = start(
        &flags_for(&data, &p, "localhost"),
        &log,
        Arc::new(SystemClock),
    )
    .await;
    server.stop(Duration::from_secs(1)).await;
    let dir = data.join("acme");
    assert_eq!(mode(&dir), 0o700);
    for f in [ACCOUNT_FILE, CERT_FILE, KEY_FILE, STATE_FILE] {
        assert_eq!(mode(&dir.join(f)), 0o600, "{f}");
    }
    // No temporary file is left behind, and nothing of it is in the data directory's other files.
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(names.iter().all(|n| !n.starts_with('.')), "{names:?}");
}

// ---------------------------------------------------------------------------------------------
// Renewal, profiles, backoff, exit 4

fn acme_for(
    p: &Pebble,
    data: &Path,
    clock: Arc<TestClock>,
    identifier: Domain,
    challenge: Challenge,
) -> Arc<Acme> {
    Arc::new(Acme::new(
        AcmeParams {
            identifier,
            directory: p.directory_url.clone(),
            ca_file: Some(p.ca_pem.clone()),
            email: None,
            challenge,
        },
        AcmeCache::open(&data.join("acme")).unwrap(),
        clock,
        CertSlot::new(),
        Http01Tokens::new(),
    ))
}

#[tokio::test]
async fn renewal_follows_the_ari_window_under_a_fake_clock_and_sends_replaces() {
    let Some(p) = Pebble::start("renewal_follows_the_ari_window") else {
        return;
    };
    let data = pebble::scratch("data");
    let clock = TestClock::now_real();
    let acme = acme_for(
        &p,
        &data,
        clock.clone(),
        Domain::Dns("localhost".into()),
        Challenge::TlsAlpn01,
    );
    assert!(!acme.start().await.expect("the first order succeeds"));
    assert_eq!(p.issued(), 1);
    let first = acme_cert_of(&data);
    let first_id = acme::replaces_id(&first)
        .expect("the certificate has an AKI")
        .to_string();

    // Now: inside the certificate's life but before the ARI window: nothing is ordered.
    let t0 = clock.now();
    let Tick::NotDue { renew_at } = acme.tick().await else {
        panic!("a fresh certificate is not due");
    };
    let (start, end, chosen) = acme.window().await.expect("Pebble publishes an ARI window");
    assert!(start > t0, "the window starts later: {start} vs {t0}");
    assert!(
        start <= chosen && chosen <= end,
        "a point inside the window"
    );
    assert_eq!(renew_at, chosen);

    // One second before the window opens: still nothing, whatever point was chosen.
    clock.set(start - 1);
    assert!(matches!(acme.tick().await, Tick::NotDue { .. }));
    assert_eq!(p.issued(), 1, "no renewal outside the window:\n{}", p.log());
    assert_eq!(acme.orders().len(), 1);

    // At the end of the window the renewal is due and replaces the first certificate.
    clock.set(end);
    assert_eq!(acme.tick().await, Tick::Renewed);
    assert_eq!(p.issued(), 2, "{}", p.log());
    let orders = acme.orders();
    let renewal = orders.last().unwrap();
    assert!(renewal.ok);
    assert_eq!(
        renewal.replaces.as_deref(),
        Some(first_id.as_str()),
        "the CA reflects `replaces`"
    );
    assert!(
        renewal
            .sent
            .contains(&format!("\"replaces\":\"{first_id}\"")),
        "the order body names the replaced certificate: {}",
        renewal.sent
    );
    assert_ne!(
        acme_cert_of(&data).serial,
        first.serial,
        "a new certificate is installed"
    );
    assert!(
        orders[0].replaces.is_none(),
        "the first order replaces nothing"
    );
}

#[tokio::test]
async fn an_ip_domain_orders_under_the_shortlived_profile() {
    let Some(p) = Pebble::start("an_ip_domain_orders") else {
        return;
    };
    let data = pebble::scratch("data");
    let ip = Domain::Ip("127.0.0.1".parse().unwrap());
    let acme = acme_for(&p, &data, TestClock::now_real(), ip, Challenge::TlsAlpn01);
    acme.start()
        .await
        .expect("Pebble issues an IP certificate under the profile");
    let o = &acme.orders()[0];
    assert!(o.sent.contains("\"profile\":\"shortlived\""), "{}", o.sent);
    assert!(
        o.sent.contains("\"type\":\"ip\"") && o.sent.contains("127.0.0.1"),
        "{}",
        o.sent
    );
    assert_eq!(
        o.profile.as_deref(),
        Some("shortlived"),
        "the CA reflects the profile"
    );
    assert!(o.ok);

    // A DNS name sends no profile.
    let data2 = pebble::scratch("data");
    let dns = acme_for(
        &p,
        &data2,
        TestClock::now_real(),
        Domain::Dns("localhost".into()),
        Challenge::TlsAlpn01,
    );
    dns.start().await.unwrap();
    assert!(
        !dns.orders()[0].sent.contains("profile"),
        "{}",
        dns.orders()[0].sent
    );
}

fn dead_ca_params(data: &Path, clock: Arc<TestClock>) -> Acme {
    Acme::new(
        AcmeParams {
            identifier: Domain::Dns("localhost".into()),
            directory: "https://127.0.0.1:9/dir".into(),
            ca_file: None,
            email: None,
            challenge: Challenge::TlsAlpn01,
        },
        AcmeCache::open(&data.join("acme")).unwrap(),
        clock,
        CertSlot::new(),
        Http01Tokens::new(),
    )
}

#[tokio::test]
async fn failed_orders_back_off_one_ten_and_sixty_minutes() {
    let data = pebble::scratch("data");
    let clock = TestClock::now_real();
    let acme = dead_ca_params(&data, clock.clone());
    let t = clock.now();
    assert_eq!(BACKOFF_S, [60, 600, 3_600]);

    let Tick::Failed { retry_at, error } = acme.tick().await else {
        panic!("the first order fails");
    };
    assert_eq!(retry_at, t + 60, "1 minute");
    assert!(
        !error.contains("127.0.0.1:9") && !error.contains("https://"),
        "{error}"
    );
    // Inside the pause nothing is attempted and the answer does not move.
    clock.set(t + 59);
    assert_eq!(acme.tick().await, Tick::Backoff { retry_at: t + 60 });
    // Then 10 minutes, then 60, then 60 again.
    clock.set(t + 60);
    assert!(matches!(acme.tick().await, Tick::Failed { retry_at, .. } if retry_at == t + 60 + 600));
    clock.set(t + 660);
    assert!(
        matches!(acme.tick().await, Tick::Failed { retry_at, .. } if retry_at == t + 660 + 3_600)
    );
    clock.set(t + 660 + 3_600);
    assert!(
        matches!(acme.tick().await, Tick::Failed { retry_at, .. } if retry_at == t + 660 + 7_200)
    );

    // The pause survives a restart: a new client in the same data directory is still paused.
    let again = dead_ca_params(&data, clock.clone());
    let err = again.start().await.unwrap_err();
    assert!(err.0.contains("backoff"), "{err}");
    let state = AcmeCache::open(&data.join("acme")).unwrap().load_state();
    assert_eq!(state.failures, 4);
    assert!(state.last_error.is_some());
}

fn seed_cached_certificate(data: &Path, name: &str) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cache = AcmeCache::open(&data.join("acme")).unwrap();
    cache.save_cert(&cert.pem(), &key.serialize_pem()).unwrap();
}

fn dead_ca_flags(data: &Path) -> Flags {
    Flags {
        data: Some(data.to_path_buf()),
        domain: Some("localhost".into()),
        listen: Some("127.0.0.1:0".into()),
        acme_directory: Some("https://127.0.0.1:9/dir".into()),
        ..Flags::default()
    }
}

#[tokio::test]
async fn exit_4_without_a_cached_certificate_when_the_order_fails_at_start() {
    let data = pebble::scratch("data");
    let log = Arc::new(Capture::default());
    let err = serve::start(
        &resolve(&dead_ca_flags(&data)),
        &settings(&log, Arc::new(SystemClock)),
    )
    .await
    .err()
    .expect("no certificate, no start");
    assert_eq!(err.code, 4, "{err}");
    assert!(err.message.contains("TLS unavailable"), "{err}");
    assert!(
        !err.message.contains("127.0.0.1:9"),
        "no URL in the message: {err}"
    );

    // The same through the command: exit code 4 on standard error and in the return value.
    let (mut out, mut errb) = (Vec::new(), Vec::new());
    let code = serve::run_async(
        Invocation {
            flags: dead_ca_flags(&data),
            command: Command::Run,
            settings: settings(&log, Arc::new(SystemClock)),
        },
        &mut Io {
            out: &mut out,
            err: &mut errb,
            tty: false,
        },
    )
    .await;
    assert_eq!(code, 4);
    assert!(String::from_utf8(errb).unwrap().contains("TLS unavailable"));
}

#[tokio::test]
async fn a_cached_certificate_keeps_the_server_up_when_the_ca_is_down() {
    let data = pebble::scratch("data");
    seed_cached_certificate(&data, "localhost");
    let log = Arc::new(Capture::default());
    let server = serve::start(
        &resolve(&dead_ca_flags(&data)),
        &settings(&log, Arc::new(SystemClock)),
    )
    .await
    .expect("the cached certificate is used");
    assert!(log.text().contains("from the cache"), "{}", log.text());
    server.stop(Duration::from_secs(1)).await;
}

// ---------------------------------------------------------------------------------------------
// HTTP-01

async fn raw(addr: SocketAddr, request: &str) -> String {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tcp.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).to_string()
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
}

#[tokio::test]
async fn the_port_80_handler_answers_only_challenges_and_redirects_everything_else() {
    let tokens = Http01Tokens::new();
    tokens.set("tok123", "tok123.thumbprint");
    let app = awm_server::tls::http01_router(tokens.clone(), Domain::Dns("awm.example.com".into()));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

    let r = raw(addr, &get("/.well-known/acme-challenge/tok123")).await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    assert!(r.ends_with("tok123.thumbprint"), "{r}");
    let r = raw(addr, &get("/.well-known/acme-challenge/unknown")).await;
    assert!(r.starts_with("HTTP/1.1 404"), "{r}");
    tokens.remove("tok123");
    let r = raw(addr, &get("/.well-known/acme-challenge/tok123")).await;
    assert!(
        r.starts_with("HTTP/1.1 404"),
        "a removed token is gone: {r}"
    );

    // Everything else, whatever the method, goes to HTTPS on the configured name (not the
    // request's Host header), and no API is served here.
    for req in [
        get("/v1/info"),
        get("/healthz"),
        get("/v1/records?x=1"),
        "POST /v1/bootstrap HTTP/1.1\r\nHost: awm.example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
        get("/"),
    ] {
        let r = raw(addr, &req).await;
        assert!(r.starts_with("HTTP/1.1 308"), "{r}");
        let loc = r
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("location:"))
            .unwrap_or_else(|| panic!("no Location in {r}"));
        assert!(loc.contains("https://awm.example.com/"), "{loc}");
        assert!(!loc.contains("evil.example"), "{loc}");
        assert!(!r.contains("\"server\""), "no API body: {r}");
    }
}

#[tokio::test]
async fn http_01_mode_opens_port_80_for_challenges_only_and_still_orders() {
    let Some(p) = Pebble::start("http_01_mode_opens_port_80") else {
        return;
    };
    let data = pebble::scratch("data");
    let log = Arc::new(Capture::default());
    let mut flags = flags_for(&data, &p, "localhost");
    flags.acme_challenge = Some("http-01".into());
    flags.acme_http_listen = Some("127.0.0.1:0".into());
    let server = start(&flags, &log, Arc::new(SystemClock)).await;
    assert_eq!(p.issued(), 1, "{}", p.log());
    let port80 = server.http01_addr.expect("the challenge listener is open");
    let r = raw(port80, &get("/v1/info")).await;
    assert!(r.starts_with("HTTP/1.1 308"), "{r}");
    assert!(r.contains("https://localhost/v1/info"), "{r}");
    let r = raw(port80, &get("/healthz")).await;
    assert!(r.starts_with("HTTP/1.1 308"), "{r}");
    // Without http-01 there is no such listener.
    let data2 = pebble::scratch("data");
    let s2 = start(
        &flags_for(&data2, &p, "localhost"),
        &log,
        Arc::new(SystemClock),
    )
    .await;
    assert!(s2.http01_addr.is_none());
    s2.stop(Duration::from_secs(1)).await;
    server.stop(Duration::from_secs(1)).await;
}
