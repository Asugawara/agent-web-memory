//! `awm serve`: the flags and `server.toml`, the refusals of §4.8.1 (exit 2), `init`, the
//! bootstrap hash of path A, the trusted proxies, the wiring of retention, backup and the
//! signal, and the commands `backup`, `restore`, `promote`, `healthcheck` (plan-v3-team §3.9.2,
//! §4.7, §4.8.1, §4.10; TM15).
//!
//! Run: `cargo test -p awm-server --features sqlite --test serve_config`. Servers run in this
//! process on loopback port 0; requests to the API go through the router with a peer address;
//! the Postgres case runs when `AWM_TEST_PG_URL` is set (it prints a SKIP otherwise).

#![cfg(feature = "sqlite")]

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use awm_proto::wire::{BootstrapToken, Id, Version, B64};
use awm_server::config::{self, Flags, Resolved, Secret, StoreChoice};
use awm_server::http::{self, LogSink, RetentionMode};
use awm_server::retention::{Clock, SystemClock};
use awm_server::serve::{self, Command, Invocation, Io, Server, Settings};
use awm_server::store::Store;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use axum::Router;
use serde_json::{json, Value};
use tower::ServiceExt;

// ---------------------------------------------------------------------------------------------
// Helpers

const CLIENT: &str = "awm/0.2.0 proto/1 redact/3";
const T0: i64 = 1_790_000_000 - 1_790_000_000 % 86_400 + 43_200;

fn scratch(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "cfg-{tag}-{}-{nanos}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn write_private(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    chmod(path, 0o600);
}

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
    fn at(t: i64) -> Arc<TestClock> {
        Arc::new(TestClock(AtomicI64::new(t)))
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

fn settings_with(
    log: &Arc<Capture>,
    clock: Arc<dyn Clock>,
    env: &'static [(&'static str, &'static str)],
) -> Settings {
    Settings {
        version: Version::new(0, 2, 0),
        env: Arc::new(move |k| {
            env.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_string())
        }),
        log: log.clone(),
        clock,
        grace: Duration::from_secs(1),
    }
}

fn settings(log: &Arc<Capture>) -> Settings {
    settings_with(log, Arc::new(SystemClock), &[])
}

fn data_flags(data: &Path) -> Flags {
    Flags {
        data: Some(data.to_path_buf()),
        listen: Some("127.0.0.1:0".into()),
        ..Flags::default()
    }
}

fn resolve_with(
    flags: &Flags,
    env: &'static [(&'static str, &'static str)],
) -> Result<Resolved, config::ConfigError> {
    config::resolve(flags, &move |k| {
        env.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| (*v).to_string())
    })
}

fn resolve(flags: &Flags) -> Result<Resolved, config::ConfigError> {
    resolve_with(flags, &[])
}

fn refused(flags: &Flags) -> String {
    let e = resolve(flags).expect_err("the configuration must be refused");
    assert_eq!(e.code, 2, "{e}");
    e.message
}

async fn cmd(flags: Flags, command: Command, s: Settings, tty: bool) -> (i32, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = serve::run_async(
        Invocation {
            flags,
            command,
            settings: s,
        },
        &mut Io {
            out: &mut out,
            err: &mut err,
            tty,
        },
    )
    .await;
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn b64(bytes: &[u8]) -> String {
    String::from(B64(bytes.to_vec()))
}

struct Resp {
    status: u16,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

async fn send(
    router: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
    peer: &str,
    headers: &[(&str, &str)],
) -> Resp {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("awm-client", CLIENT);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let body = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };
    let mut req = b.body(body).unwrap();
    let ip: IpAddr = peer.parse().unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip, 40_000)));
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Resp {
        status,
        headers,
        body,
    }
}

/// `POST /v1/bootstrap` with `token`; the response (200 holds the device token).
async fn bootstrap(router: &Router, token: &str, handle: &str) -> Resp {
    send(
        router,
        "POST",
        "/v1/bootstrap",
        None,
        Some(json!({
            "bootstrap_token": token,
            "org_id": Id::new_v4().to_string(),
            "handle": handle,
            "device_id": Id::new_v4().to_string(),
            "device_pubkey": b64(&[1u8; 32]),
        })),
        "203.0.113.5",
        &[],
    )
    .await
}

async fn running(flags: &Flags, log: &Arc<Capture>) -> Server {
    let r = resolve(flags).expect("a valid configuration");
    serve::start(&r, &settings(log))
        .await
        .expect("the server starts")
}

// ---------------------------------------------------------------------------------------------
// Listener and refusals

#[test]
fn the_defaults_listen_on_loopback_only() {
    let r = resolve(&Flags {
        data: Some("/var/lib/awm".into()),
        ..Flags::default()
    })
    .unwrap();
    assert_eq!(
        r.listen,
        vec!["127.0.0.1:8787".parse::<SocketAddr>().unwrap()]
    );
    assert!(r.domain.is_none() && !r.behind_tls_proxy && r.http01_listen.is_none());
    let c = r.server_config(Version::new(0, 2, 0), Version::new(0, 2, 0));
    assert!(!c.hsts, "no TLS, no HSTS");
    assert_eq!(
        c.retention,
        RetentionMode::Off,
        "a host runs retention hourly itself"
    );
    assert!(!c.forwarded_last_entry && c.trusted_proxies.is_empty());
    assert_eq!(
        c.org_defaults.min_client,
        Version::new(0, 2, 0),
        "the release floor"
    );
}

#[test]
fn a_domain_listens_on_443_over_ipv4_and_ipv6_with_tls_and_hsts() {
    let r = resolve(&Flags {
        data: Some("/var/lib/awm".into()),
        domain: Some("Awm.Example.COM".into()),
        ..Flags::default()
    })
    .unwrap();
    assert_eq!(
        r.listen,
        vec![
            "0.0.0.0:443".parse::<SocketAddr>().unwrap(),
            "[::]:443".parse::<SocketAddr>().unwrap()
        ]
    );
    assert_eq!(
        r.domain,
        Some(config::Domain::Dns("awm.example.com".into()))
    );
    let c = r.server_config(Version::new(0, 2, 0), Version::new(0, 2, 0));
    assert!(c.hsts, "HSTS when this binary terminates TLS");
    assert_eq!(r.acme.as_ref().unwrap().directory, config::LETS_ENCRYPT);
    assert_eq!(
        r.acme.as_ref().unwrap().challenge,
        config::Challenge::TlsAlpn01
    );
    assert!(r.http01_listen.is_none(), "port 80 is closed by default");

    // An IP literal selects an IP-address certificate; staging and http-01 are opt-in.
    let r = resolve(&Flags {
        data: Some("/var/lib/awm".into()),
        domain: Some("203.0.113.7".into()),
        acme_staging: true,
        acme_challenge: Some("http-01".into()),
        ..Flags::default()
    })
    .unwrap();
    assert!(r.domain.as_ref().unwrap().is_ip());
    assert_eq!(
        r.acme.as_ref().unwrap().directory,
        config::LETS_ENCRYPT_STAGING
    );
    assert_eq!(r.http01_listen, Some("0.0.0.0:80".parse().unwrap()));
}

#[test]
fn behind_a_tls_proxy_the_server_listens_on_port_and_trusts_the_named_proxies() {
    let flags = Flags {
        database_url_env: Some("DB".into()),
        behind_tls_proxy: true,
        trusted_proxies: vec!["cloud-run".into()],
        ..Flags::default()
    };
    // `cloud-run` is refused off Cloud Run, where anyone can write the last X-Forwarded-For entry
    // (RVT2 m4).
    for env in [
        &[("PORT", "8080"), ("DB", "postgres://u@h/d")][..],
        &[
            ("PORT", "8080"),
            ("DB", "postgres://u@h/d"),
            ("K_SERVICE", ""),
        ][..],
    ] {
        let e = resolve_with(&flags, env).unwrap_err();
        assert_eq!(e.code, 2, "{e}");
        assert!(e.message.contains("K_SERVICE"), "{e}");
    }
    let r = resolve_with(
        &flags,
        &[
            ("PORT", "8080"),
            ("DB", "postgres://u@h/d"),
            ("K_SERVICE", "awm"),
        ],
    )
    .unwrap();
    assert_eq!(
        r.listen,
        vec!["0.0.0.0:8080".parse::<SocketAddr>().unwrap()]
    );
    assert!(r.cloud_run && r.request_time_retention);
    let c = r.server_config(Version::new(0, 2, 0), Version::new(0, 2, 0));
    assert!(c.forwarded_last_entry);
    assert_eq!(c.retention, RetentionMode::InRequests);
    // The proxy terminates TLS but the client still reached the server over https, so the header
    // is sent (RVT2 m10).
    assert!(c.hsts);

    // CIDR ranges, repeatable; no PORT keeps the loopback default.
    let r = resolve(&Flags {
        data: Some("/d".into()),
        behind_tls_proxy: true,
        trusted_proxies: vec!["10.0.0.0/8".into(), "192.0.2.1".into()],
        ..Flags::default()
    })
    .unwrap();
    assert_eq!(r.trusted_proxies.len(), 2);
    assert!(!r.cloud_run && !r.request_time_retention);
    assert_eq!(
        r.listen,
        vec!["127.0.0.1:8787".parse::<SocketAddr>().unwrap()]
    );

    // `PORT` with `--behind-tls-proxy` moves retention into requests, as on Cloud Run.
    let proxied = Flags {
        data: Some("/d".into()),
        behind_tls_proxy: true,
        trusted_proxies: vec!["10.0.0.0/8".into()],
        ..Flags::default()
    };
    let r = resolve_with(&proxied, &[("PORT", "9")]).unwrap();
    assert!(r.request_time_retention);
    // A stray `PORT` on a host keeps the hourly task and the local sweep (plan §4.8.1).
    let r = resolve_with(&data_flags(Path::new("/d")), &[("PORT", "9")]).unwrap();
    assert!(!r.request_time_retention);
}

#[test]
fn every_refusal_of_4_8_1_is_exit_2() {
    let data = Path::new("/var/lib/awm");
    let base = || Flags {
        data: Some(data.to_path_buf()),
        ..Flags::default()
    };

    // A public listener without TLS.
    for l in ["0.0.0.0:8787", "[::]:8787", "192.0.2.1:80", "10.1.2.3:8787"] {
        let m = refused(&Flags {
            listen: Some(l.into()),
            ..base()
        });
        assert!(m.contains("non-loopback") && m.contains("--domain"), "{m}");
    }
    for l in ["127.0.0.1:1", "[::1]:8787", "127.9.9.9:80"] {
        resolve(&Flags {
            listen: Some(l.into()),
            ..base()
        })
        .unwrap_or_else(|e| panic!("{l} is loopback: {e}"));
    }
    // ...but a public listener is fine with TLS or a proxy in front.
    resolve(&Flags {
        listen: Some("0.0.0.0:8443".into()),
        domain: Some("awm.example.com".into()),
        ..base()
    })
    .unwrap();
    resolve(&Flags {
        listen: Some("0.0.0.0:8080".into()),
        behind_tls_proxy: true,
        trusted_proxies: vec!["10.0.0.0/8".into()],
        ..base()
    })
    .unwrap();

    // --domain with --behind-tls-proxy.
    let m = refused(&Flags {
        domain: Some("awm.example.com".into()),
        behind_tls_proxy: true,
        trusted_proxies: vec!["cloud-run".into()],
        ..base()
    });
    assert!(m.contains("exclusive"), "{m}");
    // --behind-tls-proxy without a trusted proxy.
    let m = refused(&Flags {
        behind_tls_proxy: true,
        ..base()
    });
    assert!(m.contains("--trusted-proxy"), "{m}");
    // A malformed proxy range.
    refused(&Flags {
        behind_tls_proxy: true,
        trusted_proxies: vec!["10.0.0.0/99".into()],
        ..base()
    });

    // --data with --database-url, and with --database-url-env; neither.
    let m = refused(&Flags {
        database_url: Some(Secret::new("postgres://awm_app:hunter2@h/db")),
        ..base()
    });
    assert!(m.contains("--data") && !m.contains("hunter2"), "{m}");
    refused(&Flags {
        database_url_env: Some("DB".into()),
        ..base()
    });
    let m = refused(&Flags::default());
    assert!(m.contains("no store"), "{m}");
    // The environment variable a flag names must exist.
    let m = refused(&Flags {
        database_url_env: Some("MISSING_DB".into()),
        ..Flags::default()
    });
    assert!(m.contains("MISSING_DB"), "{m}");

    // sslip.io-style hosts and malformed names.
    for d in [
        "203-0-113-7.sslip.io",
        "awm.nip.io",
        "sslip.io",
        "10.0.0.1.xip.io",
        "a.traefik.me",
        "https://awm.example.com",
        "awm.example.com:443",
        "awm example",
        "-bad.example.com",
        "0.0.0.0",
    ] {
        let m = refused(&Flags {
            domain: Some(d.into()),
            ..base()
        });
        if d.ends_with("sslip.io")
            || d.ends_with("nip.io")
            || d.ends_with("xip.io")
            || d.ends_with("traefik.me")
        {
            assert!(m.contains("Public Suffix List"), "{d}: {m}");
        }
    }
    // The ACME cache lives in --data.
    refused(&Flags {
        database_url_env: Some("DB".into()),
        domain: Some("awm.example.com".into()),
        ..Flags::default()
    });
    // --acme-* without --domain; an unknown challenge; staging with a directory; a plain URL.
    refused(&Flags {
        acme_email: Some("a@example.com".into()),
        ..base()
    });
    refused(&Flags {
        domain: Some("awm.example.com".into()),
        acme_challenge: Some("dns-01".into()),
        ..base()
    });
    refused(&Flags {
        domain: Some("awm.example.com".into()),
        acme_staging: true,
        acme_directory: Some("https://x.example/dir".into()),
        ..base()
    });
    refused(&Flags {
        domain: Some("awm.example.com".into()),
        acme_directory: Some("http://x.example/dir".into()),
        ..base()
    });
    // A backup URL that is not gs://, s3:// or file:///.
    for u in [
        "ftp://x/y",
        "gs://b/p?token=hunter2",
        "file://relative/path",
        "nope",
    ] {
        let m = refused(&Flags {
            backup: Some(u.into()),
            ..base()
        });
        assert!(!m.contains("hunter2"), "{m}");
    }
    // A retention period below the 30-day floor, in server.toml.
    let dir = scratch("retention-floor");
    let file = dir.join("server.toml");
    for days in ["0", "7", "29"] {
        write_private(&file, &format!("retention_days = {days}\n"));
        let m = refused(&Flags {
            config: Some(file.clone()),
            ..base()
        });
        assert!(
            m.contains("server.toml `retention_days` must be at least 30"),
            "{days}: {m}"
        );
    }
    write_private(&file, "retention_days = 30\n");
    resolve(&Flags {
        config: Some(file),
        ..base()
    })
    .unwrap();
    // A listen address that is a host name.
    refused(&Flags {
        listen: Some("localhost:8787".into()),
        ..base()
    });
}

#[test]
fn a_group_or_world_readable_server_toml_is_refused() {
    let dir = scratch("toml-mode");
    let file = dir.join("server.toml");
    write_private(&file, "retention_days = 30\n");
    let flags = Flags {
        data: Some(dir.clone()),
        ..Flags::default()
    };
    assert_eq!(resolve(&flags).unwrap().overrides.retention_days, Some(30));
    for bad in [0o644, 0o640, 0o604, 0o660] {
        chmod(&file, bad);
        let m = refused(&flags);
        assert!(
            m.contains("server.toml") && m.contains("readable"),
            "{bad:o}: {m}"
        );
        // An explicit --config is judged the same way.
        refused(&Flags {
            config: Some(file.clone()),
            data: Some(dir.clone()),
            ..Flags::default()
        });
    }
    chmod(&file, 0o400);
    resolve(&flags).expect("a stricter mode is fine");
    // A missing --config file is a refusal, not a silent default.
    let m = refused(&Flags {
        config: Some(dir.join("nope.toml")),
        data: Some(dir),
        ..Flags::default()
    });
    assert!(m.contains("cannot read"), "{m}");
}

#[tokio::test]
async fn a_readable_acme_key_stops_the_start() {
    let dir = scratch("acme-mode");
    let acme = dir.join("acme");
    std::fs::create_dir_all(&acme).unwrap();
    chmod(&acme, 0o700);
    for f in ["key.pem", "account.json", "cert.pem"] {
        write_private(&acme.join(f), "x");
    }
    let flags = Flags {
        data: Some(dir.clone()),
        listen: Some("127.0.0.1:0".into()),
        ..Flags::default()
    };
    let r = resolve(&flags).unwrap();
    config::verify_files(&r).expect("0600 files in a 0700 directory pass");
    for (file, bad) in [
        ("key.pem", 0o644),
        ("account.json", 0o640),
        ("cert.pem", 0o604),
    ] {
        chmod(&acme.join(file), bad);
        let e = config::verify_files(&r).expect_err("a readable ACME file is refused");
        assert_eq!(e.code, 2);
        assert!(
            e.message.contains("ACME") && e.message.contains("readable"),
            "{e}"
        );
        // The server does not start either.
        let log = Arc::new(Capture::default());
        let err = serve::start(&r, &settings(&log))
            .await
            .err()
            .expect("refused");
        assert_eq!(err.code, 2, "{err}");
        chmod(&acme.join(file), 0o600);
    }
    chmod(&acme, 0o755);
    assert_eq!(
        config::verify_files(&r).unwrap_err().code,
        2,
        "the directory too"
    );
}

// ---------------------------------------------------------------------------------------------
// server.toml

#[test]
fn server_toml_has_a_key_for_every_flag_and_flags_override_it() {
    let dir = scratch("toml-keys");
    let file = dir.join("custom.toml");
    write_private(
        &file,
        "domain = \"file.example.com\"\n\
         data = \"/from/file\"\n\
         backup = \"file:///from/file\"\n\
         listen = \"127.0.0.1:1111\"\n\
         behind_tls_proxy = false\n\
         trusted_proxies = [\"10.0.0.0/8\", \"cloud-run\"]\n\
         acme_email = \"file@example.com\"\n\
         acme_challenge = \"http-01\"\n\
         acme_directory = \"https://file.example/dir\"\n\
         acme_ca_file = \"/from/file/ca.pem\"\n\
         acme_http_listen = \"127.0.0.1:2222\"\n\
         retention_days = 30\n\
         min_client = \"0.2.1\"\n\
         max_members = 5\n\
         internal_token_sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n\
         requests_per_minute = 11\n\
         request_burst = 12\n\
         anonymous_per_minute = 13\n\
         joins_per_hour = 3\n\
         records_per_day = 99\n\
         request_timeout_s = 7\n",
    );
    // `cloud-run` needs K_SERVICE (RVT2 m4).
    let from_file = resolve_with(
        &Flags {
            config: Some(file.clone()),
            ..Flags::default()
        },
        &[("K_SERVICE", "awm")],
    )
    .unwrap();
    assert_eq!(
        from_file.store,
        StoreChoice::Sqlite {
            data: "/from/file".into()
        }
    );
    assert_eq!(
        from_file.domain,
        Some(config::Domain::Dns("file.example.com".into()))
    );
    assert_eq!(from_file.backup.as_deref(), Some("file:///from/file"));
    assert_eq!(
        from_file.listen,
        vec!["127.0.0.1:1111".parse::<SocketAddr>().unwrap()]
    );
    assert_eq!(from_file.trusted_proxies.len(), 1);
    assert!(from_file.cloud_run);
    let acme = from_file.acme.as_ref().unwrap();
    assert_eq!(acme.email.as_deref(), Some("file@example.com"));
    assert_eq!(acme.challenge, config::Challenge::Http01);
    assert_eq!(acme.directory, "https://file.example/dir");
    assert_eq!(acme.ca_file, Some(PathBuf::from("/from/file/ca.pem")));
    assert_eq!(
        from_file.http01_listen,
        Some("127.0.0.1:2222".parse().unwrap())
    );
    assert_eq!(from_file.config_file, Some(file.clone()));
    let c = from_file.server_config(Version::new(0, 2, 0), Version::new(0, 2, 0));
    assert_eq!(c.org_defaults.retention_days, 30);
    assert_eq!(c.org_defaults.min_client, Version::new(0, 2, 1));
    assert_eq!(c.org_defaults.max_members, 5);
    assert_eq!(c.limits.requests_per_minute, 11);
    assert_eq!(c.limits.request_burst, 12);
    assert_eq!(c.limits.anonymous_per_minute, 13);
    assert_eq!(c.limits.joins_per_hour, 3);
    assert_eq!(c.limits.records_per_day, 99);
    assert_eq!(c.request_timeout, Duration::from_secs(7));
    assert!(c.internal_token_hash.is_some());
    assert!(c.hsts);

    // Every flag wins over its key.
    let flags = Flags {
        config: Some(file.clone()),
        data: Some("/from/flag".into()),
        domain: Some("flag.example.com".into()),
        backup: Some("file:///from/flag".into()),
        listen: Some("127.0.0.1:3333".into()),
        trusted_proxies: vec!["192.0.2.0/24".into()],
        acme_email: Some("flag@example.com".into()),
        acme_directory: Some("https://flag.example/dir".into()),
        acme_ca_file: Some("/from/flag/ca.pem".into()),
        acme_http_listen: Some("127.0.0.1:4444".into()),
        ..Flags::default()
    };
    // The flag for the challenge beats the key too (and then the HTTP-01 listener of the file
    // has no use, which is refused rather than ignored).
    let m = refused(&Flags {
        acme_challenge: Some("tls-alpn-01".into()),
        ..flags.clone()
    });
    assert!(m.contains("http-01"), "{m}");
    let r = resolve(&flags).unwrap();
    assert_eq!(
        r.store,
        StoreChoice::Sqlite {
            data: "/from/flag".into()
        }
    );
    assert_eq!(
        r.domain,
        Some(config::Domain::Dns("flag.example.com".into()))
    );
    assert_eq!(r.backup.as_deref(), Some("file:///from/flag"));
    assert_eq!(
        r.listen,
        vec!["127.0.0.1:3333".parse::<SocketAddr>().unwrap()]
    );
    assert_eq!(r.trusted_proxies.len(), 1);
    assert!(!r.cloud_run, "the flag's list replaces the file's");
    let acme = r.acme.as_ref().unwrap();
    assert_eq!(acme.email.as_deref(), Some("flag@example.com"));
    assert_eq!(acme.challenge, config::Challenge::Http01, "from the file");
    assert_eq!(acme.directory, "https://flag.example/dir");
    assert_eq!(acme.ca_file, Some(PathBuf::from("/from/flag/ca.pem")));
    assert_eq!(r.http01_listen, Some("127.0.0.1:4444".parse().unwrap()));
}

#[test]
fn the_default_config_file_is_data_server_toml() {
    let dir = scratch("toml-default");
    write_private(
        &dir.join("server.toml"),
        "retention_days = 45\nmax_members = 9\n",
    );
    let r = resolve(&Flags {
        data: Some(dir.clone()),
        ..Flags::default()
    })
    .unwrap();
    assert_eq!(r.overrides.retention_days, Some(45));
    assert_eq!(r.config_file, Some(dir.join("server.toml")));
    // The database URL and its variables are keys too.
    write_private(
        &dir.join("server.toml"),
        "database_url_env = \"DB\"\ndatabase_url_owner_env = \"OWNER\"\n",
    );
    let r = resolve_with(
        &Flags {
            config: Some(dir.join("server.toml")),
            ..Flags::default()
        },
        &[
            ("DB", "postgres://app@h/d"),
            ("OWNER", "postgres://owner@h/d"),
        ],
    )
    .unwrap();
    let StoreChoice::Postgres { url, owner_url, .. } = r.store else {
        panic!("PgStore");
    };
    assert_eq!(url.expose(), "postgres://app@h/d");
    assert_eq!(owner_url.unwrap().expose(), "postgres://owner@h/d");
}

#[test]
fn nothing_prints_a_database_url() {
    let secret = "postgres://awm_app:hunter2-secret@db.internal/awm";
    let r = resolve(&Flags {
        database_url: Some(Secret::new(secret)),
        ..Flags::default()
    })
    .unwrap();
    let dbg = format!("{r:?}");
    assert!(
        !dbg.contains("hunter2") && !dbg.contains("db.internal"),
        "{dbg}"
    );
    assert!(dbg.contains("redacted"));
    let f = Flags {
        database_url: Some(Secret::new(secret)),
        ..Flags::default()
    };
    assert!(!format!("{f:?}").contains("hunter2"));
}

// ---------------------------------------------------------------------------------------------
// The server in process

#[tokio::test]
async fn a_started_server_creates_its_files_with_their_modes_and_answers_healthz() {
    let dir = scratch("start").join("awm");
    let log = Arc::new(Capture::default());
    let server = running(&data_flags(&dir), &log).await;
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("server.db")), 0o600);
    let router = http::router(server.state.clone());
    let r = send(&router, "GET", "/healthz", None, None, "127.0.0.1", &[]).await;
    assert_eq!(r.status, 200);
    assert!(
        !r.headers.contains_key("strict-transport-security"),
        "HSTS only when this binary terminates TLS"
    );
    // The real listener answers too (/healthz and /v1/info).
    let addr = server.addrs[0];
    let raw = raw_get(addr, "/v1/info").await;
    assert!(
        raw.starts_with("HTTP/1.1 200") && raw.contains("\"server\""),
        "{raw}"
    );
    // One request-log line per request, to the sink.
    assert!(
        log.text()
            .contains("request method=GET path=/v1/info status=200"),
        "{}",
        log.text()
    );
    assert!(
        log.text().contains("WARNING: no --backup target"),
        "{}",
        log.text()
    );
    assert!(server.no_admin);
    server.stop(Duration::from_secs(1)).await;
}

async fn raw_get(addr: SocketAddr, path: &str) -> String {
    let path = path.to_string();
    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut tcp = std::net::TcpStream::connect(addr).unwrap();
        tcp.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
        let mut out = Vec::new();
        let _ = tcp.read_to_end(&mut out);
        String::from_utf8_lossy(&out).to_string()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn a_slow_request_gets_408_after_the_timeout() {
    let dir = scratch("timeout");
    write_private(&dir.join("server.toml"), "request_timeout_s = 1\n");
    let log = Arc::new(Capture::default());
    let server = running(&data_flags(&dir), &log).await;
    let addr = server.addrs[0];
    let started = std::time::Instant::now();
    let text = tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut tcp = std::net::TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        // Headers promise a body that never comes.
        tcp.write_all(
            b"POST /v1/join HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 50\r\nAwm-Client: awm/0.2.0 proto/1 redact/3\r\n\r\n{",
        )
        .unwrap();
        let mut buf = vec![0u8; 512];
        let n = tcp.read(&mut buf).expect("the server answers");
        String::from_utf8_lossy(&buf[..n]).to_string()
    })
    .await
    .unwrap();
    assert!(text.starts_with("HTTP/1.1 408"), "{text}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "after about a second"
    );
    server.stop(Duration::from_secs(1)).await;
}

// --- init -----------------------------------------------------------------------------------

#[tokio::test]
async fn init_prints_the_token_on_a_terminal_and_replaces_it_on_a_second_run() {
    let dir = scratch("init").join("awm");
    let log = Arc::new(Capture::default());
    let (c1, out1, err1) = cmd(
        data_flags(&dir),
        Command::Init { print_hash: false },
        settings(&log),
        true,
    )
    .await;
    assert_eq!(c1, 0, "{err1}");
    assert_eq!(mode(&dir), 0o700, "init creates the database like start");
    assert_eq!(mode(&dir.join("server.db")), 0o600);
    let token1 = out1
        .lines()
        .find(|l| l.trim().starts_with("awm_b_"))
        .expect("a token")
        .trim()
        .to_string();
    BootstrapToken::parse(&token1).expect("the token `awm team create` parses");

    let (c2, out2, _) = cmd(
        data_flags(&dir),
        Command::Init { print_hash: false },
        settings(&log),
        true,
    )
    .await;
    assert_eq!(c2, 0);
    let token2 = out2
        .lines()
        .find(|l| l.trim().starts_with("awm_b_"))
        .unwrap()
        .trim()
        .to_string();
    assert_ne!(token1, token2, "a new token each time");

    // The first token no longer works; the second works once.
    let server = running(&data_flags(&dir), &log).await;
    let router = http::router(server.state.clone());
    assert_eq!(
        bootstrap(&router, &token1, "alf").await.status,
        410,
        "replaced"
    );
    assert_eq!(bootstrap(&router, &token2, "alf").await.status, 200);
    assert_eq!(
        bootstrap(&router, &token2, "alf").await.status,
        410,
        "single use"
    );
    server.stop(Duration::from_secs(1)).await;

    // With an admin, init refuses.
    let (c3, _, err3) = cmd(
        data_flags(&dir),
        Command::Init { print_hash: false },
        settings(&log),
        true,
    )
    .await;
    assert_eq!(c3, 1);
    assert!(err3.contains("already has an admin"), "{err3}");
}

#[tokio::test]
async fn without_a_terminal_no_token_is_printed_and_the_log_says_so() {
    let dir = scratch("init-notty");
    let log = Arc::new(Capture::default());
    let (c, out, err) = cmd(
        data_flags(&dir),
        Command::Init { print_hash: false },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 0, "{err}");
    assert!(
        !out.contains("awm_b_") && !err.contains("awm_b_"),
        "no token on a pipe: {out}{err}"
    );
    assert!(
        log.text().contains("no admin yet: run `awm serve init`"),
        "{}",
        log.text()
    );
    // Starting the server on a pipe logs the same line and no token.
    let server = running(&data_flags(&dir), &log).await;
    assert!(server.no_admin);
    server.stop(Duration::from_secs(1)).await;
    assert!(!log.text().contains("awm_b_"), "{}", log.text());
}

#[tokio::test]
async fn init_print_hash_touches_no_database() {
    let dir = scratch("print-hash").join("never-created");
    let clock = TestClock::at(T0);
    let log = Arc::new(Capture::default());
    let (c, out, _) = cmd(
        data_flags(&dir),
        Command::Init { print_hash: true },
        settings_with(&log, clock.clone(), &[]),
        false,
    )
    .await;
    assert_eq!(c, 0);
    assert!(!dir.exists(), "no data directory, no database");
    let token = out
        .lines()
        .find_map(|l| l.strip_prefix("bootstrap token: "))
        .expect("the token")
        .to_string();
    BootstrapToken::parse(&token).unwrap();
    let hash = out
        .lines()
        .find_map(|l| l.strip_prefix("AWM_BOOTSTRAP_SHA256="))
        .unwrap();
    let expires = out
        .lines()
        .find_map(|l| l.strip_prefix("AWM_BOOTSTRAP_EXPIRES="))
        .unwrap();
    assert_eq!(hash, awm_server::auth::hash(&token));
    assert_eq!(expires.parse::<i64>().unwrap(), T0 + 86_400);
    // No configuration is needed at all.
    let (c, _, _) = cmd(
        Flags::default(),
        Command::Init { print_hash: true },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 0);
}

#[tokio::test]
async fn a_bootstrap_hash_from_the_environment_works_once_and_not_after_expiry() {
    let (dir, dir2) = (scratch("env-hash"), scratch("env-hash-expired"));
    let clock = TestClock::at(T0);
    let log = Arc::new(Capture::default());
    let token = awm_server::auth::new_bootstrap_token().unwrap();
    let hash: &'static str = Box::leak(awm_server::auth::hash(token.as_str()).into_boxed_str());
    let expires: &'static str = Box::leak((T0 + 3_600).to_string().into_boxed_str());
    let env: &'static [(&'static str, &'static str)] = Box::leak(Box::new([
        ("AWM_BOOTSTRAP_SHA256", hash),
        ("AWM_BOOTSTRAP_EXPIRES", expires),
    ]));

    let r = resolve(&data_flags(&dir)).unwrap();
    let s = settings_with(&log, clock.clone(), env);
    let server = serve::start(&r, &s).await.unwrap();
    assert!(server.bootstrap_installed && server.no_admin);
    let router = http::router(server.state.clone());
    let wrong = awm_server::auth::new_bootstrap_token().unwrap();
    assert_eq!(
        bootstrap(&router, wrong.as_str(), "mallory").await.status,
        410
    );
    assert_eq!(
        bootstrap(&router, token.as_str(), "alf").await.status,
        200,
        "the matching token"
    );
    assert_eq!(
        bootstrap(&router, token.as_str(), "alf2").await.status,
        410,
        "once"
    );
    server.stop(Duration::from_secs(1)).await;

    // Once the admin exists, a restart ignores the variables.
    let server = serve::start(&r, &s).await.unwrap();
    assert!(!server.bootstrap_installed && !server.no_admin);
    server.stop(Duration::from_secs(1)).await;

    // After the expiry the same token is gone.
    let r2 = resolve(&data_flags(&dir2)).unwrap();
    let server = serve::start(&r2, &s).await.unwrap();
    let router = http::router(server.state.clone());
    clock.set(T0 + 3_601);
    assert_eq!(
        bootstrap(&router, token.as_str(), "late").await.status,
        410,
        "expired"
    );
    server.stop(Duration::from_secs(1)).await;

    // Half a pair, a malformed hash and a malformed expiry are refused (exit 2).
    for env in [
        &[("AWM_BOOTSTRAP_SHA256", "ab")][..],
        &[("AWM_BOOTSTRAP_EXPIRES", "5")][..],
        &[
            ("AWM_BOOTSTRAP_SHA256", "xyz"),
            ("AWM_BOOTSTRAP_EXPIRES", "5"),
        ][..],
        &[
            ("AWM_BOOTSTRAP_SHA256", hash),
            ("AWM_BOOTSTRAP_EXPIRES", "tomorrow"),
        ][..],
    ] {
        let env: &'static [(&'static str, &'static str)] =
            Box::leak(env.to_vec().into_boxed_slice());
        let dir = scratch("env-bad");
        let err = serve::start(
            &resolve(&data_flags(&dir)).unwrap(),
            &settings_with(&log, clock.clone(), env),
        )
        .await
        .err()
        .expect("refused");
        assert_eq!(err.code, 2, "{err}");
    }
}

// --- proxies --------------------------------------------------------------------------------

fn ip_of_last_request(log: &Capture) -> String {
    let text = log.text();
    let line = text
        .lines()
        .rev()
        .find(|l| l.starts_with("request "))
        .expect("a request line");
    line.split_whitespace()
        .find_map(|w| w.strip_prefix("ip="))
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn trusted_proxy_cloud_run_takes_the_last_x_forwarded_for_entry() {
    let dir = scratch("cloud-run");
    let log = Arc::new(Capture::default());
    let flags = Flags {
        data: Some(dir),
        listen: Some("127.0.0.1:0".into()),
        behind_tls_proxy: true,
        trusted_proxies: vec!["cloud-run".into()],
        ..Flags::default()
    };
    // Only on Cloud Run (RVT2 m4).
    let r = resolve_with(&flags, &[("K_SERVICE", "awm")]).expect("a valid configuration");
    let server = serve::start(&r, &settings(&log))
        .await
        .expect("the server starts");
    let router = http::router(server.state.clone());
    // The left part is client-supplied; the last entry is what the front end saw.
    send(
        &router,
        "GET",
        "/v1/info",
        None,
        None,
        "169.254.8.129",
        &[("x-forwarded-for", "6.6.6.6, 198.51.100.7")],
    )
    .await;
    assert_eq!(ip_of_last_request(&log), "198.51.100.7");
    send(
        &router,
        "GET",
        "/v1/info",
        None,
        None,
        "169.254.8.129",
        &[("x-forwarded-for", "198.51.100.9")],
    )
    .await;
    assert_eq!(ip_of_last_request(&log), "198.51.100.9");
    // No header: the socket's peer. An unparsable last entry: the peer.
    send(&router, "GET", "/v1/info", None, None, "169.254.8.129", &[]).await;
    assert_eq!(ip_of_last_request(&log), "169.254.8.129");
    send(
        &router,
        "GET",
        "/v1/info",
        None,
        None,
        "169.254.8.129",
        &[("x-forwarded-for", "1.2.3.4, garbage")],
    )
    .await;
    assert_eq!(ip_of_last_request(&log), "169.254.8.129");
    server.stop(Duration::from_secs(1)).await;

    // With a CIDR list the header counts only from a trusted peer.
    let dir = scratch("cidr");
    let flags = Flags {
        data: Some(dir),
        listen: Some("127.0.0.1:0".into()),
        behind_tls_proxy: true,
        trusted_proxies: vec!["10.0.0.0/8".into()],
        ..Flags::default()
    };
    let server = running(&flags, &log).await;
    let router = http::router(server.state.clone());
    send(
        &router,
        "GET",
        "/v1/info",
        None,
        None,
        "10.1.1.1",
        &[("x-forwarded-for", "198.51.100.7")],
    )
    .await;
    assert_eq!(ip_of_last_request(&log), "198.51.100.7");
    send(
        &router,
        "GET",
        "/v1/info",
        None,
        None,
        "203.0.113.50",
        &[("x-forwarded-for", "198.51.100.7")],
    )
    .await;
    assert_eq!(
        ip_of_last_request(&log),
        "203.0.113.50",
        "an untrusted peer cannot choose its address"
    );
    server.stop(Duration::from_secs(1)).await;
}

// --- retention, backup, signal ---------------------------------------------------------------

#[tokio::test]
async fn retention_runs_hourly_on_a_host_and_in_requests_on_cloud_run() {
    // A host: the task starts and its first run (the organisation exists) is logged.
    let dir = scratch("retention");
    let log = Arc::new(Capture::default());
    {
        let store = awm_server::store::sqlite::SqliteStore::open(&dir).unwrap();
        let t = awm_server::auth::issue_bootstrap(&store, SystemClock.now())
            .await
            .unwrap();
        // Create the organisation through the router of a throwaway state.
        let state = http::AppState::new(
            Arc::new(store),
            http::ServerConfig::new(Version::new(0, 2, 0), Version::new(0, 2, 0)),
        );
        let router = http::router(state);
        assert_eq!(bootstrap(&router, t.as_str(), "alf").await.status, 200);
    }
    // RVT2 B2: the hourly task also removes local copies of the database past the backups'
    // window, with no backup target: one 9 days old goes, one an hour old stays.
    let now = SystemClock.now();
    let old_copy = dir.join(format!("server.db.pre-restore-{}", now - 9 * 86_400));
    let new_copy = dir.join(format!("server.db.pre-restore-{}", now - 3_600));
    for p in [&old_copy, &new_copy] {
        std::fs::write(p, b"copy").unwrap();
        chmod(p, 0o600);
    }
    let server = running(&data_flags(&dir), &log).await;
    assert_eq!(server.state.config.retention, RetentionMode::Off);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !log.text().contains("retention removed=") {
        assert!(
            std::time::Instant::now() < deadline,
            "no retention run logged:\n{}",
            log.text()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!old_copy.exists(), "{}", log.text());
    assert!(new_copy.exists());
    assert!(log.text().contains("local database copy"), "{}", log.text());
    server.stop(Duration::from_secs(1)).await;

    // Request-time mode (`PORT` with `--behind-tls-proxy`): the server spawns no hourly task and
    // the state says so.
    let dir = scratch("retention-req");
    let flags = Flags {
        behind_tls_proxy: true,
        trusted_proxies: vec!["10.0.0.0/8".into()],
        ..data_flags(&dir)
    };
    let r = resolve_with(&flags, &[("PORT", "0")]).unwrap();
    let server = serve::start(&r, &settings(&log)).await.unwrap();
    assert_eq!(server.state.config.retention, RetentionMode::InRequests);
    server.stop(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn start_waits_a_second_for_a_short_lived_lock_holder_and_then_refuses() {
    // A restart that races a short-lived holder (a forked child that inherited the descriptor,
    // a `stop` whose lock drop is still in flight) succeeds; a real holder is exit 2.
    let log = Arc::new(Capture::default());
    let dir = scratch("lock-retry");
    let lock = awm_server::lockfile::try_lock(&dir).unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(lock);
    });
    let server = running(&data_flags(&dir), &log).await;
    release.join().unwrap();
    server.stop(Duration::from_secs(1)).await;

    let lock = awm_server::lockfile::try_lock(&dir).unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));
        drop(lock);
    });
    let e = serve::start(&resolve(&data_flags(&dir)).unwrap(), &settings(&log))
        .await
        .err()
        .expect("a lock held for 2 s is refused");
    assert_eq!(e.code, 2, "{e}");
    assert!(
        e.message.contains("server.lock") && e.message.contains("stop it first"),
        "{e}"
    );
    release.join().unwrap();
}

fn find_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                find_files(&p, out);
            } else {
                out.push(p);
            }
        }
    }
}

#[tokio::test]
async fn with_backup_the_runner_starts_and_the_start_snapshot_is_written() {
    let (dir, target) = (scratch("backup"), scratch("backup-target"));
    let log = Arc::new(Capture::default());
    let url = format!("file://{}", target.display());
    let flags = Flags {
        backup: Some(url),
        ..data_flags(&dir)
    };
    let server = running(&flags, &log).await;
    assert!(server.backup.is_some(), "the runner exists");
    assert!(
        !log.text().contains("WARNING: no --backup target"),
        "{}",
        log.text()
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let mut files = Vec::new();
        find_files(&target, &mut files);
        if files.iter().any(|f| {
            f.to_string_lossy().contains("/full/") && f.extension().is_some_and(|e| e == "db")
        }) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no start snapshot:\n{}\n{files:?}",
            log.text()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The event is logged just after the object lands.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !log.text().contains("backup: uploaded full/") {
        assert!(std::time::Instant::now() < deadline, "{}", log.text());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    server.stop(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn sigterm_shuts_the_server_down_cleanly_with_exit_code_0() {
    let dir = scratch("sigterm");
    let log = Arc::new(Capture::default());
    let flags = data_flags(&dir);
    let l = log.clone();
    let task = tokio::spawn(async move {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        serve::run_async(
            Invocation {
                flags,
                command: Command::Run,
                settings: settings(&l),
            },
            &mut Io {
                out: &mut out,
                err: &mut err,
                tty: false,
            },
        )
        .await
    });
    // The handlers are installed before the server starts; "listening" is logged after.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !log.text().contains("listening on") {
        assert!(std::time::Instant::now() < deadline, "{}", log.text());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let status = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(std::process::id().to_string())
        .status()
        .unwrap();
    assert!(status.success());
    let code = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the server stops")
        .unwrap();
    assert_eq!(code, 0, "clean shutdown on SIGTERM");
    assert!(log.text().contains("shutting down"), "{}", log.text());
}

// --- healthcheck ----------------------------------------------------------------------------

#[tokio::test]
async fn healthcheck_exits_0_for_a_healthy_server_and_1_otherwise() {
    let dir = scratch("health");
    let log = Arc::new(Capture::default());
    let server = running(&data_flags(&dir), &log).await;
    let port = server.addrs[0].port();
    let (c, out, _) = cmd(
        Flags::default(),
        Command::Healthcheck {
            url: Some(format!("http://127.0.0.1:{port}/healthz")),
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!((c, out.trim()), (0, "ok"));
    // From the configuration: the listener of the flags.
    let (c, _, _) = cmd(
        Flags {
            listen: Some(format!("127.0.0.1:{port}")),
            ..data_flags(&dir)
        },
        Command::Healthcheck { url: None },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 0);
    // A wrong path answers 404: unhealthy.
    let (c, _, err) = cmd(
        Flags::default(),
        Command::Healthcheck {
            url: Some(format!("http://127.0.0.1:{port}/nope")),
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 1);
    assert!(err.contains("404"), "{err}");
    server.stop(Duration::from_secs(1)).await;
    // Nothing listening any more.
    let (c, _, err) = cmd(
        Flags::default(),
        Command::Healthcheck {
            url: Some(format!("http://127.0.0.1:{port}/healthz")),
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 1);
    assert!(err.contains("unhealthy"), "{err}");
}

// --- promote, backup, restore -----------------------------------------------------------------

/// A server directory with an admin `alf` and a member `kit`; returns the store afterwards.
async fn org_with_a_member(dir: &Path, log: &Arc<Capture>) {
    let server = running(&data_flags(dir), log).await;
    let router = http::router(server.state.clone());
    let t = awm_server::auth::issue_bootstrap(&*server.store, SystemClock.now())
        .await
        .unwrap();
    let admin = bootstrap(&router, t.as_str(), "alf").await;
    assert_eq!(admin.status, 200);
    let token = admin.json()["device_token"].as_str().unwrap().to_string();
    let inv = send(
        &router,
        "POST",
        "/v1/invites",
        Some(&token),
        Some(json!({"kind": "member", "handle": "kit", "role": "member"})),
        "203.0.113.5",
        &[],
    )
    .await;
    assert_eq!(inv.status, 200);
    let inv = inv.json();
    let device = Id::new_v4();
    let joined = send(
        &router,
        "POST",
        "/v1/join",
        None,
        Some(json!({
            "invite_id": inv["invite_id"], "invite_token": inv["invite_token"],
            "handle": "kit", "device_id": device.to_string(),
            "device_pubkey": b64(&[2u8; 32]), "join_mac": b64(&[3u8; 32]),
        })),
        "203.0.113.6",
        &[],
    )
    .await;
    assert_eq!(joined.status, 200);
    let wraps =
        json!({"wraps": [{"epoch": 0, "wrap": b64(&[0x5a; 140]), "auth": b64(&[0xa0; 32])}]});
    let r = send(
        &router,
        "POST",
        &format!("/v1/devices/{device}/approve"),
        Some(&token),
        Some(wraps),
        "203.0.113.5",
        &[],
    )
    .await;
    assert_eq!(r.status, 204);
    server.stop(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn promote_makes_a_member_an_admin() {
    let dir = scratch("promote");
    let log = Arc::new(Capture::default());
    org_with_a_member(&dir, &log).await;
    let (c, out, err) = cmd(
        data_flags(&dir),
        Command::Promote {
            handle: "@kit".into(),
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 0, "{err}");
    assert!(out.contains("@kit is an admin"), "{out}");
    let store = awm_server::store::sqlite::SqliteStore::open(&dir).unwrap();
    let kit = store
        .member_by_handle(awm_proto::wire::Handle::parse("kit").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kit.role, awm_proto::wire::Role::Admin);
    // Unknown handle: exit 1. Malformed handle: exit 2.
    let (c, _, err) = cmd(
        data_flags(&dir),
        Command::Promote {
            handle: "nobody".into(),
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 1);
    assert!(err.contains("no member"), "{err}");
    let (c, _, _) = cmd(
        data_flags(&dir),
        Command::Promote {
            handle: "Not A Handle".into(),
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 2);
}

#[tokio::test]
async fn backup_verify_and_restore_are_wired_with_their_exit_codes() {
    let (dir, target, restored) = (
        scratch("br"),
        scratch("br-target"),
        scratch("br-restored").join("awm"),
    );
    let log = Arc::new(Capture::default());
    org_with_a_member(&dir, &log).await;
    let url = format!("file://{}", target.display());

    // backup --to URL --verify
    let (c, out, err) = cmd(
        data_flags(&dir),
        Command::Backup {
            to: Some(url.clone()),
            verify: true,
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 0, "{err}");
    assert!(
        out.contains("uploaded: full/") && out.contains("verify ok"),
        "{out}"
    );
    // No target at all: refused.
    let (c, _, err) = cmd(
        data_flags(&dir),
        Command::Backup {
            to: None,
            verify: false,
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 2, "{err}");
    // backup --to FILE: the canonical export.
    let file = scratch("br-export").join("export.db");
    let (c, out, err) = cmd(
        data_flags(&dir),
        Command::Backup {
            to: Some(file.display().to_string()),
            verify: false,
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 0, "{err}");
    assert!(file.is_file() && out.contains("member"), "{out}");

    // restore --from URL --data NEW: prints the report and the admin-must-sync line.
    let (c, out, err) = cmd(
        data_flags(&restored),
        Command::Restore {
            from: Some(url.clone()),
            at: None,
            force: false,
            mark_restored: false,
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 0, "{err}");
    assert!(out.contains("new generation"), "{out}");
    assert!(out.contains("an admin must run `awm sync` now"), "{out}");
    assert!(out.contains("member: 2"), "{out}");
    // A non-empty target without --force: exit 2.
    let (c, _, err) = cmd(
        data_flags(&restored),
        Command::Restore {
            from: Some(url.clone()),
            at: None,
            force: false,
            mark_restored: false,
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 2, "{err}");
    // --force renames the old database and restores again.
    let (c, out, err) = cmd(
        data_flags(&restored),
        Command::Restore {
            from: Some(url.clone()),
            at: None,
            force: true,
            mark_restored: false,
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 0, "{err}");
    assert!(out.contains("previous database kept as"), "{out}");
    // RVT2 B2: the copy holds deleted blobs; the report says when it goes (8 days on at the
    // latest).
    let line = out
        .lines()
        .find(|l| l.contains("awm serve removes it by"))
        .unwrap_or_else(|| panic!("{out}"));
    let day = |t: i64| awm_server::check::fmt_utc(t)[..10].to_string();
    let now = SystemClock.now();
    assert!(
        [day(now + 8 * 86_400 - 60), day(now + 8 * 86_400)]
            .iter()
            .any(|d| line.contains(d.as_str())),
        "{line}"
    );
    assert!(line.contains("copy it elsewhere"), "{line}");

    // RVT2 M5: no restore while a server runs on the directory, and one server per directory.
    let server = running(&data_flags(&restored), &log).await;
    for (from, force, mark) in [(Some(url.clone()), true, false), (None, false, true)] {
        let (c, _, err) = cmd(
            data_flags(&restored),
            Command::Restore {
                from,
                at: None,
                force,
                mark_restored: mark,
            },
            settings(&log),
            false,
        )
        .await;
        assert_eq!(c, 2, "{err}");
        assert!(err.contains("stop the server"), "{err}");
    }
    let e = serve::start(&resolve(&data_flags(&restored)).unwrap(), &settings(&log))
        .await
        .err()
        .expect("a second server on the directory is refused");
    assert_eq!(e.code, 2, "{e}");
    assert!(
        e.message.contains("server.lock") && e.message.contains("stop it first"),
        "{e}"
    );
    // The lock goes with the server.
    server.stop(Duration::from_secs(1)).await;
    // --mark-restored only changes the generation; no --from; both together are refused.
    let (c, _, err) = cmd(
        data_flags(&restored),
        Command::Restore {
            from: None,
            at: None,
            force: false,
            mark_restored: true,
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 0, "{err}");
    let (c, _, _) = cmd(
        data_flags(&restored),
        Command::Restore {
            from: Some(url.clone()),
            at: None,
            force: false,
            mark_restored: true,
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 2);
    // --at before the backup: nothing to restore (exit 1); a bad --at: exit 2.
    let fresh = scratch("br-at").join("awm");
    let (c, _, _) = cmd(
        data_flags(&fresh),
        Command::Restore {
            from: Some(url.clone()),
            at: Some("1000".into()),
            force: false,
            mark_restored: false,
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 1);
    let (c, _, _) = cmd(
        data_flags(&fresh),
        Command::Restore {
            from: Some(url.clone()),
            at: Some("yesterday".into()),
            force: false,
            mark_restored: false,
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 2);

    // A manifest mismatch is exit 3: flip one byte of the snapshot.
    let mut files = Vec::new();
    find_files(&target, &mut files);
    let snapshot = files
        .iter()
        .find(|f| f.extension().is_some_and(|e| e == "db"))
        .unwrap()
        .clone();
    let mut bytes = std::fs::read(&snapshot).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    chmod(&snapshot, 0o600);
    std::fs::write(&snapshot, bytes).unwrap();
    let broken = scratch("br-broken").join("awm");
    let (c, _, err) = cmd(
        data_flags(&broken),
        Command::Restore {
            from: Some(url),
            at: None,
            force: false,
            mark_restored: false,
        },
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 3, "{err}");
}

// --- the Postgres host (RVT2 M4) ---------------------------------------------------------

#[cfg(feature = "pg")]
#[tokio::test]
async fn a_public_database_host_is_exit_2_unless_the_insecure_network_flag_is_given() {
    use awm_server::store::pg::{parse_url, public_host};
    // The connection has no TLS: hosts outside loopback and the private ranges are refused
    // before anything connects.
    let log = Arc::new(Capture::default());
    for (url, host) in [
        ("postgres://awm@8.8.8.8/awm", "8.8.8.8"),
        (
            "postgres://awm@[2001:4860::8888]:5432/awm",
            "2001:4860::8888",
        ),
        (
            "postgres://awm@127.0.0.1/awm?hostaddr=192.0.2.7",
            "192.0.2.7",
        ),
    ] {
        let flags = Flags {
            database_url: Some(Secret::new(url)),
            listen: Some("127.0.0.1:0".into()),
            ..Flags::default()
        };
        let r = resolve(&flags).unwrap();
        let e = serve::start(&r, &settings(&log))
            .await
            .err()
            .expect("a public host is refused");
        assert_eq!(e.code, 2, "{url}: {e}");
        assert!(
            e.message.contains(host) && e.message.contains("--database-insecure-network"),
            "{e}"
        );
        // The refusal names no password or URL.
        assert!(!e.message.contains("postgres://"), "{e}");
    }
    // Loopback, RFC 1918, link-local, ULA, `localhost` and the Cloud SQL socket are accepted.
    for url in [
        "postgres://awm@127.0.0.1/awm",
        "postgres://awm@[::1]/awm",
        "postgres://awm@localhost/awm",
        "postgres://awm@10.1.2.3/awm",
        "postgres://awm@172.16.0.9/awm",
        "postgres://awm@192.168.5.5/awm",
        "postgres://awm@169.254.1.1/awm",
        "postgres://awm@[fd00::5]/awm",
        "postgres://awm@[fe80::1]/awm",
        "postgres://awm@/awm?host=/cloudsql/proj:region:inst",
        "host=/cloudsql/proj:region:inst user=awm dbname=awm",
        "postgres://awm@db.example.com/awm?hostaddr=10.0.0.4",
    ] {
        let cfg = parse_url(url).unwrap();
        assert_eq!(public_host(&cfg).await, None, "{url}");
    }
    // The flag (or its server.toml key) accepts the risk; without a URL it is refused.
    let flags = Flags {
        database_url: Some(Secret::new("postgres://awm@8.8.8.8/awm")),
        database_insecure_network: true,
        ..Flags::default()
    };
    match resolve(&flags).unwrap().store {
        StoreChoice::Postgres {
            insecure_network, ..
        } => assert!(insecure_network),
        other => panic!("{other:?}"),
    }
    let m = refused(&Flags {
        data: Some("/d".into()),
        database_insecure_network: true,
        ..Flags::default()
    });
    assert!(m.contains("--database-insecure-network"), "{m}");
    let dir = scratch("insecure-toml");
    let file = dir.join("server.toml");
    std::fs::write(
        &file,
        "database_url_env = \"DB\"\ndatabase_insecure_network = true\n",
    )
    .unwrap();
    chmod(&file, 0o600);
    let r = resolve_with(
        &Flags {
            config: Some(file),
            ..Flags::default()
        },
        &[("DB", "postgres://awm@8.8.8.8/awm")],
    )
    .unwrap();
    assert!(matches!(
        r.store,
        StoreChoice::Postgres {
            insecure_network: true,
            ..
        }
    ));
}

// --- logs ----------------------------------------------------------------------------------

#[tokio::test]
async fn no_token_key_or_record_text_reaches_a_log_line_or_an_error() {
    let dir = scratch("log-scan");
    let log = Arc::new(Capture::default());
    let server = running(&data_flags(&dir), &log).await;
    let router = http::router(server.state.clone());
    let t = awm_server::auth::issue_bootstrap(&*server.store, SystemClock.now())
        .await
        .unwrap();
    let r = bootstrap(&router, t.as_str(), "alf").await;
    assert_eq!(r.status, 200);
    let device_token = r.json()["device_token"].as_str().unwrap().to_string();
    // Use the device token, a wrong one, and a push with a recognisable blob.
    send(
        &router,
        "GET",
        "/v1/status",
        Some(&device_token),
        None,
        "203.0.113.5",
        &[],
    )
    .await;
    send(
        &router,
        "GET",
        "/v1/status",
        Some("awm_t_wrong_token_value"),
        None,
        "203.0.113.5",
        &[],
    )
    .await;
    let text = log.text();
    for secret in [t.as_str(), device_token.as_str(), "awm_t_wrong_token_value"] {
        assert!(!text.contains(secret), "a token is in the log:\n{text}");
    }
    assert!(!text.contains("authorization") && !text.to_lowercase().contains("bearer"));
    server.stop(Duration::from_secs(1)).await;

    // Refusals print no value: a URL with a password in a flag, an env var and the backup URL.
    let (c, out, err) = cmd(
        Flags {
            data: Some(dir.clone()),
            backup: Some("gs://bucket/p?access_token=hunter2".into()),
            ..Flags::default()
        },
        Command::Run,
        settings(&log),
        false,
    )
    .await;
    assert_eq!(c, 2);
    assert!(
        !out.contains("hunter2") && !err.contains("hunter2"),
        "{err}"
    );
}

// --- PgStore (AWM_TEST_PG_URL) -----------------------------------------------------------------

#[cfg(feature = "pg")]
#[path = "support/pg.rs"]
mod pg;

#[cfg(feature = "pg")]
#[tokio::test]
async fn pgstore_starts_from_database_url_env_and_owner_env_and_never_logs_the_url() {
    let Some(env) = pg::PgEnv::new("serve").await else {
        eprintln!("SKIP pgstore_starts_from_database_url_env: AWM_TEST_PG_URL is not set");
        return;
    };
    let app: &'static str = Box::leak(env.app_url.clone().into_boxed_str());
    let owner: &'static str = Box::leak(env.owner_url.clone().into_boxed_str());
    let envs: &'static [(&'static str, &'static str)] =
        Box::leak(Box::new([("AWM_DB", app), ("AWM_DB_OWNER", owner)]));
    let flags = Flags {
        database_url_env: Some("AWM_DB".into()),
        database_url_owner_env: Some("AWM_DB_OWNER".into()),
        listen: Some("127.0.0.1:0".into()),
        ..Flags::default()
    };
    let log = Arc::new(Capture::default());
    let r = resolve_with(&flags, envs).unwrap();
    let server = serve::start(&r, &settings_with(&log, Arc::new(SystemClock), envs))
        .await
        .expect("PgStore starts and migrates as the owner");
    let router = http::router(server.state.clone());
    assert_eq!(
        send(&router, "GET", "/healthz", None, None, "127.0.0.1", &[])
            .await
            .status,
        200
    );
    let t = awm_server::auth::issue_bootstrap(&*server.store, SystemClock.now())
        .await
        .unwrap();
    assert_eq!(bootstrap(&router, t.as_str(), "alf").await.status, 200);
    server.stop(Duration::from_secs(1)).await;
    // The password and the URL are in no log line, and `init` on PgStore works too.
    assert!(
        !log.text().contains("awm_app") && !log.text().contains(&env.schema),
        "{}",
        log.text()
    );
    let (c, _, err) = cmd(
        flags.clone(),
        Command::Init { print_hash: false },
        settings_with(&log, Arc::new(SystemClock), envs),
        true,
    )
    .await;
    assert_eq!(c, 1, "the organisation exists now: {err}");
    assert!(!err.contains("awm_app"), "{err}");
}

#[tokio::test]
async fn an_unreachable_database_is_exit_3_and_the_url_stays_out_of_every_message() {
    let envs: &'static [(&'static str, &'static str)] = &[(
        "AWM_DB",
        "postgres://awm_app:hunter2-secret@127.0.0.1:1/awm?options=-c%20search_path%3Dx",
    )];
    let log = Arc::new(Capture::default());
    let flags = Flags {
        database_url_env: Some("AWM_DB".into()),
        listen: Some("127.0.0.1:0".into()),
        ..Flags::default()
    };
    let (c, out, err) = cmd(
        flags,
        Command::Run,
        settings_with(&log, Arc::new(SystemClock), envs),
        false,
    )
    .await;
    assert!(
        c == 3 || c == 2,
        "database unusable (3), or no PgStore in this build (2): {c} {err}"
    );
    for text in [&out, &err, &log.text()] {
        assert!(
            !text.contains("hunter2") && !text.contains("127.0.0.1:1/awm"),
            "{text}"
        );
    }
}
