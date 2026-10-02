//! A local Pebble ACME server for the TLS tests (TM15), shared through
//! `#[path = "support/pebble.rs"] mod pebble;`.
//!
//! `PEBBLE_BIN` names the binary. Without it [`Pebble::start`] returns `None` after printing a
//! SKIP line, and the test returns: CI (TM30) sets the variable, so nothing passes silently
//! there. Each Pebble gets a scratch directory with a test CA (made by rcgen), a leaf
//! certificate for `localhost` and `127.0.0.1` signed by it, and a config file; it runs with
//! `PEBBLE_VA_ALWAYS_VALID=1` (no validation connection is made), `PEBBLE_VA_NOSLEEP=1` and
//! `PEBBLE_WFE_NONCEREJECT=0` on free loopback ports, with its output in a log file. Dropping
//! the value kills the process.
//!
//! **Order count**: Pebble logs `Issued certificate serial ... for order ...` once per
//! finalized order on its standard output, which goes to the log file; [`Pebble::issued`]
//! counts those lines. (Its management API has no order list.)

#![allow(dead_code)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub struct Pebble {
    child: Child,
    pub dir: PathBuf,
    pub directory_url: String,
    pub ca_pem: PathBuf,
    pub log_path: PathBuf,
    pub http_port: u16,
    pub tls_port: u16,
    pub mgmt_url: String,
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn scratch(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "pebble-{tag}-{}-{nanos}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// The test CA and a leaf for `localhost` / `127.0.0.1`, written under `dir`.
fn make_certs(dir: &Path) -> PathBuf {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "awm test CA");
    ca_params.distinguished_name = dn;
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
    std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
    std::fs::write(dir.join("leaf.pem"), leaf.pem()).unwrap();
    std::fs::write(dir.join("leaf.key"), leaf_key.serialize_pem()).unwrap();
    dir.join("ca.pem")
}

impl Pebble {
    /// Starts Pebble, or prints `SKIP` and returns `None` when `PEBBLE_BIN` is unset.
    pub fn start(test: &str) -> Option<Pebble> {
        let Some(bin) = std::env::var_os("PEBBLE_BIN") else {
            eprintln!(
                "SKIP {test}: PEBBLE_BIN is not set (CI sets it; this run did not test ACME)"
            );
            return None;
        };
        let dir = scratch("srv");
        let ca_pem = make_certs(&dir);
        let (listen, mgmt, http_port, tls_port) =
            (free_port(), free_port(), free_port(), free_port());
        let config = serde_json::json!({
            "pebble": {
                "listenAddress": format!("127.0.0.1:{listen}"),
                "managementListenAddress": format!("127.0.0.1:{mgmt}"),
                "certificate": dir.join("leaf.pem"),
                "privateKey": dir.join("leaf.key"),
                "httpPort": http_port,
                "tlsPort": tls_port,
                "ocspResponderURL": "",
                "externalAccountBindingRequired": false,
                "profiles": {
                    "default": {
                        "description": "The default profile",
                        "validityPeriod": 7_776_000
                    },
                    "shortlived": {
                        "description": "A short-lived profile",
                        "validityPeriod": 345_600
                    }
                }
            }
        });
        let config_path = dir.join("pebble.json");
        std::fs::write(&config_path, config.to_string()).unwrap();
        let log_path = dir.join("pebble.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let child = Command::new(bin)
            .arg("-config")
            .arg(&config_path)
            .env("PEBBLE_VA_ALWAYS_VALID", "1")
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .env("PEBBLE_AUTHZREUSE", "0")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("cannot start PEBBLE_BIN");
        let p = Pebble {
            child,
            dir,
            directory_url: format!("https://127.0.0.1:{listen}/dir"),
            ca_pem,
            log_path,
            http_port,
            tls_port,
            mgmt_url: format!("https://127.0.0.1:{mgmt}"),
        };
        p.wait_ready();
        Some(p)
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if std::net::TcpStream::connect(
                self.directory_url
                    .trim_start_matches("https://")
                    .trim_end_matches("/dir"),
            )
            .is_ok()
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "Pebble did not start:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    /// Orders Pebble finalized (`Issued certificate serial ...` lines).
    pub fn issued(&self) -> usize {
        self.log()
            .lines()
            .filter(|l| l.contains("Issued certificate serial"))
            .count()
    }

    /// Orders Pebble received (`POST ... /order-plz` request lines or `Added order`).
    pub fn orders_created(&self) -> usize {
        self.log()
            .lines()
            .filter(|l| l.contains("Added order"))
            .count()
    }
}

impl Drop for Pebble {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
