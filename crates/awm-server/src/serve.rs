//! `awm serve` (plan-v3-team §3.9.2, §4.8.1, TM15): the one-command server and its
//! subcommands, as a library so tests drive it in process and the CLI crate stays thin.
//!
//! [`start`] does what the one command promises, in this order: the file-mode checks, the
//! store (creating `{data}` 0700 and `server.db` 0600 and migrating, or `PgStore`), the
//! bootstrap hash from `AWM_BOOTSTRAP_SHA256` / `AWM_BOOTSTRAP_EXPIRES` while no admin exists,
//! the listeners (TLS with ACME when `--domain` is set, plain HTTP otherwise), retention (an
//! hourly task on a host, inside requests on Cloud Run), the backup runner (or the daily
//! warning). [`run`] adds the commands and the exit codes of §4.8.1:
//! 0 success, 1 runtime error, 2 refused configuration, 3 database unusable, 4 TLS unavailable.
//!
//! Nothing here writes a token, a key, a database URL or record text to a log or an error.

use std::future::Future;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use awm_proto::wire::{Handle, Role, Version};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::auth;
use crate::backup::full::{pg_daily_export, snapshot_now};
use crate::backup::restore::{self, RestoreDest, RestoreRequest, RestoreSource};
use crate::backup::run::{Backup, RunOptions};
use crate::backup::{Clock, SystemClock, Target};
use crate::check::{self, CheckInput, External, Health, HostFacts};
use crate::config::{self, ConfigError, Flags, Resolved, StoreChoice};
use crate::http::{self, AppState, LogSink, StderrLog};
use crate::retention;
use crate::store::sqlite::SqliteStore;
use crate::store::{Store, StoreError};

/// How the process reads its environment.
pub type EnvFn = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The things a test replaces: the clock, the log, the environment, the shutdown grace.
#[derive(Clone)]
pub struct Settings {
    /// This release: `GET /v1/info` `server` and the `min_client` floor.
    pub version: Version,
    pub env: EnvFn,
    pub log: Arc<dyn LogSink>,
    pub clock: Arc<dyn Clock>,
    pub grace: Duration,
}

impl Settings {
    /// The process environment, standard error, the system clock, a 30 s grace.
    pub fn system(version: Version) -> Settings {
        Settings {
            version,
            env: Arc::new(|k| std::env::var(k).ok()),
            log: Arc::new(StderrLog),
            clock: Arc::new(SystemClock),
            grace: http::SHUTDOWN_GRACE,
        }
    }

    fn env(&self, k: &str) -> Option<String> {
        (self.env)(k)
    }

    fn log(&self, line: &str) {
        self.log.line(&format!("serve: {line}"));
    }
}

/// A start that failed, with the exit code of §4.8.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartError {
    pub code: i32,
    pub message: String,
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StartError {}

impl From<ConfigError> for StartError {
    fn from(e: ConfigError) -> StartError {
        StartError {
            code: e.code,
            message: e.message,
        }
    }
}

fn start_err(code: i32, message: impl Into<String>) -> StartError {
    StartError {
        code,
        message: message.into(),
    }
}

fn store_err(e: &StoreError) -> StartError {
    start_err(3, format!("database unusable: {e}"))
}

// ---------------------------------------------------------------------------------------------
// The store

/// Opens the store of `r`: `SqliteStore` (creating the directory and file with their modes and
/// migrating) or `PgStore`'s single self-hosted organisation scope.
pub async fn open_store(r: &Resolved) -> Result<Arc<dyn Store>, StartError> {
    match &r.store {
        StoreChoice::Sqlite { data } => {
            let data = data.clone();
            let store = tokio::task::spawn_blocking(move || SqliteStore::open(&data))
                .await
                .map_err(|_| start_err(1, "the store task failed"))?
                .map_err(|e| store_err(&e))?;
            Ok(Arc::new(store))
        }
        StoreChoice::Postgres { url, owner_url } => {
            open_pg(url.expose(), owner_url.as_ref().map(config::Secret::expose)).await
        }
    }
}

#[cfg(feature = "pg")]
async fn open_pg(url: &str, owner: Option<&str>) -> Result<Arc<dyn Store>, StartError> {
    use crate::store::pg::PgStore;
    let pg = PgStore::connect(url, owner, 10)
        .await
        .map_err(|e| store_err(&e))?;
    use awm_proto::wire::Id;
    let scope = Id::parse(crate::config::SELF_HOST_SCOPE).map_err(|_| start_err(1, "bad scope"))?;
    pg.create_org(scope).await.map_err(|e| store_err(&e))
}

#[cfg(not(feature = "pg"))]
async fn open_pg(_url: &str, _owner: Option<&str>) -> Result<Arc<dyn Store>, StartError> {
    Err(start_err(2, "this build has no PgStore (feature pg)"))
}

// ---------------------------------------------------------------------------------------------
// Start

/// A running server.
pub struct Server {
    /// The addresses the API listens on (TLS when [`Resolved::domain`] is set).
    pub addrs: Vec<SocketAddr>,
    /// The HTTP-01 listener, when the challenge is `http-01`.
    pub http01_addr: Option<SocketAddr>,
    pub state: AppState,
    pub store: Arc<dyn Store>,
    /// The ACME client when this binary terminates TLS.
    #[cfg(feature = "acme")]
    pub acme: Option<Arc<crate::tls::Acme>>,
    /// The backup runner (`SqliteStore` with `--backup`).
    pub backup: Option<Arc<Backup>>,
    /// The bootstrap hash of `AWM_BOOTSTRAP_SHA256` was installed at start.
    pub bootstrap_installed: bool,
    /// There was no organisation at start.
    pub no_admin: bool,
    shutdown: watch::Sender<bool>,
    tasks: Vec<(&'static str, JoinHandle<()>)>,
}

impl Server {
    /// Asks every task to stop, waits for in-flight requests (up to the grace), and returns.
    pub async fn stop(self, grace: Duration) {
        let _ = self.shutdown.send(true);
        for (_, t) in self.tasks {
            let _ = tokio::time::timeout(grace + Duration::from_secs(5), t).await;
        }
    }

    /// The future the tasks wait on.
    pub fn signal(&self) -> impl Future<Output = ()> + Send + 'static {
        wait(self.shutdown.subscribe())
    }
}

async fn wait(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Binds `addrs`. The IPv6 wildcard goes first (on most systems it also takes IPv4); an address
/// that cannot be bound is skipped as long as one is.
async fn bind_all(addrs: &[SocketAddr]) -> Result<Vec<TcpListener>, StartError> {
    let mut ordered: Vec<SocketAddr> = addrs.to_vec();
    ordered.sort_by_key(|a| !a.is_ipv6());
    let mut bound = Vec::new();
    let mut first_err = None;
    for a in ordered {
        match TcpListener::bind(a).await {
            Ok(l) => bound.push(l),
            Err(e) => {
                first_err.get_or_insert((a, e.kind()));
            }
        }
    }
    if bound.is_empty() {
        let (a, k) = first_err.unwrap_or((
            "0.0.0.0:0".parse().unwrap_or_else(|_| unreachable!()),
            std::io::ErrorKind::Other,
        ));
        return Err(start_err(1, format!("cannot listen on {a}: {k}")));
    }
    Ok(bound)
}

fn spawn_named<F>(tasks: &mut Vec<(&'static str, JoinHandle<()>)>, name: &'static str, f: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    tasks.push((name, tokio::spawn(f)));
}

/// The scratch directory for exports and verification: private, below the temp directory.
fn private_scratch(tag: &str) -> Result<PathBuf, StartError> {
    let dir = std::env::temp_dir().join(format!("awm-{tag}-{}", std::process::id()));
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(&dir)
        .map_err(|e| start_err(1, format!("cannot create {}: {}", dir.display(), e.kind())))?;
    Ok(dir)
}

/// Installs `AWM_BOOTSTRAP_SHA256` / `AWM_BOOTSTRAP_EXPIRES` (path A) while no admin exists.
async fn install_bootstrap_env(
    store: &dyn Store,
    s: &Settings,
    now: i64,
) -> Result<bool, StartError> {
    let hash = s.env("AWM_BOOTSTRAP_SHA256").filter(|v| !v.is_empty());
    let expires = s.env("AWM_BOOTSTRAP_EXPIRES").filter(|v| !v.is_empty());
    let (hash, expires) = match (hash, expires) {
        (None, None) => return Ok(false),
        (Some(h), Some(e)) => (h, e),
        _ => {
            return Err(start_err(
                2,
                "AWM_BOOTSTRAP_SHA256 and AWM_BOOTSTRAP_EXPIRES go together",
            ))
        }
    };
    let expires: i64 = expires
        .trim()
        .parse()
        .map_err(|_| start_err(2, "AWM_BOOTSTRAP_EXPIRES is not Unix seconds"))?;
    match auth::install_bootstrap_hash(store, hash.trim(), expires, now).await {
        Ok(installed) => Ok(installed),
        Err(auth::AuthError::Store(StoreError::InvalidValue { .. })) => Err(start_err(
            2,
            "AWM_BOOTSTRAP_SHA256 is not 64 lower-case hex characters",
        )),
        Err(e) => Err(start_err(
            3,
            format!("cannot install the bootstrap hash: {e}"),
        )),
    }
}

/// Starts the server for `r`. On return the listeners are bound, the store is open and (with
/// `--domain`) a certificate is installed.
pub async fn start(r: &Resolved, s: &Settings) -> Result<Server, StartError> {
    config::verify_files(r)?;
    let store = open_store(r).await?;
    let now = s.clock.now();
    let bootstrap_installed = install_bootstrap_env(&*store, s, now).await?;
    let no_admin = store.org(now).await.map_err(|e| store_err(&e))?.is_none();

    // --- the HTTP state --------------------------------------------------------------------
    let mut cfg = r.server_config(s.version.clone(), s.version.clone());
    if let Some(d) = r.data_dir() {
        cfg.export_dir = d.to_path_buf();
    }
    let clock_fn = {
        let c = s.clock.clone();
        Arc::new(move || c.now())
    };
    let state = AppState::new(store.clone(), cfg)
        .with_clock(clock_fn)
        .with_log_sink(s.log.clone())
        .with_retention_runner(Arc::new(retention::runner_with_clock(
            store.clone(),
            s.clock.clone(),
        )));
    let router = http::router(state.clone());

    let (tx, _rx) = watch::channel(false);
    let mut server = Server {
        addrs: Vec::new(),
        http01_addr: None,
        state,
        store: store.clone(),
        #[cfg(feature = "acme")]
        acme: None,
        backup: None,
        bootstrap_installed,
        no_admin,
        shutdown: tx,
        tasks: Vec::new(),
    };

    match serve_listeners(r, s, &mut server, router).await {
        Ok(()) => {}
        Err(e) => {
            server.stop(Duration::from_secs(1)).await;
            return Err(e);
        }
    }

    // --- retention, backup ------------------------------------------------------------------
    if !r.request_time_retention {
        let (st, sc, log, rx) = (
            store.clone(),
            s.clock.clone(),
            s.clone(),
            server.shutdown.subscribe(),
        );
        spawn_named(
            &mut server.tasks,
            "retention",
            retention_loop(st, sc, log, wait(rx)),
        );
    }
    if let Err(e) = start_backup(r, s, &mut server).await {
        server.stop(Duration::from_secs(1)).await;
        return Err(e);
    }
    if no_admin && !bootstrap_installed {
        // The caller decides whether a terminal gets a token; a log line otherwise.
    }
    Ok(server)
}

async fn serve_listeners(
    r: &Resolved,
    s: &Settings,
    server: &mut Server,
    router: axum::Router,
) -> Result<(), StartError> {
    let grace = s.grace;
    let listeners = bind_all(&r.listen).await?;
    server.addrs = listeners
        .iter()
        .filter_map(|l| l.local_addr().ok())
        .collect();
    if r.domain.is_none() {
        for l in listeners {
            let fut = wait(server.shutdown.subscribe());
            let router = router.clone();
            let log = s.clone();
            spawn_named(&mut server.tasks, "http", async move {
                if let Err(e) = http::serve_with_grace(l, router, fut, grace).await {
                    log.log(&format!("listener stopped: {}", e.kind()));
                }
            });
        }
        s.log(&format!(
            "listening on {} (plain HTTP{})",
            addr_list(&server.addrs),
            if r.behind_tls_proxy {
                ", behind a TLS proxy"
            } else {
                ""
            }
        ));
        return Ok(());
    }
    serve_tls_listeners(r, s, server, router, listeners).await
}

fn addr_list(a: &[SocketAddr]) -> String {
    a.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(not(feature = "acme"))]
async fn serve_tls_listeners(
    _r: &Resolved,
    _s: &Settings,
    _server: &mut Server,
    _router: axum::Router,
    _listeners: Vec<TcpListener>,
) -> Result<(), StartError> {
    Err(start_err(
        2,
        "this build has no built-in TLS (feature acme): use --behind-tls-proxy",
    ))
}

#[cfg(feature = "acme")]
async fn serve_tls_listeners(
    r: &Resolved,
    s: &Settings,
    server: &mut Server,
    router: axum::Router,
    listeners: Vec<TcpListener>,
) -> Result<(), StartError> {
    use crate::tls::acme::{Acme, AcmeParams, Http01Tokens};
    use crate::tls::alpn::{server_config, CertSlot, TlsListener};
    use crate::tls::cache::{AcmeCache, CacheError};
    use crate::tls::serve::{http01_router, serve_tls};

    let (Some(domain), Some(settings), Some(dir)) = (&r.domain, &r.acme, r.acme_dir()) else {
        return Err(start_err(2, "TLS needs --domain and --data"));
    };
    let cache = AcmeCache::open(&dir).map_err(|e| match e {
        CacheError::Permissions(m) => start_err(2, m),
        CacheError::Io(m) => start_err(1, m),
    })?;
    let slot = CertSlot::new();
    let tls_config = server_config(slot.clone()).map_err(|m| start_err(1, m))?;
    let tls_listener = TlsListener::new(listeners, tls_config)
        .map_err(|e| start_err(1, format!("tls listener: {}", e.kind())))?;
    let grace = s.grace;
    let fut = wait(server.shutdown.subscribe());
    let log = s.clone();
    spawn_named(&mut server.tasks, "https", async move {
        if let Err(e) = serve_tls(tls_listener, router, fut, grace).await {
            log.log(&format!("tls listener stopped: {}", e.kind()));
        }
    });

    let tokens = Http01Tokens::new();
    if let Some(addr) = r.http01_listen {
        let l = TcpListener::bind(addr)
            .await
            .map_err(|e| start_err(1, format!("cannot listen on {addr}: {}", e.kind())))?;
        server.http01_addr = l.local_addr().ok();
        let app = http01_router(tokens.clone(), domain.clone());
        let fut = wait(server.shutdown.subscribe());
        spawn_named(&mut server.tasks, "http-01", async move {
            let _ = axum::serve(l, app).with_graceful_shutdown(fut).await;
        });
    }

    let acme = Arc::new(Acme::new(
        AcmeParams {
            identifier: domain.clone(),
            directory: settings.directory.clone(),
            ca_file: settings.ca_file.clone(),
            email: settings.email.clone(),
            challenge: settings.challenge,
        },
        cache,
        s.clock.clone(),
        slot.clone(),
        tokens,
    ));
    match acme.start().await {
        Ok(cached) => s.log(&format!(
            "tls: certificate for {} ({})",
            domain.name(),
            if cached { "from the cache" } else { "ordered" }
        )),
        Err(e) if slot.has_certificate() => {
            s.log(&format!("tls: the cached certificate stays in use; {e}"));
        }
        Err(e) => {
            return Err(start_err(
                4,
                format!("TLS unavailable: no cached certificate and the ACME order failed: {e}"),
            ))
        }
    }
    let (a, rx) = (acme.clone(), server.shutdown.subscribe());
    spawn_named(&mut server.tasks, "acme", async move {
        a.run(wait(rx)).await;
    });
    server.acme = Some(acme);
    s.log(&format!("listening on {} (TLS)", addr_list(&server.addrs)));
    Ok(())
}

/// The hourly retention task of a host. Unlike `retention::hourly` it logs each run and each
/// failure (TM9 P3).
async fn retention_loop<F>(store: Arc<dyn Store>, clock: Arc<dyn Clock>, s: Settings, shutdown: F)
where
    F: Future<Output = ()> + Send,
{
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let now = clock.now();
        let wait_s = match retention::run(&*store, now).await {
            Ok(Some(r)) => {
                s.log(&format!(
                    "retention removed={} batches={}",
                    r.deleted, r.batches
                ));
                retention::INTERVAL_S as u64
            }
            Ok(None) => match retention::last_retention(&*store).await {
                Ok(Some(last)) if !retention::due(Some(last), now) => {
                    (last + retention::INTERVAL_S - now).max(1) as u64
                }
                _ => retention::INTERVAL_S as u64,
            },
            Err(e) => {
                s.log(&format!("retention failed: {e}"));
                retention::RETRY_AFTER_ERROR_S
            }
        };
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = clock.sleep(wait_s) => {}
        }
    }
}

const NO_BACKUP_WARNING: &str = "WARNING: no --backup target: a disk loss destroys membership, \
invites, key wraps and every record no member still holds; set --backup gs://... \
(docs/self-host.md#backup)";

async fn start_backup(r: &Resolved, s: &Settings, server: &mut Server) -> Result<(), StartError> {
    let Some(url) = &r.backup else {
        // No target: a warning now and every day.
        s.log(NO_BACKUP_WARNING);
        let (clock, log, rx) = (s.clock.clone(), s.clone(), server.shutdown.subscribe());
        spawn_named(&mut server.tasks, "backup-warning", async move {
            let shutdown = wait(rx);
            let mut shutdown = std::pin::pin!(shutdown);
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown => break,
                    _ = clock.sleep(86_400) => log.log(NO_BACKUP_WARNING),
                }
            }
        });
        return Ok(());
    };
    let target = Target::parse(url).map_err(|e| start_err(2, format!("--backup: {e}")))?;
    let bucket = target
        .open()
        .map_err(|e| start_err(2, format!("--backup: {e}")))?;
    match &r.store {
        StoreChoice::Sqlite { data } => {
            let log = s.clone();
            let mut opts = RunOptions::new(data);
            opts.on_event = Some(Arc::new(move |e| log.log(&e.to_string())));
            let backup = Backup::new(server.store.clone(), bucket, s.clock.clone(), opts);
            let (b, rx) = (backup.clone(), server.shutdown.subscribe());
            spawn_named(&mut server.tasks, "backup", async move {
                let _ = b.run(wait(rx)).await;
            });
            server.backup = Some(backup);
            s.log(&format!("backup to {target} started"));
        }
        StoreChoice::Postgres { .. } => {
            let scratch = private_scratch("export")?;
            let (store, clock, log, rx) = (
                server.store.clone(),
                s.clock.clone(),
                s.clone(),
                server.shutdown.subscribe(),
            );
            spawn_named(&mut server.tasks, "backup", async move {
                let shutdown = wait(rx);
                let mut shutdown = std::pin::pin!(shutdown);
                loop {
                    match pg_daily_export(&*store, &*bucket, &*clock, &scratch).await {
                        Ok(Some(up)) => log.log(&format!("backup: exported {}", up.key)),
                        Ok(None) => {}
                        Err(e) => log.log(&format!("backup failed: {e}")),
                    }
                    tokio::select! {
                        biased;
                        _ = &mut shutdown => break,
                        _ = clock.sleep(3_600) => {}
                    }
                }
            });
            s.log(&format!("daily export to {target} started"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Commands

/// The subcommands of `awm serve` (§4.8.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `awm serve`: run the server.
    Run,
    Init {
        print_hash: bool,
    },
    Check {
        json: bool,
        external: bool,
    },
    Backup {
        to: Option<String>,
        verify: bool,
    },
    Restore {
        from: Option<String>,
        at: Option<String>,
        force: bool,
        mark_restored: bool,
    },
    Promote {
        handle: String,
    },
    Healthcheck {
        url: Option<String>,
    },
}

/// What the CLI hands over.
pub struct Invocation {
    pub flags: Flags,
    pub command: Command,
    pub settings: Settings,
}

/// Where a command prints. `tty` is whether standard output is a terminal.
pub struct Io<'a> {
    pub out: &'a mut (dyn Write + Send),
    pub err: &'a mut (dyn Write + Send),
    pub tty: bool,
}

/// Runs `inv` on a runtime of its own and returns the process exit code.
pub fn run(inv: Invocation, io: &mut Io<'_>) -> i32 {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(io.err, "awm serve: cannot start the runtime: {}", e.kind());
            return 1;
        }
    };
    rt.block_on(run_async(inv, io))
}

/// [`run`] on the caller's runtime.
pub async fn run_async(inv: Invocation, io: &mut Io<'_>) -> i32 {
    let Invocation {
        flags,
        command,
        settings,
    } = inv;
    let code = match command {
        Command::Run => cmd_run(&flags, &settings, io).await,
        Command::Init { print_hash } => cmd_init(&flags, print_hash, &settings, io).await,
        Command::Check { json, external } => cmd_check(&flags, json, external, &settings, io).await,
        Command::Backup { to, verify } => cmd_backup(&flags, to, verify, &settings, io).await,
        Command::Restore {
            from,
            at,
            force,
            mark_restored,
        } => cmd_restore(&flags, from, at, force, mark_restored, &settings, io).await,
        Command::Promote { handle } => cmd_promote(&flags, &handle, &settings, io).await,
        Command::Healthcheck { url } => cmd_healthcheck(&flags, url, &settings, io).await,
    };
    match code {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(io.err, "awm serve: {}", e.message);
            e.code
        }
    }
}

type CmdResult = Result<i32, StartError>;

fn resolve(flags: &Flags, s: &Settings) -> Result<Resolved, StartError> {
    let env = s.env.clone();
    config::resolve(flags, &move |k| env(k)).map_err(StartError::from)
}

async fn cmd_run(flags: &Flags, s: &Settings, io: &mut Io<'_>) -> CmdResult {
    let r = resolve(flags, s)?;
    // Install the handlers first: a SIGTERM during the (long) start is held, not fatal.
    let signals = Signals::install().map_err(|e| start_err(1, format!("signals: {}", e.kind())))?;
    let server = start(&r, s).await?;
    if server.no_admin && !server.bootstrap_installed {
        announce_bootstrap(&*server.store, s, io).await;
    }
    signals.wait().await;
    s.log("shutting down");
    server.stop(s.grace).await;
    Ok(0)
}

/// With no admin yet: a terminal gets a fresh bootstrap token; anything else gets one log line,
/// so a token never lands in a journal or a container log.
async fn announce_bootstrap(store: &dyn Store, s: &Settings, io: &mut Io<'_>) {
    if !io.tty {
        s.log("no admin yet: run `awm serve init`");
        return;
    }
    match auth::issue_bootstrap(store, s.clock.now()).await {
        Ok(t) => {
            let _ = writeln!(
                io.out,
                "no admin yet. One-time bootstrap token (valid 24 h, shown once):\n  {}",
                t.as_str()
            );
        }
        Err(_) => s.log("no admin yet: run `awm serve init`"),
    }
}

/// SIGTERM and SIGINT (Ctrl-C), installed before the server starts.
#[cfg(unix)]
struct Signals {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl Signals {
    fn install() -> std::io::Result<Signals> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Signals {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
        })
    }

    async fn wait(mut self) {
        tokio::select! {
            _ = self.term.recv() => {}
            _ = self.int.recv() => {}
        }
    }
}

#[cfg(not(unix))]
struct Signals;

#[cfg(not(unix))]
impl Signals {
    fn install() -> std::io::Result<Signals> {
        Ok(Signals)
    }

    async fn wait(self) {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn cmd_init(flags: &Flags, print_hash: bool, s: &Settings, io: &mut Io<'_>) -> CmdResult {
    let now = s.clock.now();
    if print_hash {
        // No database, no configuration: a token, its hash and its expiry.
        let t = auth::new_bootstrap_token().map_err(|e| start_err(1, e.to_string()))?;
        let _ = writeln!(io.out, "bootstrap token: {}", t.as_str());
        let _ = writeln!(io.out, "AWM_BOOTSTRAP_SHA256={}", auth::hash(t.as_str()));
        let _ = writeln!(
            io.out,
            "AWM_BOOTSTRAP_EXPIRES={}",
            now + auth::BOOTSTRAP_TTL_S
        );
        let _ = writeln!(
            io.err,
            "keep the token; the server needs only the two AWM_BOOTSTRAP_* values"
        );
        return Ok(0);
    }
    let r = resolve(flags, s)?;
    let store = open_store(&r).await?;
    if store.org(now).await.map_err(|e| store_err(&e))?.is_some() {
        return Err(start_err(
            1,
            "this server already has an admin; add more with `awm serve promote HANDLE`",
        ));
    }
    if !io.tty {
        s.log(
            "no admin yet: run `awm serve init` in a terminal (or `awm serve init --print-hash`)",
        );
        return Ok(0);
    }
    let t = auth::issue_bootstrap(&*store, now)
        .await
        .map_err(|e| start_err(1, e.to_string()))?;
    let _ = writeln!(io.out, "database ready");
    let _ = writeln!(
        io.out,
        "bootstrap token (single use, valid 24 h, shown once):\n  {}",
        t.as_str()
    );
    let _ = writeln!(
        io.out,
        "next: awm team create URL --token <the token> --handle YOURNAME"
    );
    Ok(0)
}

async fn cmd_promote(flags: &Flags, handle: &str, s: &Settings, io: &mut Io<'_>) -> CmdResult {
    let handle = Handle::parse(handle.trim_start_matches('@'))
        .map_err(|_| start_err(2, "a handle is 1-24 characters of a-z, 0-9, _ and -"))?;
    let r = resolve(flags, s)?;
    let store = open_store(&r).await?;
    let now = s.clock.now();
    let member = store
        .member_by_handle(handle.clone())
        .await
        .map_err(|e| store_err(&e))?
        .ok_or_else(|| start_err(1, format!("no member @{}", handle.as_str())))?;
    store
        .set_role(member.member_id, Role::Admin, None, now)
        .await
        .map_err(|e| start_err(1, format!("cannot promote: {e}")))?;
    let _ = writeln!(io.out, "@{} is an admin", handle.as_str());
    Ok(0)
}

async fn local_health(r: &Resolved) -> Health {
    let url = health_url(r);
    match http_get(&url, r).await {
        Ok(status) => Health::Status(status),
        Err(e) => Health::Unreachable(e),
    }
}

/// `/healthz` on the first listener, with a wildcard address read as loopback.
fn health_url(r: &Resolved) -> String {
    let addr = r
        .listen
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| r.listen.first())
        .copied()
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8787)));
    let ip: std::net::IpAddr = if addr.ip().is_unspecified() {
        if addr.is_ipv6() {
            std::net::Ipv6Addr::LOCALHOST.into()
        } else {
            std::net::Ipv4Addr::LOCALHOST.into()
        }
    } else {
        addr.ip()
    };
    let host = match ip {
        std::net::IpAddr::V6(v) => format!("[{v}]"),
        std::net::IpAddr::V4(v) => v.to_string(),
    };
    let scheme = if r.terminates_tls() { "https" } else { "http" };
    format!("{scheme}://{host}:{}/healthz", addr.port())
}

async fn cmd_healthcheck(
    flags: &Flags,
    url: Option<String>,
    s: &Settings,
    io: &mut Io<'_>,
) -> CmdResult {
    // The URL: --url, else the local listener of the configuration, else the default address.
    let resolved = resolve(flags, s).ok();
    let url = url.unwrap_or_else(|| match &resolved {
        Some(r) => health_url(r),
        None => "http://127.0.0.1:8787/healthz".to_string(),
    });
    let dummy = Resolved {
        store: StoreChoice::Sqlite {
            data: PathBuf::new(),
        },
        domain: None,
        listen: Vec::new(),
        http01_listen: None,
        acme: None,
        behind_tls_proxy: false,
        trusted_proxies: Vec::new(),
        cloud_run: false,
        request_time_retention: false,
        backup: None,
        config_file: None,
        overrides: config::Overrides::default(),
        internal_token_hash: None,
    };
    match http_get(&url, resolved.as_ref().unwrap_or(&dummy)).await {
        Ok(200) => {
            let _ = writeln!(io.out, "ok");
            Ok(0)
        }
        Ok(code) => {
            let _ = writeln!(io.err, "unhealthy: /healthz answered {code}");
            Ok(1)
        }
        Err(e) => {
            let _ = writeln!(io.err, "unhealthy: {e}");
            Ok(1)
        }
    }
}

/// `GET url`, the status code. `http://` always; `https://` needs the `acme` build and, on a
/// loopback address, skips certificate verification (the listener is this host's own).
async fn http_get(url: &str, r: &Resolved) -> Result<u16, String> {
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err("the URL must start with http:// or https://".into());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (
            h.trim_matches(['[', ']']),
            p.parse::<u16>().map_err(|_| "bad port".to_string())?,
        ),
        _ => (
            authority.trim_matches(['[', ']']),
            if https { 443 } else { 80 },
        ),
    };
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {authority}\r\nUser-Agent: awm-serve\r\nConnection: close\r\n\r\n"
    );
    let work = async {
        let tcp = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|e| format!("cannot connect: {}", e.kind()))?;
        let raw: Vec<u8> = if https {
            #[cfg(feature = "acme")]
            {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut raw = Vec::new();
                let mut tls = tls_connect(tcp, host, r).await?;
                tls.write_all(request.as_bytes())
                    .await
                    .map_err(|e| format!("write: {}", e.kind()))?;
                let _ = (&mut tls).take(8192).read_to_end(&mut raw).await;
                raw
            }
            #[cfg(not(feature = "acme"))]
            {
                let _ = (tcp, r);
                return Err("this build has no TLS client".to_string());
            }
        } else {
            use std::io::{Read, Write};
            let _ = r;
            // Plain HTTP over a blocking std stream: the `sqlite`-only build has no tokio io-util.
            let mut tcp = tcp
                .into_std()
                .map_err(|e| format!("socket: {}", e.kind()))?;
            let request = request.clone();
            tokio::task::spawn_blocking(move || {
                tcp.set_nonblocking(false)
                    .map_err(|e| format!("socket: {}", e.kind()))?;
                tcp.set_read_timeout(Some(Duration::from_secs(9))).ok();
                tcp.write_all(request.as_bytes())
                    .map_err(|e| format!("write: {}", e.kind()))?;
                let mut raw = Vec::new();
                let _ = (&mut tcp).take(8192).read_to_end(&mut raw);
                Ok::<_, String>(raw)
            })
            .await
            .map_err(|_| "healthcheck task failed".to_string())??
        };
        let text = String::from_utf8_lossy(&raw);
        text.lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| "no HTTP status in the answer".to_string())
    };
    tokio::time::timeout(Duration::from_secs(10), work)
        .await
        .unwrap_or_else(|_| Err("timed out".into()))
}

#[cfg(feature = "acme")]
async fn tls_connect(
    tcp: tokio::net::TcpStream,
    host: &str,
    r: &Resolved,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
    use rustls::pki_types::ServerName;
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("tls: {e}"))?;
    let cfg = if loopback {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(LoopbackOnly))
            .with_no_client_auth()
    } else {
        let ca = r.acme.as_ref().and_then(|a| a.ca_file.as_deref());
        builder
            .with_root_certificates(crate::tls::acme::root_store(ca))
            .with_no_client_auth()
    };
    let name = ServerName::try_from(host.to_string()).map_err(|_| "bad host name".to_string())?;
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .map_err(|e| format!("tls handshake: {}", e.kind()))
}

/// Accepts any certificate. Used only for `/healthz` on a loopback address of this host.
#[cfg(feature = "acme")]
#[derive(Debug)]
struct LoopbackOnly;

#[cfg(feature = "acme")]
impl rustls::client::danger::ServerCertVerifier for LoopbackOnly {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn cmd_check(
    flags: &Flags,
    json: bool,
    external: bool,
    s: &Settings,
    io: &mut Io<'_>,
) -> CmdResult {
    let r = resolve(flags, s)?;
    if let StoreChoice::Sqlite { data } = &r.store {
        if !data.join("server.db").is_file() {
            // Nothing to open: report it without creating the database.
            return check_missing_database(&r, json, s, io);
        }
    }
    let store = open_store(&r).await?;
    let now = s.clock.now();
    let health = local_health(&r).await;
    let external = if external {
        Some(external_check(&r).await)
    } else {
        None
    };
    let input = CheckInput {
        resolved: r.clone(),
        store,
        now,
        version: s.version.to_string(),
        release_floor: s.version.clone(),
        env: std::env::vars().collect(),
        facts: HostFacts::collect(r.data_dir()),
        health,
        external,
    };
    let report = check::run(&input).await;
    print_report(&report, json, io);
    Ok(report.exit_code())
}

fn check_missing_database(r: &Resolved, json: bool, s: &Settings, io: &mut Io<'_>) -> CmdResult {
    let data = r
        .data_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    let report = check::Report {
        header: format!(
            "awm serve check  (awm {}, proto {}, store sqlite {data}/server.db)",
            s.version,
            awm_proto::wire::PROTOCOL_VERSION
        ),
        lines: vec![check::Line {
            level: check::Level::Fail,
            name: "database",
            text: format!("no database at {data}/server.db: run awm serve init"),
        }],
    };
    print_report(&report, json, io);
    Ok(report.exit_code())
}

fn print_report(report: &check::Report, json: bool, io: &mut Io<'_>) {
    if json {
        let _ = writeln!(io.out, "{}", report.to_json());
    } else {
        let _ = write!(io.out, "{}", report.render());
    }
}

/// `--external`: `GET https://DOMAIN/v1/info` from this host.
async fn external_check(r: &Resolved) -> External {
    let Some(domain) = &r.domain else {
        return External {
            url: "(no --domain)".into(),
            result: Err("--external needs --domain: the public name of this server".into()),
        };
    };
    let port = r.listen.first().map_or(443, |a| a.port());
    let host = match domain {
        config::Domain::Dns(d) => d.clone(),
        config::Domain::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
        config::Domain::Ip(ip) => ip.to_string(),
    };
    let url = if port == 443 {
        format!("https://{host}/v1/info")
    } else {
        format!("https://{host}:{port}/v1/info")
    };
    External {
        result: external_get(&url, r).await,
        url,
    }
}

#[cfg(feature = "acme")]
async fn external_get(url: &str, r: &Resolved) -> Result<String, String> {
    let ca = r.acme.as_ref().and_then(|a| a.ca_file.as_deref());
    let roots = crate::tls::acme::root_store(ca);
    let resp = crate::tls::acme::https_get(url, &roots)
        .await
        .map_err(|e| e.to_string())?;
    if resp.status != 200 {
        return Err(format!("HTTP {}", resp.status));
    }
    let v: serde_json::Value =
        serde_json::from_slice(&resp.body).map_err(|_| "not JSON".to_string())?;
    let protocols = v["protocols"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_u64().map(|n| n.to_string()))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    Ok(format!(
        "server {}, protocols {protocols}",
        v["server"].as_str().unwrap_or("?")
    ))
}

#[cfg(not(feature = "acme"))]
async fn external_get(_url: &str, _r: &Resolved) -> Result<String, String> {
    Err("this build has no TLS client".into())
}

async fn cmd_backup(
    flags: &Flags,
    to: Option<String>,
    verify: bool,
    s: &Settings,
    io: &mut Io<'_>,
) -> CmdResult {
    let r = resolve(flags, s)?;
    let target_text = to
        .or_else(|| r.backup.clone())
        .ok_or_else(|| start_err(2, "no backup target: give --to URL or set --backup"))?;
    let store = open_store(&r).await?;
    let now = s.clock.now();
    let scratch = match r.data_dir() {
        Some(d) => d.to_path_buf(),
        None => private_scratch("backup")?,
    };
    let fail = |e: crate::backup::BackupError| start_err(e.exit_code(), e.to_string());
    if !target_text.contains("://") {
        // A file: the canonical export (§4.2).
        let path = PathBuf::from(&target_text);
        let counts = store
            .export_canonical(path.clone())
            .await
            .map_err(|e| start_err(1, format!("export failed: {e}")))?;
        let _ = writeln!(io.out, "exported {}", path.display());
        for (t, n) in &counts.0 {
            let _ = writeln!(io.out, "  {t}: {n}");
        }
        return Ok(0);
    }
    let target = Target::parse(&target_text).map_err(|e| start_err(2, format!("--to: {e}")))?;
    let bucket = target
        .open()
        .map_err(|e| start_err(2, format!("--to: {e}")))?;
    let up = snapshot_now(&*store, &*bucket, now, &scratch)
        .await
        .map_err(fail)?;
    let _ = writeln!(
        io.out,
        "{} {}",
        if up.reused {
            "already stored:"
        } else {
            "uploaded:"
        },
        up.key
    );
    if verify {
        let report = restore::verify(&*store, &*bucket, now, &scratch)
            .await
            .map_err(fail)?;
        let _ = writeln!(io.out, "verify ok: {}", report.summary());
    }
    Ok(0)
}

fn parse_at(text: &str) -> Result<i64, StartError> {
    if let Ok(n) = text.parse::<i64>() {
        return Ok(n);
    }
    #[cfg(feature = "acme")]
    if let Some(t) = crate::tls::acme::rfc3339(text) {
        return Ok(t);
    }
    Err(start_err(
        2,
        "--at takes Unix seconds or an RFC 3339 time such as 2026-10-02T14:00:00Z",
    ))
}

async fn cmd_restore(
    flags: &Flags,
    from: Option<String>,
    at: Option<String>,
    force: bool,
    mark_restored: bool,
    s: &Settings,
    io: &mut Io<'_>,
) -> CmdResult {
    let r = resolve(flags, s)?;
    let now = s.clock.now();
    let at = at.as_deref().map(parse_at).transpose()?;
    let source = match (&from, mark_restored) {
        (Some(f), false) => {
            RestoreSource::parse(f).map_err(|e| start_err(e.exit_code(), e.to_string()))?
        }
        (None, true) => RestoreSource::None,
        (Some(_), true) => {
            return Err(start_err(2, "--mark-restored takes no --from"));
        }
        (None, false) => return Err(start_err(2, "give --from URL|FILE (or --mark-restored)")),
    };
    let dest = match &r.store {
        StoreChoice::Sqlite { data } => RestoreDest::Data(data.clone()),
        StoreChoice::Postgres { .. } => RestoreDest::Store {
            store: open_store(&r).await?,
            scratch: private_scratch("restore")?,
        },
    };
    let report = restore::run(RestoreRequest {
        source,
        dest,
        at,
        force,
        mark_restored,
        now,
    })
    .await
    .map_err(|e| start_err(e.exit_code(), e.to_string()))?;
    let _ = writeln!(io.out, "restored; new generation {}", report.generation);
    if let Some(g) = report.restored_from {
        let _ = writeln!(io.out, "  from generation {g}");
    }
    if let Some(t) = report.point_in_time {
        let _ = writeln!(io.out, "  point in time {} UTC", check::fmt_utc(t));
    }
    let _ = writeln!(io.out, "  objects applied: {}", report.objects.len());
    for (t, n) in &report.counts {
        let _ = writeln!(io.out, "  {t}: {n}");
    }
    if let Some(p) = &report.pre_restore {
        let _ = writeln!(io.out, "  previous database kept as {}", p.display());
    }
    let _ = writeln!(
        io.out,
        "an admin must run `awm sync` now: removals made after the backup point are not in \
         force until an admin client has synced"
    );
    Ok(0)
}

/// For tests and the CLI: the path of `server.db` in `data`.
pub fn db_path(data: &Path) -> PathBuf {
    data.join(crate::store::sqlite::DB_FILE)
}
