//! A server on a loopback port inside the calling process, for tests of the sync client (TM10).
//!
//! The `awm` crate has no `tokio` dependency (the `sync` feature must not pull one in,
//! `scripts/check.sh` step "no-network (sync)"), so its end-to-end tests cannot start the router
//! themselves. [`spawn`] runs [`super::serve`] on its own runtime in its own thread and hands
//! back the address; [`block_on`] runs one store future (bootstrap tokens, `renew_generation`,
//! snapshots) from synchronous test code.

use std::future::Future;
use std::net::SocketAddr;
use std::thread::JoinHandle;

use super::{router, serve, AppState};

/// A running loopback server. Dropping it stops it.
pub struct Embedded {
    addr: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Embedded {
    /// The address the server listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:{port}`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Stops the server and waits for its thread; in-flight requests finish first.
    pub fn stop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Embedded {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Serves `state` on `127.0.0.1:0`.
pub fn spawn(state: AppState) -> std::io::Result<Embedded> {
    spawn_on("127.0.0.1:0".parse().expect("a socket address"), state)
}

/// Serves `state` on `addr` (port 0 picks a free one).
pub fn spawn_on(addr: SocketAddr, state: AppState) -> std::io::Result<Embedded> {
    let std_listener = std::net::TcpListener::bind(addr)?;
    std_listener.set_nonblocking(true)?;
    let bound = std_listener.local_addr()?;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let thread = std::thread::Builder::new()
        .name("awm-embedded-server".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("a tokio runtime");
            rt.block_on(async move {
                let listener =
                    tokio::net::TcpListener::from_std(std_listener).expect("a tokio listener");
                let _ = serve(listener, router(state), async {
                    let _ = stop_rx.await;
                })
                .await;
            });
        })?;
    Ok(Embedded {
        addr: bound,
        stop: Some(stop_tx),
        thread: Some(thread),
    })
}

/// Runs one future to completion on a fresh current-thread runtime (store calls use
/// `spawn_blocking`, which that runtime provides).
pub fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime")
        .block_on(f)
}
