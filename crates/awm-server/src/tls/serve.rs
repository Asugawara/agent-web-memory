//! The two ways to serve: [`serve_tls`] for the API on the TLS listener and [`http01_router`]
//! for the opt-in port-80 listener, which answers only `/.well-known/acme-challenge/{token}`
//! and redirects everything else to HTTPS (plan-v3-team §3.9.3).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::serve::ListenerExt;
use axum::Router;

use super::acme::Http01Tokens;
use super::alpn::TlsListener;
use crate::config::Domain;

/// Serves `router` on `listener` over TLS until `shutdown` resolves, then lets in-flight
/// requests finish for at most `grace` (the TLS twin of `http::serve_with_grace`; the peer
/// address reaches the handlers as `ConnectInfo<SocketAddr>`).
pub async fn serve_tls(
    listener: TlsListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
    grace: Duration,
) -> std::io::Result<()> {
    let listener = listener.tap_io(|_| {});
    let (signalled_tx, signalled_rx) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown.await;
        let _ = signalled_tx.send(());
    });
    tokio::select! {
        r = server => r,
        _ = async {
            let _ = signalled_rx.await;
            tokio::time::sleep(grace).await;
        } => Ok(()),
    }
}

#[derive(Clone)]
struct Http01State {
    tokens: Arc<Http01Tokens>,
    domain: Domain,
}

/// The router of the port-80 listener of `--acme-challenge http-01`: challenge tokens and
/// redirects, no API (§3.9.3).
pub fn http01_router(tokens: Arc<Http01Tokens>, domain: Domain) -> Router {
    Router::new()
        .route("/.well-known/acme-challenge/{token}", get(challenge))
        .fallback(redirect)
        .with_state(Http01State { tokens, domain })
}

async fn challenge(State(s): State<Http01State>, Path(token): Path<String>) -> Response {
    match s.tokens.get(&token) {
        Some(key_authorization) => {
            let mut r = key_authorization.into_response();
            r.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            r
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Everything else on port 80 goes to `https://DOMAIN/...` (the configured name, never the
/// request's `Host`, so the redirect cannot be pointed elsewhere).
async fn redirect(State(s): State<Http01State>, uri: Uri) -> Response {
    let host = match &s.domain {
        Domain::Dns(d) => d.clone(),
        Domain::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
        Domain::Ip(ip) => ip.to_string(),
    };
    let target = format!(
        "https://{host}{}",
        uri.path_and_query().map_or("/", |p| p.as_str())
    );
    match HeaderValue::from_str(&target) {
        Ok(loc) => {
            let mut r = Response::new(axum::body::Body::empty());
            *r.status_mut() = StatusCode::PERMANENT_REDIRECT;
            r.headers_mut().insert(header::LOCATION, loc);
            r
        }
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}
