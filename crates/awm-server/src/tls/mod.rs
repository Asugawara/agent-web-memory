//! Built-in TLS with ACME (plan-v3-team §3.9.3, TM15).
//!
//! - [`cache`]: `{data}/acme/` at 0700 / 0600 (also read by `check` without the `acme` feature).
//! - [`der`]: reading a certificate's validity, serial and authority key identifier.
//! - [`alpn`] (feature `acme`): the certificate resolver (TLS-ALPN-01 and the real
//!   certificate), the rustls configuration (TLS 1.2 and 1.3), the listener axum serves from.
//! - [`acme`] (feature `acme`): account, orders, ARI renewal, failure backoff (instant-acme).
//! - [`serve`] (feature `acme`): the API on the TLS listener and the opt-in port-80 handler.

pub mod cache;
pub mod der;

#[cfg(feature = "acme")]
pub mod acme;
#[cfg(feature = "acme")]
pub mod alpn;
#[cfg(feature = "acme")]
pub mod serve;

#[cfg(feature = "acme")]
pub use acme::{Acme, AcmeError, AcmeParams, Http01Tokens, OrderLog, Tick};
#[cfg(feature = "acme")]
pub use alpn::{CertSlot, TlsListener};
pub use cache::AcmeCache;
#[cfg(feature = "acme")]
pub use serve::{http01_router, serve_tls};
