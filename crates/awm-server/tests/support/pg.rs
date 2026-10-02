//! Postgres test support (TM26), shared by `store_conformance.rs`, `delete_retention.rs` and
//! `store_pg.rs` through `#[path = "support/pg.rs"] mod ...;`.
//!
//! `AWM_TEST_PG_URL` names a superuser on a throwaway server. [`PgEnv::new`] makes sure the
//! roles `awm_owner` and `awm_app` exist (cluster-wide, created once under an advisory lock),
//! creates a schema of its own owned by `awm_owner`, and connects a [`PgStore`] whose two URLs
//! put that schema first on the `search_path`: the owner URL migrates it, the application URL
//! serves it. Dropping the `PgEnv` drops the schema, so parallel tests (threads and processes)
//! never share tables.

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use awm_server::store::pg::{parse_url, PgStore};
use tokio_postgres::config::Host;
use tokio_postgres::{Client, NoTls};

pub const OWNER: &str = "awm_owner";
pub const APP: &str = "awm_app";

/// One schema with a migrated `PgStore` over it.
pub struct PgEnv {
    pub admin_url: String,
    pub schema: String,
    pub owner_url: String,
    pub app_url: String,
    pub store: PgStore,
}

/// Connects with `url` (a spawned connection task).
pub async fn connect(url: &str) -> Client {
    let cfg = parse_url(url).unwrap();
    let (client, conn) = cfg.connect(NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

fn server(admin_url: &str) -> (String, u16, String) {
    let cfg = parse_url(admin_url).unwrap();
    let host = match cfg.get_hosts().first() {
        Some(Host::Tcp(h)) => h.clone(),
        other => panic!("AWM_TEST_PG_URL must name a TCP host, got {other:?}"),
    };
    let port = cfg.get_ports().first().copied().unwrap_or(5432);
    let db = cfg.get_dbname().unwrap_or("postgres").to_string();
    (host, port, db)
}

/// A URL for `user` (password = user name) on the server of `admin_url`, with `schema` first
/// on the `search_path` when given.
pub fn url_for(admin_url: &str, user: &str, schema: Option<&str>) -> String {
    let (host, port, db) = server(admin_url);
    let mut url = format!("postgres://{user}:{user}@{host}:{port}/{db}");
    if let Some(s) = schema {
        url.push_str(&format!("?options=-c%20search_path%3D{s}"));
    }
    url
}

/// The admin (superuser) URL with `schema` on the `search_path`.
pub fn admin_url_in(admin_url: &str, schema: &str) -> String {
    let sep = if admin_url.contains('?') { '&' } else { '?' };
    format!("{admin_url}{sep}options=-c%20search_path%3D{schema}")
}

/// Creates the two login roles once per server (passwords equal to the names).
pub async fn ensure_roles(admin_url: &str) {
    let mut admin = connect(admin_url).await;
    let tx = admin.transaction().await.unwrap();
    tx.execute("SELECT pg_advisory_xact_lock(7262600)", &[])
        .await
        .unwrap();
    for role in [OWNER, APP] {
        tx.batch_execute(&format!(
            "DO $$ BEGIN \
               IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN \
                 CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{role}'; \
               END IF; \
             END $$;"
        ))
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
}

fn unique_schema(tag: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "t_{tag}_{}_{nanos}_{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

impl PgEnv {
    /// `None` when `AWM_TEST_PG_URL` is unset (the backend is not configured: skip).
    pub async fn new(tag: &str) -> Option<PgEnv> {
        let admin_url = std::env::var("AWM_TEST_PG_URL").ok()?;
        ensure_roles(&admin_url).await;
        let schema = unique_schema(tag);
        let admin = connect(&admin_url).await;
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema} AUTHORIZATION {OWNER}"))
            .await
            .unwrap();
        let owner_url = url_for(&admin_url, OWNER, Some(&schema));
        let app_url = url_for(&admin_url, APP, Some(&schema));
        let store = match PgStore::connect(&app_url, Some(&owner_url), 10).await {
            Ok(s) => s,
            Err(e) => {
                drop_schema(&admin_url, &schema);
                panic!("PgStore::connect: {e}");
            }
        };
        Some(PgEnv {
            admin_url,
            schema,
            owner_url,
            app_url,
            store,
        })
    }

    /// A superuser connection with the schema on its `search_path` (row-level security does
    /// not apply to it: catalog checks and raw counts).
    pub async fn admin(&self) -> Client {
        connect(&admin_url_in(&self.admin_url, &self.schema)).await
    }

    /// A raw connection as the application role.
    pub async fn app(&self) -> Client {
        connect(&self.app_url).await
    }

    /// A raw connection as the owner role.
    pub async fn owner(&self) -> Client {
        connect(&self.owner_url).await
    }

    /// Another `PgStore` (another pool: another server instance) on the same schema.
    pub async fn another_store(&self, pool_size: usize) -> PgStore {
        PgStore::connect(&self.app_url, None, pool_size)
            .await
            .unwrap()
    }
}

/// Drops `schema` on a thread of its own with its own runtime (Drop cannot await).
pub fn drop_schema(admin_url: &str, schema: &str) {
    let (url, schema) = (admin_url.to_string(), schema.to_string());
    let _ = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let admin = connect(&url).await;
            let _ = admin
                .batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
                .await;
        });
    })
    .join();
}

impl Drop for PgEnv {
    fn drop(&mut self) {
        drop_schema(&self.admin_url, &self.schema);
    }
}
