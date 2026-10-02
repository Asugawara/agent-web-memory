//! `PgStore`-specific cases (plan-v3-team §4.2, TM26): the migration runner, the roles and the
//! catalog, row-level security on every table, contiguity under concurrent pushes from 4
//! connections in 2 processes, the SQLite → Postgres → SQLite round trip, organisation
//! deletion, the cross-instance retention claim (TM9 P2) and the pool cap. The `Store`
//! behaviour itself is `tests/store_conformance.rs`, which runs unchanged on both backends.
//!
//! Every case needs `AWM_TEST_PG_URL` (a superuser on a throwaway server) and passes without
//! doing anything when it is unset. Each case works in a schema of its own (`support/pg.rs`).
//!
//! The second process of `pushes_from_4_connections_in_2_processes_stay_contiguous` is this
//! test binary run again on `helper_pushes_into_a_stream` with `AWM_TM26_HELPER=1` (and the
//! scope in `AWM_TM26_*` variables): without that variable the helper returns at once.
//!
//! Run: `AWM_TEST_PG_URL=... cargo test -p awm-server --features pg,sqlite --test store_pg`.

#![cfg(all(feature = "pg", feature = "sqlite"))]

#[path = "support/pg.rs"]
mod support;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use awm_proto::wire::{
    DeleteRequest, DeviceWrap, EpochWrap, Handle, Id, InviteKind, Key32, PulledItem, PushDeleted,
    PushItem, PushRecord, SettingsUpdate, Tag, Version, B64,
};
use awm_server::store::pg::{
    migrate, migrate_with, org_lock_key, parse_url, PgStore, MAX_POOL_SIZE, MIGRATIONS, ORG_TABLES,
    RETENTION_CLAIM,
};
use awm_server::store::sqlite::SqliteStore;
use awm_server::store::{
    checksum, Actor, AuditEntry, NewBootstrap, NewInvite, NewJoin, OrgDefaults, PushBatch, Store,
    StoreError,
};
use support::{PgEnv, APP, OWNER};

const T0: i64 = 1_790_000_000;
const DAY: i64 = 86_400;
const HOUR: i64 = 3_600;
const BIG: usize = awm_proto::wire::limits::PULL_RESPONSE_BYTES;

// ---------------------------------------------------------------------------------------------
// Helpers

fn h(s: &str) -> String {
    checksum(s.as_bytes())
}

fn handle(s: &str) -> Handle {
    Handle::parse(s).unwrap()
}

fn tag(s: &str) -> Tag {
    Tag::parse(s).unwrap()
}

fn blob(seed: &str) -> B64 {
    let mut v = vec![0x01u8];
    let mut i = 0u64;
    while v.len() < 297 {
        let d = checksum(format!("{seed}/{i}").as_bytes());
        v.extend((0..32).map(|j| u8::from_str_radix(&d[2 * j..2 * j + 2], 16).unwrap()));
        i += 1;
    }
    v.truncate(297);
    B64(v)
}

fn rec(t: &str, idx: u64, id: Id, epoch: u32) -> PushItem {
    PushItem::Record(PushRecord {
        tag: tag(t),
        idx,
        id,
        epoch,
        blob: blob(&id.to_string()),
    })
}

fn device_token_hash(device: Id) -> String {
    h(&format!("device-token-{device}"))
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "storepg-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn bootstrap(s: &dyn Store) -> (Id, Actor) {
    s.set_bootstrap(h("bootstrap"), T0 + DAY).await.unwrap();
    let device = Id::new_v4();
    let org_id = Id::new_v4();
    let member = s
        .bootstrap(NewBootstrap {
            bootstrap_token_hash: h("bootstrap"),
            org_id,
            handle: handle("alf"),
            device_id: device,
            device_pubkey: Key32([1; 32]),
            device_token_hash: device_token_hash(device),
            defaults: OrgDefaults {
                retention_days: 365,
                min_client: Version::new(0, 2, 0),
                max_members: 100,
            },
            now: T0,
        })
        .await
        .unwrap();
    (
        org_id,
        Actor {
            member_id: member,
            device_id: device,
            admin: true,
        },
    )
}

async fn invite(s: &dyn Store, by: Actor, kind: InviteKind, name: &str) -> Id {
    let invite_id = Id::new_v4();
    s.create_invite(NewInvite {
        invite_id,
        token_hash: h(&format!("invite-{invite_id}")),
        kind,
        handle: handle(name),
        role: None,
        expires_at: T0 + 7 * DAY,
        by,
        now: T0,
    })
    .await
    .unwrap();
    invite_id
}

fn join_req(invite_id: Id, name: &str, device: Id, n: u8) -> NewJoin {
    NewJoin {
        invite_id,
        invite_token_hash: h(&format!("invite-{invite_id}")),
        handle: handle(name),
        device_id: device,
        device_pubkey: Key32([n; 32]),
        join_mac: Key32([n.wrapping_add(100); 32]),
        device_token_hash: device_token_hash(device),
        now: T0 + 60,
    }
}

async fn add_member(s: &dyn Store, admin: Actor, name: &str, n: u8) -> Actor {
    let inv = invite(s, admin, InviteKind::Member, name).await;
    let device = Id::new_v4();
    let joined = s.join(join_req(inv, name, device, n)).await.unwrap();
    let epoch = s.org(T0).await.unwrap().unwrap().current_epoch;
    let wraps = (0..=epoch)
        .map(|e| EpochWrap {
            epoch: e,
            wrap: B64(vec![e as u8; 89]),
            auth: Key32([7; 32]),
        })
        .collect();
    s.approve_device(device, wraps, admin, T0 + 120)
        .await
        .unwrap();
    Actor {
        member_id: joined.member_id,
        device_id: device,
        admin: false,
    }
}

async fn push_n(s: &dyn Store, a: &Actor, t: &str, n: u64, now: i64) -> Vec<Id> {
    let head = s
        .stream_head(a.member_id, a.device_id, tag(t))
        .await
        .unwrap();
    let epoch = s.org(T0).await.unwrap().unwrap().current_epoch;
    let ids: Vec<Id> = (0..n).map(|_| Id::new_v4()).collect();
    let items = ids
        .iter()
        .enumerate()
        .map(|(i, id)| rec(t, (head + 1) as u64 + i as u64, *id, epoch))
        .collect();
    s.push(PushBatch {
        member_id: a.member_id,
        device_id: a.device_id,
        items,
        now,
    })
    .await
    .unwrap();
    ids
}

/// An organisation with a row in every canonical table (and a `claim` row on Postgres):
/// members, a pending device, open and revoked invites, records of several tags, markers, a
/// pre-deletion, a removal, a rotation, pending settings, audit rows and meta keys.
struct Seeded {
    org_id: Id,
    admin: Actor,
    roy: Actor,
    ids: Vec<Id>,
}

async fn seed(s: &dyn Store) -> Seeded {
    let (org_id, admin) = bootstrap(s).await;
    let roy = add_member(s, admin, "roy", 2).await;
    let kit = add_member(s, admin, "kit", 3).await;
    let pending = invite(s, roy, InviteKind::Device, "roy").await;
    s.join(join_req(pending, "roy", Id::new_v4(), 4))
        .await
        .unwrap();
    let revoked = invite(s, admin, InviteKind::Member, "sage").await;
    s.revoke_invite(revoked, admin, T0).await.unwrap();
    invite(s, admin, InviteKind::Member, "yves").await;
    let ids = push_n(s, &roy, "rec", 4, T0 + HOUR).await;
    push_n(s, &admin, "policy", 1, T0 + HOUR).await;
    push_n(s, &admin, "roster", 2, T0 + HOUR).await;
    push_n(s, &kit, "flag", 2, T0 + HOUR).await;
    s.delete(DeleteRequest::Ids(vec![ids[0], Id::new_v4()]), roy, T0)
        .await
        .unwrap();
    s.push(PushBatch {
        member_id: roy.member_id,
        device_id: roy.device_id,
        items: vec![PushItem::Deleted(PushDeleted {
            tag: tag("rec"),
            idx: 4,
            id: Id::new_v4(),
        })],
        now: T0 + HOUR,
    })
    .await
    .unwrap();
    s.remove_member(kit.member_id, true, admin, T0)
        .await
        .unwrap();
    let wrap = |d: Id| DeviceWrap {
        device_id: d,
        wrap: B64(vec![8; 89]),
        auth: Key32([8; 32]),
    };
    s.rotate_keys(
        1,
        vec![wrap(admin.device_id), wrap(roy.device_id)],
        admin,
        T0,
    )
    .await
    .unwrap();
    push_n(s, &roy, "rec", 1, T0 + 2 * HOUR).await;
    s.update_settings(
        SettingsUpdate {
            retention_days: Some(90),
            min_client: Some(Version::new(0, 2, 1)),
            max_members: Some(20),
            cancel_pending_retention: None,
        },
        Version::new(0, 2, 0),
        Some(admin),
        T0,
    )
    .await
    .unwrap();
    s.append_audit(AuditEntry {
        at: T0,
        actor: Some(admin.member_id),
        action: "export".into(),
        target: None,
        detail: None,
    })
    .await
    .unwrap();
    s.meta_set("last_retention".into(), T0.to_string())
        .await
        .unwrap();
    s.meta_set("backup_cursor".into(), "17".into())
        .await
        .unwrap();
    s.touch_device(admin.device_id, 20_710).await.unwrap();
    // A retention run far later: deletes the flag records (and writes the claim on Postgres).
    s.retention_batch(T0 + 10 * DAY, 1, T0 + 400 * DAY)
        .await
        .unwrap();
    Seeded {
        org_id,
        admin,
        roy,
        ids,
    }
}

/// Tables of the schema with an `org_id` column, from the catalog.
async fn org_tables(admin: &tokio_postgres::Client) -> BTreeSet<String> {
    admin
        .query(
            "SELECT table_name::text FROM information_schema.columns \
              WHERE table_schema = current_schema() AND column_name = 'org_id'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}

fn sqlstate(e: &tokio_postgres::Error) -> String {
    e.code()
        .map_or_else(|| "none".into(), |c| c.code().to_string())
}

// ---------------------------------------------------------------------------------------------
// Migrations

/// One transaction under an advisory lock, checksums, a second run is a no-op, a changed
/// checksum (stored or embedded) and a newer version are refused, a failing or unsafe
/// migration changes nothing, two migrators at once apply it once; the runner uses the owner
/// connection, and the application role cannot run DDL.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_migration_runner_is_atomic_checked_and_never_downgrades() {
    let Some(env) = PgEnv::new("mig").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let owner = parse_url(&env.owner_url).unwrap();
    let admin = env.admin().await;
    let fingerprint = || async {
        let r = admin
            .query(
                "SELECT version, checksum, applied_at::text, xmin::text FROM schema_migrations \
                  ORDER BY version",
                &[],
            )
            .await
            .unwrap();
        let rows: Vec<(i32, String, String, String)> = r
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
            .collect();
        let objects: i64 = admin
            .query_one(
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                  WHERE n.nspname = current_schema()",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        (rows, objects)
    };
    let before = fingerprint().await;
    assert_eq!(before.0.len(), 1);
    assert_eq!(before.0[0].1, checksum(MIGRATIONS[0].2.as_bytes()));
    eprintln!("schema 0001 checksum {}", before.0[0].1);

    // A second run is a no-op: same rows (even the row version), same objects.
    let out = migrate(&owner, APP).await.unwrap();
    assert_eq!((out.from, out.to), (1, 1));
    assert_eq!(fingerprint().await, before);

    // An edited embedded file and an edited stored checksum are refused.
    let edited = format!("-- edited\n{}", MIGRATIONS[0].2);
    let e = migrate_with(&owner, APP, &[(1, "0001_server", &edited)])
        .await
        .unwrap_err();
    assert!(e.to_string().contains("checksum mismatch"), "{e}");
    admin
        .execute(
            "UPDATE schema_migrations SET checksum = repeat('0', 64) WHERE version = 1",
            &[],
        )
        .await
        .unwrap();
    let e = migrate(&owner, APP).await.unwrap_err();
    assert!(e.to_string().contains("checksum mismatch"), "{e}");
    let e = PgStore::connect(&env.app_url, None, 1).await.unwrap_err();
    assert!(e.to_string().contains("checksum mismatch"), "{e}");
    admin
        .execute(
            "UPDATE schema_migrations SET checksum = $1 WHERE version = 1",
            &[&before.0[0].1],
        )
        .await
        .unwrap();
    // The row version changed with the two updates above; nothing below may change it again.
    let before = fingerprint().await;

    // A newer database is refused, by the runner and at connect (no downgrade).
    admin
        .execute(
            "INSERT INTO schema_migrations (version, name, checksum) \
             VALUES (2, '0002_future', repeat('a', 64))",
            &[],
        )
        .await
        .unwrap();
    let e = migrate(&owner, APP).await.unwrap_err();
    assert!(
        e.to_string().contains("newer awm (2, this binary knows 1)"),
        "{e}"
    );
    let e = PgStore::connect(&env.app_url, None, 1).await.unwrap_err();
    assert!(e.to_string().contains("newer awm"), "{e}");
    admin
        .execute("DELETE FROM schema_migrations WHERE version = 2", &[])
        .await
        .unwrap();

    // A failing migration 0002 rolls back as a whole.
    let broken = "CREATE TABLE half (org_id TEXT NOT NULL); SELECT 1 / 0;";
    let e = migrate_with(
        &owner,
        APP,
        &[
            (1, "0001_server", MIGRATIONS[0].2),
            (2, "0002_broken", broken),
        ],
    )
    .await
    .unwrap_err();
    assert!(
        e.to_string()
            .contains("migration 0002_broken failed: 22012"),
        "{e}"
    );
    // A migration that adds a table without forced row-level security is refused.
    let unforced = "CREATE TABLE loose (org_id TEXT NOT NULL);";
    let e = migrate_with(
        &owner,
        APP,
        &[
            (1, "0001_server", MIGRATIONS[0].2),
            (2, "0002_loose", unforced),
        ],
    )
    .await
    .unwrap_err();
    assert!(
        e.to_string().contains("without forced row-level security"),
        "{e}"
    );
    assert_eq!(fingerprint().await, before, "nothing changed");

    // The runner needs a distinct, existing, RLS-bound application role.
    for (role, want) in [
        (OWNER, "must not be the role that runs the migrations"),
        ("awm_nobody", "does not exist"),
    ] {
        let e = migrate(&owner, role).await.unwrap_err();
        assert!(e.to_string().contains(want), "{role}: {e}");
    }

    // The application role holds no DDL rights.
    let app = env.app().await;
    for sql in [
        "CREATE TABLE x (a int)",
        "ALTER TABLE record DISABLE ROW LEVEL SECURITY",
        "ALTER TABLE record NO FORCE ROW LEVEL SECURITY",
        "DROP POLICY tenant ON record",
        "DROP TABLE audit",
        "TRUNCATE meta",
        "INSERT INTO schema_migrations (version, name, checksum) VALUES (9, 'x', repeat('a', 64))",
        "SET ROLE awm_owner",
    ] {
        let e = app.batch_execute(sql).await.unwrap_err();
        assert_eq!(sqlstate(&e), "42501", "{sql}: {e:?}");
    }
    let e = app.batch_execute("CREATE SCHEMA y").await.unwrap_err();
    assert_eq!(sqlstate(&e), "42501");
    assert_eq!(fingerprint().await, before);
}

/// Two migrators on a new schema at once: the advisory lock lets one apply 0001 and the other
/// find it applied; a store connected without an owner URL to an unmigrated schema refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_migrators_apply_the_schema_once() {
    let Some(env) = PgEnv::new("migc").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let admin = env.admin().await;
    for round in 0..5 {
        let schema = format!("{}_r{round}", env.schema);
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema} AUTHORIZATION {OWNER}"))
            .await
            .unwrap();
        let app_url = support::url_for(&env.admin_url, APP, Some(&schema));
        let e = PgStore::connect(&app_url, None, 1).await.unwrap_err();
        assert!(e.to_string().contains("not migrated"), "{e}");
        let owner = parse_url(&support::url_for(&env.admin_url, OWNER, Some(&schema))).unwrap();
        let runs: Vec<_> = (0..4)
            .map(|_| {
                let o = owner.clone();
                tokio::spawn(async move { migrate(&o, APP).await })
            })
            .collect();
        let mut applied = 0;
        for r in runs {
            let out = r.await.unwrap().unwrap();
            assert_eq!(out.to, 1);
            applied += usize::from(out.from == 0);
        }
        assert_eq!(applied, 1, "round {round}");
        PgStore::connect(&app_url, None, 1).await.unwrap();
        admin
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}

/// RVT2 m11: before PostgreSQL 15 every role may create in `public`. The migration revokes
/// `CREATE` from `PUBLIC` on the schema it migrates (and on `public` when its owner runs it),
/// so the application role can create nothing even where `PUBLIC` was granted it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_migration_takes_create_on_its_schema_away_from_public() {
    let Some(env) = PgEnv::new("m11").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let admin = env.admin().await;
    let schema = format!("{}_pub", env.schema);
    // A schema as `public` is before PostgreSQL 15: CREATE for every role.
    admin
        .batch_execute(&format!(
            "CREATE SCHEMA {schema} AUTHORIZATION {OWNER}; GRANT CREATE ON SCHEMA {schema} TO PUBLIC"
        ))
        .await
        .unwrap();
    let app_url = support::url_for(&env.admin_url, APP, Some(&schema));
    let can_create = |role: &'static str| {
        let admin = &admin;
        let schema = schema.clone();
        async move {
            admin
                .query_one(
                    "SELECT has_schema_privilege($1, $2, 'CREATE')",
                    &[&role, &schema],
                )
                .await
                .unwrap()
                .get::<_, bool>(0)
        }
    };
    assert!(can_create(APP).await, "the grant above applies");
    let owner = parse_url(&support::url_for(&env.admin_url, OWNER, Some(&schema))).unwrap();
    migrate(&owner, APP).await.unwrap();
    assert!(!can_create(APP).await);
    let app = support::connect(&app_url).await;
    let e = app
        .batch_execute(&format!("CREATE TABLE {schema}.planted (a int)"))
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&e), "42501", "{e:?}");
    // The store still connects: its role owns nothing.
    PgStore::connect(&app_url, None, 1).await.unwrap();
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------------------------
// Roles and catalog

/// The catalog as RVT0 m16 asks: the application role has no `BYPASSRLS` and owns no table;
/// every table has row-level security enabled and forced and one `tenant` policy on
/// `awm.org`; `org_id` leads every primary key and unique index; `connect` refuses a role that
/// bypasses row-level security or owns the tables.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_catalog_shows_forced_policies_and_an_unprivileged_application_role() {
    let Some(env) = PgEnv::new("cat").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let admin = env.admin().await;
    let r = admin
        .query_one(
            "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles \
              WHERE rolname = $1",
            &[&APP],
        )
        .await
        .unwrap();
    let flags: (bool, bool, bool, bool) = (r.get(0), r.get(1), r.get(2), r.get(3));
    eprintln!("pg_roles {APP}: rolsuper, rolbypassrls, rolcreaterole, rolcreatedb = {flags:?}");
    assert_eq!(flags, (false, false, false, false));

    let tables: Vec<(String, String, bool, bool)> = admin
        .query(
            "SELECT c.relname::text, pg_get_userbyid(c.relowner)::text, c.relrowsecurity, \
                    c.relforcerowsecurity \
               FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = current_schema() AND c.relkind = 'r' ORDER BY 1",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect();
    for t in &tables {
        eprintln!(
            "pg_class {}: owner {}, relrowsecurity {}, relforcerowsecurity {}",
            t.0, t.1, t.2, t.3
        );
        assert_eq!(t.1, OWNER, "{}", t.0);
        assert!(t.2 && t.3, "{} without forced row-level security", t.0);
    }
    let names: BTreeSet<String> = tables.iter().map(|t| t.0.clone()).collect();
    let mut want: BTreeSet<String> = ORG_TABLES.iter().map(|t| t.to_string()).collect();
    assert_eq!(org_tables(&admin).await, want, "tables with org_id");
    want.insert("schema_migrations".into());
    assert_eq!(names, want);
    let owned: i64 = admin
        .query_one(
            "SELECT count(*) FROM pg_tables WHERE schemaname = current_schema() AND tableowner = $1",
            &[&APP],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(owned, 0, "pg_tables.tableowner");

    // One policy per table, on awm.org, for every command.
    let policies: Vec<(String, String, String, String)> = admin
        .query(
            "SELECT tablename::text, policyname::text, cmd, qual FROM pg_policies \
              WHERE schemaname = current_schema() ORDER BY 1",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect();
    for t in ORG_TABLES {
        let p: Vec<_> = policies.iter().filter(|p| p.0 == *t).collect();
        assert_eq!(p.len(), 1, "{t}: {p:?}");
        assert_eq!((p[0].1.as_str(), p[0].2.as_str()), ("tenant", "ALL"));
        assert!(
            p[0].3.contains("current_setting('awm.org'::text, true)"),
            "{t}: {}",
            p[0].3
        );
    }
    eprintln!("pg_policies tenant qual: {}", policies[0].3);

    // org_id leads every primary key and unique index.
    let keys: Vec<(String, String, String)> = admin
        .query(
            "SELECT t.relname::text, i.relname::text, a.attname::text \
               FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid \
               JOIN pg_class t ON t.oid = x.indrelid \
               JOIN pg_namespace n ON n.oid = t.relnamespace \
               JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = x.indkey[0] \
              WHERE n.nspname = current_schema() AND x.indisunique \
                AND t.relname <> 'schema_migrations' ORDER BY 1, 2",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    assert!(keys.len() >= ORG_TABLES.len() + 6, "{keys:?}");
    for k in &keys {
        assert_eq!(k.2, "org_id", "{} {}", k.0, k.1);
    }
    eprintln!("{} unique indexes, each led by org_id", keys.len());

    // connect refuses roles that bypass row-level security or own the tables.
    let su = support::admin_url_in(&env.admin_url, &env.schema);
    let e = PgStore::connect(&su, None, 1).await.unwrap_err();
    assert!(e.to_string().contains("bypasses row-level security"), "{e}");
    let e = PgStore::connect(&env.owner_url, None, 1).await.unwrap_err();
    assert!(
        e.to_string().contains("owns, or may act as the owner"),
        "{e}"
    );
}

// ---------------------------------------------------------------------------------------------
// Isolation

/// With `awm.org` set to A, no statement of the application role returns, changes or adds a
/// row of B, for every table; without the setting every table is empty (a new connection and
/// one whose earlier transaction set it); the owner sees nothing without it either (FORCE);
/// and B's scope finds nothing of A through the `Store` trait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_awm_org_set_to_a_no_statement_reaches_a_row_of_b() {
    let Some(env) = PgEnv::new("iso").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let (ka, kb) = (Id::new_v4(), Id::new_v4());
    let a = env.store.create_org(ka).await.unwrap();
    let b = env.store.create_org(kb).await.unwrap();
    let sa = seed(&*a).await;
    let sb = seed(&*b).await;
    let (ka, kb) = (ka.to_string(), kb.to_string());
    let admin = env.admin().await;
    assert_eq!(org_tables(&admin).await.len(), ORG_TABLES.len());
    let mut counts = BTreeMap::new();
    for t in ORG_TABLES {
        let n: i64 = admin
            .query_one(
                &format!("SELECT count(*) FROM {t} WHERE org_id = $1"),
                &[&kb],
            )
            .await
            .unwrap()
            .get(0);
        assert!(n > 0, "B has rows in {t}");
        let na: i64 = admin
            .query_one(
                &format!("SELECT count(*) FROM {t} WHERE org_id = $1"),
                &[&ka],
            )
            .await
            .unwrap()
            .get(0);
        counts.insert(*t, na);
    }
    eprintln!("rows of A per table: {counts:?}");

    let mut app = env.app().await;
    let tx = app.transaction().await.unwrap();
    tx.execute("SELECT set_config('awm.org', $1, true)", &[&ka])
        .await
        .unwrap();
    for t in ORG_TABLES {
        let r = tx
            .query_one(
                &format!(
                    "SELECT count(*), count(*) FILTER (WHERE org_id <> $1), \
                            count(*) FILTER (WHERE org_id = $2) FROM {t}"
                ),
                &[&ka, &kb],
            )
            .await
            .unwrap();
        let (all, other, of_b): (i64, i64, i64) = (r.get(0), r.get(1), r.get(2));
        assert_eq!((all, other, of_b), (counts[t], 0, 0), "{t}");
        assert_eq!(
            tx.execute(
                &format!("UPDATE {t} SET org_id = org_id WHERE org_id = $1"),
                &[&kb]
            )
            .await
            .unwrap(),
            0,
            "{t}"
        );
        assert_eq!(
            tx.execute(&format!("DELETE FROM {t} WHERE org_id = $1"), &[&kb])
                .await
                .unwrap(),
            0,
            "{t}"
        );
    }
    tx.rollback().await.unwrap();
    // Writing a row of B (or moving one of A to B) with awm.org = A is refused.
    for sql in [
        "INSERT INTO meta (org_id, key, value) VALUES ($2::text, 'x', 'y') \
          RETURNING $1::text",
        "UPDATE meta SET org_id = $2 WHERE org_id = $1",
    ] {
        let tx = app.transaction().await.unwrap();
        tx.execute("SELECT set_config('awm.org', $1, true)", &[&ka])
            .await
            .unwrap();
        let e = tx.execute(sql, &[&ka, &kb]).await.unwrap_err();
        assert_eq!(sqlstate(&e), "42501", "{sql}: {e:?}");
    }

    // Without the setting nothing is visible: on this connection (whose earlier transactions
    // set it locally), on a new one, and to the owner (FORCE ROW LEVEL SECURITY).
    let fresh = env.app().await;
    let owner = env.owner().await;
    for (who, c) in [
        ("app, after SET LOCAL", &app),
        ("app, new", &fresh),
        ("owner", &owner),
    ] {
        let setting: Option<String> = c
            .query_one("SELECT current_setting('awm.org', true)", &[])
            .await
            .unwrap()
            .get(0);
        for t in ORG_TABLES {
            let n: i64 = c
                .query_one(&format!("SELECT count(*) FROM {t}"), &[])
                .await
                .unwrap()
                .get(0);
            assert_eq!(n, 0, "{who} ({setting:?}) sees rows of {t}");
            assert_eq!(
                c.execute(&format!("DELETE FROM {t}"), &[]).await.unwrap(),
                0,
                "{who}: {t}"
            );
        }
        eprintln!("{who}: awm.org = {setting:?}, every table empty");
    }

    // Through the trait: B's scope knows nothing of A.
    assert_eq!(
        b.auth_device(device_token_hash(sa.admin.device_id))
            .await
            .unwrap(),
        None
    );
    assert_eq!(b.device(sa.roy.device_id).await.unwrap(), None);
    assert_eq!(b.member(sa.admin.member_id).await.unwrap(), None);
    assert!(matches!(
        b.status(sa.roy.device_id, T0).await,
        Err(StoreError::NotFound)
    ));
    let pulled = b
        .records(sa.roy.member_id, sa.roy.device_id, tag("rec"), 0, 500, BIG)
        .await
        .unwrap();
    assert_eq!((pulled.head, pulled.records.len()), (-1, 0));
    let dump_b = format!("{:?}", b.dump().await.unwrap());
    for id in [sa.org_id, sa.admin.member_id, sa.roy.device_id, sa.ids[1]] {
        assert!(!dump_b.contains(&id.to_string()), "{id}");
    }
    assert_eq!(
        b.org(T0).await.unwrap().unwrap().org_id,
        sb.org_id,
        "each scope its own organisation"
    );
    // A deletion in A leaves B unchanged.
    let before = b.dump().await.unwrap();
    a.delete(DeleteRequest::AllMine, sa.roy, T0).await.unwrap();
    assert_eq!(b.dump().await.unwrap(), before);
}

/// A scope that was never created reads nothing and writes nothing (TM19 routes from the
/// token first; an altered organisation part must cost no row).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_scope_reads_and_writes_nothing() {
    let Some(env) = PgEnv::new("unk").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let known = env.store.create_org(Id::new_v4()).await.unwrap();
    let s = seed(&*known).await;
    let ghost_key = Id::new_v4();
    let ghost = env.store.for_org(ghost_key);
    assert_eq!(
        ghost
            .auth_device(device_token_hash(s.admin.device_id))
            .await
            .unwrap(),
        None
    );
    assert_eq!(ghost.org(T0).await.unwrap(), None);
    assert!(matches!(
        ghost.restore_state().await,
        Err(StoreError::Backend(_))
    ));
    let admin = env.admin().await;
    for t in ORG_TABLES {
        let n: i64 = admin
            .query_one(
                &format!("SELECT count(*) FROM {t} WHERE org_id = $1"),
                &[&ghost_key.to_string()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 0, "{t}");
    }
}

// ---------------------------------------------------------------------------------------------
// Contiguity under concurrent pushes from 4 connections in 2 processes

const PER_CONNECTION: usize = 100;

/// One connection's share: `n` records into the stream, each at head + 1 with a retry on 409,
/// then the deletion of its own records in batches of 7 and 10 pre-deletions. Returns the
/// pushed ids, the pre-deleted ids and the number of stream conflicts retried.
async fn pusher(pg: PgStore, org: Id, a: Actor, n: usize, seed: &str) -> (Vec<Id>, Vec<Id>, u32) {
    let s = pg.for_org(org);
    let (mut mine, mut pre, mut conflicts) = (Vec::new(), Vec::new(), 0u32);
    for i in 0..n {
        let id = Id::new_v4();
        loop {
            let head = s
                .stream_head(a.member_id, a.device_id, tag("rec"))
                .await
                .unwrap();
            let item = PushItem::Record(PushRecord {
                tag: tag("rec"),
                idx: (head + 1) as u64,
                id,
                epoch: 0,
                blob: blob(&format!("{seed}/{i}")),
            });
            match s
                .push(PushBatch {
                    member_id: a.member_id,
                    device_id: a.device_id,
                    items: vec![item],
                    now: T0 + HOUR,
                })
                .await
            {
                Ok(r) => {
                    assert_eq!((r.accepted, r.replayed), (1, 0));
                    break;
                }
                Err(StoreError::StreamConflict { item: 0, .. }) => conflicts += 1,
                Err(e) => panic!("{seed}: {e}"),
            }
        }
        mine.push(id);
    }
    for chunk in mine.chunks(7) {
        s.delete(DeleteRequest::Ids(chunk.to_vec()), a, T0 + 2 * HOUR)
            .await
            .unwrap();
    }
    for _ in 0..10 {
        let id = Id::new_v4();
        s.delete(DeleteRequest::Ids(vec![id]), a, T0 + 2 * HOUR)
            .await
            .unwrap();
        pre.push(id);
    }
    (mine, pre, conflicts)
}

/// The second process (see the module docs): two connections of its own push and delete;
/// the ids go to stdout for the parent to check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn helper_pushes_into_a_stream() {
    if std::env::var("AWM_TM26_HELPER").is_err() {
        return;
    }
    let var = |k: &str| std::env::var(k).unwrap();
    let url = var("AWM_TM26_URL");
    let org = Id::parse(&var("AWM_TM26_ORG")).unwrap();
    let a = Actor {
        member_id: Id::parse(&var("AWM_TM26_MEMBER")).unwrap(),
        device_id: Id::parse(&var("AWM_TM26_DEVICE")).unwrap(),
        admin: true,
    };
    let tasks: Vec<_> = (0..2)
        .map(|t| {
            let url = url.clone();
            tokio::spawn(async move {
                let pg = PgStore::connect(&url, None, 1).await.unwrap();
                pusher(pg, org, a, PER_CONNECTION, &format!("child/{t}")).await
            })
        })
        .collect();
    for t in tasks {
        let (mine, pre, conflicts) = t.await.unwrap();
        for id in mine {
            println!("PUSHED {id}");
        }
        for id in pre {
            println!("PREDELETED {id}");
        }
        println!("CONFLICTS {conflicts}");
    }
}

/// §4.2: contiguous indexes and a contiguous deletion stream under concurrent pushes and
/// deletions from 4 connections (each its own pool of 1) in 2 processes into one stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pushes_from_4_connections_in_2_processes_stay_contiguous() {
    let Some(env) = PgEnv::new("procs").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let org = Id::new_v4();
    let s = env.store.create_org(org).await.unwrap();
    let (_, a) = bootstrap(&*s).await;
    let started = Instant::now();
    let child = {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "helper_pushes_into_a_stream",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("AWM_TM26_HELPER", "1")
        .env("AWM_TM26_URL", &env.app_url)
        .env("AWM_TM26_ORG", org.to_string())
        .env("AWM_TM26_MEMBER", a.member_id.to_string())
        .env("AWM_TM26_DEVICE", a.device_id.to_string());
        tokio::task::spawn_blocking(move || cmd.output())
    };
    let local: Vec<_> = (0..2)
        .map(|t| {
            let url = env.app_url.clone();
            tokio::spawn(async move {
                let pg = PgStore::connect(&url, None, 1).await.unwrap();
                pusher(pg, org, a, PER_CONNECTION, &format!("parent/{t}")).await
            })
        })
        .collect();
    let (mut pushed, mut pre, mut conflicts) = (Vec::new(), Vec::new(), 0u32);
    for t in local {
        let (m, p, c) = t.await.unwrap();
        pushed.extend(m);
        pre.extend(p);
        conflicts += c;
    }
    let out = child.await.unwrap().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "helper failed: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut child_pushed = 0;
    // libtest prints "test helper_pushes_into_a_stream ... " before the first line.
    for line in stdout.lines() {
        if let Some((_, id)) = line.split_once("PUSHED ") {
            pushed.push(Id::parse(id).unwrap());
            child_pushed += 1;
        } else if let Some((_, id)) = line.split_once("PREDELETED ") {
            pre.push(Id::parse(id).unwrap());
        } else if let Some((_, n)) = line.split_once("CONFLICTS ") {
            conflicts += n.parse::<u32>().unwrap();
        }
    }
    let elapsed = started.elapsed();
    assert_eq!(
        child_pushed,
        2 * PER_CONNECTION,
        "the second process pushed its share"
    );
    let n = 4 * PER_CONNECTION;
    let items = s
        .records(a.member_id, a.device_id, tag("rec"), 0, 500, BIG)
        .await
        .unwrap()
        .records;
    assert_eq!(items.len(), n);
    for (i, it) in items.iter().enumerate() {
        assert_eq!(it.idx(), i as u64, "no gap, no duplicate idx");
        assert!(
            matches!(it, PulledItem::Deleted(_)),
            "deleted by its pusher"
        );
    }
    let got: HashSet<Id> = items.iter().map(PulledItem::id).collect();
    assert_eq!(got, pushed.iter().copied().collect::<HashSet<_>>());
    assert_eq!(got.len(), n, "every pushed id exactly once");
    let page = s.deletions(0, 5_000).await.unwrap();
    assert_eq!(page.entries.len(), n + 40);
    assert_eq!((page.oldest, page.head), (0, (n + 40) as i64 - 1));
    for (i, e) in page.entries.iter().enumerate() {
        assert_eq!(e.idx, i as u64, "contiguous deletion stream");
    }
    let named: HashSet<Id> = page.entries.iter().map(|e| e.record_id).collect();
    let want: HashSet<Id> = pushed.iter().chain(pre.iter()).copied().collect();
    assert_eq!(named, want);
    eprintln!(
        "2 processes x 2 connections: {n} records idx 0..{}, {} deletion entries idx 0..{}, \
         {conflicts} stream conflicts retried, {:.2} s",
        n - 1,
        n + 40,
        n + 39,
        elapsed.as_secs_f64()
    );
}

/// The same id pushed into two streams at once: one push stores it, the other gets
/// `id_conflict` (the `record_id_unique` constraint), never a 500.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_id_pushed_into_two_streams_at_once_conflicts_cleanly() {
    let Some(env) = PgEnv::new("dupid").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let s = env.store.create_org(Id::new_v4()).await.unwrap();
    let (_, a) = bootstrap(&*s).await;
    let roy = add_member(&*s, a, "roy", 2).await;
    let (mut stored, mut conflicts) = (0, 0);
    for _ in 0..30 {
        let id = Id::new_v4();
        let tasks: Vec<_> = [(a, "rec"), (roy, "flag")]
            .into_iter()
            .map(|(who, t)| {
                let s = Arc::clone(&s);
                tokio::spawn(async move {
                    let head = s
                        .stream_head(who.member_id, who.device_id, tag(t))
                        .await
                        .unwrap();
                    s.push(PushBatch {
                        member_id: who.member_id,
                        device_id: who.device_id,
                        items: vec![rec(t, (head + 1) as u64, id, 0)],
                        now: T0,
                    })
                    .await
                })
            })
            .collect();
        for t in tasks {
            match t.await.unwrap() {
                Ok(_) => stored += 1,
                Err(StoreError::IdConflict { item: 0 }) => conflicts += 1,
                Err(e) => panic!("{e}"),
            }
        }
    }
    assert_eq!((stored, conflicts), (30, 30));
}

/// Re-seed markers (which append to the deletion stream) pushed into two streams at once,
/// while a third connection pre-deletes ids: the deletion stream stays contiguous and names
/// every id once (a marker push takes the organisation lock exclusively).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn markers_and_deletions_at_once_keep_the_deletion_stream_contiguous() {
    let Some(env) = PgEnv::new("markers").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let s = env.store.create_org(Id::new_v4()).await.unwrap();
    let (_, a) = bootstrap(&*s).await;
    let roy = add_member(&*s, a, "roy", 2).await;
    const N: u64 = 60;
    let markers: Vec<_> = [a, roy]
        .into_iter()
        .map(|who| {
            let s = Arc::clone(&s);
            tokio::spawn(async move {
                let mut ids = Vec::new();
                for idx in 0..N {
                    let id = Id::new_v4();
                    s.push(PushBatch {
                        member_id: who.member_id,
                        device_id: who.device_id,
                        items: vec![PushItem::Deleted(PushDeleted {
                            tag: tag("rec"),
                            idx,
                            id,
                        })],
                        now: T0,
                    })
                    .await
                    .unwrap();
                    ids.push(id);
                }
                ids
            })
        })
        .collect();
    let pre = {
        let s = Arc::clone(&s);
        tokio::spawn(async move {
            let mut ids = Vec::new();
            for _ in 0..N {
                let id = Id::new_v4();
                s.delete(DeleteRequest::Ids(vec![id]), a, T0).await.unwrap();
                ids.push(id);
            }
            ids
        })
    };
    let mut want = HashSet::new();
    for m in markers {
        want.extend(m.await.unwrap());
    }
    want.extend(pre.await.unwrap());
    let page = s.deletions(0, 5_000).await.unwrap();
    assert_eq!(page.entries.len() as u64, 3 * N);
    for (i, e) in page.entries.iter().enumerate() {
        assert_eq!(e.idx, i as u64);
    }
    let got: HashSet<Id> = page.entries.iter().map(|e| e.record_id).collect();
    assert_eq!(got, want);
}

// ---------------------------------------------------------------------------------------------
// Round trip, organisation deletion

/// SQLite → Postgres → SQLite through the canonical file gives identical logical dumps and
/// digests, and the copies answer like the original.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_to_postgres_to_sqlite_gives_identical_dumps() {
    let Some(env) = PgEnv::new("rt").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let dir = TempDir::new("rt");
    let lite: Arc<dyn Store> = Arc::new(SqliteStore::open(&dir.0.join("a")).unwrap());
    let seeded = seed(&*lite).await;
    let dump = lite.dump().await.unwrap();
    let f1 = dir.0.join("from-sqlite.db");
    let c1 = lite.export_canonical(f1.clone()).await.unwrap();

    let pg = env.store.create_org(Id::new_v4()).await.unwrap();
    assert_eq!(pg.import_canonical(f1.clone()).await.unwrap(), c1);
    let pg_dump = pg.dump().await.unwrap();
    assert_eq!(pg_dump, dump, "SQLite -> Postgres");
    assert_eq!(pg_dump.digest(), dump.digest());
    assert_eq!(
        pg.restore_state().await.unwrap(),
        lite.restore_state().await.unwrap()
    );
    assert_eq!(
        pg.status(seeded.roy.device_id, T0).await.unwrap(),
        lite.status(seeded.roy.device_id, T0).await.unwrap()
    );
    let pull = |s: Arc<dyn Store>| async move {
        s.records(
            seeded.roy.member_id,
            seeded.roy.device_id,
            tag("rec"),
            0,
            500,
            BIG,
        )
        .await
        .unwrap()
    };
    assert_eq!(pull(Arc::clone(&pg)).await, pull(Arc::clone(&lite)).await);

    let f2 = dir.0.join("from-pg.db");
    let c2 = pg.export_canonical(f2.clone()).await.unwrap();
    assert_eq!(c2, c1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&f2).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert!(
        pg.export_canonical(f2.clone()).await.is_err(),
        "never overwrites"
    );
    let back: Arc<dyn Store> = Arc::new(SqliteStore::open(&dir.0.join("b")).unwrap());
    assert_eq!(back.import_canonical(f2.clone()).await.unwrap(), c1);
    let back_dump = back.dump().await.unwrap();
    assert_eq!(back_dump, dump, "Postgres -> SQLite");
    assert_eq!(back_dump.digest(), dump.digest());
    // `awm serve` opens the Postgres export unchanged.
    let opened = SqliteStore::open_file(&f2).unwrap();
    assert_eq!(opened.dump().await.unwrap(), dump);
    // An organisation imported into a scope that holds one is refused.
    assert_eq!(pg.import_canonical(f1).await, Err(StoreError::NotEmpty));
    eprintln!("round trip: {:?}, digest {}", c1.0, &dump.digest()[..16]);
}

/// Deleting an organisation removes every row with its `org_id` from every table (the
/// catalog lists the tables), in one transaction, then vacuums them; the other organisation
/// is untouched and the scope can start again empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_an_organisation_leaves_no_row_with_its_org_id() {
    let Some(env) = PgEnv::new("del").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let (ka, kb) = (Id::new_v4(), Id::new_v4());
    let a = env.store.create_org(ka).await.unwrap();
    let b = env.store.create_org(kb).await.unwrap();
    seed(&*a).await;
    seed(&*b).await;
    let before_b = b.dump().await.unwrap();
    let admin = env.admin().await;
    let tables = org_tables(&admin).await;
    assert_eq!(tables.len(), ORG_TABLES.len());
    let count = |t: String, k: Id| {
        let admin = &admin;
        async move {
            admin
                .query_one(
                    &format!("SELECT count(*) FROM {t} WHERE org_id = $1"),
                    &[&k.to_string()],
                )
                .await
                .unwrap()
                .get::<_, i64>(0)
        }
    };
    let mut total = 0;
    for t in &tables {
        let n = count(t.clone(), ka).await;
        assert!(n > 0, "{t}");
        total += n;
    }
    let vacuums = |t: &'static str| {
        let admin = &admin;
        async move {
            admin
                .query_one(
                    "SELECT vacuum_count FROM pg_stat_user_tables \
                      WHERE schemaname = current_schema() AND relname = $1",
                    &[&t],
                )
                .await
                .unwrap()
                .get::<_, i64>(0)
        }
    };
    let record_vacuums = vacuums("record").await;
    let out = env.store.delete_org(ka).await.unwrap();
    let deleted: i64 = out.rows.iter().map(|(_, n)| *n as i64).sum();
    assert_eq!(deleted, total);
    for t in &tables {
        assert_eq!(count(t.clone(), ka).await, 0, "{t} still holds a row of A");
        assert!(count(t.clone(), kb).await > 0, "{t} lost rows of B");
    }
    let mut vacuumed: Vec<&str> = out.vacuumed.clone();
    vacuumed.sort_unstable();
    let mut all: Vec<&str> = ORG_TABLES.to_vec();
    all.sort_unstable();
    assert_eq!(vacuumed, all);
    // pg_stat counters are updated asynchronously; wait for the record table's.
    let deadline = Instant::now() + Duration::from_secs(10);
    while vacuums("record").await <= record_vacuums && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(vacuums("record").await > record_vacuums, "record vacuumed");
    assert_eq!(b.dump().await.unwrap(), before_b, "B untouched");
    // The scope reads nothing, and can be created again empty.
    assert_eq!(a.org(T0).await.unwrap(), None);
    let again = env.store.create_org(ka).await.unwrap();
    assert!(again.org(T0).await.unwrap().is_none());
    seed(&*again).await;
    eprintln!("delete_org: {:?}", out.rows);
}

// ---------------------------------------------------------------------------------------------
// TM9 P2, the pool, error texts

/// Two server instances (two pools) on one organisation: the retention claim lets only one
/// batch run in an hour, also when both start at once; `claim` is a compare-and-set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_retention_claim_holds_across_instances() {
    let Some(env) = PgEnv::new("claim").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let other = env.another_store(MAX_POOL_SIZE).await;
    let org = Id::new_v4();
    let one = env.store.create_org(org).await.unwrap();
    let two = other.for_org(org);
    let (_, a) = bootstrap(&*one).await;
    for _ in 0..3 {
        push_n(&*one, &a, "rec", 500, T0).await;
    }
    let now = T0 + 400 * DAY;
    let cutoff = now - 365 * DAY;
    assert_eq!(
        one.retention_batch(cutoff, 1_000, now).await.unwrap(),
        1_000
    );
    assert_eq!(
        one.retention_batch(cutoff, 1_000, now).await.unwrap(),
        500,
        "the same run"
    );
    // A second instance within the hour deletes nothing, at the hour it runs.
    push_n(&*one, &a, "rec", 10, T0).await;
    assert_eq!(
        two.retention_batch(cutoff, 1_000, now + 60).await.unwrap(),
        0
    );
    assert_eq!(
        two.retention_batch(cutoff, 1_000, now + HOUR)
            .await
            .unwrap(),
        10
    );

    // Both at once, at different times within one hour: exactly one batch runs.
    push_n(&*one, &a, "rec", 1_500, T0).await;
    let later = now + 3 * HOUR;
    let (x, y) = tokio::join!(
        one.retention_batch(later - 365 * DAY, 1_000, later),
        two.retention_batch(later - 365 * DAY, 1_000, later + 60)
    );
    let (x, y) = (x.unwrap(), y.unwrap());
    assert!((x, y) == (1_000, 0) || (x, y) == (0, 1_000), "{x} {y}");
    let at: i64 = env
        .admin()
        .await
        .query_one(
            "SELECT at FROM claim WHERE org_id = $1 AND name = $2",
            &[&org.to_string(), &RETENTION_CLAIM],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        at,
        if x == 1_000 { later } else { later + 60 },
        "the winner's claim"
    );
    eprintln!("concurrent retention batches of two instances: {x} and {y} rows");

    // The primitive: one winner per interval.
    let (p, q) = (env.store.scope(org), other.scope(org));
    assert!(p.claim("bulk:dev", T0, HOUR).await.unwrap());
    assert!(
        p.claim("bulk:dev", T0, HOUR).await.unwrap(),
        "the holder again"
    );
    assert!(!q.claim("bulk:dev", T0 + 10, HOUR).await.unwrap());
    assert!(q.claim("bulk:dev", T0 + HOUR, HOUR).await.unwrap());
    assert!(
        !p.claim("bulk:dev", T0 + HOUR - 30, HOUR).await.unwrap(),
        "a clock 30 s behind the winner's does not win the interval again"
    );
    let racers: Vec<_> = (0..8)
        .map(|i| {
            let s = if i % 2 == 0 {
                env.store.scope(org)
            } else {
                other.scope(org)
            };
            tokio::spawn(async move { s.claim("race", T0 + i, HOUR).await.unwrap() })
        })
        .collect();
    let mut winners = 0;
    for r in racers {
        winners += usize::from(r.await.unwrap());
    }
    assert_eq!(winners, 1);
}

/// The pool holds at most 10 connections: with the organisation's lock held elsewhere, 11
/// concurrent writes open 10 connections (all waiting on the lock) and the 11th waits in the
/// pool; all complete once the lock is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pool_opens_at_most_10_connections_and_the_11th_waits() {
    let Some(env) = PgEnv::new("pool").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let pg = Arc::new(env.another_store(50).await);
    assert_eq!(pg.pool_status().max_size, MAX_POOL_SIZE, "capped");
    let org = Id::new_v4();
    let s = pg.create_org(org).await.unwrap();
    let key = org_lock_key(org);
    let holder = env.admin().await;
    holder
        .execute("SELECT pg_advisory_lock($1)", &[&key])
        .await
        .unwrap();
    let writes: Vec<_> = (0..11)
        .map(|i| {
            let s = Arc::clone(&s);
            tokio::spawn(async move { s.meta_set(format!("k{i}"), "v".into()).await })
        })
        .collect();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let st = pg.pool_status();
        if (st.size, st.waiting) == (10, 1) || Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let st = pg.pool_status();
    assert_eq!((st.size, st.available, st.waiting), (10, 0, 1), "{st:?}");
    let waiting_on_lock = || async {
        holder
            .query_one(
                "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid \
                  WHERE l.locktype = 'advisory' AND NOT l.granted \
                    AND l.classid = (($1::bigint >> 32) & 4294967295)::oid \
                    AND l.objid = ($1::bigint & 4294967295)::oid AND l.objsubid = 1 \
                    AND a.usename = $2",
                &[&key, &APP],
            )
            .await
            .unwrap()
            .get::<_, i64>(0)
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while waiting_on_lock().await < 10 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let n = waiting_on_lock().await;
    assert_eq!(n, 10, "10 backends of the pool wait on the lock, none more");
    eprintln!("pool: {st:?}; backends waiting on the organisation lock: {n}");
    holder
        .execute("SELECT pg_advisory_unlock($1)", &[&key])
        .await
        .unwrap();
    for w in writes {
        w.await.unwrap().unwrap();
    }
    assert_eq!(pg.pool_status().size, 10);
}

/// Errors carry constraint names, never the values of the DETAIL field (a token hash in a
/// unique violation, a blob).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn error_texts_hold_no_token_hash_or_blob() {
    let Some(env) = PgEnv::new("err").await else {
        return eprintln!("skipped: AWM_TEST_PG_URL not set");
    };
    let s = env.store.create_org(Id::new_v4()).await.unwrap();
    let (_, a) = bootstrap(&*s).await;
    let inv = invite(&*s, a, InviteKind::Member, "roy").await;
    // A join whose new device token hash equals the admin's: the unique (org_id, token_hash).
    let mut req = join_req(inv, "roy", Id::new_v4(), 2);
    req.device_token_hash = device_token_hash(a.device_id);
    let e = s.join(req).await.unwrap_err();
    let text = format!("{e} {e:?}");
    assert!(matches!(e, StoreError::Backend(_)), "{text}");
    assert!(
        text.contains("23505") && text.contains("device_org_id_token_hash_key"),
        "{text}"
    );
    assert!(!text.contains(&device_token_hash(a.device_id)), "{text}");
    assert!(!text.contains("DETAIL"), "{text}");
    eprintln!("unique violation as text: {text}");
}
