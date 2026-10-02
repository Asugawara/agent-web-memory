//! `Store` conformance suite (plan-v3-team §4.2, TM6).
//!
//! Every case in `cases` takes a [`Fixture`] and uses the `Store` trait only, so it runs
//! unchanged against every backend: `conformance_cases!` instantiates the cases for a factory.
//! `SqliteStore` runs them here; `PgStore` (TM26) runs them through `pg_fixture`, which reads
//! `AWM_TEST_PG_URL` and skips (passes) when it is unset. Cases that only make sense for
//! `SqliteStore` (the `backup_log` change log, the byte scan of the database file, file modes)
//! are in `sqlite_only`.
//!
//! Run: `cargo test -p awm-server --features sqlite --test store_conformance`;
//! TM26: `AWM_TEST_PG_URL=... cargo test -p awm-server --features sqlite,pg --test store_conformance`.

#![cfg(any(feature = "sqlite", feature = "pg"))]

use std::any::Any;
use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use awm_proto::wire::{
    limits, Cursor, DeleteRequest, DeviceWrap, EpochWrap, ErrorCode, Handle, Id, InviteKind, Key32,
    PulledItem, PushDeleted, PushItem, PushRecord, PushResponse, Role, SettingsUpdate, Tag,
    Version, B64,
};
use awm_server::store::{
    checksum, Actor, AuditEntry, NewBootstrap, NewInvite, NewJoin, OrgDefaults, PushBatch, Store,
    StoreError, StoreResult,
};

// ---------------------------------------------------------------------------------------------
// Fixtures

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// What a backend hands the suite.
pub struct Fixture {
    /// A migrated store without an organisation.
    pub store: Arc<dyn Store>,
    /// Opens the same store again, as a restarted server would.
    pub reopen: Box<dyn Fn() -> BoxFuture<Arc<dyn Store>> + Send + Sync>,
    /// Another empty store of the same backend (an import target).
    pub fresh: Box<dyn Fn() -> BoxFuture<Arc<dyn Store>> + Send + Sync>,
    /// A private directory for export files; removed with the fixture.
    pub scratch: PathBuf,
    /// Whatever must live as long as the fixture (temporary directories, pools).
    pub _keep: Box<dyn Any + Send + Sync>,
}

/// A directory under the target's temporary directory, mode 0700, removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "conf-{tag}-{}-{nanos}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        TempDir(p)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(feature = "sqlite")]
async fn sqlite_fixture() -> Option<Fixture> {
    use awm_server::store::sqlite::SqliteStore;
    let root = Arc::new(TempDir::new("sqlite"));
    let data = root.path().join("data");
    let scratch = root.path().join("scratch");
    std::fs::create_dir(&scratch).unwrap();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&data).unwrap());
    let reopen_dir = data.clone();
    let fresh_root = Arc::clone(&root);
    let fresh_n = Arc::new(AtomicU64::new(0));
    Some(Fixture {
        store,
        reopen: Box::new(move || {
            let dir = reopen_dir.clone();
            Box::pin(async move { Arc::new(SqliteStore::open(&dir).unwrap()) as Arc<dyn Store> })
        }),
        fresh: Box::new(move || {
            let n = fresh_n.fetch_add(1, Ordering::Relaxed);
            let dir = fresh_root.path().join(format!("fresh-{n}"));
            Box::pin(async move { Arc::new(SqliteStore::open(&dir).unwrap()) as Arc<dyn Store> })
        }),
        scratch,
        _keep: Box::new(root),
    })
}

/// TM26 replaces this body with a factory over `PgStore` (a fresh, empty organisation scope
/// per call, a `reopen` that connects again, a `fresh` that makes another empty one). The
/// cases do not change.
#[cfg(feature = "pg")]
async fn pg_fixture() -> Option<Fixture> {
    // A schema of its own per fixture (dropped with it), migrated by the owner role and served
    // by the application role; `store` is a new organisation scope, `reopen` a new pool on the
    // same scope, `fresh` another new scope of the same database.
    #[path = "support/pg.rs"]
    mod support;
    let env = Arc::new(support::PgEnv::new("conf").await?);
    let org = Id::new_v4();
    let store = env.store.create_org(org).await.unwrap();
    let root = TempDir::new("pg");
    let scratch = root.path().join("scratch");
    std::fs::create_dir(&scratch).unwrap();
    let reopen_url = env.app_url.clone();
    let fresh_env = Arc::clone(&env);
    Some(Fixture {
        store,
        reopen: Box::new(move || {
            let url = reopen_url.clone();
            Box::pin(async move {
                let pg = awm_server::store::pg::PgStore::connect(&url, None, 10)
                    .await
                    .unwrap();
                pg.for_org(org)
            })
        }),
        fresh: Box::new(move || {
            let env = Arc::clone(&fresh_env);
            Box::pin(async move { env.store.create_org(Id::new_v4()).await.unwrap() })
        }),
        scratch,
        _keep: Box::new((env, root)),
    })
}

// ---------------------------------------------------------------------------------------------
// Helpers shared by the cases

const T0: i64 = 1_790_000_000;
const DAY: i64 = 86_400;
const BIG: usize = limits::PULL_RESPONSE_BYTES;

fn h(s: &str) -> String {
    checksum(s.as_bytes())
}

fn handle(s: &str) -> Handle {
    Handle::parse(s).unwrap()
}

fn tag(s: &str) -> Tag {
    Tag::parse(s).unwrap()
}

fn device_token_hash(device: Id) -> String {
    h(&format!("device-token-{device}"))
}

fn invite_token_hash(invite: Id) -> String {
    h(&format!("invite-token-{invite}"))
}

/// An envelope-shaped blob (`0x01` and 41 + 256·k bytes) whose content is unique to `seed`.
fn blob(seed: &str, k: usize) -> B64 {
    let len = 41 + 256 * k;
    let mut v = vec![0x01u8];
    let mut i = 0u64;
    while v.len() < len {
        let d = checksum(format!("{seed}/{i}").as_bytes());
        v.extend((0..32).map(|j| u8::from_str_radix(&d[2 * j..2 * j + 2], 16).unwrap()));
        i += 1;
    }
    v.truncate(len);
    B64(v)
}

fn defaults() -> OrgDefaults {
    OrgDefaults {
        retention_days: 365,
        min_client: Version::new(0, 2, 0),
        max_members: 100,
    }
}

fn rec(t: &str, idx: u64, id: Id, epoch: u32, b: B64) -> PushItem {
    PushItem::Record(PushRecord {
        tag: tag(t),
        idx,
        id,
        epoch,
        blob: b,
    })
}

fn marker(t: &str, idx: u64, id: Id) -> PushItem {
    PushItem::Deleted(PushDeleted {
        tag: tag(t),
        idx,
        id,
    })
}

struct Org {
    org_id: Id,
    admin: Actor,
}

async fn bootstrap(s: &dyn Store) -> Org {
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
            defaults: defaults(),
            now: T0,
        })
        .await
        .unwrap();
    Org {
        org_id,
        admin: Actor {
            member_id: member,
            device_id: device,
            admin: true,
        },
    }
}

async fn invite(s: &dyn Store, by: Actor, kind: InviteKind, name: &str) -> Id {
    let invite_id = Id::new_v4();
    s.create_invite(NewInvite {
        invite_id,
        token_hash: invite_token_hash(invite_id),
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
        invite_token_hash: invite_token_hash(invite_id),
        handle: handle(name),
        device_id: device,
        device_pubkey: Key32([n; 32]),
        join_mac: Key32([n.wrapping_add(100); 32]),
        device_token_hash: device_token_hash(device),
        now: T0 + 60,
    }
}

async fn wraps_for(s: &dyn Store) -> Vec<EpochWrap> {
    let epoch = s.org(T0).await.unwrap().unwrap().current_epoch;
    (0..=epoch)
        .map(|e| EpochWrap {
            epoch: e,
            wrap: B64(vec![e as u8; 89]),
            auth: Key32([7; 32]),
        })
        .collect()
}

/// Invites, joins and approves a member with one device.
async fn add_member(s: &dyn Store, org: &Org, name: &str, n: u8) -> Actor {
    let inv = invite(s, org.admin, InviteKind::Member, name).await;
    let device = Id::new_v4();
    let joined = s.join(join_req(inv, name, device, n)).await.unwrap();
    s.approve_device(device, wraps_for(s).await, org.admin, T0 + 120)
        .await
        .unwrap();
    Actor {
        member_id: joined.member_id,
        device_id: device,
        admin: false,
    }
}

async fn push(s: &dyn Store, a: &Actor, items: Vec<PushItem>) -> StoreResult<PushResponse> {
    s.push(PushBatch {
        member_id: a.member_id,
        device_id: a.device_id,
        items,
        now: T0 + 3_600,
    })
    .await
}

/// Pushes `n` records at the stream's head + 1 in one batch; returns their ids.
async fn push_n(s: &dyn Store, a: &Actor, t: &str, n: u64) -> Vec<Id> {
    let head = s
        .stream_head(a.member_id, a.device_id, tag(t))
        .await
        .unwrap();
    let epoch = s.org(T0).await.unwrap().unwrap().current_epoch;
    let ids: Vec<Id> = (0..n).map(|_| Id::new_v4()).collect();
    let items = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            rec(
                t,
                (head + 1) as u64 + i as u64,
                *id,
                epoch,
                blob(&id.to_string(), 1),
            )
        })
        .collect();
    let r = push(s, a, items).await.unwrap();
    assert_eq!(r.accepted as u64, n);
    ids
}

async fn all_records(s: &dyn Store, a: &Actor, t: &str) -> Vec<PulledItem> {
    s.records(a.member_id, a.device_id, tag(t), 0, 500, BIG)
        .await
        .unwrap()
        .records
}

/// An error's text and debug form hold none of the given blobs' bytes.
fn assert_no_content(e: &StoreError, blobs: &[&B64]) {
    let text = format!("{e} {e:?} {:?}", e.to_body());
    for b in blobs {
        let b64 = String::from(B64(b.0.clone()));
        let hex: String = b.0[1..17].iter().map(|x| format!("{x:02x}")).collect();
        assert!(!text.contains(&b64[4..40]), "blob in error: {text}");
        assert!(!text.contains(&hex), "blob hex in error: {text}");
    }
}

fn is_code(e: &StoreError, code: ErrorCode, status: u16) {
    assert_eq!(e.code(), Some(code), "{e:?}");
    assert_eq!(e.status(), status, "{e:?}");
    let body = e.to_body().unwrap();
    assert_eq!(body.error, code);
}

// ---------------------------------------------------------------------------------------------
// The cases (backend-independent)

mod cases {
    use super::*;

    pub async fn bootstrap_creates_one_admin_and_consumes_the_token(f: Fixture) {
        let s = &*f.store;
        assert!(s.org(T0).await.unwrap().is_none());
        // No token stored yet.
        let mut req = NewBootstrap {
            bootstrap_token_hash: h("bootstrap"),
            org_id: Id::new_v4(),
            handle: handle("alf"),
            device_id: Id::new_v4(),
            device_pubkey: Key32([1; 32]),
            device_token_hash: h("d"),
            defaults: defaults(),
            now: T0,
        };
        assert_eq!(s.bootstrap(req.clone()).await, Err(StoreError::Gone));
        s.set_bootstrap(h("bootstrap"), T0 + DAY).await.unwrap();
        // A token that is not a hash never reaches a column.
        assert!(matches!(
            s.set_bootstrap("awm_b_not-a-hash".into(), T0 + DAY).await,
            Err(StoreError::InvalidValue { .. })
        ));
        let mut wrong = req.clone();
        wrong.bootstrap_token_hash = h("other");
        assert_eq!(s.bootstrap(wrong).await, Err(StoreError::Gone));
        let mut late = req.clone();
        late.now = T0 + DAY;
        assert_eq!(s.bootstrap(late).await, Err(StoreError::Gone));

        // Two concurrent uses: exactly one admin.
        let a = Arc::clone(&f.store);
        let b = Arc::clone(&f.store);
        let (ra, rb) = {
            let mut r1 = req.clone();
            r1.device_id = Id::new_v4();
            r1.device_token_hash = h("d1");
            let mut r2 = req.clone();
            r2.device_id = Id::new_v4();
            r2.device_token_hash = h("d2");
            tokio::join!(
                tokio::spawn(async move { a.bootstrap(r1).await }),
                tokio::spawn(async move { b.bootstrap(r2).await })
            )
        };
        let results = [ra.unwrap(), rb.unwrap()];
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "{results:?}"
        );
        assert!(results.contains(&Err(StoreError::Gone)));
        let members = s.members().await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].role, Role::Admin);
        assert!(members[0].devices[0].approved);

        // Used: a further bootstrap is gone, and a new token cannot be set.
        req.device_id = Id::new_v4();
        assert_eq!(s.bootstrap(req).await, Err(StoreError::Gone));
        assert_eq!(
            s.set_bootstrap(h("again"), T0 + DAY).await,
            Err(StoreError::NotEmpty)
        );
        let org = s.org(T0).await.unwrap().unwrap();
        assert_eq!(org.current_epoch, 0);
        assert_eq!(org.settings.retention_days, 365);
        let audit = s.audit(0, 100).await.unwrap();
        assert_eq!(audit.rows.len(), 1);
        assert_eq!(audit.rows[0].action, "bootstrap");
    }

    pub async fn token_lookup_is_by_hash_only(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let dev = org.admin.device_id;
        let found = s
            .auth_device(device_token_hash(dev))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.org_id, org.org_id);
        assert_eq!(found.device_id, dev);
        assert_eq!(found.member_id, org.admin.member_id);
        assert_eq!(found.role, Role::Admin);
        assert!(found.approved && !found.device_revoked && !found.member_revoked);
        // The plaintext form of a token, an unknown hash, and upper-case hex find nothing.
        let token = awm_proto::wire::DeviceToken::new(org.org_id, &[3; 32]);
        assert_eq!(
            s.auth_device(token.as_str().to_string()).await.unwrap(),
            None
        );
        assert_eq!(s.auth_device(h("unknown")).await.unwrap(), None);
        assert_eq!(
            s.auth_device(device_token_hash(dev).to_uppercase())
                .await
                .unwrap(),
            None
        );
        // Rotation: the old hash stops at once.
        s.rotate_token(dev, h("rotated"), T0).await.unwrap();
        assert_eq!(s.auth_device(device_token_hash(dev)).await.unwrap(), None);
        assert_eq!(
            s.auth_device(h("rotated"))
                .await
                .unwrap()
                .unwrap()
                .device_id,
            dev
        );
        assert!(matches!(
            s.rotate_token(dev, token.as_str().to_string(), T0).await,
            Err(StoreError::InvalidValue { .. })
        ));
        assert_eq!(
            s.rotate_token(Id::new_v4(), h("x"), T0).await,
            Err(StoreError::NotFound)
        );
        // Revocation shows in the lookup; a revoked device cannot rotate.
        let m = add_member(s, &org, "roy", 2).await;
        s.revoke_device(m.device_id, org.admin, T0).await.unwrap();
        let r = s
            .auth_device(device_token_hash(m.device_id))
            .await
            .unwrap()
            .unwrap();
        assert!(r.device_revoked && !r.member_revoked);
        assert_eq!(
            s.rotate_token(m.device_id, h("y"), T0).await,
            Err(StoreError::NotFound)
        );
        // Last seen: written once per day.
        s.touch_device(dev, 20_000).await.unwrap();
        s.touch_device(dev, 20_000).await.unwrap();
        assert_eq!(
            s.device(dev).await.unwrap().unwrap().last_seen_day,
            Some(20_000)
        );
    }

    pub async fn invites_joins_and_approvals(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let inv = invite(s, org.admin, InviteKind::Member, "roy").await;
        let row = s.invite(inv).await.unwrap().unwrap();
        assert_eq!(row.kind, InviteKind::Member);
        assert_eq!(row.role, Some(Role::Member));
        assert_eq!(row.created_by, org.admin.device_id);
        assert_eq!(row.created_by_member, org.admin.member_id);

        let device = Id::new_v4();
        let mut bad = join_req(inv, "roy", device, 2);
        bad.invite_token_hash = h("wrong");
        assert_eq!(s.join(bad).await, Err(StoreError::Gone));
        let other_handle = join_req(inv, "kit", device, 2);
        assert_eq!(
            s.join(other_handle).await,
            Err(StoreError::InvalidValue {
                field: "/handle".into()
            })
        );
        let taken = join_req(inv, "roy", org.admin.device_id, 2);
        assert_eq!(s.join(taken).await, Err(StoreError::DeviceConflict));
        let joined = s.join(join_req(inv, "roy", device, 2)).await.unwrap();
        assert_eq!(joined.org_id, org.org_id);
        assert_eq!(joined.kind, InviteKind::Member);
        // A second join with the same invite is gone.
        assert_eq!(
            s.join(join_req(inv, "roy", Id::new_v4(), 3)).await,
            Err(StoreError::Gone)
        );

        // Pending: the admin sees it; the pending device sees itself, not approved.
        let st = s.status(org.admin.device_id, T0).await.unwrap();
        assert_eq!(st.pending.len(), 1);
        assert_eq!(st.pending[0].device_id, device);
        assert_eq!(st.pending[0].handle, handle("roy"));
        assert_eq!(st.pending[0].kind, InviteKind::Member);
        assert_eq!(st.pending[0].invite_id, inv);
        assert_eq!(st.pending[0].join_mac, Key32([102; 32]));
        assert_eq!(st.pending[0].joined_at % 3_600, 0);
        let mine = s.status(device, T0).await.unwrap();
        assert!(!mine.approved);
        assert_eq!(mine.role, Role::Member);
        assert_eq!(mine.member_id, joined.member_id);

        // Approval needs a wrap for every epoch; the first wrap stays.
        assert_eq!(
            s.approve_device(device, vec![], org.admin, T0).await,
            Err(StoreError::InvalidValue {
                field: "/wraps".into()
            })
        );
        let future = vec![EpochWrap {
            epoch: 5,
            wrap: B64(vec![1; 89]),
            auth: Key32([1; 32]),
        }];
        assert_eq!(
            s.approve_device(device, future, org.admin, T0).await,
            Err(StoreError::InvalidValue {
                field: "/wraps/0/epoch".into()
            })
        );
        s.approve_device(device, wraps_for(s).await, org.admin, T0)
            .await
            .unwrap();
        let again = vec![EpochWrap {
            epoch: 0,
            wrap: B64(vec![42; 89]),
            auth: Key32([42; 32]),
        }];
        s.approve_device(device, again, org.admin, T0)
            .await
            .unwrap();
        let keys = s.keys(device).await.unwrap();
        assert_eq!(keys.wraps.len(), 1);
        assert_eq!(keys.wraps[0].wrap, B64(vec![0; 89]));
        assert_eq!(keys.wraps[0].created_by, org.admin.device_id);
        assert!(s.status(device, T0).await.unwrap().approved);
        assert!(s
            .status(org.admin.device_id, T0)
            .await
            .unwrap()
            .pending
            .is_empty());
        assert_eq!(
            s.approve_device(Id::new_v4(), vec![], org.admin, T0).await,
            Err(StoreError::NotFound)
        );

        // A device invite for an existing member keeps its member id.
        let roy = Actor {
            member_id: joined.member_id,
            device_id: device,
            admin: false,
        };
        let dinv = invite(s, roy, InviteKind::Device, "roy").await;
        let d2 = Id::new_v4();
        let j2 = s.join(join_req(dinv, "roy", d2, 4)).await.unwrap();
        assert_eq!(j2.member_id, joined.member_id);
        assert_eq!(j2.kind, InviteKind::Device);
        let st = s.status(device, T0).await.unwrap();
        assert_eq!(st.pending.len(), 1, "a member sees its own pending device");
        assert_eq!(st.pending[0].kind, InviteKind::Device);

        // Invite rules.
        let dup = NewInvite {
            invite_id: Id::new_v4(),
            token_hash: h("dup"),
            kind: InviteKind::Member,
            handle: handle("roy"),
            role: None,
            expires_at: T0 + DAY,
            by: org.admin,
            now: T0,
        };
        assert_eq!(
            s.create_invite(dup.clone()).await,
            Err(StoreError::InvalidValue {
                field: "/handle".into()
            })
        );
        let nobody = NewInvite {
            kind: InviteKind::Device,
            handle: handle("nobody"),
            ..dup.clone()
        };
        assert_eq!(
            s.create_invite(nobody).await,
            Err(StoreError::InvalidValue {
                field: "/handle".into()
            })
        );
        let role_on_device = NewInvite {
            kind: InviteKind::Device,
            role: Some(Role::Admin),
            ..dup.clone()
        };
        assert_eq!(
            s.create_invite(role_on_device).await,
            Err(StoreError::InvalidValue {
                field: "/role".into()
            })
        );
        s.update_settings(
            SettingsUpdate {
                retention_days: None,
                min_client: None,
                max_members: Some(3),
                cancel_pending_retention: None,
            },
            Version::new(0, 2, 0),
            Some(org.admin),
            T0,
        )
        .await
        .unwrap();
        let third = invite(s, org.admin, InviteKind::Member, "kit").await;
        let full = NewInvite {
            invite_id: Id::new_v4(),
            handle: handle("sage"),
            ..dup.clone()
        };
        assert_eq!(s.create_invite(full).await, Err(StoreError::Forbidden));
        // Revoking frees the seat; revocation is idempotent; unknown ids are not found.
        s.revoke_invite(third, org.admin, T0).await.unwrap();
        s.revoke_invite(third, org.admin, T0).await.unwrap();
        assert_eq!(
            s.revoke_invite(Id::new_v4(), org.admin, T0).await,
            Err(StoreError::NotFound)
        );
        assert_eq!(
            s.join(join_req(third, "kit", Id::new_v4(), 5)).await,
            Err(StoreError::Gone)
        );
        // An expired invite is gone.
        let exp = invite(s, org.admin, InviteKind::Member, "sage").await;
        let mut late = join_req(exp, "sage", Id::new_v4(), 6);
        late.now = T0 + 7 * DAY;
        assert_eq!(s.join(late).await, Err(StoreError::Gone));

        let members = s.members().await.unwrap();
        let roy_info = members.iter().find(|m| m.handle == handle("roy")).unwrap();
        assert_eq!(roy_info.devices.len(), 2);
        let first = roy_info
            .devices
            .iter()
            .find(|d| d.device_id == device)
            .unwrap();
        let second = roy_info.devices.iter().find(|d| d.device_id == d2).unwrap();
        assert!(first.approved && !second.approved);
        assert_eq!(first.device_pubkey, Key32([2; 32]));
        assert_eq!(second.device_pubkey, Key32([4; 32]));
    }

    pub async fn concurrent_appends_to_one_stream_stay_contiguous(f: Fixture) {
        let org = bootstrap(&*f.store).await;
        let a = org.admin;
        const PER_TASK: usize = 100;
        let tasks: Vec<_> = (0..2)
            .map(|t| {
                let s = Arc::clone(&f.store);
                tokio::spawn(async move {
                    let mut mine = Vec::new();
                    let mut conflicts = 0;
                    for i in 0..PER_TASK {
                        let id = Id::new_v4();
                        loop {
                            let head = s
                                .stream_head(a.member_id, a.device_id, tag("rec"))
                                .await
                                .unwrap();
                            let item = rec(
                                "rec",
                                (head + 1) as u64,
                                id,
                                0,
                                blob(&format!("{t}/{i}"), 1),
                            );
                            match push(&*s, &a, vec![item]).await {
                                Ok(r) => {
                                    assert_eq!((r.accepted, r.replayed), (1, 0));
                                    break;
                                }
                                Err(StoreError::StreamConflict { item: 0, .. }) => conflicts += 1,
                                Err(e) => panic!("task {t}: {e}"),
                            }
                        }
                        mine.push(id);
                    }
                    (mine, conflicts)
                })
            })
            .collect();
        let mut expected = HashSet::new();
        let mut conflicts = 0;
        for t in tasks {
            let (ids, c) = t.await.unwrap();
            conflicts += c;
            expected.extend(ids);
        }
        let items = all_records(&*f.store, &a, "rec").await;
        assert_eq!(items.len(), 2 * PER_TASK);
        for (i, it) in items.iter().enumerate() {
            assert_eq!(it.idx(), i as u64, "no gap, no duplicate idx");
        }
        let got: HashSet<Id> = items.iter().map(PulledItem::id).collect();
        assert_eq!(got, expected, "every pushed id exactly once");
        eprintln!(
            "concurrent appends: {} records, {conflicts} conflicts retried",
            items.len()
        );

        // The deletion stream stays contiguous under concurrent deletions too.
        let ids: Vec<Id> = got.into_iter().collect();
        let halves: Vec<Vec<Id>> = ids.chunks(PER_TASK).map(<[Id]>::to_vec).collect();
        let dels: Vec<_> = halves
            .into_iter()
            .map(|half| {
                let s = Arc::clone(&f.store);
                tokio::spawn(async move {
                    for chunk in half.chunks(7) {
                        s.delete(DeleteRequest::Ids(chunk.to_vec()), a, T0)
                            .await
                            .unwrap();
                    }
                    for _ in 0..20 {
                        s.delete(DeleteRequest::Ids(vec![Id::new_v4()]), a, T0)
                            .await
                            .unwrap();
                    }
                })
            })
            .collect();
        for d in dels {
            d.await.unwrap();
        }
        let page = f.store.deletions(0, 5_000).await.unwrap();
        assert_eq!(page.entries.len(), 2 * PER_TASK + 40);
        assert_eq!(page.head, (2 * PER_TASK + 40) as i64 - 1);
        assert_eq!(page.oldest, 0);
        for (i, e) in page.entries.iter().enumerate() {
            assert_eq!(e.idx, i as u64);
        }
        let unique: HashSet<Id> = page.entries.iter().map(|e| e.record_id).collect();
        assert_eq!(unique.len(), page.entries.len());
    }

    pub async fn a_duplicate_push_is_a_no_op(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let id = Id::new_v4();
        let b = blob("dup", 2);
        let first = push(s, &a, vec![rec("rec", 0, id, 0, b.clone())])
            .await
            .unwrap();
        assert_eq!((first.accepted, first.replayed), (1, 0));
        assert_eq!(first.heads.len(), 1);
        assert_eq!(first.heads[0].head, 0);
        let before = s.dump().await.unwrap();
        let again = push(s, &a, vec![rec("rec", 0, id, 0, b.clone())])
            .await
            .unwrap();
        assert_eq!((again.accepted, again.replayed), (0, 1));
        assert_eq!(again.heads[0].head, 0);
        // Idempotent by (stream, idx, id): another blob, epoch or the marker form replays too.
        let other = push(s, &a, vec![rec("rec", 0, id, 3, blob("other", 1))])
            .await
            .unwrap();
        assert_eq!(other.replayed, 1);
        let as_marker = push(s, &a, vec![marker("rec", 0, id)]).await.unwrap();
        assert_eq!(as_marker.replayed, 1);
        assert_eq!(s.dump().await.unwrap(), before, "nothing changed");
        match &all_records(s, &a, "rec").await[0] {
            PulledItem::Record(r) => {
                assert_eq!(r.blob, b, "the first blob stays");
                assert_eq!(r.received_at % 3_600, 0);
                assert_eq!(r.epoch, 0);
            }
            other => panic!("{other:?}"),
        }
        // Within one batch: the second copy of an item replays.
        let id2 = Id::new_v4();
        let both = push(
            s,
            &a,
            vec![
                rec("rec", 1, id2, 0, blob("x", 1)),
                rec("rec", 1, id2, 0, blob("x", 1)),
            ],
        )
        .await
        .unwrap();
        assert_eq!((both.accepted, both.replayed), (1, 1));
    }

    pub async fn a_different_record_at_an_existing_index_conflicts(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let ids = push_n(s, &a, "rec", 3).await;
        let before = s.dump().await.unwrap();
        let b = blob("intruder", 1);
        // A valid item first, then a different id at index 1: the whole batch is refused.
        let e = push(
            s,
            &a,
            vec![
                rec("rec", 3, Id::new_v4(), 0, blob("ok", 1)),
                rec("rec", 1, Id::new_v4(), 0, b.clone()),
            ],
        )
        .await
        .unwrap_err();
        assert_eq!(
            e,
            StoreError::StreamConflict { item: 1, head: 3 },
            "head counts item 0"
        );
        is_code(&e, ErrorCode::StreamConflict, 409);
        assert_eq!(e.to_body().unwrap().head, Some(3));
        assert_eq!(e.to_body().unwrap().item, Some(1));
        assert_no_content(&e, &[&b]);
        assert_eq!(
            s.dump().await.unwrap(),
            before,
            "nothing of a failed request is stored"
        );
        // A gap is a stream conflict with the head.
        let e = push(s, &a, vec![rec("rec", 5, Id::new_v4(), 0, b.clone())])
            .await
            .unwrap_err();
        assert_eq!(e, StoreError::StreamConflict { item: 0, head: 2 });
        assert_eq!(ids.len(), 3);
    }

    pub async fn the_same_id_at_another_position_conflicts(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let ids = push_n(s, &a, "rec", 2).await;
        let b = blob("moved", 1);
        // Same stream, next index.
        let e = push(s, &a, vec![rec("rec", 2, ids[0], 0, b.clone())])
            .await
            .unwrap_err();
        assert_eq!(e, StoreError::IdConflict { item: 0 });
        is_code(&e, ErrorCode::IdConflict, 409);
        assert_no_content(&e, &[&b]);
        // Another tag of the same device, and another member's stream.
        let e = push(s, &a, vec![rec("flag", 0, ids[1], 0, b.clone())])
            .await
            .unwrap_err();
        assert_eq!(e, StoreError::IdConflict { item: 0 });
        let e = push(s, &roy, vec![marker("rec", 0, ids[1])])
            .await
            .unwrap_err();
        assert_eq!(e, StoreError::IdConflict { item: 0 });
        // Within one batch.
        let fresh = Id::new_v4();
        let e = push(
            s,
            &a,
            vec![
                rec("rec", 2, fresh, 0, b.clone()),
                rec("rec", 3, fresh, 0, b.clone()),
            ],
        )
        .await
        .unwrap_err();
        assert_eq!(e, StoreError::IdConflict { item: 1 });
    }

    pub async fn stale_epochs_are_refused_after_the_replay_check(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let ids = push_n(s, &a, "rec", 1).await;
        // Rotation rules.
        let w = |d: Id| DeviceWrap {
            device_id: d,
            wrap: B64(vec![5; 89]),
            auth: Key32([5; 32]),
        };
        assert_eq!(
            s.rotate_keys(2, vec![w(a.device_id)], a, T0).await,
            Err(StoreError::EpochConflict { current_epoch: 0 })
        );
        assert_eq!(
            s.rotate_keys(1, vec![w(a.device_id), w(Id::new_v4())], a, T0)
                .await,
            Err(StoreError::InvalidValue {
                field: "/wraps/1/device_id".into()
            })
        );
        assert_eq!(
            s.rotate_keys(1, vec![w(a.device_id), w(a.device_id)], a, T0)
                .await,
            Err(StoreError::InvalidValue {
                field: "/wraps/1/device_id".into()
            })
        );
        s.revoke_device(roy.device_id, a, T0).await.unwrap();
        assert!(s.org(T0).await.unwrap().unwrap().rotation_needed);
        assert_eq!(
            s.rotate_keys(1, vec![w(a.device_id), w(roy.device_id)], a, T0)
                .await,
            Err(StoreError::InvalidValue {
                field: "/wraps/1/device_id".into()
            })
        );
        s.rotate_keys(1, vec![w(a.device_id)], a, T0).await.unwrap();
        let org_row = s.org(T0).await.unwrap().unwrap();
        assert_eq!(org_row.current_epoch, 1);
        assert!(!org_row.rotation_needed);
        let keys = s.keys(a.device_id).await.unwrap();
        assert_eq!(keys.current_epoch, 1);
        // The bootstrap device made K_0 itself, so its only wrap is the rotation's.
        assert_eq!(keys.wraps.iter().map(|w| w.epoch).collect::<Vec<_>>(), [1]);
        assert_eq!(keys.wraps[0].created_by, a.device_id);
        assert_eq!(
            s.rotate_keys(1, vec![w(a.device_id)], a, T0).await,
            Err(StoreError::EpochConflict { current_epoch: 1 })
        );
        // The acknowledged record replays under its old epoch; a new one under epoch 0 is stale.
        let r = push(s, &a, vec![rec("rec", 0, ids[0], 0, blob("re", 1))])
            .await
            .unwrap();
        assert_eq!(r.replayed, 1);
        let e = push(s, &a, vec![rec("rec", 1, Id::new_v4(), 0, blob("old", 1))])
            .await
            .unwrap_err();
        assert_eq!(
            e,
            StoreError::StaleEpoch {
                item: 0,
                current_epoch: 1
            }
        );
        is_code(&e, ErrorCode::StaleEpoch, 409);
        assert_eq!(e.to_body().unwrap().current_epoch, Some(1));
        // Markers carry no epoch.
        push(s, &a, vec![marker("rec", 1, Id::new_v4())])
            .await
            .unwrap();
        push(s, &a, vec![rec("rec", 2, Id::new_v4(), 1, blob("new", 1))])
            .await
            .unwrap();
    }

    pub async fn a_deletion_leaves_a_marker_and_one_deletion_entry(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let ids = push_n(s, &roy, "rec", 3).await;
        let target = ids[1];
        // A member may not delete another member's record; an admin may.
        let alf_ids = push_n(s, &a, "rec", 1).await;
        assert_eq!(
            s.delete(DeleteRequest::Ids(vec![target, alf_ids[0]]), roy, T0)
                .await,
            Err(StoreError::Forbidden)
        );
        assert_eq!(
            s.deletion_heads().await.unwrap().head,
            -1,
            "nothing deleted"
        );
        let r = s
            .delete(DeleteRequest::Ids(vec![target]), roy, T0 + 10)
            .await
            .unwrap();
        assert_eq!((r.deleted, r.already), (1, 0));
        let items = all_records(s, &roy, "rec").await;
        assert_eq!(items.len(), 3, "the index is kept");
        assert!(matches!(&items[1], PulledItem::Deleted(d) if d.idx == 1 && d.id == target));
        assert!(matches!(&items[0], PulledItem::Record(_)));
        let page = s.deletions(0, 100).await.unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].record_id, target);
        assert_eq!((page.head, page.oldest), (0, 0));
        // Repeating is idempotent; the blob does not come back.
        let r = s
            .delete(DeleteRequest::Ids(vec![target]), roy, T0)
            .await
            .unwrap();
        assert_eq!((r.deleted, r.already), (0, 1));
        assert_eq!(s.deletions(0, 100).await.unwrap().entries.len(), 1);
        // A retry of the acknowledged push replays (the marker keeps the id).
        let r = push(s, &roy, vec![rec("rec", 1, target, 0, blob("again", 1))])
            .await
            .unwrap();
        assert_eq!(r.replayed, 1);
        // The same deleted id pushed as a record elsewhere: 410 with every deleted id.
        let b = blob("resurrect", 1);
        let e = push(
            s,
            &roy,
            vec![
                rec("rec", 3, Id::new_v4(), 0, blob("fine", 1)),
                rec("rec", 4, target, 0, b.clone()),
            ],
        )
        .await
        .unwrap_err();
        assert_eq!(
            e,
            StoreError::Deleted {
                item: 1,
                ids: vec![target]
            }
        );
        is_code(&e, ErrorCode::Deleted, 410);
        assert_eq!(e.to_body().unwrap().ids, Some(vec![target]));
        assert_no_content(&e, &[&b]);
        // An admin deletes roy's record.
        let r = s
            .delete(DeleteRequest::Ids(vec![ids[2]]), a, T0)
            .await
            .unwrap();
        assert_eq!(r.deleted, 1);
        // Pre-deletion of an unknown id: by the same member 410, by another member 409.
        let pre = Id::new_v4();
        let r = s
            .delete(DeleteRequest::Ids(vec![pre]), roy, T0)
            .await
            .unwrap();
        assert_eq!((r.deleted, r.already), (1, 0));
        let e = push(s, &roy, vec![rec("rec", 3, pre, 0, blob("p", 1))])
            .await
            .unwrap_err();
        assert_eq!(
            e,
            StoreError::Deleted {
                item: 0,
                ids: vec![pre]
            }
        );
        let e = push(s, &a, vec![rec("rec", 1, pre, 0, blob("p", 1))])
            .await
            .unwrap_err();
        assert_eq!(e, StoreError::IdConflict { item: 0 });
        // all_mine and member.
        push_n(s, &roy, "flag", 2).await;
        assert_eq!(
            s.delete(DeleteRequest::Member(a.member_id), roy, T0).await,
            Err(StoreError::Forbidden)
        );
        assert_eq!(
            s.delete(DeleteRequest::Member(Id::new_v4()), a, T0).await,
            Err(StoreError::NotFound)
        );
        let r = s.delete(DeleteRequest::AllMine, roy, T0).await.unwrap();
        assert_eq!((r.deleted, r.already), (3, 0), "rec 0 and two flags");
        let r = s.delete(DeleteRequest::AllMine, roy, T0).await.unwrap();
        assert_eq!((r.deleted, r.already), (0, 0));
        let r = s
            .delete(DeleteRequest::Member(a.member_id), a, T0)
            .await
            .unwrap();
        assert_eq!(r.deleted, 1);
        let heads = s.deletion_heads().await.unwrap();
        assert_eq!((heads.head, heads.oldest), (6, 0));
        // Every deletion is audited with counts only.
        let audit = s.audit(0, 1_000).await.unwrap();
        let deletes: Vec<_> = audit.rows.iter().filter(|r| r.action == "delete").collect();
        assert_eq!(deletes.len(), 7);
        assert!(deletes
            .iter()
            .all(|r| r.detail.as_deref().unwrap().starts_with("deleted=")));
    }

    pub async fn a_reseed_marker_at_head_plus_one_is_accepted(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        push_n(s, &a, "rec", 2).await;
        // A marker for an index whose record the writer deleted before a restore.
        let gone = Id::new_v4();
        let r = push(s, &a, vec![marker("rec", 2, gone)]).await.unwrap();
        assert_eq!((r.accepted, r.replayed), (1, 0));
        assert_eq!(r.heads[0].head, 2);
        let page = s.deletions(0, 10).await.unwrap();
        assert_eq!(
            page.entries.len(),
            1,
            "the marker's id enters the deletion stream"
        );
        assert_eq!(page.entries[0].record_id, gone);
        // A marker for an id this member pre-deleted adds no second entry.
        let pre = Id::new_v4();
        s.delete(DeleteRequest::Ids(vec![pre]), a, T0)
            .await
            .unwrap();
        let r = push(s, &a, vec![marker("rec", 3, pre)]).await.unwrap();
        assert_eq!(r.accepted, 1);
        assert_eq!(s.deletions(0, 10).await.unwrap().entries.len(), 2);
        // Not at head + 1: refused.
        let e = push(s, &a, vec![marker("rec", 9, Id::new_v4())])
            .await
            .unwrap_err();
        assert_eq!(e, StoreError::StreamConflict { item: 0, head: 3 });
        // Markers and records mixed in one batch; the stream reads back contiguous.
        let next = Id::new_v4();
        push(
            s,
            &a,
            vec![
                marker("rec", 4, Id::new_v4()),
                rec("rec", 5, next, 0, blob("n", 1)),
            ],
        )
        .await
        .unwrap();
        let items = all_records(s, &a, "rec").await;
        assert_eq!(
            items.iter().map(PulledItem::idx).collect::<Vec<_>>(),
            [0, 1, 2, 3, 4, 5]
        );
        assert!(matches!(items[2], PulledItem::Deleted(_)));
        assert!(matches!(items[5], PulledItem::Record(_)));
        // Markers do not count against the daily quota; records and pre-deletions do.
        assert_eq!(s.pushed_since(a.member_id, T0).await.unwrap(), 3);
    }

    pub async fn pull_by_cursor_returns_the_right_rows_across_streams(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let a_rec = push_n(s, &a, "rec", 5).await;
        let r_rec = push_n(s, &roy, "rec", 3).await;
        let r_flag = push_n(s, &roy, "flag", 2).await;
        s.delete(DeleteRequest::Ids(vec![a_rec[3]]), a, T0)
            .await
            .unwrap();
        let cur = |who: &Actor, t: &str, from: u64| Cursor {
            member: who.member_id,
            device: who.device_id,
            tag: tag(t),
            from,
        };
        // Limit 6 over three streams: 4 from the first (from 1), 2 of the second; the third is
        // not reached.
        let p = s
            .pull(
                vec![cur(&a, "rec", 1), cur(&roy, "rec", 0), cur(&roy, "flag", 0)],
                6,
                BIG,
            )
            .await
            .unwrap();
        assert!(p.more);
        assert_eq!(p.streams.len(), 2);
        assert_eq!(p.streams[0].head, 4);
        assert_eq!(
            p.streams[0]
                .records
                .iter()
                .map(PulledItem::id)
                .collect::<Vec<_>>(),
            a_rec[1..].to_vec()
        );
        assert!(matches!(p.streams[0].records[2], PulledItem::Deleted(_)));
        assert_eq!(p.streams[1].member, roy.member_id);
        assert_eq!(p.streams[1].head, 2);
        assert_eq!(
            p.streams[1]
                .records
                .iter()
                .map(PulledItem::id)
                .collect::<Vec<_>>(),
            r_rec[..2].to_vec()
        );
        // The next request continues; everything fits; unknown and caught-up streams.
        let ghost = Actor {
            member_id: Id::new_v4(),
            device_id: Id::new_v4(),
            admin: false,
        };
        let p = s
            .pull(
                vec![
                    cur(&roy, "rec", 2),
                    cur(&roy, "flag", 0),
                    cur(&a, "rec", 5),
                    cur(&ghost, "rec", 0),
                ],
                500,
                BIG,
            )
            .await
            .unwrap();
        assert!(!p.more);
        assert_eq!(p.streams.len(), 4);
        assert_eq!(
            p.streams[0]
                .records
                .iter()
                .map(PulledItem::id)
                .collect::<Vec<_>>(),
            [r_rec[2]]
        );
        assert_eq!(
            p.streams[1]
                .records
                .iter()
                .map(PulledItem::id)
                .collect::<Vec<_>>(),
            r_flag
        );
        assert_eq!((p.streams[2].head, p.streams[2].records.len()), (4, 0));
        assert_eq!((p.streams[3].head, p.streams[3].records.len()), (-1, 0));
        // A byte budget cuts the response: fewer records, `more`, still contiguous.
        let one = serde_json::to_vec(&p.streams[1]).unwrap().len();
        let p = s
            .pull(
                vec![cur(&a, "rec", 0), cur(&roy, "flag", 0)],
                500,
                one + 200,
            )
            .await
            .unwrap();
        assert!(p.more);
        let got = &p.streams[0].records;
        assert!(!got.is_empty() && got.len() < 5, "{}", got.len());
        for (i, it) in got.iter().enumerate() {
            assert_eq!(it.idx(), i as u64);
        }
        assert!(serde_json::to_vec(&p).unwrap().len() <= one + 200);
        // GET /v1/records: one stream, from and limit.
        let r = s
            .records(a.member_id, a.device_id, tag("rec"), 2, 2, BIG)
            .await
            .unwrap();
        assert_eq!(r.head, 4);
        assert_eq!(
            r.records.iter().map(PulledItem::idx).collect::<Vec<_>>(),
            [2, 3]
        );
        // The status lists every stream's head.
        let st = s.status(a.device_id, T0).await.unwrap();
        assert_eq!(st.streams.len(), 3);
        assert!(st
            .streams
            .iter()
            .any(|h| h.member == roy.member_id && h.tag == tag("flag") && h.head == 1));
        assert_eq!((st.deletions.head, st.deletions.oldest), (0, 0));
    }

    pub async fn export_and_import_give_identical_logical_dumps(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let kit = add_member(s, &org, "kit", 3).await;
        let pending = invite(s, roy, InviteKind::Device, "roy").await;
        s.join(join_req(pending, "roy", Id::new_v4(), 4))
            .await
            .unwrap();
        let revoked = invite(s, a, InviteKind::Member, "sage").await;
        s.revoke_invite(revoked, a, T0).await.unwrap();
        invite(s, a, InviteKind::Member, "yves").await;
        let ids = push_n(s, &roy, "rec", 4).await;
        push_n(s, &a, "policy", 1).await;
        push_n(s, &a, "roster", 2).await;
        s.delete(DeleteRequest::Ids(vec![ids[0], Id::new_v4()]), roy, T0)
            .await
            .unwrap();
        push(s, &roy, vec![marker("rec", 4, Id::new_v4())])
            .await
            .unwrap();
        s.remove_member(kit.member_id, true, a, T0).await.unwrap();
        let wrap = DeviceWrap {
            device_id: a.device_id,
            wrap: B64(vec![8; 89]),
            auth: Key32([8; 32]),
        };
        let wrap_roy = DeviceWrap {
            device_id: roy.device_id,
            ..wrap.clone()
        };
        s.rotate_keys(1, vec![wrap, wrap_roy], a, T0).await.unwrap();
        push_n(s, &roy, "rec", 1).await;
        s.update_settings(
            SettingsUpdate {
                retention_days: Some(90),
                min_client: Some(Version::new(0, 2, 1)),
                max_members: Some(20),
                cancel_pending_retention: None,
            },
            Version::new(0, 2, 0),
            Some(a),
            T0,
        )
        .await
        .unwrap();
        s.set_role(roy.member_id, Role::Admin, Some(a), T0)
            .await
            .unwrap();
        s.append_audit(AuditEntry {
            at: T0,
            actor: Some(a.member_id),
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
        s.touch_device(a.device_id, 20_710).await.unwrap();

        let dump = s.dump().await.unwrap();
        assert!(dump
            .rows("meta")
            .iter()
            .all(|r| !format!("{r:?}").contains("backup_")));
        let file = f.scratch.join("org.awm.sqlite");
        let counts = s.export_canonical(file.clone()).await.unwrap();
        for (table, rows) in &dump.tables {
            assert_eq!(counts.get(table), Some(rows.len() as u64), "{table}");
        }
        assert!(
            s.export_canonical(file.clone()).await.is_err(),
            "an export never overwrites a file"
        );

        let other = (f.fresh)().await;
        let imported = other.import_canonical(file.clone()).await.unwrap();
        assert_eq!(imported, counts);
        let copy = other.dump().await.unwrap();
        assert_eq!(copy, dump, "identical logical dumps");
        assert_eq!(copy.digest(), dump.digest());
        // The import keeps generation; the copy answers like the original.
        assert_eq!(
            other.restore_state().await.unwrap(),
            s.restore_state().await.unwrap()
        );
        assert_eq!(
            other.status(roy.device_id, T0).await.unwrap(),
            s.status(roy.device_id, T0).await.unwrap()
        );
        assert_eq!(
            other
                .auth_device(device_token_hash(a.device_id))
                .await
                .unwrap(),
            s.auth_device(device_token_hash(a.device_id)).await.unwrap()
        );
        // A store that holds an organisation refuses an import.
        assert_eq!(
            other.import_canonical(file.clone()).await,
            Err(StoreError::NotEmpty)
        );
        assert_eq!(
            s.import_canonical(file.clone()).await,
            Err(StoreError::NotEmpty)
        );
        // Round trip again.
        let file2 = f.scratch.join("org2.awm.sqlite");
        other.export_canonical(file2.clone()).await.unwrap();
        let third = (f.fresh)().await;
        third.import_canonical(file2).await.unwrap();
        assert_eq!(third.dump().await.unwrap(), dump);
        // A dump's debug form holds no blob bytes.
        let text = format!("{dump:?}");
        for id in &ids[1..] {
            let b = String::from(blob(&id.to_string(), 1));
            assert!(!text.contains(&b[4..40]));
        }
    }

    pub async fn generation_changes_on_renew_and_survives_reopen(f: Fixture) {
        let s = &*f.store;
        let g0 = s.restore_state().await.unwrap();
        assert!(!g0.restore_pending);
        assert_eq!(g0.restored_at, None);
        assert_eq!(
            Id::parse(&g0.generation.to_string()).unwrap(),
            g0.generation
        );
        assert_eq!(g0.generation.as_uuid().get_version_num(), 4);
        let reopened = (f.reopen)().await;
        assert_eq!(reopened.restore_state().await.unwrap(), g0);
        let org = bootstrap(s).await;

        let g1 = s.renew_generation(T0 + 50).await.unwrap();
        assert_ne!(g1, g0.generation);
        let st = s.restore_state().await.unwrap();
        assert_eq!(st.generation, g1);
        assert!(st.restore_pending);
        assert_eq!(st.restored_at, Some(T0 + 50));
        let reopened = (f.reopen)().await;
        assert_eq!(
            reopened.restore_state().await.unwrap(),
            st,
            "survives reopen"
        );
        let status = reopened.status(org.admin.device_id, T0).await.unwrap();
        assert_eq!(status.generation, g1);
        assert!(status.restore_pending);

        assert_eq!(
            s.complete_restore(g0.generation, org.admin, T0).await,
            Err(StoreError::InvalidValue {
                field: "/generation".into()
            })
        );
        s.complete_restore(g1, org.admin, T0).await.unwrap();
        s.complete_restore(g1, org.admin, T0).await.unwrap();
        assert!(!s.restore_state().await.unwrap().restore_pending);
        let g2 = s.renew_generation(T0 + 60).await.unwrap();
        assert!(g2 != g1 && g2 != g0.generation);
        let actions: Vec<String> = s
            .audit(0, 100)
            .await
            .unwrap()
            .rows
            .into_iter()
            .map(|r| r.action)
            .collect();
        assert_eq!(
            actions.iter().filter(|a| a.as_str() == "restore").count(),
            2
        );
        assert_eq!(
            actions
                .iter()
                .filter(|a| a.as_str() == "restore.complete")
                .count(),
            1
        );
        // The store owns these keys.
        for key in [
            "generation",
            "restore_pending",
            "restored_at",
            "schema_version",
            "bootstrap_token_hash",
        ] {
            assert!(matches!(
                s.meta_set(key.into(), "x".into()).await,
                Err(StoreError::InvalidValue { .. })
            ));
        }
        s.meta_set("backup_cursor".into(), "5".into())
            .await
            .unwrap();
        assert_eq!(
            s.meta_get("backup_cursor".into()).await.unwrap().as_deref(),
            Some("5")
        );
        assert_eq!(s.meta_get("nothing".into()).await.unwrap(), None);
    }

    pub async fn settings_follow_the_retention_and_min_client_rules(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let floor = Version::new(0, 2, 0);
        let upd = |r: Option<u32>, m: Option<Version>, c: Option<bool>| SettingsUpdate {
            retention_days: r,
            min_client: m,
            max_members: None,
            cancel_pending_retention: c,
        };
        let a = Some(org.admin);
        assert_eq!(
            s.update_settings(upd(Some(29), None, None), floor.clone(), a, T0)
                .await,
            Err(StoreError::InvalidValue {
                field: "/retention_days".into()
            })
        );
        // A decrease waits 7 days.
        let st = s
            .update_settings(upd(Some(90), None, None), floor.clone(), a, T0)
            .await
            .unwrap();
        assert_eq!(st.retention_days, 365);
        let p = st.pending_retention.unwrap();
        assert_eq!((p.retention_days, p.effective_at), (90, T0 + 7 * DAY));
        let status = s.status(org.admin.device_id, T0).await.unwrap();
        assert_eq!(
            status.settings.pending_retention.unwrap().retention_days,
            90
        );
        assert_eq!(
            s.org(T0 + 7 * DAY - 1)
                .await
                .unwrap()
                .unwrap()
                .settings
                .retention_days,
            365
        );
        let later = s.org(T0 + 7 * DAY).await.unwrap().unwrap().settings;
        assert_eq!((later.retention_days, later.pending_retention), (90, None));
        // Cancelled by any admin, or by an increase.
        let st = s
            .update_settings(upd(None, None, Some(true)), floor.clone(), a, T0)
            .await
            .unwrap();
        assert_eq!((st.retention_days, st.pending_retention), (365, None));
        s.update_settings(upd(Some(60), None, None), floor.clone(), a, T0)
            .await
            .unwrap();
        let st = s
            .update_settings(upd(Some(400), None, None), floor.clone(), a, T0)
            .await
            .unwrap();
        assert_eq!((st.retention_days, st.pending_retention), (400, None));
        // min_client only rises and never below the floor.
        let st = s
            .update_settings(
                upd(None, Some(Version::new(0, 3, 0)), None),
                floor.clone(),
                a,
                T0,
            )
            .await
            .unwrap();
        assert_eq!(st.min_client, Version::new(0, 3, 0));
        assert_eq!(
            s.update_settings(
                upd(None, Some(Version::new(0, 2, 5)), None),
                floor.clone(),
                a,
                T0
            )
            .await,
            Err(StoreError::InvalidValue {
                field: "/min_client".into()
            })
        );
        assert_eq!(
            s.update_settings(
                upd(None, Some(Version::new(0, 3, 1)), None),
                Version::new(0, 4, 0),
                a,
                T0
            )
            .await,
            Err(StoreError::InvalidValue {
                field: "/min_client".into()
            })
        );
        // A due decrease is written by the next change.
        s.update_settings(upd(Some(100), None, None), floor.clone(), a, T0)
            .await
            .unwrap();
        let st = s
            .update_settings(upd(None, None, None), floor.clone(), a, T0 + 8 * DAY)
            .await
            .unwrap();
        assert_eq!((st.retention_days, st.pending_retention), (100, None));
        let n = s
            .audit(0, 100)
            .await
            .unwrap()
            .rows
            .iter()
            .filter(|r| r.action == "settings")
            .count();
        // Six changes; refusals and the promotion of a due decrease add no row.
        assert_eq!(n, 6);
    }

    pub async fn removal_roles_and_the_last_admin(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        assert_eq!(
            s.remove_member(a.member_id, false, a, T0).await,
            Err(StoreError::LastAdmin)
        );
        assert_eq!(
            s.set_role(a.member_id, Role::Member, Some(a), T0).await,
            Err(StoreError::LastAdmin)
        );
        assert_eq!(
            s.set_role(a.member_id, Role::Unknown, Some(a), T0).await,
            Err(StoreError::InvalidValue {
                field: "/role".into()
            })
        );
        let roy = add_member(s, &org, "roy", 2).await;
        let open = invite(s, roy, InviteKind::Device, "roy").await;
        push_n(s, &roy, "rec", 3).await;
        s.set_role(roy.member_id, Role::Admin, None, T0)
            .await
            .unwrap();
        s.set_role(a.member_id, Role::Member, Some(a), T0)
            .await
            .unwrap();
        assert_eq!(
            s.member(a.member_id).await.unwrap().unwrap().role,
            Role::Member
        );
        s.set_role(a.member_id, Role::Admin, None, T0)
            .await
            .unwrap();
        // Removal revokes the member, its devices and its open invites, and asks for rotation.
        let deleted = s.remove_member(roy.member_id, true, a, T0).await.unwrap();
        assert_eq!(deleted, 3);
        let auth = s
            .auth_device(device_token_hash(roy.device_id))
            .await
            .unwrap()
            .unwrap();
        assert!(auth.member_revoked && auth.device_revoked);
        assert!(s.org(T0).await.unwrap().unwrap().rotation_needed);
        assert!(s.invite(open).await.unwrap().unwrap().revoked_at.is_some());
        assert_eq!(s.deletion_heads().await.unwrap().head, 2);
        assert_eq!(s.member_by_handle(handle("roy")).await.unwrap(), None);
        let info = s.members().await.unwrap();
        let r = info.iter().find(|m| m.member_id == roy.member_id).unwrap();
        assert!(!r.active && r.devices.iter().all(|d| d.revoked));
        // Idempotent; unknown members are not found; a removed member's role cannot change.
        assert_eq!(s.remove_member(roy.member_id, true, a, T0).await, Ok(0));
        assert_eq!(
            s.remove_member(Id::new_v4(), false, a, T0).await,
            Err(StoreError::NotFound)
        );
        assert_eq!(
            s.set_role(roy.member_id, Role::Member, Some(a), T0).await,
            Err(StoreError::NotFound)
        );
        // The handle is free again for a new member.
        add_member(s, &org, "roy", 5).await;
    }

    pub async fn retention_is_bounded_oldest_first_and_prunes_keep_the_head(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let at = |t: i64, items: Vec<PushItem>| PushBatch {
            member_id: a.member_id,
            device_id: a.device_id,
            items,
            now: t,
        };
        let mut old = Vec::new();
        for i in 0..5u64 {
            let id = Id::new_v4();
            old.push(id);
            s.push(at(
                T0 + i as i64 * 3_600,
                vec![rec("rec", i, id, 0, blob(&id.to_string(), 1))],
            ))
            .await
            .unwrap();
        }
        let young = Id::new_v4();
        s.push(at(
            T0 + 100 * DAY,
            vec![rec("rec", 5, young, 0, blob("young", 1))],
        ))
        .await
        .unwrap();
        let cutoff = T0 + 10 * DAY;
        assert_eq!(
            s.retention_batch(cutoff, 2, T0 + 101 * DAY).await.unwrap(),
            2
        );
        let page = s.deletions(0, 10).await.unwrap();
        assert_eq!(
            page.entries.iter().map(|e| e.record_id).collect::<Vec<_>>(),
            old[..2].to_vec(),
            "oldest first"
        );
        assert_eq!(
            s.retention_batch(cutoff, 2, T0 + 101 * DAY).await.unwrap(),
            2
        );
        assert_eq!(
            s.retention_batch(cutoff, 2, T0 + 101 * DAY).await.unwrap(),
            1
        );
        assert_eq!(
            s.retention_batch(cutoff, 2, T0 + 101 * DAY).await.unwrap(),
            0
        );
        let items = all_records(s, &a, "rec").await;
        assert!(items[..5]
            .iter()
            .all(|i| matches!(i, PulledItem::Deleted(_))));
        assert!(
            matches!(items[5], PulledItem::Record(_)),
            "younger records stay"
        );
        // Pruning keeps the newest entry so the head never moves back.
        assert_eq!(s.prune_deletions(T0 + 200 * DAY).await.unwrap(), 4);
        let heads = s.deletion_heads().await.unwrap();
        assert_eq!((heads.head, heads.oldest), (4, 4));
        s.delete(DeleteRequest::Ids(vec![Id::new_v4()]), a, T0)
            .await
            .unwrap();
        assert_eq!(s.deletion_heads().await.unwrap().head, 5);
        let n = s.audit(0, 100).await.unwrap().rows.len() as u64;
        assert_eq!(s.prune_audit(T0 + 1_000 * DAY).await.unwrap(), n - 1);
        let audit = s.audit(0, 100).await.unwrap();
        assert_eq!(audit.rows.len(), 1);
        assert_eq!(audit.head, n as i64 - 1);
        let idx = s
            .append_audit(AuditEntry {
                at: T0,
                actor: None,
                action: "retention".into(),
                target: None,
                detail: Some("deleted=5".into()),
            })
            .await
            .unwrap();
        assert_eq!(idx, n);
        s.checkpoint().await.unwrap();
        // Quota: pushes since a time.
        assert_eq!(s.pushed_since(a.member_id, T0 + 50 * DAY).await.unwrap(), 1);
    }

    /// TM9 F1 and F2: retention, `{all_mine}`, `{member}` and removal with `delete_records`
    /// never delete `roster` records (crypto §7: every later joiner verifies the roster from
    /// the genesis), and `{ids}` naming one fails as a whole. Other tags are deleted.
    pub async fn roster_records_survive_retention_and_bulk_deletes(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let kit = add_member(s, &org, "kit", 3).await;
        let mut roster = Vec::new();
        for who in [&a, &roy, &kit] {
            roster.extend(push_n(s, who, "roster", 2).await);
            push_n(s, who, "rec", 2).await;
            push_n(s, who, "flag", 1).await;
        }
        // `{ids}` naming a roster record: 400 `/ids` for the whole request, nothing deleted.
        let mine = push_n(s, &roy, "rec", 1).await;
        for (by, ids) in [
            (roy, vec![mine[0], roster[2]]),
            (a, vec![roster[4], Id::new_v4()]),
        ] {
            let e = s.delete(DeleteRequest::Ids(ids), by, T0).await.unwrap_err();
            assert_eq!(
                e,
                StoreError::InvalidValue {
                    field: "/ids".into()
                }
            );
            is_code(&e, ErrorCode::InvalidValue, 400);
        }
        assert_eq!(
            s.deletion_heads().await.unwrap().head,
            -1,
            "nothing deleted"
        );
        // The bulk scopes skip roster records.
        let r = s.delete(DeleteRequest::AllMine, roy, T0).await.unwrap();
        assert_eq!(
            (r.deleted, r.already),
            (4, 0),
            "2 rec + 1 flag + 1 rec, no roster"
        );
        let r = s
            .delete(DeleteRequest::Member(a.member_id), a, T0)
            .await
            .unwrap();
        assert_eq!(r.deleted, 3);
        assert_eq!(
            s.remove_member(kit.member_id, true, a, T0).await.unwrap(),
            3
        );
        // Retention, far in the future: nothing left but roster records, and they stay.
        push_n(s, &a, "stats", 1).await;
        assert_eq!(
            s.retention_batch(T0 + 1_000 * DAY, 1_000, T0 + 1_000 * DAY)
                .await
                .unwrap(),
            1,
            "only the stats record"
        );
        let deleted: HashSet<Id> = s
            .deletions(0, 1_000)
            .await
            .unwrap()
            .entries
            .iter()
            .map(|e| e.record_id)
            .collect();
        assert_eq!(deleted.len(), 11);
        for who in [&a, &roy, &kit] {
            let items = all_records(s, who, "roster").await;
            assert_eq!(items.len(), 2, "the roster stream is complete");
            for (i, item) in items.iter().enumerate() {
                match item {
                    PulledItem::Record(r) => {
                        assert_eq!(r.idx, i as u64);
                        assert!(roster.contains(&r.id) && !deleted.contains(&r.id));
                        assert_eq!(r.blob, blob(&r.id.to_string(), 1), "the blob is kept");
                    }
                    PulledItem::Deleted(_) => panic!("a roster record was deleted"),
                }
            }
            for t in ["rec", "flag"] {
                assert!(all_records(s, who, t)
                    .await
                    .iter()
                    .all(|i| matches!(i, PulledItem::Deleted(_))));
            }
        }
    }

    /// TM9 P1: retention keeps the newest `policy` record of each `(member, device, policy)`
    /// stream whatever its age (a member who joins later must still find the policy); older
    /// `policy` records and every other tag expire as usual.
    pub async fn retention_keeps_the_newest_policy_record_of_each_stream(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let mut ids: Vec<Vec<Id>> = Vec::new();
        for (who, n) in [(&a, 3u64), (&roy, 1)] {
            let mut stream = Vec::new();
            for i in 0..n {
                let id = Id::new_v4();
                stream.push(id);
                s.push(PushBatch {
                    member_id: who.member_id,
                    device_id: who.device_id,
                    items: vec![rec("policy", i, id, 0, blob(&id.to_string(), 1))],
                    now: T0 + i as i64 * DAY,
                })
                .await
                .unwrap();
            }
            ids.push(stream);
        }
        let other = push_n(s, &a, "rec", 1).await;
        let now = T0 + 1_000 * DAY;
        assert_eq!(
            s.retention_batch(now - 365 * DAY, 1_000, now)
                .await
                .unwrap(),
            3,
            "the rec record and the two older admin policy records"
        );
        let deleted: HashSet<Id> = s
            .deletions(0, 1_000)
            .await
            .unwrap()
            .entries
            .iter()
            .map(|e| e.record_id)
            .collect();
        assert_eq!(
            deleted,
            HashSet::from([ids[0][0], ids[0][1], other[0]]),
            "older policy records expire"
        );
        for (who, stream) in [(&a, &ids[0]), (&roy, &ids[1])] {
            let items = all_records(s, who, "policy").await;
            match items.last().unwrap() {
                PulledItem::Record(r) => {
                    assert_eq!(r.id, *stream.last().unwrap());
                    assert_eq!(r.blob, blob(&r.id.to_string(), 1), "the blob is kept");
                }
                PulledItem::Deleted(_) => panic!("the newest policy record was deleted"),
            }
        }
        // Run again: nothing more goes, however old the newest policy record becomes.
        let later = now + 5_000 * DAY;
        assert_eq!(
            s.retention_batch(later - 365 * DAY, 1_000, later)
                .await
                .unwrap(),
            0
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Instantiation per backend

macro_rules! conformance_cases {
    ($factory:path) => {
        conformance_cases!(@each $factory;
            bootstrap_creates_one_admin_and_consumes_the_token,
            token_lookup_is_by_hash_only,
            invites_joins_and_approvals,
            concurrent_appends_to_one_stream_stay_contiguous,
            a_duplicate_push_is_a_no_op,
            a_different_record_at_an_existing_index_conflicts,
            the_same_id_at_another_position_conflicts,
            stale_epochs_are_refused_after_the_replay_check,
            a_deletion_leaves_a_marker_and_one_deletion_entry,
            a_reseed_marker_at_head_plus_one_is_accepted,
            pull_by_cursor_returns_the_right_rows_across_streams,
            export_and_import_give_identical_logical_dumps,
            generation_changes_on_renew_and_survives_reopen,
            settings_follow_the_retention_and_min_client_rules,
            removal_roles_and_the_last_admin,
            retention_is_bounded_oldest_first_and_prunes_keep_the_head,
            roster_records_survive_retention_and_bulk_deletes,
            retention_keeps_the_newest_policy_record_of_each_stream,
        );
    };
    (@each $factory:path; $($case:ident),* $(,)?) => {
        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn $case() {
                match $factory().await {
                    Some(f) => super::cases::$case(f).await,
                    None => eprintln!("skipped: backend not configured"),
                }
            }
        )*
    };
}

#[cfg(feature = "sqlite")]
mod sqlite {
    conformance_cases!(super::sqlite_fixture);
}

#[cfg(feature = "pg")]
mod pg {
    conformance_cases!(super::pg_fixture);
}

// ---------------------------------------------------------------------------------------------
// SQLite-specific cases

#[cfg(feature = "sqlite")]
mod sqlite_only {
    use super::*;
    use awm_server::store::sqlite::{SqliteStore, DB_FILE};
    use rusqlite::types::Value;
    use rusqlite::{Connection, OpenFlags};
    use std::collections::BTreeMap;

    const KEYS: &[(&str, &str)] = &[
        ("org", "id"),
        ("member", "id"),
        ("device", "id"),
        ("invite", "id"),
        ("record", "id"),
        ("deletion", "CAST(idx AS TEXT)"),
        ("wrap", "device_id || '/' || epoch"),
        ("audit", "CAST(idx AS TEXT)"),
        ("meta", "key"),
    ];

    fn ro(path: &Path) -> Connection {
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
    }

    /// Every row of every logged table, by (table, key).
    fn rows(path: &Path) -> BTreeMap<(String, String), Vec<Value>> {
        let conn = ro(path);
        let mut out = BTreeMap::new();
        for (t, k) in KEYS {
            let mut st = conn.prepare(&format!("SELECT {k}, * FROM {t}")).unwrap();
            let n = st.column_count();
            let mut q = st.query([]).unwrap();
            while let Some(r) = q.next().unwrap() {
                let key: String = r.get(0).unwrap();
                let vals: Vec<Value> = (1..n).map(|i| r.get(i).unwrap()).collect();
                out.insert((t.to_string(), key), vals);
            }
        }
        out
    }

    fn log_after(path: &Path, seq: i64) -> Vec<(i64, String, String, String)> {
        let conn = ro(path);
        let mut st = conn
            .prepare("SELECT seq, tbl, key, op FROM backup_log WHERE seq > ?1 ORDER BY seq")
            .unwrap();
        st.query_map([seq], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn head(path: &Path) -> i64 {
        ro(path)
            .query_row("SELECT COALESCE(MAX(seq), 0) FROM backup_log", [], |r| {
                r.get(0)
            })
            .unwrap()
    }

    /// Runs `op` and checks that every changed row added exactly one `backup_log` row naming
    /// it with the right operation (backup_* meta keys excepted).
    async fn exactly_one_log_row_per_changed_row<F, Fut>(path: &Path, what: &str, op: F) -> usize
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        let before = rows(path);
        let seq = head(path);
        op().await;
        let after = rows(path);
        let mut changed = BTreeMap::new();
        for (k, v) in &after {
            match before.get(k) {
                None => {
                    changed.insert(k.clone(), "i");
                }
                Some(old) if old != v => {
                    changed.insert(k.clone(), "u");
                }
                _ => {}
            }
        }
        for k in before.keys() {
            if !after.contains_key(k) {
                changed.insert(k.clone(), "d");
            }
        }
        changed.retain(|(t, k), _| !(t == "meta" && k.starts_with("backup_")));
        let log = log_after(path, seq);
        let logged: BTreeMap<(String, String), &str> = log
            .iter()
            .map(|(_, t, k, o)| ((t.clone(), k.clone()), o.as_str()))
            .collect();
        assert_eq!(
            log.len(),
            logged.len(),
            "{what}: one log row per row: {log:?}"
        );
        assert_eq!(logged, changed, "{what}");
        log.len()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_changed_row_adds_exactly_one_backup_log_row() {
        let f = sqlite_fixture().await.unwrap();
        let s = Arc::clone(&f.store);
        let path = f.scratch.parent().unwrap().join("data").join(DB_FILE);
        let mut total = 0;
        let mut steps = 0;
        // One store operation per step; the body sees the store as `$s`.
        macro_rules! step {
            ($what:expr, |$s:ident| $body:block) => {{
                let store = Arc::clone(&s);
                total += exactly_one_log_row_per_changed_row(&path, $what, || async move {
                    let $s: &dyn Store = &*store;
                    $body
                })
                .await;
                steps += 1;
            }};
        }
        let admin_device = Id::new_v4();
        let roy_device = Id::new_v4();
        let invite_id = Id::new_v4();
        step!("set_bootstrap", |s| {
            s.set_bootstrap(h("bootstrap"), T0 + DAY).await.unwrap();
        });
        step!("bootstrap", |s| {
            s.bootstrap(NewBootstrap {
                bootstrap_token_hash: h("bootstrap"),
                org_id: Id::new_v4(),
                handle: handle("alf"),
                device_id: admin_device,
                device_pubkey: Key32([1; 32]),
                device_token_hash: device_token_hash(admin_device),
                defaults: defaults(),
                now: T0,
            })
            .await
            .unwrap();
        });
        let alf = s
            .member_by_handle(handle("alf"))
            .await
            .unwrap()
            .unwrap()
            .member_id;
        let a = Actor {
            member_id: alf,
            device_id: admin_device,
            admin: true,
        };
        step!("create_invite", |s| {
            s.create_invite(NewInvite {
                invite_id,
                token_hash: invite_token_hash(invite_id),
                kind: InviteKind::Member,
                handle: handle("roy"),
                role: None,
                expires_at: T0 + DAY,
                by: a,
                now: T0,
            })
            .await
            .unwrap();
        });
        step!("join", |s| {
            s.join(join_req(invite_id, "roy", roy_device, 2))
                .await
                .unwrap();
        });
        step!("approve", |s| {
            s.approve_device(roy_device, wraps_for(s).await, a, T0)
                .await
                .unwrap();
        });
        let roy = Actor {
            member_id: s
                .member_by_handle(handle("roy"))
                .await
                .unwrap()
                .unwrap()
                .member_id,
            device_id: roy_device,
            admin: false,
        };
        step!("push", |s| {
            push_n(s, &roy, "rec", 3).await;
        });
        step!("replayed push", |s| {
            let first = s
                .records(roy.member_id, roy_device, tag("rec"), 0, 1, BIG)
                .await
                .unwrap();
            let id = first.records[0].id();
            assert_eq!(
                push(s, &roy, vec![marker("rec", 0, id)])
                    .await
                    .unwrap()
                    .replayed,
                1
            );
        });
        step!("marker", |s| {
            push(s, &roy, vec![marker("rec", 3, Id::new_v4())])
                .await
                .unwrap();
        });
        step!("delete", |s| {
            let page = s
                .records(roy.member_id, roy_device, tag("rec"), 0, 2, BIG)
                .await
                .unwrap();
            let ids = page.records.iter().map(PulledItem::id).collect();
            s.delete(DeleteRequest::Ids(ids), roy, T0).await.unwrap();
        });
        step!("pre-delete", |s| {
            s.delete(DeleteRequest::Ids(vec![Id::new_v4()]), roy, T0)
                .await
                .unwrap();
        });
        step!("rotate_keys", |s| {
            let w = |d: Id| DeviceWrap {
                device_id: d,
                wrap: B64(vec![3; 89]),
                auth: Key32([3; 32]),
            };
            s.rotate_keys(1, vec![w(admin_device), w(roy_device)], a, T0)
                .await
                .unwrap();
        });
        step!("update_settings", |s| {
            let u = SettingsUpdate {
                retention_days: Some(90),
                min_client: None,
                max_members: None,
                cancel_pending_retention: None,
            };
            s.update_settings(u, Version::new(0, 2, 0), Some(a), T0)
                .await
                .unwrap();
        });
        step!("touch_device twice", |s| {
            s.touch_device(roy_device, 21_000).await.unwrap();
            s.touch_device(roy_device, 21_000).await.unwrap();
        });
        step!("rotate_token", |s| {
            s.rotate_token(roy_device, h("new"), T0).await.unwrap();
        });
        step!("revoke_device", |s| {
            s.revoke_device(roy_device, a, T0).await.unwrap();
        });
        step!("remove_member", |s| {
            assert_eq!(
                s.remove_member(roy.member_id, true, a, T0).await.unwrap(),
                1
            );
        });
        step!("push 2", |s| {
            push_n(s, &a, "rec", 2).await;
        });
        step!("retention_batch", |s| {
            let n = s
                .retention_batch(T0 + 400 * DAY, 10, T0 + 400 * DAY)
                .await
                .unwrap();
            assert_eq!(n, 2);
        });
        step!("prune_deletions", |s| {
            // Marker 1, delete 2, pre-delete 1, removal 1, retention 2: all but the newest.
            assert_eq!(s.prune_deletions(T0 + 1_000 * DAY).await.unwrap(), 6);
        });
        step!("prune_audit", |s| {
            // 11 audit rows so far; the newest stays.
            assert_eq!(s.prune_audit(T0 + 1_000 * DAY).await.unwrap(), 10);
        });
        step!("renew_generation", |s| {
            s.renew_generation(T0).await.unwrap();
        });
        step!("complete_restore", |s| {
            let g = s.restore_state().await.unwrap().generation;
            s.complete_restore(g, a, T0).await.unwrap();
        });
        step!("meta_set last_retention", |s| {
            s.meta_set("last_retention".into(), T0.to_string())
                .await
                .unwrap();
        });
        step!("append_audit", |s| {
            let e = AuditEntry {
                at: T0,
                actor: None,
                action: "retention".into(),
                target: None,
                detail: Some("deleted=2".into()),
            };
            s.append_audit(e).await.unwrap();
        });
        // Writing the backup's own state adds no row, so the next change set stays empty.
        let before = head(&path);
        s.meta_set("backup_cursor".into(), before.to_string())
            .await
            .unwrap();
        s.meta_set("backup_verified_at".into(), T0.to_string())
            .await
            .unwrap();
        assert_eq!(head(&path), before);
        // The trait view of the log agrees with the table; pruning never moves the head back.
        let via_trait = s.backup_log(0, 100_000).await.unwrap();
        assert_eq!(via_trait.len() as i64, head(&path));
        assert_eq!(s.backup_log_head().await.unwrap(), head(&path));
        assert_eq!(s.prune_backup_log(10).await.unwrap(), 10);
        assert_eq!(s.backup_log(0, 5).await.unwrap()[0].seq, 11);
        assert_eq!(s.backup_log_head().await.unwrap(), before);
        eprintln!("backup_log: {total} rows over {steps} operations, one per changed row");
    }

    /// TM8 holds the store as `Arc<dyn Store>` in axum state; this handler must compile.
    async fn info(
        axum::extract::State(store): axum::extract::State<Arc<dyn Store>>,
    ) -> Result<String, (axum::http::StatusCode, String)> {
        let r = store.restore_state().await.map_err(|e| {
            let status = axum::http::StatusCode::from_u16(e.status()).unwrap();
            (status, e.to_string())
        })?;
        Ok(r.generation.to_string())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_arc_dyn_store_serves_from_an_axum_handler() {
        let f = sqlite_fixture().await.unwrap();
        let _router: axum::Router = axum::Router::new()
            .route("/v1/info", axum::routing::get(info))
            .with_state(Arc::clone(&f.store));
        let g = info(axum::extract::State(Arc::clone(&f.store)))
            .await
            .unwrap();
        assert_eq!(
            g,
            f.store
                .restore_state()
                .await
                .unwrap()
                .generation
                .to_string()
        );
        // A missing import file is an error and is not created.
        let missing = f.scratch.join("missing.sqlite");
        assert!(matches!(
            f.store.import_canonical(missing.clone()).await,
            Err(StoreError::Backend(_))
        ));
        assert!(!missing.exists());
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn file_bytes(path: &Path) -> Vec<u8> {
        std::fs::read(path).unwrap_or_default()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn deleted_blob_bytes_are_absent_from_the_file_after_a_checkpoint() {
        let dir = TempDir::new("bytes");
        let store = SqliteStore::open(dir.path()).unwrap();
        let s: &dyn Store = &store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let path = dir.path().join(DB_FILE);
        let wal = dir.path().join(format!("{DB_FILE}-wal"));
        // A small blob (in the row's page) and a large one (overflow pages), and a neighbour.
        let small_id = Id::new_v4();
        let large_id = Id::new_v4();
        let keep_id = Id::new_v4();
        let small = blob("small-secret", 1);
        let large = blob("large-secret", 60);
        let keep = blob("kept", 2);
        push(
            s,
            &a,
            vec![
                rec("rec", 0, small_id, 0, small.clone()),
                rec("rec", 1, large_id, 0, large.clone()),
                rec("rec", 2, keep_id, 0, keep.clone()),
            ],
        )
        .await
        .unwrap();
        s.checkpoint().await.unwrap();
        let probe = |b: &B64| -> Vec<Vec<u8>> {
            // Several 48-byte windows across the blob, past the version byte.
            let v = &b.0;
            (1..v.len() - 48)
                .step_by(v.len() / 8)
                .map(|i| v[i..i + 48].to_vec())
                .collect()
        };
        let bytes = file_bytes(&path);
        for b in [&small, &large, &keep] {
            assert!(
                probe(b).iter().all(|p| contains(&bytes, p)),
                "the scan finds stored blobs"
            );
        }
        s.delete(DeleteRequest::Ids(vec![small_id, large_id]), a, T0)
            .await
            .unwrap();
        s.checkpoint().await.unwrap();
        let bytes = file_bytes(&path);
        let wal_bytes = file_bytes(&wal);
        for b in [&small, &large] {
            for p in probe(b) {
                assert!(!contains(&bytes, &p), "deleted blob bytes in server.db");
                assert!(!contains(&wal_bytes, &p), "deleted blob bytes in the WAL");
            }
        }
        assert!(
            probe(&keep).iter().all(|p| contains(&bytes, p)),
            "other blobs stay"
        );
        assert_eq!(wal_bytes.len(), 0, "TRUNCATE empties the WAL");
        eprintln!(
            "byte scan: server.db {} bytes, WAL {} bytes, {} probes per blob absent",
            bytes.len(),
            wal_bytes.len(),
            probe(&small).len()
        );
        // The same after retention.
        let r_id = Id::new_v4();
        let r_blob = blob("retained-secret", 3);
        s.push(PushBatch {
            member_id: a.member_id,
            device_id: a.device_id,
            items: vec![rec("rec", 3, r_id, 0, r_blob.clone())],
            now: T0,
        })
        .await
        .unwrap();
        s.checkpoint().await.unwrap();
        assert!(probe(&r_blob)
            .iter()
            .all(|p| contains(&file_bytes(&path), p)));
        assert_eq!(
            s.retention_batch(T0 + 3_600 * 2, 100, T0 + DAY)
                .await
                .unwrap(),
            2
        );
        s.checkpoint().await.unwrap();
        for p in probe(&r_blob) {
            assert!(!contains(&file_bytes(&path), &p));
        }
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn files_are_private_and_the_export_holds_no_backup_state() {
        let dir = TempDir::new("modes");
        let data = dir.path().join("a").join("data");
        let store = SqliteStore::open(&data).unwrap();
        let s: &dyn Store = &store;
        assert_eq!(mode(&data), 0o700);
        assert_eq!(mode(&data.join(DB_FILE)), 0o600);
        let org = bootstrap(s).await;
        push_n(s, &org.admin, "rec", 2).await;
        assert_eq!(mode(&data.join(format!("{DB_FILE}-wal"))), 0o600);
        s.meta_set("backup_cursor".into(), "3".into())
            .await
            .unwrap();
        let out = dir.path().join("export.sqlite");
        s.export_canonical(out.clone()).await.unwrap();
        assert_eq!(mode(&out), 0o600);
        let conn = ro(&out);
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM backup_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
        let keys: Vec<String> = conn
            .prepare("SELECT key FROM meta ORDER BY key")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            keys,
            [
                "generation",
                "restore_pending",
                "schema_checksum.1",
                "schema_version"
            ]
        );
        let mode_name: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode_name, "delete", "a single self-contained file");
        let integrity: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        drop(conn);
        // `awm serve` opens the canonical file unchanged (§4.2).
        let moved = dir.path().join("moved");
        std::fs::create_dir(&moved).unwrap();
        std::fs::copy(&out, moved.join(DB_FILE)).unwrap();
        let opened = SqliteStore::open(&moved).unwrap();
        assert_eq!(opened.dump().await.unwrap(), s.dump().await.unwrap());
        let snap = dir.path().join("snap.db");
        let seq = s.snapshot(snap.clone()).await.unwrap();
        assert_eq!(mode(&snap), 0o600);
        assert_eq!(seq, s.backup_log_head().await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_snapshot_plus_change_sets_restores_the_live_dump() {
        let dir = TempDir::new("chain");
        let store = SqliteStore::open(&dir.path().join("live")).unwrap();
        let s: &dyn Store = &store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        push_n(s, &roy, "rec", 3).await;
        let full = dir.path().join("full.db");
        let s0 = s.snapshot(full.clone()).await.unwrap();
        // Changes after the snapshot: inserts, updates (deletion markers) and a removal.
        let ids = push_n(s, &a, "rec", 4).await;
        s.delete(DeleteRequest::Ids(vec![ids[0]]), a, T0)
            .await
            .unwrap();
        let inc1 = dir.path().join("inc1.db");
        let c1 = s.export_changes(s0, inc1.clone()).await.unwrap();
        assert_eq!(c1.after, s0);
        assert!(c1.to > s0 && c1.rows > 0);
        s.remove_member(roy.member_id, true, a, T0).await.unwrap();
        s.prune_audit(T0 + 1).await.unwrap();
        s.meta_set("last_retention".into(), "1".into())
            .await
            .unwrap();
        let inc2 = dir.path().join("inc2.db");
        let c2 = s.export_changes(c1.to, inc2.clone()).await.unwrap();
        assert_eq!(c2.after, c1.to);
        let empty = dir.path().join("inc3.db");
        let c3 = s.export_changes(c2.to, empty.clone()).await.unwrap();
        assert_eq!((c3.after, c3.to, c3.rows), (c2.to, c2.to, 0));

        // Restore: the snapshot as server.db, then the change sets in order.
        let restored_dir = dir.path().join("restored");
        std::fs::create_dir(&restored_dir).unwrap();
        std::fs::copy(&full, restored_dir.join(DB_FILE)).unwrap();
        let restored = SqliteStore::open(&restored_dir).unwrap();
        assert_ne!(restored.dump().await.unwrap(), s.dump().await.unwrap());
        let r1 = restored.apply_changes(inc1).await.unwrap();
        assert_eq!((r1.after, r1.to), (c1.after, c1.to));
        restored.apply_changes(inc2).await.unwrap();
        restored.apply_changes(empty).await.unwrap();
        assert_eq!(restored.dump().await.unwrap(), s.dump().await.unwrap());
        // A record pushed and deleted inside one window ships as its marker: the change set
        // holds the row as it is now, never the deleted blob.
        let deleted = blob(&ids[0].to_string(), 1);
        let kept = blob(&ids[1].to_string(), 1);
        let inc1_bytes = std::fs::read(dir.path().join("inc1.db")).unwrap();
        assert!(!contains(&inc1_bytes, &deleted.0[1..49]));
        assert!(contains(&inc1_bytes, &kept.0[1..49]));
    }
}
