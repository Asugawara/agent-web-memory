//! Deletion and retention (plan-v3-team §3.6, §3.7, §5.6, §6.1; TM9) through `delete::run`,
//! `delete::remove_member`, `retention::run`, `retention::request_time` and
//! `retention::hourly`, against a real store.
//!
//! The cases in `cases` use the `Store` trait only and run for every backend: `SqliteStore`
//! here, `PgStore` (TM26) through `pg_fixture`, which reads `AWM_TEST_PG_URL` and skips
//! (passes) when it is unset, as in `tests/store_conformance.rs`. The byte scan of the
//! database file is in `sqlite_only`.
//!
//! Run: `cargo test -p awm-server --features sqlite --test delete_retention`;
//! TM26: `AWM_TEST_PG_URL=... cargo test -p awm-server --features sqlite,pg --test delete_retention`.

#![cfg(any(feature = "sqlite", feature = "pg"))]

use std::any::Any;
use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use awm_proto::wire::{
    DeleteRequest, EpochWrap, ErrorCode, Handle, Id, InviteKind, Key32, PulledItem, PushDeleted,
    PushItem, PushRecord, Role, SettingsUpdate, Tag, Version, B64,
};
use awm_server::auth::{Caller, CloudOwner, Device};
use awm_server::authz::Refusal;
use awm_server::delete::{self, DeleteError, NOTICE_ACTION};
use awm_server::retention::{self, Clock, HourlyReport, RetentionRun};
use awm_server::store::{
    checksum, meta_keys, Actor, NewBootstrap, NewInvite, NewJoin, OrgDefaults, PushBatch, Store,
    StoreError,
};

// ---------------------------------------------------------------------------------------------
// Fixtures

/// What a backend hands the cases.
pub struct Fixture {
    /// A migrated store without an organisation.
    pub store: Arc<dyn Store>,
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
            "delret-{tag}-{}-{nanos}-{}",
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
    let root = TempDir::new("sqlite");
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&root.path().join("data")).unwrap());
    Some(Fixture {
        store,
        _keep: Box::new(root),
    })
}

/// TM26 replaces this body with a factory over `PgStore` (a fresh, empty organisation scope
/// per call). The cases do not change.
#[cfg(feature = "pg")]
async fn pg_fixture() -> Option<Fixture> {
    let url = std::env::var("AWM_TEST_PG_URL").ok()?;
    let _ = awm_server::store::pg::PgStore::connect;
    panic!(
        "TM26: build a Fixture over PgStore for AWM_TEST_PG_URL ({} bytes)",
        url.len()
    );
}

// ---------------------------------------------------------------------------------------------
// Helpers

const T0: i64 = 1_790_000_000;
const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;
const BIG: usize = awm_proto::wire::limits::PULL_RESPONSE_BYTES;
/// Handles used in the cases; none of them can appear inside a UUID or hex text.
const HANDLES: &[&str] = &["alf", "roy", "kit", "mia"];

fn h(s: &str) -> String {
    checksum(s.as_bytes())
}

fn handle(s: &str) -> Handle {
    Handle::parse(s).unwrap()
}

fn tag(s: &str) -> Tag {
    Tag::parse(s).unwrap()
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

struct Org {
    org_id: Id,
    admin: Actor,
}

impl Org {
    fn caller(&self, a: Actor) -> Caller {
        let d = Device {
            org_id: self.org_id,
            member_id: a.member_id,
            device_id: a.device_id,
        };
        if a.admin {
            Caller::Admin(d)
        } else {
            Caller::Member(d)
        }
    }
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
            device_token_hash: h(&format!("device-{device}")),
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

/// An invite by `by` and a join; returns the new device's actor (not yet approved).
async fn join(s: &dyn Store, by: Actor, kind: InviteKind, name: &str, n: u8) -> Actor {
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
    let device = Id::new_v4();
    let joined = s
        .join(NewJoin {
            invite_id,
            invite_token_hash: h(&format!("invite-{invite_id}")),
            handle: handle(name),
            device_id: device,
            device_pubkey: Key32([n; 32]),
            join_mac: Key32([n.wrapping_add(100); 32]),
            device_token_hash: h(&format!("device-{device}")),
            now: T0 + 60,
        })
        .await
        .unwrap();
    Actor {
        member_id: joined.member_id,
        device_id: device,
        admin: false,
    }
}

/// A new member with one approved device.
async fn add_member(s: &dyn Store, org: &Org, name: &str, n: u8) -> Actor {
    let a = join(s, org.admin, InviteKind::Member, name, n).await;
    s.approve_device(a.device_id, wraps_for(s).await, org.admin, T0 + 120)
        .await
        .unwrap();
    a
}

/// A second approved device of `of`'s member, invited and approved by `of`.
async fn add_device(s: &dyn Store, of: Actor, name: &str, n: u8) -> Actor {
    let a = join(s, of, InviteKind::Device, name, n).await;
    s.approve_device(a.device_id, wraps_for(s).await, of, T0 + 120)
        .await
        .unwrap();
    Actor {
        admin: of.admin,
        ..a
    }
}

/// Pushes `n` records at the stream's head + 1, in batches of 100, received at `now`;
/// returns their ids in push order.
async fn push_at(s: &dyn Store, a: &Actor, t: &str, n: u64, now: i64) -> Vec<Id> {
    let epoch = s.org(now).await.unwrap().unwrap().current_epoch;
    let mut ids = Vec::new();
    while (ids.len() as u64) < n {
        let k = (n - ids.len() as u64).min(100);
        let head = s
            .stream_head(a.member_id, a.device_id, tag(t))
            .await
            .unwrap();
        let batch: Vec<Id> = (0..k).map(|_| Id::new_v4()).collect();
        let items = batch
            .iter()
            .enumerate()
            .map(|(i, id)| {
                PushItem::Record(PushRecord {
                    tag: tag(t),
                    idx: (head + 1) as u64 + i as u64,
                    id: *id,
                    epoch,
                    blob: blob(&id.to_string(), 1),
                })
            })
            .collect();
        let r = s
            .push(PushBatch {
                member_id: a.member_id,
                device_id: a.device_id,
                items,
                now,
            })
            .await
            .unwrap();
        assert_eq!(u64::from(r.accepted), k);
        ids.extend(batch);
    }
    ids
}

async fn push_one(s: &dyn Store, a: &Actor, item: PushItem) -> Result<(), StoreError> {
    s.push(PushBatch {
        member_id: a.member_id,
        device_id: a.device_id,
        items: vec![item],
        now: T0 + HOUR,
    })
    .await
    .map(|_| ())
}

async fn items(s: &dyn Store, a: &Actor, t: &str) -> Vec<PulledItem> {
    s.records(a.member_id, a.device_id, tag(t), 0, 500, BIG)
        .await
        .unwrap()
        .records
}

/// Every deletion-stream entry, ascending, read in pages.
async fn entries(s: &dyn Store) -> Vec<(u64, Id)> {
    let mut out = Vec::new();
    let mut from = 0u64;
    loop {
        let page = s.deletions(from, 5_000).await.unwrap();
        if page.entries.is_empty() {
            return out;
        }
        from = page.entries.last().unwrap().idx + 1;
        out.extend(page.entries.into_iter().map(|e| (e.idx, e.record_id)));
    }
}

/// The deletion stream from `oldest` to `head` has every index once and every id once.
async fn assert_contiguous(s: &dyn Store) -> Vec<(u64, Id)> {
    let heads = s.deletion_heads().await.unwrap();
    let e = entries(s).await;
    let idx: Vec<u64> = e.iter().map(|(i, _)| *i).collect();
    let want: Vec<u64> = if heads.head < 0 {
        Vec::new()
    } else {
        (heads.oldest as u64..=heads.head as u64).collect()
    };
    assert_eq!(idx, want, "deletion stream not contiguous");
    let ids: HashSet<Id> = e.iter().map(|(_, id)| *id).collect();
    assert_eq!(
        ids.len(),
        e.len(),
        "an id appears twice in the deletion stream"
    );
    e
}

async fn record_rows(s: &dyn Store) -> usize {
    s.dump().await.unwrap().rows("record").len()
}

async fn audit_rows(s: &dyn Store) -> Vec<awm_proto::wire::AuditRow> {
    s.audit(0, 1_000).await.unwrap().rows
}

fn is_status(e: &DeleteError, status: u16, code: ErrorCode) {
    assert_eq!(e.status(), status, "{e:?}");
    assert_eq!(e.to_body().map(|b| b.error), Some(code), "{e:?}");
}

/// Neither the text forms nor the body of `e` hold a blob or a handle.
fn assert_clean_error(e: &DeleteError, blobs: &[B64]) {
    let text = format!("{e} {e:?} {}", serde_json::to_string(&e.to_body()).unwrap());
    assert_clean(&text, blobs);
}

fn assert_clean(text: &str, blobs: &[B64]) {
    for b in blobs {
        let b64 = String::from(B64(b.0.clone()));
        let hex: String = b.0[1..17].iter().map(|x| format!("{x:02x}")).collect();
        assert!(!text.contains(&b64[4..40]), "blob in {text}");
        assert!(!text.contains(&hex), "blob hex in {text}");
    }
    for name in HANDLES {
        assert!(!text.contains(name), "handle {name} in {text}");
    }
}

/// A clock for `retention::hourly`: `sleep` advances the time by its argument and returns at
/// once; after `limit` sleeps it signals shutdown and sleeps forever.
struct FakeClock {
    now: AtomicI64,
    sleeps: Mutex<Vec<u64>>,
    limit: usize,
    done: tokio::sync::Notify,
}

impl FakeClock {
    fn new(now: i64, limit: usize) -> Arc<FakeClock> {
        Arc::new(FakeClock {
            now: AtomicI64::new(now),
            sleeps: Mutex::new(Vec::new()),
            limit,
            done: tokio::sync::Notify::new(),
        })
    }

    fn sleeps(&self) -> Vec<u64> {
        self.sleeps.lock().unwrap().clone()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }

    fn sleep(&self, secs: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let n = {
            let mut s = self.sleeps.lock().unwrap();
            s.push(secs);
            s.len()
        };
        Box::pin(async move {
            if n >= self.limit {
                self.done.notify_one();
                std::future::pending::<()>().await;
            }
            self.now.fetch_add(secs as i64, Ordering::SeqCst);
            tokio::task::yield_now().await;
        })
    }
}

async fn run_hourly(s: &Arc<dyn Store>, clock: &Arc<FakeClock>) -> HourlyReport {
    let c = Arc::clone(clock);
    let task = tokio::spawn(retention::hourly(
        Arc::clone(s),
        Arc::clone(clock) as Arc<dyn Clock>,
        async move { c.done.notified().await },
    ));
    tokio::time::timeout(Duration::from_secs(60), task)
        .await
        .expect("hourly did not stop on shutdown")
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// The cases (backend-independent)

mod cases {
    use super::*;

    /// A member deleting another member's record gets 403 and nothing changes; any device of
    /// the member may delete the member's records; an admin deletes any record; the matrix
    /// refuses `{member}` for members, anonymous, pending and cloud-owner callers.
    pub async fn deletes_follow_ownership_and_admins_delete_any_record(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let roy2 = add_device(s, roy, "roy", 3).await;
        let rens = push_at(s, &roy, "rec", 3, T0).await;
        let akis = push_at(s, &a, "rec", 1, T0).await;
        let before = s.dump().await.unwrap();
        let e = delete::run(
            s,
            &org.caller(roy),
            DeleteRequest::Ids(vec![rens[0], akis[0]]),
            T0,
        )
        .await
        .unwrap_err();
        assert_eq!(e, DeleteError::Store(StoreError::Forbidden));
        is_status(&e, 403, ErrorCode::Forbidden);
        assert_eq!(
            s.dump().await.unwrap(),
            before,
            "nothing deleted, nothing written"
        );
        // Another device of the same member deletes the member's record.
        let r = delete::run(s, &org.caller(roy2), DeleteRequest::Ids(vec![rens[0]]), T0)
            .await
            .unwrap();
        assert_eq!((r.deleted, r.already), (1, 0));
        // An admin deletes another member's record.
        let r = delete::run(s, &org.caller(a), DeleteRequest::Ids(vec![rens[1]]), T0)
            .await
            .unwrap();
        assert_eq!((r.deleted, r.already), (1, 0));
        let got = items(s, &roy, "rec").await;
        assert!(matches!(&got[0], PulledItem::Deleted(d) if d.id == rens[0]));
        assert!(matches!(&got[1], PulledItem::Deleted(d) if d.id == rens[1]));
        assert!(matches!(&got[2], PulledItem::Record(r) if r.id == rens[2]));
        assert!(matches!(
            &items(s, &a, "rec").await[0],
            PulledItem::Record(_)
        ));
        // `{member}` is an admin cell; refusals by a token are audited.
        let e = delete::run(s, &org.caller(roy), DeleteRequest::Member(a.member_id), T0)
            .await
            .unwrap_err();
        assert_eq!(e, DeleteError::Refused(Refusal::Forbidden));
        is_status(&e, 403, ErrorCode::Forbidden);
        let refused = audit_rows(s).await.into_iter().last().unwrap();
        assert_eq!(refused.action, "authz.refused");
        assert_eq!(
            refused.detail.as_deref(),
            Some("action=delete.member error=forbidden")
        );
        // Anonymous, pending and cloud-owner callers.
        let pending = join(s, a, InviteKind::Member, "mia", 9).await;
        let pending = Caller::Pending(Device {
            org_id: org.org_id,
            member_id: pending.member_id,
            device_id: pending.device_id,
        });
        let owner = Caller::CloudOwner(CloudOwner { org_id: org.org_id });
        for (c, status, code) in [
            (Caller::Anonymous, 401, ErrorCode::Unauthenticated),
            (pending, 403, ErrorCode::NotApproved),
            (owner, 403, ErrorCode::Forbidden),
        ] {
            for req in [
                DeleteRequest::Ids(vec![rens[2]]),
                DeleteRequest::AllMine,
                DeleteRequest::Member(roy.member_id),
            ] {
                let e = delete::run(s, &c, req, T0).await.unwrap_err();
                is_status(&e, status, code);
            }
        }
        assert_eq!(assert_contiguous(s).await.len(), 2);
        assert!(matches!(
            &items(s, &roy, "rec").await[2],
            PulledItem::Record(_)
        ));
    }

    /// Deletes are idempotent by id; unknown ids are pre-deleted for the caller's member: a
    /// later push of that id by the same member gets 410 `deleted`, by another member 409
    /// `id_conflict`, and the writer fills the index with a marker.
    pub async fn deletes_by_id_are_idempotent_and_unknown_ids_are_pre_deleted(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let ids = push_at(s, &roy, "rec", 2, T0).await;
        let c = org.caller(roy);
        let r = delete::run(s, &c, DeleteRequest::Ids(vec![ids[0], ids[0]]), T0)
            .await
            .unwrap();
        assert_eq!((r.deleted, r.already), (1, 0), "a repeated id counts once");
        let r = delete::run(s, &c, DeleteRequest::Ids(vec![ids[0]]), T0 + 1)
            .await
            .unwrap();
        assert_eq!((r.deleted, r.already), (0, 1));
        // An admin repeating a member's deletion is idempotent too.
        let r = delete::run(s, &org.caller(a), DeleteRequest::Ids(vec![ids[0]]), T0 + 2)
            .await
            .unwrap();
        assert_eq!((r.deleted, r.already), (0, 1));
        // Pre-deletion.
        let pre = Id::new_v4();
        let r = delete::run(s, &c, DeleteRequest::Ids(vec![pre, ids[1]]), T0 + 3)
            .await
            .unwrap();
        assert_eq!((r.deleted, r.already), (2, 0));
        let item = |idx, id| {
            PushItem::Record(PushRecord {
                tag: tag("rec"),
                idx,
                id,
                epoch: 0,
                blob: blob("late", 1),
            })
        };
        let e = push_one(s, &roy, item(2, pre)).await.unwrap_err();
        assert_eq!(
            e,
            StoreError::Deleted {
                item: 0,
                ids: vec![pre]
            }
        );
        assert_eq!(e.status(), 410);
        assert_eq!(
            push_one(s, &a, item(0, pre)).await,
            Err(StoreError::IdConflict { item: 0 })
        );
        // The writer fills the index with a marker; the stream stays contiguous.
        push_one(
            s,
            &roy,
            PushItem::Deleted(PushDeleted {
                tag: tag("rec"),
                idx: 2,
                id: pre,
            }),
        )
        .await
        .unwrap();
        assert_eq!(items(s, &roy, "rec").await.len(), 3);
        let e = assert_contiguous(s).await;
        assert_eq!(
            e.iter().map(|(_, id)| *id).collect::<Vec<_>>(),
            vec![ids[0], pre, ids[1]],
            "one entry per id, the marker added none"
        );
    }

    /// More than 1,000 ids: 413 `too_large` with `limit: delete_ids`, nothing deleted;
    /// exactly 1,000 is accepted.
    pub async fn more_than_1000_ids_get_413_and_nothing_is_deleted(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let held = push_at(s, &a, "rec", 1, T0).await;
        let mut ids: Vec<Id> = (0..1_000).map(|_| Id::new_v4()).collect();
        ids.push(held[0]);
        let e = delete::run(s, &org.caller(a), DeleteRequest::Ids(ids.clone()), T0)
            .await
            .unwrap_err();
        assert_eq!(e, DeleteError::TooManyIds { count: 1_001 });
        is_status(&e, 413, ErrorCode::TooLarge);
        let body = e.to_body().unwrap();
        assert_eq!(
            (body.limit.as_deref(), body.max),
            (Some("delete_ids"), Some(1_000))
        );
        assert_eq!(s.deletion_heads().await.unwrap().head, -1);
        assert!(matches!(
            &items(s, &a, "rec").await[0],
            PulledItem::Record(_)
        ));
        ids.remove(0);
        let r = delete::run(s, &org.caller(a), DeleteRequest::Ids(ids), T0)
            .await
            .unwrap();
        assert_eq!((r.deleted, r.already), (1_000, 0));
        assert_eq!(assert_contiguous(s).await.len(), 1_000);
    }

    /// `{all_mine}` and `{member}` at most once per hour per token (429 with `Retry-After`),
    /// shared by both scopes, not consumed by a failed request; each one audited twice: the
    /// store's `delete` row and the notice row admins read.
    pub async fn bulk_deletes_are_once_per_hour_per_token_and_noticed_to_admins(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let roy2 = add_device(s, roy, "roy", 3).await;
        push_at(s, &roy, "rec", 2, T0).await;
        let t = T0 + DAY;
        let r = delete::run(s, &org.caller(roy), DeleteRequest::AllMine, t)
            .await
            .unwrap();
        assert_eq!((r.deleted, r.already), (2, 0));
        let notice = audit_rows(s).await.into_iter().last().unwrap();
        assert_eq!(notice.action, NOTICE_ACTION);
        assert_eq!(notice.actor, Some(roy.member_id));
        assert_eq!(notice.target, Some(roy.device_id.to_string()));
        assert_eq!(
            notice.detail.as_deref(),
            Some("scope=all_mine deleted=2 already=0")
        );
        // The same token within the hour: 429 with the rest of the hour.
        let e = delete::run(s, &org.caller(roy), DeleteRequest::AllMine, t + 60)
            .await
            .unwrap_err();
        assert_eq!(
            e,
            DeleteError::RateLimited {
                retry_after_s: 3_540
            }
        );
        is_status(&e, 429, ErrorCode::RateLimited);
        assert_eq!(e.retry_after(), Some(3_540));
        assert_eq!(e.to_body().unwrap().retry_after_s, Some(3_540));
        // Ids deletes are not limited; another token of the same member is not either.
        delete::run(
            s,
            &org.caller(roy),
            DeleteRequest::Ids(vec![Id::new_v4()]),
            t + 61,
        )
        .await
        .unwrap();
        delete::run(s, &org.caller(roy2), DeleteRequest::AllMine, t + 62)
            .await
            .unwrap();
        let e = delete::run(s, &org.caller(roy), DeleteRequest::AllMine, t + HOUR - 1)
            .await
            .unwrap_err();
        assert_eq!(e.retry_after(), Some(1));
        delete::run(s, &org.caller(roy), DeleteRequest::AllMine, t + HOUR)
            .await
            .unwrap();
        // `{member}` by an admin: a failed request does not use the hour; both scopes share it.
        let e = delete::run(s, &org.caller(a), DeleteRequest::Member(Id::new_v4()), t)
            .await
            .unwrap_err();
        assert_eq!(e, DeleteError::Store(StoreError::NotFound));
        is_status(&e, 404, ErrorCode::NotFound);
        push_at(s, &roy2, "flag", 3, t).await;
        let r = delete::run(
            s,
            &org.caller(a),
            DeleteRequest::Member(roy.member_id),
            t + 1,
        )
        .await
        .unwrap();
        assert_eq!(r.deleted, 3);
        let e = delete::run(s, &org.caller(a), DeleteRequest::AllMine, t + 2)
            .await
            .unwrap_err();
        assert_eq!(e.retry_after(), Some(3_599));
        // Concurrent bulk deletes by one token: exactly one runs.
        let kit = add_member(s, &org, "kit", 4).await;
        push_at(s, &kit, "rec", 5, t).await;
        let kit_c = org.caller(kit);
        let (x, y) = tokio::join!(
            delete::run(s, &kit_c, DeleteRequest::AllMine, t + 5),
            delete::run(s, &kit_c, DeleteRequest::AllMine, t + 5),
        );
        let ok: Vec<_> = [&x, &y]
            .into_iter()
            .filter_map(|r| r.as_ref().ok())
            .collect();
        assert_eq!(ok.len(), 1, "{x:?} {y:?}");
        assert_eq!(ok[0].deleted, 5);
        assert!([&x, &y]
            .iter()
            .any(|r| matches!(r, Err(DeleteError::RateLimited { .. }))));
        // The notices: one per bulk delete that ran, readable by admins, counts only.
        let notices: Vec<_> = audit_rows(s)
            .await
            .into_iter()
            .filter(|r| r.action == NOTICE_ACTION)
            .collect();
        let details: Vec<_> = notices.iter().map(|r| r.detail.clone().unwrap()).collect();
        assert_eq!(
            details,
            vec![
                "scope=all_mine deleted=2 already=0".to_string(),
                "scope=all_mine deleted=0 already=0".to_string(),
                "scope=all_mine deleted=0 already=0".to_string(),
                format!("scope=member member={} deleted=3 already=0", roy.member_id),
                "scope=all_mine deleted=5 already=0".to_string(),
            ]
        );
        let stored: Vec<_> = audit_rows(s)
            .await
            .into_iter()
            .filter(|r| r.action == "delete")
            .collect();
        assert_eq!(stored.len(), 6, "the store's own rows: 5 bulk + 1 ids");
        assert_contiguous(s).await;
    }

    /// `awm team remove @h --delete-records`: the member's records are deleted (not its roster
    /// records), every token is revoked, `rotation_needed` is set; members may not.
    pub async fn removal_with_delete_records_deletes_and_asks_for_rotation(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let kit = add_member(s, &org, "kit", 3).await;
        let recs = push_at(s, &kit, "rec", 3, T0).await;
        let roster = push_at(s, &kit, "roster", 1, T0).await;
        let e = delete::remove_member(s, &org.caller(roy), kit.member_id, true, T0)
            .await
            .unwrap_err();
        assert_eq!(e, DeleteError::Refused(Refusal::Forbidden));
        assert!(!s.org(T0).await.unwrap().unwrap().rotation_needed);
        let n = delete::remove_member(s, &org.caller(a), kit.member_id, true, T0 + 10)
            .await
            .unwrap();
        assert_eq!(n, 3);
        assert!(s.org(T0).await.unwrap().unwrap().rotation_needed);
        let auth = s
            .auth_device(h(&format!("device-{}", kit.device_id)))
            .await
            .unwrap()
            .unwrap();
        assert!(auth.member_revoked && auth.device_revoked);
        assert!(items(s, &kit, "rec")
            .await
            .iter()
            .all(|i| matches!(i, PulledItem::Deleted(_))));
        assert!(
            matches!(&items(s, &kit, "roster").await[0], PulledItem::Record(r) if r.id == roster[0])
        );
        let e = assert_contiguous(s).await;
        assert_eq!(e.iter().map(|(_, id)| *id).collect::<Vec<_>>(), recs);
        let row = audit_rows(s)
            .await
            .into_iter()
            .find(|r| r.action == "member.remove")
            .unwrap();
        assert_eq!(row.detail.as_deref(), Some("delete_records=true deleted=3"));
        // Idempotent; the last admin cannot be removed.
        assert_eq!(
            delete::remove_member(s, &org.caller(a), kit.member_id, true, T0 + 20).await,
            Ok(0)
        );
        let e = delete::remove_member(s, &org.caller(a), a.member_id, true, T0)
            .await
            .unwrap_err();
        assert_eq!(e, DeleteError::Store(StoreError::LastAdmin));
        is_status(&e, 409, ErrorCode::LastAdmin);
    }

    /// F2: no deletion path deletes a `roster` record. The bulk scopes, removal and retention
    /// skip them, `{ids}` naming one is refused (400 `/ids`, nothing deleted), and every
    /// roster stream stays complete from index 0 with its blobs, while the other records'
    /// contents are gone.
    pub async fn roster_records_are_never_deleted_and_the_chain_stays_complete(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let kit = add_member(s, &org, "kit", 3).await;
        let mia = add_member(s, &org, "mia", 4).await;
        s.set_role(mia.member_id, Role::Admin, Some(a), T0)
            .await
            .unwrap();
        let mia = Actor { admin: true, ..mia };
        let mut roster = Vec::new();
        let mut content = Vec::new();
        for who in [&a, &roy, &kit, &mia] {
            roster.push(push_at(s, who, "roster", 3, T0).await);
            content.extend(push_at(s, who, "rec", 2, T0).await);
            content.extend(push_at(s, who, "stats", 1, T0).await);
        }
        let e = delete::run(
            s,
            &org.caller(a),
            DeleteRequest::Ids(vec![content[0], roster[1][0]]),
            T0,
        )
        .await
        .unwrap_err();
        assert_eq!(
            e,
            DeleteError::Store(StoreError::InvalidValue {
                field: "/ids".into()
            })
        );
        is_status(&e, 400, ErrorCode::InvalidValue);
        assert_eq!(s.deletion_heads().await.unwrap().head, -1);
        delete::run(s, &org.caller(roy), DeleteRequest::AllMine, T0)
            .await
            .unwrap();
        delete::run(s, &org.caller(a), DeleteRequest::Member(kit.member_id), T0)
            .await
            .unwrap();
        delete::remove_member(s, &org.caller(a), mia.member_id, true, T0)
            .await
            .unwrap();
        // The genesis admin's content goes through retention (380 days: the deletion entries
        // of T0 are not yet pruned).
        let run = retention::run(s, T0 + 380 * DAY).await.unwrap().unwrap();
        assert_eq!(run.deleted, 3);
        let deleted: HashSet<Id> = assert_contiguous(s)
            .await
            .into_iter()
            .map(|(_, id)| id)
            .collect();
        assert_eq!(deleted, content.iter().copied().collect::<HashSet<_>>());
        for (who, ids) in [&a, &roy, &kit, &mia].into_iter().zip(&roster) {
            let got = items(s, who, "roster").await;
            assert_eq!(got.len(), 3);
            for (i, item) in got.iter().enumerate() {
                let PulledItem::Record(r) = item else {
                    panic!("roster idx {i} deleted");
                };
                assert_eq!((r.idx, r.id), (i as u64, ids[i]));
                assert_eq!(r.blob, blob(&ids[i].to_string(), 1));
            }
            for t in ["rec", "stats"] {
                assert!(items(s, who, t)
                    .await
                    .iter()
                    .all(|i| matches!(i, PulledItem::Deleted(_))));
            }
        }
        // The deleted contents are gone from every column, the roster blobs are not.
        let dump = s.dump().await.unwrap();
        let blobs: Vec<Vec<u8>> = dump
            .rows("record")
            .iter()
            .filter_map(|row| match &row[8] {
                awm_server::store::DumpValue::Blob(b) => Some(b.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(blobs.len(), 12, "the 12 roster blobs only");
        for id in &content {
            assert!(!blobs.contains(&blob(&id.to_string(), 1).0));
        }
    }

    /// Retention deletes only records older than `retention_days` by `received_at`, oldest
    /// first, in batches of at most 1,000, each with one deletion entry; audits once with the
    /// count; writes `last_retention`; a second run within the hour is a no-op.
    pub async fn retention_deletes_only_older_records_in_batches_oldest_first(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let mut old = Vec::new();
        for b in 0..25i64 {
            let who = if b % 2 == 0 { &a } else { &roy };
            old.extend(push_at(s, who, "rec", 100, T0 + b * HOUR).await);
        }
        let young = push_at(s, &roy, "flag", 10, T0 + 300 * DAY).await;
        let rows = record_rows(s).await;
        // Received at T0 + 24 h at the latest; the cutoff is T0 + 26 h.
        let now = T0 + 365 * DAY + 26 * HOUR;
        let run = retention::run(s, now).await.unwrap().unwrap();
        assert_eq!(
            run,
            RetentionRun {
                retention_days: 365,
                deleted: 2_500,
                batches: 3,
                complete: true,
                pruned_deletions: 0,
                pruned_audit: 0,
            }
        );
        let e = assert_contiguous(s).await;
        assert_eq!(
            e.iter().map(|(_, id)| *id).collect::<Vec<_>>(),
            old,
            "oldest first, one entry each"
        );
        for who in [&a, &roy] {
            assert!(items(s, who, "rec")
                .await
                .iter()
                .all(|i| matches!(i, PulledItem::Deleted(_))));
        }
        let kept = items(s, &roy, "flag").await;
        assert_eq!(
            kept.iter()
                .filter_map(|i| match i {
                    PulledItem::Record(r) => Some(r.id),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            young,
            "younger records stay"
        );
        assert_eq!(record_rows(s).await, rows, "no record row is deleted");
        let last = audit_rows(s).await.into_iter().last().unwrap();
        assert_eq!(
            (last.action.as_str(), last.at, last.actor),
            ("retention", now, None)
        );
        assert_eq!(
            last.detail.as_deref(),
            Some(
                "deleted=2500 batches=3 complete=true pruned_deletions=0 pruned_audit=0 \
                 retention_days=365"
            )
        );
        assert_eq!(retention::last_retention(s).await.unwrap(), Some(now));
        // Within the hour: a no-op that writes nothing.
        let before = s.dump().await.unwrap();
        assert_eq!(retention::run(s, now + HOUR - 1).await.unwrap(), None);
        assert_eq!(retention::request_time(s, now + 1).await, None);
        assert_eq!(s.dump().await.unwrap(), before);
        // An hour later it runs again and finds nothing.
        let run = retention::run(s, now + HOUR).await.unwrap().unwrap();
        assert_eq!((run.deleted, run.batches), (0, 1));
    }

    /// The effective `retention_days` is read from `org(now)`: a pending decrease applies only
    /// once its 7 days are over.
    pub async fn a_pending_retention_decrease_applies_only_when_due(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let aged = push_at(s, &a, "rec", 2, T0 - 100 * DAY).await;
        s.update_settings(
            SettingsUpdate {
                retention_days: Some(30),
                min_client: None,
                max_members: None,
                cancel_pending_retention: None,
            },
            Version::new(0, 2, 0),
            Some(a),
            T0,
        )
        .await
        .unwrap();
        let run = retention::run(s, T0 + DAY).await.unwrap().unwrap();
        assert_eq!((run.retention_days, run.deleted), (365, 0));
        let run = retention::run(s, T0 + 7 * DAY - HOUR)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (run.retention_days, run.deleted),
            (365, 0),
            "an hour before it is due"
        );
        let run = retention::run(s, T0 + 7 * DAY).await.unwrap().unwrap();
        assert_eq!((run.retention_days, run.deleted), (30, 2));
        let e = assert_contiguous(s).await;
        assert_eq!(e.iter().map(|(_, id)| *id).collect::<Vec<_>>(), aged);
        let settings = s.org(T0 + 7 * DAY).await.unwrap().unwrap().settings;
        assert_eq!(
            (settings.retention_days, settings.pending_retention),
            (30, None)
        );
    }

    /// The request-time schedule deletes at most 1,000 rows per call and runs at most once an
    /// hour, keyed on `last_retention` (shared with `retention::run`).
    pub async fn request_time_deletes_at_most_1000_rows_once_an_hour(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        // Before bootstrap there is nothing to do; here there is.
        let old = push_at(s, &a, "rec", 1_500, T0).await;
        let now = T0 + 366 * DAY;
        assert_eq!(retention::request_time(s, now).await, Some(1_000));
        assert_eq!(assert_contiguous(s).await.len(), 1_000);
        let last = audit_rows(s).await.into_iter().last().unwrap();
        assert!(last
            .detail
            .unwrap()
            .starts_with("deleted=1000 batches=1 complete=false"));
        for t in [now, now + 1, now + HOUR - 1] {
            assert_eq!(retention::request_time(s, t).await, None);
        }
        assert_eq!(retention::run(s, now + 60).await.unwrap(), None);
        assert_eq!(assert_contiguous(s).await.len(), 1_000);
        assert_eq!(retention::request_time(s, now + HOUR).await, Some(500));
        assert_eq!(retention::request_time(s, now + 2 * HOUR).await, Some(0));
        let e = assert_contiguous(s).await;
        assert_eq!(e.iter().map(|(_, id)| *id).collect::<Vec<_>>(), old);
        assert_eq!(
            audit_rows(s)
                .await
                .iter()
                .filter(|r| r.action == "retention")
                .count(),
            3
        );
    }

    /// TM8's synchronous runner (`retention::runner`, called on `spawn_blocking`): one bounded
    /// batch per call, at most once an hour; the `retention_days` argument is not trusted, the
    /// effective value is read from the store; the TM1 `sweep` stub deletes nothing.
    pub async fn the_tm8_runner_does_one_bounded_batch_at_most_once_an_hour(f: Fixture) {
        let s = Arc::clone(&f.store);
        let org = bootstrap(&*s).await;
        push_at(&*s, &org.admin, "rec", 1_200, T0).await;
        assert!(retention::sweep(30).is_err());
        assert_eq!(assert_contiguous(&*s).await.len(), 0);
        let clock = FakeClock::new(T0 + 366 * DAY, usize::MAX);
        let runner = Arc::new(retention::runner_with_clock(
            Arc::clone(&s),
            Arc::clone(&clock) as Arc<dyn Clock>,
        ));
        let call = |days: u32| {
            let r = Arc::clone(&runner);
            async move { tokio::task::spawn_blocking(move || r(days)).await.unwrap() }
        };
        assert_eq!(
            call(1_000).await,
            Ok(1_000),
            "the argument does not widen the run"
        );
        assert_eq!(call(365).await, Ok(0), "within the hour: nothing");
        clock.now.fetch_add(HOUR, Ordering::SeqCst);
        assert_eq!(call(365).await, Ok(200));
        assert_eq!(assert_contiguous(&*s).await.len(), 1_200);
        assert_eq!(
            audit_rows(&*s)
                .await
                .iter()
                .filter(|r| r.action == "retention")
                .count(),
            2
        );
        // Outside a runtime the runner refuses instead of panicking.
        let r = Arc::clone(&runner);
        let outside = std::thread::spawn(move || r(365)).join().unwrap();
        assert!(matches!(outside, Err(StoreError::Backend(_))));
    }

    /// Deletion entries are kept for `retention_days` + 30 days and audit rows for 400 days;
    /// both prunes keep the newest row, so the heads never move back.
    pub async fn prunes_keep_deletions_for_retention_plus_30_days_and_the_heads(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let c = org.caller(org.admin);
        let ids: Vec<Id> = (0..3).map(|_| Id::new_v4()).collect();
        for (id, at) in ids.iter().zip([T0, T0 + 100 * DAY, T0 + 380 * DAY]) {
            delete::run(s, &c, DeleteRequest::Ids(vec![*id]), at)
                .await
                .unwrap();
        }
        // 395 days after T0 + 2 h: the entry of T0 is older than 365 + 30 days, the others not.
        let now = T0 + 395 * DAY + 2 * HOUR;
        let run = retention::run(s, now).await.unwrap().unwrap();
        assert_eq!(run.pruned_deletions, 1);
        let heads = s.deletion_heads().await.unwrap();
        assert_eq!((heads.oldest, heads.head), (1, 2));
        // Far later: every entry is old; the head stays and keeps its index.
        let later = T0 + 2_000 * DAY;
        let audit_head = s.audit(0, 1).await.unwrap().head;
        let run = retention::run(s, later).await.unwrap().unwrap();
        assert_eq!(run.pruned_deletions, 1);
        let heads = s.deletion_heads().await.unwrap();
        assert_eq!((heads.oldest, heads.head), (2, 2));
        assert_eq!(assert_contiguous(s).await, vec![(2, ids[2])]);
        // Audit: every row older than 400 days is gone except the newest old one; the new
        // retention row continues the index.
        assert_eq!(run.pruned_audit as i64, audit_head);
        let rows = audit_rows(s).await;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].idx as i64, audit_head);
        assert_eq!((rows[1].idx as i64, rows[1].at), (audit_head + 1, later));
        // A new deletion continues the stream at head + 1.
        delete::run(s, &c, DeleteRequest::Ids(vec![Id::new_v4()]), later)
            .await
            .unwrap();
        assert_eq!(s.deletion_heads().await.unwrap().head, 3);
    }

    /// Retention, member deletes by id and pre-deletions running at once: the deletion stream
    /// is contiguous and names every id exactly once.
    pub async fn the_deletion_stream_stays_contiguous_under_concurrent_deletes(f: Fixture) {
        let s = Arc::clone(&f.store);
        let org = bootstrap(&*s).await;
        let a = org.admin;
        let roy = add_member(&*s, &org, "roy", 2).await;
        let old = push_at(&*s, &a, "rec", 2_000, T0).await;
        let rens = push_at(&*s, &roy, "rec", 300, T0 + 300 * DAY).await;
        let now = T0 + 400 * DAY;
        let roy_c = org.caller(roy);
        let a_c = org.caller(a);
        // Two runs at once: exactly one of them does the work (one run per organisation).
        let t1 = {
            let s = Arc::clone(&s);
            tokio::spawn(async move {
                let (x, y) = tokio::join!(retention::run(&*s, now), retention::run(&*s, now));
                let runs: Vec<RetentionRun> =
                    [x.unwrap(), y.unwrap()].into_iter().flatten().collect();
                assert_eq!(runs.len(), 1, "{runs:?}");
                runs[0]
            })
        };
        let t2 = {
            let s = Arc::clone(&s);
            let ids = rens.clone();
            tokio::spawn(async move {
                for chunk in ids.chunks(10) {
                    delete::run(&*s, &roy_c, DeleteRequest::Ids(chunk.to_vec()), now)
                        .await
                        .unwrap();
                }
            })
        };
        let t3 = {
            let s = Arc::clone(&s);
            tokio::spawn(async move {
                let mut pre = Vec::new();
                for _ in 0..50 {
                    let id = Id::new_v4();
                    pre.push(id);
                    delete::run(&*s, &a_c, DeleteRequest::Ids(vec![id]), now)
                        .await
                        .unwrap();
                }
                pre
            })
        };
        let run = t1.await.unwrap();
        t2.await.unwrap();
        let pre = t3.await.unwrap();
        assert_eq!(run.deleted, 2_000);
        let e = assert_contiguous(&*s).await;
        assert_eq!(e.len(), 2_350);
        assert_eq!(e[0].0, 0);
        let got: HashSet<Id> = e.into_iter().map(|(_, id)| id).collect();
        let want: HashSet<Id> = old.into_iter().chain(rens).chain(pre).collect();
        assert_eq!(got, want);
    }

    /// `retention::hourly` with an injected clock: does nothing before the organisation
    /// exists, runs at start when the last run is an hour old, then every hour, and stops on
    /// shutdown.
    pub async fn hourly_runs_at_start_when_due_then_every_hour_and_stops(f: Fixture) {
        let s = &f.store;
        let start = T0 + 365 * DAY + HOUR;
        let clock = FakeClock::new(start, 1);
        let report = run_hourly(s, &clock).await;
        assert_eq!(report, HourlyReport::default(), "no organisation yet");
        assert_eq!(clock.sleeps(), vec![3_600]);
        let org = bootstrap(&**s).await;
        let a = org.admin;
        let x = push_at(&**s, &a, "rec", 1, T0).await;
        // `received_at` is rounded down to the hour, and T0 is 800 s past one: x is received
        // at T0 - 800 s, y at T0 + 10,000 s. Runs at start (cutoff T0 + 1 h) delete x, at
        // + 1 h (cutoff T0 + 2 h) nothing, at + 2 h (cutoff T0 + 3 h) y.
        let y = push_at(&**s, &a, "rec", 1, T0 + 3 * HOUR).await;
        let clock = FakeClock::new(start, 3);
        let report = run_hourly(s, &clock).await;
        assert_eq!(
            report,
            HourlyReport {
                runs: 3,
                failures: 0,
                deleted: 2
            }
        );
        assert_eq!(clock.sleeps(), vec![3_600, 3_600, 3_600]);
        let runs: Vec<_> = audit_rows(&**s)
            .await
            .into_iter()
            .filter(|r| r.action == "retention")
            .map(|r| (r.at, r.detail.unwrap()))
            .collect();
        assert_eq!(runs.len(), 3);
        for ((at, detail), (want_at, n)) in
            runs.iter()
                .zip([(start, 1), (start + HOUR, 0), (start + 2 * HOUR, 1)])
        {
            assert_eq!(*at, want_at);
            assert!(detail.starts_with(&format!("deleted={n} ")), "{detail}");
        }
        let e = assert_contiguous(&**s).await;
        assert_eq!(e, vec![(0, x[0]), (1, y[0])]);
    }

    /// `retention::hourly` after a recent run waits for the rest of the hour, then runs.
    pub async fn hourly_waits_for_the_rest_of_the_hour_after_a_recent_run(f: Fixture) {
        let s = &f.store;
        bootstrap(&**s).await;
        let start = T0 + 10 * DAY;
        s.meta_set(
            meta_keys::LAST_RETENTION.into(),
            (start - 1_800).to_string(),
        )
        .await
        .unwrap();
        let clock = FakeClock::new(start, 2);
        let report = run_hourly(s, &clock).await;
        assert_eq!(report.runs, 1);
        assert_eq!(clock.sleeps(), vec![1_800, 3_600]);
        assert_eq!(
            retention::last_retention(&**s).await.unwrap(),
            Some(start + 1_800)
        );
        let runs: Vec<_> = audit_rows(&**s)
            .await
            .into_iter()
            .filter(|r| r.action == "retention")
            .map(|r| r.at)
            .collect();
        assert_eq!(runs, vec![start + 1_800]);
    }

    /// No path deletes a `record` row (only blobs; markers keep index and id), and a caller of
    /// another organisation deletes nothing (401 before anything is read or written).
    pub async fn no_path_deletes_a_record_row_or_reaches_another_organisation(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let kit = add_member(s, &org, "kit", 3).await;
        let ids = push_at(s, &roy, "rec", 4, T0).await;
        push_at(s, &kit, "rec", 4, T0).await;
        push_at(s, &a, "rec", 4, T0).await;
        // Another organisation's callers, with this store's own member and device ids.
        let before = s.dump().await.unwrap();
        let foreign = Id::new_v4();
        for who in [a, roy] {
            let d = Device {
                org_id: foreign,
                member_id: who.member_id,
                device_id: who.device_id,
            };
            let c = if who.admin {
                Caller::Admin(d)
            } else {
                Caller::Member(d)
            };
            for req in [
                DeleteRequest::Ids(vec![ids[0]]),
                DeleteRequest::AllMine,
                DeleteRequest::Member(roy.member_id),
            ] {
                let e = delete::run(s, &c, req, T0).await.unwrap_err();
                if who.admin {
                    assert_eq!(e, DeleteError::Refused(Refusal::Unauthenticated));
                }
                assert!(matches!(e.status(), 401 | 403), "{e:?}");
            }
            let e = delete::remove_member(s, &c, kit.member_id, true, T0)
                .await
                .unwrap_err();
            assert!(matches!(e.status(), 401 | 403), "{e:?}");
        }
        let after = s.dump().await.unwrap();
        assert_eq!(after.rows("record"), before.rows("record"));
        assert_eq!(after.rows("deletion"), before.rows("deletion"));
        assert_eq!(after.rows("member"), before.rows("member"));
        // Every path of this organisation: rows stay, blobs go.
        let rows = record_rows(s).await;
        delete::run(s, &org.caller(roy), DeleteRequest::Ids(vec![ids[0]]), T0)
            .await
            .unwrap();
        delete::run(s, &org.caller(roy), DeleteRequest::AllMine, T0)
            .await
            .unwrap();
        delete::run(
            s,
            &org.caller(a),
            DeleteRequest::Member(roy.member_id),
            T0 + HOUR,
        )
        .await
        .unwrap();
        delete::remove_member(s, &org.caller(a), kit.member_id, true, T0)
            .await
            .unwrap();
        retention::run(s, T0 + 400 * DAY).await.unwrap().unwrap();
        retention::run(s, T0 + 2_000 * DAY).await.unwrap().unwrap();
        assert_eq!(record_rows(s).await, rows);
        assert_eq!(assert_contiguous(s).await.len(), 1, "pruned to the head");
        for who in [&a, &roy, &kit] {
            let got = items(s, who, "rec").await;
            assert_eq!(got.len(), 4, "every index kept");
            assert!(got.iter().all(|i| matches!(i, PulledItem::Deleted(_))));
        }
    }

    /// Audit rows and error bodies hold ids and counts only: no blob, no handle.
    pub async fn audit_rows_and_errors_hold_no_blob_and_no_handle(f: Fixture) {
        let s = &*f.store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let kit = add_member(s, &org, "kit", 3).await;
        let mut blobs = Vec::new();
        for who in [&a, &roy, &kit] {
            for id in push_at(s, who, "rec", 3, T0).await {
                blobs.push(blob(&id.to_string(), 1));
            }
        }
        let rens = items(s, &roy, "rec").await;
        let PulledItem::Record(first) = &rens[0] else {
            panic!()
        };
        let akis = items(s, &a, "rec").await;
        let PulledItem::Record(alf0) = &akis[0] else {
            panic!()
        };
        let mut errors = Vec::new();
        errors.push(
            delete::run(
                s,
                &org.caller(roy),
                DeleteRequest::Ids(vec![first.id, alf0.id]),
                T0,
            )
            .await
            .unwrap_err(),
        );
        delete::run(s, &org.caller(roy), DeleteRequest::Ids(vec![first.id]), T0)
            .await
            .unwrap();
        delete::run(s, &org.caller(roy), DeleteRequest::AllMine, T0)
            .await
            .unwrap();
        errors.push(
            delete::run(s, &org.caller(roy), DeleteRequest::AllMine, T0 + 1)
                .await
                .unwrap_err(),
        );
        errors.push(
            delete::run(
                s,
                &org.caller(roy),
                DeleteRequest::Member(kit.member_id),
                T0,
            )
            .await
            .unwrap_err(),
        );
        errors.push(
            delete::run(
                s,
                &org.caller(a),
                DeleteRequest::Ids((0..1_001).map(|_| Id::new_v4()).collect()),
                T0,
            )
            .await
            .unwrap_err(),
        );
        delete::remove_member(s, &org.caller(a), kit.member_id, true, T0)
            .await
            .unwrap();
        retention::run(s, T0 + 400 * DAY).await.unwrap().unwrap();
        assert_eq!(errors.len(), 4);
        for e in &errors {
            assert_clean_error(e, &blobs);
        }
        let rows = audit_rows(s).await;
        assert!(rows.len() >= 8);
        for r in &rows {
            assert_clean(&format!("{r:?}"), &blobs);
        }
        // Positive control: the scan finds a handle and a blob where they are.
        let text = format!("roy {}", String::from(B64(blobs[0].0.clone())));
        assert!(std::panic::catch_unwind(|| assert_clean(&text, &blobs)).is_err());
    }
}

// ---------------------------------------------------------------------------------------------
// Instantiation per backend

macro_rules! delete_retention_cases {
    ($factory:path) => {
        delete_retention_cases!(@each $factory;
            deletes_follow_ownership_and_admins_delete_any_record,
            deletes_by_id_are_idempotent_and_unknown_ids_are_pre_deleted,
            more_than_1000_ids_get_413_and_nothing_is_deleted,
            bulk_deletes_are_once_per_hour_per_token_and_noticed_to_admins,
            removal_with_delete_records_deletes_and_asks_for_rotation,
            roster_records_are_never_deleted_and_the_chain_stays_complete,
            retention_deletes_only_older_records_in_batches_oldest_first,
            a_pending_retention_decrease_applies_only_when_due,
            request_time_deletes_at_most_1000_rows_once_an_hour,
            the_tm8_runner_does_one_bounded_batch_at_most_once_an_hour,
            prunes_keep_deletions_for_retention_plus_30_days_and_the_heads,
            the_deletion_stream_stays_contiguous_under_concurrent_deletes,
            hourly_runs_at_start_when_due_then_every_hour_and_stops,
            hourly_waits_for_the_rest_of_the_hour_after_a_recent_run,
            no_path_deletes_a_record_row_or_reaches_another_organisation,
            audit_rows_and_errors_hold_no_blob_and_no_handle,
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
    delete_retention_cases!(super::sqlite_fixture);
}

#[cfg(feature = "pg")]
mod pg {
    delete_retention_cases!(super::pg_fixture);
}

// ---------------------------------------------------------------------------------------------
// SQLite only: the byte scan of the database file

#[cfg(feature = "sqlite")]
mod sqlite_only {
    use super::*;
    use awm_server::store::sqlite::{SqliteStore, DB_FILE};

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn file_bytes(path: &Path) -> Vec<u8> {
        std::fs::read(path).unwrap_or_default()
    }

    /// Several 48-byte windows across the blob, past the version byte.
    fn probe(b: &B64) -> Vec<Vec<u8>> {
        let v = &b.0;
        (1..v.len() - 48)
            .step_by(v.len() / 8)
            .map(|i| v[i..i + 48].to_vec())
            .collect()
    }

    fn pushed(id: Id, idx: u64, b: &B64) -> PushItem {
        PushItem::Record(PushRecord {
            tag: tag("rec"),
            idx,
            id,
            epoch: 0,
            blob: b.clone(),
        })
    }

    /// §5.6 through `delete::run` (no explicit checkpoint by the caller: `run` does it),
    /// through a bulk delete, and through `retention::run`: the deleted blobs' bytes are in
    /// neither `server.db` nor its WAL afterwards; a kept neighbour is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn deleted_blob_bytes_are_absent_from_the_file_and_the_wal() {
        let dir = TempDir::new("bytes");
        let store = SqliteStore::open(dir.path()).unwrap();
        let s: &dyn Store = &store;
        let org = bootstrap(s).await;
        let a = org.admin;
        let roy = add_member(s, &org, "roy", 2).await;
        let db = dir.path().join(DB_FILE);
        let wal = dir.path().join(format!("{DB_FILE}-wal"));
        let (small, large, keep) = (
            blob("small-secret", 1),
            blob("large-secret", 60),
            blob("kept", 2),
        );
        let (small_id, large_id, keep_id) = (Id::new_v4(), Id::new_v4(), Id::new_v4());
        let bulk = blob("bulk-secret", 4);
        let old = blob("retained-secret", 3);
        s.push(PushBatch {
            member_id: a.member_id,
            device_id: a.device_id,
            items: vec![
                pushed(small_id, 0, &small),
                pushed(large_id, 1, &large),
                pushed(keep_id, 2, &keep),
            ],
            now: T0 + 400 * DAY,
        })
        .await
        .unwrap();
        s.push(PushBatch {
            member_id: roy.member_id,
            device_id: roy.device_id,
            items: vec![pushed(Id::new_v4(), 0, &bulk)],
            now: T0 + 400 * DAY,
        })
        .await
        .unwrap();
        s.push(PushBatch {
            member_id: a.member_id,
            device_id: a.device_id,
            items: vec![PushItem::Record(PushRecord {
                tag: tag("flag"),
                idx: 0,
                id: Id::new_v4(),
                epoch: 0,
                blob: old.clone(),
            })],
            now: T0,
        })
        .await
        .unwrap();
        s.checkpoint().await.unwrap();
        let bytes = file_bytes(&db);
        for b in [&small, &large, &keep, &bulk, &old] {
            assert!(
                probe(b).iter().all(|p| contains(&bytes, p)),
                "the scan finds stored blobs"
            );
        }
        // 1. `delete::run` with ids, then without any checkpoint of our own.
        delete::run(
            s,
            &org.caller(a),
            DeleteRequest::Ids(vec![small_id, large_id]),
            T0 + 400 * DAY,
        )
        .await
        .unwrap();
        let (bytes, wal_bytes) = (file_bytes(&db), file_bytes(&wal));
        let mut probes = 0;
        for b in [&small, &large] {
            for p in probe(b) {
                probes += 1;
                assert!(!contains(&bytes, &p), "deleted blob bytes in server.db");
                assert!(!contains(&wal_bytes, &p), "deleted blob bytes in the WAL");
            }
        }
        assert!(
            probe(&keep).iter().all(|p| contains(&bytes, p)),
            "others stay"
        );
        assert_eq!(wal_bytes.len(), 0, "TRUNCATE empties the WAL");
        eprintln!(
            "byte scan (delete::run ids): server.db {} bytes, WAL {} bytes, {probes} probes absent",
            bytes.len(),
            wal_bytes.len()
        );
        // 2. A bulk delete (`all_mine`).
        delete::run(s, &org.caller(roy), DeleteRequest::AllMine, T0 + 400 * DAY)
            .await
            .unwrap();
        // 3. Retention (the flag record received at T0).
        let run = retention::run(s, T0 + 400 * DAY).await.unwrap().unwrap();
        assert_eq!(run.deleted, 1);
        let (bytes, wal_bytes) = (file_bytes(&db), file_bytes(&wal));
        for b in [&bulk, &old] {
            for p in probe(b) {
                assert!(!contains(&bytes, &p), "deleted blob bytes in server.db");
                assert!(!contains(&wal_bytes, &p), "deleted blob bytes in the WAL");
            }
        }
        assert!(probe(&keep).iter().all(|p| contains(&bytes, p)));
        eprintln!(
            "byte scan (all_mine + retention::run): server.db {} bytes, WAL {} bytes, {} probes absent",
            bytes.len(),
            wal_bytes.len(),
            probe(&bulk).len() + probe(&old).len()
        );
    }
}
