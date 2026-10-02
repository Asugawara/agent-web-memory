//! Built-in backup and restore (plan-v3-team §6.2, §3.9.5, §4.8.1, §5.6; TM27).
//!
//! Every scenario runs against a `file://` directory and, with `object-store-ring`, against
//! object_store's `InMemory`; a fake clock drives the cadence; nothing touches the network
//! (the S3 endpoint test talks to a listener on 127.0.0.1).
//!
//! Run: `cargo test -p awm-server --features sqlite,object-store-ring --test backup`
//! (`--features sqlite` runs the `file://` half; `--features all` adds the S3 endpoint test and,
//! with `AWM_TEST_PG_URL`, the `PgStore` export).

#![cfg(feature = "sqlite")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use awm_proto::wire::{
    DeleteRequest, Handle, Id, InviteKind, Key32, PushItem, PushRecord, Tag, Version, B64,
};
use awm_server::backup::full::{pg_daily_export, snapshot_now};
use awm_server::backup::restore::{
    self, assemble, select_chain, verify, RestoreDest, RestoreReport, RestoreRequest, RestoreSource,
};
use awm_server::backup::run::{retention, Backup, RunOptions, Step, AUDIT_FULL};
use awm_server::backup::target::{BucketFuture, Listing};
use awm_server::backup::{
    keys, list_all, status, BackupError, Bucket, Clock, Kind, Level, Manifest, Origin, Target,
    TargetError, FULL_INTERVAL_S, KEEP_FULL_S, NO_TARGET,
};
use awm_server::store::sqlite::{SqliteStore, DB_FILE};
use awm_server::store::{
    checksum, Actor, LogicalDump, NewBootstrap, NewInvite, NewJoin, OrgDefaults, PushBatch, Store,
};

// ---------------------------------------------------------------------------------------------
// Fixtures

const T0: i64 = 1_790_000_000;
const DAY: i64 = 86_400;

/// A directory under the target's temporary directory, mode 0700, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "backup-{tag}-{}-{nanos}-{}",
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

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A clock whose sleep advances its own time.
struct FakeClock(AtomicI64);

impl FakeClock {
    fn new(t: i64) -> Arc<FakeClock> {
        Arc::new(FakeClock(AtomicI64::new(t)))
    }

    fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    fn sleep(
        &self,
        secs: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.0.fetch_add(secs as i64, Ordering::SeqCst);
            tokio::task::yield_now().await;
        })
    }
}

fn h(s: &str) -> String {
    checksum(s.as_bytes())
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

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

struct Org {
    admin: Actor,
}

async fn bootstrap(s: &dyn Store) -> Org {
    s.set_bootstrap(h("bootstrap"), T0 + DAY).await.unwrap();
    let device = Id::new_v4();
    let member = s
        .bootstrap(NewBootstrap {
            bootstrap_token_hash: h("bootstrap"),
            org_id: Id::new_v4(),
            handle: Handle::parse("alf").unwrap(),
            device_id: device,
            device_pubkey: Key32([1; 32]),
            device_token_hash: h(&format!("device-{device}")),
            defaults: OrgDefaults {
                retention_days: 365,
                min_client: Version::new(0, 2, 0),
                max_members: 100,
            },
            now: T0,
        })
        .await
        .unwrap();
    Org {
        admin: Actor {
            member_id: member,
            device_id: device,
            admin: true,
        },
    }
}

/// Invites and joins a member (pending device): rows in invite, member, device, audit.
async fn add_member(s: &dyn Store, org: &Org, name: &str) {
    let invite_id = Id::new_v4();
    s.create_invite(NewInvite {
        invite_id,
        token_hash: h(&format!("invite-{invite_id}")),
        kind: InviteKind::Member,
        handle: Handle::parse(name).unwrap(),
        role: None,
        expires_at: T0 + 7 * DAY,
        by: org.admin,
        now: T0,
    })
    .await
    .unwrap();
    let device = Id::new_v4();
    s.join(NewJoin {
        invite_id,
        invite_token_hash: h(&format!("invite-{invite_id}")),
        handle: Handle::parse(name).unwrap(),
        device_id: device,
        device_pubkey: Key32([9; 32]),
        join_mac: Key32([8; 32]),
        device_token_hash: h(&format!("device-{device}")),
        now: T0 + 60,
    })
    .await
    .unwrap();
}

/// Pushes `n` records to the admin's `rec` stream; returns their ids.
async fn push_n(s: &dyn Store, a: &Actor, n: u64) -> Vec<Id> {
    let t = Tag::parse("rec").unwrap();
    let head = s
        .stream_head(a.member_id, a.device_id, t.clone())
        .await
        .unwrap();
    let ids: Vec<Id> = (0..n).map(|_| Id::new_v4()).collect();
    let items = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            PushItem::Record(PushRecord {
                tag: t.clone(),
                idx: (head + 1) as u64 + i as u64,
                id: *id,
                epoch: 0,
                blob: blob(&id.to_string(), 1),
            })
        })
        .collect();
    let r = s
        .push(PushBatch {
            member_id: a.member_id,
            device_id: a.device_id,
            items,
            now: T0 + 3_600,
        })
        .await
        .unwrap();
    assert_eq!(r.accepted as u64, n);
    ids
}

fn file_bucket(dir: &Path) -> Arc<dyn Bucket> {
    Target::parse(&format!("file://{}", dir.display()))
        .unwrap()
        .open()
        .unwrap()
}

/// The buckets every scenario runs against.
fn buckets(root: &Path) -> Vec<(&'static str, Arc<dyn Bucket>)> {
    #[allow(unused_mut)]
    let mut v = vec![("file", file_bucket(&root.join("bucket")))];
    #[cfg(feature = "object-store-ring")]
    v.push((
        "memory",
        Arc::new(awm_server::backup::target::ObjectStoreBucket::new(
            Arc::new(object_store::memory::InMemory::new()),
            "teams/awm",
            "memory://teams/awm",
        )) as Arc<dyn Bucket>,
    ));
    v
}

/// A server: its store, data directory, clock and backup runner.
struct Server {
    data: PathBuf,
    sqlite: SqliteStore,
    store: Arc<dyn Store>,
    clock: Arc<FakeClock>,
    backup: Arc<Backup>,
}

fn runner(
    store: &Arc<dyn Store>,
    bucket: &Arc<dyn Bucket>,
    clock: &Arc<FakeClock>,
    data: &Path,
    verify: Option<i64>,
) -> Arc<Backup> {
    let mut opts = RunOptions::new(data);
    opts.verify_interval_s = verify;
    Backup::new(
        Arc::clone(store),
        Arc::clone(bucket),
        Arc::clone(clock) as Arc<dyn Clock>,
        opts,
    )
}

async fn server(root: &Path, name: &str, bucket: &Arc<dyn Bucket>) -> (Server, Org) {
    let data = root.join(name);
    let sqlite = SqliteStore::open(&data).unwrap();
    let store: Arc<dyn Store> = Arc::new(sqlite.clone());
    let org = bootstrap(&*store).await;
    let clock = FakeClock::new(T0 + 2 * 3_600);
    let backup = runner(&store, bucket, &clock, &data, None);
    (
        Server {
            data,
            sqlite,
            store,
            clock,
            backup,
        },
        org,
    )
}

async fn restore_to(
    bucket: &Arc<dyn Bucket>,
    dir: &Path,
    at: Option<i64>,
    force: bool,
    now: i64,
) -> Result<RestoreReport, BackupError> {
    restore::run(RestoreRequest {
        source: RestoreSource::Bucket(Arc::clone(bucket)),
        dest: RestoreDest::Data(dir.to_path_buf()),
        at,
        force,
        mark_restored: false,
        now,
    })
    .await
}

/// Every object key in the bucket.
async fn all_keys(bucket: &dyn Bucket) -> Vec<String> {
    let mut keys: Vec<String> = list_all(bucket)
        .await
        .unwrap()
        .iter()
        .flat_map(|(g, o)| o.keys(*g))
        .collect();
    keys.sort();
    keys
}

async fn manifest_of(bucket: &dyn Bucket, data_key: &str) -> Manifest {
    let key = data_key.replace(".db", ".json");
    Manifest::from_bytes(&bucket.get(key).await.unwrap().unwrap()).unwrap()
}

fn integrity_ok(db: &Path) {
    let conn = rusqlite::Connection::open(db).unwrap();
    let r: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(r, "ok");
}

fn incr(step: &Step) -> &Manifest {
    match step {
        Step::Incremental(u) => &u.manifest,
        other => panic!("expected an incremental, got {other:?}"),
    }
}

fn full_of(step: &Step) -> &Manifest {
    match step {
        Step::Full(u) => &u.manifest,
        other => panic!("expected a full snapshot, got {other:?}"),
    }
}

/// A bucket wrapper that fails on demand, as a process killed in the middle of an upload.
#[derive(Debug)]
struct Flaky {
    inner: Arc<dyn Bucket>,
    mode: Mutex<Fail>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fail {
    Never,
    /// The next upload fails before anything is stored.
    NextPut,
    /// The next manifest upload fails: the data object is stored without its manifest.
    NextManifest,
}

impl Flaky {
    fn new(inner: Arc<dyn Bucket>) -> Arc<Flaky> {
        Arc::new(Flaky {
            inner,
            mode: Mutex::new(Fail::Never),
        })
    }

    fn set(&self, f: Fail) {
        *self.mode.lock().unwrap() = f;
    }
}

impl Bucket for Flaky {
    fn url(&self) -> String {
        self.inner.url()
    }

    fn put_new(&self, key: String, bytes: Vec<u8>) -> BucketFuture<'_, ()> {
        let mut mode = self.mode.lock().unwrap();
        let fail = match *mode {
            Fail::Never => false,
            Fail::NextPut => true,
            Fail::NextManifest => key.ends_with(".json"),
        };
        if fail {
            *mode = Fail::Never;
            return Box::pin(async move {
                Err(TargetError::Io {
                    op: "upload",
                    key,
                    msg: "connection reset (process killed)".into(),
                })
            });
        }
        drop(mode);
        self.inner.put_new(key, bytes)
    }

    fn get(&self, key: String) -> BucketFuture<'_, Option<Vec<u8>>> {
        self.inner.get(key)
    }

    fn list(&self, dir: String) -> BucketFuture<'_, Listing> {
        self.inner.list(dir)
    }

    fn delete(&self, key: String) -> BucketFuture<'_, ()> {
        self.inner.delete(key)
    }
}

// ---------------------------------------------------------------------------------------------
// Targets

#[test]
fn targets_parse_from_urls_and_refuse_credentials_and_unknown_schemes() {
    assert_eq!(
        Target::parse("gs://example-awm-backup/awm").unwrap(),
        Target::Gcs {
            bucket: "example-awm-backup".into(),
            prefix: "awm".into()
        }
    );
    assert_eq!(
        Target::parse("s3://bkt/a/b/").unwrap(),
        Target::S3 {
            bucket: "bkt".into(),
            prefix: "a/b".into()
        }
    );
    assert_eq!(
        Target::parse("file:///var/backups/awm").unwrap(),
        Target::File {
            path: PathBuf::from("/var/backups/awm")
        }
    );
    assert_eq!(Target::parse("gs://bkt").unwrap().to_string(), "gs://bkt");
    // Unknown schemes: the §4.8.1 wording, without the URL.
    let e = Target::parse("ftp://host/x").unwrap_err();
    assert!(matches!(e, TargetError::Invalid(_)));
    let text = e.to_string();
    assert!(text.contains("unsupported scheme `ftp`"), "{text}");
    assert!(
        text.contains("gs://BUCKET/PREFIX") && text.contains("file:///PATH"),
        "{text}"
    );
    // Credentials and options never come from the URL.
    for (url, secret) in [
        ("s3://bkt/p?credentials=SECRETKEY", "SECRETKEY"),
        ("gs://bkt/p?key_file=/etc/SECRETKEY.json", "SECRETKEY"),
        ("gs://user:SECRETKEY@bkt/p", "SECRETKEY"),
        ("s3://bkt/p#SECRETKEY", "SECRETKEY"),
        ("SECRETKEY://bkt", "SECRETKEY"),
    ] {
        let e = Target::parse(url).unwrap_err();
        assert!(matches!(e, TargetError::Invalid(_)), "{url}");
        assert!(!e.to_string().contains(secret), "{url}: {e}");
        assert_eq!(BackupError::from(e).exit_code(), 2);
    }
    for bad in [
        "file://relative/path",
        "file:///",
        "file:///a/../b",
        "gs://",
        "gs://ab/p",
        "gs://Bkt/p",
        "s3://bkt/a//b",
        "gs://bkt/a/../b",
        "no-scheme",
    ] {
        assert!(Target::parse(bad).is_err(), "{bad}");
    }
    // Key-file environment variables are reported by name only.
    let env = vec![
        (
            "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
            "/k.json".to_string(),
        ),
        ("HOME".to_string(), "/home/x".to_string()),
    ];
    assert_eq!(
        awm_server::backup::target::key_file_env(env),
        vec!["GOOGLE_APPLICATION_CREDENTIALS".to_string()]
    );
}

#[cfg(not(feature = "backup-s3"))]
#[test]
fn a_cloud_scheme_without_its_feature_is_refused() {
    let e = Target::parse("s3://bkt/p")
        .unwrap()
        .open_with_env(vec![])
        .unwrap_err();
    assert_eq!(e, TargetError::NotBuilt("backup-s3"));
}

/// `AWS_ENDPOINT_URL` (an S3-compatible endpoint) is honoured: the request reaches a listener
/// on 127.0.0.1, signed with the key from the environment; the secret appears in no error.
#[cfg(feature = "backup-s3")]
#[tokio::test]
async fn s3_uses_aws_endpoint_url_and_credentials_from_the_environment() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while !contains(&buf, b"\r\n\r\n") {
            let n = sock.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        sock.write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        String::from_utf8_lossy(&buf).to_string()
    });
    let env = vec![
        (
            "AWS_ENDPOINT_URL".to_string(),
            format!("http://127.0.0.1:{port}"),
        ),
        ("AWS_ALLOW_HTTP".to_string(), "true".to_string()),
        ("AWS_ACCESS_KEY_ID".to_string(), "AKIDEXAMPLE".to_string()),
        (
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "SECRETEXAMPLEKEY".to_string(),
        ),
        ("AWS_REGION".to_string(), "us-east-1".to_string()),
    ];
    let bucket = Target::parse("s3://awm-bkt/team")
        .unwrap()
        .open_with_env(env)
        .unwrap();
    assert!(!format!("{bucket:?}").contains("SECRETEXAMPLEKEY"));
    let err = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        bucket.list("full".into()),
    )
    .await
    .expect("no answer from the local endpoint")
    .unwrap_err();
    let request = server.await.unwrap();
    assert!(request.starts_with("GET /awm-bkt"), "{request}");
    assert!(request.contains("prefix=team%2Ffull%2F"), "{request}");
    assert!(
        request.contains("AKIDEXAMPLE"),
        "signed with the environment's key"
    );
    assert!(!request.contains("SECRETEXAMPLEKEY"));
    assert!(!err.to_string().contains("SECRETEXAMPLEKEY"), "{err}");
    // Google Cloud Storage builds from the environment alone (no network until used).
    #[cfg(feature = "backup-gcs")]
    assert!(Target::parse("gs://awm-bkt/team")
        .unwrap()
        .open_with_env(vec![])
        .is_ok());
}

#[tokio::test]
async fn file_targets_are_private_and_create_only() {
    let root = TempDir::new("file");
    let dir = root.path().join("a/b");
    let bucket = file_bucket(&dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
    bucket
        .put_new("full/x/1.db".into(), b"one".to_vec())
        .await
        .unwrap();
    let e = bucket
        .put_new("full/x/1.db".into(), b"two".to_vec())
        .await
        .unwrap_err();
    assert_eq!(
        e,
        TargetError::AlreadyExists {
            key: "full/x/1.db".into()
        }
    );
    assert_eq!(
        bucket.get("full/x/1.db".into()).await.unwrap().unwrap(),
        b"one"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("full/x/1.db"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    // A leftover temporary file of an upload cut short is invisible.
    std::fs::write(dir.join("full/x/.tmp-1-1"), b"partial").unwrap();
    assert_eq!(
        bucket.list("full/x".into()).await.unwrap().objects,
        vec!["1.db".to_string()]
    );
    assert_eq!(bucket.get("full/x/2.db".into()).await.unwrap(), None);
    bucket.delete("full/x/1.db".into()).await.unwrap();
    bucket.delete("full/x/1.db".into()).await.unwrap();
    assert!(bucket
        .list("full/x".into())
        .await
        .unwrap()
        .objects
        .is_empty());
}

// ---------------------------------------------------------------------------------------------
// Format, cadence and restore

/// TM27 row: a full snapshot plus three incrementals restores to a logical dump identical to
/// the live database; the result passes `integrity_check`; a restore writes a new generation.
#[tokio::test]
async fn a_full_snapshot_plus_three_incrementals_restores_the_live_dump() {
    let root = TempDir::new("chain");
    for (name, bucket) in buckets(root.path()) {
        let (s, org) = server(root.path(), &format!("live-{name}"), &bucket).await;
        let start = s.backup.tick().await.unwrap();
        let full = full_of(&start.step).clone();
        assert_eq!((full.kind, full.origin), (Kind::Full, Origin::Start));
        assert_eq!(
            full.data_key(),
            format!("full/{}/{}.db", full.generation, full.seq)
        );
        // An unchanged minute uploads nothing.
        s.clock.advance(60);
        assert_eq!(s.backup.tick().await.unwrap().step, Step::Unchanged);
        // Three minutes with changes: inserts, an update (a deletion marker), a new member.
        let ids = push_n(&*s.store, &org.admin, 3).await;
        s.clock.advance(60);
        let i1 = incr(&s.backup.tick().await.unwrap().step).clone();
        s.store
            .delete(DeleteRequest::Ids(vec![ids[0]]), org.admin, T0 + 7_200)
            .await
            .unwrap();
        s.clock.advance(60);
        let i2 = incr(&s.backup.tick().await.unwrap().step).clone();
        add_member(&*s.store, &org, "roy").await;
        push_n(&*s.store, &org.admin, 2).await;
        s.clock.advance(60);
        let i3 = incr(&s.backup.tick().await.unwrap().step).clone();
        // The chain is contiguous and named after its heads.
        assert_eq!(i1.after, full.to);
        assert_eq!((i2.after, i3.after), (i1.to, i2.to));
        assert_eq!(
            i3.data_key(),
            format!("incr/{}/{}.db", i3.generation, i3.seq)
        );
        assert_eq!(Some(i3.seq), i3.to);
        assert_eq!(all_keys(&*bucket).await.len(), 8, "{name}");
        // The manifest's counts and hash describe the object.
        let data = bucket.get(i1.data_key()).await.unwrap().unwrap();
        assert!(i1.matches(&data));
        assert_eq!(i1.rows.get("record"), Some(&3));
        assert_eq!(manifest_of(&*bucket, &i1.data_key()).await, i1);
        assert_eq!(
            s.store.meta_get(keys::CURSOR.into()).await.unwrap(),
            Some(i3.seq.to_string())
        );

        let live = s.store.dump().await.unwrap();
        let chain = select_chain(&*bucket, None).await.unwrap();
        assert_eq!(chain.keys().len(), 4);
        let asm = TempDir::new("asm");
        let assembled = assemble(&*bucket, &chain, &asm.path().join("db"))
            .await
            .unwrap();
        assert_eq!(assembled.dump().await.unwrap(), live, "{name}");

        let target = root.path().join(format!("restored-{name}"));
        let report = restore_to(&bucket, &target, None, false, s.clock.now())
            .await
            .unwrap();
        assert_eq!(report.digest.as_deref(), Some(live.digest().as_str()));
        assert_eq!(report.objects, chain.keys());
        assert_eq!(report.cursor, i3.to);
        integrity_ok(&target.join(DB_FILE));
        let restored = SqliteStore::open(&target).unwrap();
        let before = s.store.restore_state().await.unwrap();
        let after = restored.restore_state().await.unwrap();
        assert_ne!(after.generation, before.generation);
        assert_eq!(after.generation, report.generation);
        assert_eq!(report.restored_from, Some(before.generation));
        assert!(after.restore_pending);
        assert_eq!(after.restored_at, Some(s.clock.now()));
        // Every table but meta and audit (the new generation and its audit row) is the live one.
        let rd = restored.dump().await.unwrap();
        for (t, rows) in &live.tables {
            if *t != "meta" && *t != "audit" {
                assert_eq!(rd.rows(t), rows.as_slice(), "{name}: {t}");
            }
        }
        assert_eq!(rd.rows("audit").len(), live.rows("audit").len() + 1);
        // The backup state starts afresh, the old generation is the lineage.
        assert_eq!(
            restored
                .meta_get(keys::CURSOR.into())
                .await
                .unwrap()
                .as_deref(),
            Some("")
        );
        assert_eq!(
            restored.meta_get(keys::LINEAGE.into()).await.unwrap(),
            Some(before.generation.to_string())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(target.join(DB_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}

/// TM27 row: `--at` restores the chain up to that time: the latest full snapshot at or before
/// it, then only the change sets written up to it.
#[tokio::test]
async fn at_restores_the_chain_up_to_that_time() {
    let root = TempDir::new("at");
    for (name, bucket) in buckets(root.path()) {
        let (s, org) = server(root.path(), &format!("live-{name}"), &bucket).await;
        let t_full = s.clock.now();
        s.backup.tick().await.unwrap();
        let mut dumps = Vec::new();
        for _ in 0..3 {
            push_n(&*s.store, &org.admin, 2).await;
            s.clock.advance(60);
            incr(&s.backup.tick().await.unwrap().step);
            dumps.push((s.clock.now(), s.store.dump().await.unwrap()));
        }
        // A day later: the daily full snapshot, then one more change set.
        s.clock.advance(DAY);
        let daily = full_of(&s.backup.tick().await.unwrap().step).clone();
        assert_eq!(daily.origin, Origin::Daily);
        push_n(&*s.store, &org.admin, 1).await;
        s.clock.advance(60);
        incr(&s.backup.tick().await.unwrap().step);
        let last = s.store.dump().await.unwrap();

        let now = s.clock.now();
        for (i, (t, dump)) in dumps.iter().enumerate() {
            let dir = root.path().join(format!("at-{name}-{i}"));
            let r = restore_to(&bucket, &dir, Some(*t + 30), false, now)
                .await
                .unwrap();
            assert_eq!(
                r.digest.as_deref(),
                Some(dump.digest().as_str()),
                "{name} {i}"
            );
            assert_eq!(r.objects.len(), 2 + i);
            assert_eq!(r.point_in_time, Some(*t));
        }
        // Between the daily snapshot and the next change set: that snapshot alone.
        let dir = root.path().join(format!("at-{name}-daily"));
        let r = restore_to(&bucket, &dir, Some(daily.time + 1), false, now)
            .await
            .unwrap();
        assert_eq!(r.objects, vec![daily.data_key()]);
        // Without --at: everything.
        let dir = root.path().join(format!("at-{name}-latest"));
        let r = restore_to(&bucket, &dir, None, false, now).await.unwrap();
        assert_eq!(r.digest.as_deref(), Some(last.digest().as_str()));
        // Before the first full snapshot: nothing to restore.
        let dir = root.path().join(format!("at-{name}-none"));
        let e = restore_to(&bucket, &dir, Some(t_full - 1), false, now)
            .await
            .unwrap_err();
        assert!(matches!(e, BackupError::NoBackup(_)), "{e}");
        assert_eq!(e.exit_code(), 1);
        assert!(!dir.join(DB_FILE).exists());
    }
}

/// TM27 row: one flipped byte in any object (data or manifest) is refused with exit 3 naming
/// the object, and nothing is written to the data directory.
#[tokio::test]
async fn one_flipped_byte_in_any_object_is_refused_with_exit_3_naming_it() {
    let root = TempDir::new("flip");
    let bucket_dir = root.path().join("bucket");
    let bucket = file_bucket(&bucket_dir);
    let (s, org) = server(root.path(), "live", &bucket).await;
    s.backup.tick().await.unwrap();
    for _ in 0..3 {
        push_n(&*s.store, &org.admin, 2).await;
        s.clock.advance(60);
        incr(&s.backup.tick().await.unwrap().step);
    }
    let keys = all_keys(&*bucket).await;
    assert_eq!(keys.len(), 8);
    let now = s.clock.now();
    for (n, key) in keys.iter().enumerate() {
        let path = bucket_dir.join(key);
        let original = std::fs::read(&path).unwrap();
        for at in [original.len() / 2, original.len() - 1] {
            let mut bytes = original.clone();
            bytes[at] ^= 0x01;
            std::fs::write(&path, &bytes).unwrap();
            let dir = root.path().join(format!("r-{n}-{at}"));
            let e = restore_to(&bucket, &dir, None, false, now)
                .await
                .unwrap_err();
            assert_eq!(e.exit_code(), 3, "{key} byte {at}: {e}");
            assert!(e.to_string().contains(key.as_str()), "{key}: {e}");
            assert!(!dir.join(DB_FILE).exists(), "{key}");
        }
        std::fs::write(&path, &original).unwrap();
    }
    let dir = root.path().join("r-ok");
    restore_to(&bucket, &dir, None, false, now).await.unwrap();
}

/// TM27 row: a missing change set in the chain is refused (exit 3), and so is a data object
/// whose manifest remains; `--verify` detects the missing change set.
#[tokio::test]
async fn a_missing_incremental_is_refused_and_verify_detects_it() {
    let root = TempDir::new("missing");
    for (name, bucket) in buckets(root.path()) {
        let (s, org) = server(root.path(), &format!("live-{name}"), &bucket).await;
        s.backup.tick().await.unwrap();
        let mut sets = Vec::new();
        for _ in 0..3 {
            push_n(&*s.store, &org.admin, 2).await;
            s.clock.advance(60);
            sets.push(incr(&s.backup.tick().await.unwrap().step).clone());
        }
        let now = s.clock.now();
        let scratch = root.path().join(format!("scratch-{name}"));
        std::fs::create_dir_all(&scratch).unwrap();
        let ok = verify(&*s.store, &*bucket, now, &scratch).await.unwrap();
        assert!(ok.compared);
        assert_eq!(ok.objects, 4);
        assert_eq!(ok.behind_rows, 0);

        // Only the data object of the second set gone: refused, naming it.
        let data = bucket.get(sets[1].data_key()).await.unwrap().unwrap();
        bucket.delete(sets[1].data_key()).await.unwrap();
        let e = restore_to(
            &bucket,
            &root.path().join(format!("a-{name}")),
            None,
            false,
            now,
        )
        .await
        .unwrap_err();
        assert_eq!(e.exit_code(), 3);
        assert!(e.to_string().contains(&sets[1].data_key()), "{e}");
        bucket.put_new(sets[1].data_key(), data).await.unwrap();

        // The whole second set gone: a gap.
        bucket.delete(sets[1].key()).await.unwrap();
        bucket.delete(sets[1].data_key()).await.unwrap();
        let e = restore_to(
            &bucket,
            &root.path().join(format!("b-{name}")),
            None,
            false,
            now,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(e, BackupError::MissingIncrement { after, .. } if Some(after) == sets[0].to),
            "{e}"
        );
        assert_eq!(e.exit_code(), 3);
        // --at before the gap still restores.
        restore_to(
            &bucket,
            &root.path().join(format!("c-{name}")),
            Some(sets[0].time),
            false,
            now,
        )
        .await
        .unwrap();

        s.clock.advance(60);
        let e = verify(&*s.store, &*bucket, s.clock.now(), &scratch)
            .await
            .unwrap_err();
        assert!(matches!(e, BackupError::MissingIncrement { .. }), "{e}");
        assert_eq!(e.exit_code(), 3);
        let st = status(&*s.store).await.unwrap();
        assert_eq!(st.verify_ok, Some(false));
        assert_eq!(st.verify_at, Some(s.clock.now()));
        assert_eq!(st.verify_ok_at, Some(now));
        // The temporary directories are gone.
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
    }
}

/// `--force` is required over an existing database (which it moves aside); every restore
/// writes a new generation; `--mark-restored` only renews the generation.
#[tokio::test]
async fn restore_needs_force_over_a_database_and_always_renews_the_generation() {
    let root = TempDir::new("force");
    let bucket = file_bucket(&root.path().join("bucket"));
    let (s, org) = server(root.path(), "live", &bucket).await;
    s.backup.tick().await.unwrap();
    push_n(&*s.store, &org.admin, 2).await;
    s.clock.advance(60);
    s.backup.tick().await.unwrap();
    let now = s.clock.now();

    let target = root.path().join("target");
    let first = restore_to(&bucket, &target, None, false, now)
        .await
        .unwrap();
    let e = restore_to(&bucket, &target, None, false, now + 1)
        .await
        .unwrap_err();
    assert!(matches!(e, BackupError::Refused(_)), "{e}");
    assert_eq!(e.exit_code(), 2);
    let second = restore_to(&bucket, &target, None, true, now + 2)
        .await
        .unwrap();
    assert_ne!(second.generation, first.generation);
    let moved = second.pre_restore.clone().unwrap();
    assert_eq!(
        moved,
        target.join(format!("{DB_FILE}.pre-restore-{}", now + 2))
    );
    // The previous database is intact under its new name.
    let old = SqliteStore::open_file(&moved).unwrap();
    assert_eq!(
        old.restore_state().await.unwrap().generation,
        first.generation
    );
    drop(old);
    integrity_ok(&target.join(DB_FILE));

    // --mark-restored: the same data, a new generation, restore_pending.
    let store = SqliteStore::open(&target).unwrap();
    let before = store.dump().await.unwrap();
    let gen_before = store.restore_state().await.unwrap().generation;
    drop(store);
    let marked = restore::run(RestoreRequest {
        source: RestoreSource::None,
        dest: RestoreDest::Data(target.clone()),
        at: None,
        force: false,
        mark_restored: true,
        now: now + 3,
    })
    .await
    .unwrap();
    assert_ne!(marked.generation, gen_before);
    let store = SqliteStore::open(&target).unwrap();
    let after = store.dump().await.unwrap();
    for t in [
        "org", "member", "device", "invite", "record", "deletion", "wrap",
    ] {
        assert_eq!(after.rows(t), before.rows(t), "{t}");
    }
    assert!(store.restore_state().await.unwrap().restore_pending);
    // --mark-restored with a source, and a restore without one, are refused.
    for (source, mark) in [
        (RestoreSource::Bucket(Arc::clone(&bucket)), true),
        (RestoreSource::None, false),
    ] {
        let e = restore::run(RestoreRequest {
            source,
            dest: RestoreDest::Data(root.path().join("other")),
            at: None,
            force: false,
            mark_restored: mark,
            now,
        })
        .await
        .unwrap_err();
        assert_eq!(e.exit_code(), 2, "{e}");
    }
    // A file source: an on-demand snapshot written to a file target restores too.
    let file_target = file_bucket(&root.path().join("ondemand"));
    let up = snapshot_now(&*s.store, &*file_target, now, &s.data)
        .await
        .unwrap();
    assert_eq!(up.manifest.origin, Origin::OnDemand);
    let file = root.path().join("ondemand").join(&up.key);
    let r = restore::run(RestoreRequest {
        source: RestoreSource::parse(file.to_str().unwrap()).unwrap(),
        dest: RestoreDest::Data(root.path().join("from-file")),
        at: None,
        force: false,
        mark_restored: false,
        now,
    })
    .await
    .unwrap();
    assert_eq!(r.digest, Some(s.store.dump().await.unwrap().digest()));
}

/// TM27 row: `kill -9` during an upload leaves a restorable chain: an upload cut off after its
/// data object and before its manifest is ignored by restore, and the restarted server
/// replaces it and goes on.
#[tokio::test]
async fn kill_9_during_an_upload_leaves_a_restorable_chain() {
    let root = TempDir::new("kill");
    for (name, inner) in buckets(root.path()) {
        let flaky = Flaky::new(Arc::clone(&inner));
        let bucket: Arc<dyn Bucket> = flaky.clone();
        let (s, org) = server(root.path(), &format!("live-{name}"), &bucket).await;
        s.backup.tick().await.unwrap();
        push_n(&*s.store, &org.admin, 2).await;
        s.clock.advance(60);
        incr(&s.backup.tick().await.unwrap().step);
        let shipped = s.store.dump().await.unwrap();

        // The next change set: its data object is stored, then the process dies.
        push_n(&*s.store, &org.admin, 2).await;
        s.clock.advance(60);
        flaky.set(Fail::NextManifest);
        let e = s.backup.tick().await.unwrap_err();
        assert!(matches!(e, BackupError::Target(_)), "{e}");
        let cursor = s.store.meta_get(keys::CURSOR.into()).await.unwrap();
        drop(s.backup);

        let orphans = list_all(&*inner).await.unwrap();
        let (g, objs) = orphans.iter().next().unwrap();
        assert_eq!(
            objs.incr_data.len(),
            objs.incr_json.len() + 1,
            "one data object without manifest"
        );
        let r = restore_to(
            &inner,
            &root.path().join(format!("r1-{name}")),
            None,
            false,
            s.clock.now(),
        )
        .await
        .unwrap();
        assert_eq!(
            r.digest,
            Some(shipped.digest()),
            "{name}: the chain up to the last complete set"
        );

        // The restarted server: a start snapshot of everything, then it goes on.
        let backup = runner(&s.store, &bucket, &s.clock, &s.data, None);
        s.clock.advance(5);
        let start = full_of(&backup.tick().await.unwrap().step).clone();
        assert_eq!(start.generation, *g);
        assert_ne!(s.store.meta_get(keys::CURSOR.into()).await.unwrap(), cursor);
        push_n(&*s.store, &org.admin, 1).await;
        s.clock.advance(60);
        incr(&backup.tick().await.unwrap().step);
        let r = restore_to(
            &inner,
            &root.path().join(format!("r2-{name}")),
            None,
            false,
            s.clock.now(),
        )
        .await
        .unwrap();
        assert_eq!(r.digest, Some(s.store.dump().await.unwrap().digest()));

        // Killed while uploading the start snapshot of an unchanged database: the restart
        // removes the object without a manifest and writes it again.
        drop(backup);
        let backup = runner(&s.store, &bucket, &s.clock, &s.data, None);
        flaky.set(Fail::NextManifest);
        s.clock.advance(5);
        backup.tick().await.unwrap_err();
        drop(backup);
        let backup = runner(&s.store, &bucket, &s.clock, &s.data, None);
        s.clock.advance(5);
        let again = backup.tick().await.unwrap();
        assert!(
            matches!(&again.step, Step::Full(u) if !u.reused),
            "{again:?}"
        );
        // A failure before anything is stored leaves the cursor; the next tick ships it all.
        push_n(&*s.store, &org.admin, 1).await;
        let cursor = s.store.meta_get(keys::CURSOR.into()).await.unwrap();
        flaky.set(Fail::NextPut);
        s.clock.advance(60);
        backup.tick().await.unwrap_err();
        assert_eq!(s.store.meta_get(keys::CURSOR.into()).await.unwrap(), cursor);
        let st = status(&*s.store).await.unwrap();
        assert!(st.error.as_deref().unwrap().contains("process killed"));
        assert_eq!(st.failing_since, Some(s.clock.now()));
        s.clock.advance(60);
        incr(&backup.tick().await.unwrap().step);
        assert_eq!(status(&*s.store).await.unwrap().failing_since, None);
        let r = restore_to(
            &inner,
            &root.path().join(format!("r3-{name}")),
            None,
            false,
            s.clock.now(),
        )
        .await
        .unwrap();
        assert_eq!(r.digest, Some(s.store.dump().await.unwrap().digest()));
    }
}

/// TM27 row: a second server writing to the same prefix fails its first upload and `check`
/// reports `FAIL backup`; it uploads nothing afterwards. A server of another database is
/// refused before its first upload; a restored server (the old generation in its lineage) is
/// not.
#[tokio::test]
async fn a_second_server_on_the_same_prefix_fails_its_first_upload() {
    let root = TempDir::new("second");
    for (name, bucket) in buckets(root.path()) {
        let (s, org) = server(root.path(), &format!("live-{name}"), &bucket).await;
        s.backup.tick().await.unwrap();
        // A second process over the same database (two `awm serve` on one data directory).
        let twin_store: Arc<dyn Store> = Arc::new(SqliteStore::open(&s.data).unwrap());
        let twin = runner(&twin_store, &bucket, &s.clock, &s.data, None);
        let started = twin.tick().await.unwrap();
        assert!(
            matches!(&started.step, Step::Full(u) if u.reused),
            "the start snapshot is the same object"
        );
        push_n(&*s.store, &org.admin, 2).await;
        s.clock.advance(60);
        incr(&s.backup.tick().await.unwrap().step);
        let before = all_keys(&*bucket).await;
        let e = twin.tick().await.unwrap_err();
        assert!(matches!(e, BackupError::Conflict(_)), "{e}");
        push_n(&*s.store, &org.admin, 1).await;
        s.clock.advance(60);
        assert!(matches!(twin.tick().await.unwrap().step, Step::Blocked(_)));
        assert_eq!(all_keys(&*bucket).await, before, "the twin wrote nothing");
        let lines = status(&*s.store)
            .await
            .unwrap()
            .check(Some(&bucket.url()), s.clock.now());
        assert!(
            lines
                .iter()
                .any(|l| l.level == Level::Fail && l.text.contains("another server")),
            "{lines:?}"
        );

        // Another database on the same prefix: refused before it uploads anything.
        let other_dir = root.path().join(format!("other-{name}"));
        let other: Arc<dyn Store> = Arc::new(SqliteStore::open(&other_dir).unwrap());
        bootstrap(&*other).await;
        let o = runner(&other, &bucket, &s.clock, &other_dir, None);
        let before = all_keys(&*bucket).await;
        let e = o.tick().await.unwrap_err();
        assert!(matches!(e, BackupError::Conflict(_)), "{e}");
        assert_eq!(all_keys(&*bucket).await, before);
        let lines = status(&*other)
            .await
            .unwrap()
            .check(Some("x"), s.clock.now());
        assert!(lines.iter().any(|l| l.level == Level::Fail), "{lines:?}");

        // A server restored from this prefix writes its new generation next to the old one.
        let restored_dir = root.path().join(format!("restored-{name}"));
        restore_to(&bucket, &restored_dir, None, false, s.clock.now())
            .await
            .unwrap();
        let r: Arc<dyn Store> = Arc::new(SqliteStore::open(&restored_dir).unwrap());
        let rb = runner(&r, &bucket, &s.clock, &restored_dir, None);
        s.clock.advance(60);
        let up = full_of(&rb.tick().await.unwrap().step).clone();
        assert_eq!(up.origin, Origin::Restore);
        assert_eq!(up.generation, r.restore_state().await.unwrap().generation);
        // ... and the old server, still running, now sees a newer foreign generation.
        s.clock.advance(3_600);
        let e = s.backup.tick().await.unwrap_err();
        assert!(matches!(e, BackupError::Conflict(_)), "{e}");
    }
}

/// The cadence under a fake clock: start, incrementals only when `backup_log` grew, the cursor
/// after a successful upload only, pruning after each full snapshot, daily snapshots, the
/// migration hook, an idle day, and the restore → start of a new generation.
#[tokio::test]
async fn the_cadence_follows_6_2() {
    let root = TempDir::new("cadence");
    for (name, bucket) in buckets(root.path()) {
        let (s, org) = server(root.path(), &format!("live-{name}"), &bucket).await;
        let start = full_of(&s.backup.tick().await.unwrap().step).clone();
        // The log up to the snapshot is pruned.
        let log = s.store.backup_log(0, 10_000).await.unwrap();
        assert!(log.iter().all(|r| r.seq > start.seq), "{name}");
        assert_eq!(
            status(&*s.store).await.unwrap().last_full_at,
            Some(start.time)
        );
        for _ in 0..3 {
            s.clock.advance(60);
            assert_eq!(s.backup.tick().await.unwrap().step, Step::Unchanged);
        }
        assert_eq!(all_keys(&*bucket).await.len(), 2);
        // A write after the start → one change set at the next tick, none after.
        add_member(&*s.store, &org, "roy").await;
        s.clock.advance(60);
        let i = incr(&s.backup.tick().await.unwrap().step).clone();
        assert_eq!(
            s.store.meta_get(keys::CURSOR.into()).await.unwrap(),
            Some(i.seq.to_string())
        );
        s.clock.advance(60);
        assert_eq!(s.backup.tick().await.unwrap().step, Step::Unchanged);
        // The migration hook: a full snapshot at the next tick, whatever the time.
        s.backup.request_full(Origin::Migration);
        s.clock.advance(60);
        let m = full_of(&s.backup.tick().await.unwrap().step).clone();
        assert_eq!(m.origin, Origin::Migration);
        // An idle day: an audit row gives the daily snapshot a name of its own.
        s.clock.advance(DAY);
        let d = full_of(&s.backup.tick().await.unwrap().step).clone();
        assert_eq!(d.origin, Origin::Daily);
        assert!(d.seq > m.seq);
        let audit = s.store.audit(0, 1_000).await.unwrap();
        assert!(audit.rows.iter().any(|r| r.action == AUDIT_FULL));
        // The store's generation changes under the running server: a full snapshot of it.
        s.store.renew_generation(s.clock.now()).await.unwrap();
        s.clock.advance(60);
        let g = full_of(&s.backup.tick().await.unwrap().step).clone();
        assert_eq!(g.origin, Origin::Generation);
        assert_ne!(g.generation, d.generation);
        // The old generation is this database's history: the hourly check passes, and
        // retention covers it.
        assert_eq!(
            s.store.meta_get(keys::LINEAGE.into()).await.unwrap(),
            Some(d.generation.to_string())
        );
        add_member(&*s.store, &org, "kit").await;
        s.clock.advance(3_600);
        let t = s.backup.tick().await.unwrap();
        incr(&t.step);
        assert!(t.retention.is_some());
        // Status: everything fine except the verification that never ran.
        let lines = status(&*s.store)
            .await
            .unwrap()
            .check(Some("u"), s.clock.now());
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(lines[0].level, Level::Warn);
        assert!(lines[0]
            .text
            .contains("no successful --verify within 30 days"));
    }
}

/// The weekly self-verification in the loop, and the `check` lines of §4.8.1.
#[tokio::test]
async fn weekly_verification_and_check_lines() {
    let root = TempDir::new("verify");
    let bucket = file_bucket(&root.path().join("bucket"));
    let data = root.path().join("live");
    let sqlite = SqliteStore::open(&data).unwrap();
    let store: Arc<dyn Store> = Arc::new(sqlite);
    let org = bootstrap(&*store).await;
    let clock = FakeClock::new(T0 + 7_200);

    // Before any backup: the §4.8.1 lines.
    let st = status(&*store).await.unwrap();
    let none = st.check(None, clock.now());
    assert_eq!(none.len(), 1);
    assert_eq!(
        (none[0].level, none[0].text.as_str()),
        (Level::Warn, NO_TARGET)
    );
    let fresh = st.check(Some("gs://b/p"), clock.now());
    assert!(fresh
        .iter()
        .any(|l| l.level == Level::Fail && l.text.contains("no full snapshot within 48 h")));

    let backup = runner(&store, &bucket, &clock, &data, Some(7 * DAY));
    let t = backup.tick().await.unwrap();
    let v = t.verify.unwrap().unwrap();
    assert!(v.compared && v.objects == 1);
    let lines = status(&*store)
        .await
        .unwrap()
        .check(Some("gs://b/p"), clock.now());
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].level, Level::Ok, "{lines:?}");
    // Writes newer than the chain do not fail it.
    push_n(&*store, &org.admin, 3).await;
    let v = verify(&*store, &*bucket, clock.now(), &data).await.unwrap();
    assert!(v.behind_rows > 0);
    // Not again within the week; again after it.
    clock.advance(DAY);
    assert!(backup.tick().await.unwrap().verify.is_none());
    clock.advance(6 * DAY);
    let t = backup.tick().await.unwrap();
    assert!(t.verify.unwrap().is_ok());
    // No leftover temporary directories in the data directory.
    let leftovers: Vec<_> = std::fs::read_dir(&data)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".backup-"))
        .collect();
    assert!(leftovers.is_empty());

    // Uploads failing for more than an hour, no full snapshot within 48 h, no verification
    // within 30 days.
    let flaky = Flaky::new(Arc::clone(&bucket));
    let b2 = runner(
        &store,
        &(flaky.clone() as Arc<dyn Bucket>),
        &clock,
        &data,
        None,
    );
    clock.advance(60);
    b2.tick().await.unwrap();
    push_n(&*store, &org.admin, 1).await;
    flaky.set(Fail::NextPut);
    clock.advance(60);
    b2.tick().await.unwrap_err();
    let st = status(&*store).await.unwrap();
    let soon = st.check(Some("u"), clock.now() + 3_000);
    assert!(soon.iter().all(|l| !l.text.contains("failing")), "{soon:?}");
    let later = st.check(Some("u"), clock.now() + 3_700);
    assert!(
        later
            .iter()
            .any(|l| l.level == Level::Fail && l.text.contains("failing for more than 1 h")),
        "{later:?}"
    );
    let old = st.check(Some("u"), clock.now() + 49 * 3_600);
    assert!(old
        .iter()
        .any(|l| l.level == Level::Fail && l.text.contains("no full snapshot within 48 h")));
    let stale = st.check(Some("u"), clock.now() + 31 * DAY);
    assert!(stale
        .iter()
        .any(|l| l.level == Level::Warn && l.text.contains("--verify")));
}

/// TM27 row and §5.6: retention keeps 7 days of full snapshots and the change sets newer than
/// the oldest kept one and removes only older objects; after it and the 8-day window no object
/// holds a deleted blob's bytes (byte scan of every object); old `server.db.bak-v*` files go.
#[tokio::test]
async fn retention_keeps_seven_days_and_deleted_blobs_are_gone_within_eight() {
    let root = TempDir::new("retention");
    for (name, bucket) in buckets(root.path()) {
        let (s, org) = server(root.path(), &format!("live-{name}"), &bucket).await;
        let a = org.admin;
        // A record in the start snapshot and one only in a change set; both deleted on day 0.
        let in_full = push_n(&*s.store, &a, 1).await[0];
        let t0 = s.clock.now();
        let mut uploaded: Vec<Manifest> =
            vec![full_of(&s.backup.tick().await.unwrap().step).clone()];
        let in_incr = push_n(&*s.store, &a, 1).await[0];
        let kept = push_n(&*s.store, &a, 1).await[0];
        s.clock.advance(60);
        uploaded.push(incr(&s.backup.tick().await.unwrap().step).clone());
        let needles: Vec<Vec<u8>> = [in_full, in_incr]
            .iter()
            .map(|id| blob(&id.to_string(), 1).0[1..49].to_vec())
            .collect();
        let kept_needle = blob(&kept.to_string(), 1).0[1..49].to_vec();
        s.store
            .delete(DeleteRequest::Ids(vec![in_full, in_incr]), a, T0 + 7_300)
            .await
            .unwrap();
        s.store.checkpoint().await.unwrap();
        s.clock.advance(60);
        uploaded.push(incr(&s.backup.tick().await.unwrap().step).clone());

        // Migration backups: one from day 0, one from day 7.
        let old_bak = s.data.join(format!("{DB_FILE}.bak-v1"));
        let new_bak = s.data.join(format!("{DB_FILE}.bak-v2"));
        for (p, t) in [(&old_bak, t0), (&new_bak, t0 + 7 * DAY + 3_600)] {
            std::fs::write(p, b"bak").unwrap();
            let f = std::fs::File::options().write(true).open(p).unwrap();
            f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(t as u64))
                .unwrap();
        }

        let scan = |objects: Vec<(String, Vec<u8>)>, needle: &[u8]| -> Vec<String> {
            objects
                .into_iter()
                .filter(|(_, b)| contains(b, needle))
                .map(|(k, _)| k)
                .collect()
        };
        let mut found_at_day_6 = Vec::new();
        let mut bak_removed = Vec::new();
        for day in 1..=8 {
            // A daily full snapshot, then a change set, every day.
            s.clock.advance(DAY - 120);
            push_n(&*s.store, &a, 1).await;
            s.clock.advance(60);
            let t = s.backup.tick().await.unwrap();
            let daily = full_of(&t.step).clone();
            assert_eq!(daily.origin, Origin::Daily);
            uploaded.push(daily);
            let r = t.retention.unwrap();
            bak_removed.extend(r.bak_removed.clone());
            let now = s.clock.now();
            // Exactly the full snapshots of the last 7 days and the change sets newer than the
            // oldest of them remain; everything older is gone.
            let keys_now: std::collections::BTreeSet<String> =
                all_keys(&*bucket).await.into_iter().collect();
            let kept_fulls: Vec<&Manifest> = uploaded
                .iter()
                .filter(|m| m.kind == Kind::Full && m.time >= now - KEEP_FULL_S)
                .collect();
            let s_keep = kept_fulls.iter().map(|m| m.seq).min().unwrap();
            assert_eq!(r.kept_fulls, kept_fulls.len(), "day {day}");
            let mut expected = 0;
            for m in &uploaded {
                let present = match m.kind {
                    Kind::Full => m.time >= now - KEEP_FULL_S,
                    _ => m.seq > s_keep,
                };
                expected += 2 * usize::from(present);
                for key in [m.data_key(), m.key()] {
                    assert_eq!(keys_now.contains(&key), present, "{name} day {day}: {key}");
                }
            }
            assert_eq!(keys_now.len(), expected, "{name} day {day}");
            push_n(&*s.store, &a, 1).await;
            s.clock.advance(60);
            uploaded.push(incr(&s.backup.tick().await.unwrap().step).clone());
            let now = s.clock.now();
            let mut objects = Vec::new();
            for key in all_keys(&*bucket).await {
                let bytes = bucket.get(key.clone()).await.unwrap().unwrap();
                objects.push((key, bytes));
            }
            let hits: usize = needles.iter().map(|n| scan(objects.clone(), n).len()).sum();
            let bytes: usize = objects.iter().map(|(_, b)| b.len()).sum();
            println!(
                "byte scan {name} day {day}: {} objects, {bytes} bytes, {hits} object(s) with a deleted blob",
                objects.len()
            );
            if day == 6 {
                for n in &needles {
                    found_at_day_6.extend(scan(objects.clone(), n));
                }
                assert!(old_bak.exists() && new_bak.exists());
            }
            if day == 8 {
                for n in &needles {
                    let hits = scan(objects.clone(), n);
                    assert!(
                        hits.is_empty(),
                        "{name}: deleted bytes in {hits:?} after 8 days"
                    );
                }
                assert!(
                    !scan(objects.clone(), &kept_needle).is_empty(),
                    "the kept record is backed up"
                );
                assert_eq!(bak_removed, vec![old_bak.clone()]);
                assert!(!old_bak.exists() && new_bak.exists());
                // What remains still restores to the live database.
                let dir = root.path().join(format!("after-{name}"));
                let rr = restore_to(&bucket, &dir, None, false, now).await.unwrap();
                assert_eq!(rr.digest, Some(s.store.dump().await.unwrap().digest()));
            }
        }
        assert!(
            !found_at_day_6.is_empty(),
            "{name}: within 7 days the old snapshot is still kept"
        );
    }
}

/// Retention never touches another generation's objects or names that are not backup objects,
/// and keeps the newest full snapshot even when it is older than 7 days.
#[tokio::test]
async fn retention_leaves_foreign_objects_and_keeps_the_newest_snapshot() {
    let root = TempDir::new("foreign");
    for (name, bucket) in buckets(root.path()) {
        let (s, _org) = server(root.path(), &format!("live-{name}"), &bucket).await;
        let up = full_of(&s.backup.tick().await.unwrap().step).clone();
        let foreign = Id::new_v4();
        bucket
            .put_new(format!("full/{foreign}/1.db"), b"x".to_vec())
            .await
            .unwrap();
        bucket
            .put_new("README.txt".into(), b"keep".to_vec())
            .await
            .unwrap();
        let r = retention(&*bucket, s.clock.now() + 30 * DAY, &[up.generation])
            .await
            .unwrap();
        assert!(r.deleted.is_empty(), "{r:?}");
        assert_eq!(r.kept_fulls, 1);
        assert!(bucket
            .get(format!("full/{foreign}/1.db"))
            .await
            .unwrap()
            .is_some());
        assert!(bucket.get("README.txt".into()).await.unwrap().is_some());
    }
}

/// `PgStore`'s daily canonical export (run here over a `SqliteStore` behind `dyn Store`), and
/// over `PgStore` itself when `AWM_TEST_PG_URL` is set.
#[tokio::test]
async fn the_daily_canonical_export_once_a_day_restores() {
    let root = TempDir::new("export");
    for (name, bucket) in buckets(root.path()) {
        let data = root.path().join(format!("live-{name}"));
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&data).unwrap());
        let org = bootstrap(&*store).await;
        push_n(&*store, &org.admin, 2).await;
        export_round_trip(&*store, &bucket, root.path(), name).await;
    }
}

async fn export_round_trip(store: &dyn Store, bucket: &Arc<dyn Bucket>, root: &Path, name: &str) {
    let clock = FakeClock::new(T0 + 7_200);
    let scratch = root.join(format!("scratch-{name}"));
    std::fs::create_dir_all(&scratch).unwrap();
    let up = pg_daily_export(store, &**bucket, &*clock, &scratch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (up.manifest.kind, up.manifest.seq),
        (Kind::Export, clock.now())
    );
    assert_eq!(up.manifest.to, None);
    assert!(up.key.starts_with("full/"));
    assert_eq!(manifest_of(&**bucket, &up.key).await, up.manifest);
    clock.advance(3_600);
    assert!(pg_daily_export(store, &**bucket, &*clock, &scratch)
        .await
        .unwrap()
        .is_none());
    clock.advance(FULL_INTERVAL_S);
    let second = pg_daily_export(store, &**bucket, &*clock, &scratch)
        .await
        .unwrap()
        .unwrap();
    assert!(second.manifest.seq > up.manifest.seq);
    let st = status(store).await.unwrap();
    assert_eq!(st.last_full_at, Some(clock.now()));
    let dir = root.join(format!("restored-{name}"));
    let r = restore_to(bucket, &dir, None, false, clock.now())
        .await
        .unwrap();
    assert_eq!(r.objects, vec![second.key.clone()]);
    assert_eq!(r.digest, Some(store.dump().await.unwrap().digest()));
    // Verification of an export chain: checked and counted (the live store moves on).
    let v = verify(store, &**bucket, clock.now(), &scratch)
        .await
        .unwrap();
    assert_eq!(v.objects, 1);
}

#[cfg(feature = "pg")]
#[path = "support/pg.rs"]
mod pg_support;

#[cfg(feature = "pg")]
#[tokio::test]
async fn the_daily_canonical_export_over_pg_store() {
    let Some(env) = pg_support::PgEnv::new("backup").await else {
        return;
    };
    let root = TempDir::new("pg");
    let store = env.store.create_org(Id::new_v4()).await.unwrap();
    let org = bootstrap(&*store).await;
    push_n(&*store, &org.admin, 2).await;
    let bucket = file_bucket(&root.path().join("bucket"));
    export_round_trip(&*store, &bucket, root.path(), "pg").await;
    // Restore into another, empty organisation of the same database.
    let target = env.store.create_org(Id::new_v4()).await.unwrap();
    let r = restore::run(RestoreRequest {
        source: RestoreSource::Bucket(Arc::clone(&bucket)),
        dest: RestoreDest::Store {
            store: Arc::clone(&target),
            scratch: root.path().join("scratch"),
        },
        at: None,
        force: false,
        mark_restored: false,
        now: T0 + 9_000,
    })
    .await
    .unwrap();
    assert_eq!(r.digest, Some(store.dump().await.unwrap().digest()));
    assert!(target.restore_state().await.unwrap().restore_pending);
    // Into an organisation that holds data: refused.
    let e = restore::run(RestoreRequest {
        source: RestoreSource::Bucket(Arc::clone(&bucket)),
        dest: RestoreDest::Store {
            store: Arc::clone(&target),
            scratch: root.path().join("scratch"),
        },
        at: None,
        force: false,
        mark_restored: false,
        now: T0 + 9_000,
    })
    .await
    .unwrap_err();
    assert_eq!(e.exit_code(), 2);
}

/// Manifests and errors hold no blob bytes, token hashes or credentials.
#[tokio::test]
async fn manifests_and_errors_hold_no_content() {
    let root = TempDir::new("content");
    let bucket = file_bucket(&root.path().join("bucket"));
    let (s, org) = server(root.path(), "live", &bucket).await;
    let ids = push_n(&*s.store, &org.admin, 2).await;
    s.backup.tick().await.unwrap();
    push_n(&*s.store, &org.admin, 2).await;
    s.clock.advance(60);
    s.backup.tick().await.unwrap();
    let needle = blob(&ids[0].to_string(), 1).0[1..49].to_vec();
    let token_hash = h(&format!("device-{}", org.admin.device_id));
    for key in all_keys(&*bucket).await {
        let bytes = bucket.get(key.clone()).await.unwrap().unwrap();
        if key.ends_with(".json") {
            assert!(!contains(&bytes, &needle), "{key}");
            assert!(!contains(&bytes, token_hash.as_bytes()), "{key}");
            assert!(!contains(&bytes, ids[0].to_string().as_bytes()), "{key}");
        }
    }
    // A corrupt object's error names the key and the reason only.
    let key = all_keys(&*bucket)
        .await
        .into_iter()
        .find(|k| k.ends_with(".db"))
        .unwrap();
    let path = root.path().join("bucket").join(&key);
    let mut bytes = std::fs::read(&path).unwrap();
    let n = bytes.len() / 2;
    bytes[n] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    let e = restore_to(&bucket, &root.path().join("r"), None, false, s.clock.now())
        .await
        .unwrap_err();
    assert!(!e.to_string().contains(&token_hash));
    let rendered = format!("{e:?}");
    assert!(!rendered.contains(&token_hash));
}

/// `Backup::run` ticks every 60 s until shutdown, then ships what changed once more.
#[tokio::test]
async fn the_loop_ticks_until_shutdown_and_ships_once_more() {
    let root = TempDir::new("loop");
    let bucket = file_bucket(&root.path().join("bucket"));
    let (s, org) = server(root.path(), "live", &bucket).await;
    let end = s.clock.now() + 300;
    let clock = Arc::clone(&s.clock);
    let store = Arc::clone(&s.store);
    let admin = org.admin;
    let shutdown = async move {
        while clock.now() < end {
            tokio::task::yield_now().await;
        }
        // A write after the last regular tick, shipped by the final one.
        push_n(&*store, &admin, 1).await;
    };
    let report = Arc::clone(&s.backup).run(shutdown).await;
    assert_eq!(report.failures, 0);
    assert!(report.ticks >= 6, "{report:?}");
    assert_eq!(
        report.uploads, 2,
        "the start snapshot and the final change set"
    );
    let r = restore_to(&bucket, &root.path().join("r"), None, false, s.clock.now())
        .await
        .unwrap();
    assert_eq!(r.digest, Some(s.store.dump().await.unwrap().digest()));
    let _ = s.sqlite.path();
}

/// The manifest's row counts of a full snapshot are the table counts of the database.
#[tokio::test]
async fn full_snapshot_manifests_count_rows_per_table() {
    let root = TempDir::new("rows");
    let bucket = file_bucket(&root.path().join("bucket"));
    let (s, org) = server(root.path(), "live", &bucket).await;
    add_member(&*s.store, &org, "roy").await;
    push_n(&*s.store, &org.admin, 4).await;
    let m = full_of(&s.backup.tick().await.unwrap().step).clone();
    let dump: LogicalDump = s.store.dump().await.unwrap();
    for t in [
        "org", "member", "device", "invite", "record", "wrap", "deletion",
    ] {
        assert_eq!(
            m.rows.get(t).copied(),
            Some(dump.rows(t).len() as u64),
            "{t}"
        );
    }
    assert!(m.rows.contains_key("backup_log"));
    assert_eq!(m.server_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(m.format, 1);
}
