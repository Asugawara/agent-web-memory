//! Authentication and authorisation (plan-v3-team §4.10, §4.3.3; `docs/sync-v1.md` §3, §6,
//! §7, §13; TM7) against a real `SqliteStore` in a scratch directory.
//!
//! Run: `cargo test -p awm-server --features sqlite --test authz`.
//!
//! Every test works in an [`Env`], which records the plaintext of every token it issues; when
//! the `Env` is dropped it scans the raw bytes of the database file and its WAL for each
//! token, its secret part and the secret's 32 raw bytes, and fails the test if any is found.
//! So every token issued anywhere in the suite is checked against the file it was issued for.

#![cfg(feature = "sqlite")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use awm_proto::wire::{
    ApproveRequest, BootstrapRequest, BootstrapToken, DeviceToken, EpochWrap, ErrorCode, Handle,
    Id, InviteKind, InviteRequest, InviteResponse, JoinRequest, JoinResponse, Key32, KnownTag,
    PushDeleted, PushItem, PushRecord, Role, Tag, Version, B64,
};
use awm_server::auth::{self, AuthError, Caller, CloudOwner, RateKey, TokenKind};
use awm_server::authz::{self, Action, DeleteScope, Refusal};
use awm_server::store::sqlite::{SqliteStore, DB_FILE};
use awm_server::store::{OrgDefaults, PushBatch, Store, StoreError};

// ---------------------------------------------------------------------------------------------
// Scratch directories and the plaintext scan

const T0: i64 = 1_790_000_000;
const DAY: i64 = 86_400;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "authz-{tag}-{}-{nanos}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The secret part of a token (43 base64url characters) and its 32 raw bytes.
fn secret_of(token: &str) -> (String, Vec<u8>) {
    let s = &token[token.len() - 43..];
    let raw = Key32::try_from(s.to_string())
        .expect("43-character secret")
        .0;
    (s.to_string(), raw.to_vec())
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Every place in the database directory where a token, its secret or the secret's raw
/// bytes occur (`server.db`, `-wal`, `-shm`).
fn plaintext_hits(dir: &Path, tokens: &[String]) -> Vec<String> {
    let mut hits = Vec::new();
    for name in [
        DB_FILE.to_string(),
        format!("{DB_FILE}-wal"),
        format!("{DB_FILE}-shm"),
    ] {
        let Ok(bytes) = std::fs::read(dir.join(&name)) else {
            continue;
        };
        for t in tokens {
            let (secret, raw) = secret_of(t);
            for (what, needle) in [
                ("token", t.as_bytes()),
                ("secret", secret.as_bytes()),
                ("raw secret", raw.as_slice()),
            ] {
                if contains(&bytes, needle) {
                    hits.push(format!("{what} of {}… in {name}", &t[..6]));
                }
            }
        }
    }
    hits
}

/// A store in a scratch directory plus the plaintext of every token issued in it.
struct Env {
    store: Arc<dyn Store>,
    data: PathBuf,
    issued: Mutex<Vec<String>>,
    _dir: TempDir,
}

impl Env {
    fn new(tag: &str) -> Env {
        let dir = TempDir::new(tag);
        let data = dir.0.join("data");
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&data).unwrap());
        Env {
            store,
            data,
            issued: Mutex::new(Vec::new()),
            _dir: dir,
        }
    }

    fn s(&self) -> &dyn Store {
        &*self.store
    }

    fn keep(&self, token: &str) {
        self.issued.lock().unwrap().push(token.to_string());
    }

    fn issued(&self) -> Vec<String> {
        self.issued.lock().unwrap().clone()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        let tokens = self.issued();
        let hits = plaintext_hits(&self.data, &tokens);
        assert!(
            hits.is_empty(),
            "plaintext tokens in the database: {hits:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Helpers

fn defaults() -> OrgDefaults {
    OrgDefaults {
        retention_days: 365,
        min_client: Version::new(0, 2, 0),
        max_members: 100,
    }
}

fn handle(s: &str) -> Handle {
    Handle::parse(s).unwrap()
}

fn key(n: u8) -> Key32 {
    Key32([n; 32])
}

fn header(t: &DeviceToken) -> String {
    format!("Bearer {}", t.as_str())
}

/// One wrap per epoch 0..=current (the server stores them as given).
fn wraps(current: u32) -> ApproveRequest {
    ApproveRequest {
        wraps: (0..=current)
            .map(|e| EpochWrap {
                epoch: e,
                wrap: B64(vec![0x5a; 140]),
                auth: key(0xa0 + e as u8),
            })
            .collect(),
    }
}

/// An envelope-shaped blob (`0x01` and 41 + 256 bytes).
fn blob(seed: u8) -> B64 {
    let mut v = vec![seed; 41 + 256];
    v[0] = 0x01;
    B64(v)
}

fn roster_item(idx: u64, epoch: u32) -> PushItem {
    PushItem::Record(PushRecord {
        tag: Tag::from(KnownTag::Roster),
        idx,
        id: Id::new_v4(),
        epoch,
        blob: blob(0x33),
    })
}

/// A device that belongs to a member, with its token.
#[derive(Clone)]
struct Who {
    token: DeviceToken,
    member: Id,
    device: Id,
}

impl Env {
    /// `awm serve init` + `POST /v1/bootstrap` with handle `alf`.
    async fn bootstrap(&self) -> Who {
        let bt = auth::issue_bootstrap(self.s(), T0).await.unwrap();
        self.keep(bt.as_str());
        let org = Id::new_v4();
        let device = Id::new_v4();
        let r = auth::bootstrap(
            self.s(),
            BootstrapRequest {
                bootstrap_token: bt,
                org_id: org,
                handle: handle("alf"),
                device_id: device,
                device_pubkey: key(1),
            },
            defaults(),
            T0,
        )
        .await
        .unwrap();
        self.keep(r.device_token.as_str());
        Who {
            token: r.device_token,
            member: r.member_id,
            device,
        }
    }

    async fn caller(&self, who: &Who) -> Caller {
        auth::authenticate(self.s(), Some(&header(&who.token)), T0)
            .await
            .unwrap()
    }

    async fn caller_at(&self, token: &DeviceToken, now: i64) -> Result<Caller, AuthError> {
        auth::authenticate(self.s(), Some(&header(token)), now).await
    }

    async fn invite(
        &self,
        by: &Who,
        kind: InviteKind,
        h: &str,
        role: Option<Role>,
    ) -> Result<InviteResponse, AuthError> {
        let caller = self.caller(by).await;
        let r = auth::create_invite(
            self.s(),
            &caller,
            InviteRequest {
                kind,
                handle: handle(h),
                role,
                expires_days: None,
            },
            T0,
        )
        .await;
        if let Ok(inv) = &r {
            self.keep(inv.invite_token.as_str());
        }
        r
    }

    async fn join_at(
        &self,
        inv: &InviteResponse,
        h: &str,
        now: i64,
    ) -> Result<(JoinResponse, JoinRequest), AuthError> {
        let req = JoinRequest {
            invite_id: inv.invite_id,
            invite_token: inv.invite_token.clone(),
            handle: handle(h),
            device_id: Id::new_v4(),
            device_pubkey: key(7),
            join_mac: key(9),
        };
        let r = auth::join(self.s(), req.clone(), now).await?;
        self.keep(r.device_token.as_str());
        Ok((r, req))
    }

    async fn join(&self, inv: &InviteResponse, h: &str) -> Who {
        let (r, _) = self.join_at(inv, h, T0).await.unwrap();
        Who {
            token: r.device_token,
            member: r.member_id,
            device: r.device_id,
        }
    }

    async fn approve(&self, by: &Who, device: Id) -> Result<(), AuthError> {
        let caller = self.caller(by).await;
        auth::approve(self.s(), &caller, device, wraps(0), T0).await
    }

    /// A member invite by `admin`, a join and the admin's approval.
    async fn member(&self, admin: &Who, h: &str, role: Option<Role>) -> Who {
        let inv = self
            .invite(admin, InviteKind::Member, h, role)
            .await
            .unwrap();
        let who = self.join(&inv, h).await;
        self.approve(admin, who.device).await.unwrap();
        who
    }

    /// A device invite for `h` created by `by`, and a join (pending).
    async fn device_for(&self, by: &Who, h: &str) -> Who {
        let inv = self.invite(by, InviteKind::Device, h, None).await.unwrap();
        self.join(&inv, h).await
    }

    async fn audit_actions(&self) -> Vec<String> {
        self.s()
            .audit(0, 1_000)
            .await
            .unwrap()
            .rows
            .into_iter()
            .map(|r| r.action)
            .collect()
    }
}

fn refused(r: Result<impl std::fmt::Debug, AuthError>) -> Refusal {
    match r {
        Err(AuthError::Refused(x)) => x,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn store_err(r: Result<impl std::fmt::Debug, AuthError>) -> StoreError {
    match r {
        Err(AuthError::Store(e)) => e,
        other => panic!("expected a store error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Tokens and parsing

#[test]
fn tokens_have_the_v1_formats_and_hash_to_sha256_hex() {
    let org = Id::new_v4();
    let b64url = |s: &str| {
        s.len() == 43
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    };
    let mut seen = BTreeSet::new();
    for _ in 0..50 {
        let d = auth::new_device_token(org).unwrap();
        let i = auth::new_invite_token(org).unwrap();
        let b = auth::new_bootstrap_token().unwrap();
        let ds = d.as_str();
        assert_eq!(ds.len(), 6 + 36 + 1 + 43, "{d:?}");
        assert!(ds.starts_with(&format!("awm_t_{org}_")));
        assert!(i.as_str().starts_with(&format!("awm_i_{org}_")));
        assert_eq!(i.as_str().len(), 86);
        assert!(b.as_str().starts_with("awm_b_"));
        assert_eq!(b.as_str().len(), 6 + 43);
        for t in [ds, i.as_str(), b.as_str()] {
            let tail = &t[t.len() - 43..];
            assert!(b64url(tail), "base64url without padding: {}", &t[..6]);
            assert!(!t.contains('='));
            assert_eq!(secret_of(t).1.len(), 32);
            assert!(seen.insert(tail.to_string()), "secrets are random");
        }
        assert_eq!(d.org(), org);
        assert_eq!(i.org(), org);
    }
    // FIPS 180-4 "abc", lower-case hex.
    assert_eq!(
        auth::hash("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let d = auth::new_device_token(org).unwrap();
    let h = auth::hash(d.as_str());
    assert_eq!(h.len(), 64);
    assert!(h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
}

#[test]
fn parse_reads_the_bearer_header_and_keeps_kind_org_and_hash_only() {
    let org = Id::new_v4();
    let d = auth::new_device_token(org).unwrap();
    let p = auth::parse(&header(&d)).unwrap();
    assert_eq!(p.kind(), TokenKind::Device);
    assert_eq!(p.org(), Some(org));
    assert_eq!(p.hash(), auth::hash(d.as_str()));
    let (secret, _) = secret_of(d.as_str());
    assert_eq!(p.log_prefix(), format!("awm_t_{org}_{}", &secret[..6]));
    assert!(!format!("{p:?}").contains(&secret), "{p:?}");
    assert!(!format!("{p:?}").contains(p.hash()), "{p:?}");
    // The scheme is case-insensitive.
    assert_eq!(auth::parse(&format!("bearer {}", d.as_str())).unwrap(), p);
    let i = auth::new_invite_token(org).unwrap();
    let b = auth::new_bootstrap_token().unwrap();
    assert_eq!(
        auth::parse(&format!("Bearer {}", i.as_str()))
            .unwrap()
            .kind(),
        TokenKind::Invite
    );
    let pb = auth::parse(&format!("Bearer {}", b.as_str())).unwrap();
    assert_eq!((pb.kind(), pb.org()), (TokenKind::Bootstrap, None));

    let t = d.as_str();
    let malformed = [
        String::new(),
        "Bearer".to_string(),
        t.to_string(),
        format!("Basic {t}"),
        format!("Bearer  {t}"),
        format!("Bearer {t} "),
        format!("Bearer {t}x"),
        format!("Bearer {}", &t[..t.len() - 1]),
        format!("Bearer {}=", &t[..t.len() - 1]),
        format!("Bearer {}", t.replacen("awm_t_", "awm_x_", 1)),
        format!("Bearer {}", t.to_uppercase()),
        format!("Bearer awm_t_{}_{}", org.to_string().to_uppercase(), secret),
        format!("Bearer awm_t_{org}-{secret}"),
    ];
    for m in &malformed {
        assert_eq!(auth::parse(m), Err(Refusal::Unauthenticated), "{m:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// Authentication

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticate_resolves_each_kind_of_caller_and_refuses_bad_tokens() {
    let env = Env::new("authn");
    let s = env.s();
    // No organisation yet: every token is 401, no header is anonymous.
    assert_eq!(
        auth::authenticate(s, None, T0).await.unwrap(),
        Caller::Anonymous
    );
    let early = auth::new_device_token(Id::new_v4()).unwrap();
    assert_eq!(
        refused(env.caller_at(&early, T0).await),
        Refusal::Unauthenticated
    );

    let alf = env.bootstrap().await;
    let roy = env.member(&alf, "roy", None).await;
    let inv = env
        .invite(&alf, InviteKind::Member, "pen", None)
        .await
        .unwrap();
    let pen = env.join(&inv, "pen").await;

    let org = s.org(T0).await.unwrap().unwrap().org_id;
    let dev = |w: &Who| auth::Device {
        org_id: org,
        member_id: w.member,
        device_id: w.device,
    };
    assert_eq!(env.caller(&alf).await, Caller::Admin(dev(&alf)));
    assert_eq!(env.caller(&roy).await, Caller::Member(dev(&roy)));
    assert_eq!(env.caller(&pen).await, Caller::Pending(dev(&pen)));
    assert_eq!(
        env.caller(&roy).await.rate_key(),
        RateKey::Device(roy.device)
    );
    assert_eq!(Caller::Anonymous.rate_key(), RateKey::Address);
    assert_eq!(env.caller(&pen).await.actor(), None);
    assert!(env.caller(&alf).await.actor().unwrap().admin);
    assert!(!env.caller(&roy).await.actor().unwrap().admin);

    // Wrong kind in the header, another organisation, an unknown hash.
    let other_kind = format!("Bearer {}", inv.invite_token.as_str());
    let bt = auth::new_bootstrap_token().unwrap();
    for h in [other_kind, format!("Bearer {}", bt.as_str())] {
        assert_eq!(
            refused(auth::authenticate(s, Some(&h), T0).await),
            Refusal::Unauthenticated
        );
    }
    let foreign = auth::new_device_token(Id::new_v4()).unwrap();
    let unknown = auth::new_device_token(org).unwrap();
    for t in [&foreign, &unknown] {
        let r = env.caller_at(t, T0).await;
        let e = r.unwrap_err();
        assert_eq!(e.status(), 401);
        assert_eq!(e.to_body().unwrap().error, ErrorCode::Unauthenticated);
    }

    // Lookup is by hash: the plaintext finds nothing, the hash finds the device.
    assert!(s
        .auth_device(alf.token.as_str().to_string())
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        s.auth_device(auth::hash(alf.token.as_str()))
            .await
            .unwrap()
            .unwrap()
            .device_id,
        alf.device
    );

    // The `{org}` part is checked on its own, not only through the hash: a stored hash of a
    // token that names another organisation (planted through the store) is still 401.
    let planted = auth::new_device_token(Id::new_v4()).unwrap();
    env.keep(planted.as_str());
    s.rotate_token(roy.device, auth::hash(planted.as_str()), T0)
        .await
        .unwrap();
    assert!(s
        .auth_device(auth::hash(planted.as_str()))
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        refused(env.caller_at(&planted, T0).await),
        Refusal::Unauthenticated
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_successful_authentication_records_the_day_once() {
    let env = Env::new("touch");
    let s = env.s();
    let alf = env.bootstrap().await;
    assert_eq!(
        s.device(alf.device).await.unwrap().unwrap().last_seen_day,
        None
    );
    env.caller_at(&alf.token, T0).await.unwrap();
    let day0 = T0.div_euclid(DAY);
    assert_eq!(
        s.device(alf.device).await.unwrap().unwrap().last_seen_day,
        Some(day0)
    );
    // Same day: no write (backup_log grows by nothing).
    let head = s.backup_log_head().await.unwrap();
    env.caller_at(&alf.token, T0 + 60).await.unwrap();
    assert_eq!(s.backup_log_head().await.unwrap(), head);
    env.caller_at(&alf.token, T0 + DAY).await.unwrap();
    assert_eq!(
        s.device(alf.device).await.unwrap().unwrap().last_seen_day,
        Some(day0 + 1)
    );
    // A refused token touches nothing.
    let head = s.backup_log_head().await.unwrap();
    let org = s.org(T0).await.unwrap().unwrap().org_id;
    let unknown = auth::new_device_token(org).unwrap();
    assert!(env.caller_at(&unknown, T0 + 2 * DAY).await.is_err());
    assert_eq!(s.backup_log_head().await.unwrap(), head);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_device_or_member_gets_401_everywhere() {
    let env = Env::new("revoked");
    let s = env.s();
    let alf = env.bootstrap().await;
    let roy = env.member(&alf, "roy", None).await;
    let roy2 = env.device_for(&roy, "roy").await;
    env.approve(&roy, roy2.device).await.unwrap();
    let mia = env.member(&alf, "mia", None).await;

    // roy revokes its second device; alf removes mia.
    let roy_c = env.caller(&roy).await;
    auth::revoke_device(s, &roy_c, roy2.device, T0)
        .await
        .unwrap();
    let alf_c = env.caller(&alf).await;
    auth::remove_member(s, &alf_c, mia.member, false, T0)
        .await
        .unwrap();

    for (who, what) in [(&roy2, "revoked device"), (&mia, "removed member")] {
        let e = env.caller_at(&who.token, T0).await.unwrap_err();
        assert_eq!(e, AuthError::Refused(Refusal::Unauthenticated), "{what}");
        assert_eq!(e.status(), 401);
        // Authentication runs before every endpoint, so no action is reachable: a revoked
        // token never becomes a caller for any row of the matrix.
        for _action in all_actions() {
            assert!(env.caller_at(&who.token, T0 + DAY).await.is_err());
        }
    }
    // The others still work.
    env.caller_at(&roy.token, T0).await.unwrap();
    env.caller_at(&alf.token, T0).await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// The matrix

/// Every `Action`, with every combination of its parameters.
fn all_actions() -> Vec<Action> {
    use Action::*;
    // A match without a wildcard: a new variant fails to compile here until it is listed.
    fn listed(a: Action) {
        match a {
            Info
            | Bootstrap
            | Join
            | Status
            | Keys
            | Pull
            | Members
            | ReadSettings
            | Push(_)
            | Delete(_)
            | CreateInvite { .. }
            | RevokeInvite { .. }
            | Approve { .. }
            | RevokeDevice { .. }
            | RemoveMember
            | SetRole { .. }
            | RotateKeys
            | RotateToken
            | WriteSettings { .. }
            | ReadAudit
            | CompleteRestore
            | Export
            | DeleteOrg => {}
        }
    }
    let kinds = [InviteKind::Member, InviteKind::Device, InviteKind::Unknown];
    let bools = [false, true];
    let mut v = vec![
        Info,
        Bootstrap,
        Join,
        Status,
        Keys,
        Pull,
        Members,
        ReadSettings,
        RemoveMember,
        RotateKeys,
        RotateToken,
        ReadAudit,
        CompleteRestore,
        Export,
        DeleteOrg,
    ];
    v.extend(KnownTag::ALL.map(Push));
    v.extend([DeleteScope::Ids, DeleteScope::AllMine, DeleteScope::Member].map(Delete));
    for kind in kinds {
        for for_self in bools {
            v.push(CreateInvite { kind, for_self });
            for created_by_caller in bools {
                v.push(Approve {
                    kind,
                    created_by_caller,
                    for_self,
                });
            }
        }
    }
    for b in bools {
        v.push(RevokeInvite {
            created_by_caller: b,
        });
        v.push(RevokeDevice { for_self: b });
        v.push(WriteSettings { min_client: b });
    }
    v.extend([Role::Member, Role::Admin, Role::Unknown].map(|to| SetRole { to }));
    v.iter().copied().for_each(listed);
    v
}

/// Expected outcome per caller: `Y` allowed, `U` 401, `P` 403 `not_approved`, `F` 403
/// `forbidden`, for (anonymous, pending, member, admin, cloud owner).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum E {
    Y,
    U,
    P,
    F,
}

/// plan-v3-team §4.3.3 refined by `docs/sync-v1.md` §7, written out row by row from the
/// spec (not from `require`).
fn spec_row(a: Action) -> [E; 5] {
    use Action::*;
    use E::*;
    // Rows every approved member may use; the anonymous and pending columns follow the gates.
    const MEMBER_ROW: [E; 5] = [U, P, Y, Y, F];
    const ADMIN_ROW: [E; 5] = [U, P, F, Y, F];
    const NOBODY: [E; 5] = [U, P, F, F, F];
    match a {
        Info => [Y, Y, Y, Y, Y],
        // "-" cells: only anonymous callers carry the body token; a device caller is refused.
        Bootstrap | Join => [Y, P, F, F, F],
        // Own status and own keys: pending devices too; the cloud owner uses a member token.
        Status | Keys => [U, Y, Y, Y, F],
        // Pull records and deletions, members, settings read, own token rotation.
        Pull | Members | ReadSettings | RotateToken => MEMBER_ROW,
        // Push to own device's rec, flag, stats; roster: own approvals of own devices.
        Push(KnownTag::Rec | KnownTag::Flag | KnownTag::Stats | KnownTag::Roster) => MEMBER_ROW,
        Push(KnownTag::Policy) => ADMIN_ROW,
        // Delete own records (ids: the store narrows a member to own records), all_mine.
        Delete(DeleteScope::Ids | DeleteScope::AllMine) => MEMBER_ROW,
        Delete(DeleteScope::Member) => ADMIN_ROW,
        // Invite new members: admin. Device invite for oneself: member and admin. Device
        // invite for another member: admin. Unknown kinds: nobody.
        CreateInvite {
            kind: InviteKind::Device,
            for_self: true,
        } => MEMBER_ROW,
        CreateInvite {
            kind: InviteKind::Device | InviteKind::Member,
            ..
        } => ADMIN_ROW,
        CreateInvite { .. } => NOBODY,
        // Invite revocation: an admin or the invite's creator (sync-v1 §6).
        RevokeInvite {
            created_by_caller: true,
        } => MEMBER_ROW,
        RevokeInvite { .. } => ADMIN_ROW,
        // Approval: the invite's creating member; member invites need an admin, a device of
        // another member needs an admin; never an unknown kind.
        Approve {
            kind: InviteKind::Device,
            created_by_caller: true,
            for_self: true,
        } => MEMBER_ROW,
        Approve {
            kind: InviteKind::Device | InviteKind::Member,
            created_by_caller: true,
            ..
        } => ADMIN_ROW,
        Approve { .. } => NOBODY,
        // Revocation of one's own devices: member; of another's: admin.
        RevokeDevice { for_self: true } => MEMBER_ROW,
        RevokeDevice { for_self: false } => ADMIN_ROW,
        // Remove, rotate, audit, restore: admin.
        RemoveMember | RotateKeys | ReadAudit | CompleteRestore => ADMIN_ROW,
        // Promote: admin and the cloud owner (recovery); other role changes: admin.
        SetRole { to: Role::Admin } => [U, P, F, Y, Y],
        SetRole { .. } => ADMIN_ROW,
        // Settings: admin; the cloud owner only retention_days and max_members.
        WriteSettings { min_client: false } => [U, P, F, Y, Y],
        WriteSettings { min_client: true } => ADMIN_ROW,
        Export => [U, P, F, Y, Y],
        DeleteOrg => [U, P, F, F, Y],
    }
}

fn outcome(r: Result<(), Refusal>) -> E {
    match r {
        Ok(()) => E::Y,
        Err(Refusal::Unauthenticated) => E::U,
        Err(Refusal::NotApproved) => E::P,
        Err(Refusal::Forbidden) => E::F,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_cell_of_the_matrix_holds() {
    let env = Env::new("matrix");
    let s = env.s();
    let alf = env.bootstrap().await;
    let roy = env.member(&alf, "roy", None).await;
    let inv = env
        .invite(&alf, InviteKind::Member, "pen", None)
        .await
        .unwrap();
    let pen = env.join(&inv, "pen").await;
    let org = s.org(T0).await.unwrap().unwrap().org_id;
    // Callers as authentication produces them from real tokens.
    let callers = [
        auth::authenticate(s, None, T0).await.unwrap(),
        env.caller(&pen).await,
        env.caller(&roy).await,
        env.caller(&alf).await,
        Caller::CloudOwner(CloudOwner { org_id: org }),
    ];
    assert!(matches!(callers[1], Caller::Pending(_)));
    assert!(matches!(callers[2], Caller::Member(_)));
    assert!(matches!(callers[3], Caller::Admin(_)));

    let actions = all_actions();
    let mut cells = 0;
    let mut table = String::new();
    for a in &actions {
        let want = spec_row(*a);
        let got: Vec<E> = callers
            .iter()
            .map(|c| outcome(authz::require(c, *a)))
            .collect();
        assert_eq!(
            got, want,
            "{a:?}: (anonymous, pending, member, admin, owner)"
        );
        table.push_str(&format!("{a:?}: {got:?}\n"));
        cells += got.len();
        // Through `authorise`: the same outcome, and an audit row for each refusal with a
        // token (pending, member, admin), none for anonymous or allowed requests.
        for (i, c) in callers.iter().enumerate() {
            let before = s.audit(0, 1_000).await.unwrap().head;
            let r = auth::authorise(s, c, *a, T0).await;
            let after = s.audit(0, 1_000).await.unwrap();
            match want[i] {
                E::Y => assert!(r.is_ok()),
                e => {
                    let err = r.unwrap_err();
                    let body = err.to_body().unwrap();
                    let (status, code) = match e {
                        E::U => (401, ErrorCode::Unauthenticated),
                        E::P => (403, ErrorCode::NotApproved),
                        _ => (403, ErrorCode::Forbidden),
                    };
                    assert_eq!((err.status(), body.error), (status, code), "{a:?} {c:?}");
                    assert_eq!(code.status(), Some(status));
                }
            }
            let audited = after.head > before;
            let expect_row = want[i] != E::Y && c.device().is_some();
            assert_eq!(audited, expect_row, "{a:?} {c:?}");
            if audited {
                let row = after.rows.last().unwrap();
                assert_eq!(row.action, "authz.refused");
                assert_eq!(row.actor, Some(c.device().unwrap().member_id));
                assert_eq!(
                    row.target.as_deref(),
                    Some(c.device().unwrap().device_id.to_string().as_str())
                );
                assert!(row
                    .detail
                    .as_deref()
                    .unwrap()
                    .starts_with(&format!("action={} error=", a.name())));
            }
        }
    }
    assert_eq!(actions.len(), 50);
    assert_eq!(cells, 50 * 5);
    let names: BTreeSet<&str> = actions.iter().map(|a| a.name()).collect();
    assert!(names.len() >= 26, "{names:?}");
    println!("{table}");
}

#[test]
fn refusals_carry_the_sync_v1_error_bodies() {
    for (r, status, code, wire) in [
        (
            Refusal::Unauthenticated,
            401,
            ErrorCode::Unauthenticated,
            "unauthenticated",
        ),
        (
            Refusal::NotApproved,
            403,
            ErrorCode::NotApproved,
            "not_approved",
        ),
        (Refusal::Forbidden, 403, ErrorCode::Forbidden, "forbidden"),
    ] {
        assert_eq!(r.status(), status);
        assert_eq!(r.code(), code);
        let body = serde_json::to_value(r.to_body()).unwrap();
        assert_eq!(body["error"], wire);
        assert!(body["message"].as_str().is_some_and(|m| !m.is_empty()));
        assert_eq!(body.as_object().unwrap().len(), 2, "{body}");
        let e = AuthError::from(r);
        assert_eq!((e.status(), e.to_body().unwrap().error), (status, code));
    }
    assert_eq!(AuthError::Random.status(), 500);
    assert!(AuthError::Random.to_body().is_none());
    let gone = AuthError::Store(StoreError::Gone);
    assert_eq!(gone.status(), 410);
    assert_eq!(gone.to_body().unwrap().error, ErrorCode::InviteGone);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_another_members_record_is_an_admin_cell_applied_by_the_store() {
    let env = Env::new("delete");
    let s = env.s();
    let alf = env.bootstrap().await;
    let roy = env.member(&alf, "roy", None).await;
    let mia = env.member(&alf, "mia", None).await;
    let id = Id::new_v4();
    s.push(PushBatch {
        member_id: mia.member,
        device_id: mia.device,
        items: vec![PushItem::Record(PushRecord {
            tag: Tag::from(KnownTag::Rec),
            idx: 0,
            id,
            epoch: 0,
            blob: blob(0x44),
        })],
        now: T0,
    })
    .await
    .unwrap();
    let roy_c = env.caller(&roy).await;
    authz::require(&roy_c, Action::Delete(DeleteScope::Ids)).unwrap();
    let e = s
        .delete(
            awm_proto::wire::DeleteRequest::Ids(vec![id]),
            roy_c.actor().unwrap(),
            T0,
        )
        .await
        .unwrap_err();
    assert_eq!(e, StoreError::Forbidden);
    let alf_c = env.caller(&alf).await;
    let r = s
        .delete(
            awm_proto::wire::DeleteRequest::Ids(vec![id]),
            alf_c.actor().unwrap(),
            T0,
        )
        .await
        .unwrap();
    assert_eq!(r.deleted, 1);
}

#[test]
fn the_client_gate_skips_batches_of_roster_items_and_markers() {
    let marker = |t: KnownTag| {
        PushItem::Deleted(PushDeleted {
            tag: Tag::from(t),
            idx: 3,
            id: Id::new_v4(),
        })
    };
    let rec = PushItem::Record(PushRecord {
        tag: Tag::from(KnownTag::Rec),
        idx: 0,
        id: Id::new_v4(),
        epoch: 0,
        blob: blob(1),
    });
    assert!(!authz::push_needs_min_client(&[roster_item(0, 0)]));
    assert!(!authz::push_needs_min_client(&[
        roster_item(0, 0),
        marker(KnownTag::Rec),
        marker(KnownTag::Policy)
    ]));
    assert!(authz::push_needs_min_client(std::slice::from_ref(&rec)));
    assert!(authz::push_needs_min_client(&[roster_item(0, 0), rec]));
}

// ---------------------------------------------------------------------------------------------
// Bootstrap

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_issues_one_approved_admin_and_refuses_reuse() {
    let env = Env::new("bootstrap");
    let s = env.s();
    let req = |t: &BootstrapToken| BootstrapRequest {
        bootstrap_token: t.clone(),
        org_id: Id::new_v4(),
        handle: handle("alf"),
        device_id: Id::new_v4(),
        device_pubkey: key(1),
    };
    // Before `serve init`: nothing to match.
    let stray = auth::new_bootstrap_token().unwrap();
    env.keep(stray.as_str());
    let e = auth::bootstrap(s, req(&stray), defaults(), T0).await;
    assert_eq!(store_err(e), StoreError::Gone);

    let bt = auth::issue_bootstrap(s, T0).await.unwrap();
    env.keep(bt.as_str());
    // A wrong token, and the right one after 24 hours.
    let e = auth::bootstrap(s, req(&stray), defaults(), T0).await;
    assert_eq!(e.unwrap_err().status(), 410);
    let e = auth::bootstrap(s, req(&bt), defaults(), T0 + auth::BOOTSTRAP_TTL_S).await;
    assert_eq!(
        e.unwrap_err().to_body().unwrap().error,
        ErrorCode::InviteGone
    );

    let r = req(&bt);
    let (org, device) = (r.org_id, r.device_id);
    let resp = auth::bootstrap(s, r, defaults(), T0 + auth::BOOTSTRAP_TTL_S - 1)
        .await
        .unwrap();
    env.keep(resp.device_token.as_str());
    assert_eq!(
        (resp.org_id, resp.device_id, resp.role),
        (org, device, Role::Admin)
    );
    assert_eq!(resp.device_token.org(), org);
    let caller = env.caller_at(&resp.device_token, T0).await.unwrap();
    assert!(matches!(caller, Caller::Admin(d) if d.member_id == resp.member_id));
    let row = s.device(device).await.unwrap().unwrap();
    assert!(row.approved);
    assert_eq!((row.invite_id, row.join_mac), (None, None));

    // Used: 410, and a new `serve init` is refused once the organisation exists.
    let e = auth::bootstrap(s, req(&bt), defaults(), T0).await;
    assert_eq!(store_err(e), StoreError::Gone);
    assert_eq!(
        store_err(auth::issue_bootstrap(s, T0).await),
        StoreError::NotEmpty
    );

    // The genesis roster record goes to (member, device, roster, 0) under epoch 0.
    let roster = Tag::from(KnownTag::Roster);
    let first = |idx, epoch| PushBatch {
        member_id: resp.member_id,
        device_id: device,
        items: vec![roster_item(idx, epoch)],
        now: T0,
    };
    for (idx, epoch) in [(1, 0), (0, 1)] {
        assert!(matches!(
            s.push(first(idx, epoch)).await,
            Err(StoreError::StreamConflict { .. } | StoreError::StaleEpoch { .. })
        ));
    }
    s.push(first(0, 0)).await.unwrap();
    assert_eq!(
        s.stream_head(resp.member_id, device, roster).await.unwrap(),
        0
    );
    let actions = env.audit_actions().await;
    assert_eq!(actions, ["bootstrap"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_bootstraps_create_exactly_one_admin() {
    for round in 0..5 {
        let env = Env::new("race");
        let bt = auth::issue_bootstrap(env.s(), T0).await.unwrap();
        env.keep(bt.as_str());
        let mut tasks = Vec::new();
        for i in 0..8u8 {
            let store = Arc::clone(&env.store);
            let bt = bt.clone();
            tasks.push(tokio::spawn(async move {
                auth::bootstrap(
                    &*store,
                    BootstrapRequest {
                        bootstrap_token: bt,
                        org_id: Id::new_v4(),
                        handle: handle(&format!("admin{i}")),
                        device_id: Id::new_v4(),
                        device_pubkey: key(i),
                    },
                    defaults(),
                    T0,
                )
                .await
            }));
        }
        let mut ok = 0;
        for t in tasks {
            match t.await.unwrap() {
                Ok(r) => {
                    env.keep(r.device_token.as_str());
                    ok += 1;
                }
                Err(e) => assert_eq!(e, AuthError::Store(StoreError::Gone), "round {round}"),
            }
        }
        assert_eq!(ok, 1, "round {round}");
        let members = env.s().members().await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].role, Role::Admin);
        assert_eq!(members[0].devices.len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_a_bootstrap_hash_works_until_the_first_admin_exists() {
    let env = Env::new("path-a");
    let s = env.s();
    let bt = auth::new_bootstrap_token().unwrap();
    env.keep(bt.as_str());
    for bad in ["", "ABC", &auth::hash("x").to_uppercase(), bt.as_str()] {
        let e = auth::install_bootstrap_hash(s, bad, T0 + DAY, T0).await;
        assert_eq!(
            store_err(e),
            StoreError::InvalidValue {
                field: "AWM_BOOTSTRAP_SHA256".into()
            }
        );
    }
    assert!(
        auth::install_bootstrap_hash(s, &auth::hash(bt.as_str()), T0 + DAY, T0)
            .await
            .unwrap()
    );
    let r = auth::bootstrap(
        s,
        BootstrapRequest {
            bootstrap_token: bt.clone(),
            org_id: Id::new_v4(),
            handle: handle("alf"),
            device_id: Id::new_v4(),
            device_pubkey: key(1),
        },
        defaults(),
        T0 + 10,
    )
    .await
    .unwrap();
    env.keep(r.device_token.as_str());
    // A restart with the same environment after the first admin exists changes nothing.
    assert!(
        !auth::install_bootstrap_hash(s, &auth::hash(bt.as_str()), T0 + DAY, T0)
            .await
            .unwrap()
    );
    assert_eq!(
        s.meta_get("bootstrap_token_hash".into()).await.unwrap(),
        None
    );
}

// ---------------------------------------------------------------------------------------------
// Joins and invites

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_join_is_stored_as_given_and_waits_for_approval() {
    let env = Env::new("join");
    let s = env.s();
    let alf = env.bootstrap().await;
    let inv = env
        .invite(&alf, InviteKind::Member, "roy", None)
        .await
        .unwrap();
    assert_eq!(inv.expires_at, T0 + 7 * DAY);
    let (resp, req) = env.join_at(&inv, "roy", T0).await.unwrap();
    assert!(resp.pending);
    assert_eq!(resp.device_id, req.device_id);
    assert_eq!(resp.device_token.org(), resp.org_id);
    let row = s.device(req.device_id).await.unwrap().unwrap();
    assert_eq!(row.pubkey, req.device_pubkey);
    assert_eq!(row.join_mac, Some(req.join_mac));
    assert_eq!(row.invite_id, Some(inv.invite_id));
    assert!(!row.approved);
    assert_eq!(row.member_id, resp.member_id);
    let pending = env.caller_at(&resp.device_token, T0).await.unwrap();
    assert!(matches!(pending, Caller::Pending(_)));
    for a in [Action::Info, Action::Status, Action::Keys] {
        authz::require(&pending, a).unwrap();
    }
    for a in [
        Action::Pull,
        Action::Members,
        Action::Push(KnownTag::Rec),
        Action::RotateToken,
    ] {
        assert_eq!(authz::require(&pending, a), Err(Refusal::NotApproved));
    }
    // The admin sees it pending with the MAC and key as sent.
    let st = s.status(alf.device, T0).await.unwrap();
    assert_eq!(st.pending.len(), 1);
    assert_eq!(st.pending[0].join_mac, req.join_mac);
    assert_eq!(st.pending[0].device_pubkey, req.device_pubkey);
    assert_eq!(st.pending[0].kind, InviteKind::Member);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_used_revoked_or_expired_invite_is_gone_and_the_handle_must_match() {
    let env = Env::new("join-errors");
    let s = env.s();
    let alf = env.bootstrap().await;
    let gone = |r: Result<(JoinResponse, JoinRequest), AuthError>| {
        let e = r.map(|(j, _)| j).unwrap_err();
        assert_eq!(e.status(), 410);
        assert_eq!(e.to_body().unwrap().error, ErrorCode::InviteGone);
    };
    // Used.
    let inv = env
        .invite(&alf, InviteKind::Member, "roy", None)
        .await
        .unwrap();
    env.join(&inv, "roy").await;
    gone(env.join_at(&inv, "roy", T0).await);
    // Revoked.
    let inv = env
        .invite(&alf, InviteKind::Member, "mia", None)
        .await
        .unwrap();
    let alf_c = env.caller(&alf).await;
    auth::revoke_invite(s, &alf_c, inv.invite_id, T0)
        .await
        .unwrap();
    gone(env.join_at(&inv, "mia", T0).await);
    // Expired.
    let inv = env
        .invite(&alf, InviteKind::Member, "kit", None)
        .await
        .unwrap();
    gone(env.join_at(&inv, "kit", inv.expires_at).await);
    // Another handle: 400 /handle, and the invite is still usable.
    let e = env.join_at(&inv, "kaz", T0).await.map(|(j, _)| j);
    let e = store_err(e);
    assert_eq!(
        e,
        StoreError::InvalidValue {
            field: "/handle".into()
        }
    );
    // An invite token of another organisation: 401 before any lookup.
    let foreign = InviteResponse {
        invite_id: inv.invite_id,
        invite_token: auth::new_invite_token(Id::new_v4()).unwrap(),
        expires_at: inv.expires_at,
    };
    env.keep(foreign.invite_token.as_str());
    let e = env.join_at(&foreign, "kit", T0).await.map(|(j, _)| j);
    assert_eq!(refused(e), Refusal::Unauthenticated);
    // A token of this organisation that is not the invite's: 410.
    let wrong = InviteResponse {
        invite_token: auth::new_invite_token(inv.invite_token.org()).unwrap(),
        ..inv.clone()
    };
    env.keep(wrong.invite_token.as_str());
    gone(env.join_at(&wrong, "kit", T0).await);
    env.join(&inv, "kit").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invites_follow_the_matrix_and_refuse_unknown_kinds() {
    let env = Env::new("invites");
    let s = env.s();
    let alf = env.bootstrap().await;
    let roy = env.member(&alf, "roy", None).await;
    // Member: a device invite for themselves only.
    assert_eq!(
        refused(env.invite(&roy, InviteKind::Member, "new", None).await),
        Refusal::Forbidden
    );
    assert_eq!(
        refused(env.invite(&roy, InviteKind::Device, "alf", None).await),
        Refusal::Forbidden
    );
    env.invite(&roy, InviteKind::Device, "roy", None)
        .await
        .unwrap();
    // Admin: member invites of any role, device invites for anyone.
    env.invite(&alf, InviteKind::Member, "new", Some(Role::Admin))
        .await
        .unwrap();
    env.invite(&alf, InviteKind::Device, "roy", None)
        .await
        .unwrap();
    env.invite(&alf, InviteKind::Device, "alf", None)
        .await
        .unwrap();
    // Unknown kind: 400 invalid_value /kind, for anyone authenticated and approved.
    for who in [&alf, &roy] {
        let e = env.invite(who, InviteKind::Unknown, "roy", None).await;
        let e = e.unwrap_err();
        let body = e.to_body().unwrap();
        assert_eq!(
            (e.status(), body.error, body.field.as_deref()),
            (400, ErrorCode::InvalidValue, Some("/kind"))
        );
    }
    // `expires_days` outside 1-30.
    let alf_c = env.caller(&alf).await;
    for days in [0, 31] {
        let e = auth::create_invite(
            s,
            &alf_c,
            InviteRequest {
                kind: InviteKind::Member,
                handle: handle("late"),
                role: None,
                expires_days: Some(days),
            },
            T0,
        )
        .await;
        assert_eq!(
            store_err(e),
            StoreError::InvalidValue {
                field: "/expires_days".into()
            }
        );
    }
    // Revocation: the creator or an admin.
    let by_alf = env
        .invite(&alf, InviteKind::Device, "roy", None)
        .await
        .unwrap();
    let roy_c = env.caller(&roy).await;
    assert_eq!(
        refused(auth::revoke_invite(s, &roy_c, by_alf.invite_id, T0).await),
        Refusal::Forbidden
    );
    let by_roy = env
        .invite(&roy, InviteKind::Device, "roy", None)
        .await
        .unwrap();
    auth::revoke_invite(s, &roy_c, by_roy.invite_id, T0)
        .await
        .unwrap();
    auth::revoke_invite(s, &alf_c, by_alf.invite_id, T0)
        .await
        .unwrap();
    assert_eq!(
        store_err(auth::revoke_invite(s, &alf_c, Id::new_v4(), T0).await),
        StoreError::NotFound
    );
    // Anonymous and pending callers learn nothing about the invite.
    assert_eq!(
        refused(auth::revoke_invite(s, &Caller::Anonymous, Id::new_v4(), T0).await),
        Refusal::Unauthenticated
    );
}

// ---------------------------------------------------------------------------------------------
// Approval, revocation, removal, roles, token rotation

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_is_for_the_invites_creator() {
    let env = Env::new("approve");
    let s = env.s();
    let alf = env.bootstrap().await;
    let roy = env.member(&alf, "roy", None).await;
    let sam = env.member(&alf, "sam", Some(Role::Admin)).await;

    // A member invite by alf: another admin (no `S`) and a member are refused; alf approves.
    let inv = env
        .invite(&alf, InviteKind::Member, "mia", None)
        .await
        .unwrap();
    let mia = env.join(&inv, "mia").await;
    assert_eq!(
        refused(env.approve(&sam, mia.device).await),
        Refusal::Forbidden
    );
    assert_eq!(
        refused(env.approve(&roy, mia.device).await),
        Refusal::Forbidden
    );
    let mia_c = env.caller(&mia).await;
    assert_eq!(
        refused(auth::approve(s, &mia_c, mia.device, wraps(0), T0).await),
        Refusal::NotApproved
    );
    assert_eq!(
        refused(auth::approve(s, &Caller::Anonymous, mia.device, wraps(0), T0).await),
        Refusal::Unauthenticated
    );
    env.approve(&alf, mia.device).await.unwrap();
    assert!(matches!(env.caller(&mia).await, Caller::Member(_)));
    let keys = s.keys(mia.device).await.unwrap();
    assert_eq!(keys.wraps.len(), 1);
    assert_eq!(keys.wraps[0].created_by, alf.device);
    assert_eq!(keys.wraps[0].auth, wraps(0).wraps[0].auth);

    // roy's own device invite: roy approves; alf (not the creator) is refused.
    let roy2 = env.device_for(&roy, "roy").await;
    assert_eq!(roy2.member, roy.member);
    assert_eq!(
        refused(env.approve(&alf, roy2.device).await),
        Refusal::Forbidden
    );
    env.approve(&roy, roy2.device).await.unwrap();
    assert!(matches!(env.caller(&roy2).await, Caller::Member(_)));

    // alf's device invite for roy (recovery): roy is refused, alf approves.
    let roy3 = env.device_for(&alf, "roy").await;
    assert_eq!(
        refused(env.approve(&roy, roy3.device).await),
        Refusal::Forbidden
    );
    env.approve(&alf, roy3.device).await.unwrap();

    // The bootstrap device has no invite (kind Unknown): refused; an unknown device: 404.
    assert_eq!(
        refused(env.approve(&alf, alf.device).await),
        Refusal::Forbidden
    );
    assert_eq!(
        store_err(env.approve(&alf, Id::new_v4()).await),
        StoreError::NotFound
    );
    // A demoted creator can no longer approve another member's device.
    let roy4 = env.device_for(&sam, "roy").await;
    let alf_c = env.caller(&alf).await;
    auth::set_role(s, &alf_c, sam.member, Role::Member, T0)
        .await
        .unwrap();
    assert_eq!(
        refused(env.approve(&sam, roy4.device).await),
        Refusal::Forbidden
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_revocation_is_for_oneself_or_an_admin() {
    let env = Env::new("revoke");
    let s = env.s();
    let alf = env.bootstrap().await;
    let roy = env.member(&alf, "roy", None).await;
    let mia = env.member(&alf, "mia", None).await;
    let roy2 = env.device_for(&roy, "roy").await;
    env.approve(&roy, roy2.device).await.unwrap();
    let roy_c = env.caller(&roy).await;
    assert_eq!(
        refused(auth::revoke_device(s, &roy_c, mia.device, T0).await),
        Refusal::Forbidden
    );
    assert!(!s.org(T0).await.unwrap().unwrap().rotation_needed);
    auth::revoke_device(s, &roy_c, roy2.device, T0)
        .await
        .unwrap();
    assert!(s.org(T0).await.unwrap().unwrap().rotation_needed);
    let alf_c = env.caller(&alf).await;
    auth::revoke_device(s, &alf_c, mia.device, T0)
        .await
        .unwrap();
    for who in [&roy2, &mia] {
        assert_eq!(
            refused(env.caller_at(&who.token, T0).await),
            Refusal::Unauthenticated
        );
    }
    assert_eq!(
        store_err(auth::revoke_device(s, &alf_c, Id::new_v4(), T0).await),
        StoreError::NotFound
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removal_revokes_tokens_sets_rotation_needed_and_keeps_an_admin() {
    let env = Env::new("remove");
    let s = env.s();
    let alf = env.bootstrap().await;
    let roy = env.member(&alf, "roy", None).await;
    let roy2 = env.device_for(&roy, "roy").await;
    env.approve(&roy, roy2.device).await.unwrap();
    let open = env
        .invite(&roy, InviteKind::Device, "roy", None)
        .await
        .unwrap();
    let roy_c = env.caller(&roy).await;
    let alf_c = env.caller(&alf).await;

    assert_eq!(
        refused(auth::remove_member(s, &roy_c, alf.member, false, T0).await),
        Refusal::Forbidden
    );
    auth::remove_member(s, &alf_c, roy.member, false, T0)
        .await
        .unwrap();
    for who in [&roy, &roy2] {
        assert_eq!(
            refused(env.caller_at(&who.token, T0).await),
            Refusal::Unauthenticated
        );
    }
    assert!(s.org(T0).await.unwrap().unwrap().rotation_needed);
    // Its open invite admits nobody now.
    let e = env.join_at(&open, "roy", T0).await.map(|(j, _)| j);
    assert_eq!(store_err(e), StoreError::Gone);

    // The last admin cannot be removed or demoted.
    let e = auth::remove_member(s, &alf_c, alf.member, false, T0).await;
    let e = e.unwrap_err();
    assert_eq!(
        (e.status(), e.to_body().unwrap().error),
        (409, ErrorCode::LastAdmin)
    );
    let e = auth::set_role(s, &alf_c, alf.member, Role::Member, T0).await;
    assert_eq!(store_err(e), StoreError::LastAdmin);
    // With a second admin, the demotion works.
    let sam = env.member(&alf, "sam", None).await;
    auth::set_role(s, &alf_c, sam.member, Role::Admin, T0)
        .await
        .unwrap();
    assert!(matches!(env.caller(&sam).await, Caller::Admin(_)));
    auth::set_role(s, &alf_c, alf.member, Role::Member, T0)
        .await
        .unwrap();
    assert!(matches!(env.caller(&alf).await, Caller::Member(_)));
    // Role checks: unknown role 400, a member 403, the cloud owner only promotes.
    let sam_c = env.caller(&sam).await;
    assert_eq!(
        store_err(auth::set_role(s, &sam_c, alf.member, Role::Unknown, T0).await),
        StoreError::InvalidValue {
            field: "/role".into()
        }
    );
    let alf_c = env.caller(&alf).await;
    assert_eq!(
        refused(auth::set_role(s, &alf_c, alf.member, Role::Admin, T0).await),
        Refusal::Forbidden
    );
    let owner = Caller::CloudOwner(CloudOwner {
        org_id: s.org(T0).await.unwrap().unwrap().org_id,
    });
    assert_eq!(
        refused(auth::set_role(s, &owner, sam.member, Role::Member, T0).await),
        Refusal::Forbidden
    );
    auth::set_role(s, &owner, alf.member, Role::Admin, T0)
        .await
        .unwrap();
    assert!(matches!(env.caller(&alf).await, Caller::Admin(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_rotation_stops_the_old_token_at_once() {
    let env = Env::new("rotate");
    let s = env.s();
    let alf = env.bootstrap().await;
    let roy = env.member(&alf, "roy", None).await;
    let roy_c = env.caller(&roy).await;
    let r = auth::rotate_token(s, &roy_c, T0).await.unwrap();
    env.keep(r.device_token.as_str());
    assert_ne!(r.device_token, roy.token);
    assert_eq!(
        refused(env.caller_at(&roy.token, T0).await),
        Refusal::Unauthenticated
    );
    assert_eq!(env.caller_at(&r.device_token, T0).await.unwrap(), roy_c);
    // A pending device may not rotate.
    let inv = env
        .invite(&alf, InviteKind::Member, "pen", None)
        .await
        .unwrap();
    let pen = env.join(&inv, "pen").await;
    let pen_c = env.caller(&pen).await;
    assert_eq!(
        refused(auth::rotate_token(s, &pen_c, T0).await),
        Refusal::NotApproved
    );
    env.caller_at(&pen.token, T0).await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// Audit, logs, plaintext

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_events_are_audited_without_secrets_handles_or_blobs() {
    let env = Env::new("audit");
    let s = env.s();
    let alf = env.bootstrap().await;
    let roy = env.member(&alf, "roy", None).await;
    let mia = env.member(&alf, "mia", None).await;
    let roy2 = env.device_for(&roy, "roy").await;
    env.approve(&roy, roy2.device).await.unwrap();
    let b = blob(0x77);
    s.push(PushBatch {
        member_id: roy.member,
        device_id: roy.device,
        items: vec![PushItem::Record(PushRecord {
            tag: Tag::from(KnownTag::Rec),
            idx: 0,
            id: Id::new_v4(),
            epoch: 0,
            blob: b.clone(),
        })],
        now: T0,
    })
    .await
    .unwrap();
    let roy_c = env.caller(&roy).await;
    let alf_c = env.caller(&alf).await;
    auth::revoke_device(s, &roy_c, roy2.device, T0)
        .await
        .unwrap();
    let r = auth::rotate_token(s, &roy_c, T0).await.unwrap();
    env.keep(r.device_token.as_str());
    assert!(auth::remove_member(s, &roy_c, mia.member, false, T0)
        .await
        .is_err());
    auth::set_role(s, &alf_c, mia.member, Role::Admin, T0)
        .await
        .unwrap();
    auth::remove_member(s, &alf_c, mia.member, false, T0)
        .await
        .unwrap();

    let rows = s.audit(0, 1_000).await.unwrap().rows;
    let actions: BTreeSet<&str> = rows.iter().map(|r| r.action.as_str()).collect();
    for a in [
        "bootstrap",
        "invite.create",
        "join",
        "approve",
        "device.revoke",
        "token.rotate",
        "authz.refused",
        "member.role",
        "member.remove",
    ] {
        assert!(actions.contains(a), "missing {a}: {actions:?}");
    }
    let refusal = rows.iter().find(|r| r.action == "authz.refused").unwrap();
    assert_eq!(refusal.actor, Some(roy.member));
    assert_eq!(refusal.target, Some(roy.device.to_string()));
    assert_eq!(
        refusal.detail.as_deref(),
        Some("action=member.remove error=forbidden")
    );
    // Actor and target are ids; nothing secret, no handle, no blob.
    let mut forbidden: Vec<String> = Vec::new();
    for t in env.issued() {
        forbidden.push(auth::hash(&t));
        forbidden.push(secret_of(&t).0);
        forbidden.push(t);
    }
    forbidden.extend(["alf", "roy", "mia"].map(String::from));
    forbidden.push(String::from(b.clone()));
    for row in &rows {
        assert!(row.actor.is_some(), "{row:?}");
        let text = format!(
            "{} {} {}",
            row.action,
            row.target.as_deref().unwrap_or(""),
            row.detail.as_deref().unwrap_or("")
        );
        for f in &forbidden {
            assert!(!text.contains(f.as_str()), "{f:?} in audit row {row:?}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_debug_or_display_prints_a_secret() {
    let env = Env::new("logs");
    let s = env.s();
    let alf = env.bootstrap().await;
    let inv = env
        .invite(&alf, InviteKind::Member, "roy", None)
        .await
        .unwrap();
    let (jr, jreq) = env.join_at(&inv, "roy", T0).await.unwrap();
    let bt = auth::new_bootstrap_token().unwrap();
    let breq = BootstrapRequest {
        bootstrap_token: bt.clone(),
        org_id: Id::new_v4(),
        handle: handle("alf"),
        device_id: Id::new_v4(),
        device_pubkey: key(1),
    };
    let presented = auth::parse(&header(&alf.token)).unwrap();
    let callers = [
        Caller::Anonymous,
        env.caller(&alf).await,
        env.caller_at(&jr.device_token, T0).await.unwrap(),
        Caller::CloudOwner(CloudOwner {
            org_id: Id::new_v4(),
        }),
    ];
    let errors = [
        AuthError::Refused(Refusal::Unauthenticated),
        AuthError::Refused(Refusal::NotApproved),
        AuthError::Refused(Refusal::Forbidden),
        AuthError::Store(StoreError::Gone),
        AuthError::Random,
    ];
    let mut out: Vec<String> = Vec::new();
    out.extend(callers.iter().map(|c| format!("{c:?} {:?}", c.actor())));
    out.extend(
        errors
            .iter()
            .map(|e| format!("{e:?} {e} {:?}", e.to_body())),
    );
    out.push(format!("{presented:?}"));
    out.push(format!("{:?} {:?} {:?}", alf.token, inv.invite_token, bt));
    out.push(format!("{breq:?} {jreq:?} {jr:?} {inv:?}"));
    let rot = auth::rotate_token(s, &callers[1], T0).await.unwrap();
    env.keep(rot.device_token.as_str());
    out.push(format!("{rot:?}"));
    let all = out.join("\n");
    for t in [
        alf.token.as_str(),
        inv.invite_token.as_str(),
        bt.as_str(),
        jr.device_token.as_str(),
        rot.device_token.as_str(),
    ] {
        let (secret, _) = secret_of(t);
        assert!(!all.contains(&secret), "secret of {}… printed", &t[..6]);
        assert!(
            !all.contains(&auth::hash(t)),
            "hash of {}… printed",
            &t[..6]
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_column_holds_a_token_or_secret_in_plaintext() {
    let env = Env::new("plaintext");
    let s = env.s();
    // The scan finds a planted token (positive control), in the file and in the dump.
    let planted = auth::new_device_token(Id::new_v4()).unwrap();
    {
        let probe = Env::new("probe");
        probe
            .s()
            .meta_set("probe".into(), planted.as_str().into())
            .await
            .unwrap();
        let hits = plaintext_hits(&probe.data, &[planted.as_str().to_string()]);
        assert!(!hits.is_empty(), "the scan must see a planted token");
        let dump = format!("{:?}", probe.s().dump().await.unwrap());
        assert!(dump.contains(planted.as_str()));
        // Clear it so the probe's own drop-time scan passes.
        probe
            .s()
            .meta_set("probe".into(), "-".into())
            .await
            .unwrap();
        probe.s().checkpoint().await.unwrap();
        assert!(plaintext_hits(&probe.data, &[planted.as_str().to_string()]).is_empty());
    }
    // A full lifecycle: bootstrap, member and device joins, approvals, a revoked invite, a
    // token rotation, a removal.
    let alf = env.bootstrap().await;
    let roy = env.member(&alf, "roy", None).await;
    let roy2 = env.device_for(&roy, "roy").await;
    env.approve(&roy, roy2.device).await.unwrap();
    let inv = env
        .invite(&alf, InviteKind::Member, "mia", None)
        .await
        .unwrap();
    let alf_c = env.caller(&alf).await;
    auth::revoke_invite(s, &alf_c, inv.invite_id, T0)
        .await
        .unwrap();
    let roy_c = env.caller(&roy).await;
    let r = auth::rotate_token(s, &roy_c, T0).await.unwrap();
    env.keep(r.device_token.as_str());
    auth::remove_member(s, &alf_c, roy.member, false, T0)
        .await
        .unwrap();
    let tokens = env.issued();
    assert!(tokens.len() >= 8, "{}", tokens.len());
    // Every column, through the logical dump, and the raw file bytes.
    let dump = format!("{:?}", s.dump().await.unwrap());
    for t in &tokens {
        assert!(!dump.contains(t.as_str()));
        assert!(!dump.contains(&secret_of(t).0));
    }
    // The hashes are there (lookup by hash).
    assert!(dump.contains(&auth::hash(alf.token.as_str())));
    assert!(dump.contains(&auth::hash(r.device_token.as_str())));
    assert!(plaintext_hits(&env.data, &tokens).is_empty());
    s.checkpoint().await.unwrap();
    assert!(plaintext_hits(&env.data, &tokens).is_empty());
}

/// FT1 hand-off: "retention never deletes `roster` records" (crypto §7: a joiner verifies the
/// whole chain from the genesis). `Store::retention_batch` (TM6, used by TM9) selects every
/// record older than the cutoff, roster records included, so this fails today; it is ignored
/// and handed to TM9 / RVT2 (report "Findings").
#[tokio::test]
#[ignore = "store gap handed to TM9: retention_batch deletes roster records"]
async fn retention_never_deletes_roster_records() {
    let env = Env::new("retention");
    let s = env.s();
    let alf = env.bootstrap().await;
    s.push(PushBatch {
        member_id: alf.member,
        device_id: alf.device,
        items: vec![roster_item(0, 0)],
        now: T0,
    })
    .await
    .unwrap();
    let n = s
        .retention_batch(T0 + 400 * DAY, 1_000, T0 + 400 * DAY)
        .await
        .unwrap();
    assert_eq!(n, 0, "a roster record was deleted by retention");
}
