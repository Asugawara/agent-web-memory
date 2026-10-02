//! Key flows (plan-v3-team §5.1, TM3): invites and the join MAC, approval wraps, the
//! roster (RV8-team X1), rotation, removal, recovery (M6) and the P1-P5 outcomes.
//!
//! Set `AWM_WRITE_VECTORS=1` to rewrite `tests/vectors/v1/keys.json` after an intended
//! format change. Nothing has shipped yet (FT1 regenerated them for RVT1 B1); from the first
//! release on there must be none within v1.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use awm_proto::crypto::{open_record, seal_record, Error, RecordAd, Rng, Secret32};
use awm_proto::keys::{
    accept_join, approve, approve_with, fingerprint, org_id, plan_rotation, rotate, rotate_with,
    seal_roster, seal_roster_with, ApprovalInfo, ApprovalKind, DeviceKeys, DeviceStatus, EpochKey,
    Invite, JoinRequest, KeyRing, ListedDevice, Role, Roster, RosterBlob, RosterEntry, RosterSlot,
    Wrap, ORG_NONCE_LEN, ROSTER_TAG,
};
use serde_json::{json, Value};
use uuid::Uuid;

// ---------------------------------------------------------------------------------------
// Test helpers

/// Hands out exactly the bytes it was given; a test-only stand-in for the system source.
struct FixedRng(Vec<u8>);

impl Rng for FixedRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if self.0.len() < out.len() {
            return Err(Error::Rng);
        }
        let rest = self.0.split_off(out.len());
        out.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

fn bytes(seed: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn check_vector(name: &str, computed: &Value) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/v1")
        .join(name);
    if std::env::var("AWM_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(computed).unwrap() + "\n",
        )
        .unwrap();
    }
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(&stored, computed, "vector {name} changed");
    stored
}

/// One device: its member, id, key pair and key ring.
struct Dev {
    member: Uuid,
    device: Uuid,
    keys: DeviceKeys,
    ring: KeyRing,
}

impl Dev {
    fn listed(&self) -> ListedDevice {
        ListedDevice {
            member_id: self.member,
            device_id: self.device,
            public_key: self.keys.public,
        }
    }

    fn accept_rotation(&mut self, wraps: &[Wrap]) -> Result<u32, Error> {
        let wrap = wraps
            .iter()
            .find(|w| w.device_id == self.device)
            .ok_or(Error::Rejected("no wrap for this device"))?;
        self.ring.accept_rotation(self.device, &self.keys, wrap)
    }
}

/// A simulated organisation: what clients hold and what the server stores.
struct Org {
    roster: Vec<RosterBlob>,
    next_idx: BTreeMap<Uuid, u64>,
    /// Every byte string the server receives or stores, for the P1 test.
    server_saw: Vec<Vec<u8>>,
    /// The genesis entry's nonce (the server never sees it; tests that give it to an
    /// attacker do so on purpose).
    org_nonce: [u8; ORG_NONCE_LEN],
}

impl Org {
    /// `awm team create`: device key, then `K_0` and the organisation id, then the genesis
    /// roster record.
    fn create(handle: &str) -> (Org, Dev) {
        let keys = DeviceKeys::generate().unwrap();
        let device = Uuid::new_v4();
        let (ring, org_nonce) = KeyRing::create(device, &keys.public).unwrap();
        let admin = Dev {
            member: Uuid::new_v4(),
            device,
            keys,
            ring,
        };
        let mut org = Org {
            roster: Vec::new(),
            next_idx: BTreeMap::new(),
            server_saw: Vec::new(),
            org_nonce,
        };
        let entry = RosterEntry::Genesis {
            member_id: admin.member,
            handle: handle.into(),
            device_id: admin.device,
            device_pub: admin.keys.public,
            org_nonce,
            created_at: 1_790_000_000,
        };
        org.append_roster(&admin, &entry);
        (org, admin)
    }

    /// A copy of the server's roster records, for a test that appends forged ones.
    fn fork(&self) -> Org {
        Org {
            roster: self.roster.clone(),
            next_idx: self.next_idx.clone(),
            server_saw: Vec::new(),
            org_nonce: self.org_nonce,
        }
    }

    fn append_roster(&mut self, writer: &Dev, entry: &RosterEntry) {
        let idx = self.next_idx.entry(writer.device).or_insert(0);
        let slot = RosterSlot {
            member: writer.member,
            device: writer.device,
            idx: *idx,
            record_id: Uuid::new_v4(),
        };
        *idx += 1;
        let blob = seal_roster(writer.ring.org(), writer.ring.current(), slot, entry).unwrap();
        self.server_saw.push(blob.blob.clone());
        self.roster.push(blob);
    }

    fn verified(&self, ring: &KeyRing) -> Roster {
        Roster::verify(ring, &self.roster, &BTreeSet::new()).roster
    }

    /// Invite, join, verify, approve, accept: returns the new device.
    fn join(&mut self, approver: &Dev, handle: &str, member: Option<Uuid>, role: Role) -> Dev {
        let invite_id = Uuid::new_v4().to_string();
        let invite = Invite::create(approver.ring.org(), &invite_id, "tok_123", handle).unwrap();
        let invite_string = invite.encode();
        // The joining side only ever sees the string.
        let theirs = Invite::parse(&invite_string).unwrap();
        let keys = DeviceKeys::generate().unwrap();
        let device = Uuid::new_v4();
        let request = JoinRequest::new(&theirs, device, &keys);
        self.server_saw.push(
            serde_json::to_vec(&json!({
                "invite_id": request.invite_id, "token": "tok_123", "handle": request.handle,
                "device_id": request.device_id, "public_key": hex(&request.public_key),
                "mac": hex(&request.mac),
            }))
            .unwrap(),
        );
        let verified = invite.verify_join(&request).unwrap();
        assert_eq!(
            verified.code(),
            theirs.confirmation_code(device, &keys.public)
        );
        let (member_id, kind) = match member {
            Some(m) => (m, ApprovalKind::Device),
            None => (Uuid::new_v4(), ApprovalKind::Member),
        };
        let approval = approve(
            &approver.ring,
            &self.verified(&approver.ring),
            &invite,
            &verified,
            ApprovalInfo {
                member_id,
                kind,
                role,
                approver_device: approver.device,
                approved_at: 1_790_000_100,
            },
        )
        .unwrap();
        for w in &approval.wraps {
            self.server_saw.push(w.blob.clone());
            self.server_saw.push(w.auth.to_vec());
        }
        self.append_roster(approver, &approval.roster);
        let ring = accept_join(&theirs, device, &keys, &approval.wraps).unwrap();
        Dev {
            member: member_id,
            device,
            keys,
            ring,
        }
    }

    /// `awm team remove`: the admin appends a revocation of the whole member.
    fn remove(&mut self, admin: &Dev, member: Uuid) {
        let entry = RosterEntry::Revoke {
            member_id: member,
            device_id: None,
            revoked_at: 1_790_000_500,
            by_device_id: admin.device,
        };
        self.append_roster(admin, &entry);
    }
}

fn rec_ad(ring: &KeyRing, dev: &Dev, idx: u64) -> RecordAd {
    RecordAd {
        org: ring.org(),
        member: dev.member,
        device: dev.device,
        tag: "rec".into(),
        idx,
        record_id: Uuid::new_v4(),
        epoch: ring.current_epoch(),
    }
}

// ---------------------------------------------------------------------------------------
// Known-answer vectors

#[test]
fn vectors_v1_keys_known_answer() {
    let approver = Uuid::parse_str("2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f").unwrap();
    let joiner = Uuid::parse_str("9d8c7b6a-5f4e-4d3c-8b2a-1f0e9d8c7b6a").unwrap();
    let joiner_member = Uuid::parse_str("1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d").unwrap();
    let k0: [u8; 32] = bytes(0x10, 32).try_into().unwrap();
    // `awm team create`: the first admin's device key, then 16 bytes of org nonce and K_0.
    let admin_keys = DeviceKeys::from_secret_bytes(bytes(0x30, 32).try_into().unwrap());
    let org_nonce: [u8; ORG_NONCE_LEN] = bytes(0x60, 16).try_into().unwrap();
    let (ring, nonce_out) = KeyRing::create_with(
        &mut FixedRng([org_nonce.to_vec(), k0.to_vec()].concat()),
        approver,
        &admin_keys.public,
    )
    .unwrap();
    assert_eq!(nonce_out, org_nonce);
    assert_eq!(ring.current().expose_secret(), &k0);
    let org = ring.org();
    assert_eq!(org, org_id(approver, &admin_keys.public, &org_nonce));
    assert_eq!(org.get_version_num(), 4);
    let s: [u8; 32] = bytes(0x50, 32).try_into().unwrap();
    let invite = Invite::from_parts(
        org,
        "inv_01",
        "tok_abc_def",
        "alice",
        Secret32::from_bytes(s),
    )
    .unwrap();
    let dev_secret: [u8; 32] = bytes(0x70, 32).try_into().unwrap();
    let dev = DeviceKeys::from_secret_bytes(dev_secret);
    let request = JoinRequest::new(&invite, joiner, &dev);
    let verified = invite.verify_join(&request).unwrap();

    // Approval wrap: 32 bytes of ephemeral secret, then 24 bytes of nonce.
    let approval_rng = [bytes(0x90, 32), bytes(0xb0, 24)].concat();
    let approval = approve_with(
        &mut FixedRng(approval_rng.clone()),
        &ring,
        &Roster::default(),
        &invite,
        &verified,
        ApprovalInfo {
            member_id: joiner_member,
            kind: ApprovalKind::Member,
            role: Role::Member,
            approver_device: approver,
            approved_at: 1_790_000_100,
        },
    )
    .unwrap();
    let join_wrap = &approval.wraps[0];

    // Roster record of that approval: 24 bytes of nonce.
    let roster_nonce = bytes(0xc0, 24);
    let roster_id = Uuid::parse_str("0b1c2d3e-4f5a-4b6c-ad7e-8f9a0b1c2d3e").unwrap();
    let roster_blob = seal_roster_with(
        &mut FixedRng(roster_nonce.clone()),
        org,
        ring.current(),
        RosterSlot {
            member: Uuid::nil(),
            device: approver,
            idx: 1,
            record_id: roster_id,
        },
        &approval.roster,
    )
    .unwrap();

    // Rotation to epoch 1: 32 bytes of new key, 32 of ephemeral secret, 24 of nonce.
    let rotation_rng = [bytes(0x20, 32), bytes(0xa0, 32), bytes(0xd0, 24)].concat();
    let fake_roster = {
        // A minimal verified roster holding the joiner, built through the public API.
        let admin_member = Uuid::nil();
        let genesis = seal_roster_with(
            &mut FixedRng(bytes(0xe0, 24)),
            org,
            ring.current(),
            RosterSlot {
                member: admin_member,
                device: approver,
                idx: 0,
                record_id: Uuid::nil(),
            },
            &RosterEntry::Genesis {
                member_id: admin_member,
                handle: "admin".into(),
                device_id: approver,
                device_pub: admin_keys.public,
                org_nonce,
                created_at: 1_790_000_000,
            },
        )
        .unwrap();
        let report = Roster::verify(
            &ring,
            &[genesis.clone(), roster_blob.clone()],
            &BTreeSet::new(),
        );
        assert!(report.rejected.is_empty(), "{:?}", report.rejected);
        (report.roster, genesis)
    };
    let (fake_roster, genesis) = fake_roster;
    let listed = [ListedDevice {
        member_id: joiner_member,
        device_id: joiner,
        public_key: dev.public,
    }];
    let plan = plan_rotation(&ring, &fake_roster, &listed, &BTreeSet::new());
    let rotation = rotate_with(
        &mut FixedRng(rotation_rng.clone()),
        &ring,
        &plan,
        approver,
        1_790_000_600,
    )
    .unwrap();
    let rot_wrap = &rotation.wraps[0];

    let computed = json!({
        "org": org,
        "org_derivation": {
            "genesis_device": approver, "genesis_secret": hex(admin_keys.secret_bytes()),
            "genesis_pub": hex(&admin_keys.public), "org_nonce": hex(&org_nonce),
        },
        "genesis_record": {
            "writer_member": Uuid::nil(), "writer_device": approver, "idx": 0,
            "record_id": Uuid::nil(), "epoch": 0, "nonce": hex(&bytes(0xe0, 24)),
            "entry": serde_json::to_value(RosterEntry::Genesis {
                member_id: Uuid::nil(), handle: "admin".into(), device_id: approver,
                device_pub: admin_keys.public, org_nonce, created_at: 1_790_000_000,
            }).unwrap(),
            "envelope": hex(&genesis.blob),
        },
        "k0": hex(&k0),
        "k_repo_of_k0": ring.repo_key().encode(),
        "repo_key": {"remote": "github.com/owner/repo", "value": ring.repo_key().repo_key("github.com/owner/repo")},
        "invite": {
            "invite_id": "inv_01", "token": "tok_abc_def", "handle": "alice", "s": hex(&s),
            "string": invite.encode(),
        },
        "joiner": {
            "device_id": joiner, "secret": hex(&dev_secret), "public": hex(&dev.public),
            "fingerprint": fingerprint(&dev.public),
            "join_mac": hex(&request.mac),
            "code": invite.confirmation_code(joiner, &dev.public),
        },
        "join_wrap": {
            "approver_device": approver, "epoch": 0, "rng": hex(&approval_rng),
            "blob": hex(&join_wrap.blob), "auth": hex(&join_wrap.auth),
        },
        "roster_record": {
            "writer_member": Uuid::nil(), "writer_device": approver, "idx": 1,
            "record_id": roster_id, "epoch": 0, "nonce": hex(&roster_nonce),
            "entry": serde_json::to_value(&approval.roster).unwrap(),
            "envelope": hex(&roster_blob.blob),
        },
        "rotation_wrap": {
            "rng": hex(&rotation_rng), "new_key": hex(rotation.key.expose_secret()),
            "epoch": 1, "blob": hex(&rot_wrap.blob), "auth": hex(&rot_wrap.auth),
        },
        "recovery_export": KeyRing::from_keys(org, vec![
            EpochKey::from_bytes(0, k0), EpochKey::from_bytes(1, *rotation.key.expose_secret()),
        ]).unwrap().export_recovery(),
    });
    let stored = check_vector("keys.json", &computed);

    // The stored bytes still open with the stored secrets (v1 stays readable).
    let wrap = Wrap {
        device_id: joiner,
        epoch: 0,
        approver_device: approver,
        blob: unhex(stored["join_wrap"]["blob"].as_str().unwrap()),
        auth: unhex(stored["join_wrap"]["auth"].as_str().unwrap())
            .try_into()
            .unwrap(),
    };
    let parsed = Invite::parse(stored["invite"]["string"].as_str().unwrap()).unwrap();
    let mut joined = accept_join(&parsed, joiner, &dev, &[wrap]).unwrap();
    assert_eq!(joined.get(0).unwrap().expose_secret(), &k0);
    let rot = Wrap {
        device_id: joiner,
        epoch: 1,
        approver_device: approver,
        blob: unhex(stored["rotation_wrap"]["blob"].as_str().unwrap()),
        auth: unhex(stored["rotation_wrap"]["auth"].as_str().unwrap())
            .try_into()
            .unwrap(),
    };
    joined.accept_rotation(joiner, &dev, &rot).unwrap();
    assert_eq!(
        hex(joined.get(1).unwrap().expose_secret()),
        stored["rotation_wrap"]["new_key"].as_str().unwrap()
    );
    let imported = KeyRing::import_recovery(stored["recovery_export"].as_str().unwrap()).unwrap();
    assert_eq!(imported.org(), org);
    assert_eq!(imported.current_epoch(), 1);
    // The stored organisation id is the hash of the stored genesis fields, and the stored
    // genesis and approval records verify under it.
    let d = &stored["org_derivation"];
    let field = |v: &Value| unhex(v.as_str().unwrap());
    let stored_org = org_id(
        Uuid::parse_str(d["genesis_device"].as_str().unwrap()).unwrap(),
        &field(&d["genesis_pub"]).try_into().unwrap(),
        &field(&d["org_nonce"]).try_into().unwrap(),
    );
    assert_eq!(stored_org.to_string(), stored["org"].as_str().unwrap());
    let stored_ring = KeyRing::from_keys(
        stored_org,
        vec![EpochKey::from_bytes(
            0,
            field(&stored["k0"]).try_into().unwrap(),
        )],
    )
    .unwrap();
    let blob = |rec: &Value| RosterBlob {
        member: Uuid::parse_str(rec["writer_member"].as_str().unwrap()).unwrap(),
        device: Uuid::parse_str(rec["writer_device"].as_str().unwrap()).unwrap(),
        idx: rec["idx"].as_u64().unwrap(),
        record_id: Uuid::parse_str(rec["record_id"].as_str().unwrap()).unwrap(),
        epoch: 0,
        blob: field(&rec["envelope"]),
    };
    let report = Roster::verify(
        &stored_ring,
        &[
            blob(&stored["genesis_record"]),
            blob(&stored["roster_record"]),
        ],
        &BTreeSet::new(),
    );
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
    assert_eq!(
        report.roster.device(joiner).unwrap().member_id,
        joiner_member
    );
}

// ---------------------------------------------------------------------------------------
// Joins, MACs and wraps

#[test]
fn a_wrap_for_one_device_does_not_open_for_another() {
    let (mut org, admin) = Org::create("admin");
    let alice = org.join(&admin, "alice", None, Role::Member);
    // Wraps for a second device, then offered to alice.
    let invite = Invite::create(admin.ring.org(), "inv_b", "tok", "bob").unwrap();
    let bob_keys = DeviceKeys::generate().unwrap();
    let bob_dev = Uuid::new_v4();
    let verified = invite
        .verify_join(&JoinRequest::new(&invite, bob_dev, &bob_keys))
        .unwrap();
    let approval = approve(
        &admin.ring,
        &org.verified(&admin.ring),
        &invite,
        &verified,
        ApprovalInfo {
            member_id: Uuid::new_v4(),
            kind: ApprovalKind::Member,
            role: Role::Member,
            approver_device: admin.device,
            approved_at: 1,
        },
    )
    .unwrap();
    // Alice's key cannot open bob's wrap, under bob's device id or relabelled as hers.
    assert!(accept_join(&invite, bob_dev, &alice.keys, &approval.wraps).is_err());
    let mut relabelled = approval.wraps.clone();
    relabelled[0].device_id = alice.device;
    assert!(accept_join(&invite, alice.device, &alice.keys, &relabelled).is_err());
    // Bob's own key opens it.
    assert!(accept_join(&invite, bob_dev, &bob_keys, &approval.wraps).is_ok());
}

#[test]
fn a_join_with_a_wrong_mac_is_rejected() {
    let (_org, admin) = Org::create("admin");
    let ring = admin.ring;
    let invite = Invite::create(ring.org(), "inv", "tok", "alice").unwrap();
    let keys = DeviceKeys::generate().unwrap();
    let device = Uuid::new_v4();
    let good = JoinRequest::new(&invite, device, &keys);
    assert!(invite.verify_join(&good).is_ok());

    let mut bad_mac = good.clone();
    bad_mac.mac[0] ^= 1;
    assert_eq!(invite.verify_join(&bad_mac), Err(Error::BadMac));
    // The server swaps the public key for its own: the MAC no longer verifies.
    let mut swapped_key = good.clone();
    swapped_key.public_key = DeviceKeys::generate().unwrap().public;
    assert_eq!(invite.verify_join(&swapped_key), Err(Error::BadMac));
    let mut swapped_dev = good.clone();
    swapped_dev.device_id = Uuid::new_v4();
    assert_eq!(invite.verify_join(&swapped_dev), Err(Error::BadMac));
    let mut other_handle = good.clone();
    other_handle.handle = "mallory".into();
    assert!(invite.verify_join(&other_handle).is_err());
    // A MAC made with another S (another invite, or a server guess) fails.
    let other = Invite::create(ring.org(), "inv", "tok", "alice").unwrap();
    assert_eq!(
        invite.verify_join(&JoinRequest::new(&other, device, &keys)),
        Err(Error::BadMac)
    );
    // A MAC bound to another organisation id fails.
    let other_org = Invite::from_parts(
        Uuid::new_v4(),
        "inv",
        "tok",
        "alice",
        invite.secret().clone(),
    )
    .unwrap();
    assert_eq!(
        invite.verify_join(&JoinRequest::new(&other_org, device, &keys)),
        Err(Error::BadMac)
    );
}

/// P2 at join: a server that knows everything but `S` cannot make the joining device accept
/// a key the server chose.
#[test]
fn p2_a_wrap_not_authenticated_with_s_is_rejected() {
    let (org, admin) = Org::create("admin");
    let invite = Invite::create(admin.ring.org(), "inv", "tok", "alice").unwrap();
    let theirs = Invite::parse(&invite.encode()).unwrap();
    let keys = DeviceKeys::generate().unwrap();
    let device = Uuid::new_v4();
    let request = JoinRequest::new(&theirs, device, &keys);
    let verified = invite.verify_join(&request).unwrap();
    let info = ApprovalInfo {
        member_id: Uuid::new_v4(),
        kind: ApprovalKind::Member,
        role: Role::Member,
        approver_device: admin.device,
        approved_at: 1,
    };

    // The server builds a genuine-looking approval from its own key ring and an invite whose
    // S it made up (it has the invite id, token, handle and the device's public key).
    let server_ring =
        KeyRing::from_keys(admin.ring.org(), vec![EpochKey::generate(0).unwrap()]).unwrap();
    let server_invite = Invite::create(admin.ring.org(), "inv", "tok", "alice").unwrap();
    let forged = approve(
        &server_ring,
        &Roster::default(),
        &server_invite,
        &verified,
        info,
    )
    .unwrap();
    assert_eq!(
        accept_join(&theirs, device, &keys, &forged.wraps).unwrap_err(),
        Error::BadMac
    );
    // A genuine wrap with a modified authenticator, or a genuine authenticator over another
    // blob, is rejected too.
    let genuine = approve(
        &admin.ring,
        &org.verified(&admin.ring),
        &invite,
        &verified,
        info,
    )
    .unwrap();
    let mut bad_auth = genuine.wraps.clone();
    bad_auth[0].auth[31] ^= 1;
    assert_eq!(
        accept_join(&theirs, device, &keys, &bad_auth).unwrap_err(),
        Error::BadMac
    );
    let mut spliced = genuine.wraps.clone();
    spliced[0].blob = forged.wraps[0].blob.clone();
    assert_eq!(
        accept_join(&theirs, device, &keys, &spliced).unwrap_err(),
        Error::BadMac
    );
    let mut wrong_epoch = genuine.wraps.clone();
    wrong_epoch[0].epoch = 5;
    assert_eq!(
        accept_join(&theirs, device, &keys, &wrong_epoch).unwrap_err(),
        Error::BadMac
    );
    // The genuine approval works.
    let ring = accept_join(&theirs, device, &keys, &genuine.wraps).unwrap();
    assert_eq!(
        ring.current().expose_secret(),
        admin.ring.current().expose_secret()
    );
}

/// P2 at rotation: a server without `K_e` cannot hand a device a key it knows.
#[test]
fn p2_a_rotation_wrap_forged_by_the_server_is_rejected() {
    let (mut org, admin) = Org::create("admin");
    let mut alice = org.join(&admin, "alice", None, Role::Member);
    // The server knows alice's public key and device id, and (worst case) the admin's genesis
    // fields; it wraps its own key and signs the wrap with a key ring of its own.
    let server_ring =
        KeyRing::from_keys(admin.ring.org(), vec![EpochKey::generate(0).unwrap()]).unwrap();
    let server_roster = {
        let mut o = Org {
            roster: Vec::new(),
            next_idx: BTreeMap::new(),
            server_saw: Vec::new(),
            org_nonce: org.org_nonce,
        };
        let fake_admin = Dev {
            member: admin.member,
            device: admin.device,
            keys: DeviceKeys::generate().unwrap(),
            ring: server_ring.clone(),
        };
        o.append_roster(
            &fake_admin,
            &RosterEntry::Genesis {
                member_id: admin.member,
                handle: "admin".into(),
                device_id: admin.device,
                device_pub: admin.keys.public,
                org_nonce: org.org_nonce,
                created_at: 0,
            },
        );
        o.append_roster(
            &fake_admin,
            &RosterEntry::Approve {
                member_id: alice.member,
                handle: "alice".into(),
                role: Role::Member,
                kind: ApprovalKind::Member,
                device_id: alice.device,
                device_pub: alice.keys.public,
                approved_at: 0,
                approver_device_id: admin.device,
            },
        );
        o.verified(&server_ring)
    };
    let plan = plan_rotation(
        &server_ring,
        &server_roster,
        &[alice.listed()],
        &BTreeSet::new(),
    );
    let forged = rotate(&server_ring, &plan, admin.device, 2).unwrap();
    assert_eq!(alice.accept_rotation(&forged.wraps), Err(Error::BadMac));
    assert_eq!(alice.ring.current_epoch(), 0);
}

// ---------------------------------------------------------------------------------------
// Roster (RV8-team X1)

/// X1: a server that lists an extra device (its own key) gets no wrap.
#[test]
fn p2_a_rotation_wraps_nothing_to_an_extra_server_listed_device() {
    let (mut org, admin) = Org::create("admin");
    let alice = org.join(&admin, "alice", None, Role::Member);
    let bob = org.join(&admin, "bob", None, Role::Member);
    org.remove(&admin, bob.member);
    let roster = org.verified(&admin.ring);
    assert_eq!(roster.status(&alice.listed()), DeviceStatus::Verified);

    let server_keys = DeviceKeys::generate().unwrap();
    let extra_for_alice = ListedDevice {
        member_id: alice.member,
        device_id: Uuid::new_v4(),
        public_key: server_keys.public,
    };
    let extra_member = ListedDevice {
        member_id: Uuid::new_v4(),
        device_id: Uuid::new_v4(),
        public_key: server_keys.public,
    };
    assert_eq!(roster.status(&extra_for_alice), DeviceStatus::Unverified);
    let listed = [
        admin.listed(),
        alice.listed(),
        bob.listed(),
        extra_for_alice.clone(),
        extra_member.clone(),
    ];
    let plan = plan_rotation(&admin.ring, &roster, &listed, &BTreeSet::new());
    let targets: Vec<Uuid> = plan.wrap_to().iter().map(|d| d.device_id).collect();
    assert_eq!(targets, vec![admin.device, alice.device]);
    assert_eq!(
        plan.unverified(),
        &[extra_for_alice.device_id, extra_member.device_id]
    );
    let rotation = rotate(&admin.ring, &plan, admin.device, 3).unwrap();
    assert!(
        rotation
            .wraps
            .iter()
            .all(|w| w.device_id != extra_for_alice.device_id
                && w.device_id != extra_member.device_id)
    );
    assert_eq!(rotation.wraps.len(), 2);
}

/// X1: a server that lists a verified device with its own public key gets no wrap either.
#[test]
fn p2_a_rotation_wraps_nothing_to_a_server_substituted_key() {
    let (mut org, admin) = Org::create("admin");
    let alice = org.join(&admin, "alice", None, Role::Member);
    let roster = org.verified(&admin.ring);
    let mut swapped = alice.listed();
    swapped.public_key = DeviceKeys::generate().unwrap().public;
    let mut moved = alice.listed();
    moved.member_id = admin.member;
    assert_eq!(roster.status(&swapped), DeviceStatus::Mismatch);
    let plan = plan_rotation(&admin.ring, &roster, &[swapped, moved], &BTreeSet::new());
    assert!(plan.wrap_to().is_empty());
    assert_eq!(plan.mismatch(), &[alice.device]);
}

#[test]
fn a_roster_entry_with_a_forged_ad_is_rejected() {
    let (mut org, admin) = Org::create("admin");
    let alice = org.join(&admin, "alice", None, Role::Member);
    let approval = org.roster[1].clone();
    let genesis = org.roster[0].clone();
    let verify = |blobs: Vec<RosterBlob>| Roster::verify(&admin.ring, &blobs, &BTreeSet::new());

    // Served from another stream, index, record id or epoch: does not open.
    let mut other_stream = approval.clone();
    other_stream.device = alice.device;
    other_stream.member = alice.member;
    let mut other_idx = approval.clone();
    other_idx.idx = 7;
    let mut other_id = approval.clone();
    other_id.record_id = Uuid::new_v4();
    let mut other_epoch = approval.clone();
    other_epoch.epoch = 1;
    for forged in [other_stream, other_idx, other_id, other_epoch] {
        let report = verify(vec![genesis.clone(), forged]);
        assert!(report.roster.device(alice.device).is_none());
        assert_eq!(report.rejected.len(), 1);
    }
    // A record the server sealed under a key of its own does not open.
    let server_key = EpochKey::generate(0).unwrap();
    let forged = seal_roster(
        admin.ring.org(),
        &server_key,
        RosterSlot {
            member: admin.member,
            device: admin.device,
            idx: 1,
            record_id: Uuid::new_v4(),
        },
        &RosterEntry::Approve {
            member_id: Uuid::new_v4(),
            handle: "evil".into(),
            role: Role::Admin,
            kind: ApprovalKind::Member,
            device_id: Uuid::new_v4(),
            device_pub: DeviceKeys::generate().unwrap().public,
            approved_at: 0,
            approver_device_id: admin.device,
        },
    )
    .unwrap();
    let report = verify(vec![genesis.clone(), forged]);
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.roster.devices().count(), 1);
    // A record with a valid tag but another kind's AD (`rec`) does not open as a roster entry.
    let as_rec = RecordAd {
        org: admin.ring.org(),
        member: admin.member,
        device: admin.device,
        tag: ROSTER_TAG.into(),
        idx: 1,
        record_id: approval.record_id,
        epoch: 0,
    };
    let mut rec_ad = as_rec.clone();
    rec_ad.tag = "rec".into();
    assert!(open_record(&admin.ring, &rec_ad, &approval.blob).is_err());
    assert!(open_record(&admin.ring, &as_rec, &approval.blob).is_ok());
    // The unmodified set verifies.
    assert!(verify(org.roster.clone()).rejected.is_empty());
}

#[test]
fn roster_order_does_not_matter_and_authority_is_checked() {
    let (mut org, admin) = Org::create("admin");
    let alice = org.join(&admin, "alice", None, Role::Member);
    let alice2 = org.join(&alice, "alice", Some(alice.member), Role::Member);
    let mut reversed = org.roster.clone();
    reversed.reverse();
    let report = Roster::verify(&admin.ring, &reversed, &BTreeSet::new());
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
    assert_eq!(report.roster.devices().count(), 3);
    assert_eq!(
        report.roster.device(alice2.device).unwrap().approver,
        alice.device
    );

    // Alice (a member) cannot approve a new member, nor a device of another member.
    let mut bad = org.fork();
    let stranger = DeviceKeys::generate().unwrap();
    bad.append_roster(
        &alice,
        &RosterEntry::Approve {
            member_id: Uuid::new_v4(),
            handle: "carol".into(),
            role: Role::Admin,
            kind: ApprovalKind::Member,
            device_id: Uuid::new_v4(),
            device_pub: stranger.public,
            approved_at: 2,
            approver_device_id: alice.device,
        },
    );
    let planted = Uuid::new_v4();
    bad.append_roster(
        &alice,
        &RosterEntry::Approve {
            member_id: admin.member,
            handle: "admin".into(),
            role: Role::Member,
            kind: ApprovalKind::Device,
            device_id: planted,
            device_pub: stranger.public,
            approved_at: 2,
            approver_device_id: alice.device,
        },
    );
    let report = Roster::verify(&admin.ring, &bad.roster, &BTreeSet::new());
    let reasons: Vec<&str> = report.rejected.iter().map(|r| r.reason).collect();
    assert_eq!(
        reasons,
        vec![
            "only an admin approves a new member",
            "a member approves only their own devices"
        ]
    );
    assert!(report.roster.device(planted).is_none());
}

// ---------------------------------------------------------------------------------------
// Removal and rotation (P3)

#[test]
fn p3_after_rotation_the_removed_members_keys_open_no_new_epoch_record() {
    let (mut org, mut admin) = Org::create("admin");
    let mut alice = org.join(&admin, "alice", None, Role::Member);
    let bob = org.join(&admin, "bob", None, Role::Member);
    let bob2 = org.join(&bob, "bob", Some(bob.member), Role::Member);

    org.remove(&admin, bob.member);
    let roster = org.verified(&admin.ring);
    assert_eq!(roster.status(&bob.listed()), DeviceStatus::Revoked);
    let listed = [admin.listed(), alice.listed(), bob.listed(), bob2.listed()];
    let removed = BTreeSet::from([bob.member]);
    let plan = plan_rotation(&admin.ring, &roster, &listed, &removed);
    assert_eq!(plan.removed(), &[bob.device, bob2.device]);
    let rotation = rotate(&admin.ring, &plan, admin.device, 10).unwrap();
    // No wrap to a removed device is ever produced.
    assert!(rotation
        .wraps
        .iter()
        .all(|w| w.device_id != bob.device && w.device_id != bob2.device));
    admin.ring.adopt_own_rotation(&rotation).unwrap();
    assert_eq!(alice.accept_rotation(&rotation.wraps).unwrap(), 1);
    org.append_roster(&admin, &rotation.roster);

    // A record alice writes under epoch 1 opens for the admin and not for bob's devices.
    let ad = rec_ad(&alice.ring, &alice, 0);
    let env = seal_record(alice.ring.current(), &ad, b"after the removal").unwrap();
    assert_eq!(
        open_record(&admin.ring, &ad, &env).unwrap(),
        b"after the removal"
    );
    for b in [&bob, &bob2] {
        assert_eq!(open_record(&b.ring, &ad, &env), Err(Error::UnknownEpoch(1)));
        // Not with the old epoch key either (another key and another AD epoch).
        let old = RecordAd {
            epoch: 0,
            ..ad.clone()
        };
        assert_eq!(open_record(&b.ring, &old, &env), Err(Error::Open));
        // Bob cannot use the wraps meant for others.
        for w in &rotation.wraps {
            let mut r = b.ring.clone();
            let mut w = w.clone();
            w.device_id = b.device;
            assert!(r.accept_rotation(b.device, &b.keys, &w).is_err());
        }
    }
    // Old records stay readable for everyone who had them.
    let old_ad = RecordAd {
        epoch: 0,
        ..rec_ad(&bob.ring, &bob, 0)
    };
    let old = seal_record(bob.ring.get(0).unwrap(), &old_ad, b"before").unwrap();
    assert_eq!(open_record(&alice.ring, &old_ad, &old).unwrap(), b"before");
    // The epoch record verifies and lists exactly the wrapped devices.
    let roster = org.verified(&admin.ring);
    assert_eq!(
        roster.epoch_devices(1).unwrap(),
        &[admin.device, alice.device]
    );
}

#[test]
fn p3_a_revoked_device_of_a_remaining_member_gets_no_wrap() {
    let (mut org, admin) = Org::create("admin");
    let alice = org.join(&admin, "alice", None, Role::Member);
    let alice2 = org.join(&alice, "alice", Some(alice.member), Role::Member);
    // Alice revokes her lost laptop herself.
    org.append_roster(
        &alice,
        &RosterEntry::Revoke {
            member_id: alice.member,
            device_id: Some(alice2.device),
            revoked_at: 5,
            by_device_id: alice.device,
        },
    );
    let roster = org.verified(&admin.ring);
    let plan = plan_rotation(
        &admin.ring,
        &roster,
        &[admin.listed(), alice.listed(), alice2.listed()],
        &BTreeSet::new(),
    );
    assert_eq!(plan.revoked(), &[alice2.device]);
    let rotation = rotate(&admin.ring, &plan, admin.device, 6).unwrap();
    assert!(rotation.wraps.iter().all(|w| w.device_id != alice2.device));
}

/// P4 decision: not defended in v1 (no signature crate may be added in TM3). A removed member
/// who still holds `K_e` and colludes with the server can authenticate a rotation wrap of a
/// key they know. This test pins the gap; closing P4 must turn it into a rejection.
#[test]
fn p4_not_defended_removed_member_colluding_with_server_can_push_a_known_key() {
    let (mut org, admin) = Org::create("admin");
    let mut alice = org.join(&admin, "alice", None, Role::Member);
    let bob = org.join(&admin, "bob", None, Role::Member);
    org.remove(&admin, bob.member);
    // Bob (removed, still holding K_0) plans a "rotation" from his own copy of the roster,
    // and the colluding server serves it before the admin's genuine one.
    let roster = org.verified(&bob.ring);
    let plan = plan_rotation(&bob.ring, &roster, &[alice.listed()], &BTreeSet::new());
    let evil = rotate(&bob.ring, &plan, bob.device, 7).unwrap();
    assert_eq!(alice.accept_rotation(&evil.wraps), Ok(1));
    assert_eq!(
        alice.ring.current().expose_secret(),
        evil.key.expose_secret(),
        "alice now seals under a key bob knows: P4 is open in v1"
    );
}

/// P5: not defended in v1. A member holding `K_e` can seal a record in another member's
/// stream; only the server's stream binding (the token) stops it.
#[test]
fn p5_not_defended_member_can_seal_a_record_in_another_members_stream() {
    let (mut org, admin) = Org::create("admin");
    let alice = org.join(&admin, "alice", None, Role::Member);
    let ad_as_admin = rec_ad(&alice.ring, &admin, 3);
    let forged = seal_record(alice.ring.current(), &ad_as_admin, b"admin says").unwrap();
    assert_eq!(
        open_record(&admin.ring, &ad_as_admin, &forged).unwrap(),
        b"admin says"
    );
}

// ---------------------------------------------------------------------------------------
// Invites (M5), fingerprints and codes

#[test]
fn the_invite_secret_never_leaves_the_creating_device_except_in_the_string() {
    let (mut org, admin) = Org::create("admin");
    let alice = org.join(&admin, "alice", None, Role::Member);
    let invite = Invite::create(admin.ring.org(), "inv_x", "tok_x", "carol").unwrap();
    let s = *invite.secret().expose();
    let request = JoinRequest::new(&invite, alice.device, &alice.keys);
    let sent = format!("{request:?}");
    assert!(!sent.contains(&hex(&s)));
    assert!(!request.mac.windows(8).any(|w| s.windows(8).any(|x| x == w)));
    // Debug output never prints S.
    assert!(!format!("{invite:?}").contains(&hex(&s)));
    // The string round-trips, including a token with underscores.
    let parsed = Invite::parse(&invite.encode()).unwrap();
    assert_eq!(parsed.secret().expose(), &s);
    assert_eq!(
        (parsed.invite_id.as_str(), parsed.token.as_str()),
        ("inv_x", "tok_x")
    );
    assert!(Invite::parse("awmi1_AAAA").is_err());
    assert!(Invite::parse(&invite.encode().replace("awmi1_", "awmi2_")).is_err());
}

/// M5: a stolen invite string alone yields no history; the admin's manual approval compares
/// a code the thief's key cannot reproduce.
#[test]
fn a_stolen_invite_alone_yields_no_history_without_an_approval() {
    let (_org, admin) = Org::create("admin");
    let invite = Invite::create(admin.ring.org(), "inv", "tok", "alice").unwrap();
    let string = invite.encode();

    // The thief joins first.
    let thief = Invite::parse(&string).unwrap();
    let thief_keys = DeviceKeys::generate().unwrap();
    let thief_dev = Uuid::new_v4();
    let thief_req = JoinRequest::new(&thief, thief_dev, &thief_keys);
    // Without approval there are no wraps and nothing to open.
    assert!(accept_join(&thief, thief_dev, &thief_keys, &[]).is_err());
    let ad = rec_ad(&admin.ring, &admin, 0);
    let env = seal_record(admin.ring.current(), &ad, b"history").unwrap();
    let thief_guess = KeyRing::from_keys(
        admin.ring.org(),
        vec![EpochKey::from_bytes(0, *thief.secret().expose())],
    )
    .unwrap();
    assert_eq!(open_record(&thief_guess, &ad, &env), Err(Error::Open));

    // The admin's approve shows the thief's fingerprint and code; the real invitee reads out
    // the code of their own key, which differs.
    let pending = invite.verify_join(&thief_req).unwrap();
    let real = Invite::parse(&string).unwrap();
    let real_keys = DeviceKeys::generate().unwrap();
    let real_code = real.confirmation_code(Uuid::new_v4(), &real_keys.public);
    assert_ne!(pending.code(), real_code);
    assert_ne!(pending.fingerprint(), fingerprint(&real_keys.public));
}

#[test]
fn fingerprint_and_code_are_deterministic_from_the_key_and_s() {
    let org = Uuid::parse_str("6f1c2a9e-3b4d-4e5f-8a7b-0c1d2e3f4a5b").unwrap();
    let s = Secret32::from_bytes([7u8; 32]);
    let a = Invite::from_parts(org, "inv", "tok", "alice", s.clone()).unwrap();
    let b = Invite::from_parts(org, "inv", "tok", "alice", s).unwrap();
    let keys = DeviceKeys::from_secret_bytes([9u8; 32]);
    let dev = Uuid::nil();
    assert_eq!(
        a.confirmation_code(dev, &keys.public),
        b.confirmation_code(dev, &keys.public)
    );
    let code = a.confirmation_code(dev, &keys.public);
    assert_eq!(code.len(), 7);
    assert!(code.chars().enumerate().all(|(i, c)| if i == 3 {
        c == ' '
    } else {
        c.is_ascii_digit()
    }));
    assert_eq!(fingerprint(&keys.public), keys.fingerprint());
    assert_eq!(fingerprint(&keys.public).len(), 39);
    // Another S or another key changes the code.
    let c =
        Invite::from_parts(org, "inv", "tok", "alice", Secret32::from_bytes([8u8; 32])).unwrap();
    assert_ne!(c.confirmation_code(dev, &keys.public), code);
    let other = DeviceKeys::from_secret_bytes([10u8; 32]);
    assert_ne!(a.confirmation_code(dev, &other.public), code);
    assert_ne!(fingerprint(&other.public), fingerprint(&keys.public));
}

// ---------------------------------------------------------------------------------------
// Own devices, recovery (M6) and the export

#[test]
fn a_member_approves_their_own_second_device() {
    let (mut org, admin) = Org::create("admin");
    let alice = org.join(&admin, "alice", None, Role::Member);
    let laptop = org.join(&alice, "alice", Some(alice.member), Role::Member);
    let roster = org.verified(&admin.ring);
    assert_eq!(roster.status(&laptop.listed()), DeviceStatus::Verified);
    assert_eq!(
        roster.device(laptop.device).unwrap().member_id,
        alice.member
    );
    // The laptop reads what the first device wrote.
    let ad = rec_ad(&alice.ring, &alice, 0);
    let env = seal_record(alice.ring.current(), &ad, b"mine").unwrap();
    assert_eq!(open_record(&laptop.ring, &ad, &env).unwrap(), b"mine");
}

/// M6: a member who lost every device is re-enrolled by an admin's device invite under the
/// same member id; the old device is revoked and the new one is a rotation target.
#[test]
fn an_admin_re_enrols_a_member_who_lost_every_device_under_the_same_member_id() {
    let (mut org, admin) = Org::create("admin");
    let alice = org.join(&admin, "alice", None, Role::Member);
    let ad = rec_ad(&alice.ring, &alice, 0);
    let old_record = seal_record(alice.ring.current(), &ad, b"written before the loss").unwrap();
    // Laptop lost: the admin revokes it and creates `add-device --for @alice`.
    org.append_roster(
        &admin,
        &RosterEntry::Revoke {
            member_id: alice.member,
            device_id: Some(alice.device),
            revoked_at: 9,
            by_device_id: admin.device,
        },
    );
    let new = org.join(&admin, "alice", Some(alice.member), Role::Member);
    assert_eq!(new.member, alice.member);
    let roster = org.verified(&admin.ring);
    assert_eq!(roster.status(&new.listed()), DeviceStatus::Verified);
    assert_eq!(roster.status(&alice.listed()), DeviceStatus::Revoked);
    assert_eq!(roster.member(alice.member).unwrap().handle, "alice");
    // Same member id: the old stream's records open, and the new device writes to the
    // member's streams.
    assert_eq!(
        open_record(&new.ring, &ad, &old_record).unwrap(),
        b"written before the loss"
    );
    // The next rotation wraps to the new device and not to the lost one.
    let plan = plan_rotation(
        &admin.ring,
        &roster,
        &[admin.listed(), alice.listed(), new.listed()],
        &BTreeSet::new(),
    );
    let targets: Vec<Uuid> = plan.wrap_to().iter().map(|d| d.device_id).collect();
    assert!(targets.contains(&new.device) && !targets.contains(&alice.device));
}

/// An exported recovery blob restores an admin's ability to rotate on a new device.
#[test]
fn a_recovery_export_restores_an_admins_ability_to_rotate() {
    let (mut org, admin) = Org::create("admin");
    let mut alice = org.join(&admin, "alice", None, Role::Member);
    let export = admin.ring.export_recovery();
    let admin_member = admin.member;
    drop(admin); // every admin device lost

    let ring = KeyRing::import_recovery(&export).unwrap();
    let restored = Dev {
        member: admin_member,
        device: Uuid::new_v4(),
        keys: DeviceKeys::generate().unwrap(),
        ring,
    };
    org.append_roster(
        &restored,
        &RosterEntry::Recover {
            member_id: admin_member,
            handle: "admin".into(),
            device_id: restored.device,
            device_pub: restored.keys.public,
            recovered_at: 20,
        },
    );
    let roster = org.verified(&restored.ring);
    assert_eq!(roster.status(&restored.listed()), DeviceStatus::Verified);
    let plan = plan_rotation(
        &restored.ring,
        &roster,
        &[restored.listed(), alice.listed()],
        &BTreeSet::new(),
    );
    let rotation = rotate(&restored.ring, &plan, restored.device, 21).unwrap();
    assert_eq!(alice.accept_rotation(&rotation.wraps), Ok(1));

    // A member (not an admin) cannot self-enrol with a Recover entry.
    let mut m = org.fork();
    let alice_new = Dev {
        member: alice.member,
        device: Uuid::new_v4(),
        keys: DeviceKeys::generate().unwrap(),
        ring: alice.ring.clone(),
    };
    m.append_roster(
        &alice_new,
        &RosterEntry::Recover {
            member_id: alice.member,
            handle: "alice".into(),
            device_id: alice_new.device,
            device_pub: alice_new.keys.public,
            recovered_at: 22,
        },
    );
    let report = Roster::verify(&alice.ring, &m.roster, &BTreeSet::new());
    assert!(report.roster.device(alice_new.device).is_none());
    assert_eq!(
        report.rejected.last().unwrap().reason,
        "only an admin recovers from an export"
    );
}

#[test]
fn a_recovery_export_rejects_typos_and_gaps() {
    let (_org, admin) = Org::create("admin");
    let ring = admin.ring;
    let export = ring.export_recovery();
    assert!(export.starts_with("awmk1_"));
    let back = KeyRing::import_recovery(&export).unwrap();
    assert_eq!(back.org(), ring.org());
    assert_eq!(
        back.current().expose_secret(),
        ring.current().expose_secret()
    );
    // One changed character fails the checksum or the decoding.
    let mut chars: Vec<char> = export.chars().collect();
    let i = chars.len() / 2;
    chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
    let typo: String = chars.into_iter().collect();
    assert!(KeyRing::import_recovery(&typo).is_err());
    // A ring must hold epochs 0..n.
    assert!(KeyRing::from_keys(ring.org(), vec![EpochKey::from_bytes(1, [0u8; 32])]).is_err());
    assert!(KeyRing::from_keys(
        ring.org(),
        vec![
            EpochKey::from_bytes(0, [0u8; 32]),
            EpochKey::from_bytes(0, [1u8; 32])
        ]
    )
    .is_err());
}

/// M4: `K_repo` comes from `K_0`, so `repo_key` survives rotations.
#[test]
fn repo_key_is_fixed_across_rotations() {
    let (mut org, mut admin) = Org::create("admin");
    let alice = org.join(&admin, "alice", None, Role::Member);
    let before = admin.ring.repo_key().repo_key("github.com/owner/repo");
    let roster = org.verified(&admin.ring);
    let plan = plan_rotation(&admin.ring, &roster, &[alice.listed()], &BTreeSet::new());
    let rotation = rotate(&admin.ring, &plan, admin.device, 1).unwrap();
    admin.ring.adopt_own_rotation(&rotation).unwrap();
    assert_eq!(
        admin.ring.repo_key().repo_key("github.com/owner/repo"),
        before
    );
    assert_eq!(
        alice.ring.repo_key().repo_key("github.com/owner/repo"),
        before
    );
    assert_eq!(before.len(), 32);
    assert_ne!(
        admin.ring.repo_key().repo_key("github.com/owner/other"),
        before
    );
    // `team.repo` round-trips.
    let file = admin.ring.repo_key().encode();
    let k = awm_proto::keys::RepoKey::decode(&file).unwrap();
    assert_eq!(k.repo_key("github.com/owner/repo"), before);
}

// ---------------------------------------------------------------------------------------
// P1 and zeroisation

/// P1: across a whole life cycle (create, joins, own device, removal, rotation, records), no
/// byte string the server receives contains an epoch key, the invite secret, a device secret
/// or record plaintext.
#[test]
fn p1_nothing_the_server_receives_holds_a_key_or_plaintext() {
    let (mut org, mut admin) = Org::create("admin");
    let mut alice = org.join(&admin, "alice", None, Role::Member);
    let bob = org.join(&admin, "bob", None, Role::Member);
    let laptop = org.join(&alice, "alice", Some(alice.member), Role::Member);
    org.remove(&admin, bob.member);
    let roster = org.verified(&admin.ring);
    let plan = plan_rotation(
        &admin.ring,
        &roster,
        &[
            admin.listed(),
            alice.listed(),
            bob.listed(),
            laptop.listed(),
        ],
        &BTreeSet::from([bob.member]),
    );
    let rotation = rotate(&admin.ring, &plan, admin.device, 30).unwrap();
    for w in &rotation.wraps {
        org.server_saw.push(w.blob.clone());
        org.server_saw.push(w.auth.to_vec());
    }
    admin.ring.adopt_own_rotation(&rotation).unwrap();
    alice.accept_rotation(&rotation.wraps).unwrap();
    org.append_roster(&admin, &rotation.roster);
    let plaintext = b"customer acme: the staging password rotation runbook";
    let ad = rec_ad(&alice.ring, &alice, 0);
    org.server_saw
        .push(seal_record(alice.ring.current(), &ad, plaintext).unwrap());

    let mut secrets: Vec<Vec<u8>> = Vec::new();
    for e in admin.ring.epochs() {
        secrets.push(e.expose_secret().to_vec());
    }
    for d in [&admin, &alice, &bob, &laptop] {
        secrets.push(d.keys.secret_bytes().to_vec());
    }
    secrets.push(plaintext[..16].to_vec());
    let roster_text = serde_json::to_vec(&rotation.roster).unwrap();
    secrets.push(roster_text[..16].to_vec());
    for item in &org.server_saw {
        for s in &secrets {
            let w = s.len().min(16);
            assert!(
                !item.windows(w).any(|x| x == &s[..w]),
                "server-visible bytes contain a secret or plaintext"
            );
        }
    }
    // The server can open none of the roster records it stores.
    let server_ring =
        KeyRing::from_keys(admin.ring.org(), vec![EpochKey::generate(0).unwrap()]).unwrap();
    let report = Roster::verify(&server_ring, &org.roster, &BTreeSet::new());
    assert_eq!(report.rejected.len(), org.roster.len());
}

#[test]
fn secret_material_is_zeroized_on_drop() {
    use awm_proto::crypto::Secret32;
    use hmac::digest::zeroize::{Zeroize, ZeroizeOnDrop};
    fn zeroizes_on_drop<T: ZeroizeOnDrop>() {}
    zeroizes_on_drop::<Secret32>();
    zeroizes_on_drop::<EpochKey>();
    zeroizes_on_drop::<DeviceKeys>();
    zeroizes_on_drop::<x25519_dalek::StaticSecret>();
    zeroizes_on_drop::<x25519_dalek::SharedSecret>();
    zeroizes_on_drop::<chacha20poly1305::XChaCha20Poly1305>();
    let mut s = Secret32::from_bytes([0xaa; 32]);
    s.zeroize();
    assert_eq!(s.expose(), &[0u8; 32]);
    assert_eq!(format!("{s:?}"), "Secret32(..)");
    let k = EpochKey::from_bytes(3, [0xbb; 32]);
    assert!(!format!("{k:?}").contains("bb"));
}

// ---------------------------------------------------------------------------------------
// RVT1: self-certifying genesis (B1), extra admins (M5), own approval and approvals (M2),
// the one roster plaintext (M1), suspect approvers (m6)

/// B1: an ordinary member writes a genesis of their own, earlier than the admin's, in their
/// own stream. It does not hash to the organisation id, so it is rejected; the admin stays
/// the trust root and the member's "new member" approval does not verify.
#[test]
fn a_genesis_written_by_a_member_is_rejected() {
    let (mut org, alf) = Org::create("alf");
    let roy = org.join(&alf, "roy", None, Role::Member);
    assert!(
        !org.next_idx.contains_key(&roy.device),
        "roy's roster stream is empty"
    );

    // (1) roy's own key and a nonce of roy's choosing; (2) alf's genuine key and nonce copied
    // into roy's stream. Both claim created_at 0.
    let forged_own = RosterEntry::Genesis {
        member_id: roy.member,
        handle: "roy".into(),
        device_id: roy.device,
        device_pub: roy.keys.public,
        org_nonce: [7; ORG_NONCE_LEN],
        created_at: 0,
    };
    let forged_copy = RosterEntry::Genesis {
        member_id: roy.member,
        handle: "roy".into(),
        device_id: roy.device,
        device_pub: alf.keys.public,
        org_nonce: org.org_nonce,
        created_at: 0,
    };
    for forged in [forged_own, forged_copy] {
        let mut bad = org.fork();
        bad.append_roster(&roy, &forged);
        // roy then enrols a device X it controls as a new admin "member".
        let x_keys = DeviceKeys::generate().unwrap();
        let x = Dev {
            member: Uuid::new_v4(),
            device: Uuid::new_v4(),
            keys: x_keys.clone(),
            ring: roy.ring.clone(),
        };
        bad.append_roster(
            &roy,
            &RosterEntry::Approve {
                member_id: x.member,
                handle: "xavier".into(),
                role: Role::Admin,
                kind: ApprovalKind::Member,
                device_id: x.device,
                device_pub: x_keys.public,
                approved_at: 1,
                approver_device_id: roy.device,
            },
        );
        let report = Roster::verify(&alf.ring, &bad.roster, &BTreeSet::new());
        let reasons: Vec<&str> = report.rejected.iter().map(|r| r.reason).collect();
        assert_eq!(
            reasons,
            vec![
                "genesis does not hash to the organisation id",
                "only an admin approves a new member"
            ]
        );
        let roster = &report.roster;
        assert!(roster.member(alf.member).unwrap().admin);
        assert!(!roster.member(roy.member).unwrap().admin);
        assert_eq!(roster.status(&alf.listed()), DeviceStatus::Verified);
        assert_eq!(roster.status(&roy.listed()), DeviceStatus::Verified);
        assert_eq!(roster.status(&x.listed()), DeviceStatus::Unverified);

        // After roy's removal the rotation wraps to alf's device, not to X nor to roy.
        bad.remove(&alf, roy.member);
        let roster = bad.verified(&alf.ring);
        let plan = plan_rotation(
            &alf.ring,
            &roster,
            &[alf.listed(), roy.listed(), x.listed()],
            &BTreeSet::from([roy.member]),
        );
        let targets: Vec<Uuid> = plan.wrap_to().iter().map(|d| d.device_id).collect();
        assert_eq!(targets, vec![alf.device]);
        assert_eq!(plan.unverified(), &[x.device]);
        assert_eq!(plan.removed(), &[roy.device]);
    }
}

/// B1: the genesis rule. Only the stream of the device the organisation id was derived from
/// can hold a genesis that counts; moving fields or index, or two passing geneses, fail closed.
#[test]
fn only_a_genesis_that_hashes_to_the_organisation_id_counts() {
    let (org, alf) = Org::create("alf");
    let genesis = |device_pub: [u8; 32], org_nonce: [u8; ORG_NONCE_LEN]| RosterEntry::Genesis {
        member_id: alf.member,
        handle: "alf".into(),
        device_id: alf.device,
        device_pub,
        org_nonce,
        created_at: 1,
    };
    // The genuine one verifies alone.
    assert!(org.verified(&alf.ring).member(alf.member).unwrap().admin);
    // Another nonce or another key in the right stream does not hash to the id.
    for entry in [
        genesis(alf.keys.public, [0; ORG_NONCE_LEN]),
        genesis(DeviceKeys::generate().unwrap().public, org.org_nonce),
    ] {
        let mut o = Org {
            roster: Vec::new(),
            next_idx: BTreeMap::new(),
            server_saw: Vec::new(),
            org_nonce: org.org_nonce,
        };
        o.append_roster(&alf, &entry);
        let report = Roster::verify(&alf.ring, &o.roster, &BTreeSet::new());
        assert_eq!(
            report.rejected[0].reason,
            "genesis does not hash to the organisation id"
        );
        assert_eq!(report.roster.members().count(), 0);
    }
    // The genuine entry at index 1 is not a genesis.
    let mut o = org.fork();
    o.append_roster(&alf, &genesis(alf.keys.public, org.org_nonce));
    let report = Roster::verify(&alf.ring, &o.roster[1..], &BTreeSet::new());
    assert_eq!(
        report.rejected[0].reason,
        "genesis not at index 0 under epoch 0"
    );
    // Two passing geneses (here: a colluding server lets a second member's stream reuse the
    // genesis device id) are both rejected: nothing is trusted.
    let twin = Uuid::new_v4();
    let mut two = org.roster.clone();
    two.push(
        seal_roster(
            alf.ring.org(),
            alf.ring.current(),
            RosterSlot {
                member: twin,
                device: alf.device,
                idx: 0,
                record_id: Uuid::new_v4(),
            },
            &RosterEntry::Genesis {
                member_id: twin,
                handle: "twin".into(),
                device_id: alf.device,
                device_pub: alf.keys.public,
                org_nonce: org.org_nonce,
                created_at: 0,
            },
        )
        .unwrap(),
    );
    let report = Roster::verify(&alf.ring, &two, &BTreeSet::new());
    let reasons: Vec<&str> = report.rejected.iter().map(|r| r.reason).collect();
    assert_eq!(
        reasons,
        vec!["more than one genesis", "more than one genesis"]
    );
    assert_eq!(report.roster.devices().count(), 0);
    // The same record served twice counts once.
    let mut doubled = org.roster.clone();
    doubled.push(org.roster[0].clone());
    assert!(Roster::verify(&alf.ring, &doubled, &BTreeSet::new())
        .rejected
        .is_empty());
}

#[test]
fn the_organisation_id_is_derived_from_the_genesis_device() {
    let keys = DeviceKeys::generate().unwrap();
    let device = Uuid::new_v4();
    let (ring, nonce) = KeyRing::create(device, &keys.public).unwrap();
    assert_eq!(ring.org(), org_id(device, &keys.public, &nonce));
    assert_eq!(ring.org().get_version_num(), 4);
    let (again, nonce2) = KeyRing::create(device, &keys.public).unwrap();
    assert_ne!(nonce, nonce2, "a fresh nonce per organisation");
    assert_ne!(ring.org(), again.org());
    assert_ne!(org_id(Uuid::new_v4(), &keys.public, &nonce), ring.org());
}

/// M5: with a verified admin in the roster, the server's role list widens nothing.
#[test]
fn extra_admins_are_ignored_while_the_roster_holds_a_verified_admin() {
    let (mut org, alf) = Org::create("alf");
    let roy = org.join(&alf, "roy", None, Role::Member);
    let planted = Uuid::new_v4();
    org.append_roster(
        &roy,
        &RosterEntry::Approve {
            member_id: Uuid::new_v4(),
            handle: "srv".into(),
            role: Role::Admin,
            kind: ApprovalKind::Member,
            device_id: planted,
            device_pub: DeviceKeys::generate().unwrap().public,
            approved_at: 1,
            approver_device_id: roy.device,
        },
    );
    let extra = BTreeSet::from([roy.member]);
    let report = Roster::verify(&alf.ring, &org.roster, &extra);
    assert!(report.extra_admins_ignored);
    assert!(report.roster.device(planted).is_none());
    assert_eq!(
        report.rejected.last().unwrap().reason,
        "only an admin approves a new member"
    );
    assert!(!report.roster.member(roy.member).unwrap().admin);
    // Without extra admins nothing is "ignored".
    assert!(!Roster::verify(&alf.ring, &org.roster, &BTreeSet::new()).extra_admins_ignored);
}

/// M5: when the roster holds no non-revoked admin (recovery after `awm serve promote`),
/// confirmed extra admins apply.
#[test]
fn extra_admins_apply_only_when_no_admin_is_left() {
    let (mut org, alf) = Org::create("alf");
    let roy = org.join(&alf, "roy", None, Role::Member);
    // alf leaves: the only admin revokes their own membership.
    org.remove(&alf, alf.member);
    let newcomer = Uuid::new_v4();
    org.append_roster(
        &roy,
        &RosterEntry::Approve {
            member_id: Uuid::new_v4(),
            handle: "noa".into(),
            role: Role::Member,
            kind: ApprovalKind::Member,
            device_id: newcomer,
            device_pub: DeviceKeys::generate().unwrap().public,
            approved_at: 2,
            approver_device_id: roy.device,
        },
    );
    let without = Roster::verify(&alf.ring, &org.roster, &BTreeSet::new());
    assert!(without.roster.device(newcomer).is_none());
    let with = Roster::verify(&alf.ring, &org.roster, &BTreeSet::from([roy.member]));
    assert!(!with.extra_admins_ignored);
    assert!(with.roster.device(newcomer).is_some());
}

/// M2: the joining device checks its own roster entry before its first push.
#[test]
fn a_joining_device_checks_its_own_roster_entry_before_pushing() {
    let (mut org, alf) = Org::create("alf");
    let roy = org.join(&alf, "roy", None, Role::Member);
    let roster = org.verified(&roy.ring);
    assert_eq!(
        roster.check_own_approval(roy.device, roy.member, "roy", &roy.keys.public),
        Ok(())
    );
    // The server answered the join with another member id, or the approval is not there.
    let other = Uuid::new_v4();
    assert!(roster
        .check_own_approval(roy.device, other, "roy", &roy.keys.public)
        .is_err());
    assert!(roster
        .check_own_approval(roy.device, alf.member, "alf", &roy.keys.public)
        .is_err());
    assert!(roster
        .check_own_approval(roy.device, roy.member, "rex", &roy.keys.public)
        .is_err());
    assert!(roster
        .check_own_approval(roy.device, roy.member, "roy", &alf.keys.public)
        .is_err());
    assert!(roster
        .check_own_approval(Uuid::new_v4(), roy.member, "roy", &roy.keys.public)
        .is_err());
    // A revoked device fails the check.
    org.append_roster(
        &alf,
        &RosterEntry::Revoke {
            member_id: roy.member,
            device_id: Some(roy.device),
            revoked_at: 3,
            by_device_id: alf.device,
        },
    );
    assert!(org
        .verified(&roy.ring)
        .check_own_approval(roy.device, roy.member, "roy", &roy.keys.public)
        .is_err());
}

/// M2: the approver refuses a member approval that reuses a member id its roster holds, and a
/// device approval for a member it does not hold.
#[test]
fn an_approval_reusing_a_member_id_is_refused() {
    let (mut org, alf) = Org::create("alf");
    let roy = org.join(&alf, "roy", None, Role::Member);
    let roster = org.verified(&alf.ring);
    let invite = Invite::create(alf.ring.org(), "inv", "tok", "kit").unwrap();
    let keys = DeviceKeys::generate().unwrap();
    let verified = invite
        .verify_join(&JoinRequest::new(&invite, Uuid::new_v4(), &keys))
        .unwrap();
    let info = |member_id, kind| ApprovalInfo {
        member_id,
        kind,
        role: Role::Member,
        approver_device: alf.device,
        approved_at: 4,
    };
    for taken in [roy.member, alf.member] {
        assert_eq!(
            approve(
                &alf.ring,
                &roster,
                &invite,
                &verified,
                info(taken, ApprovalKind::Member)
            )
            .unwrap_err(),
            Error::Rejected("member id already in the roster")
        );
    }
    assert!(approve(
        &alf.ring,
        &roster,
        &invite,
        &verified,
        info(Uuid::new_v4(), ApprovalKind::Device)
    )
    .is_err());
    // A device invite for roy under another handle is refused too.
    assert!(approve(
        &alf.ring,
        &roster,
        &invite,
        &verified,
        info(roy.member, ApprovalKind::Device)
    )
    .is_err());
    assert!(approve(
        &alf.ring,
        &roster,
        &invite,
        &verified,
        info(Uuid::new_v4(), ApprovalKind::Member)
    )
    .is_ok());
}

/// M1: one roster plaintext. What `keys` seals decodes through `wire`, and what `wire`
/// serialises verifies through `keys`, for every entry type.
#[test]
fn roster_plaintext_round_trips_through_wire_and_keys() {
    use awm_proto::wire::{decode_plaintext, Decoded, RosterPlaintext};
    let (mut org, alf) = Org::create("alf");
    let roy = org.join(&alf, "roy", None, Role::Member);
    let laptop = org.join(&roy, "roy", Some(roy.member), Role::Member);
    org.append_roster(
        &roy,
        &RosterEntry::Revoke {
            member_id: roy.member,
            device_id: Some(laptop.device),
            revoked_at: 5,
            by_device_id: roy.device,
        },
    );
    let recovered = Dev {
        member: alf.member,
        device: Uuid::new_v4(),
        keys: DeviceKeys::generate().unwrap(),
        ring: alf.ring.clone(),
    };
    org.append_roster(
        &recovered,
        &RosterEntry::Recover {
            member_id: alf.member,
            handle: "alf".into(),
            device_id: recovered.device,
            device_pub: recovered.keys.public,
            recovered_at: 6,
        },
    );
    org.remove(&alf, roy.member);
    org.append_roster(
        &alf,
        &RosterEntry::Epoch {
            epoch: 0,
            devices: vec![alf.device],
            created_at: 7,
            by_device_id: alf.device,
        },
    );
    let mut types = BTreeSet::new();
    let mut rebuilt = Vec::new();
    for b in &org.roster {
        let ad = RecordAd {
            org: alf.ring.org(),
            member: b.member,
            device: b.device,
            tag: ROSTER_TAG.into(),
            idx: b.idx,
            record_id: b.record_id,
            epoch: b.epoch,
        };
        let plain = open_record(&alf.ring, &ad, &b.blob).unwrap();
        let Ok(Decoded::Known(p)) = decode_plaintext::<RosterPlaintext>(&plain) else {
            panic!("keys wrote a roster plaintext wire does not decode");
        };
        let v = serde_json::to_value(&p.entry).unwrap();
        types.insert(v["type"].as_str().unwrap().to_string());
        assert_eq!(serde_json::to_vec(&p).unwrap(), plain, "byte for byte");
        // Re-seal the wire value as a record of the same stream: keys verifies it.
        let bytes = serde_json::to_vec(&RosterPlaintext {
            schema: 1,
            entry: p.entry,
        })
        .unwrap();
        rebuilt.push(RosterBlob {
            blob: seal_record(alf.ring.get(b.epoch).unwrap(), &ad, &bytes).unwrap(),
            ..b.clone()
        });
    }
    assert_eq!(
        types,
        BTreeSet::from(["genesis", "approve", "recover", "revoke", "epoch"].map(String::from))
    );
    let report = Roster::verify(&alf.ring, &rebuilt, &BTreeSet::new());
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
    assert_eq!(report.roster, org.verified(&alf.ring));
    assert_eq!(
        report.roster.status(&laptop.listed()),
        DeviceStatus::Revoked
    );
    // The fixtures of the wire crate are entries keys accepts as such.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1");
    for t in ["genesis", "approve", "recover", "revoke", "epoch"] {
        let text = std::fs::read(dir.join(format!("plaintext.roster.{t}.json"))).unwrap();
        let Ok(Decoded::Known(p)) = decode_plaintext::<RosterPlaintext>(&text) else {
            panic!("fixture {t}");
        };
        assert_eq!(serde_json::to_value(&p.entry).unwrap()["type"], t);
    }
}

/// m6: a device approved by a device that is now revoked is wrapped but shown.
#[test]
fn a_device_approved_by_a_revoked_device_is_shown_to_the_rotating_admin() {
    let (mut org, alf) = Org::create("alf");
    let roy = org.join(&alf, "roy", None, Role::Member);
    let laptop = org.join(&roy, "roy", Some(roy.member), Role::Member);
    let phone = org.join(&laptop, "roy", Some(roy.member), Role::Member);
    org.append_roster(
        &roy,
        &RosterEntry::Revoke {
            member_id: roy.member,
            device_id: Some(laptop.device),
            revoked_at: 8,
            by_device_id: roy.device,
        },
    );
    let roster = org.verified(&alf.ring);
    let plan = plan_rotation(
        &alf.ring,
        &roster,
        &[alf.listed(), roy.listed(), laptop.listed(), phone.listed()],
        &BTreeSet::new(),
    );
    assert_eq!(plan.revoked(), &[laptop.device]);
    assert_eq!(plan.approved_by_removed(), &[phone.device]);
    assert!(plan.wrap_to().iter().any(|d| d.device_id == phone.device));
}
