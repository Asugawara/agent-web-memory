//! Organisation fixtures of the store-level suites (`backup.rs`, `delete_retention.rs`,
//! `store_conformance.rs`, `store_pg.rs`), shared through
//! `#[path = "support/org.rs"] mod fixtures;`: the clock constants, the token-hash scheme, an
//! organisation with one admin, invites and joins, and the base64url helper.

#![allow(dead_code)]

use awm_proto::wire::{EpochWrap, Handle, Id, InviteKind, Key32, Version, B64};
use awm_server::store::{checksum, Actor, NewBootstrap, NewInvite, NewJoin, OrgDefaults, Store};

/// The time the fixtures start at (Unix seconds).
pub const T0: i64 = 1_790_000_000;
pub const DAY: i64 = 86_400;

pub fn h(s: &str) -> String {
    checksum(s.as_bytes())
}

pub fn handle(s: &str) -> Handle {
    Handle::parse(s).unwrap()
}

pub fn defaults() -> OrgDefaults {
    OrgDefaults {
        retention_days: 365,
        min_client: Version::new(0, 2, 0),
        max_members: 100,
    }
}

pub fn device_token_hash(device: Id) -> String {
    h(&format!("device-token-{device}"))
}

pub fn invite_token_hash(invite: Id) -> String {
    h(&format!("invite-token-{invite}"))
}

/// Unpadded base64url, the wire encoding of every binary field.
pub fn b64(bytes: &[u8]) -> String {
    String::from(B64(bytes.to_vec()))
}

/// An organisation with its first admin (handle `alf`, one approved device).
pub struct Org {
    pub org_id: Id,
    pub admin: Actor,
}

/// Bootstraps an organisation at [`T0`] with the bootstrap token `h("bootstrap")`.
pub async fn bootstrap(s: &dyn Store) -> Org {
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

/// An invite by `by` at [`T0`], good for 7 days.
pub async fn invite(s: &dyn Store, by: Actor, kind: InviteKind, name: &str) -> Id {
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

pub fn join_req(invite_id: Id, name: &str, device: Id, n: u8) -> NewJoin {
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

/// An invite by `by` and a join; returns the new device's actor (not yet approved).
pub async fn join(s: &dyn Store, by: Actor, kind: InviteKind, name: &str, n: u8) -> Actor {
    let inv = invite(s, by, kind, name).await;
    let device = Id::new_v4();
    let joined = s.join(join_req(inv, name, device, n)).await.unwrap();
    Actor {
        member_id: joined.member_id,
        device_id: device,
        admin: false,
    }
}

/// A wrap of every epoch up to the organisation's current one, for `approve_device`.
pub async fn wraps_for(s: &dyn Store) -> Vec<EpochWrap> {
    let epoch = s.org(T0).await.unwrap().unwrap().current_epoch;
    (0..=epoch)
        .map(|e| EpochWrap {
            epoch: e,
            wrap: B64(vec![e as u8; 89]),
            auth: Key32([7; 32]),
        })
        .collect()
}
