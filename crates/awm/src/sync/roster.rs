//! The roster on the client: every roster record seen is kept in `roster_record`, the roster is
//! verified over those and stored in `team_member` / `team_device`, and the engine's two
//! roster duties (approvals and rotation) run from here (plan-v3-team §4.6 item 7, §5.1;
//! `docs/sync-v1-crypto.md` §6-§8; TM10).
//!
//! A revocation never goes back: `roster_record` is only ever added to, so a restored server
//! cannot undo one, and the two tables are written with `MIN(active)` and `MAX(revoked)`.

use std::collections::BTreeSet;

use anyhow::Result;
use awm_proto::keys::{
    approve, plan_rotation, rotate, ApprovalInfo, ApprovalKind, Invite, JoinRequest, ListedDevice,
    Role as KeyRole, Roster, RosterBlob,
};
use awm_proto::wire::{
    ApproveRequest, DeviceWrap, EpochWrap, ErrorCode, Id, InviteKind, Key32, RotateRequest, B64,
};
use rusqlite::{params, Connection};

use crate::config::AutoApprove;
use crate::sync::push;
use crate::sync::state::Identity;
use crate::sync::Session;

/// Stores one roster record; false when it was already there.
pub fn store_record(
    conn: &Connection,
    member: &str,
    device: &str,
    idx: u64,
    record_id: &str,
    epoch: u32,
    blob: &[u8],
) -> Result<bool> {
    let n = conn.execute(
        "INSERT OR IGNORE INTO roster_record (member_id, device_id, idx, record_id, epoch, blob) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![member, device, idx as i64, record_id, epoch, blob],
    )?;
    Ok(n > 0)
}

/// Every stored roster record.
pub fn blobs(conn: &Connection) -> Result<Vec<RosterBlob>> {
    let mut st = conn.prepare(
        "SELECT member_id, device_id, idx, record_id, epoch, blob FROM roster_record \
         ORDER BY member_id, device_id, idx",
    )?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, u32>(4)?,
            r.get::<_, Vec<u8>>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (member, device, idx, record_id, epoch, blob) = row?;
        let (Ok(member), Ok(device), Ok(record_id)) = (
            Id::parse(&member),
            Id::parse(&device),
            Id::parse(&record_id),
        ) else {
            continue;
        };
        out.push(RosterBlob {
            member: *member.as_uuid(),
            device: *device.as_uuid(),
            idx: idx.max(0) as u64,
            record_id: *record_id.as_uuid(),
            epoch,
            blob,
        });
    }
    Ok(out)
}

/// Verifies the roster over the stored records and writes the result to `team_member` and
/// `team_device`. Returns the roster and the number of records that did not verify.
pub fn verify_and_store(
    conn: &Connection,
    ring: &awm_proto::keys::KeyRing,
    now_ms: i64,
) -> Result<(Roster, usize)> {
    let blobs = blobs(conn)?;
    let report = Roster::verify(ring, &blobs, &BTreeSet::new());
    for (id, m) in report.roster.members() {
        conn.execute(
            "INSERT INTO team_member (member_id, handle, role, active, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(member_id) DO UPDATE SET handle = excluded.handle, role = excluded.role, \
               active = MIN(active, excluded.active), updated_at = excluded.updated_at",
            params![
                Id::from(*id).to_string(),
                m.handle,
                if m.admin { "admin" } else { "member" },
                i64::from(!m.revoked),
                now_ms
            ],
        )?;
    }
    for (id, d) in report.roster.devices() {
        conn.execute(
            "INSERT INTO team_device (device_id, member_id, pubkey, verified, revoked, approver, \
               updated_at) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6) \
             ON CONFLICT(device_id) DO UPDATE SET member_id = excluded.member_id, \
               pubkey = excluded.pubkey, verified = 1, revoked = MAX(revoked, excluded.revoked), \
               approver = excluded.approver, updated_at = excluded.updated_at",
            params![
                Id::from(*id).to_string(),
                Id::from(d.member_id).to_string(),
                String::from(Key32(d.public_key)),
                i64::from(d.revoked),
                (d.approver != *id).then(|| Id::from(d.approver).to_string()),
                now_ms
            ],
        )?;
    }
    Ok((report.roster, report.rejected.len()))
}

/// Whether the verified roster names this device as an approved, unrevoked device of this
/// member (`Roster::check_own_approval`; a device refuses to push content until it does).
pub fn own_approval_ok(roster: &Roster, ident: &Identity) -> bool {
    roster
        .check_own_approval(
            *ident.team.device_id.as_uuid(),
            *ident.team.member_id.as_uuid(),
            &ident.team.handle,
            &ident.device_keys().public,
        )
        .is_ok()
}

/// Whether the roster makes this member an admin.
pub fn own_member_is_admin(roster: &Roster, ident: &Identity) -> bool {
    roster
        .member(*ident.team.member_id.as_uuid())
        .is_some_and(|m| m.admin && !m.revoked)
}

fn to_wrap_item(w: &awm_proto::keys::Wrap) -> EpochWrap {
    EpochWrap {
        epoch: w.epoch,
        wrap: B64(w.blob.clone()),
        auth: Key32(w.auth),
    }
}

/// Approves pending devices (plan-v3-team §4.6 item 7): the device's join MAC must verify under
/// the secret of an invite this device created, and `decide` (`team::auto_approve`) must say
/// yes for that kind of join. The member id and kind come from the invite record, never from
/// the server's pending list (RVT1 M2). Returns how many were approved.
pub fn approve_pending(
    s: &mut Session<'_>,
    decide: &dyn Fn(AutoApprove, bool) -> bool,
) -> Result<usize> {
    let Some(status) = s.status.clone() else {
        return Ok(0);
    };
    let mut approved = 0;
    for p in &status.pending {
        if p.kind == InviteKind::Unknown {
            continue;
        }
        let Some((pos, invite)) =
            s.ident
                .key
                .pending_invites
                .iter()
                .enumerate()
                .find_map(|(i, pi)| {
                    Invite::parse(&pi.invite)
                        .ok()
                        .filter(|inv| inv.invite_id == p.invite_id.to_string())
                        .map(|inv| (i, inv))
                })
        else {
            continue;
        };
        let record = s.ident.key.pending_invites[pos].clone();
        let (kind, member_id, role) = match record.kind.as_str() {
            "device" => {
                let m = match record.member_id.as_deref().map(Id::parse) {
                    Some(Ok(m)) => m,
                    _ => s.ident.team.member_id,
                };
                (ApprovalKind::Device, m, KeyRole::Member)
            }
            "member" => (
                ApprovalKind::Member,
                p.member_id,
                if record.role.as_deref() == Some("admin") {
                    KeyRole::Admin
                } else {
                    KeyRole::Member
                },
            ),
            _ => continue,
        };
        let request = JoinRequest {
            invite_id: invite.invite_id.clone(),
            handle: p.handle.as_str().to_string(),
            device_id: *p.device_id.as_uuid(),
            public_key: p.device_pubkey.0,
            mac: p.join_mac.0,
        };
        let Ok(verified) = invite.verify_join(&request) else {
            crate::sync::state::bump(&s.conn, "dropped.join_mac", 1)?;
            continue;
        };
        let is_own = kind == ApprovalKind::Device && member_id == s.ident.team.member_id;
        if !decide(s.env.config.team.auto_approve, is_own) {
            continue;
        }
        let approval = match approve(
            &s.ring,
            &s.roster,
            &invite,
            &verified,
            ApprovalInfo {
                member_id: *member_id.as_uuid(),
                kind,
                role,
                approver_device: *s.ident.team.device_id.as_uuid(),
                approved_at: s.now_ms() / 1_000,
            },
        ) {
            Ok(a) => a,
            Err(_) => {
                crate::sync::state::bump(&s.conn, "dropped.approval_refused", 1)?;
                continue;
            }
        };
        let body = ApproveRequest {
            wraps: approval.wraps.iter().map(to_wrap_item).collect(),
        };
        s.client.approve_device(p.device_id, &body)?;
        let now = s.now_ms();
        push::queue_roster_entry(&mut s.conn, &s.ident, &s.ring, &approval.roster, now)?;
        s.ident.key.pending_invites.remove(pos);
        s.ident.save_key(&s.env.data_dir)?;
        let (roster, _) = verify_and_store(&s.conn, &s.ring, now)?;
        s.roster = roster;
        approved += 1;
    }
    Ok(approved)
}

/// Rotates the epoch key when the server says so and this device is an admin (item 7): the new
/// key is wrapped only to devices the roster verifies (`plan_rotation`), then the `epoch`
/// roster entry is queued under the new key. Returns whether a rotation happened.
pub fn rotate_if_needed(s: &mut Session<'_>) -> Result<bool> {
    let Some(status) = s.status.clone() else {
        return Ok(false);
    };
    if !status.rotation_needed || !own_member_is_admin(&s.roster, &s.ident) {
        return Ok(false);
    }
    let members = s.client.members()?;
    let listed: Vec<ListedDevice> = members
        .members
        .iter()
        .flat_map(|m| {
            m.devices
                .iter()
                .filter(|d| d.approved && !d.revoked)
                .map(|d| ListedDevice {
                    member_id: *m.member_id.as_uuid(),
                    device_id: *d.device_id.as_uuid(),
                    public_key: d.device_pubkey.0,
                })
        })
        .collect();
    let removed: BTreeSet<_> = s
        .roster
        .members()
        .filter(|(_, m)| m.revoked)
        .map(|(id, _)| *id)
        .collect();
    let plan = plan_rotation(&s.ring, &s.roster, &listed, &removed);
    for (name, n) in [
        ("rotation_unverified", plan.unverified().len()),
        ("rotation_mismatch", plan.mismatch().len()),
        (
            "rotation_approved_by_removed",
            plan.approved_by_removed().len(),
        ),
    ] {
        if n > 0 {
            crate::sync::state::bump(&s.conn, &format!("dropped.{name}"), n as i64)?;
        }
    }
    let rotation = rotate(
        &s.ring,
        &plan,
        *s.ident.team.device_id.as_uuid(),
        s.now_ms() / 1_000,
    )
    .map_err(|e| anyhow::anyhow!("rotation: {e}"))?;
    let req = RotateRequest {
        epoch: plan.new_epoch(),
        wraps: rotation
            .wraps
            .iter()
            .map(|w| DeviceWrap {
                device_id: Id::from(w.device_id),
                wrap: B64(w.blob.clone()),
                auth: Key32(w.auth),
            })
            .collect(),
    };
    match s.client.rotate_keys(&req) {
        Ok(()) => {}
        Err(e) if e.code() == Some(ErrorCode::EpochConflict) => {
            // Another admin rotated first: take its key and rotate again only if still needed.
            push::refresh_keys(s)?;
            return Ok(false);
        }
        Err(e) => return Err(e.into()),
    }
    s.ring
        .adopt_own_rotation(&rotation)
        .map_err(|e| anyhow::anyhow!("rotation: {e}"))?;
    s.ident.key.set_ring(&s.ring);
    s.ident.save_key(&s.env.data_dir)?;
    let now = s.now_ms();
    push::queue_roster_entry(&mut s.conn, &s.ident, &s.ring, &rotation.roster, now)?;
    let (roster, _) = verify_and_store(&s.conn, &s.ring, now)?;
    s.roster = roster;
    if let Some(st) = s.status.as_mut() {
        st.current_epoch = plan.new_epoch();
        st.rotation_needed = false;
    }
    Ok(true)
}
