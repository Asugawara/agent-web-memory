//! Re-seeding after a server restore (plan-v3-team §3.9.5, §4.6 step 5; `docs/sync-v1.md` §11;
//! TM10).
//!
//! `GET /v1/status` carries `generation`, a random id that `awm serve restore` changes. A client
//! that sees one it has not stored repairs the restored server from what it holds:
//!
//! 1. as a reader: lowers its heads to the server's and re-applies the kept deletion stream;
//! 2. as an admin, first: re-applies the roster's removals and revocations, re-uploads the wraps
//!    of every epoch above the server's, to verified roster devices only, and completes the
//!    restore;
//! 3. re-sends the `team:` tombstones it may delete;
//! 4. as an author: re-pushes every own item above the server's head, a record re-sealed under
//!    the current epoch at the same idx and id, or a marker for one it deleted since;
//! 5. stores the generation.
//!
//! Every step is idempotent, so a server that fakes a new generation only causes repeated work.

use std::collections::BTreeSet;

use anyhow::{anyhow, Result};
use awm_proto::crypto::{seal_record, OsRng, Rng};
use awm_proto::keys::{plan_rotation, rotate_with, KeyRing, ListedDevice, ROSTER_TAG};
use awm_proto::wire::{
    DeleteRequest, DeviceWrap, ErrorCode, Id, Key32, RotateRequest, StatusResponse, B64,
};
use rusqlite::{params, OptionalExtension};

use crate::sync::payload::{self, Share, ShareCtx};
use crate::sync::push::{self, own_ad};
use crate::sync::state;
use crate::sync::{roster, Session};

/// Every tag a device writes.
const TAGS: [&str; 5] = ["roster", "policy", "rec", "flag", "stats"];

/// An `Rng` whose first 32-byte request returns a given key, so that [`rotate_with`] wraps an
/// epoch key that already exists instead of making a new one. Everything else (ephemeral keys,
/// nonces) comes from the operating system.
struct ReplayRng {
    first: Option<[u8; 32]>,
}

impl Rng for ReplayRng {
    fn fill(&mut self, out: &mut [u8]) -> std::result::Result<(), awm_proto::crypto::Error> {
        if out.len() == 32 {
            if let Some(k) = self.first.take() {
                out.copy_from_slice(&k);
                return Ok(());
            }
        }
        OsRng.fill(out)
    }
}

/// Runs the whole re-seed for the generation in `s.status`, then stores it.
pub fn run(s: &mut Session<'_>) -> Result<()> {
    let status = s
        .status
        .clone()
        .ok_or_else(|| anyhow!("re-seed without a status"))?;
    reader_reset(s, &status)?;
    if roster::own_member_is_admin(&s.roster, &s.ident) {
        admin_steps(s, &status)?;
    }
    resend_tombstones(s, &status)?;
    for tag in TAGS {
        author_stream(s, tag)?;
    }
    state::set(&s.conn, state::GENERATION, &status.generation.to_string())?;
    s.report.reseeded = true;
    Ok(())
}

/// Step 1: heads of other devices' streams go down to the server's, and the deletion stream is
/// re-applied from its oldest kept entry.
fn reader_reset(s: &mut Session<'_>, status: &StatusResponse) -> Result<()> {
    let own = s.ident.team.device_id.to_string();
    let mut st = s.conn.prepare(
        "SELECT member_id, device_id, tag, head_idx FROM sync_stream WHERE device_id <> ?1",
    )?;
    let rows: Vec<(String, String, String, i64)> = st
        .query_map([&own], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<std::result::Result<_, _>>()?;
    drop(st);
    for (member, device, tag, head) in rows {
        let server = match (Id::parse(&member), Id::parse(&device)) {
            (Ok(m), Ok(d)) => push::head_of(status, m, d, &tag),
            _ => -1,
        };
        if server < head {
            s.conn.execute(
                "UPDATE sync_stream SET head_idx = ?4 WHERE member_id = ?1 AND device_id = ?2 AND tag = ?3",
                params![member, device, tag, server],
            )?;
        }
    }
    state::set(
        &s.conn,
        state::DELETION_HEAD,
        &(status.deletions.oldest - 1).max(-1).to_string(),
    )
}

/// Step 2: removals and revocations from the verified roster, then the wraps of the epochs the
/// server lacks, then `POST /v1/restore/complete`.
fn admin_steps(s: &mut Session<'_>, status: &StatusResponse) -> Result<()> {
    let members = s.client.members()?;
    let removed: BTreeSet<_> = s
        .roster
        .members()
        .filter(|(_, m)| m.revoked)
        .map(|(id, _)| *id)
        .collect();
    for (id, _) in s.roster.members().filter(|(_, m)| m.revoked) {
        let id = Id::from(*id);
        if members
            .members
            .iter()
            .any(|m| m.member_id == id && m.active)
        {
            s.client.remove_member(id)?;
            state::bump(&s.conn, "reseed_removed", 1)?;
        }
    }
    for (id, d) in s.roster.devices() {
        if !d.revoked || removed.contains(&d.member_id) {
            continue;
        }
        let id = Id::from(*id);
        let live = members
            .members
            .iter()
            .flat_map(|m| m.devices.iter())
            .any(|dev| dev.device_id == id && !dev.revoked);
        if live {
            s.client.revoke_device(id)?;
        }
    }
    // The server's view after the removals: wraps go only to devices both sides agree on.
    let members = s.client.members()?;
    let listed: Vec<ListedDevice> = members
        .members
        .iter()
        .filter(|m| m.active)
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
    let org = s.ring.org();
    for epoch in (status.current_epoch + 1)..=s.ring.current_epoch() {
        let Some(key) = s.ring.get(epoch) else { break };
        let below: Vec<_> = s
            .ring
            .epochs()
            .filter(|k| k.epoch() < epoch)
            .cloned()
            .collect();
        let tmp = KeyRing::from_keys(org, below).map_err(|e| anyhow!("re-seed: {e}"))?;
        let plan = plan_rotation(&tmp, &s.roster, &listed, &removed);
        let mut rng = ReplayRng {
            first: Some(*key.expose_secret()),
        };
        let rotation = rotate_with(
            &mut rng,
            &tmp,
            &plan,
            *s.ident.team.device_id.as_uuid(),
            s.now_ms() / 1_000,
        )
        .map_err(|e| anyhow!("re-seed: {e}"))?;
        let req = RotateRequest {
            epoch,
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
            // Another admin got there first.
            Err(e) if e.code() == Some(ErrorCode::EpochConflict) => break,
            Err(e) => return Err(e.into()),
        }
    }
    if status.restore_pending {
        s.client.restore_complete(status.generation)?;
    }
    Ok(())
}

/// Step 3: `POST /v1/delete` for the `team:` tombstones of the last `retention_days` + 30 days.
/// A member may delete only their own records, so a member sends the ids of records they
/// pushed or deleted from another of their machines; an admin sends all of them except
/// teammates' records deleted on this machine only (`apply::resend_ids`, TM11). A refused
/// batch is not an error.
fn resend_tombstones(s: &mut Session<'_>, status: &StatusResponse) -> Result<()> {
    let cutoff = s.now_ms() - (i64::from(status.settings.retention_days) + 30) * 86_400_000;
    let admin = roster::own_member_is_admin(&s.roster, &s.ident);
    let ids: Vec<Id> = crate::sync::apply::resend_ids(&s.conn, cutoff, admin)?
        .iter()
        .filter_map(|v| Id::parse(v).ok())
        .collect();
    for chunk in ids.chunks(awm_proto::wire::limits::DELETE_IDS) {
        match s.client.delete(&DeleteRequest::Ids(chunk.to_vec())) {
            Ok(_) => {}
            Err(e) if matches!(e.status(), Some(400 | 403)) => {
                state::bump(&s.conn, "dropped.delete_refused", chunk.len() as i64)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn own_server_head(status: &StatusResponse, s: &Session<'_>, tag: &str) -> i64 {
    push::head_of(status, s.ident.team.member_id, s.ident.team.device_id, tag)
}

/// Makes the stored item (tag, idx) ready to send under the current epoch: a record whose blob
/// was dropped after its push is rebuilt from its `event` row; an item whose row is gone
/// becomes a marker.
fn materialize(s: &mut Session<'_>, tag: &str, idx: u64) -> Result<()> {
    let deleted: Option<i64> = s
        .conn
        .query_row(
            "SELECT deleted FROM sync_own WHERE tag = ?1 AND idx = ?2",
            params![tag, idx as i64],
            |r| r.get(0),
        )
        .optional()?;
    if deleted != Some(0) {
        // A marker already, or nothing stored under this idx.
        return Ok(());
    }
    let Some(p) = push::load_pending(&s.conn, tag, idx)? else {
        return Ok(());
    };
    if p.blob.is_some() {
        return push::reseal(s, tag, idx);
    }
    if tag != "rec" {
        return mark_marker(s, tag, idx);
    }
    // A rec item whose blob went away after its push: rebuild from the row.
    let event_id: Option<i64> = s
        .conn
        .query_row(
            "SELECT id FROM event WHERE sync_id = ?1 AND origin = 'local'",
            [p.id.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(event_id) = event_id else {
        return mark_marker(s, tag, idx);
    };
    let Some((rec, repo_key)) = push::load_record(&s.conn, event_id)? else {
        return mark_marker(s, tag, idx);
    };
    let share: String = s.conn.query_row(
        "SELECT shareable FROM event WHERE id = ?1",
        [event_id],
        |r| r.get(0),
    )?;
    let policy = push::load_policy(&s.conn, push::load_opt_in(&s.conn, &[])?)?;
    let ctx = ShareCtx::new(
        if share == "link" {
            Share::Link
        } else {
            Share::Full
        },
        repo_key,
        &s.env.config,
        &policy,
    );
    let Ok(built) = payload::build(&rec, &ctx) else {
        return mark_marker(s, tag, idx);
    };
    let key = s.ring.current();
    let blob = seal_record(
        key,
        &own_ad(&s.ident, &s.ring, tag, idx, p.id, key.epoch()),
        &built.plaintext,
    )
    .map_err(|e| anyhow!("cannot seal a record: {e}"))?;
    s.conn.execute(
        "UPDATE sync_own SET epoch = ?1, blob = ?2 WHERE tag = ?3 AND idx = ?4",
        params![key.epoch(), blob, tag, idx as i64],
    )?;
    Ok(())
}

fn mark_marker(s: &Session<'_>, tag: &str, idx: u64) -> Result<()> {
    s.conn.execute(
        "UPDATE sync_own SET deleted = 1, blob = NULL, epoch = NULL WHERE tag = ?1 AND idx = ?2",
        params![tag, idx as i64],
    )?;
    Ok(())
}

/// Step 4 for one tag: every stored own item above the server's head, in order. Also the
/// answer to a 409 `stream_conflict` whose head is below ours (the earlier items were lost).
pub fn author_stream(s: &mut Session<'_>, tag: &str) -> Result<usize> {
    if tag == "stats" && !s.env.config.team.share_stats {
        return Ok(0);
    }
    if tag != ROSTER_TAG && !roster::own_approval_ok(&s.roster, &s.ident) {
        return Ok(0);
    }
    let status = s.client.status()?;
    let head = own_server_head(&status, s, tag);
    s.status = Some(status);
    let mut st = s
        .conn
        .prepare("SELECT idx FROM sync_own WHERE tag = ?1 AND idx > ?2 ORDER BY idx")?;
    let idxs: Vec<u64> = st
        .query_map(params![tag, head], |r| r.get::<_, i64>(0))?
        .filter_map(|r| r.ok())
        .map(|i| i as u64)
        .collect();
    drop(st);
    if idxs.is_empty() {
        return Ok(0);
    }
    // The server holds the stream contiguously, so the first item must follow its head.
    if idxs[0] as i64 != head + 1 {
        return Ok(0);
    }
    for idx in &idxs {
        materialize(s, tag, *idx)?;
    }
    let keys: Vec<(String, u64)> = idxs.iter().map(|i| (tag.to_string(), *i)).collect();
    match push::send_keys(s, &keys)? {
        Ok(n) => {
            s.report.pushed += n;
            Ok(n)
        }
        Err(push::SendStop::NeedsReseed(_)) => Ok(0),
    }
}
