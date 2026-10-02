//! Push step of `awm sync` (plan-v3-team §4.6 steps 3 and 4; `docs/sync-v1.md` §9; TM10).
//!
//! Every item a device pushes lives in `sync_own` under (tag, idx) with the exact envelope
//! that goes on the wire. An item is written there, with its outbox row (`ref = "tag:idx"`)
//! and the stream head, in one short transaction **before** the request (§9.3, §16.1), so a
//! retry resends the stored bytes: the server answers 200 `replayed` to a request it already
//! stored, whether or not the epoch moved on, and nothing is duplicated.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};
use awm_proto::crypto::{open_record, seal_record, RecordAd};
use awm_proto::keys::{RosterEntry, ROSTER_TAG};
use awm_proto::wire::{
    ErrorCode, FlagPlaintext, Id, PushDeleted, PushItem, PushRecord, PushRequest, StatsPlaintext,
    Tag, B64,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::config::Config;
use crate::note::{Status, Tool};
use crate::record::{Agent, Record, ResultRow};
use crate::sync::eligible::{self, Eligibility, OptIn, Project, RuleKind, ShareRule, TeamPolicy};
use crate::sync::payload::{self, Share, ShareCtx};
use crate::sync::state::{self, Identity};
use crate::sync::{roster, Backfill, Session};

/// At most this many items in one request (sync-v1 §12).
const BATCH_ITEMS: usize = 100;
/// The encoded request stays under 1.5 MiB with room for the envelope around the items.
const BATCH_BYTES: usize = 1_400_000;
/// Rows looked at per run.
const SCAN_LIMIT: i64 = 1_000;

// ---------------------------------------------------------------------------------------
// Queueing

/// The head of this device's own stream `tag`: the highest idx queued (-1 when none).
pub fn own_head(conn: &Connection, ident: &Identity, tag: &str) -> Result<i64> {
    Ok(conn
        .query_row(
            "SELECT head_idx FROM sync_stream WHERE member_id = ?1 AND device_id = ?2 AND tag = ?3",
            params![
                ident.team.member_id.to_string(),
                ident.team.device_id.to_string(),
                tag
            ],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(-1))
}

/// The AD of an item of this device's own stream.
pub fn own_ad(
    ident: &Identity,
    ring: &awm_proto::keys::KeyRing,
    tag: &str,
    idx: u64,
    id: Id,
    epoch: u32,
) -> RecordAd {
    RecordAd {
        org: ring.org(),
        member: *ident.team.member_id.as_uuid(),
        device: *ident.team.device_id.as_uuid(),
        tag: tag.to_string(),
        idx,
        record_id: *id.as_uuid(),
        epoch,
    }
}

fn set_head(tx: &Connection, ident: &Identity, tag: &str, idx: u64) -> Result<()> {
    tx.execute(
        "INSERT INTO sync_stream (member_id, device_id, tag, head_idx) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(member_id, device_id, tag) DO UPDATE SET head_idx = MAX(head_idx, excluded.head_idx)",
        params![
            ident.team.member_id.to_string(),
            ident.team.device_id.to_string(),
            tag,
            idx as i64
        ],
    )?;
    Ok(())
}

/// Queues one item of another tag (`flag`, `stats`, `policy`, `roster`): assigns the next idx,
/// seals under the current epoch, and writes `sync_own`, the outbox row and the head in one
/// transaction. Returns the idx and the record id.
pub fn queue_item(
    conn: &mut Connection,
    ident: &Identity,
    ring: &awm_proto::keys::KeyRing,
    tag: &str,
    kind: &str,
    plaintext: &[u8],
    now_ms: i64,
) -> Result<(u64, Id)> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let idx = (own_head(&tx, ident, tag)? + 1) as u64;
    let id = Id::new_v4();
    let key = ring.current();
    let blob = seal_record(
        key,
        &own_ad(ident, ring, tag, idx, id, key.epoch()),
        plaintext,
    )
    .map_err(|e| anyhow!("cannot seal a {tag} record: {e}"))?;
    tx.execute(
        "INSERT INTO sync_own (tag, idx, record_id, epoch, blob, deleted) VALUES (?1, ?2, ?3, ?4, ?5, 0)",
        params![tag, idx as i64, id.to_string(), key.epoch(), blob],
    )?;
    tx.execute(
        "INSERT INTO sync_outbox (kind, ref, created_at) VALUES (?1, ?2, ?3)",
        params![kind, format!("{tag}:{idx}"), now_ms],
    )?;
    if tag == ROSTER_TAG {
        roster::store_record(
            &tx,
            &ident.team.member_id.to_string(),
            &ident.team.device_id.to_string(),
            idx,
            &id.to_string(),
            key.epoch(),
            &blob,
        )?;
    }
    set_head(&tx, ident, tag, idx)?;
    tx.commit()?;
    Ok((idx, id))
}

/// Queues a roster entry this device wrote (genesis, approval, revocation, epoch, recovery) for
/// push, and keeps it in `roster_record`. `awm team` (TM12) calls this after it makes the entry.
pub fn queue_roster_entry(
    conn: &mut Connection,
    ident: &Identity,
    ring: &awm_proto::keys::KeyRing,
    entry: &RosterEntry,
    now_ms: i64,
) -> Result<u64> {
    let plain = serde_json::to_vec(&awm_proto::wire::RosterPlaintext {
        schema: awm_proto::keys::ROSTER_SCHEMA,
        entry: entry.clone(),
    })?;
    // An `epoch` entry is sealed under the epoch it names, which is the ring's current one.
    queue_item(conn, ident, ring, ROSTER_TAG, "roster", &plain, now_ms).map(|(idx, _)| idx)
}

/// Queues a quarantine (or user) flag for a teammate's record.
pub fn queue_flag(
    conn: &mut Connection,
    ident: &Identity,
    ring: &awm_proto::keys::KeyRing,
    record_id: Id,
    reason: awm_proto::wire::FlagReason,
    detail: Option<&str>,
    now_ms: i64,
) -> Result<()> {
    let detail = detail.map(|d| {
        let (clean, _) = crate::redact::redact(d, &[]);
        clean.chars().take(200).collect::<String>()
    });
    let plain = serde_json::to_vec(&FlagPlaintext {
        schema: payload::SCHEMA,
        record_id,
        reason,
        detail,
        created_at: now_ms / 1_000,
    })?;
    queue_item(conn, ident, ring, "flag", "flag", &plain, now_ms).map(|_| ())
}

/// The hook for TM14's daily stats record: queued like any item and sent only when
/// `team.share_stats` is on.
pub fn queue_stats(
    conn: &mut Connection,
    ident: &Identity,
    ring: &awm_proto::keys::KeyRing,
    stats: &StatsPlaintext,
    now_ms: i64,
) -> Result<()> {
    let plain = serde_json::to_vec(stats)?;
    queue_item(conn, ident, ring, "stats", "stats", &plain, now_ms).map(|_| ())
}

// ---------------------------------------------------------------------------------------
// Eligible rows

/// One local row that may leave the machine.
pub struct Candidate {
    pub event_id: i64,
    pub share: Share,
    pub record: Record,
    pub repo_key: Option<String>,
}

/// What a scan found.
#[derive(Default)]
pub struct Scan {
    pub candidates: Vec<Candidate>,
    /// Rows that stay local, by the counter name of `Eligibility::counter()`.
    pub counts: BTreeMap<String, u64>,
}

fn tool_of(s: &str) -> Option<Tool> {
    match s {
        "WebSearch" => Some(Tool::WebSearch),
        "WebFetch" => Some(Tool::WebFetch),
        _ => None,
    }
}

fn status_of(s: &str) -> Option<Status> {
    match s {
        "ok" => Some(Status::Ok),
        "dead_end" => Some(Status::DeadEnd),
        "refusal" => Some(Status::Refusal),
        "placeholder" => Some(Status::Placeholder),
        _ => None,
    }
}

/// A row of `event` as a [`Record`], with its results, and its `repo_key`.
pub fn load_record(conn: &Connection, id: i64) -> Result<Option<(Record, Option<String>)>> {
    let row = conn
        .query_row(
            "SELECT tool_use_id, tool, session_id, agent_id, agent_type, cwd_hash, created_at, \
             query, url, url_norm, fetch_prompt, http_code, bytes, duration_ms, status, summary, \
             match_text, source, quarantined, quarantine_reason, agent, repo_key \
             FROM event WHERE id = ?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, Option<String>>(9)?,
                    r.get::<_, Option<String>>(10)?,
                    r.get::<_, Option<i64>>(11)?,
                    r.get::<_, Option<i64>>(12)?,
                    r.get::<_, Option<i64>>(13)?,
                    r.get::<_, String>(14)?,
                    r.get::<_, Option<String>>(15)?,
                    r.get::<_, String>(16)?,
                    r.get::<_, String>(17)?,
                    r.get::<_, i64>(18)?,
                    r.get::<_, Option<String>>(19)?,
                    r.get::<_, String>(20)?,
                    r.get::<_, Option<String>>(21)?,
                ))
            },
        )
        .optional()?;
    let Some(t) = row else {
        return Ok(None);
    };
    let (Some(tool), Some(status)) = (tool_of(&t.1), status_of(&t.14)) else {
        return Ok(None);
    };
    let mut st = conn.prepare(
        "SELECT rank, url, url_norm, title FROM result WHERE event_id = ?1 ORDER BY rank",
    )?;
    let results = st
        .query_map([id], |r| {
            Ok(ResultRow {
                rank: r.get(0)?,
                url: r.get(1)?,
                url_norm: r.get(2)?,
                title: r.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let quarantine_reason =
        t.19.clone()
            .or_else(|| (t.18 != 0).then(|| "quarantined".to_string()));
    let rec = Record {
        tool_use_id: t.0,
        tool,
        session_id: t.2,
        agent_id: t.3,
        agent_type: t.4,
        cwd_hash: t.5,
        created_at: t.6,
        query: t.7,
        url: t.8,
        url_norm: t.9,
        fetch_prompt: t.10,
        http_code: t.11,
        bytes: t.12,
        duration_ms: t.13,
        status,
        summary: t.15,
        match_text: t.16,
        source: t.17,
        agent: if t.20 == "codex" {
            Agent::Codex
        } else {
            Agent::Claude
        },
        results,
        quarantine_reason,
    };
    Ok(Some((rec, t.21)))
}

/// The local opt-in state (`share_rule`, `project`, `sync_state.share_all_since`).
pub fn load_opt_in(conn: &Connection, backfill_values: &[String]) -> Result<OptIn> {
    let mut rules = Vec::new();
    let mut st = conn.prepare("SELECT kind, value, created_at FROM share_rule")?;
    for row in st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })? {
        let (kind, value, created_at) = row?;
        rules.push(ShareRule {
            kind: if kind == "repo" {
                RuleKind::Repo
            } else {
                RuleKind::Cwd
            },
            value,
            created_at,
        });
    }
    let mut projects = Vec::new();
    let mut st = conn.prepare("SELECT cwd_hash, repo_key FROM project")?;
    for row in st.query_map([], |r| {
        Ok(Project {
            cwd_hash: r.get(0)?,
            repo_key: r.get(1)?,
        })
    })? {
        projects.push(row?);
    }
    Ok(OptIn {
        rules,
        projects,
        backfill: backfill_values.to_vec(),
        share_all_since: state::get_i64(conn, state::SHARE_ALL_SINCE)?,
    })
}

/// The effective policy: the highest `policy` record seen, plus the local opt-in.
pub fn load_policy(conn: &Connection, opt_in: OptIn) -> Result<TeamPolicy> {
    let mut policy = match state::get(conn, state::POLICY_JSON)? {
        Some(json) => match serde_json::from_str::<awm_proto::wire::PolicyPlaintext>(&json) {
            Ok(p) => TeamPolicy::from_wire(&p),
            Err(_) => TeamPolicy::default(),
        },
        None => TeamPolicy::default(),
    };
    policy.opt_in = opt_in;
    Ok(policy)
}

/// Selects the local rows that may be pushed and runs `eligible::check` on each. Nothing is
/// written.
pub fn scan(
    conn: &Connection,
    cfg: &Config,
    backfill: Option<&Backfill>,
    limit: i64,
) -> Result<Scan> {
    let values: Vec<String> = backfill.map(|b| b.values.clone()).unwrap_or_default();
    let opt_in = load_opt_in(conn, &values)?;
    let share_all = cfg.team.share_all_projects && opt_in.share_all_since.is_some();
    let all_since = opt_in.share_all_since.unwrap_or(i64::MAX);
    let since = backfill.and_then(|b| b.since_ms).unwrap_or(0);
    let policy = load_policy(conn, opt_in)?;
    let bf_json = serde_json::to_string(&values)?;
    let mut st = conn.prepare(
        "SELECT e.id FROM event e \
         WHERE e.origin = 'local' AND e.shareable = 'no' AND e.sync_id IS NULL \
           AND e.pushed_at IS NULL AND e.status IN ('ok','dead_end','refusal') \
           AND e.quarantined = 0 AND e.created_at >= :since \
           AND ((:share_all = 1 AND e.created_at >= :all_since) \
             OR EXISTS (SELECT 1 FROM share_rule r \
                WHERE (e.created_at >= r.created_at \
                       OR r.value IN (SELECT value FROM json_each(:bf))) \
                  AND ((r.kind = 'cwd' AND r.value = e.cwd_hash) \
                    OR (r.kind = 'repo' AND EXISTS (SELECT 1 FROM project p \
                          WHERE p.cwd_hash = e.cwd_hash AND p.repo_key = r.value))))) \
         ORDER BY e.id LIMIT :limit",
    )?;
    let ids: Vec<i64> = st
        .query_map(
            rusqlite::named_params! {
                ":since": since,
                ":share_all": i64::from(share_all),
                ":all_since": all_since,
                ":bf": bf_json,
                ":limit": limit,
            },
            |r| r.get(0),
        )?
        .collect::<Result<_, _>>()?;
    let mut scan = Scan::default();
    for id in ids {
        let Some((rec, repo_key)) = load_record(conn, id)? else {
            continue;
        };
        match eligible::check(&rec, cfg, &policy) {
            Eligibility::Share(c) | Eligibility::Replaced(c) => scan.candidates.push(Candidate {
                event_id: id,
                share: c.share,
                record: c.record,
                repo_key,
            }),
            Eligibility::Blocked(b) => {
                *scan.counts.entry(b.counter().to_string()).or_insert(0) += 1
            }
            Eligibility::Skipped(sk) => {
                *scan.counts.entry(sk.counter().to_string()).or_insert(0) += 1
            }
        }
    }
    Ok(scan)
}

/// Builds, seals and queues the candidates in batches of at most 100: `sync_id`, `sync_idx`,
/// the `sync_own` row, the outbox row and the stream head, one short transaction per batch,
/// before any request. Returns how many were queued.
pub fn queue_records(s: &mut Session<'_>, scan: &mut Scan) -> Result<usize> {
    let cfg = s.env.config.clone();
    let policy = load_policy(&s.conn, load_opt_in(&s.conn, &[])?)?;
    let mut queued = 0;
    let mut built: Vec<(i64, Vec<u8>)> = Vec::new();
    for c in scan.candidates.drain(..) {
        let ctx = ShareCtx::new(c.share, c.repo_key.clone(), &cfg, &policy);
        match payload::build(&c.record, &ctx) {
            Ok(p) if p.fits() => built.push((c.event_id, p.plaintext)),
            _ => *scan.counts.entry("build_error".into()).or_insert(0) += 1,
        }
    }
    let now = s.now_ms();
    for chunk in built.chunks(BATCH_ITEMS) {
        let tx = s
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut idx = (own_head(&tx, &s.ident, "rec")? + 1) as u64;
        let key = s.ring.current();
        for (event_id, plaintext) in chunk {
            let id = Id::new_v4();
            let blob = seal_record(
                key,
                &own_ad(&s.ident, &s.ring, "rec", idx, id, key.epoch()),
                plaintext,
            )
            .map_err(|e| anyhow!("cannot seal a record: {e}"))?;
            let n = tx.execute(
                "UPDATE event SET sync_id = ?1, sync_idx = ?2 WHERE id = ?3 AND sync_id IS NULL",
                params![id.to_string(), idx as i64, event_id],
            )?;
            if n == 0 {
                continue;
            }
            tx.execute(
                "INSERT INTO sync_own (tag, idx, record_id, epoch, blob, deleted) \
                 VALUES ('rec', ?1, ?2, ?3, ?4, 0)",
                params![idx as i64, id.to_string(), key.epoch(), blob],
            )?;
            tx.execute(
                "INSERT INTO sync_outbox (kind, ref, created_at) VALUES ('record', ?1, ?2)",
                params![format!("rec:{idx}"), now],
            )?;
            set_head(&tx, &s.ident, "rec", idx)?;
            idx += 1;
            queued += 1;
        }
        tx.commit()?;
    }
    Ok(queued)
}

// ---------------------------------------------------------------------------------------
// Sending

/// One item as stored in `sync_own`.
#[derive(Debug, Clone)]
pub struct Pending {
    pub tag: String,
    pub idx: u64,
    pub id: Id,
    pub epoch: Option<u32>,
    /// `None`: a deletion marker.
    pub blob: Option<Vec<u8>>,
}

pub fn load_pending(conn: &Connection, tag: &str, idx: u64) -> Result<Option<Pending>> {
    let row = conn
        .query_row(
            "SELECT record_id, epoch, blob, deleted FROM sync_own WHERE tag = ?1 AND idx = ?2",
            params![tag, idx as i64],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<u32>>(1)?,
                    r.get::<_, Option<Vec<u8>>>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((id, epoch, blob, deleted)) = row else {
        return Ok(None);
    };
    let Ok(id) = Id::parse(&id) else {
        return Ok(None);
    };
    Ok(Some(Pending {
        tag: tag.to_string(),
        idx,
        id,
        epoch,
        blob: if deleted != 0 { None } else { blob },
    }))
}

fn item_of(p: &Pending) -> Result<PushItem> {
    let tag = Tag::parse(&p.tag).map_err(|e| anyhow!("{e}"))?;
    Ok(match (&p.blob, p.epoch) {
        (Some(blob), Some(epoch)) => PushItem::Record(PushRecord {
            tag,
            idx: p.idx,
            id: p.id,
            epoch,
            blob: B64(blob.clone()),
        }),
        _ => PushItem::Deleted(PushDeleted {
            tag,
            idx: p.idx,
            id: p.id,
        }),
    })
}

fn size_of(p: &Pending) -> usize {
    p.blob.as_ref().map_or(0, |b| b.len().div_ceil(3) * 4) + 160
}

/// Fetches the wraps of epochs above the ring's and accepts them in order. Returns whether the
/// ring advanced; the new keys are saved to `team.key`.
pub fn refresh_keys(s: &mut Session<'_>) -> Result<bool> {
    s.keys_refreshed = true;
    let resp = s.client.keys()?;
    let before = s.ring.current_epoch();
    let mut wraps = resp.wraps;
    wraps.sort_by_key(|w| w.epoch);
    for w in wraps.iter().filter(|w| w.epoch > before) {
        let wrap = awm_proto::keys::Wrap {
            device_id: *s.ident.team.device_id.as_uuid(),
            epoch: w.epoch,
            approver_device: *w.created_by.as_uuid(),
            blob: w.wrap.0.clone(),
            auth: w.auth.0,
        };
        // A wrap that does not verify (a server-made one) is skipped, never accepted.
        if s.ring
            .accept_rotation(*s.ident.team.device_id.as_uuid(), &s.device, &wrap)
            .is_err()
        {
            state::bump(&s.conn, "dropped.bad_wrap", 1)?;
            break;
        }
    }
    let advanced = s.ring.current_epoch() > before;
    if advanced {
        s.ident.key.set_ring(&s.ring);
        s.ident.save_key(&s.env.data_dir)?;
    }
    Ok(advanced)
}

/// Re-seals the stored item (tag, idx) under the current epoch with the same idx and id.
pub(crate) fn reseal(s: &mut Session<'_>, tag: &str, idx: u64) -> Result<()> {
    let Some(p) = load_pending(&s.conn, tag, idx)? else {
        return Ok(());
    };
    let (Some(blob), Some(epoch)) = (p.blob, p.epoch) else {
        return Ok(());
    };
    if epoch == s.ring.current_epoch() {
        return Ok(());
    }
    let plain = open_record(
        &s.ring,
        &own_ad(&s.ident, &s.ring, tag, idx, p.id, epoch),
        &blob,
    )
    .map_err(|e| anyhow!("cannot re-seal a stored item: {e}"))?;
    let key = s.ring.current();
    let fresh = seal_record(
        key,
        &own_ad(&s.ident, &s.ring, tag, idx, p.id, key.epoch()),
        &plain,
    )
    .map_err(|e| anyhow!("cannot re-seal a stored item: {e}"))?;
    s.conn.execute(
        "UPDATE sync_own SET epoch = ?1, blob = ?2 WHERE tag = ?3 AND idx = ?4",
        params![key.epoch(), fresh, tag, idx as i64],
    )?;
    if tag == ROSTER_TAG {
        s.conn.execute(
            "UPDATE roster_record SET epoch = ?1, blob = ?2 WHERE member_id = ?3 AND device_id = ?4 AND idx = ?5",
            params![
                key.epoch(),
                fresh,
                s.ident.team.member_id.to_string(),
                s.ident.team.device_id.to_string(),
                idx as i64
            ],
        )?;
    }
    Ok(())
}

/// Replaces the id of the stored item (tag, idx) by a fresh one (409 `id_conflict`).
fn renew_id(s: &mut Session<'_>, tag: &str, idx: u64) -> Result<()> {
    let Some(p) = load_pending(&s.conn, tag, idx)? else {
        return Ok(());
    };
    let new = Id::new_v4();
    if let (Some(blob), Some(epoch)) = (p.blob, p.epoch) {
        let plain = open_record(
            &s.ring,
            &own_ad(&s.ident, &s.ring, tag, idx, p.id, epoch),
            &blob,
        )
        .map_err(|e| anyhow!("cannot re-seal a stored item: {e}"))?;
        let key = s.ring.current();
        let fresh = seal_record(
            key,
            &own_ad(&s.ident, &s.ring, tag, idx, new, key.epoch()),
            &plain,
        )
        .map_err(|e| anyhow!("cannot re-seal a stored item: {e}"))?;
        s.conn.execute(
            "UPDATE sync_own SET record_id = ?1, epoch = ?2, blob = ?3 WHERE tag = ?4 AND idx = ?5",
            params![new.to_string(), key.epoch(), fresh, tag, idx as i64],
        )?;
        if tag == "rec" {
            s.conn.execute(
                "UPDATE event SET sync_id = ?1 WHERE sync_id = ?2",
                params![new.to_string(), p.id.to_string()],
            )?;
        }
    }
    Ok(())
}

/// A record the server holds as deleted (410): the local row goes, `team:{id}` is tombstoned,
/// and the item becomes a marker at the same idx so the stream stays contiguous (§9.3).
pub fn mark_deleted(conn: &Connection, id: Id, now_ms: i64) -> Result<()> {
    let id = id.to_string();
    conn.execute(
        "UPDATE sync_own SET deleted = 1, blob = NULL, epoch = NULL WHERE record_id = ?1",
        [&id],
    )?;
    conn.execute(
        "DELETE FROM event WHERE sync_id = ?1 AND origin = 'local'",
        [&id],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO tombstone (kind, value, created_at) VALUES ('tool_use_id', ?1, ?2)",
        params![format!("team:{id}"), now_ms],
    )?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct ShareProbe {
    share: Option<String>,
}

/// Bookkeeping after the server stored (or replayed) these items: outbox rows and, for `rec`,
/// `pushed_at`, the pushed `shareable` level and the dropped blob (a re-seed rebuilds it).
fn finish(s: &mut Session<'_>, keys: &[(String, u64)]) -> Result<()> {
    let now = s.now_ms();
    let mut levels: Vec<(u64, Option<&'static str>)> = Vec::new();
    for (tag, idx) in keys {
        if tag != "rec" {
            continue;
        }
        let level = match load_pending(&s.conn, tag, *idx)? {
            Some(Pending {
                blob: Some(blob),
                epoch: Some(epoch),
                id,
                ..
            }) => open_record(
                &s.ring,
                &own_ad(&s.ident, &s.ring, tag, *idx, id, epoch),
                &blob,
            )
            .ok()
            .and_then(|plain| serde_json::from_slice::<ShareProbe>(&plain).ok())
            .map(|p| {
                if p.share.as_deref() == Some("link") {
                    "link"
                } else {
                    "full"
                }
            }),
            _ => None,
        };
        levels.push((*idx, level));
    }
    let tx = s
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (tag, idx) in keys {
        tx.execute(
            "DELETE FROM sync_outbox WHERE ref = ?1",
            [format!("{tag}:{idx}")],
        )?;
    }
    for (idx, level) in levels {
        let id: Option<String> = tx
            .query_row(
                "SELECT record_id FROM sync_own WHERE tag = 'rec' AND idx = ?1 AND deleted = 0",
                [idx as i64],
                |r| r.get(0),
            )
            .optional()?;
        let Some(id) = id else { continue };
        if let Some(level) = level {
            tx.execute(
                "UPDATE event SET pushed_at = COALESCE(pushed_at, ?1), \
                   shareable = CASE WHEN shareable = 'no' THEN ?2 ELSE shareable END \
                 WHERE sync_id = ?3 AND origin = 'local'",
                params![now, level, id],
            )?;
        }
        tx.execute(
            "UPDATE sync_own SET blob = NULL WHERE tag = 'rec' AND idx = ?1 AND deleted = 0",
            [idx as i64],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// What stopped a send.
#[derive(Debug)]
pub enum SendStop {
    /// The server needs a re-seed of this stream first (its head is below ours).
    NeedsReseed(String),
}

/// Sends the stored items `keys` in order, in requests of at most 100 items and 1.4 MB, and
/// does the bookkeeping. Handles 409 `stale_epoch`, 410 `deleted`, 409 `id_conflict` and
/// 409 `stream_conflict` as `docs/sync-v1.md` §9.3 says; every other failure is returned with
/// the outbox untouched.
pub fn send_keys(
    s: &mut Session<'_>,
    keys: &[(String, u64)],
) -> Result<std::result::Result<usize, SendStop>> {
    let mut sent = 0;
    let mut rest: &[(String, u64)] = keys;
    while !rest.is_empty() {
        // Take as many as fit one request.
        let mut take = 0;
        let mut bytes = 0;
        for (tag, idx) in rest.iter().take(BATCH_ITEMS) {
            let Some(p) = load_pending(&s.conn, tag, *idx)? else {
                break;
            };
            let sz = size_of(&p);
            if take > 0 && bytes + sz > BATCH_BYTES {
                break;
            }
            bytes += sz;
            take += 1;
        }
        if take == 0 {
            // A queued key without a sync_own row: nothing to send, drop the outbox row.
            let (tag, idx) = &rest[0];
            s.conn.execute(
                "DELETE FROM sync_outbox WHERE ref = ?1",
                [format!("{tag}:{idx}")],
            )?;
            rest = &rest[1..];
            continue;
        }
        let batch = &rest[..take];
        let mut tries = 0;
        loop {
            tries += 1;
            let mut records = Vec::with_capacity(batch.len());
            for (tag, idx) in batch {
                if let Some(p) = load_pending(&s.conn, tag, *idx)? {
                    records.push(item_of(&p)?);
                }
            }
            match s.client.push(&PushRequest { records }) {
                Ok(_) => {
                    if s.opts.crash_after_ack {
                        bail!("injected crash after the server acknowledged the push");
                    }
                    finish(s, batch)?;
                    sent += batch.len();
                    break;
                }
                Err(e) if tries < 4 => match (e.status(), e.code()) {
                    (Some(409), Some(ErrorCode::StaleEpoch)) => {
                        let advanced = refresh_keys(s)?;
                        if !advanced && tries > 1 {
                            return Err(anyhow!(
                                "the server wants an epoch this device has no key for"
                            ));
                        }
                        for (tag, idx) in batch {
                            reseal(s, tag, *idx)?;
                        }
                    }
                    (Some(410), Some(ErrorCode::Deleted)) => {
                        let now = s.now_ms();
                        for id in e.body().and_then(|b| b.ids.clone()).unwrap_or_default() {
                            mark_deleted(&s.conn, id, now)?;
                        }
                    }
                    (Some(409), Some(ErrorCode::IdConflict)) => {
                        let item = e.body().and_then(|b| b.item).unwrap_or(0) as usize;
                        if let Some((tag, idx)) = batch.get(item) {
                            renew_id(s, tag, *idx)?;
                        }
                    }
                    (Some(409), Some(ErrorCode::StreamConflict)) => {
                        let item = e.body().and_then(|b| b.item).unwrap_or(0) as usize;
                        let (tag, idx) =
                            batch.get(item).cloned().unwrap_or_else(|| batch[0].clone());
                        let status = s.client.status()?;
                        let head = status
                            .streams
                            .iter()
                            .find(|h| {
                                h.member == s.ident.team.member_id
                                    && h.device == s.ident.team.device_id
                                    && h.tag.as_str() == tag
                            })
                            .map_or(-1, |h| h.head);
                        s.status = Some(status);
                        if head < idx as i64 - 1 {
                            return Ok(Err(SendStop::NeedsReseed(tag)));
                        }
                        if head >= idx as i64 {
                            bail!(
                                "the server holds another record at {tag} {idx} of this device's stream: \
                                 this data directory was copied to another machine. \
                                 Take a new device id with a device invite (awm doctor explains)"
                            );
                        }
                    }
                    _ => return Err(e.into()),
                },
                Err(e) => return Err(e.into()),
            }
        }
        rest = &rest[take..];
    }
    Ok(Ok(sent))
}

/// Sends the outbox: records, roster entries, flags, stats (only with `team.share_stats`) and
/// policy items; then the deletions. Content (everything but roster entries) waits until the
/// verified roster names this device. Returns the number of items sent.
pub fn flush(s: &mut Session<'_>) -> Result<usize> {
    let mut total = 0;
    for pass in 0..2 {
        let content = pass == 1;
        if content && !roster::own_approval_ok(&s.roster, &s.ident) {
            if s.report.push_blocked.is_none() {
                s.report.push_blocked = Some("this device has no verified roster entry yet".into());
            }
            break;
        }
        let kinds: &[&str] = if content {
            &["record", "flag", "stats", "policy"]
        } else {
            &["roster"]
        };
        let share_stats = s.env.config.team.share_stats;
        let mut st = s.conn.prepare(
            "SELECT kind, ref FROM sync_outbox WHERE kind IN ('record','roster','flag','stats','policy') ORDER BY id",
        )?;
        let rows: Vec<(String, String)> = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        drop(st);
        let mut keys = Vec::new();
        for (kind, r) in rows {
            if !kinds.contains(&kind.as_str()) || (kind == "stats" && !share_stats) {
                continue;
            }
            let Some((tag, idx)) = r.rsplit_once(':') else {
                continue;
            };
            let Ok(idx) = idx.parse::<u64>() else {
                continue;
            };
            keys.push((tag.to_string(), idx));
        }
        if keys.is_empty() {
            continue;
        }
        match send_keys(s, &keys) {
            Ok(Ok(n)) => total += n,
            Ok(Err(SendStop::NeedsReseed(tag))) => {
                crate::sync::reseed::author_stream(s, &tag)?;
                // The re-seed pushed every item above the server's head, outbox items included.
                let again = keys.iter().filter(|(t, i)| {
                    s.conn
                        .query_row(
                            "SELECT 1 FROM sync_outbox WHERE ref = ?1",
                            [format!("{t}:{i}")],
                            |_| Ok(()),
                        )
                        .optional()
                        .ok()
                        .flatten()
                        .is_some()
                });
                let again: Vec<(String, u64)> = again.cloned().collect();
                if !again.is_empty() {
                    if let Ok(Ok(n)) = send_keys(s, &again) {
                        total += n;
                    }
                }
            }
            Err(e) => {
                record_attempt(&s.conn, &keys, &e.to_string())?;
                return Err(e);
            }
        }
    }
    Ok(total)
}

fn record_attempt(conn: &Connection, keys: &[(String, u64)], message: &str) -> Result<()> {
    let one: String = message
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect();
    for (tag, idx) in keys {
        conn.execute(
            "UPDATE sync_outbox SET attempts = attempts + 1, last_error = ?2 WHERE ref = ?1",
            params![format!("{tag}:{idx}"), one],
        )?;
    }
    Ok(())
}

/// Sends the outbox rows of kind `delete` (§4.6 step 4): a row's `ref` is a record id or the
/// JSON of a `DeleteRequest`. Returns the number of requests that went through. A refusal
/// (403, 404) is final and drops the row; anything else keeps it.
pub fn deletions(s: &mut Session<'_>) -> Result<usize> {
    let mut st = s
        .conn
        .prepare("SELECT id, ref FROM sync_outbox WHERE kind = 'delete' ORDER BY id")?;
    let rows: Vec<(i64, String)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    drop(st);
    let mut done = 0;
    let mut ids: Vec<(i64, Id)> = Vec::new();
    let flush_ids = |s: &mut Session<'_>, ids: &mut Vec<(i64, Id)>| -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let req = awm_proto::wire::DeleteRequest::Ids(ids.iter().map(|(_, id)| *id).collect());
        let outcome = s.client.delete(&req);
        let finished = match &outcome {
            Ok(_) => true,
            Err(e) => matches!(e.status(), Some(400 | 403 | 404)),
        };
        if finished {
            for (row, _) in ids.iter() {
                s.conn
                    .execute("DELETE FROM sync_outbox WHERE id = ?1", [row])?;
            }
            if outcome.is_err() {
                state::bump(&s.conn, "dropped.delete_refused", ids.len() as i64)?;
            }
        }
        ids.clear();
        match outcome {
            Ok(_) => Ok(1),
            Err(e) if finished => {
                let _ = e;
                Ok(0)
            }
            Err(e) => Err(e.into()),
        }
    };
    for (row, r) in rows {
        if r.trim_start().starts_with('{') {
            done += flush_ids(s, &mut ids)?;
            let Ok(req) = serde_json::from_str::<awm_proto::wire::DeleteRequest>(&r) else {
                s.conn
                    .execute("DELETE FROM sync_outbox WHERE id = ?1", [row])?;
                continue;
            };
            match s.client.delete(&req) {
                Ok(_) => {
                    s.conn
                        .execute("DELETE FROM sync_outbox WHERE id = ?1", [row])?;
                    done += 1;
                }
                Err(e) if matches!(e.status(), Some(400 | 403 | 404)) => {
                    s.conn
                        .execute("DELETE FROM sync_outbox WHERE id = ?1", [row])?;
                    state::bump(&s.conn, "dropped.delete_refused", 1)?;
                }
                Err(e) => return Err(e.into()),
            }
        } else if let Ok(id) = Id::parse(r.trim()) {
            ids.push((row, id));
            if ids.len() >= awm_proto::wire::limits::DELETE_IDS {
                done += flush_ids(s, &mut ids)?;
            }
        } else {
            s.conn
                .execute("DELETE FROM sync_outbox WHERE id = ?1", [row])?;
        }
    }
    done += flush_ids(s, &mut ids)?;
    Ok(done)
}

/// Whether the pushes wait for `team.push_delay_s` (plan-v3-team §4.7): the oldest unpushed
/// eligible row must be that old, plus up to 20 % of jitter.
pub fn delayed(s: &Session<'_>, scan: &Scan) -> bool {
    let delay = i64::from(s.env.config.team.push_delay_s) * 1_000;
    if delay == 0 || scan.candidates.is_empty() {
        return false;
    }
    let oldest = scan
        .candidates
        .iter()
        .map(|c| c.record.created_at)
        .min()
        .unwrap_or(0);
    let jitter = (s.now_ms().rem_euclid(1_000) * delay / 5_000).max(0);
    s.now_ms() - oldest < delay + jitter
}

/// One run's push: scan, queue, send. Returns the number of items sent.
pub fn run(s: &mut Session<'_>) -> Result<usize> {
    let mut scan = scan(&s.conn, &s.env.config, s.opts.backfill.as_ref(), SCAN_LIMIT)?;
    let may_queue = !delayed(s, &scan) && s.report.push_blocked.is_none();
    if may_queue {
        queue_records(s, &mut scan)?;
    }
    state::set_skipped(&s.conn, &scan.counts)?;
    s.report.skipped = scan.counts.clone();
    let mut sent = flush(s)?;
    sent += deletions(s)?;
    s.report.pushed += sent;
    Ok(sent)
}
