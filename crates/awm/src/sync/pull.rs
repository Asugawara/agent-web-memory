//! Pull step of `awm sync` (plan-v3-team §4.6 step 6, §4.5 pull rows; `docs/sync-v1.md` §8;
//! TM10).
//!
//! `GET /v1/status` gives every stream's head; the streams above the local head are read with
//! `POST /v1/pull` in pages of at most 500 records. A page is first decrypted and checked
//! without touching the database, then written in transactions of at most 25 rows and 20 ms,
//! with a pause between them, so capture (2 s wait) and the hooks' `injection` writes (50 ms)
//! always find the write lock free for long enough.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use anyhow::Result;
use awm_proto::crypto::{open_record, RecordAd};
use awm_proto::keys::ROSTER_TAG;
use awm_proto::wire::{
    decode_plaintext, Cursor, Decoded, FlagReason, Id, PolicyPlaintext, PullRequest, PulledItem,
    PulledRecord, RecPlaintext, Share as WireShare, StreamRecords, Tag, Tool as WireTool,
};
use rusqlite::{params, Connection, TransactionBehavior};
use url::Url;

use crate::note::{Status, Tool};
use crate::record::{sha256_hex, Agent, Record, ResultRow};
use crate::sync::eligible;
use crate::sync::payload::{
    MAX_QUERY_CHARS, MAX_RESULTS, MAX_RESULT_URL_CHARS, MAX_SUMMARY_CHARS, MAX_TITLE_CHARS,
    MAX_URL_CHARS,
};
use crate::sync::state;
use crate::sync::{push, roster, Session};

/// Rows per write transaction (plan-v3-team §4.6 step 6).
pub const CHUNK_ROWS: usize = 25;
/// Time per write transaction.
pub const CHUNK_TIME: Duration = Duration::from_millis(20);
/// Records per `POST /v1/pull`.
pub const PAGE: u32 = 500;
/// A pull of more rows than this ends with `PRAGMA wal_checkpoint(PASSIVE)`.
pub const CHECKPOINT_ROWS: usize = 1_000;
/// A teammate's `created_at` is held to the hour the server received the record, plus or
/// minus this (RVT0 m8), in seconds.
pub const CLAMP_SECS: i64 = 86_400;

/// What to do with one index of a stream.
enum Action {
    /// Nothing to store; the index counts as applied.
    Advance,
    /// A teammate's record.
    Insert(Box<NewRow>),
    /// A roster record, stored as received.
    Roster {
        record_id: String,
        epoch: u32,
        blob: Vec<u8>,
    },
    /// A policy record from a verified admin.
    Policy(Box<PolicyPlaintext>),
    /// A deletion marker.
    Marker(Id),
}

struct NewRow {
    record: Record,
    member: String,
    sync_id: String,
    repo_key: Option<String>,
    shareable: &'static str,
    quarantined: bool,
    flag: Option<String>,
}

struct Prepared {
    key: (Id, Id, String),
    idx: u64,
    action: Action,
}

fn is_repo_key(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Decrypts one record; the keys are fetched again once when the epoch or the key is wrong.
fn open(
    s: &mut Session<'_>,
    member: Id,
    device: Id,
    tag: &str,
    r: &PulledRecord,
) -> Result<Option<Vec<u8>>> {
    let mut refreshed = false;
    loop {
        let ad = RecordAd {
            org: s.ring.org(),
            member: *member.as_uuid(),
            device: *device.as_uuid(),
            tag: tag.to_string(),
            idx: r.idx,
            record_id: *r.id.as_uuid(),
            epoch: r.epoch,
        };
        match open_record(&s.ring, &ad, &r.blob.0) {
            Ok(plain) => return Ok(Some(plain)),
            Err(_) if !refreshed && !s.keys_refreshed => {
                refreshed = true;
                push::refresh_keys(s)?;
            }
            Err(_) => return Ok(None),
        }
    }
}

fn tombstoned(conn: &Connection, kind: &str, value: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM tombstone WHERE kind = ?1 AND value = ?2",
            params![kind, value],
            |_| Ok(()),
        )
        .map(|_| true)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(false),
            other => Err(other),
        })?)
}

fn cut(s: &str, n: usize) -> (String, bool) {
    if s.chars().count() > n {
        (s.chars().take(n).collect(), true)
    } else {
        (s.to_string(), false)
    }
}

/// Cuts `text` to `cap` characters (noting it in `caps`), re-redacts it with the receiver's
/// patterns and terms, and collects the secret kinds the patterns found.
fn scrub_text(
    text: &str,
    cap: usize,
    terms: &[String],
    caps: &mut bool,
    secrets: &mut Vec<String>,
) -> String {
    let (cut_text, over) = cut(text, cap);
    *caps |= over;
    let sc = eligible::scrub(&cut_text, terms);
    for k in sc.secrets {
        if !secrets.contains(&k) {
            secrets.push(k);
        }
    }
    sc.text
}

/// The pull-side checks of §4.5 for one `rec` plaintext. `None`: not stored (counted).
fn check_rec(
    s: &Session<'_>,
    member: Id,
    id: Id,
    received_at: i64,
    p: RecPlaintext,
    policy: &eligible::TeamPolicy,
) -> Result<Option<NewRow>> {
    let cfg = &s.env.config;
    let terms = eligible::terms(cfg, policy);
    let conn = &s.conn;
    let sync_id = id.to_string();
    if tombstoned(conn, "tool_use_id", &format!("team:{sync_id}"))? {
        state::bump(conn, "dropped.tombstone", 1)?;
        return Ok(None);
    }
    let mut caps = false;
    let mut secrets: Vec<String> = Vec::new();

    let tool = match p.tool {
        WireTool::WebSearch => Tool::WebSearch,
        WireTool::WebFetch => Tool::WebFetch,
    };
    let exclude = &cfg.capture.exclude_hosts;
    let private = |u: &str| Url::parse(u).map_or(true, |u| crate::hosts::is_private(&u, exclude));

    // The record's own URL.
    let (url, url_norm) = match p.url.as_deref() {
        Some(u) => {
            let (u, over) = cut(u, MAX_URL_CHARS);
            caps |= over;
            if private(&u) {
                state::bump(conn, "dropped.private_host", 1)?;
                return Ok(None);
            }
            let Some(norm) = crate::normalize::norm_url(&u) else {
                state::bump(conn, "dropped.malformed", 1)?;
                return Ok(None);
            };
            if tombstoned(conn, "url_hash", &sha256_hex(&norm))? {
                state::bump(conn, "dropped.tombstone", 1)?;
                return Ok(None);
            }
            let text = scrub_text(&u, usize::MAX, &terms, &mut caps, &mut secrets);
            (Some(text), Some(norm))
        }
        None => (None, None),
    };
    match (tool, p.query.is_some(), url.is_some()) {
        (Tool::WebSearch, false, _) | (Tool::WebFetch, _, false) => {
            state::bump(conn, "dropped.malformed", 1)?;
            return Ok(None);
        }
        _ => {}
    }

    // Result rows: private hosts and forgotten URLs are dropped, as capture does.
    let listed = p.results.len();
    caps |= listed > MAX_RESULTS;
    let mut results: Vec<ResultRow> = Vec::new();
    let (mut private_rows, mut forgotten) = (0usize, 0usize);
    for row in p.results.iter().take(MAX_RESULTS) {
        let (ru, over) = cut(&row.url, MAX_RESULT_URL_CHARS);
        caps |= over;
        if private(&ru) {
            private_rows += 1;
            continue;
        }
        let Some(norm) = crate::normalize::norm_url(&ru) else {
            private_rows += 1;
            continue;
        };
        if tombstoned(conn, "url_hash", &sha256_hex(&norm))? {
            forgotten += 1;
            continue;
        }
        let title = row
            .title
            .as_deref()
            .map(|t| scrub_text(t, MAX_TITLE_CHARS, &terms, &mut caps, &mut secrets));
        results.push(ResultRow {
            rank: results.len() as i64 + 1,
            url: ru,
            url_norm: norm,
            title,
        });
    }
    if url.is_none() && listed > 0 && results.is_empty() {
        state::bump(
            conn,
            if private_rows == listed.min(MAX_RESULTS) {
                "dropped.private_host"
            } else {
                "dropped.tombstone"
            },
            1,
        )?;
        return Ok(None);
    }
    let _ = forgotten;

    let query = p
        .query
        .as_deref()
        .map(|q| scrub_text(q, MAX_QUERY_CHARS, &terms, &mut caps, &mut secrets));
    let fetch_prompt = p
        .fetch_prompt
        .as_deref()
        .map(|q| scrub_text(q, MAX_QUERY_CHARS, &terms, &mut caps, &mut secrets));
    let summary = p
        .summary
        .as_deref()
        .map(|q| scrub_text(q, MAX_SUMMARY_CHARS, &terms, &mut caps, &mut secrets));

    let mut reasons: Vec<String> = Vec::new();
    if caps {
        reasons.push("a size cap of the shared record was exceeded".to_string());
    }
    if !secrets.is_empty() {
        reasons.push(format!(
            "secret shape found on receipt ({})",
            secrets.join(", ")
        ));
    }
    if let Some(r) = crate::sanitize::record_quarantine_reason(
        summary.as_deref(),
        fetch_prompt.as_deref(),
        query.as_deref(),
    ) {
        reasons.push(r);
    }
    let quarantine_reason = (!reasons.is_empty()).then(|| reasons.join("; "));

    let status = match p.status {
        awm_proto::wire::RecStatus::Ok => Status::Ok,
        awm_proto::wire::RecStatus::DeadEnd => Status::DeadEnd,
        awm_proto::wire::RecStatus::Refusal => Status::Refusal,
    };
    let created_secs = p
        .created_at
        .clamp(received_at - CLAMP_SECS, received_at + CLAMP_SECS);
    let mut record = Record {
        tool_use_id: format!("team:{sync_id}"),
        tool,
        session_id: format!("team:{member}"),
        agent_id: None,
        agent_type: None,
        cwd_hash: String::new(),
        created_at: created_secs.saturating_mul(1_000),
        query,
        url,
        url_norm,
        fetch_prompt,
        http_code: p.http_code,
        bytes: p.bytes,
        duration_ms: p.duration_ms,
        status,
        summary,
        match_text: String::new(),
        source: match p.source {
            awm_proto::wire::Source::Hook => "hook".to_string(),
            awm_proto::wire::Source::Import => "import".to_string(),
        },
        agent: match p.agent {
            awm_proto::wire::Agent::Claude => Agent::Claude,
            awm_proto::wire::Agent::Codex => Agent::Codex,
        },
        results,
        quarantine_reason: quarantine_reason.clone(),
    };
    record.match_text = record.match_text();
    Ok(Some(NewRow {
        record,
        member: member.to_string(),
        sync_id,
        repo_key: p.repo_key.filter(|k| is_repo_key(k)),
        shareable: match p.share {
            WireShare::Full => "full",
            WireShare::Link => "link",
        },
        quarantined: quarantine_reason.is_some(),
        flag: quarantine_reason,
    }))
}

/// Decrypts and checks the records of one stream; returns the items in index order, stopping
/// at the first gap.
fn prepare_stream(
    s: &mut Session<'_>,
    from: u64,
    sr: &StreamRecords,
    policy: &eligible::TeamPolicy,
) -> Result<Vec<Prepared>> {
    let tag = sr.tag.as_str().to_string();
    let key = (sr.member, sr.device, tag.clone());
    let mut out = Vec::with_capacity(sr.records.len());
    for (expected, item) in (from..).zip(sr.records.iter()) {
        if item.idx() != expected {
            break;
        }
        let idx = item.idx();
        let action = match item {
            PulledItem::Deleted(d) => Action::Marker(d.id),
            PulledItem::Record(r) => {
                if tag == ROSTER_TAG {
                    Action::Roster {
                        record_id: r.id.to_string(),
                        epoch: r.epoch,
                        blob: r.blob.0.clone(),
                    }
                } else if sr.tag.known().is_none() {
                    Action::Advance
                } else {
                    match open(s, sr.member, sr.device, &tag, r)? {
                        None => {
                            state::bump(&s.conn, "dropped.decrypt", 1)?;
                            s.report.dropped += 1;
                            Action::Advance
                        }
                        Some(plain) => prepare_plain(s, sr, r, &tag, &plain, policy)?,
                    }
                }
            }
        };
        out.push(Prepared {
            key: key.clone(),
            idx,
            action,
        });
    }
    Ok(out)
}

fn prepare_plain(
    s: &mut Session<'_>,
    sr: &StreamRecords,
    r: &PulledRecord,
    tag: &str,
    plain: &[u8],
    policy: &eligible::TeamPolicy,
) -> Result<Action> {
    match tag {
        "rec" => match decode_plaintext::<RecPlaintext>(plain) {
            Ok(Decoded::Known(p)) => {
                match check_rec(s, sr.member, r.id, r.received_at, p, policy)? {
                    Some(row) => Ok(Action::Insert(Box::new(row))),
                    None => {
                        s.report.dropped += 1;
                        Ok(Action::Advance)
                    }
                }
            }
            Ok(Decoded::Newer { .. }) => {
                state::set(&s.conn, state::NEWER_SCHEMA, "1")?;
                s.report.skipped_newer += 1;
                Ok(Action::Advance)
            }
            Err(_) => {
                state::bump(&s.conn, "dropped.malformed", 1)?;
                s.report.dropped += 1;
                Ok(Action::Advance)
            }
        },
        "policy" => match decode_plaintext::<PolicyPlaintext>(plain) {
            Ok(Decoded::Known(p)) => {
                let author_is_admin = s
                    .roster
                    .member(*sr.member.as_uuid())
                    .is_some_and(|m| m.admin && !m.revoked);
                let held = state::get_i64(&s.conn, state::POLICY_VERSION)?.unwrap_or(-1);
                if author_is_admin && i64::try_from(p.version).unwrap_or(i64::MAX) > held {
                    Ok(Action::Policy(Box::new(p)))
                } else {
                    if !author_is_admin {
                        state::bump(&s.conn, "dropped.policy_not_admin", 1)?;
                    }
                    Ok(Action::Advance)
                }
            }
            Ok(Decoded::Newer { .. }) => {
                state::set(&s.conn, state::NEWER_SCHEMA, "1")?;
                Ok(Action::Advance)
            }
            Err(_) => Ok(Action::Advance),
        },
        // `flag` and `stats` records of teammates are read by `awm team status` and
        // `awm stats --team` (TM14); the engine only advances over them.
        _ => Ok(Action::Advance),
    }
}

fn apply_row(tx: &Connection, row: &NewRow) -> Result<bool> {
    let rec = &row.record;
    let n = tx.execute(
        "INSERT OR IGNORE INTO event (tool_use_id, tool, session_id, agent_id, agent_type, \
         cwd_hash, created_at, query, url, url_norm, fetch_prompt, http_code, bytes, duration_ms, \
         status, summary, match_text, source, quarantined, quarantine_reason, agent, origin, \
         member, repo_key, shareable, sync_id) \
         VALUES (?1, ?2, ?3, NULL, NULL, '', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
                 ?16, ?17, ?18, 'team', ?19, ?20, ?21, ?22)",
        params![
            rec.tool_use_id,
            rec.tool.as_db_str(),
            rec.session_id,
            rec.created_at,
            rec.query,
            rec.url,
            rec.url_norm,
            rec.fetch_prompt,
            rec.http_code,
            rec.bytes,
            rec.duration_ms,
            rec.status.as_db_str(),
            rec.summary,
            rec.match_text,
            rec.db_source(),
            i64::from(row.quarantined),
            rec.quarantine_reason,
            rec.agent.as_db_str(),
            row.member,
            row.repo_key,
            row.shareable,
            row.sync_id,
        ],
    )?;
    if n == 0 {
        return Ok(false);
    }
    let event_id = tx.last_insert_rowid();
    let mut st = tx.prepare_cached(
        "INSERT INTO result (event_id, rank, url, url_norm, title) VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for r in &rec.results {
        st.execute(params![event_id, r.rank, r.url, r.url_norm, r.title])?;
    }
    Ok(true)
}

/// The tombstone of a record id and the removal of its team row.
fn forget_team_record(tx: &Connection, id: &str, now_ms: i64) -> Result<usize> {
    tx.execute(
        "INSERT OR IGNORE INTO tombstone (kind, value, created_at) VALUES ('tool_use_id', ?1, ?2)",
        params![format!("team:{id}"), now_ms],
    )?;
    Ok(tx.execute(
        "DELETE FROM event WHERE sync_id = ?1 AND origin = 'team'",
        [id],
    )?)
}

/// Writes prepared items in transactions of at most [`CHUNK_ROWS`] rows and [`CHUNK_TIME`].
fn apply(s: &mut Session<'_>, items: Vec<Prepared>) -> Result<usize> {
    let now = s.now_ms();
    let mut applied = 0;
    let mut i = 0;
    let mut flags: Vec<(Id, String)> = Vec::new();
    while i < items.len() {
        let started = Instant::now();
        let tx = s
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut heads: HashMap<(Id, Id, String), u64> = HashMap::new();
        let mut n = 0;
        while i < items.len() && n < CHUNK_ROWS {
            let it = &items[i];
            match &it.action {
                Action::Advance => {}
                Action::Insert(row) => {
                    if apply_row(&tx, row)? {
                        applied += 1;
                        if let Some(reason) = &row.flag {
                            if let Ok(id) = Id::parse(&row.sync_id) {
                                flags.push((id, reason.clone()));
                            }
                        }
                    }
                }
                Action::Roster {
                    record_id,
                    epoch,
                    blob,
                } => {
                    roster::store_record(
                        &tx,
                        &it.key.0.to_string(),
                        &it.key.1.to_string(),
                        it.idx,
                        record_id,
                        *epoch,
                        blob,
                    )?;
                }
                Action::Policy(p) => {
                    state::set(&tx, state::POLICY_JSON, &serde_json::to_string(p.as_ref())?)?;
                    state::set(&tx, state::POLICY_VERSION, &p.version.to_string())?;
                }
                Action::Marker(id) => {
                    forget_team_record(&tx, &id.to_string(), now)?;
                }
            }
            heads.insert(it.key.clone(), it.idx);
            i += 1;
            n += 1;
            if started.elapsed() >= CHUNK_TIME {
                break;
            }
        }
        for ((member, device, tag), idx) in heads {
            tx.execute(
                "INSERT INTO sync_stream (member_id, device_id, tag, head_idx) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(member_id, device_id, tag) DO UPDATE SET head_idx = excluded.head_idx",
                params![member.to_string(), device.to_string(), tag, idx as i64],
            )?;
        }
        tx.commit()?;
        let took = started.elapsed();
        s.report.apply_ms.push(took.as_millis() as u64);
        if i < items.len() {
            // Leave the write lock free long enough for a waiting hook to take it: SQLite's
            // busy handler polls at 1, 3, 8, 18, 33 ms.
            let gap = (took * 3).clamp(Duration::from_millis(15), Duration::from_millis(40));
            std::thread::sleep(gap);
        }
    }
    for (id, reason) in flags {
        let now = s.now_ms();
        push::queue_flag(
            &mut s.conn,
            &s.ident,
            &s.ring,
            id,
            FlagReason::Quarantine,
            Some(&reason),
            now,
        )?;
        s.report.quarantined += 1;
        state::bump(&s.conn, "quarantined", 1)?;
    }
    Ok(applied)
}

fn local_head(conn: &Connection, member: Id, device: Id, tag: &str) -> Result<i64> {
    Ok(conn
        .query_row(
            "SELECT head_idx FROM sync_stream WHERE member_id = ?1 AND device_id = ?2 AND tag = ?3",
            params![member.to_string(), device.to_string(), tag],
            |r| r.get(0),
        )
        .unwrap_or(-1))
}

/// One pull: status heads, pages of at most 500 records, roster and policy streams first.
/// Returns the number of teammate records stored.
pub fn run(s: &mut Session<'_>) -> Result<usize> {
    let Some(status) = s.status.clone() else {
        return Ok(0);
    };
    let own_device = s.ident.team.device_id;
    let mut streams: Vec<(Id, Id, Tag, i64)> = status
        .streams
        .iter()
        .filter(|h| h.device != own_device)
        .map(|h| (h.member, h.device, h.tag.clone(), h.head))
        .collect();
    let rank = |t: &Tag| match t.as_str() {
        "roster" => 0,
        "policy" => 1,
        _ => 2,
    };
    streams.sort_by(|a, b| {
        rank(&a.2)
            .cmp(&rank(&b.2))
            .then_with(|| (a.0, a.1, &a.2).cmp(&(b.0, b.1, &b.2)))
    });
    let policy = push::load_policy(&s.conn, push::load_opt_in(&s.conn, &[])?)?;
    let mut total = 0;
    let mut rows = 0;
    let started = Instant::now();
    loop {
        let mut cursors: Vec<Cursor> = Vec::new();
        for (member, device, tag, head) in &streams {
            let local = local_head(&s.conn, *member, *device, tag.as_str())?;
            if *head > local {
                cursors.push(Cursor {
                    member: *member,
                    device: *device,
                    tag: tag.clone(),
                    from: (local + 1) as u64,
                });
            }
            if cursors.len() >= awm_proto::wire::limits::PULL_CURSORS {
                break;
            }
        }
        if cursors.is_empty() {
            break;
        }
        let sent: HashMap<(Id, Id, String), u64> = cursors
            .iter()
            .map(|c| ((c.member, c.device, c.tag.as_str().to_string()), c.from))
            .collect();
        let resp = s.client.pull(&PullRequest {
            cursors,
            limit: PAGE,
        })?;
        // Roster records first, so that a policy in the same page is judged by the new roster.
        let mut ordered: Vec<&StreamRecords> = resp.streams.iter().collect();
        ordered.sort_by_key(|sr| rank(&sr.tag));
        let mut advanced = 0usize;
        let mut roster_done = false;
        for sr in ordered {
            // Entries for streams that were not asked for are ignored (RVT1 m4).
            let Some(&from) = sent.get(&(sr.member, sr.device, sr.tag.as_str().to_string())) else {
                continue;
            };
            if rank(&sr.tag) > 0 && !roster_done {
                let (r, _) = roster::verify_and_store(&s.conn, &s.ring, s.now_ms())?;
                s.roster = r;
                roster_done = true;
            }
            let prepared = prepare_stream(s, from, sr, &policy)?;
            advanced += prepared.len();
            let stored = apply(s, prepared)?;
            total += stored;
            rows += stored;
            // The stream's head at read time bounds the next round.
            if let Some(entry) = streams
                .iter_mut()
                .find(|(m, d, t, _)| *m == sr.member && *d == sr.device && *t == sr.tag)
            {
                entry.3 = entry.3.max(sr.head);
            }
        }
        if !roster_done {
            let (r, _) = roster::verify_and_store(&s.conn, &s.ring, s.now_ms())?;
            s.roster = r;
        }
        if advanced == 0 || (!resp.more && sent.len() < awm_proto::wire::limits::PULL_CURSORS) {
            // No progress (a gap), or everything asked for was served.
            let still = streams
                .iter()
                .any(|(m, d, t, h)| local_head(&s.conn, *m, *d, t.as_str()).is_ok_and(|l| *h > l));
            if advanced == 0 || !still {
                break;
            }
        }
    }
    s.report.pull_ms = started.elapsed().as_millis() as u64;
    if rows > CHECKPOINT_ROWS {
        let _ = s
            .conn
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()));
    }
    s.report.pulled += total;
    Ok(total)
}

/// Applies the deletion stream (`GET /v1/deletions`; plan-v3-team §3.7, `docs/sync-v1.md` §8.5):
/// for every entry the `team:{id}` tombstone is written whether or not the row exists, and the
/// team row goes. A full reconcile (the entries the client has not seen are gone from the
/// server) drops every team row and re-pulls every stream, at most once in 24 hours.
///
/// Entries that name this member's own `origin = 'local'` rows are left alone and counted
/// (`dropped.own_deleted`); TM11 decides (sync-v1 §5.2 row (e)).
pub fn apply_deletions(s: &mut Session<'_>) -> Result<usize> {
    let Some(status) = s.status.clone() else {
        return Ok(0);
    };
    let mut head = state::get_i64(&s.conn, state::DELETION_HEAD)?.unwrap_or(-1);
    let now = s.now_ms();
    if status.deletions.oldest > head + 1 && head >= 0 {
        let last = state::get_i64(&s.conn, "last_reconcile")?.unwrap_or(0);
        if now - last >= 86_400_000 {
            reconcile(s)?;
            state::set(&s.conn, "last_reconcile", &now.to_string())?;
        }
        head = status.deletions.oldest - 1;
        state::set(&s.conn, state::DELETION_HEAD, &head.to_string())?;
    }
    let mut applied = 0;
    while head < status.deletions.head {
        let page = s.client.deletions((head + 1) as u64, 5_000)?;
        if page.entries.is_empty() {
            break;
        }
        for chunk in page.entries.chunks(CHUNK_ROWS) {
            let tx = s
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            for e in chunk {
                let id = e.record_id.to_string();
                let own: bool = tx
                    .query_row(
                        "SELECT 1 FROM event WHERE sync_id = ?1 AND origin = 'local'",
                        [&id],
                        |_| Ok(()),
                    )
                    .is_ok();
                if own {
                    state::bump(&tx, "dropped.own_deleted", 1)?;
                } else {
                    // The tombstone is written whether or not the row exists (sync-v1 §8.5).
                    applied += forget_team_record(&tx, &id, now)?;
                }
                head = head.max(e.idx as i64);
            }
            state::set(&tx, state::DELETION_HEAD, &head.to_string())?;
            tx.commit()?;
        }
        if page.entries.len() < 5_000 {
            break;
        }
    }
    s.report.deletions_applied += applied;
    Ok(applied)
}

/// Drops every team row in 25-row transactions and sets every other device's stream heads back
/// to -1, so the next pull reads them again from 0.
fn reconcile(s: &mut Session<'_>) -> Result<()> {
    loop {
        let tx = s
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n = tx.execute(
            "DELETE FROM event WHERE id IN (SELECT id FROM event WHERE origin = 'team' LIMIT 25)",
            [],
        )?;
        tx.commit()?;
        if n == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    s.conn.execute(
        "UPDATE sync_stream SET head_idx = -1 WHERE device_id <> ?1 AND tag <> 'roster'",
        [s.ident.team.device_id.to_string()],
    )?;
    state::set(&s.conn, "reconciled_notice", "1")?;
    Ok(())
}

/// Removes teammates' rows older than the organisation's `retention_days` (plan-v3-team §3.7).
pub fn prune_retention(s: &mut Session<'_>) -> Result<usize> {
    let Some(status) = s.status.as_ref() else {
        return Ok(0);
    };
    let cutoff = s.now_ms() - i64::from(status.settings.retention_days) * 86_400_000;
    Ok(s.conn.execute(
        "DELETE FROM event WHERE origin = 'team' AND created_at < ?1",
        [cutoff],
    )?)
}

/// A count of teammates' rows by author, for the report and the tests.
pub fn team_rows_by_member(conn: &Connection) -> Result<BTreeMap<String, i64>> {
    let mut st =
        conn.prepare("SELECT member, COUNT(*) FROM event WHERE origin = 'team' GROUP BY member")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    Ok(rows.collect::<Result<_, _>>()?)
}
