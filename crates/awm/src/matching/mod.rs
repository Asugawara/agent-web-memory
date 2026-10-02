//! Matching of prompts and URLs against stored records (plan-v2 §3.1).
//!
//! Rules shared by every channel are enforced here: never the caller's own
//! `tool_use_id` (1), never the caller's own (session, agent) when
//! `exclude_same_agent` (2), never quarantined or tombstoned records (3), one hit
//! per group with its size in `seen` (4), never an id in `shown_event_ids` (5),
//! and at most three hits.

pub mod calibrate;
pub mod fts;
pub mod url;

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OptionalExtension};

use crate::normalize::{norm_query, norm_url};
use crate::note::{Note, Relation, Status, Tool};
use crate::record::sha256_hex;
use crate::sanitize;

/// Hits returned by any channel, at most.
pub const MAX_HITS: usize = 3;
/// BM25 candidates read before the cutoff, grouping and rule 5 are applied.
const CANDIDATES: i64 = 300;

#[derive(Debug, Clone, Default)]
pub struct MatchOpts {
    pub caller_session: String,
    /// `None` = main agent.
    pub caller_agent: Option<String>,
    pub caller_cwd_hash: String,
    pub caller_tool_use_id: Option<String>,
    /// Only records created strictly before this time.
    pub before_ms: Option<i64>,
    pub exclude_same_agent: bool,
    pub limit: usize,
    pub shown_event_ids: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub event_id: i64,
    /// Negated bm25; 1.0 for URL matches.
    pub score: f64,
    /// Records in the hit's group.
    pub seen: u32,
}

/// SQL for rules 1-3 on alias `e`; `?1` tool_use_id, `?2` session, `?3` agent,
/// `?4` exclude flag, `?5` before_ms.
const RULES_SQL: &str = "(?1 IS NULL OR e.tool_use_id != ?1) \
     AND (?4 = 0 OR NOT (e.session_id = ?2 AND e.agent_id IS ?3)) \
     AND (?5 IS NULL OR e.created_at < ?5) \
     AND e.quarantined = 0 \
     AND NOT EXISTS (SELECT 1 FROM tombstone t \
                     WHERE t.kind = 'tool_use_id' AND t.value = e.tool_use_id)";

struct Candidate {
    id: i64,
    group: String,
    created_at: i64,
    score: f64,
    url_norm: Option<String>,
}

fn limit_of(opts: &MatchOpts) -> usize {
    opts.limit.min(MAX_HITS)
}

fn url_tombstoned(conn: &Connection, url_norm: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM tombstone WHERE kind = 'url_hash' AND value = ?1",
            [sha256_hex(url_norm)],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Rule 4, rule 5 and the limit: newest per group, best score first, newest first on ties.
fn finish(conn: &Connection, cands: Vec<Candidate>, opts: &MatchOpts) -> Result<Vec<Hit>> {
    let mut groups: HashMap<String, (Candidate, u32)> = HashMap::new();
    for c in cands {
        if let Some(u) = &c.url_norm {
            if url_tombstoned(conn, u)? {
                continue;
            }
        }
        match groups.get_mut(&c.group) {
            Some((best, n)) => {
                *n += 1;
                if (c.created_at, c.id) > (best.created_at, best.id) {
                    *best = c;
                }
            }
            None => {
                groups.insert(c.group.clone(), (c, 1));
            }
        }
    }
    let mut hits: Vec<(i64, Hit)> = groups
        .into_values()
        .filter(|(c, _)| !opts.shown_event_ids.contains(&c.id))
        .map(|(c, seen)| {
            (
                c.created_at,
                Hit {
                    event_id: c.id,
                    score: c.score,
                    seen,
                },
            )
        })
        .collect();
    hits.sort_by(|a, b| {
        b.1.score
            .total_cmp(&a.1.score)
            .then(b.0.cmp(&a.0))
            .then(b.1.event_id.cmp(&a.1.event_id))
    });
    hits.truncate(limit_of(opts));
    Ok(hits.into_iter().map(|(_, h)| h).collect())
}

/// Exact `url_norm` match on WebFetch events of any status, newest first.
pub fn url_channel(conn: &Connection, url_norm: &str, opts: &MatchOpts) -> Result<Vec<Hit>> {
    let sql = format!(
        "SELECT e.id, e.created_at FROM event e \
         WHERE e.tool = 'WebFetch' AND e.url_norm = ?6 AND {RULES_SQL} \
         ORDER BY e.created_at DESC, e.id DESC"
    );
    let mut st = conn.prepare_cached(&sql)?;
    let rows = st.query_map(
        params![
            opts.caller_tool_use_id,
            opts.caller_session,
            opts.caller_agent,
            opts.exclude_same_agent,
            opts.before_ms,
            url_norm
        ],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    )?;
    let cands = rows
        .map(|r| {
            r.map(|(id, created_at)| Candidate {
                id,
                group: url_norm.to_string(),
                created_at,
                score: 1.0,
                url_norm: Some(url_norm.to_string()),
            })
        })
        .collect::<rusqlite::Result<Vec<_>>>()?;
    finish(conn, cands, opts)
}

/// FTS5 BM25 over status `ok` events; keeps scores of at least `cutoff`.
pub fn query_channel(
    conn: &Connection,
    text: &str,
    cutoff: f64,
    opts: &MatchOpts,
) -> Result<Vec<Hit>> {
    let Some(expr) = fts::match_expr(text) else {
        return Ok(Vec::new());
    };
    let sql = format!(
        "SELECT e.id, e.tool, e.query, e.url_norm, e.created_at, -bm25(event_fts) AS score \
         FROM event_fts JOIN event e ON e.id = event_fts.rowid \
         WHERE event_fts MATCH ?6 AND e.status = 'ok' AND {RULES_SQL} \
         ORDER BY bm25(event_fts) LIMIT ?7"
    );
    let mut st = conn.prepare_cached(&sql)?;
    let rows = st.query_map(
        params![
            opts.caller_tool_use_id,
            opts.caller_session,
            opts.caller_agent,
            opts.exclude_same_agent,
            opts.before_ms,
            expr,
            CANDIDATES
        ],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, f64>(5)?,
            ))
        },
    )?;
    let mut cands = Vec::new();
    for row in rows {
        let (id, tool, query, url_norm, created_at, score) = row?;
        if score < cutoff {
            continue;
        }
        let group = match tool.as_str() {
            "WebFetch" => format!("u:{}", url_norm.as_deref().unwrap_or("")),
            _ => format!("q:{}", norm_query(query.as_deref().unwrap_or(""))),
        };
        cands.push(Candidate {
            id,
            group,
            created_at,
            score,
            url_norm: if tool == "WebFetch" { url_norm } else { None },
        });
    }
    finish(conn, cands, opts)
}

/// Up to five `https://` URLs of the prompt through [`url_channel`], merged and deduplicated.
pub fn prompt_url_channel(conn: &Connection, prompt: &str, opts: &MatchOpts) -> Result<Vec<Hit>> {
    let mut merged: Vec<(i64, Hit)> = Vec::new();
    for raw in url::extract_urls(prompt) {
        let Some(norm) = norm_url(&raw) else {
            continue;
        };
        for hit in url_channel(conn, &norm, opts)? {
            if merged.iter().all(|(_, h)| h.event_id != hit.event_id) {
                let created: i64 = conn.query_row(
                    "SELECT created_at FROM event WHERE id = ?1",
                    [hit.event_id],
                    |r| r.get(0),
                )?;
                merged.push((created, hit));
            }
        }
    }
    merged.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.event_id.cmp(&a.1.event_id)));
    merged.truncate(limit_of(opts));
    Ok(merged.into_iter().map(|(_, h)| h).collect())
}

/// Builds the note of a hit: relation to the caller, and for a search the first result URL that passes `url_ok`.
pub fn to_note(conn: &Connection, hit: &Hit, opts: &MatchOpts) -> Result<Note> {
    to_note_as(conn, hit, opts, None)
}

/// [`to_note`] where the caller's own member id is known: the `member` of `team.toml`, read
/// only when the record is a team row and `own_member` is `None`.
pub fn to_note_as(
    conn: &Connection,
    hit: &Hit,
    opts: &MatchOpts,
    own_member: Option<&str>,
) -> Result<Note> {
    let own = own_member;
    type Row = (
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
    );
    let row: Row = conn
        .query_row(
            "SELECT tool, session_id, agent_id, agent_type, cwd_hash, created_at, query, url, \
                    fetch_prompt, http_code, status, summary, origin, member, repo_key \
             FROM event WHERE id = ?1",
            [hit.event_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                    r.get(13)?,
                    r.get(14)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| anyhow!("event {} not found", hit.event_id))?;
    let (
        tool,
        session,
        agent,
        agent_type,
        cwd_hash,
        created_at,
        query,
        url,
        asked,
        code,
        status,
        summary,
        origin,
        member,
        repo_key,
    ) = row;
    let tool = Tool::from_db_str(&tool).ok_or_else(|| anyhow!("bad tool {tool}"))?;
    let status = Status::from_db_str(&status).ok_or_else(|| anyhow!("bad status {status}"))?;
    let relation = if origin == "team" {
        team_relation(conn, member.as_deref(), repo_key.as_deref(), opts, own)?
    } else if session == opts.caller_session {
        match agent {
            None => Relation::MainAgent,
            Some(_) => Relation::OtherSubagent {
                agent_type: agent_type.unwrap_or_else(|| "subagent".to_string()),
            },
        }
    } else if cwd_hash == opts.caller_cwd_hash {
        Relation::SameProject
    } else {
        Relation::OtherProject
    };
    let url = match tool {
        Tool::WebFetch => url,
        Tool::WebSearch => {
            let mut st =
                conn.prepare_cached("SELECT url FROM result WHERE event_id = ?1 ORDER BY rank")?;
            let urls = st.query_map([hit.event_id], |r| r.get::<_, String>(0))?;
            let mut found = None;
            for u in urls {
                let u = u?;
                if sanitize::url_ok(&u) {
                    found = Some(u);
                    break;
                }
            }
            found
        }
    };
    Ok(Note {
        event_id: hit.event_id,
        tool,
        created_at_ms: created_at,
        relation,
        seen: hit.seen.max(1),
        url,
        asked,
        searched: query,
        status,
        http_code: code.and_then(|c| u16::try_from(c).ok()),
        summary,
        score: hit.score,
    })
}

/// The caller's member id from `team.toml` (read without the `sync` feature); `None` outside a team.
pub fn own_member_id() -> Option<String> {
    let dir = crate::paths::data_dir().ok()?;
    let text = std::fs::read_to_string(dir.join("team.toml")).ok()?;
    let table = text.parse::<toml::Table>().ok()?;
    table.get("member_id")?.as_str().map(str::to_string)
}

/// Relation of a team row (§3.5): the caller's other machine, or a teammate with the handle of
/// the local roster and whether the record's `repo_key` is the caller's (through `project`).
fn team_relation(
    conn: &Connection,
    member: Option<&str>,
    repo_key: Option<&str>,
    opts: &MatchOpts,
    own: Option<&str>,
) -> Result<Relation> {
    let own = match own {
        Some(o) => Some(o.to_string()),
        None => own_member_id(),
    };
    if member.is_some() && member == own.as_deref() {
        return Ok(Relation::OwnDevice);
    }
    let handle: Option<String> = match member {
        Some(m) => conn
            .query_row(
                "SELECT handle FROM team_member WHERE member_id = ?1",
                [m],
                |r| r.get(0),
            )
            .optional()?,
        None => None,
    };
    let caller_repo: Option<String> = conn
        .query_row(
            "SELECT repo_key FROM project WHERE cwd_hash = ?1",
            [&opts.caller_cwd_hash],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let same_repo = matches!((repo_key, caller_repo.as_deref()), (Some(a), Some(b)) if a == b);
    Ok(Relation::Teammate {
        handle: handle.unwrap_or_default(),
        same_repo,
    })
}
