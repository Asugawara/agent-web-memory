//! The plain working directory behind a `cwd_hash`, and the repository that holds it
//! (migration 0004). Local only: the sync payload never carries either.

use std::path::{Component, Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

use crate::record::sha256_hex;

/// The main checkout holding `path`, by filesystem only (hooks never run git).
///
/// The parent of the common git directory when that directory is named `.git` (a normal
/// checkout, or a linked worktree whose `commondir` names `<main>/.git`); otherwise (a bare
/// repository, a submodule, an odd layout) the work tree root. A `path` that no longer exists
/// resolves through its nearest existing ancestor. `None` outside git.
pub fn repo_root(path: &Path) -> Option<PathBuf> {
    let existing = path.ancestors().find(|p| p.exists())?;
    let (common, worktree) = crate::team::git_dirs(existing)?;
    let common = lexical(&common);
    match (common.file_name(), common.parent()) {
        (Some(name), Some(parent)) if name == ".git" && !parent.as_os_str().is_empty() => {
            Some(parent.to_path_buf())
        }
        _ => Some(worktree),
    }
}

/// `p` with `.` and `..` components resolved without touching the filesystem: git writes
/// `commondir` as `../..`, relative to the worktree's git directory.
fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// One path made ready for [`store`]: hashed, its [`repo_root`] found, and whether its `cwd`
/// row needs a write. [`resolve`] it before the write transaction that [`store`]s it: finding
/// the root costs a few `stat`s, which an automounted parent (`/home` on macOS, ~16 ms each)
/// can make slow, and the write lock must not wait on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// `sha256_hex(path)`, as `event.cwd_hash`.
    pub hash: String,
    path: String,
    root: Option<String>,
    write: bool,
}

/// Hashes `path`, finds its repository root and reads its `cwd` row (one `SELECT`, no write).
/// A write is needed for a new path, or when a root is found that differs from the stored one;
/// a root that is no longer found keeps the stored one. An empty `path` never writes (team rows
/// use `cwd_hash = ''`, a different value, and are never touched).
pub fn resolve(conn: &Connection, path: &str) -> rusqlite::Result<Resolved> {
    resolve_with(conn, path, true)
}

/// [`resolve`] for hook processes (the PreToolUse / PostToolUse hooks, and capture, which Codex
/// runs inline): a path that already has a `cwd` row costs one `SELECT` and no `stat`. Its root
/// is refreshed by `awm import` and by any caller of [`resolve`] or [`remember`].
pub fn resolve_once(conn: &Connection, path: &str) -> rusqlite::Result<Resolved> {
    resolve_with(conn, path, false)
}

fn resolve_with(conn: &Connection, path: &str, refresh: bool) -> rusqlite::Result<Resolved> {
    let hash = sha256_hex(path);
    let mut r = Resolved {
        hash,
        path: path.to_string(),
        root: None,
        write: false,
    };
    if path.is_empty() {
        return Ok(r);
    }
    let stored: Option<Option<String>> = conn
        .prepare_cached("SELECT repo_root FROM cwd WHERE cwd_hash = ?1")?
        .query_row([&r.hash], |row| row.get(0))
        .optional()?;
    if stored.is_some() && !refresh {
        return Ok(r);
    }
    r.root = repo_root(Path::new(path)).map(|p| p.to_string_lossy().into_owned());
    r.write = match &stored {
        None => true,
        Some(old) => r.root.is_some() && r.root != *old,
    };
    Ok(r)
}

/// Writes the `cwd` row of `r` when [`resolve`] found one needed. The upsert re-checks under the
/// write lock, so a row another process wrote in between is never overwritten with less.
pub fn store(conn: &Connection, r: &Resolved, now_ms: i64) -> rusqlite::Result<()> {
    if !r.write {
        return Ok(());
    }
    conn.prepare_cached(
        "INSERT INTO cwd (cwd_hash, path, repo_root, updated_at) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(cwd_hash) DO UPDATE SET \
           repo_root = COALESCE(excluded.repo_root, cwd.repo_root), \
           updated_at = excluded.updated_at \
         WHERE excluded.repo_root IS NOT NULL AND cwd.repo_root IS NOT excluded.repo_root",
    )?
    .execute(params![r.hash, r.path, r.root, now_ms])?;
    Ok(())
}

/// [`resolve`] then [`store`]: records `path` under its `cwd_hash` with its repository root and
/// returns the hash. For callers that hold no write transaction yet, or do not mind the `stat`s
/// inside one.
pub fn remember(conn: &Connection, path: &str, now_ms: i64) -> rusqlite::Result<String> {
    let r = resolve(conn, path)?;
    store(conn, &r, now_ms)?;
    Ok(r.hash)
}

/// What [`backfill`] placed and what stayed unplaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Backfill {
    pub injections_resolved: usize,
    /// Injections still without a `cwd` row behind their `cwd_hash`.
    pub injections_unresolved: usize,
    pub events_resolved: usize,
    /// Local events whose non-empty `cwd_hash` still has no `cwd` row.
    pub events_unresolved: usize,
}

/// Every line of a transcript that names a directory, as (timestamp ms, cwd): a Claude Code line's
/// top-level `cwd`, or a Codex rollout's `session_meta` payload `cwd`. `first_only` stops at the
/// first. A missing or unreadable file has none.
fn transcript_cwds(path: &Path, first_only: bool) -> Vec<(Option<i64>, String)> {
    use std::io::BufRead;
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
        if !line.contains("\"cwd\"") {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let cwd = v.get("cwd").and_then(|c| c.as_str()).or_else(|| {
            (v.get("type").and_then(|t| t.as_str()) == Some("session_meta"))
                .then(|| v.pointer("/payload/cwd").and_then(|c| c.as_str()))
                .flatten()
        });
        let Some(cwd) = cwd.filter(|c| !c.is_empty()) else {
            continue;
        };
        let at = v
            .get("timestamp")
            .and_then(|t| t.as_str())
            .and_then(|t| {
                time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339).ok()
            })
            .and_then(|t| i64::try_from(t.unix_timestamp_nanos() / 1_000_000).ok());
        out.push((at, cwd.to_string()));
        if first_only {
            break;
        }
    }
    out
}

/// The cwd of the line nearest `at` (the earliest on a tie; a line without a timestamp ranks last).
fn nearest(cands: &[(Option<i64>, String)], at: i64) -> Option<&str> {
    cands
        .iter()
        .min_by_key(|(t, _)| t.map_or(u64::MAX, |t| t.abs_diff(at)))
        .map(|(_, c)| c.as_str())
}

/// `<repo>` of a path with the components `worktrees/<repo>/<something>`.
fn worktree_repo_name(path: &Path) -> Option<std::ffi::OsString> {
    let parts: Vec<_> = path.components().collect();
    parts.windows(3).find_map(|w| match w {
        [a, b, _] if a.as_os_str() == "worktrees" => Some(b.as_os_str().to_os_string()),
        _ => None,
    })
}

/// `meta` key prefix of a hash the transcript walk of [`backfill`] could not place (value: when).
const WALKED: &str = "cwd.walked.";
/// How long a fruitless walk for a hash is not repeated.
const WALK_RETRY_MS: i64 = 7 * 86_400_000;

fn missing_events(conn: &Connection) -> rusqlite::Result<usize> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM event WHERE origin = 'local' AND cwd_hash != '' \
           AND cwd_hash NOT IN (SELECT cwd_hash FROM cwd)",
        [],
        |r| r.get(0),
    )?;
    Ok(usize::try_from(n).unwrap_or(0))
}

/// Names the directories of rows from before migration 0004, from the transcripts that are left:
///
/// 1. an injection without `cwd_hash` takes the cwd of the line of its transcript nearest its
///    `created_at`; without a transcript, the `cwd_hash` of its session's first local event (this
///    assumes a session stays in one directory);
/// 2. a local event whose `cwd_hash` has no `cwd` row gets one when a transcript under `projects`
///    or `codex` starts in that directory (the first `cwd` of each file is hashed);
/// 3. a `cwd` row without a repository root is looked up again, so a directory that became a
///    checkout after it was first seen is placed in it; a vanished `.../worktrees/<repo>/<x>`
///    directory takes the one known repository root named `<repo>`.
///
/// Every path is resolved before the write transaction (a `stat` of a missing path under an
/// automounted parent costs ~16 ms and hooks wait at most 50 ms for the lock); the transaction
/// only writes.
pub fn backfill(
    conn: &Connection,
    projects: &Path,
    codex: Option<&Path>,
    now_ms: i64,
) -> anyhow::Result<Backfill> {
    use std::collections::{BTreeMap, HashMap, HashSet};

    let events_before = missing_events(conn)?;
    // hash -> resolved path to store.
    let mut resolved: HashMap<String, Resolved> = HashMap::new();
    let mut by_cwd: HashMap<String, String> = HashMap::new();
    let mut hash_of =
        |cwd: &str, resolved: &mut HashMap<String, Resolved>| -> rusqlite::Result<String> {
            if let Some(h) = by_cwd.get(cwd) {
                return Ok(h.clone());
            }
            let r = resolve(conn, cwd)?;
            let h = r.hash.clone();
            resolved.entry(h.clone()).or_insert(r);
            by_cwd.insert(cwd.to_string(), h.clone());
            Ok(h)
        };

    // 1. Injections.
    let rows: Vec<(i64, Option<String>, i64, String)> = conn
        .prepare(
            "SELECT id, transcript_path, created_at, session_id FROM injection \
             WHERE cwd_hash IS NULL AND mode IN ('inject','deny') ORDER BY id",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut by_transcript: BTreeMap<String, Vec<(i64, i64)>> = BTreeMap::new();
    let mut loose: Vec<(i64, String)> = Vec::new();
    for (id, path, at, session) in &rows {
        match path.as_deref().filter(|p| !p.is_empty()) {
            Some(p) => by_transcript
                .entry(p.to_string())
                .or_default()
                .push((*id, *at)),
            None => loose.push((*id, session.clone())),
        }
    }
    let mut assign: Vec<(i64, String)> = Vec::new();
    for (path, injections) in &by_transcript {
        let cands = transcript_cwds(Path::new(path), false);
        for (id, at) in injections {
            match nearest(&cands, *at) {
                Some(cwd) => assign.push((*id, hash_of(cwd, &mut resolved)?)),
                None => {
                    let session = rows
                        .iter()
                        .find(|r| r.0 == *id)
                        .map(|r| r.3.clone())
                        .unwrap_or_default();
                    loose.push((*id, session));
                }
            }
        }
    }
    let mut first_event = conn.prepare(
        "SELECT cwd_hash FROM event WHERE session_id = ?1 AND origin = 'local' AND cwd_hash != '' \
         ORDER BY created_at, id LIMIT 1",
    )?;
    for (id, session) in &loose {
        if let Some(h) = first_event
            .query_row([session], |r| r.get::<_, String>(0))
            .optional()?
        {
            assign.push((*id, h));
        }
    }

    // 2. Hashes with no row: of local events, and of the injections just placed through them.
    let mut missing: HashSet<String> = conn
        .prepare(
            "SELECT DISTINCT cwd_hash FROM event WHERE origin = 'local' AND cwd_hash != '' \
               AND cwd_hash NOT IN (SELECT cwd_hash FROM cwd)",
        )?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for (_, h) in &assign {
        let known: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM cwd WHERE cwd_hash = ?1)",
            [h],
            |r| r.get(0),
        )?;
        if !known {
            missing.insert(h.clone());
        }
    }
    missing.retain(|h| !resolved.contains_key(h));
    // A walk that did not find a hash is not repeated for a week: its transcripts are gone, and
    // the walk reads the head of every transcript file.
    let tried = |h: &str| -> rusqlite::Result<bool> {
        let at: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [format!("{WALKED}{h}")],
                |r| r.get(0),
            )
            .optional()?;
        Ok(at
            .and_then(|v| v.parse::<i64>().ok())
            .is_some_and(|t| now_ms - t < WALK_RETRY_MS))
    };
    let mut skipped = HashSet::new();
    for h in &missing {
        if tried(h)? {
            skipped.insert(h.clone());
        }
    }
    missing.retain(|h| !skipped.contains(h));
    let mut gave_up: Vec<String> = Vec::new();
    if !missing.is_empty() {
        let mut files = crate::import::transcript_files(projects);
        if let Some(dir) = codex {
            files.extend(crate::import::codex_files(dir));
        }
        for file in files {
            if missing.is_empty() {
                break;
            }
            let Some((_, cwd)) = transcript_cwds(&file, true).pop() else {
                continue;
            };
            if missing.contains(&sha256_hex(&cwd)) {
                let h = hash_of(&cwd, &mut resolved)?;
                missing.remove(&h);
            }
        }
        gave_up = missing.iter().cloned().collect();
    }

    // 3. Rows whose root was not found when the directory was first seen.
    let rootless: Vec<(String, String)> = conn
        .prepare("SELECT cwd_hash, path FROM cwd WHERE repo_root IS NULL")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut roots: Vec<(String, String)> = Vec::new();
    let mut orphans: Vec<(String, String)> = Vec::new();
    for (h, p) in rootless {
        match repo_root(Path::new(&p)) {
            Some(r) => roots.push((h, r.to_string_lossy().into_owned())),
            None => orphans.push((h, p)),
        }
    }
    // A worktree directory that is gone (`.../worktrees/<repo>/<branch>`) belongs to the one
    // known repository named `<repo>`; with none or several, it stays unplaced.
    if !orphans.is_empty() {
        let mut known: HashSet<String> = conn
            .prepare("SELECT DISTINCT repo_root FROM cwd WHERE repo_root IS NOT NULL")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        known.extend(roots.iter().map(|(_, r)| r.clone()));
        for (h, p) in orphans {
            let path = Path::new(&p);
            if path.exists() {
                continue;
            }
            let Some(repo) = worktree_repo_name(path) else {
                continue;
            };
            let mut named = known
                .iter()
                .filter(|r| Path::new(r.as_str()).file_name().is_some_and(|n| n == repo));
            if let (Some(root), None) = (named.next(), named.next()) {
                roots.push((h, root.clone()));
            }
        }
    }

    // The write: no filesystem access from here on.
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let write = || -> anyhow::Result<usize> {
        for r in resolved.values() {
            store(conn, r, now_ms)?;
        }
        for (hash, root) in &roots {
            conn.execute(
                "UPDATE cwd SET repo_root = ?1, updated_at = ?2 WHERE cwd_hash = ?3 AND repo_root IS NULL",
                rusqlite::params![root, now_ms, hash],
            )?;
        }
        for h in &gave_up {
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![format!("{WALKED}{h}"), now_ms.to_string()],
            )?;
        }
        let mut placed = 0;
        for (id, hash) in &assign {
            placed += conn.execute(
                "UPDATE injection SET cwd_hash = ?1 WHERE id = ?2 AND cwd_hash IS NULL",
                rusqlite::params![hash, id],
            )?;
        }
        Ok(placed)
    };
    let placed = match write() {
        Ok(n) => {
            conn.execute_batch("COMMIT")?;
            n
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    };

    let events_after = missing_events(conn)?;
    let injections_unresolved: i64 = conn.query_row(
        "SELECT COUNT(*) FROM injection WHERE mode IN ('inject','deny') \
           AND (cwd_hash IS NULL OR cwd_hash NOT IN (SELECT cwd_hash FROM cwd))",
        [],
        |r| r.get(0),
    )?;
    Ok(Backfill {
        injections_resolved: placed,
        injections_unresolved: usize::try_from(injections_unresolved).unwrap_or(0),
        events_resolved: events_before.saturating_sub(events_after),
        events_unresolved: events_after,
    })
}
