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
