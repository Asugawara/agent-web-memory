//! `cwd::repo_root` and `cwd::remember` (STATS1, migration 0004). Git layouts are built by hand:
//! the hooks never run git, and neither do these tests.

use std::path::{Path, PathBuf};

use awm::cwd::{remember, repo_root, resolve, resolve_once, store};
use awm::db::{self, Role};
use awm::record::sha256_hex;
use rusqlite::{Connection, OptionalExtension};

/// `<dir>/main` with a `.git` directory, as `git init` leaves it (only what `git_dirs` reads).
fn checkout(dir: &Path) -> PathBuf {
    let main = dir.join("main");
    std::fs::create_dir_all(main.join(".git/objects")).unwrap();
    std::fs::create_dir_all(main.join("src/deep")).unwrap();
    std::fs::write(main.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    main
}

/// A linked worktree of `main` at `<dir>/wt`, as `git worktree add` lays it out: a `.git` file
/// naming `<main>/.git/worktrees/wt`, whose `commondir` is `../..`.
fn linked_worktree(dir: &Path, main: &Path) -> PathBuf {
    let wt = dir.join("wt");
    std::fs::create_dir_all(wt.join("crates/x")).unwrap();
    let gitdir = main.join(".git/worktrees/wt");
    std::fs::create_dir_all(&gitdir).unwrap();
    std::fs::write(gitdir.join("commondir"), "../..\n").unwrap();
    std::fs::write(
        gitdir.join("gitdir"),
        format!("{}\n", wt.join(".git").display()),
    )
    .unwrap();
    std::fs::write(wt.join(".git"), format!("gitdir: {}\n", gitdir.display())).unwrap();
    wt
}

#[test]
fn a_normal_checkout_is_its_own_root_from_any_depth() {
    let dir = tempfile::tempdir().unwrap();
    let main = checkout(dir.path());
    assert_eq!(repo_root(&main), Some(main.clone()));
    assert_eq!(repo_root(&main.join("src/deep")), Some(main.clone()));
}

#[test]
fn a_linked_worktree_resolves_to_the_main_checkout() {
    let dir = tempfile::tempdir().unwrap();
    let main = checkout(dir.path());
    let wt = linked_worktree(dir.path(), &main);
    assert_eq!(repo_root(&wt), Some(main.clone()));
    assert_eq!(repo_root(&wt.join("crates/x")), Some(main.clone()));
}

#[test]
fn a_relative_gitdir_and_an_absolute_commondir_resolve_as_well() {
    let dir = tempfile::tempdir().unwrap();
    let main = checkout(dir.path());
    let wt = dir.path().join("wt2");
    std::fs::create_dir_all(&wt).unwrap();
    let gitdir = main.join(".git/worktrees/wt2");
    std::fs::create_dir_all(&gitdir).unwrap();
    std::fs::write(
        gitdir.join("commondir"),
        format!("{}\n", main.join(".git").display()),
    )
    .unwrap();
    std::fs::write(wt.join(".git"), "gitdir: ../main/.git/worktrees/wt2\n").unwrap();
    assert_eq!(repo_root(&wt), Some(main));
}

#[test]
fn a_bare_repository_worktree_falls_back_to_the_worktree_root() {
    let dir = tempfile::tempdir().unwrap();
    let bare = dir.path().join("repo.git");
    std::fs::create_dir_all(bare.join("worktrees/w")).unwrap();
    std::fs::write(bare.join("worktrees/w/commondir"), "../..\n").unwrap();
    let wt = dir.path().join("w");
    std::fs::create_dir_all(wt.join("sub")).unwrap();
    std::fs::write(
        wt.join(".git"),
        format!("gitdir: {}\n", bare.join("worktrees/w").display()),
    )
    .unwrap();
    assert_eq!(repo_root(&wt.join("sub")), Some(wt));
}

#[test]
fn a_path_outside_git_has_no_root() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain/dir");
    std::fs::create_dir_all(&plain).unwrap();
    // The temporary directory itself may sit under a checkout on some machines; skip then.
    if repo_root(dir.path()).is_none() {
        assert_eq!(repo_root(&plain), None);
    }
    assert_eq!(repo_root(Path::new("")), None);
}

#[test]
fn a_path_that_no_longer_exists_resolves_through_its_nearest_ancestor() {
    let dir = tempfile::tempdir().unwrap();
    let main = checkout(dir.path());
    assert_eq!(repo_root(&main.join("gone/and/deeper")), Some(main.clone()));
    let wt = linked_worktree(dir.path(), &main);
    assert_eq!(repo_root(&wt.join("removed")), Some(main));
}

// ---- remember ----

fn db(dir: &Path) -> Connection {
    let mut conn = db::open(&dir.join("awm.db"), Role::Cli).unwrap();
    db::migrate(&mut conn).unwrap();
    conn
}

type Row = (String, Option<String>, i64);

fn row(conn: &Connection, hash: &str) -> Option<Row> {
    conn.query_row(
        "SELECT path, repo_root, updated_at FROM cwd WHERE cwd_hash = ?1",
        [hash],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()
    .unwrap()
}

fn rows(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM cwd", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn remember_is_idempotent_and_returns_the_event_hash() {
    let dir = tempfile::tempdir().unwrap();
    let conn = db(dir.path());
    let main = checkout(dir.path());
    let wt = linked_worktree(dir.path(), &main);
    let path = wt.join("crates/x").to_string_lossy().into_owned();

    let hash = remember(&conn, &path, 10).unwrap();
    assert_eq!(hash, sha256_hex(&path));
    let main_s = main.to_string_lossy().into_owned();
    assert_eq!(
        row(&conn, &hash),
        Some((path.clone(), Some(main_s.clone()), 10))
    );

    // Same path, same root: nothing is written, not even updated_at.
    assert_eq!(remember(&conn, &path, 20).unwrap(), hash);
    assert_eq!(row(&conn, &hash), Some((path, Some(main_s), 10)));
    assert_eq!(rows(&conn), 1);
}

#[test]
fn remember_fills_a_null_root_and_keeps_a_known_one() {
    let dir = tempfile::tempdir().unwrap();
    let conn = db(dir.path());
    // Not a checkout yet.
    let proj = dir.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let path = proj.to_string_lossy().into_owned();
    let hash = remember(&conn, &path, 10).unwrap();
    if repo_root(dir.path()).is_some() {
        return; // the temporary directory sits under a checkout on this machine
    }
    assert_eq!(row(&conn, &hash), Some((path.clone(), None, 10)));

    // `git init` later: the root goes from NULL to the checkout.
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    remember(&conn, &path, 20).unwrap();
    assert_eq!(
        row(&conn, &hash),
        Some((path.clone(), Some(path.clone()), 20))
    );

    // The checkout goes away: the known root stays.
    std::fs::remove_dir_all(proj.join(".git")).unwrap();
    remember(&conn, &path, 30).unwrap();
    assert_eq!(row(&conn, &hash), Some((path.clone(), Some(path), 20)));
    assert_eq!(rows(&conn), 1);
}

#[test]
fn remember_an_empty_path_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let conn = db(dir.path());
    assert_eq!(remember(&conn, "", 10).unwrap(), sha256_hex(""));
    assert_eq!(rows(&conn), 0);
}

#[test]
fn remember_a_path_outside_git_stores_a_null_root() {
    let dir = tempfile::tempdir().unwrap();
    let conn = db(dir.path());
    let path = "/nonexistent-awm-stats1/never/created";
    let hash = remember(&conn, path, 10).unwrap();
    // `/` is not a checkout on any test machine.
    assert_eq!(row(&conn, &hash), Some((path.to_string(), None, 10)));
}

#[test]
fn a_store_after_another_writer_never_writes_less() {
    let dir = tempfile::tempdir().unwrap();
    let conn = db(dir.path());
    if repo_root(dir.path()).is_some() {
        return; // the temporary directory sits under a checkout on this machine
    }
    let proj = dir.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let path = proj.to_string_lossy().into_owned();
    // Resolved before the checkout exists: a new row with no root.
    let early = resolve(&conn, &path).unwrap();
    assert_eq!(early.hash, sha256_hex(&path));
    // Meanwhile another process sees the checkout and writes its root.
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    remember(&conn, &path, 20).unwrap();
    // The late store keeps that root and its time.
    store(&conn, &early, 30).unwrap();
    assert_eq!(
        row(&conn, &early.hash),
        Some((path.clone(), Some(path), 20))
    );
}

#[test]
fn resolve_once_writes_a_new_path_and_leaves_a_known_one_to_import() {
    let dir = tempfile::tempdir().unwrap();
    let conn = db(dir.path());
    if repo_root(dir.path()).is_some() {
        return; // the temporary directory sits under a checkout on this machine
    }
    let proj = dir.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let path = proj.to_string_lossy().into_owned();
    let first = resolve_once(&conn, &path).unwrap();
    store(&conn, &first, 10).unwrap();
    assert_eq!(row(&conn, &first.hash), Some((path.clone(), None, 10)));

    // The checkout appears: the hooks' resolve does not look again, import's does.
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    let hook = resolve_once(&conn, &path).unwrap();
    store(&conn, &hook, 20).unwrap();
    assert_eq!(row(&conn, &first.hash), Some((path.clone(), None, 10)));
    store(&conn, &resolve(&conn, &path).unwrap(), 30).unwrap();
    assert_eq!(
        row(&conn, &first.hash),
        Some((path.clone(), Some(path), 30))
    );
    assert_eq!(resolve_once(&conn, "").unwrap().hash, sha256_hex(""));
    assert_eq!(rows(&conn), 1);
}

// ---- backfill (STATS2) ----

fn event(conn: &Connection, id: i64, session: &str, hash: &str, at: i64) {
    conn.execute(
        "INSERT INTO event (id, tool_use_id, tool, session_id, cwd_hash, created_at, query, status, \
                            summary, match_text, source) \
         VALUES (?1, ?2, 'WebSearch', ?3, ?4, ?5, 'q', 'ok', 's', 'q', 'hook')",
        rusqlite::params![id, format!("tu{id}"), session, hash, at],
    )
    .unwrap();
}

fn injection(conn: &Connection, id: i64, session: &str, transcript: Option<&Path>, at: i64) {
    conn.execute(
        "INSERT INTO injection (id, ref, created_at, hook, channel, mode, session_id, tool_use_id, \
                                rendered_chars, latency_ms, transcript_path) \
         VALUES (?1, ?2, ?3, 'PostToolUse', 'url', 'inject', ?4, ?5, 300, 10, ?6)",
        rusqlite::params![
            id,
            format!("{id:08x}"),
            at,
            session,
            format!("inj{id}"),
            transcript.map(|p| p.to_string_lossy().into_owned())
        ],
    )
    .unwrap();
}

fn injection_hash(conn: &Connection, id: i64) -> Option<String> {
    conn.query_row("SELECT cwd_hash FROM injection WHERE id = ?1", [id], |r| {
        r.get(0)
    })
    .unwrap()
}

#[test]
fn backfill_places_old_injections_and_events_from_the_transcripts() {
    let dir = tempfile::tempdir().unwrap();
    let conn = db(dir.path());
    let main = checkout(dir.path());
    let src = main.join("src").to_string_lossy().into_owned();
    let other = dir.path().join("other");
    std::fs::create_dir_all(&other).unwrap();
    let other_s = other.to_string_lossy().into_owned();
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let elsewhere_s = elsewhere.to_string_lossy().into_owned();

    // Transcripts: s1 moves from `src` to `other`; e2 and e3 start where events were captured.
    let projects = dir.path().join("projects/p");
    std::fs::create_dir_all(&projects).unwrap();
    let t1 = projects.join("s1.jsonl");
    std::fs::write(
        &t1,
        format!(
            "{{\"type\":\"user\",\"timestamp\":\"2026-10-04T00:00:00Z\"}}\n\
             {{\"type\":\"user\",\"cwd\":{src:?},\"timestamp\":\"2026-10-04T00:00:10Z\"}}\n\
             {{\"type\":\"user\",\"cwd\":{other_s:?},\"timestamp\":\"2026-10-04T01:00:00Z\"}}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        projects.join("e2.jsonl"),
        format!("{{\"type\":\"user\",\"cwd\":{elsewhere_s:?}}}\n"),
    )
    .unwrap();
    // A Codex rollout: the session meta line names the directory.
    let codex = dir.path().join("codex/2026/10/04");
    std::fs::create_dir_all(&codex).unwrap();
    let rollout_cwd = dir.path().join("rollout-dir");
    std::fs::create_dir_all(&rollout_cwd).unwrap();
    let rollout_s = rollout_cwd.to_string_lossy().into_owned();
    std::fs::write(
        codex.join("rollout-x.jsonl"),
        format!(
            "{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"c1\",\"cwd\":{rollout_s:?}}}}}\n"
        ),
    )
    .unwrap();

    let t = |s: &str| {
        time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .map(|t| i64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap())
            .unwrap()
    };
    // Injection 1: near the first line (src). 2: near the last (other). 3: its transcript is gone,
    // its session has an event in `elsewhere`. 4: nothing is left. 5: already placed.
    injection(&conn, 1, "s1", Some(&t1), t("2026-10-04T00:00:20Z"));
    injection(&conn, 2, "s1", Some(&t1), t("2026-10-04T00:59:00Z"));
    injection(&conn, 3, "s3", Some(&dir.path().join("gone.jsonl")), 5);
    injection(&conn, 4, "s4", None, 6);
    injection(&conn, 5, "s5", None, 7);
    conn.execute(
        "UPDATE injection SET cwd_hash = ?1 WHERE id = 5",
        [sha256_hex(&rollout_s)],
    )
    .unwrap();
    event(&conn, 1, "s3", &sha256_hex(&elsewhere_s), 1);
    event(&conn, 2, "s7", &sha256_hex(&rollout_s), 2);
    event(&conn, 3, "s8", &sha256_hex("/gone/for/good"), 3);
    // A directory first seen outside git that is a checkout now.
    let late = dir.path().join("late");
    std::fs::create_dir_all(&late).unwrap();
    let late_s = late.to_string_lossy().into_owned();
    let late_hash = remember(&conn, &late_s, 1).unwrap();
    if repo_root(&late).is_none() {
        std::fs::create_dir_all(late.join(".git")).unwrap();
    }

    let codex_dir = dir.path().join("codex");
    let b = awm::cwd::backfill(&conn, &dir.path().join("projects"), Some(&codex_dir), 99).unwrap();
    assert_eq!(b.injections_resolved, 3, "{b:?}");
    assert_eq!(b.injections_unresolved, 1, "{b:?}");
    assert_eq!(b.events_resolved, 2, "{b:?}");
    assert_eq!(b.events_unresolved, 1, "{b:?}");

    assert_eq!(injection_hash(&conn, 1), Some(sha256_hex(&src)));
    assert_eq!(injection_hash(&conn, 2), Some(sha256_hex(&other_s)));
    assert_eq!(injection_hash(&conn, 3), Some(sha256_hex(&elsewhere_s)));
    assert_eq!(injection_hash(&conn, 4), None);
    assert_eq!(injection_hash(&conn, 5), Some(sha256_hex(&rollout_s)));
    let main_s = main.to_string_lossy().into_owned();
    assert_eq!(
        row(&conn, &sha256_hex(&src)),
        Some((src.clone(), Some(main_s), 99))
    );
    assert_eq!(
        row(&conn, &sha256_hex(&elsewhere_s)).unwrap().0,
        elsewhere_s
    );
    assert_eq!(row(&conn, &sha256_hex(&rollout_s)).unwrap().0, rollout_s);
    assert_eq!(row(&conn, &sha256_hex("/gone/for/good")), None);
    // The refreshed root of the directory that became a checkout.
    assert_eq!(
        row(&conn, &late_hash),
        Some((late_s.clone(), Some(late_s), 99))
    );

    // The hash no transcript names is remembered, so the next run does not walk for it again.
    let walked: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM meta WHERE key LIKE 'cwd.walked.%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(walked, 1);

    // A second run finds nothing more to place.
    let again =
        awm::cwd::backfill(&conn, &dir.path().join("projects"), Some(&codex_dir), 100).unwrap();
    assert_eq!(again.injections_resolved, 0);
    assert_eq!(again.events_resolved, 0);
    assert_eq!(again.injections_unresolved, 1);
    assert_eq!(again.events_unresolved, 1);
}
