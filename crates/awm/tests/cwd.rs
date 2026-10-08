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
