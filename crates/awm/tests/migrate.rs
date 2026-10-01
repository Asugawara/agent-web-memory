//! Schema, migration runner and data path tests (plan-v2 §6.1, §6.2, §5.7).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use awm::db::{self, MigrateOutcome, Role, VersionCheck, MIGRATIONS};
use rusqlite::Connection;

const TABLES: &[&str] = &[
    "schema_version",
    "meta",
    "import_source",
    "event",
    "result",
    "event_fts",
    "injection",
    "injection_item",
    "outcome",
    "hook_run",
    "tombstone",
];

const INDEXES: &[&str] = &[
    "event_url_norm",
    "event_created_at",
    "event_session",
    "result_url_norm",
    "injection_created_at",
    "injection_agent",
    "injection_item_event",
    "hook_run_started_at",
];

const TRIGGERS: &[&str] = &["event_fts_ai", "event_fts_ad", "event_fts_au"];

fn db_in(dir: &Path) -> PathBuf {
    dir.join("awm.db")
}

fn fresh(dir: &Path) -> Connection {
    let mut conn = db::open(&db_in(dir), Role::Cli).unwrap();
    db::migrate(&mut conn).unwrap();
    conn
}

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).unwrap()
}

fn insert_search(conn: &Connection, tool_use_id: &str, match_text: &str) -> i64 {
    conn.execute(
        "INSERT INTO event (tool_use_id, tool, session_id, cwd_hash, created_at, query, status, \
         match_text, source) VALUES (?1, 'WebSearch', 's1', 'h', 1, 'q', 'ok', ?2, 'hook')",
        [tool_use_id, match_text],
    )
    .unwrap();
    conn.last_insert_rowid()
}

fn fts_hits(conn: &Connection, term: &str) -> Vec<i64> {
    let mut st = conn
        .prepare("SELECT rowid FROM event_fts WHERE event_fts MATCH ?1 ORDER BY rowid")
        .unwrap();
    st.query_map([term], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn fresh_database_migrates_to_version_2() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = db::open(&db_in(dir.path()), Role::Cli).unwrap();
    assert_eq!(db::schema_version(&conn).unwrap(), 0);
    let out = db::migrate(&mut conn).unwrap();
    assert_eq!(
        out,
        MigrateOutcome {
            from: 0,
            to: 2,
            backup: None
        }
    );
    assert_eq!(db::schema_version(&conn).unwrap(), 2);
    let mut st = conn
        .prepare("SELECT version, name, checksum FROM schema_version ORDER BY version")
        .unwrap();
    let rows: Vec<(u32, String, String)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![
            (1, "0001_init".to_string(), db::checksum(MIGRATIONS[0].2)),
            (
                2,
                "0002_event_agent".to_string(),
                db::checksum(MIGRATIONS[1].2)
            ),
        ]
    );
    assert!(rows.iter().all(|(_, _, sum)| sum.len() == 64));
}

#[test]
fn embedded_migrations_match_the_files() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    assert_eq!(MIGRATIONS.len(), 2);
    for (version, name, sql) in MIGRATIONS {
        let file = std::fs::read_to_string(dir.join(format!("{name}.sql"))).unwrap();
        assert_eq!(db::checksum(sql), db::checksum(&file), "{name}");
        assert!(name.starts_with(&format!("{version:04}_")), "{name}");
    }
    // 0001 is applied on users' databases; its bytes must never change.
    assert_eq!(
        db::checksum(MIGRATIONS[0].2),
        "29660e731f4c8aecf3d376879706c7442c2c8d3df847d71c70688dcfca20e6eb"
    );
}

#[test]
fn all_tables_indexes_and_triggers_exist() {
    let dir = tempfile::tempdir().unwrap();
    let conn = fresh(dir.path());
    let has = |kind: &str, name: &str| {
        count(
            &conn,
            &format!(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = '{kind}' AND name = '{name}'"
            ),
        ) == 1
    };
    for t in TABLES {
        assert!(has("table", t), "missing table {t}");
    }
    for i in INDEXES {
        assert!(has("index", i), "missing index {i}");
    }
    for t in TRIGGERS {
        assert!(has("trigger", t), "missing trigger {t}");
    }
}

#[test]
fn sqlite_has_fts5() {
    let conn = Connection::open_in_memory().unwrap();
    assert!(db::has_fts5(&conn).unwrap());
}

#[test]
fn second_migrate_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = fresh(dir.path());
    insert_search(&conn, "tu1", "alpha");
    let out = db::migrate(&mut conn).unwrap();
    assert_eq!(
        out,
        MigrateOutcome {
            from: 2,
            to: 2,
            backup: None
        }
    );
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM schema_version"), 2);
    assert!(!dir.path().join("awm.db.bak-v2").exists());
}

#[test]
fn edited_checksum_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = fresh(dir.path());
    conn.execute(
        "UPDATE schema_version SET checksum = ?1 WHERE version = 1",
        ["0".repeat(64)],
    )
    .unwrap();
    let err = db::migrate(&mut conn).unwrap_err().to_string();
    assert!(err.contains("checksum mismatch"), "{err}");
}

#[test]
fn newer_database_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = fresh(dir.path());
    conn.execute(
        "INSERT INTO schema_version (version, name, checksum, applied_at) \
         VALUES (99, '0099_future', 'x', 0)",
        [],
    )
    .unwrap();
    let err = db::migrate(&mut conn).unwrap_err().to_string();
    assert!(err.contains("database is from a newer awm (99)"), "{err}");
    assert_eq!(db::schema_version(&conn).unwrap(), 99);
}

#[test]
fn check_version_reports_older_current_and_newer() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = db::open(&db_in(dir.path()), Role::Cli).unwrap();
    assert_eq!(
        db::check_version(&conn).unwrap(),
        VersionCheck::Older { db: 0, bin: 2 }
    );
    db::migrate(&mut conn).unwrap();
    assert_eq!(db::check_version(&conn).unwrap(), VersionCheck::Current);
    conn.execute(
        "INSERT INTO schema_version (version, name, checksum, applied_at) \
         VALUES (3, '0003_future', 'x', 0)",
        [],
    )
    .unwrap();
    assert_eq!(
        db::check_version(&conn).unwrap(),
        VersionCheck::Newer { db: 3, bin: 2 }
    );
}

#[test]
fn fts_follows_insert_update_and_delete() {
    let dir = tempfile::tempdir().unwrap();
    let conn = fresh(dir.path());
    let a = insert_search(&conn, "tu1", "rusqlite bundled feature");
    let b = insert_search(&conn, "tu2", "tantivy segment merge");
    assert_eq!(fts_hits(&conn, "rusqlite"), vec![a]);
    assert_eq!(fts_hits(&conn, "tantivy"), vec![b]);

    conn.execute(
        "UPDATE event SET match_text = 'sqlite wal checkpoint' WHERE id = ?1",
        [a],
    )
    .unwrap();
    assert!(fts_hits(&conn, "rusqlite").is_empty());
    assert_eq!(fts_hits(&conn, "checkpoint"), vec![a]);

    conn.execute("DELETE FROM event WHERE id = ?1", [b])
        .unwrap();
    assert!(fts_hits(&conn, "tantivy").is_empty());
    assert_eq!(fts_hits(&conn, "checkpoint"), vec![a]);
}

#[test]
fn deleting_event_cascades_to_result() {
    let dir = tempfile::tempdir().unwrap();
    let conn = fresh(dir.path());
    let ev = insert_search(&conn, "tu1", "alpha");
    for rank in 1..=2 {
        conn.execute(
            "INSERT INTO result (event_id, rank, url, url_norm) VALUES (?1, ?2, 'u', 'u')",
            [ev, rank],
        )
        .unwrap();
    }
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM result"), 2);
    conn.execute("DELETE FROM event WHERE id = ?1", [ev])
        .unwrap();
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM result"), 0);
}

fn insert_injection_chain(conn: &Connection, ref_: &str, event_id: i64) -> i64 {
    conn.execute(
        "INSERT INTO injection (ref, created_at, hook, channel, mode, session_id, latency_ms) \
         VALUES (?1, 1, 'PostToolUse', 'url', 'inject', 's1', 3)",
        [ref_],
    )
    .unwrap();
    let inj = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO injection_item (injection_id, position, event_id, score) VALUES (?1, 1, ?2, 1.0)",
        [inj, event_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO outcome (injection_id, position, label, labelled_at) VALUES (?1, 1, '2', 1)",
        [inj],
    )
    .unwrap();
    inj
}

#[test]
fn deleting_injection_cascades_to_items_and_outcomes() {
    let dir = tempfile::tempdir().unwrap();
    let conn = fresh(dir.path());
    let ev = insert_search(&conn, "tu1", "alpha");
    let inj = insert_injection_chain(&conn, "0000abcd", ev);
    conn.execute("DELETE FROM injection WHERE id = ?1", [inj])
        .unwrap();
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM injection_item"), 0);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM outcome"), 0);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM event"), 1);

    // Deleting the event also removes items that point at it, and their outcomes.
    insert_injection_chain(&conn, "0000abce", ev);
    conn.execute("DELETE FROM event WHERE id = ?1", [ev])
        .unwrap();
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM injection_item"), 0);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM outcome"), 0);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM injection"), 1);
}

/// Backup temporaries (`awm.db.bak-v*.tmp*`) left in `dir`.
fn leftover_tmp(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("awm.db.bak-v") && n.contains(".tmp"))
        .collect()
}

#[test]
fn migrating_a_database_with_data_writes_a_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_in(dir.path());
    let mut conn = fresh(dir.path());
    insert_search(&conn, "tu1", "alpha");

    let mut next = MIGRATIONS.to_vec();
    next.push((3, "0003_test", "CREATE TABLE extra (x INTEGER);"));
    let out = db::migrate_with(&mut conn, &next).unwrap();

    let bak = dir.path().join("awm.db.bak-v2");
    assert_eq!(out.from, 2);
    assert_eq!(out.to, 3);
    assert_eq!(
        out.backup.as_deref().map(|p| p.canonicalize().unwrap()),
        Some(bak.canonicalize().unwrap())
    );
    assert_eq!(leftover_tmp(dir.path()), Vec::<String>::new());
    assert_eq!(db::schema_version(&conn).unwrap(), 3);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM extra"), 0);

    let old = Connection::open(&bak).unwrap();
    assert_eq!(db::schema_version(&old).unwrap(), 2);
    assert_eq!(count(&old, "SELECT COUNT(*) FROM event"), 1);
    assert_eq!(fts_hits(&old, "alpha").len(), 1);
    #[cfg(unix)]
    assert_eq!(mode(&bak), 0o600);

    // The live database is untouched apart from the new migration.
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM event"), 1);
    assert!(path.exists());
}

/// A database as v0.1 left it: only `0001_init` applied.
fn v1(dir: &Path) -> Connection {
    let mut conn = db::open(&db_in(dir), Role::Cli).unwrap();
    db::migrate_with(&mut conn, &MIGRATIONS[..1]).unwrap();
    conn
}

#[test]
fn v1_database_with_data_migrates_to_v2() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = v1(dir.path());
    let a = insert_search(&conn, "tu1", "alpha");
    insert_search(&conn, "tu2", "bravo");
    insert_search(&conn, "tu3", "charlie");
    for rank in 1..=2 {
        conn.execute(
            "INSERT INTO result (event_id, rank, url, url_norm) VALUES (?1, ?2, 'https://a.example/', 'a.example/')",
            rusqlite::params![a, rank],
        )
        .unwrap();
    }
    assert_eq!(
        db::check_version(&conn).unwrap(),
        VersionCheck::Older { db: 1, bin: 2 }
    );
    // A stale temporary from the old fixed name does not get in the way.
    std::fs::write(dir.path().join("awm.db.bak-v1.tmp"), "stale").unwrap();

    let out = db::migrate(&mut conn).unwrap();
    let bak = dir.path().join("awm.db.bak-v1");
    assert_eq!((out.from, out.to), (1, 2));
    assert_eq!(
        out.backup.as_deref().map(|p| p.canonicalize().unwrap()),
        Some(bak.canonicalize().unwrap())
    );
    assert_eq!(db::check_version(&conn).unwrap(), VersionCheck::Current);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM event"), 3);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM result"), 2);
    assert_eq!(
        count(&conn, "SELECT COUNT(*) FROM event WHERE agent = 'claude'"),
        3
    );
    assert_eq!(fts_hits(&conn, "bravo").len(), 1);
    assert_eq!(fts_hits(&conn, "alpha OR charlie").len(), 2);
    let quick: String = conn
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(quick, "ok");
    assert_eq!(
        leftover_tmp(dir.path()),
        vec!["awm.db.bak-v1.tmp".to_string()]
    );

    let old = Connection::open(&bak).unwrap();
    assert_eq!(db::schema_version(&old).unwrap(), 1);
    assert_eq!(count(&old, "SELECT COUNT(*) FROM event"), 3);
    assert_eq!(count(&old, "SELECT COUNT(*) FROM result"), 2);
    assert_eq!(
        count(
            &old,
            "SELECT COUNT(*) FROM pragma_table_info('event') WHERE name = 'agent'"
        ),
        0
    );
    #[cfg(unix)]
    assert_eq!(mode(&bak), 0o600);
}

#[test]
fn agent_column_defaults_to_claude_and_rejects_other_values() {
    let dir = tempfile::tempdir().unwrap();
    let conn = fresh(dir.path());
    let id = insert_search(&conn, "tu1", "alpha");
    let agent: String = conn
        .query_row("SELECT agent FROM event WHERE id = ?1", [id], |r| r.get(0))
        .unwrap();
    assert_eq!(agent, "claude");
    conn.execute("UPDATE event SET agent = 'codex' WHERE id = ?1", [id])
        .unwrap();
    let err = conn
        .execute("UPDATE event SET agent = 'other' WHERE id = ?1", [id])
        .unwrap_err()
        .to_string();
    assert!(err.contains("CHECK constraint failed"), "{err}");
    let err = conn
        .execute(
            "INSERT INTO event (tool_use_id, tool, session_id, cwd_hash, created_at, query, \
             status, match_text, source, agent) \
             VALUES ('tu2', 'WebSearch', 's1', 'h', 1, 'q', 'ok', 'x', 'hook', 'other')",
            [],
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("CHECK constraint failed"), "{err}");
    assert!(conn
        .execute(
            "INSERT INTO event (tool_use_id, tool, session_id, cwd_hash, created_at, query, \
             status, match_text, source, agent) \
             VALUES ('tu3', 'WebSearch', 's1', 'h', 1, 'q', 'ok', 'x', 'hook', NULL)",
            [],
        )
        .is_err());
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
#[test]
fn new_directory_is_0700_and_new_files_are_0600() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("nested").join("data");
    let path = db_in(&data);
    let mut conn = db::open(&path, Role::Capture).unwrap();
    db::migrate(&mut conn).unwrap();
    insert_search(&conn, "tu1", "alpha");
    assert_eq!(mode(&data), 0o700);
    assert_eq!(mode(&path), 0o600);
    let wal = data.join("awm.db-wal");
    let shm = data.join("awm.db-shm");
    assert!(wal.exists());
    assert_eq!(mode(&wal), 0o600);
    assert_eq!(mode(&shm), 0o600);
}

#[cfg(unix)]
#[test]
fn ensure_private_dir_creates_0700() {
    let dir = tempfile::tempdir().unwrap();
    let home = awm::paths::data_dir_from(Some(OsString::from(dir.path().join("home")))).unwrap();
    awm::paths::ensure_private_dir(&home).unwrap();
    assert_eq!(mode(&home), 0o700);
}

#[test]
fn data_dir_honours_awm_home_argument() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("h");
    assert_eq!(
        awm::paths::data_dir_from(Some(home.clone().into_os_string())).unwrap(),
        home
    );
    let default = awm::paths::data_dir_from(Some(OsString::new())).unwrap();
    assert!(
        default.ends_with("agent-web-memory"),
        "{}",
        default.display()
    );
    assert_eq!(
        awm::paths::data_dir_from(None).unwrap(),
        default,
        "empty AWM_HOME means unset"
    );
}

#[test]
fn hook_read_on_missing_file_fails_without_creating_it() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let path = db_in(&data);
    let err = db::open(&path, Role::HookRead).unwrap_err().to_string();
    assert!(err.contains("database not found"), "{err}");
    assert!(!path.exists());
    assert!(!data.exists());
}

#[test]
fn busy_timeout_and_pragmas_follow_the_role() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_in(dir.path());
    drop(fresh(dir.path()));
    for (role, ms) in [
        (Role::HookRead, 50),
        (Role::Capture, 2_000),
        (Role::Cli, 5_000),
    ] {
        let conn = db::open(&path, role).unwrap();
        assert_eq!(count(&conn, "PRAGMA busy_timeout"), ms, "{role:?}");
        let jm: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(jm, "wal");
        assert_eq!(count(&conn, "PRAGMA synchronous"), 1, "NORMAL");
        assert_eq!(count(&conn, "PRAGMA foreign_keys"), 1);
        assert_eq!(count(&conn, "PRAGMA secure_delete"), 1);
    }
}
