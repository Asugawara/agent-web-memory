//! Schema, migration runner and data path tests (plan-v2 §6.1, §6.2, §5.7;
//! plan-v3-team §4.4 for 0003; STATS1 for 0004).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use awm::capture::{self, CaptureOpts, CaptureOutcome};
use awm::config::Config;
use awm::db::{self, MigrateOutcome, Role, VersionCheck, MIGRATIONS};
use rusqlite::types::Value as SqlValue;
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
    "sync_state",
    "sync_stream",
    "sync_outbox",
    "sync_own",
    "roster_record",
    "team_member",
    "team_device",
    "project",
    "share_rule",
    "cwd",
];

const INDEXES: &[&str] = &[
    "event_url_norm",
    "event_created_at",
    "event_session",
    "event_sync_id",
    "event_origin",
    "result_url_norm",
    "injection_created_at",
    "injection_agent",
    "injection_cwd",
    "injection_item_event",
    "hook_run_started_at",
];

const TRIGGERS: &[&str] = &[
    "event_fts_ai",
    "event_fts_ad",
    "event_fts_au",
    "injection_item_origin_ai",
];

/// Tables whose rows a migration must keep, with the order that makes a dump comparable.
const DATA_TABLES: &[(&str, &str)] = &[
    ("meta", "key"),
    ("import_source", "id"),
    ("event", "id"),
    ("result", "event_id, rank"),
    ("injection", "id"),
    ("injection_item", "injection_id, position"),
    ("outcome", "injection_id, position"),
    ("hook_run", "id"),
    ("tombstone", "kind, value"),
];

/// sha256 of `0003_team.sql` as released: databases at version 3 record it.
const CHECKSUM_0003: &str = "6f944cd3d3d2deff31085bc15b6650b5fb3af53bf3456552ecf43745d7671186";

/// sha256 of `0004_cwd.sql` as released: databases at version 4 record it.
const CHECKSUM_0004: &str = "e04fe64c6d339e7c4b3c9cb14b4dc7f72ad75556433d9af364fbedcb35b9858d";

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
fn fresh_database_migrates_to_version_4() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = db::open(&db_in(dir.path()), Role::Cli).unwrap();
    assert_eq!(db::schema_version(&conn).unwrap(), 0);
    let out = db::migrate(&mut conn).unwrap();
    assert_eq!(
        out,
        MigrateOutcome {
            from: 0,
            to: 4,
            backup: None
        }
    );
    assert_eq!(db::schema_version(&conn).unwrap(), 4);
    // The runner turns foreign keys back on after the 0003 rebuild.
    assert_eq!(count(&conn, "PRAGMA foreign_keys"), 1);
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
            (3, "0003_team".to_string(), db::checksum(MIGRATIONS[2].2)),
            (4, "0004_cwd".to_string(), db::checksum(MIGRATIONS[3].2)),
        ]
    );
    assert!(rows.iter().all(|(_, _, sum)| sum.len() == 64));
}

#[test]
fn embedded_migrations_match_the_files() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    assert_eq!(MIGRATIONS.len(), 4);
    for (version, name, sql) in MIGRATIONS {
        let file = std::fs::read_to_string(dir.join(format!("{name}.sql"))).unwrap();
        assert_eq!(db::checksum(sql), db::checksum(&file), "{name}");
        assert!(name.starts_with(&format!("{version:04}_")), "{name}");
        // The runner owns the transaction (RV1 m3).
        for word in ["BEGIN", "COMMIT", "SAVEPOINT", "ROLLBACK", "PRAGMA"] {
            let code: String = sql
                .lines()
                .map(|l| l.split("--").next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n")
                .to_uppercase();
            let hits = code
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .filter(|w| *w == word)
                .count();
            // A trigger body is the only BEGIN allowed.
            let allowed = if word == "BEGIN" {
                code.matches("CREATE TRIGGER").count()
            } else {
                0
            };
            assert_eq!(hits, allowed, "{name} contains {word}");
        }
    }
    // 0001 to 0003 are applied on users' databases; their bytes must never change.
    assert_eq!(
        db::checksum(MIGRATIONS[0].2),
        "29660e731f4c8aecf3d376879706c7442c2c8d3df847d71c70688dcfca20e6eb"
    );
    assert_eq!(
        db::checksum(MIGRATIONS[1].2),
        "4eeb90b7505302c46eff8aee5d878a05f342be873ffdeaa9da16a8262c3adc72"
    );
    assert_eq!(db::checksum(MIGRATIONS[2].2), CHECKSUM_0003);
    assert_eq!(db::checksum(MIGRATIONS[3].2), CHECKSUM_0004);
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
            from: 4,
            to: 4,
            backup: None
        }
    );
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM schema_version"), 4);
    assert!(!dir.path().join("awm.db.bak-v4").exists());
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
        VersionCheck::Older { db: 0, bin: 4 }
    );
    db::migrate_with(&mut conn, &MIGRATIONS[..2]).unwrap();
    assert_eq!(
        db::check_version(&conn).unwrap(),
        VersionCheck::Older { db: 2, bin: 4 }
    );
    db::migrate(&mut conn).unwrap();
    assert_eq!(db::check_version(&conn).unwrap(), VersionCheck::Current);
    conn.execute(
        "INSERT INTO schema_version (version, name, checksum, applied_at) \
         VALUES (5, '0005_future', 'x', 0)",
        [],
    )
    .unwrap();
    assert_eq!(
        db::check_version(&conn).unwrap(),
        VersionCheck::Newer { db: 5, bin: 4 }
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
}

#[test]
fn deleting_an_event_keeps_its_items_outcomes_and_origin() {
    let dir = tempfile::tempdir().unwrap();
    let conn = fresh(dir.path());
    let local = insert_search(&conn, "tu1", "alpha");
    let team = insert_search(&conn, "team:abc", "bravo");
    conn.execute("UPDATE event SET origin = 'team' WHERE id = ?1", [team])
        .unwrap();
    let a = insert_injection_chain(&conn, "0000abce", local);
    let b = insert_injection_chain(&conn, "0000abcf", team);
    // The writer names only the 0001 columns; the trigger copies event.origin.
    let origins = |conn: &Connection| -> Vec<(i64, Option<i64>, String)> {
        let mut st = conn
            .prepare(
                "SELECT injection_id, event_id, origin FROM injection_item ORDER BY injection_id",
            )
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(
        origins(&conn),
        vec![
            (a, Some(local), "local".to_string()),
            (b, Some(team), "team".to_string())
        ]
    );

    // Not a constraint error: event_id becomes NULL, the item and its label stay.
    conn.execute("DELETE FROM event WHERE id = ?1", [team])
        .unwrap();
    conn.execute("DELETE FROM event WHERE id = ?1", [local])
        .unwrap();
    assert_eq!(
        origins(&conn),
        vec![
            (a, None, "local".to_string()),
            (b, None, "team".to_string())
        ]
    );
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM outcome"), 2);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM injection"), 2);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM event"), 0);

    // An item without an event can still be written, and deleting the injection
    // still removes items and outcomes.
    conn.execute(
        "INSERT INTO injection_item (injection_id, position, event_id, score) VALUES (?1, 2, NULL, 0.5)",
        [a],
    )
    .unwrap();
    conn.execute("DELETE FROM injection WHERE id = ?1", [a])
        .unwrap();
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM injection_item"), 1);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM outcome"), 1);
    // Foreign keys are still enforced on the rebuilt table.
    let err = conn
        .execute(
            "INSERT INTO injection_item (injection_id, position, event_id, score) VALUES (?1, 3, 999, 1.0)",
            [b],
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("FOREIGN KEY constraint failed"), "{err}");
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
    next.push((5, "0005_test", "CREATE TABLE extra (x INTEGER);"));
    let out = db::migrate_with(&mut conn, &next).unwrap();

    let bak = dir.path().join("awm.db.bak-v4");
    assert_eq!(out.from, 4);
    assert_eq!(out.to, 5);
    assert_eq!(
        out.backup.as_deref().map(|p| p.canonicalize().unwrap()),
        Some(bak.canonicalize().unwrap())
    );
    assert_eq!(leftover_tmp(dir.path()), Vec::<String>::new());
    assert_eq!(db::schema_version(&conn).unwrap(), 5);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM extra"), 0);

    let old = Connection::open(&bak).unwrap();
    assert_eq!(db::schema_version(&old).unwrap(), 4);
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
fn v1_database_with_data_migrates_to_v4() {
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
        VersionCheck::Older { db: 1, bin: 4 }
    );
    let ev = insert_search(&conn, "tu4", "delta");
    insert_injection_chain(&conn, "0000abcd", ev);
    // A stale temporary from the old fixed name does not get in the way.
    std::fs::write(dir.path().join("awm.db.bak-v1.tmp"), "stale").unwrap();

    // Every pending migration runs in the one transaction, after one backup at v1.
    let out = db::migrate(&mut conn).unwrap();
    let bak = dir.path().join("awm.db.bak-v1");
    assert_eq!((out.from, out.to), (1, 4));
    assert!(!dir.path().join("awm.db.bak-v2").exists());
    assert!(!dir.path().join("awm.db.bak-v3").exists());
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM schema_version"), 4);
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM injection WHERE cwd_hash IS NULL"
        ),
        1
    );
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM cwd"), 0);
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM event WHERE origin = 'local' AND shareable = 'no' \
             AND member IS NULL AND sync_id IS NULL AND repo_key IS NULL"
        ),
        4
    );
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM injection_item WHERE event_id = (SELECT id FROM event \
             WHERE tool_use_id = 'tu4') AND origin = 'local'"
        ),
        1
    );
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM outcome"), 1);
    assert_eq!(
        out.backup.as_deref().map(|p| p.canonicalize().unwrap()),
        Some(bak.canonicalize().unwrap())
    );
    assert_eq!(db::check_version(&conn).unwrap(), VersionCheck::Current);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM event"), 4);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM result"), 2);
    assert_eq!(
        count(&conn, "SELECT COUNT(*) FROM event WHERE agent = 'claude'"),
        4
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
    assert_eq!(count(&old, "SELECT COUNT(*) FROM event"), 4);
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

// ---- 0003_team (plan-v3-team §4.4) ----

/// (name, declared type, NOT NULL, default) from `pragma_table_info`.
type Column = (String, String, bool, Option<String>);

fn table_info(conn: &Connection, table: &str) -> Vec<Column> {
    let mut st = conn
        .prepare(
            "SELECT name, type, \"notnull\", dflt_value FROM pragma_table_info(?1) ORDER BY cid",
        )
        .unwrap();
    st.query_map([table], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? == 1, r.get(3)?))
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

fn col(name: &str, ty: &str, not_null: bool, default: Option<&str>) -> Column {
    (
        name.to_string(),
        ty.to_string(),
        not_null,
        default.map(str::to_string),
    )
}

#[test]
fn fresh_schema_has_every_team_column_table_and_foreign_key() {
    let dir = tempfile::tempdir().unwrap();
    let conn = fresh(dir.path());
    let event = table_info(&conn, "event");
    let added: Vec<Column> = event[event.len() - 7..].to_vec();
    assert_eq!(
        added,
        vec![
            col("origin", "TEXT", true, Some("'local'")),
            col("member", "TEXT", false, None),
            col("repo_key", "TEXT", false, None),
            col("shareable", "TEXT", true, Some("'no'")),
            col("sync_id", "TEXT", false, None),
            col("pushed_at", "INTEGER", false, None),
            col("sync_idx", "INTEGER", false, None),
        ]
    );
    assert_eq!(event[event.len() - 8].0, "agent");

    let expect: &[(&str, Vec<Column>)] = &[
        (
            "sync_state",
            vec![
                col("key", "TEXT", false, None),
                col("value", "TEXT", true, None),
            ],
        ),
        (
            "sync_stream",
            vec![
                col("member_id", "TEXT", true, None),
                col("device_id", "TEXT", true, None),
                col("tag", "TEXT", true, None),
                col("head_idx", "INTEGER", true, None),
            ],
        ),
        (
            "sync_outbox",
            vec![
                col("id", "INTEGER", false, None),
                col("kind", "TEXT", true, None),
                col("ref", "TEXT", true, None),
                col("created_at", "INTEGER", true, None),
                col("attempts", "INTEGER", true, Some("0")),
                col("last_error", "TEXT", false, None),
            ],
        ),
        (
            "sync_own",
            vec![
                col("tag", "TEXT", true, None),
                col("idx", "INTEGER", true, None),
                col("record_id", "TEXT", true, None),
                col("epoch", "INTEGER", false, None),
                col("blob", "BLOB", false, None),
                col("deleted", "INTEGER", true, Some("0")),
            ],
        ),
        (
            "roster_record",
            vec![
                col("member_id", "TEXT", true, None),
                col("device_id", "TEXT", true, None),
                col("idx", "INTEGER", true, None),
                col("record_id", "TEXT", true, None),
                col("epoch", "INTEGER", true, None),
                col("blob", "BLOB", true, None),
            ],
        ),
        (
            "team_member",
            vec![
                col("member_id", "TEXT", false, None),
                col("handle", "TEXT", true, None),
                col("role", "TEXT", true, None),
                col("active", "INTEGER", true, Some("1")),
                col("updated_at", "INTEGER", true, None),
            ],
        ),
        (
            "team_device",
            vec![
                col("device_id", "TEXT", false, None),
                col("member_id", "TEXT", true, None),
                col("pubkey", "TEXT", true, None),
                col("verified", "INTEGER", true, None),
                col("revoked", "INTEGER", true, Some("0")),
                col("approver", "TEXT", false, None),
                col("updated_at", "INTEGER", true, None),
            ],
        ),
        (
            "project",
            vec![
                col("cwd_hash", "TEXT", false, None),
                col("repo_key", "TEXT", false, None),
                col("updated_at", "INTEGER", true, None),
            ],
        ),
        (
            "share_rule",
            vec![
                col("kind", "TEXT", true, None),
                col("value", "TEXT", true, None),
                col("created_at", "INTEGER", true, None),
            ],
        ),
        (
            "injection_item",
            vec![
                col("injection_id", "INTEGER", true, None),
                col("position", "INTEGER", true, None),
                col("event_id", "INTEGER", false, None),
                col("score", "REAL", true, None),
                col("origin", "TEXT", true, Some("'local'")),
            ],
        ),
    ];
    for (table, cols) in expect {
        assert_eq!(&table_info(&conn, table), cols, "{table}");
    }

    // Primary keys.
    let pk = |table: &str| -> Vec<String> {
        let mut st = conn
            .prepare("SELECT name FROM pragma_table_info(?1) WHERE pk > 0 ORDER BY pk")
            .unwrap();
        st.query_map([table], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(pk("sync_state"), ["key"]);
    assert_eq!(pk("sync_stream"), ["member_id", "device_id", "tag"]);
    assert_eq!(pk("sync_outbox"), ["id"]);
    assert_eq!(pk("sync_own"), ["tag", "idx"]);
    assert_eq!(pk("roster_record"), ["member_id", "device_id", "idx"]);
    assert_eq!(pk("team_member"), ["member_id"]);
    assert_eq!(pk("team_device"), ["device_id"]);
    assert_eq!(pk("project"), ["cwd_hash"]);
    assert_eq!(pk("share_rule"), ["kind", "value"]);
    assert_eq!(pk("injection_item"), ["injection_id", "position"]);

    // Foreign keys: injection_item's event link is SET NULL; outcome still points at the rebuilt table.
    let fks = |table: &str| -> Vec<(String, String, String, String)> {
        let mut st = conn
            .prepare(
                "SELECT \"table\", \"from\", \"to\", on_delete FROM pragma_foreign_key_list(?1) \
                 ORDER BY id, seq",
            )
            .unwrap();
        st.query_map([table], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    };
    let mut item = fks("injection_item");
    item.sort();
    let s = |a: &str, b: &str, c: &str, d: &str| {
        (a.to_string(), b.to_string(), c.to_string(), d.to_string())
    };
    assert_eq!(
        item,
        vec![
            s("event", "event_id", "id", "SET NULL"),
            s("injection", "injection_id", "id", "CASCADE")
        ]
    );
    assert_eq!(
        fks("outcome"),
        vec![
            s("injection_item", "injection_id", "injection_id", "CASCADE"),
            s("injection_item", "position", "position", "CASCADE")
        ]
    );
    for t in [
        "sync_state",
        "sync_stream",
        "sync_outbox",
        "sync_own",
        "roster_record",
        "team_member",
        "team_device",
        "project",
        "share_rule",
    ] {
        assert!(fks(t).is_empty(), "{t}");
    }
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'injection_item_new'"
        ),
        0
    );
    // The partial unique index and the origin index.
    let index_sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name = 'event_sync_id'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(index_sql.contains("UNIQUE") && index_sql.contains("WHERE sync_id IS NOT NULL"));
    let cols = |index: &str| -> Vec<String> {
        let mut st = conn
            .prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")
            .unwrap();
        st.query_map([index], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(cols("event_origin"), ["origin", "created_at"]);
    assert_eq!(cols("event_sync_id"), ["sync_id"]);
    assert_eq!(cols("event_created_at"), ["created_at"]);
    assert_eq!(cols("injection_item_event"), ["event_id"]);
}

#[test]
fn team_checks_reject_values_outside_their_sets() {
    let dir = tempfile::tempdir().unwrap();
    let conn = fresh(dir.path());
    let ev = insert_search(&conn, "tu1", "alpha");
    let inj = insert_injection_chain(&conn, "0000abcd", ev);
    let ok = [
        "UPDATE event SET origin = 'team', shareable = 'full' WHERE id = 1".to_string(),
        // RVT1 M4: 'never' marks a record the user unshared; 'no' is "not pushed yet".
        "UPDATE event SET origin = 'local', shareable = 'never' WHERE id = 1".to_string(),
        "UPDATE event SET shareable = 'link', sync_id = 'u1', member = 'm', repo_key = 'r', \
         pushed_at = 1, sync_idx = 0 WHERE id = 1"
            .to_string(),
        "INSERT INTO sync_state (key, value) VALUES ('deletion_head', '0')".to_string(),
        "INSERT INTO sync_stream VALUES ('m', 'd', 'rec', 0)".to_string(),
        "INSERT INTO sync_outbox (kind, ref, created_at) VALUES ('record', 'rec:0', 1), \
         ('roster', 'roster:0', 1), ('delete', 'u', 1), ('flag', 'flag:0', 1), \
         ('stats', 'stats:0', 1), ('policy', 'policy:0', 1)"
            .to_string(),
        "INSERT INTO sync_own (tag, idx, record_id, epoch, blob) VALUES ('rec', 0, 'r0', 1, x'01'), \
         ('roster', 0, 'r1', 1, x'01')"
            .to_string(),
        "INSERT INTO sync_own (tag, idx, record_id, deleted) VALUES ('rec', 1, 'r2', 1)".to_string(),
        "INSERT INTO roster_record VALUES ('m', 'd', 0, 'r3', 0, x'01')".to_string(),
        "INSERT INTO team_member (member_id, handle, role, updated_at) VALUES ('m', 'h', 'member', 1), \
         ('a', 'g', 'admin', 1)"
            .to_string(),
        "INSERT INTO team_device (device_id, member_id, pubkey, verified, updated_at) \
         VALUES ('d', 'm', 'k', 1, 1), ('e', 'm', 'k', 0, 1)"
            .to_string(),
        "INSERT INTO project (cwd_hash, updated_at) VALUES ('h', 1)".to_string(),
        "INSERT INTO share_rule VALUES ('repo', 'r', 1), ('cwd', 'h', 1)".to_string(),
        format!("UPDATE injection_item SET origin = 'team' WHERE injection_id = {inj}"),
    ];
    for sql in &ok {
        conn.execute_batch(sql)
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }
    let bad = [
        "UPDATE event SET origin = 'other' WHERE id = 1",
        "UPDATE event SET origin = NULL WHERE id = 1",
        "UPDATE event SET shareable = 'yes' WHERE id = 1",
        "UPDATE event SET shareable = NULL WHERE id = 1",
        "INSERT INTO sync_outbox (kind, ref, created_at) VALUES ('other', '1', 1)",
        "INSERT INTO sync_own (tag, idx, record_id, deleted) VALUES ('rec', 9, 'r9', 2)",
        "INSERT INTO sync_own (tag, idx) VALUES ('rec', 9)",
        "INSERT INTO roster_record (member_id, device_id, idx, record_id, epoch) \
         VALUES ('m', 'd', 9, 'r', 0)",
        "INSERT INTO team_member (member_id, handle, role, updated_at) VALUES ('x', 'h', 'owner', 1)",
        "INSERT INTO team_member (member_id, handle, role, active, updated_at) VALUES ('x', 'h', 'member', 2, 1)",
        "INSERT INTO team_device (device_id, member_id, pubkey, verified, updated_at) VALUES ('x', 'm', 'k', 2, 1)",
        "INSERT INTO team_device (device_id, member_id, pubkey, verified, revoked, updated_at) VALUES ('x', 'm', 'k', 1, 2, 1)",
        "INSERT INTO share_rule VALUES ('path', 'p', 1)",
        "UPDATE injection_item SET origin = 'other'",
    ];
    for sql in bad {
        let err = conn.execute_batch(sql).unwrap_err().to_string();
        assert!(
            err.contains("CHECK constraint failed") || err.contains("NOT NULL constraint failed"),
            "{sql}: {err}"
        );
    }
    // sync_id is unique when set; any number of rows may have none.
    insert_search(&conn, "tu2", "bravo");
    insert_search(&conn, "tu3", "charlie");
    let err = conn
        .execute("UPDATE event SET sync_id = 'u1' WHERE id = 2", [])
        .unwrap_err()
        .to_string();
    assert!(err.contains("UNIQUE constraint failed"), "{err}");
    assert_eq!(
        count(&conn, "SELECT COUNT(*) FROM event WHERE sync_id IS NULL"),
        2
    );
}

/// A database at schema version 2 (v0.1 with 0002).
fn v2(dir: &Path) -> Connection {
    let mut conn = db::open(&db_in(dir), Role::Cli).unwrap();
    db::migrate_with(&mut conn, &MIGRATIONS[..2]).unwrap();
    conn
}

/// Seeds every table that holds user data: `n` events (searches and fetches,
/// hook and import, both agents), results, injections with items and outcomes,
/// hook runs, tombstones, meta and an import source.
fn seed(conn: &Connection, n: i64) {
    conn.execute_batch(
        "INSERT INTO meta (key, value) VALUES ('consent.record', 'yes'), ('cutoff.query', '0.5');
         INSERT INTO import_source (path, head_sha256, file_size, file_mtime, status, imported_at)
           VALUES ('/t/a.jsonl', 'aa', 10, 1, 'ok', 1);
         INSERT INTO tombstone VALUES ('tool_use_id', 'gone1', 1), ('url_hash', 'ff', 2);",
    )
    .unwrap();
    for i in 0..n {
        let (tool, query, url, norm) = if i % 2 == 0 {
            ("WebSearch", Some(format!("query {i}")), None, None)
        } else {
            (
                "WebFetch",
                None,
                Some(format!("https://e{i}.example/p?x=1")),
                Some(format!("e{i}.example/p?x=1")),
            )
        };
        conn.execute(
            "INSERT INTO event (tool_use_id, tool, session_id, agent_id, cwd_hash, created_at, \
             query, url, url_norm, status, summary, match_text, source, import_source_id, agent) \
             VALUES (?1, ?2, 's1', ?3, 'h', ?4, ?5, ?6, ?7, 'ok', 'sum', ?8, ?9, ?10, ?11)",
            rusqlite::params![
                format!("tu{i}"),
                tool,
                (i % 3 == 0).then_some("sub"),
                1_000 + i,
                query,
                url,
                norm,
                format!("word{i} common"),
                if i % 5 == 0 { "import" } else { "hook" },
                (i % 5 == 0).then_some(1),
                if i % 4 == 0 { "codex" } else { "claude" },
            ],
        )
        .unwrap();
        let id = conn.last_insert_rowid();
        if tool == "WebSearch" {
            for rank in 1..=2 {
                conn.execute(
                    "INSERT INTO result (event_id, rank, url, url_norm, title) \
                     VALUES (?1, ?2, ?3, ?3, 't')",
                    rusqlite::params![id, rank, format!("r{i}-{rank}.example/")],
                )
                .unwrap();
            }
        }
    }
    for j in 0..(n / 4).max(1) {
        conn.execute(
            "INSERT INTO injection (ref, created_at, hook, channel, mode, session_id, latency_ms) \
             VALUES (?1, ?2, 'PostToolUse', 'url', 'inject', 's1', 3)",
            rusqlite::params![format!("{j:08x}"), 2_000 + j],
        )
        .unwrap();
        let inj = conn.last_insert_rowid();
        for pos in 1..=3_i64 {
            let event = (j * 3 + pos - 1) % n + 1;
            conn.execute(
                "INSERT INTO injection_item (injection_id, position, event_id, score) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![inj, pos, event, 1.0 / pos as f64],
            )
            .unwrap();
            if pos < 3 {
                conn.execute(
                    "INSERT INTO outcome VALUES (?1, ?2, ?3, 5)",
                    rusqlite::params![inj, pos, if pos == 1 { "2" } else { "h" }],
                )
                .unwrap();
            }
        }
    }
    for k in 0..10 {
        conn.execute(
            "INSERT INTO hook_run (started_at, hook, agent_kind, total_ms, outcome) \
             VALUES (?1, 'capture', 'main', 3, 'captured')",
            [k],
        )
        .unwrap();
    }
}

fn columns(conn: &Connection, table: &str) -> Vec<String> {
    table_info(conn, table).into_iter().map(|c| c.0).collect()
}

/// Every row of `table`, restricted to `cols`, in a fixed order.
fn dump(conn: &Connection, table: &str, order: &str, cols: &[String]) -> Vec<Vec<SqlValue>> {
    let mut st = conn
        .prepare(&format!(
            "SELECT {} FROM {table} ORDER BY {order}",
            cols.join(", ")
        ))
        .unwrap();
    st.query_map([], |r| {
        (0..cols.len())
            .map(|i| r.get::<_, SqlValue>(i))
            .collect::<Result<Vec<_>, _>>()
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

type Snapshot = Vec<(String, Vec<String>, Vec<Vec<SqlValue>>)>;

/// Every user-data table with its columns at the time of the call.
fn snapshot(conn: &Connection) -> Snapshot {
    DATA_TABLES
        .iter()
        .map(|(t, order)| {
            let cols = columns(conn, t);
            let rows = dump(conn, t, order, &cols);
            (t.to_string(), cols, rows)
        })
        .collect()
}

/// `conn` holds every row of `before`, column for column.
fn assert_keeps(conn: &Connection, before: &Snapshot) {
    for (t, cols, rows) in before {
        let order = DATA_TABLES.iter().find(|(n, _)| n == t).unwrap().1;
        assert_eq!(&dump(conn, t, order, cols), rows, "{t}");
    }
}

fn pragma_ok(conn: &Connection, pragma: &str) {
    let rows: Vec<String> = conn
        .prepare(&format!("PRAGMA {pragma}"))
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows, ["ok"], "{pragma}");
}

fn assert_no_fk_violation(conn: &Connection) {
    assert_eq!(
        count(conn, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        0
    );
}

#[test]
fn v2_database_with_data_migrates_to_v4_and_keeps_every_row() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = v2(dir.path());
    seed(&conn, 40);
    let before = snapshot(&conn);
    let n_fts = count(&conn, "SELECT COUNT(*) FROM event_fts");
    assert_eq!(n_fts, 40);
    assert_eq!(
        db::check_version(&conn).unwrap(),
        VersionCheck::Older { db: 2, bin: 4 }
    );

    let out = db::migrate(&mut conn).unwrap();
    let bak = dir.path().join("awm.db.bak-v2");
    assert_eq!((out.from, out.to), (2, 4));
    assert_eq!(
        out.backup.as_deref().map(|p| p.canonicalize().unwrap()),
        Some(bak.canonicalize().unwrap())
    );
    assert_eq!(db::check_version(&conn).unwrap(), VersionCheck::Current);
    assert_eq!(count(&conn, "PRAGMA foreign_keys"), 1);

    // Every row, column for column; the new columns hold their defaults.
    assert_keeps(&conn, &before);
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM event WHERE origin = 'local' AND shareable = 'no' \
             AND member IS NULL AND sync_id IS NULL AND repo_key IS NULL \
             AND pushed_at IS NULL AND sync_idx IS NULL"
        ),
        40
    );
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM injection_item WHERE origin = 'local' AND event_id IS NOT NULL"
        ),
        30
    );
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM outcome"), 20);
    for t in [
        "sync_state",
        "sync_stream",
        "sync_outbox",
        "sync_own",
        "roster_record",
        "team_member",
        "team_device",
        "project",
        "share_rule",
        "cwd",
    ] {
        assert_eq!(count(&conn, &format!("SELECT COUNT(*) FROM {t}")), 0, "{t}");
    }
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM injection WHERE cwd_hash IS NULL"
        ),
        10
    );
    pragma_ok(&conn, "quick_check");
    pragma_ok(&conn, "integrity_check");
    assert_no_fk_violation(&conn);

    // The FTS index and its triggers.
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM event_fts"), n_fts);
    conn.execute_batch("INSERT INTO event_fts(event_fts) VALUES ('integrity-check')")
        .unwrap();
    assert_eq!(fts_hits(&conn, "common").len(), 40);
    assert_eq!(fts_hits(&conn, "word7"), vec![8]);
    let new = insert_search(&conn, "tu-new", "zebra");
    assert_eq!(fts_hits(&conn, "zebra"), vec![new]);
    conn.execute("UPDATE event SET match_text = 'yak' WHERE id = ?1", [new])
        .unwrap();
    assert!(fts_hits(&conn, "zebra").is_empty());
    assert_eq!(fts_hits(&conn, "yak"), vec![new]);
    // An UPDATE of a sync column leaves the FTS row alone.
    conn.execute("UPDATE event SET sync_id = 'u' WHERE id = ?1", [new])
        .unwrap();
    assert_eq!(fts_hits(&conn, "yak"), vec![new]);
    conn.execute("DELETE FROM event WHERE id = ?1", [new])
        .unwrap();
    assert!(fts_hits(&conn, "yak").is_empty());

    // The backup: at v2, every row, no 0003 column, 0600.
    let old = Connection::open(&bak).unwrap();
    assert_eq!(db::schema_version(&old).unwrap(), 2);
    assert_keeps(&old, &before);
    assert!(!columns(&old, "event").contains(&"origin".to_string()));
    assert!(!columns(&old, "injection_item").contains(&"origin".to_string()));
    pragma_ok(&old, "quick_check");
    drop(old);
    #[cfg(unix)]
    assert_eq!(mode(&bak), 0o600);
    assert_eq!(leftover_tmp(dir.path()), Vec::<String>::new());

    // A rerun is a no-op and leaves the backup alone.
    let bak_bytes = std::fs::read(&bak).unwrap();
    assert_eq!(
        db::migrate(&mut conn).unwrap(),
        MigrateOutcome {
            from: 4,
            to: 4,
            backup: None
        }
    );
    assert_eq!(std::fs::read(&bak).unwrap(), bak_bytes);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM schema_version"), 4);
    assert_keeps(&conn, &before);
}

#[test]
fn concurrent_migrators_lose_nothing() {
    const ROUNDS: usize = 20;
    const THREADS: usize = 4;
    let (mut wins, mut no_ops, mut changed, mut collided) = (0, 0, 0, 0);
    for round in 0..ROUNDS {
        let dir = tempfile::tempdir().unwrap();
        let before = {
            let conn = v2(dir.path());
            seed(&conn, 200);
            snapshot(&conn)
        };
        let path = db_in(dir.path());
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let (path, barrier) = (path.clone(), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    let mut conn = db::open(&path, Role::Cli).unwrap();
                    barrier.wait();
                    let r = db::migrate(&mut conn).map_err(|e| format!("{e:#}"));
                    // Every migrator leaves its connection with foreign keys on.
                    assert_eq!(count(&conn, "PRAGMA foreign_keys"), 1);
                    r
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let mut round_wins = 0;
        for r in &results {
            match r {
                Ok(o) if o.from == 2 && o.to == 4 && o.backup.is_some() => round_wins += 1,
                Ok(o) if o.from == 4 && o.to == 4 && o.backup.is_none() => no_ops += 1,
                Err(e) if e.contains("run the command again") => changed += 1,
                // Threads of one process share a pid (RV5 m5); create_new refuses the name.
                Err(e) if e.contains("File exists") => collided += 1,
                other => panic!("round {round}: unexpected {other:?}"),
            }
        }
        assert_eq!(round_wins, 1, "round {round}: {results:?}");
        wins += round_wins;

        let mut conn = db::open(&path, Role::Cli).unwrap();
        assert_eq!(db::schema_version(&conn).unwrap(), 4, "round {round}");
        assert_keeps(&conn, &before);
        pragma_ok(&conn, "quick_check");
        assert_no_fk_violation(&conn);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM event_fts"), 200);
        let old = Connection::open(dir.path().join("awm.db.bak-v2")).unwrap();
        assert_eq!(db::schema_version(&old).unwrap(), 2, "round {round}");
        assert_keeps(&old, &before);
        pragma_ok(&old, "quick_check");
        assert_eq!(leftover_tmp(dir.path()), Vec::<String>::new());
        assert_eq!(db::migrate(&mut conn).unwrap().from, 4);
    }
    eprintln!(
        "concurrent migrators: {ROUNDS} rounds x {THREADS} threads: {wins} migrated, \
         {no_ops} no-op, {changed} 'run the command again', {collided} temporary-name collisions"
    );
    assert_eq!(wins, ROUNDS);
}

#[test]
fn a_migration_that_breaks_a_foreign_key_is_rolled_back() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = fresh(dir.path());
    insert_search(&conn, "tu1", "alpha");
    let mut next = MIGRATIONS.to_vec();
    next.push((
        5,
        "0005_test",
        "CREATE TABLE extra (x INTEGER);\n\
         INSERT INTO result (event_id, rank, url, url_norm) VALUES (999, 1, 'u', 'u');",
    ));
    let err = format!("{:#}", db::migrate_with(&mut conn, &next).unwrap_err());
    assert!(
        err.contains("1 row(s) violate a foreign key (result rowid 1 -> event)"),
        "{err}"
    );
    assert_eq!(db::schema_version(&conn).unwrap(), 4);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM result"), 0);
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'extra'"
        ),
        0
    );
    assert_eq!(count(&conn, "PRAGMA foreign_keys"), 1);

    // A migration that fails outright also leaves foreign keys on.
    next[4] = (5, "0005_test", "CREATE TABLE (;");
    let err = format!("{:#}", db::migrate_with(&mut conn, &next).unwrap_err());
    assert!(err.contains("migration 0005_test failed"), "{err}");
    assert_eq!(count(&conn, "PRAGMA foreign_keys"), 1);
    assert_eq!(db::schema_version(&conn).unwrap(), 4);
}

/// Library-level version of the `hooks_e2e` upgrade window (plan-v2 §5.4, F6) for a
/// version-2 database: the new binary is installed and `awm doctor` has not run.
#[test]
fn capture_spools_at_version_2_and_the_spool_is_stored_after_migrating() {
    let dir = tempfile::tempdir().unwrap();
    drop(v2(dir.path()));
    let opts = CaptureOpts {
        data_dir: dir.path().to_path_buf(),
        config: Config::default(),
        now_ms: 1_790_000_000_000,
    };
    let fixture = |name: &str| -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/hooks")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    };
    let spool_files = || match std::fs::read_dir(dir.path().join("spool")) {
        Ok(d) => d.count(),
        Err(_) => 0,
    };
    let fetch = fixture("PostToolUse-WebFetch-plugin-3.json");
    let codex = fixture("codex-PostToolUse-webrun-search-1.json");
    assert_eq!(
        capture::run(&fetch, &opts).unwrap(),
        CaptureOutcome::Spooled
    );
    assert_eq!(
        capture::run(&codex, &opts).unwrap(),
        CaptureOutcome::Spooled
    );
    assert_eq!(spool_files(), 2);
    // A drain in the window keeps the files.
    assert_eq!(capture::drain_spool(&opts).unwrap(), 0);
    assert_eq!(spool_files(), 2);
    {
        let conn = db::open(&db_in(dir.path()), Role::Cli).unwrap();
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM event"), 0);
        assert_eq!(
            db::check_version(&conn).unwrap(),
            VersionCheck::Older { db: 2, bin: 4 }
        );
    }

    // What `awm doctor` does: migrate, then drain.
    let mut conn = db::open(&db_in(dir.path()), Role::Cli).unwrap();
    let out = db::migrate(&mut conn).unwrap();
    assert_eq!((out.from, out.to), (2, 4));
    assert!(dir.path().join("awm.db.bak-v2").is_file());
    assert_eq!(capture::drain_spool(&opts).unwrap(), 2);
    assert_eq!(spool_files(), 0);
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM event WHERE origin = 'local' AND shareable = 'no' \
             AND sync_id IS NULL"
        ),
        2
    );
    assert_eq!(
        count(&conn, "SELECT COUNT(*) FROM event WHERE agent = 'codex'"),
        1
    );
    // The same call again is a duplicate; capture keeps working at v4 with the defaults.
    assert_eq!(
        capture::run(&fetch, &opts).unwrap(),
        CaptureOutcome::Skipped("duplicate")
    );
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM event"), 2);
}

// ---- 0004_cwd (STATS1) ----

#[test]
fn fresh_schema_has_the_cwd_table_and_the_injection_column() {
    let dir = tempfile::tempdir().unwrap();
    let conn = fresh(dir.path());
    assert_eq!(
        table_info(&conn, "cwd"),
        vec![
            col("cwd_hash", "TEXT", false, None),
            col("path", "TEXT", true, None),
            col("repo_root", "TEXT", false, None),
            col("updated_at", "INTEGER", true, None),
        ]
    );
    let pk: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('cwd') WHERE pk > 0")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(pk, ["cwd_hash"]);
    let injection = table_info(&conn, "injection");
    assert_eq!(
        injection.last().unwrap(),
        &col("cwd_hash", "TEXT", false, None)
    );
    let index: Vec<String> = conn
        .prepare("SELECT name FROM pragma_index_info('injection_cwd') ORDER BY seqno")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(index, ["cwd_hash"]);
    // Local only: no foreign key ties it to anything synced.
    assert_eq!(
        count(&conn, "SELECT COUNT(*) FROM pragma_foreign_key_list('cwd')"),
        0
    );
    // The primary key refuses a second row for one hash; path is required.
    conn.execute_batch("INSERT INTO cwd VALUES ('h', '/p', NULL, 1)")
        .unwrap();
    let err = conn
        .execute_batch("INSERT INTO cwd VALUES ('h', '/q', NULL, 2)")
        .unwrap_err()
        .to_string();
    assert!(err.contains("UNIQUE constraint failed"), "{err}");
    let err = conn
        .execute_batch("INSERT INTO cwd (cwd_hash, updated_at) VALUES ('i', 1)")
        .unwrap_err()
        .to_string();
    assert!(err.contains("NOT NULL constraint failed"), "{err}");
}

/// A database at schema version 3 (the team release).
fn v3(dir: &Path) -> Connection {
    let mut conn = db::open(&db_in(dir), Role::Cli).unwrap();
    db::migrate_with(&mut conn, &MIGRATIONS[..3]).unwrap();
    conn
}

#[test]
fn v3_database_with_data_migrates_to_v4_and_keeps_every_row() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = v3(dir.path());
    seed(&conn, 40);
    conn.execute_batch(
        "INSERT INTO project (cwd_hash, repo_key, updated_at) VALUES ('h', 'r', 1);
         INSERT INTO share_rule VALUES ('cwd', 'h', 1);
         UPDATE event SET origin = 'team', member = 'm', sync_id = 'u1' WHERE id = 2;",
    )
    .unwrap();
    let before = snapshot(&conn);
    let team_cols = columns(&conn, "event");
    let team_before = dump(&conn, "event", "id", &team_cols);
    let project_before = dump(&conn, "project", "cwd_hash", &columns(&conn, "project"));
    assert_eq!(
        db::check_version(&conn).unwrap(),
        VersionCheck::Older { db: 3, bin: 4 }
    );

    let out = db::migrate(&mut conn).unwrap();
    let bak = dir.path().join("awm.db.bak-v3");
    assert_eq!((out.from, out.to), (3, 4));
    assert_eq!(
        out.backup.as_deref().map(|p| p.canonicalize().unwrap()),
        Some(bak.canonicalize().unwrap())
    );
    assert_eq!(db::check_version(&conn).unwrap(), VersionCheck::Current);

    assert_keeps(&conn, &before);
    assert_eq!(dump(&conn, "event", "id", &team_cols), team_before);
    assert_eq!(
        dump(&conn, "project", "cwd_hash", &columns(&conn, "project")),
        project_before
    );
    // Old injections have no caller cwd; nothing is invented for them.
    assert_eq!(
        count(
            &conn,
            "SELECT COUNT(*) FROM injection WHERE cwd_hash IS NULL"
        ),
        10
    );
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM cwd"), 0);
    pragma_ok(&conn, "quick_check");
    pragma_ok(&conn, "integrity_check");
    assert_no_fk_violation(&conn);
    assert_eq!(count(&conn, "SELECT COUNT(*) FROM event_fts"), 40);

    let old = Connection::open(&bak).unwrap();
    assert_eq!(db::schema_version(&old).unwrap(), 3);
    assert_keeps(&old, &before);
    assert!(!columns(&old, "injection").contains(&"cwd_hash".to_string()));
    drop(old);
    #[cfg(unix)]
    assert_eq!(mode(&bak), 0o600);

    assert_eq!(
        db::migrate(&mut conn).unwrap(),
        MigrateOutcome {
            from: 4,
            to: 4,
            backup: None
        }
    );
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
