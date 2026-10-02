//! Server migration 0001 and its runner (plan-v3-team §4.2, TM6), tested like the client's
//! (`crates/awm/tests/migrate.rs`, TM4): a fresh database, a second run, the version guard, the
//! checksum guard, a migration over data with its backup, a migration that breaks a foreign
//! key, and concurrent migrators.
//!
//! Run: `cargo test -p awm-server --features sqlite --test store_migrate`.

#![cfg(feature = "sqlite")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use awm_proto::wire::{DeleteRequest, Handle, Id, Key32, PushItem, PushRecord, Tag, Version, B64};
use awm_server::store::sqlite::{
    migrate, migrate_with, open_connection, schema_version, SqliteStore, DB_FILE, MIGRATIONS,
};
use awm_server::store::{
    checksum, Actor, NewBootstrap, OrgDefaults, PushBatch, Store, CANONICAL_TABLES,
};
use rusqlite::types::Value;
use rusqlite::Connection;

const T0: i64 = 1_790_000_000;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "migrate-{tag}-{}-{nanos}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn one(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).unwrap()
}

fn text(conn: &Connection, sql: &str) -> String {
    conn.query_row(sql, [], |r| r.get(0)).unwrap()
}

fn meta(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .ok()
}

/// Every row of every table of the schema (canonical tables and `backup_log`), in key order.
fn raw_dump(conn: &Connection) -> Vec<(String, Vec<Vec<Value>>)> {
    let mut out = Vec::new();
    let tables = CANONICAL_TABLES
        .iter()
        .map(|(t, _)| *t)
        .chain(["backup_log"]);
    for t in tables {
        let mut st = conn
            .prepare(&format!("SELECT * FROM {t} ORDER BY 1, 2"))
            .unwrap();
        let n = st.column_count();
        let rows = st
            .query_map([], |r| (0..n).map(|i| r.get::<_, Value>(i)).collect())
            .unwrap()
            .collect::<Result<Vec<Vec<Value>>, _>>()
            .unwrap();
        out.push((t.to_string(), rows));
    }
    out
}

/// A server database with an organisation, a member's records and a deletion; returns its
/// raw dump.
fn seed(dir: &Path, records: u64) -> Vec<(String, Vec<Vec<Value>>)> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let store = SqliteStore::open(dir).unwrap();
        store
            .set_bootstrap(checksum(b"bootstrap"), T0 + 86_400)
            .await
            .unwrap();
        let device = Id::new_v4();
        let member = store
            .bootstrap(NewBootstrap {
                bootstrap_token_hash: checksum(b"bootstrap"),
                org_id: Id::new_v4(),
                handle: Handle::parse("alf").unwrap(),
                device_id: device,
                device_pubkey: Key32([1; 32]),
                device_token_hash: checksum(device.to_string().as_bytes()),
                defaults: OrgDefaults {
                    retention_days: 365,
                    min_client: Version::new(0, 2, 0),
                    max_members: 100,
                },
                now: T0,
            })
            .await
            .unwrap();
        let ids: Vec<Id> = (0..records).map(|_| Id::new_v4()).collect();
        let items = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                PushItem::Record(PushRecord {
                    tag: Tag::parse("rec").unwrap(),
                    idx: i as u64,
                    id: *id,
                    epoch: 0,
                    blob: B64(vec![1; 297]),
                })
            })
            .collect();
        store
            .push(PushBatch {
                member_id: member,
                device_id: device,
                items,
                now: T0,
            })
            .await
            .unwrap();
        let actor = Actor {
            member_id: member,
            device_id: device,
            admin: true,
        };
        store
            .delete(DeleteRequest::Ids(vec![ids[0]]), actor, T0)
            .await
            .unwrap();
        let conn = Connection::open(dir.join(DB_FILE)).unwrap();
        raw_dump(&conn)
    })
}

fn with_test_migration(sql: &'static str) -> Vec<(u32, &'static str, &'static str)> {
    let mut list = MIGRATIONS.to_vec();
    list.push((2, "0002_test", sql));
    list
}

const EXTRA: &str = "CREATE TABLE extra (n INTEGER NOT NULL);\n\
                     INSERT INTO extra (n) SELECT COUNT(*) FROM record;";

fn leftover_tmp(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp-"))
        .collect()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn fresh_database_has_the_ten_tables_seeded_meta_and_pragmas() {
    let dir = TempDir::new("fresh");
    let data = dir.path().join("srv").join("data");
    let mut conn = open_connection(&data.join(DB_FILE)).unwrap();
    assert_eq!(schema_version(&conn).unwrap(), 0);
    let out = migrate(&mut conn).unwrap();
    assert_eq!((out.from, out.to, out.backup), (0, 1, None));
    #[cfg(unix)]
    {
        assert_eq!(mode(&data), 0o700);
        assert_eq!(mode(&data.join(DB_FILE)), 0o600);
        assert_eq!(mode(&data.join(format!("{DB_FILE}-wal"))), 0o600);
    }
    // Pragmas.
    assert_eq!(text(&conn, "PRAGMA journal_mode"), "wal");
    assert_eq!(one(&conn, "PRAGMA foreign_keys"), 1);
    assert_eq!(one(&conn, "PRAGMA secure_delete"), 1);
    assert_eq!(one(&conn, "PRAGMA synchronous"), 2, "FULL");
    assert_eq!(text(&conn, "PRAGMA quick_check"), "ok");

    // The ten tables of §4.2 (plus SQLite's own sqlite_sequence for AUTOINCREMENT).
    let mut tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    tables.retain(|t| t != "sqlite_sequence");
    let mut expected: Vec<String> = CANONICAL_TABLES
        .iter()
        .map(|(t, _)| t.to_string())
        .chain(["backup_log".to_string()])
        .collect();
    expected.sort();
    assert_eq!(tables, expected);
    assert_eq!(tables.len(), 10);
    // Columns in canonical order.
    let columns = |t: &str| -> Vec<(String, i64, i64)> {
        conn.prepare(&format!(
            "SELECT name, \"notnull\", pk FROM pragma_table_info('{t}')"
        ))
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    };
    for (t, cols) in CANONICAL_TABLES {
        let names: Vec<String> = columns(t).into_iter().map(|c| c.0).collect();
        assert_eq!(names, *cols, "{t}");
    }
    let log: Vec<String> = columns("backup_log").into_iter().map(|c| c.0).collect();
    assert_eq!(log, ["seq", "tbl", "key", "op"]);
    // record: primary key (member_id, device_id, tag, idx) and a unique id.
    let pk: Vec<(String, i64)> = columns("record")
        .into_iter()
        .filter(|c| c.2 > 0)
        .map(|c| (c.0, c.2))
        .collect();
    assert_eq!(
        pk,
        [
            ("member_id".to_string(), 1),
            ("device_id".to_string(), 2),
            ("tag".to_string(), 3),
            ("idx".to_string(), 4)
        ]
    );
    let unique_id = one(
        &conn,
        "SELECT COUNT(*) FROM pragma_index_list('record') l \
          JOIN pragma_index_info(l.name) i WHERE l.\"unique\" = 1 AND i.name = 'id' \
            AND (SELECT COUNT(*) FROM pragma_index_info(l.name)) = 1",
    );
    assert_eq!(unique_id, 1);
    // No column can hold a plaintext token: the only token columns are hashes.
    let token_cols = one(
        &conn,
        "SELECT COUNT(*) FROM sqlite_master m JOIN pragma_table_info(m.name) c \
          WHERE m.type = 'table' AND c.name LIKE '%token%'",
    );
    assert_eq!(token_cols, 2, "device.token_hash and invite.token_hash");
    // Three triggers on each of the nine logged tables.
    assert_eq!(
        one(
            &conn,
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'"
        ),
        27
    );
    // meta: generation (a canonical UUIDv4), restore_pending, schema version and checksum.
    let generation = meta(&conn, "generation").unwrap();
    let id = Id::parse(&generation).unwrap();
    assert_eq!(id.as_uuid().get_version_num(), 4);
    assert_eq!(id.to_string(), generation);
    assert_eq!(meta(&conn, "restore_pending").as_deref(), Some("0"));
    assert_eq!(meta(&conn, "schema_version").as_deref(), Some("1"));
    assert_eq!(
        meta(&conn, "schema_checksum.1"),
        Some(checksum(MIGRATIONS[0].2.as_bytes()))
    );
    // The runner's two meta writes were logged; the seed rows predate the triggers.
    assert_eq!(one(&conn, "SELECT COUNT(*) FROM backup_log"), 2);
}

#[test]
fn checks_refuse_values_outside_their_sets() {
    let dir = TempDir::new("checks");
    let mut conn = open_connection(&dir.path().join(DB_FILE)).unwrap();
    migrate(&mut conn).unwrap();
    let hash = checksum(b"x");
    let ok = conn.execute(
        "INSERT INTO member (id, handle, role, created_at) VALUES ('m', 'alf', 'admin', 0)",
        [],
    );
    assert_eq!(ok.unwrap(), 1);
    let bad = [
        "INSERT INTO member (id, handle, role, created_at) VALUES ('m2', 'roy', 'owner', 0)".to_string(),
        // A plaintext token never fits token_hash.
        "INSERT INTO device (id, member_id, token_hash, pubkey, created_at) \
         VALUES ('d', 'm', 'awm_t_0123456789012345678901234567890123456789012345678901', zeroblob(32), 0)"
            .to_string(),
        format!(
            "INSERT INTO device (id, member_id, token_hash, pubkey, created_at) \
             VALUES ('d', 'm', '{}', zeroblob(32), 0)",
            hash.to_uppercase()
        ),
        format!(
            "INSERT INTO device (id, member_id, token_hash, pubkey, created_at) \
             VALUES ('d', 'm', '{hash}', zeroblob(31), 0)"
        ),
        format!(
            "INSERT INTO device (id, member_id, token_hash, pubkey, join_mac, created_at) \
             VALUES ('d', 'm', '{hash}', zeroblob(32), zeroblob(32), 0)"
        ),
        "INSERT INTO record (member_id, device_id, tag, idx, id, size, received_at) \
         VALUES ('m', 'd', 'rec', 0, 'r', 0, 0)"
            .to_string(),
        "INSERT INTO org (id, created_at, retention_days, min_client, max_members) \
         VALUES ('o', 0, 29, '0.2.0', 1)"
            .to_string(),
        "INSERT INTO backup_log (tbl, key, op) VALUES ('org', 'o', 'x')".to_string(),
    ];
    for sql in bad {
        assert!(conn.execute(&sql, []).is_err(), "accepted: {sql}");
    }
    let good = format!(
        "INSERT INTO device (id, member_id, token_hash, pubkey, created_at) \
         VALUES ('d', 'm', '{hash}', zeroblob(32), 0)"
    );
    assert_eq!(conn.execute(&good, []).unwrap(), 1);
    // Foreign keys are enforced.
    assert!(conn
        .execute(
            &format!(
                "INSERT INTO device (id, member_id, token_hash, pubkey, created_at) \
                 VALUES ('d2', 'nobody', '{}', zeroblob(32), 0)",
                checksum(b"y")
            ),
            [],
        )
        .is_err());
}

#[test]
fn a_second_run_is_a_no_op() {
    let dir = TempDir::new("rerun");
    let before = seed(dir.path(), 5);
    let path = dir.path().join(DB_FILE);
    let mut conn = open_connection(&path).unwrap();
    let out = migrate(&mut conn).unwrap();
    assert_eq!((out.from, out.to, out.backup), (1, 1, None));
    assert_eq!(
        raw_dump(&conn),
        before,
        "nothing changed, not even backup_log"
    );
    drop(conn);
    let store = SqliteStore::open(dir.path()).unwrap();
    drop(store);
    let conn = Connection::open(&path).unwrap();
    assert_eq!(raw_dump(&conn), before);
    let files: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".bak-v"))
        .collect();
    assert!(files.is_empty(), "{files:?}");
}

#[test]
fn a_newer_database_is_refused() {
    let dir = TempDir::new("newer");
    seed(dir.path(), 1);
    let path = dir.path().join(DB_FILE);
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE meta SET value = '2' WHERE key = 'schema_version'",
        [],
    )
    .unwrap();
    let before = raw_dump(&conn);
    drop(conn);
    let err = SqliteStore::open(dir.path()).unwrap_err().to_string();
    assert!(
        err.contains("from a newer awm (2, this binary knows 1)"),
        "{err}"
    );
    let mut conn = open_connection(&path).unwrap();
    assert!(migrate(&mut conn).is_err());
    assert_eq!(raw_dump(&conn), before, "no downgrade, nothing written");
}

#[test]
fn a_changed_or_missing_checksum_is_refused() {
    let dir = TempDir::new("checksum");
    seed(dir.path(), 1);
    let path = dir.path().join(DB_FILE);
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'schema_checksum.1'",
        [checksum(b"edited")],
    )
    .unwrap();
    drop(conn);
    let err = SqliteStore::open(dir.path()).unwrap_err().to_string();
    assert!(
        err.contains("checksum mismatch for migration 0001_server"),
        "{err}"
    );

    // An edited embedded file is refused the same way.
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'schema_checksum.1'",
        [checksum(MIGRATIONS[0].2.as_bytes())],
    )
    .unwrap();
    drop(conn);
    let mut conn = open_connection(&path).unwrap();
    let edited = [(1, "0001_server", "-- edited\nSELECT 1;")];
    let err = migrate_with(&mut conn, &edited).unwrap_err().to_string();
    assert!(err.contains("checksum mismatch"), "{err}");
    conn.execute("DELETE FROM meta WHERE key = 'schema_checksum.1'", [])
        .unwrap();
    let err = migrate(&mut conn).unwrap_err().to_string();
    assert!(err.contains("has no checksum"), "{err}");
}

#[test]
fn migrating_a_database_with_data_writes_a_verified_backup() {
    let dir = TempDir::new("backup");
    let before = seed(dir.path(), 20);
    let path = dir.path().join(DB_FILE);
    let mut conn = open_connection(&path).unwrap();
    let list = with_test_migration(EXTRA);
    let out = migrate_with(&mut conn, &list).unwrap();
    assert_eq!((out.from, out.to), (1, 2));
    let backup = out.backup.unwrap();
    assert_eq!(backup, dir.path().join(format!("{DB_FILE}.bak-v1")));
    #[cfg(unix)]
    assert_eq!(mode(&backup), 0o600);
    assert_eq!(schema_version(&conn).unwrap(), 2);
    assert_eq!(one(&conn, "SELECT n FROM extra"), 20);
    assert_eq!(one(&conn, "PRAGMA foreign_keys"), 1);
    assert_eq!(
        meta(&conn, "schema_checksum.2"),
        Some(checksum(EXTRA.as_bytes()))
    );
    // Every row is kept (backup_log gains the runner's two meta writes).
    let after = raw_dump(&conn);
    for ((t, b), (t2, a)) in before.iter().zip(&after) {
        assert_eq!(t, t2);
        if t == "meta" || t == "backup_log" {
            continue;
        }
        assert_eq!(a, b, "{t}");
    }
    let old = Connection::open(&backup).unwrap();
    assert_eq!(schema_version(&old).unwrap(), 1);
    assert_eq!(
        raw_dump(&old),
        before,
        "the backup is the database before the migration"
    );
    assert_eq!(text(&old, "PRAGMA quick_check"), "ok");
    assert_eq!(leftover_tmp(dir.path()), Vec::<String>::new());
    // A rerun is a no-op and leaves the backup alone.
    let bytes = std::fs::read(&backup).unwrap();
    let out = migrate_with(&mut conn, &list).unwrap();
    assert_eq!((out.from, out.to, out.backup), (2, 2, None));
    assert_eq!(std::fs::read(&backup).unwrap(), bytes);
}

#[test]
fn a_migration_that_breaks_a_foreign_key_is_rolled_back() {
    let dir = TempDir::new("fk");
    let before = seed(dir.path(), 3);
    let path = dir.path().join(DB_FILE);
    let mut conn = open_connection(&path).unwrap();
    let orphan: &'static str = "CREATE TABLE extra (x INTEGER);\n\
        INSERT INTO deletion (idx, record_id, member_id, deleted_at) \
        VALUES (99, 'r', 'nobody', 0);";
    let err = migrate_with(&mut conn, &with_test_migration(orphan))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("1 row(s) violate a foreign key (deletion rowid 99 -> member)"),
        "{err}"
    );
    assert_eq!(schema_version(&conn).unwrap(), 1);
    assert_eq!(
        one(
            &conn,
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'extra'"
        ),
        0
    );
    assert_eq!(one(&conn, "PRAGMA foreign_keys"), 1);
    let after = raw_dump(&conn);
    assert_eq!(after, before, "rolled back");
    // A migration that fails outright also leaves foreign keys on.
    assert!(migrate_with(&mut conn, &with_test_migration("CREATE TABLE (;")).is_err());
    assert_eq!(one(&conn, "PRAGMA foreign_keys"), 1);
    assert_eq!(schema_version(&conn).unwrap(), 1);
}

#[test]
fn concurrent_migrators_lose_nothing() {
    const ROUNDS: usize = 20;
    const THREADS: usize = 4;
    let list = Arc::new(with_test_migration(EXTRA));
    let (mut wins, mut no_ops, mut changed, mut collided) = (0, 0, 0, 0);
    for round in 0..ROUNDS {
        let dir = TempDir::new("concurrent");
        let before = seed(dir.path(), 50);
        let path = dir.path().join(DB_FILE);
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let (path, barrier, list) = (path.clone(), Arc::clone(&barrier), Arc::clone(&list));
                std::thread::spawn(move || {
                    let mut conn = open_connection(&path).unwrap();
                    barrier.wait();
                    let r = migrate_with(&mut conn, &list).map_err(|e| e.to_string());
                    assert_eq!(one(&conn, "PRAGMA foreign_keys"), 1);
                    r
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let mut round_wins = 0;
        for r in &results {
            match r {
                Ok(o) if (o.from, o.to) == (1, 2) && o.backup.is_some() => round_wins += 1,
                Ok(o) if (o.from, o.to) == (2, 2) && o.backup.is_none() => no_ops += 1,
                Err(e) if e.contains("run the command again") => changed += 1,
                // Threads of one process share a pid; create_new refuses the name.
                Err(e) if e.contains("File exists") => collided += 1,
                other => panic!("round {round}: unexpected {other:?}"),
            }
        }
        assert_eq!(round_wins, 1, "round {round}: {results:?}");
        wins += round_wins;
        let conn = Connection::open(&path).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 2);
        assert_eq!(one(&conn, "SELECT COUNT(*) FROM extra"), 1, "applied once");
        assert_eq!(one(&conn, "SELECT n FROM extra"), 50);
        let after = raw_dump(&conn);
        for ((t, b), (_, a)) in before.iter().zip(&after) {
            if t != "meta" && t != "backup_log" {
                assert_eq!(a, b, "round {round}: {t}");
            }
        }
        assert_eq!(text(&conn, "PRAGMA quick_check"), "ok");
        assert_eq!(
            one(&conn, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
            0
        );
        let old = Connection::open(dir.path().join(format!("{DB_FILE}.bak-v1"))).unwrap();
        assert_eq!(schema_version(&old).unwrap(), 1);
        assert_eq!(raw_dump(&old), before, "round {round}");
        assert_eq!(leftover_tmp(dir.path()), Vec::<String>::new());
    }
    eprintln!(
        "concurrent migrators: {ROUNDS} rounds x {THREADS} threads: {wins} migrated, \
         {no_ops} no-op, {changed} 'run the command again', {collided} temporary-name collisions"
    );
    assert_eq!(wins, ROUNDS);
}

#[test]
fn concurrent_first_opens_create_one_schema() {
    const ROUNDS: usize = 20;
    const THREADS: usize = 4;
    let (mut created, mut no_ops, mut changed) = (0, 0, 0);
    for round in 0..ROUNDS {
        let dir = TempDir::new("first");
        let path = dir.path().join("data").join(DB_FILE);
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let (path, barrier) = (path.clone(), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut conn = open_connection(&path).map_err(|e| e.to_string())?;
                    migrate(&mut conn).map_err(|e| e.to_string())
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let mut round_created = 0;
        for r in &results {
            match r {
                Ok(o) if (o.from, o.to) == (0, 1) => round_created += 1,
                Ok(o) if (o.from, o.to) == (1, 1) => no_ops += 1,
                Err(e) if e.contains("run the command again") => changed += 1,
                other => panic!("round {round}: unexpected {other:?}"),
            }
        }
        assert_eq!(round_created, 1, "round {round}: {results:?}");
        created += round_created;
        let conn = Connection::open(&path).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 1);
        assert_eq!(
            one(&conn, "SELECT COUNT(*) FROM meta WHERE key = 'generation'"),
            1
        );
        assert_eq!(
            one(
                &conn,
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'"
            ),
            27
        );
    }
    eprintln!(
        "concurrent first opens: {ROUNDS} rounds x {THREADS} threads: {created} created, \
         {no_ops} no-op, {changed} 'run the command again'"
    );
    assert_eq!(created, ROUNDS);
}

#[test]
fn the_embedded_migration_is_the_file_and_controls_no_transaction() {
    let file = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations/sqlite/0001_server.sql"),
    )
    .unwrap();
    assert_eq!(MIGRATIONS.len(), 1);
    assert_eq!(MIGRATIONS[0].0, 1);
    assert_eq!(MIGRATIONS[0].1, "0001_server");
    assert_eq!(MIGRATIONS[0].2, file);
    // The runner owns the transaction and the pragmas; the file has neither (outside comments).
    for line in file.lines() {
        let code = line.split("--").next().unwrap().to_ascii_uppercase();
        for word in [
            "BEGIN TRANSACTION",
            "COMMIT",
            "SAVEPOINT",
            "ROLLBACK",
            "PRAGMA",
            "VACUUM",
        ] {
            assert!(!code.contains(word), "{word} in: {line}");
        }
        let trimmed = code.trim_start();
        assert!(
            !trimmed.starts_with("BEGIN;") && trimmed != "BEGIN",
            "{line}"
        );
    }
    // Pin the shipped file once v0.2 ships; until then record its checksum here.
    eprintln!("0001_server checksum: {}", checksum(file.as_bytes()));
}
