//! Deletion propagation in a team (plan-v3-team §3.6, §3.7, §3.9.5; `docs/sync-v1.md` §8.5,
//! §9.3, §10, §11; TM11).
//!
//! Run: `cargo test -p agent-web-memory --features sync,serve --test team_delete`.
//!
//! Every test starts its own server (`awm_server::http::embedded` on a loopback port, a
//! `SqliteStore` in a scratch directory, a captured log) and drives the built `awm` binary with
//! one `AWM_HOME` per machine. Runs that need a fixed clock call `awm::sync::run` in-process
//! with `Env::now_ms`. Nothing else opens a socket. Where a test needs a server that lost or
//! re-serves something, it edits the server database directly, as a restore or a compromised
//! host would.

#![cfg(all(feature = "sync", feature = "serve"))]

use std::time::{Duration, Instant};

use awm::sync::state;
use awm::sync::{Env, Opts, Outcome, Report};
use rusqlite::{params, OptionalExtension};

mod support;
use support::{contains, now_ms, Node, Out, Srv};

// ---------------------------------------------------------------------------------------------
// The server and a machine: `support::Srv` and `support::Node`, plus what only this suite asks

const DAY_MS: i64 = 86_400_000;

/// `YYYY-MM-DD` (UTC) of a unix time in ms.
fn utc_date(ms: i64) -> String {
    let d = time::OffsetDateTime::from_unix_timestamp(ms / 1_000)
        .unwrap()
        .date();
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

impl Srv {
    /// Requests to `POST /v1/delete` in the log.
    fn delete_requests(&self) -> usize {
        self.logs
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains("method=POST path=/v1/delete "))
            .count()
    }

    /// Whether the server holds the blob of record `id` (not a marker, not unknown).
    fn holds_blob(&self, id: &str) -> bool {
        self.raw()
            .query_row(
                "SELECT blob IS NOT NULL FROM record WHERE id = ?1",
                [id],
                |r| r.get::<_, bool>(0),
            )
            .optional()
            .unwrap()
            .unwrap_or(false)
    }

    /// The server's row for record `id`: (blob present, deleted_at present); `None` if unknown.
    fn record_state(&self, id: &str) -> Option<(bool, bool)> {
        self.raw()
            .query_row(
                "SELECT blob IS NOT NULL, deleted_at IS NOT NULL FROM record WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .unwrap()
    }
}

impl Node {
    #[track_caller]
    fn refused(&self, args: &[&str]) -> Out {
        let o = self.run(args);
        assert_ne!(
            o.code,
            Some(0),
            "awm {args:?} should be refused\nstdout: {}",
            o.stdout
        );
        o
    }

    fn member(&self) -> String {
        self.ident().team.member_id.to_string()
    }

    fn set_state(&self, key: &str, value: &str) {
        state::set(&self.conn(), key, value).unwrap();
    }

    /// The local row of record id `id`, if any: (event id, origin).
    fn row_of(&self, id: &str) -> Option<(i64, String)> {
        self.conn()
            .query_row(
                "SELECT id, origin FROM event WHERE sync_id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .unwrap()
    }

    fn has_tombstone(&self, id: &str) -> bool {
        self.count(&format!(
            "SELECT COUNT(*) FROM tombstone WHERE kind = 'tool_use_id' AND value = 'team:{id}'"
        )) == 1
    }

    fn team_rows(&self) -> i64 {
        self.count("SELECT COUNT(*) FROM event WHERE origin = 'team'")
    }

    fn rows_with_url(&self, url: &str) -> i64 {
        let norm = awm::normalize::norm_url(url).unwrap();
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM event WHERE url_norm = ?1",
                [norm],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// Every stream head and the deletion head go back, so the next run re-pulls everything.
    fn forget_heads(&self) {
        let own = self.ident().team.device_id.to_string();
        self.conn()
            .execute(
                "UPDATE sync_stream SET head_idx = -1 WHERE device_id <> ?1 AND tag <> 'roster'",
                [own],
            )
            .unwrap();
        self.set_state(state::DELETION_HEAD, "-1");
    }

    /// One `awm sync` run in this process with a fixed clock.
    fn sync_at(&self, now: i64) -> Report {
        let env = Env {
            data_dir: self.path().to_path_buf(),
            config: awm::config::load(&self.path().join("config.toml")).unwrap(),
            now_ms: Some(now),
        };
        match awm::sync::run(&env, &Opts::default()).unwrap() {
            Outcome::Done(r) => r,
            other => panic!("the run did not finish: {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Flows (the same commands a user types)

fn create(srv: &Srv, handle: &str) -> Node {
    let n = Node::new_apart();
    let out = n.ok(&[
        "team",
        "create",
        &srv.url(),
        "--token",
        &srv.bootstrap_token(),
        "--handle",
        handle,
    ]);
    assert!(out.contains("created organisation"), "{out}");
    n.ok(&["sync"]);
    n
}

fn token_of(srv: &Srv, out: &str) -> String {
    let prefix = format!("awm team join {} --token ", srv.url());
    out.trim_end()
        .strip_prefix(&prefix)
        .unwrap_or_else(|| panic!("not a join command: {out}"))
        .to_string()
}

fn code_of(join_out: &str) -> String {
    join_out
        .lines()
        .find_map(|l| l.strip_prefix("read this code to the person who invited you: "))
        .unwrap_or_else(|| panic!("no code: {join_out}"))
        .replace(' ', "")
}

/// A new member's machine, approved by `admin` with the code, synced once.
fn member(srv: &Srv, admin: &Node, handle: &str) -> Node {
    let t = token_of(srv, &admin.ok(&["team", "invite", "--handle", handle]));
    let n = Node::new_apart();
    let out = n.ok(&["team", "join", &srv.url(), "--token", &t]);
    let code = code_of(&out);
    admin.ok(&["team", "approve", handle, "--code", &code]);
    n.ok(&["sync"]);
    n
}

/// `owner`'s next machine: a device invite, approved by `owner` with the code it prints
/// (`team.auto_approve = none`, the default since RVT2 m3).
fn other_machine(srv: &Srv, owner: &Node) -> Node {
    let t = token_of(srv, &owner.ok(&["team", "add-device"]));
    let n = Node::new_apart();
    let out = n.ok(&["team", "join", &srv.url(), "--token", &t]);
    let handle = owner.ident().team.handle;
    owner.ok(&["team", "approve", &handle, "--code", &code_of(&out)]);
    n.ok(&["sync"]);
    assert_eq!(n.member(), owner.member());
    n
}

fn share(n: &Node) {
    let p = n.project();
    n.ok(&["team", "share", p.to_str().unwrap()]);
}

/// No record text, device token or epoch key in the server's log and database, in any
/// machine's `last_error`, or in `outputs`.
#[track_caller]
fn assert_no_secrets(srv: &Srv, nodes: &[&Node], texts: &[&str], outputs: &[String]) {
    let log = srv.log_text();
    let db = srv.db_bytes();
    let mut needles: Vec<Vec<u8>> = texts.iter().map(|t| t.as_bytes().to_vec()).collect();
    for n in nodes {
        if !n.path().join("team.key").exists() {
            continue;
        }
        let key = n.ident().key;
        needles.push(key.device_token.as_bytes().to_vec());
        for e in &key.epoch_keys {
            needles.push(e.key.0.to_vec());
        }
    }
    for needle in &needles {
        assert!(
            !contains(log.as_bytes(), needle),
            "the server log holds a secret"
        );
        assert!(!contains(&db, needle), "the server database holds a secret");
        for n in nodes {
            if n.path().join("awm.db").exists() {
                let e = n.state(state::LAST_ERROR).unwrap_or_default();
                assert!(!contains(e.as_bytes(), needle), "last_error holds a secret");
            }
        }
        for o in outputs {
            assert!(
                !contains(o.as_bytes(), needle),
                "output holds a secret: {o}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// forget <url>

#[test]
fn a_forgotten_url_leaves_the_server_every_device_and_teammates_and_stays_gone_after_a_re_pull() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    let a2 = other_machine(&srv, &a);
    let b = member(&srv, &a, "bob");
    for n in [&a, &a2, &b] {
        share(n);
    }
    let url = "https://docs.example.org/forgotten";
    let r1 = a.capture(1, url, "Ann read the forgotten page about lanterns.");
    let r2 = a.capture(
        2,
        "https://docs.example.org/kept",
        "Kept page; see https://docs.example.org/forgotten for the lantern details.",
    );
    let r3 = a2.capture(
        1,
        url,
        "Ann's laptop read the forgotten page about lanterns too.",
    );
    let r4 = b.capture(1, url, "Bob read the forgotten page about lanterns.");
    for n in [&a, &a2, &b, &a, &a2, &b] {
        n.ok(&["sync"]);
    }
    let (id1, id2, id3, id4) = (a.sync_id(r1), a.sync_id(r2), a2.sync_id(r3), b.sync_id(r4));
    assert_eq!(b.team_rows(), 3, "Bob holds Ann's three records");
    assert_eq!(a.team_rows(), 2, "Ann holds her laptop's record and Bob's");
    let a1_blob: Vec<u8> = srv
        .raw()
        .query_row("SELECT blob FROM record WHERE id = ?1", [&id1], |r| {
            r.get(0)
        })
        .unwrap();

    // Bob's machine: a note that showed Ann's record, labelled; and two migration backups.
    let (b1, _) = b.row_of(&id1).unwrap();
    {
        let c = b.conn();
        c.execute(
            "INSERT INTO injection (ref, created_at, hook, channel, mode, session_id, rendered_chars, latency_ms) \
             VALUES ('ab12cd34', ?1, 'PreToolUse', 'url', 'inject', 'sess-b', 120, 3)",
            [now_ms()],
        )
        .unwrap();
        let inj = c.last_insert_rowid();
        c.execute(
            "INSERT INTO injection_item (injection_id, position, event_id, score) VALUES (?1, 1, ?2, 1.0)",
            params![inj, b1],
        )
        .unwrap();
        c.execute(
            "INSERT INTO outcome (injection_id, position, label, labelled_at) VALUES (?1, 1, '2', ?2)",
            params![inj, now_ms()],
        )
        .unwrap();
    }
    std::fs::write(b.path().join("awm.db.bak-v2"), b"schema 2 copy").unwrap();
    std::fs::write(b.path().join("awm.db.bak-v3"), b"schema 3 copy").unwrap();

    let out = a.ok(&["forget", url, "--yes"]);
    // Ann's capture, her laptop's record and the record that mentions the URL (superseded) go
    // from the server; Bob's copy only from Ann's machine.
    assert!(
        out.contains("Deleted 3 shared record(s) on the server."),
        "{out}"
    );
    assert!(out.contains("Superseded 1 shared record(s)"), "{out}");
    assert!(
        out.contains("1 teammate record(s) deleted on this machine only"),
        "{out}"
    );
    let deleted = srv.deleted_ids();
    for id in [&id1, &id2, &id3] {
        assert!(deleted.contains(id), "{id} is in the deletion stream");
        assert!(!srv.holds_blob(id));
        assert!(a.has_tombstone(id));
    }
    assert!(!deleted.contains(&id4), "Bob's server copy stays his");
    assert!(srv.holds_blob(&id4));
    assert_eq!(a.rows_with_url(url), 0);
    assert_eq!(
        a.count("SELECT COUNT(*) FROM sync_outbox WHERE kind = 'delete'"),
        0
    );
    // The rewritten record waits for its new push: no sync id, shareable again.
    assert_eq!(
        a.count(&format!(
            "SELECT COUNT(*) FROM event WHERE id = {r2} AND sync_id IS NULL AND shareable = 'no'"
        )),
        1
    );
    assert!(a.state(&format!("own_deleted.{id3}")).is_some());
    assert!(a.state(&format!("local_only.{id4}")).is_some());

    // The next sync pushes the cleaned record under a new id; Bob gets it and loses the rest.
    a.ok(&["sync"]);
    let new2 = a.sync_id(r2);
    assert_ne!(new2, id2);
    b.ok(&["sync"]);
    for id in [&id1, &id2, &id3] {
        assert!(b.row_of(id).is_none(), "{id} is gone from Bob");
        assert!(b.has_tombstone(id));
    }
    let summary: String = b
        .conn()
        .query_row(
            "SELECT summary FROM event WHERE sync_id = ?1",
            [&new2],
            |r| r.get(0),
        )
        .unwrap();
    assert!(summary.contains("[forgotten url]"), "{summary}");
    assert!(!summary.contains("docs.example.org/forgotten"), "{summary}");
    // Bob's labels stay without the text; the schema-2 backup stays, the schema-3 one goes.
    assert_eq!(
        b.count("SELECT COUNT(*) FROM injection_item WHERE event_id IS NULL AND origin = 'team'"),
        1
    );
    assert_eq!(b.count("SELECT COUNT(*) FROM injection"), 1);
    assert_eq!(b.count("SELECT COUNT(*) FROM outcome WHERE label = '2'"), 1);
    assert!(b.path().join("awm.db.bak-v2").exists());
    assert!(!b.path().join("awm.db.bak-v3").exists());
    assert_eq!(
        b.count("SELECT COUNT(*) FROM event_fts WHERE event_fts MATCH 'lanterns'"),
        1,
        "only Bob's own capture is still indexed"
    );
    // The commands that read the NULL item still work.
    b.ok(&["stats", "--savings", "--json"]);
    b.ok(&["stats", "--value", "--json"]);

    // Ann's laptop keeps its own capture (its local history), never shared again.
    a2.ok(&["sync"]);
    let (_, origin) = a2.row_of(&id3).unwrap();
    assert_eq!(origin, "local");
    assert_eq!(
        a2.count(&format!(
            "SELECT COUNT(*) FROM event WHERE sync_id = '{id3}' AND shareable = 'never'"
        )),
        1
    );
    assert_eq!(
        a2.count(&format!(
            "SELECT COUNT(*) FROM sync_own WHERE record_id = '{id3}' AND deleted = 1 AND blob IS NULL"
        )),
        1
    );
    assert!(a2.row_of(&id1).is_none());

    // A server that serves Ann's record again (restored, or lying), and a full re-pull: Bob's
    // `team:` tombstone keeps it out; Ann's `url_hash` tombstone keeps Bob's copy out.
    srv.raw()
        .execute(
            "UPDATE record SET blob = ?2, deleted_at = NULL WHERE id = ?1",
            params![id1, a1_blob],
        )
        .unwrap();
    b.forget_heads();
    b.ok(&["sync"]);
    assert!(b.row_of(&id1).is_none(), "the tombstone keeps it out");
    assert!(b.state("dropped.tombstone").is_some());
    a.forget_heads();
    a.ok(&["sync"]);
    assert_eq!(
        a.rows_with_url(url),
        0,
        "the URL tombstone keeps Bob's copy out"
    );
    assert!(srv.holds_blob(&id4));

    assert_no_secrets(
        &srv,
        &[&a, &a2, &b],
        &["lanterns", "forgotten page"],
        &[out],
    );
}

// ---------------------------------------------------------------------------------------------
// In-flight records

#[test]
fn a_record_in_an_unfinished_push_batch_never_reaches_the_server_and_a_stale_push_gets_410() {
    let mut srv = Srv::start();
    let a = create(&srv, "ann");
    share(&a);
    let url = "https://docs.example.org/in-flight";
    let e = a.capture(1, url, "Queued but never sent.");
    // The push fails after the batch was queued: the daily quota is used up.
    srv.stop();
    srv.resume_with(0);
    let o = a.refused(&["sync"]);
    assert!(o.stderr.contains("429"), "{}", o.all());
    let id = a.sync_id(e);
    let (blob, idx): (Vec<u8>, i64) = a
        .conn()
        .query_row(
            "SELECT blob, idx FROM sync_own WHERE record_id = ?1 AND deleted = 0",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        a.count("SELECT COUNT(*) FROM event WHERE pushed_at IS NOT NULL"),
        0
    );
    // Another process that read this state earlier (a copy of the data directory).
    let stale = Node::copy_of(&a);
    srv.stop();
    srv.resume();

    let out = a.ok(&["forget", url, "--yes"]);
    assert!(
        out.contains("Deleted 1 shared record(s) on the server."),
        "{out}"
    );
    // Pre-deleted: in the deletion stream, never stored.
    assert!(srv.deleted_ids().contains(&id));
    assert_eq!(srv.record_state(&id), None);
    assert!(a.has_tombstone(&id));
    assert_eq!(
        a.count(&format!(
            "SELECT COUNT(*) FROM sync_own WHERE record_id = '{id}' AND deleted = 1 AND blob IS NULL"
        )),
        1
    );
    assert_eq!(
        a.count("SELECT COUNT(*) FROM sync_outbox WHERE kind = 'delete'"),
        0
    );

    // The stale copy pushes the blob: 410, its local row goes, a marker fills the index. Its
    // deletion head is at the server's, as when the deletion lands between that run's read of
    // the deletion stream and its push (a run reads the stream first, and an entry naming an
    // own capture keeps the row, never shared again).
    let head = srv.deleted_ids().len() as i64 - 1;
    stale.set_state(state::DELETION_HEAD, &head.to_string());
    let o = stale.run(&["sync"]);
    assert_eq!(o.code, Some(0), "{}", o.all());
    assert!(
        stale.row_of(&id).is_none(),
        "the client deleted the local row"
    );
    assert!(stale.has_tombstone(&id));
    assert_eq!(srv.record_state(&id), Some((false, true)), "a marker");
    assert!(
        !contains(&srv.db_bytes(), &blob),
        "the blob never reached the server"
    );
    // Ann's own queued item is a marker too: a replay, nothing new.
    a.ok(&["sync"]);
    assert_eq!(a.count("SELECT COUNT(*) FROM sync_outbox"), 0);
    let marker: (Option<Vec<u8>>, String) = srv
        .raw()
        .query_row(
            "SELECT blob, id FROM record WHERE tag = 'rec' AND idx = ?1",
            [idx],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(marker, (None, id));
}

// ---------------------------------------------------------------------------------------------
// purge

#[test]
fn purge_all_leaves_the_team_with_one_bulk_request_and_deletes_the_directory() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    let b = member(&srv, &a, "bob");
    share(&b);
    let e1 = b.capture(1, "https://docs.example.org/b1", "First of Bob's notes.");
    let e2 = b.capture(2, "https://docs.example.org/b2", "Second of Bob's notes.");
    b.ok(&["sync"]);
    let ids = [b.sync_id(e1), b.sync_id(e2)];
    let token = b.ident().key.device_token;
    let before = srv.delete_requests();

    let out = b.ok(&["purge", "--all", "--yes"]);
    assert!(out.contains("deleted 2 shared record(s) of @bob"), "{out}");
    assert!(out.contains("left the organisation"), "{out}");
    assert!(
        out.contains("Not covered: records that another of your devices"),
        "{out}"
    );
    assert!(
        out.contains(&format!("Deleted {} (", b.path().display())),
        "{out}"
    );
    assert!(
        !b.path().exists(),
        "the directory is gone, not refused as foreign"
    );
    assert_eq!(
        srv.delete_requests(),
        before + 1,
        "one {{all_mine}} request"
    );
    for id in &ids {
        assert!(srv.deleted_ids().contains(id));
        assert!(!srv.holds_blob(id));
    }
    let left: i64 = srv
        .raw()
        .query_row(
            "SELECT COUNT(*) FROM record r JOIN member m ON m.id = r.member_id \
             WHERE m.handle = 'bob' AND r.tag <> 'roster' AND r.blob IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(left, 0, "the server holds none of Bob's records");
    let old = awm::sync::http::Client::new(&srv.url(), Some(&token), None).unwrap();
    assert_eq!(old.status().unwrap_err().status(), Some(401));
    a.ok(&["sync"]);
    assert_eq!(a.team_rows(), 0);

    // A second bulk deletion within the hour: 429, reported, nothing deleted here.
    let c = member(&srv, &a, "cat");
    share(&c);
    c.capture(1, "https://docs.example.org/c1", "Cat's note.");
    c.ok(&["sync"]);
    c.ok(&["team", "delete-mine"]);
    let o = c.run(&["purge", "--all", "--yes"]);
    assert_eq!(o.code, Some(2), "{}", o.all());
    assert!(
        o.stdout.contains("one bulk deletion an hour"),
        "{}",
        o.all()
    );
    assert!(o.stdout.contains("try again in"), "{}", o.all());
    assert!(
        o.stdout.contains("nothing was deleted on this machine"),
        "{}",
        o.all()
    );
    for f in ["awm.db", "team.toml", "team.key", "team.repo"] {
        assert!(c.path().join(f).exists(), "{f}");
    }
    assert_no_secrets(
        &srv,
        &[&a, &c],
        &["Bob's notes", "Cat's note"],
        &[out, o.all()],
    );
}

#[test]
fn purge_before_deletes_remotely_first_keeps_the_team_files_and_offline_needs_local_only() {
    let mut srv = Srv::start();
    let a = create(&srv, "ann");
    let b = member(&srv, &a, "bob");
    share(&b);
    let old = b.capture(1, "https://docs.example.org/old", "An old note.");
    let older = b.capture(2, "https://docs.example.org/older", "An older note.");
    b.ok(&["sync"]);
    let (old_id, older_id) = (b.sync_id(old), b.sync_id(older));
    // Both were captured yesterday, as far as this machine knows.
    b.conn()
        .execute(
            "UPDATE event SET created_at = ?1 WHERE origin = 'local'",
            [now_ms() - DAY_MS],
        )
        .unwrap();
    let today = utc_date(now_ms());

    // Offline: refused, nothing changed, the count of what would stay is printed.
    srv.stop();
    let o = b.refused(&["purge", "--before", &today, "--yes"]);
    assert_eq!(o.code, Some(2));
    assert!(o.stdout.contains("cannot be reached"), "{}", o.all());
    assert!(
        o.stdout
            .contains("--local-only (2 shared record(s) would stay"),
        "{}",
        o.all()
    );
    assert_eq!(
        b.count("SELECT COUNT(*) FROM event WHERE origin = 'local'"),
        2
    );
    // purge --all offline: leave --delete cannot run, nothing is deleted.
    let o = b.refused(&["purge", "--all", "--yes"]);
    assert!(
        o.stdout.contains("nothing was deleted on this machine"),
        "{}",
        o.all()
    );
    assert!(b.path().join("awm.db").exists());

    // Offline with --local-only: deleted here, the count that stays on the server printed.
    b.conn()
        .execute(
            "UPDATE event SET created_at = ?1 WHERE id = ?2",
            params![now_ms(), old],
        )
        .unwrap();
    let out = b.ok(&["purge", "--before", &today, "--local-only", "--yes"]);
    assert!(
        out.contains("--local-only: 1 shared record(s) of yours stay on the server"),
        "{out}"
    );
    assert!(b.row_of(&older_id).is_none());
    srv.resume();
    assert!(srv.holds_blob(&older_id), "stays on the server");
    assert!(!srv.deleted_ids().contains(&older_id));

    // Online: remote first; team.toml and team.key stay.
    b.conn()
        .execute(
            "UPDATE event SET created_at = ?1 WHERE id = ?2",
            params![now_ms() - DAY_MS, old],
        )
        .unwrap();
    let out = b.ok(&["purge", "--before", &today, "--yes"]);
    assert!(
        out.contains("Deleted 1 shared record(s) on the server."),
        "{out}"
    );
    assert!(srv.deleted_ids().contains(&old_id));
    assert!(b.row_of(&old_id).is_none());
    for f in ["team.toml", "team.key"] {
        assert!(b.path().join(f).exists(), "{f}");
    }
    b.ok(&["sync"]);
}

// ---------------------------------------------------------------------------------------------
// Offline forget and quarantine

#[test]
fn forget_and_quarantine_offline_queue_their_deletions_and_print_both_counts() {
    let mut srv = Srv::start();
    let a = create(&srv, "ann");
    let b = member(&srv, &a, "bob");
    share(&a);
    share(&b);
    let f = b.capture(1, "https://docs.example.org/f", "To forget offline.");
    let q = b.capture(2, "https://docs.example.org/q", "To quarantine online.");
    let q2 = b.capture(3, "https://docs.example.org/q2", "To quarantine offline.");
    let t = a.capture(1, "https://docs.example.org/t", "Ann's note.");
    b.ok(&["sync"]);
    a.ok(&["sync"]);
    b.ok(&["sync"]);
    let (fid, qid, q2id, tid) = (b.sync_id(f), b.sync_id(q), b.sync_id(q2), a.sync_id(t));

    // Quarantine of an own shared record deletes it on the server.
    let out = b.ok(&["quarantine", &q.to_string(), "--yes"]);
    assert!(out.contains("Quarantined 1 record(s)."), "{out}");
    assert!(
        out.contains("Deleted 1 shared record(s) on the server."),
        "{out}"
    );
    assert!(srv.deleted_ids().contains(&qid));
    // A teammate's record is quarantined here only.
    let (tev, _) = b.row_of(&tid).unwrap();
    let out = b.ok(&["quarantine", &tev.to_string(), "--yes"]);
    assert!(
        out.contains("1 teammate record(s) quarantined on this machine only"),
        "{out}"
    );
    assert!(!srv.deleted_ids().contains(&tid));

    srv.stop();
    let out = b.ok(&["forget", "https://docs.example.org/f", "--yes"]);
    assert!(
        out.contains("Deleted 0 shared record(s) on the server."),
        "{out}"
    );
    assert!(
        out.contains("1 deletion(s) queued for the next awm sync"),
        "{out}"
    );
    let out = b.ok(&["quarantine", &q2.to_string(), "--yes"]);
    assert!(
        out.contains("1 deletion(s) queued for the next awm sync"),
        "{out}"
    );
    assert_eq!(
        b.count("SELECT COUNT(*) FROM sync_outbox WHERE kind = 'delete'"),
        2
    );
    srv.resume();
    b.ok(&["sync"]);
    assert!(srv.deleted_ids().contains(&fid));
    assert!(srv.deleted_ids().contains(&q2id));
    assert_eq!(b.count("SELECT COUNT(*) FROM sync_outbox"), 0);
    a.ok(&["sync"]);
    for id in [&fid, &qid, &q2id] {
        assert!(a.row_of(id).is_none());
    }
}

// ---------------------------------------------------------------------------------------------
// sync.lock

#[test]
fn the_commands_that_delete_wait_ten_seconds_for_sync_lock_then_refuse() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    let b = member(&srv, &a, "bob");
    share(&b);
    let e = b.capture(1, "https://docs.example.org/locked", "Locked note.");
    b.ok(&["sync"]);
    let id = b.sync_id(e);
    let today = utc_date(now_ms());
    let project = b.project().to_string_lossy().into_owned();

    let lock = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(b.path().join("sync.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let commands: Vec<Vec<String>> = vec![
        vec![
            "forget".into(),
            "https://docs.example.org/locked".into(),
            "--yes".into(),
        ],
        vec!["purge".into(), "--before".into(), today, "--yes".into()],
        vec!["team".into(), "unshare".into(), project, "--delete".into()],
        vec!["team".into(), "leave".into(), "--delete".into()],
    ];
    let started = Instant::now();
    let outs: Vec<(Vec<String>, Out, Duration)> = std::thread::scope(|scope| {
        let handles: Vec<_> = commands
            .iter()
            .map(|c| {
                let b = &b;
                scope.spawn(move || {
                    let t = Instant::now();
                    let args: Vec<&str> = c.iter().map(String::as_str).collect();
                    let o = b.run(&args);
                    (c.clone(), o, t.elapsed())
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for (c, o, took) in &outs {
        assert_ne!(o.code, Some(0), "{c:?}: {}", o.all());
        assert!(o.all().contains("sync.lock"), "{c:?}: {}", o.all());
        assert!(took >= &Duration::from_secs(10), "{c:?} waited {took:?}");
    }
    assert!(
        started.elapsed() < Duration::from_secs(40),
        "they waited side by side"
    );
    // Nothing changed.
    assert!(b.row_of(&id).is_some());
    assert!(!srv.deleted_ids().contains(&id));
    assert!(b.path().join("team.toml").exists());

    // A lock released within the wait: the command goes ahead.
    let out = std::thread::scope(|scope| {
        let h = scope.spawn(|| b.run(&["forget", "https://docs.example.org/locked", "--yes"]));
        std::thread::sleep(Duration::from_secs(2));
        lock.unlock().unwrap();
        h.join().unwrap()
    });
    assert_eq!(out.code, Some(0), "{}", out.all());
    assert!(srv.deleted_ids().contains(&id));
}

// ---------------------------------------------------------------------------------------------
// Applying remote deletions

#[test]
fn remote_deletions_apply_in_25_row_transactions_and_the_scrub_runs_at_most_once_a_day() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    let b = member(&srv, &a, "bob");
    share(&a);
    let project = a.project().to_string_lossy().into_owned();
    for i in 0..60 {
        a.capture(
            i,
            &format!("https://docs.example.org/n{i}"),
            &format!("Note {i}."),
        );
    }
    a.ok(&["sync"]);
    let t0 = now_ms();
    b.sync_at(t0);
    assert_eq!(b.team_rows(), 60);

    a.ok(&["team", "unshare", &project, "--delete"]);
    let r = b.sync_at(t0 + 60_000);
    assert_eq!(b.team_rows(), 0);
    assert_eq!(r.deletions_applied, 60);
    assert_eq!(r.delete_tx_rows, vec![25, 25, 10], "{r:?}");
    assert_eq!(b.state("last_scrub"), Some((t0 + 60_000).to_string()));
    assert_eq!(b.state("scrub_pending"), None);

    // A second deletion the same day: applied, the scrub waits.
    share(&a);
    for i in 60..65 {
        a.capture(
            i,
            &format!("https://docs.example.org/n{i}"),
            &format!("Note {i}."),
        );
    }
    a.ok(&["sync"]);
    b.sync_at(t0 + 120_000);
    assert_eq!(b.team_rows(), 5);
    a.ok(&["team", "unshare", &project, "--delete"]);
    let r = b.sync_at(t0 + 3_600_000);
    assert_eq!(b.team_rows(), 0);
    assert_eq!(r.delete_tx_rows, vec![5]);
    assert_eq!(b.state("last_scrub"), Some((t0 + 60_000).to_string()));
    assert_eq!(b.state("scrub_pending").as_deref(), Some("1"));
    // A run with nothing to delete, still within the day: no scrub.
    b.sync_at(t0 + 7_200_000);
    assert_eq!(b.state("last_scrub"), Some((t0 + 60_000).to_string()));
    // A day later the pending scrub runs once.
    b.sync_at(t0 + 60_000 + DAY_MS);
    assert_eq!(
        b.state("last_scrub"),
        Some((t0 + 60_000 + DAY_MS).to_string())
    );
    assert_eq!(b.state("scrub_pending"), None);
}

#[test]
fn a_client_offline_past_the_kept_deletions_reconciles_in_full_and_old_team_rows_expire() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    let b = member(&srv, &a, "bob");
    share(&a);
    for i in 0..30 {
        a.capture(
            i,
            &format!("https://docs.example.org/k{i}"),
            &format!("Kept {i}."),
        );
    }
    for i in 30..40 {
        a.capture(
            i,
            &format!("https://docs.example.org/d{i}"),
            &format!("Doomed {i}."),
        );
    }
    a.ok(&["sync"]);
    b.ok(&["sync"]);
    assert_eq!(b.team_rows(), 40);
    let doomed: Vec<String> = {
        let c = a.conn();
        let mut st = c
            .prepare("SELECT sync_id FROM event WHERE url LIKE '%.org/d%' ORDER BY id")
            .unwrap();
        st.query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    // Ann deletes ten while Bob is away; the server drops those deletion entries (they are
    // older than retention + 30 days when Bob comes back) but keeps a later one.
    b.set_state(state::DELETION_HEAD, "0");
    for id in &doomed {
        a.ok(&["team", "unshare", "--record", id]);
    }
    let entries: i64 = srv
        .raw()
        .query_row("SELECT MAX(idx) FROM deletion", [], |r| r.get(0))
        .unwrap();
    srv.raw()
        .execute("DELETE FROM deletion WHERE idx < ?1", [entries])
        .unwrap();
    assert_eq!(doomed.len(), 10);
    let r = b.sync_at(now_ms());
    assert!(r.reconciled, "{r:?}");
    assert_eq!(r.delete_tx_rows[..2], [25, 15], "{r:?}");
    assert_eq!(
        b.team_rows(),
        30,
        "the re-pull brought back what the server still holds"
    );
    for id in &doomed {
        assert!(b.row_of(id).is_none());
    }
    assert!(b.state("reconciled_notice").is_some());

    // Teammates' rows older than retention_days (365) go, in 25-row transactions; own ones stay.
    b.capture(1, "https://docs.example.org/own", "Bob's own old note.");
    b.conn()
        .execute(
            "UPDATE event SET created_at = ?1",
            [now_ms() - 400 * DAY_MS],
        )
        .unwrap();
    let r = b.sync_at(now_ms());
    assert_eq!(b.team_rows(), 0);
    assert_eq!(r.delete_tx_rows, vec![25, 5], "{r:?}");
    assert_eq!(
        b.count("SELECT COUNT(*) FROM event WHERE origin = 'local'"),
        1
    );
}

// ---------------------------------------------------------------------------------------------
// Restore

#[test]
fn after_a_restore_any_own_device_deletes_again_what_was_deleted_after_the_backup_point() {
    let mut srv = Srv::start();
    let a = create(&srv, "ann");
    let b = member(&srv, &a, "bob");
    let b2 = other_machine(&srv, &b);
    share(&b);
    let r1 = b.capture(1, "https://docs.example.org/r1", "Restored note one.");
    let r3 = b.capture(3, "https://docs.example.org/r3", "Restored note three.");
    b.ok(&["sync"]);
    b2.ok(&["sync"]);
    a.ok(&["sync"]);
    let (id1, id3) = (b.sync_id(r1), b.sync_id(r3));
    assert!(b2.row_of(&id1).is_some());
    let snap = srv.snapshot();

    // After the backup point: Bob's laptop forgets the record of his desktop, the desktop
    // forgets its own.
    b2.ok(&["forget", "https://docs.example.org/r1", "--yes"]);
    b.ok(&["forget", "https://docs.example.org/r3", "--yes"]);
    a.ok(&["sync"]);
    assert!(a.row_of(&id1).is_none() && a.row_of(&id3).is_none());

    srv.restore(&snap);
    assert!(
        srv.holds_blob(&id1) && srv.holds_blob(&id3),
        "the restore brought them back"
    );
    // The laptop (a plain member's device) syncs first: it sends its deletion again.
    let o = b2.run(&["sync"]);
    assert!(
        o.code == Some(0) || o.stderr.contains("restore"),
        "{}",
        o.all()
    );
    assert!(
        !srv.holds_blob(&id1),
        "deleted again by the device that deleted it"
    );
    assert!(srv.deleted_ids().contains(&id1));
    // The desktop's next sync: its own record's deletion again.
    let o = b.run(&["sync"]);
    assert!(
        o.code == Some(0) || o.stderr.contains("restore"),
        "{}",
        o.all()
    );
    assert!(!srv.holds_blob(&id3));
    a.ok(&["sync"]);
    assert!(a.row_of(&id1).is_none() && a.row_of(&id3).is_none());
    // Idempotent: another restore of the same copy, and the admin's sync alone repairs it
    // (an admin sends every tombstone it holds).
    srv.restore(&snap);
    a.ok(&["sync"]);
    assert!(!srv.holds_blob(&id1) && !srv.holds_blob(&id3));
}

// B16 (`apply::resend_ids`): the admin's re-send after a restore covers every tombstone it holds
// except a teammate's record that it deleted on this machine only (`local_only.*`): that deletion
// was never the admin's to make on the server.
#[test]
fn the_admins_re_send_after_a_restore_skips_a_teammates_record_it_deleted_only_here() {
    let mut srv = Srv::start();
    let a = create(&srv, "ann");
    let b = member(&srv, &a, "bob");
    share(&b);
    let local = b.capture(
        1,
        "https://docs.example.org/local-only",
        "Deleted on ann's machine.",
    );
    let remote = b.capture(
        2,
        "https://docs.example.org/remote",
        "Deleted by bob everywhere.",
    );
    b.ok(&["sync"]);
    a.ok(&["sync"]);
    let (id_local, id_remote) = (b.sync_id(local), b.sync_id(remote));
    assert!(a.row_of(&id_local).is_some() && a.row_of(&id_remote).is_some());
    let snap = srv.snapshot();

    // After the backup point: the admin drops a teammate's record on her machine only; Bob
    // deletes his other record for everyone.
    a.ok(&["forget", "https://docs.example.org/local-only", "--yes"]);
    assert!(a.row_of(&id_local).is_none());
    assert!(
        srv.holds_blob(&id_local),
        "a teammate's record is not deleted on the server"
    );
    b.ok(&["forget", "https://docs.example.org/remote", "--yes"]);
    a.ok(&["sync"]);
    assert!(a.row_of(&id_remote).is_none());

    srv.restore(&snap);
    assert!(srv.holds_blob(&id_local) && srv.holds_blob(&id_remote));
    a.ok(&["sync"]);
    assert!(
        !srv.holds_blob(&id_remote),
        "the admin sends the tombstone it holds for Bob's deletion"
    );
    assert!(
        srv.holds_blob(&id_local),
        "but not the one for the record it deleted only on its own machine"
    );
    assert!(!srv.deleted_ids().contains(&id_local));
    assert!(a.row_of(&id_local).is_none(), "and it stays gone here");
}

// ---------------------------------------------------------------------------------------------
// Your other machine

#[test]
fn records_of_your_other_machine_are_yours_for_forget_last_purge_and_unshare() {
    let srv = Srv::start();
    let a = create(&srv, "ann");
    let b = member(&srv, &a, "bob");
    let b2 = other_machine(&srv, &b);
    share(&b);
    let r1 = b.capture(1, "https://docs.example.org/m1", "Desktop note one.");
    b.ok(&["sync"]);
    b2.ok(&["sync"]);
    let id1 = b.sync_id(r1);
    assert_eq!(b2.row_of(&id1).map(|r| r.1).as_deref(), Some("team"));

    // `forget last` on the laptop picks the desktop's record (the laptop has none of its own).
    let out = b2.ok(&["forget", "last", "--yes"]);
    assert!(
        out.contains("Deleted 1 shared record(s) on the server."),
        "{out}"
    );
    assert!(srv.deleted_ids().contains(&id1));
    assert!(b2.row_of(&id1).is_none());
    assert!(b2.state(&format!("own_deleted.{id1}")).is_some());
    // The desktop keeps its capture, never shared again.
    b.ok(&["sync"]);
    assert_eq!(b.row_of(&id1).map(|r| r.1).as_deref(), Some("local"));
    assert_eq!(b.state("dropped.own_deleted").as_deref(), Some("1"));
    assert_eq!(
        b.count(&format!(
            "SELECT COUNT(*) FROM event WHERE sync_id = '{id1}' AND shareable = 'never'"
        )),
        1
    );

    // purge on the laptop deletes the desktop's records in the range remotely.
    let r2 = b.capture(2, "https://docs.example.org/m2", "Desktop note two.");
    b.ok(&["sync"]);
    b2.ok(&["sync"]);
    let id2 = b.sync_id(r2);
    b2.conn()
        .execute(
            "UPDATE event SET created_at = ?1 WHERE sync_id = ?2",
            params![now_ms() - DAY_MS, id2],
        )
        .unwrap();
    let out = b2.ok(&["purge", "--before", &utc_date(now_ms()), "--yes"]);
    assert!(
        out.contains("Deleted 1 shared record(s) on the server."),
        "{out}"
    );
    assert!(srv.deleted_ids().contains(&id2));

    // unshare --record of the desktop's record on the laptop: deleted remotely and locally.
    let r3 = b.capture(3, "https://docs.example.org/m3", "Desktop note three.");
    b.ok(&["sync"]);
    b2.ok(&["sync"]);
    let id3 = b.sync_id(r3);
    b2.ok(&["team", "unshare", "--record", &id3]);
    assert!(srv.deleted_ids().contains(&id3));
    assert!(b2.row_of(&id3).is_none());
    assert!(b2.state(&format!("own_deleted.{id3}")).is_some());
}
