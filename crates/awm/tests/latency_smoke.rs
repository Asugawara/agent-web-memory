//! Latency of the query channel on 3,000 synthetic records (plan-v2 §3.6).
//! Run in release mode: `cargo test --release -p agent-web-memory --test latency_smoke -- --ignored`.

use std::time::Instant;

use awm::db::{self, Role};
use awm::matching::{self, MatchOpts};

const RECORDS: usize = 3_000;
const QUERIES: usize = 200;
const VOCAB: usize = 2_000;

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    /// Zipf-like: low word numbers are common.
    fn word(&mut self) -> String {
        let r = (self.next() % VOCAB as u64) as f64 / VOCAB as f64;
        format!("w{}", (r * r * VOCAB as f64) as u64)
    }

    fn words(&mut self, n: usize) -> Vec<String> {
        (0..n).map(|_| self.word()).collect()
    }
}

#[test]
#[ignore]
fn query_channel_p95_is_within_50_ms_at_3000_records() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = db::open(&dir.path().join("awm.db"), Role::Cli).unwrap();
    db::migrate(&mut conn).unwrap();
    let mut rng = Lcg(42);
    let tx = conn.transaction().unwrap();
    {
        let mut st = tx
            .prepare(
                "INSERT INTO event (tool_use_id, tool, session_id, cwd_hash, created_at, query, \
                 status, summary, match_text, source) \
                 VALUES (?1, 'WebSearch', ?2, 'cwd', ?3, ?4, 'ok', ?5, ?6, 'hook')",
            )
            .unwrap();
        for i in 0..RECORDS {
            let query = rng.words(6).join(" ");
            let summary = rng.words(60).join(" ");
            let match_text = format!(
                "{query}\n{}\n{}",
                rng.words(20).join(" "),
                &summary[..summary.len().min(400)]
            );
            st.execute(rusqlite::params![
                format!("syn{i}"),
                format!("s{}", i % 40),
                1_790_000_000_000_i64 + i as i64 * 60_000,
                query,
                summary,
                match_text
            ])
            .unwrap();
        }
    }
    tx.commit().unwrap();

    let opts = MatchOpts {
        caller_session: "s-caller".to_string(),
        caller_cwd_hash: "cwd".to_string(),
        exclude_same_agent: true,
        limit: 3,
        ..MatchOpts::default()
    };
    // Warm-up: statement cache and page cache.
    matching::query_channel(&conn, "w1 w2 w3", 0.0, &opts).unwrap();
    let mut ms: Vec<f64> = Vec::new();
    for _ in 0..QUERIES {
        let text = rng.words(8).join(" ");
        let t = Instant::now();
        matching::query_channel(&conn, &text, 0.0, &opts).unwrap();
        ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    ms.sort_by(f64::total_cmp);
    let p50 = ms[QUERIES / 2];
    let p95 = ms[QUERIES * 95 / 100];
    println!(
        "query_channel over {RECORDS} records, {QUERIES} calls: p50 {p50:.2} ms, p95 {p95:.2} ms"
    );
    assert!(p95 <= 50.0, "p95 {p95:.2} ms exceeds 50 ms");
}

#[test]
#[ignore]
fn similar_search_lookup_p95_is_within_50_ms_at_3000_searches_in_7_days() {
    use awm::config::Config;
    use awm::hook::{pre_search, Env, HookInput};

    const SEARCHES: usize = 3_000;
    const DAY_MS: i64 = 86_400_000;
    let dir = tempfile::tempdir().unwrap();
    let mut conn = db::open(&dir.path().join("awm.db"), Role::Cli).unwrap();
    db::migrate(&mut conn).unwrap();
    let now = 1_790_000_000_000_i64;
    let mut rng = Lcg(7);
    let mut queries = Vec::new();
    let tx = conn.transaction().unwrap();
    {
        let mut st = tx
            .prepare(
                "INSERT INTO event (tool_use_id, tool, session_id, cwd_hash, created_at, query, \
                 status, summary, match_text, source) \
                 VALUES (?1, 'WebSearch', ?2, 'cwd', ?3, ?4, 'ok', ?5, ?6, 'hook')",
            )
            .unwrap();
        for i in 0..SEARCHES {
            let query = rng.words(6).join(" ");
            let summary = rng.words(60).join(" ");
            st.execute(rusqlite::params![
                format!("syn{i}"),
                format!("s{}", i % 40),
                // All inside one 24 h window, spread evenly.
                now - 1_000 - (i as i64) * (DAY_MS - 2_000) / SEARCHES as i64,
                query,
                summary,
                query
            ])
            .unwrap();
            queries.push(query);
        }
    }
    tx.commit().unwrap();
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('cutoff.query', '0'), ('cutoff.query_deny', '0')",
        [],
    )
    .unwrap();

    let env = Env {
        hook: "pre-fetch",
        input: HookInput {
            session_id: "s-caller".to_string(),
            tool_name: "WebSearch".to_string(),
            ..HookInput::default()
        },
        config: Config::default(),
        started: Instant::now(),
        started_at_ms: now,
        utc_offset_min: 0,
    };
    // Mostly unrelated words (misses), every fifth lookup repeats an earlier query.
    let mut texts: Vec<String> = (0..QUERIES).map(|_| rng.words(6).join(" ")).collect();
    for t in texts.iter_mut().step_by(5) {
        *t = queries[(rng.next() as usize) % 2_000].clone();
    }
    pre_search::find_similar(&env, &conn, &texts[0]).unwrap();
    let mut ms: Vec<f64> = Vec::new();
    let mut found = 0;
    for text in &texts {
        let t = Instant::now();
        found += usize::from(
            !pre_search::find_similar(&env, &conn, text)
                .unwrap()
                .is_empty(),
        );
        ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    ms.sort_by(f64::total_cmp);
    let p50 = ms[QUERIES / 2];
    let p95 = ms[QUERIES * 95 / 100];
    println!(
        "find_similar over {SEARCHES} searches, {QUERIES} lookups ({found} hits): p50 {p50:.2} ms, p95 {p95:.2} ms"
    );
    assert!(found >= QUERIES / 5 - 1, "hits {found}");
    assert!(p95 <= 50.0, "p95 {p95:.2} ms exceeds 50 ms");
}
