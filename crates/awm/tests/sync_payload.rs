//! `sync::payload::build` (plan-v3-team §3.2; TM5): shared fields only, caps, hour rounding, fit.

use awm::config::Config;
use awm::note::{Status, Tool};
use awm::record::{Agent, Record, ResultRow};
use awm::redact;
use awm::sync::eligible::TeamPolicy;
use awm::sync::payload::{
    self, build, hour_floor_secs, Payload, Share, ShareCtx, MAX_PLAINTEXT, PLAINTEXT_BUDGET,
};
use serde_json::Value;

/// 2026-10-02 06:58:25 UTC in milliseconds; the hour starts at 1_790_920_800 s.
const CREATED_MS: i64 = 1_790_924_305_000;
const REPO_KEY: &str = "0123456789abcdef0123456789abcdef";

fn row(rank: i64, url: &str, title: Option<&str>) -> ResultRow {
    ResultRow {
        rank,
        url: url.to_string(),
        url_norm: format!("NORM-{url}"),
        title: title.map(str::to_string),
    }
}

fn fetch() -> Record {
    Record {
        tool_use_id: "toolu_NEVER_SHARED_ID".into(),
        tool: Tool::WebFetch,
        session_id: "SESSION-NEVER-SHARED".into(),
        agent_id: Some("AGENT-ID-NEVER-SHARED".into()),
        agent_type: Some("AGENT-TYPE-NEVER-SHARED".into()),
        cwd_hash: "CWDHASH-NEVER-SHARED".into(),
        cwd: "/Users/CWD-NEVER-SHARED/repo".into(),
        created_at: CREATED_MS,
        query: None,
        url: Some("https://sqlite.org/fts5.html".into()),
        url_norm: Some("NORM-NEVER-SHARED".into()),
        fetch_prompt: Some("What does bm25 return?".into()),
        http_code: Some(200),
        bytes: Some(10_240),
        duration_ms: Some(812),
        status: Status::Ok,
        summary: Some("bm25 returns a negative score; lower is better.".into()),
        match_text: "MATCH-TEXT-NEVER-SHARED".into(),
        source: "hook".into(),
        agent: Agent::Claude,
        results: Vec::new(),
        quarantine_reason: None,
    }
}

fn search() -> Record {
    Record {
        tool: Tool::WebSearch,
        query: Some("sqlite fts5 bm25 ranking".into()),
        url: None,
        url_norm: None,
        fetch_prompt: None,
        http_code: None,
        bytes: None,
        summary: Some("Results describe bm25().".into()),
        results: vec![
            row(1, "https://sqlite.org/fts5.html", Some("FTS5 Extension")),
            row(2, "https://example.com/bm25", Some("BM25 explained")),
        ],
        source: "import".into(),
        agent: Agent::Codex,
        ..fetch()
    }
}

fn ctx(share: Share) -> ShareCtx {
    ShareCtx::new(
        share,
        Some(REPO_KEY.to_string()),
        &Config::default(),
        &TeamPolicy::default(),
    )
}

fn json(p: &Payload) -> Value {
    serde_json::from_slice(&p.plaintext).expect("payload is JSON")
}

fn text(p: &Payload) -> &str {
    std::str::from_utf8(&p.plaintext).expect("utf-8")
}

#[test]
fn never_shared_fields_are_absent_from_the_json() {
    let mut rec = fetch();
    rec.results = vec![row(1, "https://example.com/a", Some("A"))];
    let p = build(&rec, &ctx(Share::Full)).expect("builds");
    let body = text(&p);
    for secret in [
        "toolu_NEVER_SHARED_ID",
        "SESSION-NEVER-SHARED",
        "AGENT-ID-NEVER-SHARED",
        "AGENT-TYPE-NEVER-SHARED",
        "CWDHASH-NEVER-SHARED",
        "CWD-NEVER-SHARED",
        "NORM-NEVER-SHARED",
        "MATCH-TEXT-NEVER-SHARED",
        "NORM-https",
    ] {
        assert!(!body.contains(secret), "{secret} leaked: {body}");
    }
    // The key set is exactly the §15.1 list: no tool_use_id, session_id, agent_id, agent_type,
    // cwd, cwd_hash, path, repo_root, url_norm, match_text, quarantine_reason, prompt or tool
    // response.
    let v = json(&p);
    let allowed = [
        "schema",
        "tool",
        "query",
        "url",
        "fetch_prompt",
        "http_code",
        "bytes",
        "duration_ms",
        "status",
        "summary",
        "results",
        "agent",
        "source",
        "created_at",
        "repo_key",
        "share",
    ];
    for key in v.as_object().unwrap().keys() {
        assert!(allowed.contains(&key.as_str()), "unexpected key {key}");
    }
    // STATS1: the plain cwd and its repository root (the local `cwd` table) are never sent.
    for name in ["cwd", "cwd_hash", "path", "repo_root"] {
        assert!(v.get(name).is_none(), "{name} in the payload: {body}");
        assert!(
            !body.contains(&format!("\"{name}\"")),
            "{name} in the payload: {body}"
        );
    }
    for r in v["results"].as_array().unwrap() {
        let keys: Vec<&String> = r.as_object().unwrap().keys().collect();
        assert!(keys
            .iter()
            .all(|k| ["rank", "url", "title"].contains(&k.as_str())));
    }
}

#[test]
fn a_credential_url_never_reaches_the_json() {
    // A fetch whose URL carries a credential is refused outright.
    let mut rec = fetch();
    rec.url = Some("https://example.com/doc?token=SECRETVALUE123&page=2".into());
    assert!(build(&rec, &ctx(Share::Full)).is_err());
    rec.url = Some("https://user:hunter2@example.com/doc".into());
    assert!(build(&rec, &ctx(Share::Full)).is_err());

    // A result row with one is dropped; the query string does not appear anywhere.
    let mut rec = search();
    rec.results.push(row(
        3,
        "https://example.com/cb?access_token=SECRETVALUE123&sig=abcdef",
        Some("Callback"),
    ));
    rec.results.push(row(
        4,
        "https://example.com/dl?X-Amz-Signature=SIGVALUE999",
        None,
    ));
    let p = build(&rec, &ctx(Share::Full)).expect("builds");
    let body = text(&p);
    assert!(!body.contains("SECRETVALUE123"), "{body}");
    assert!(!body.contains("SIGVALUE999"), "{body}");
    assert!(!body.contains("access_token"), "{body}");
    assert_eq!(json(&p)["results"].as_array().unwrap().len(), 2);
}

#[test]
fn created_at_is_rounded_down_to_the_hour_in_seconds() {
    let p = build(&fetch(), &ctx(Share::Full)).unwrap();
    assert_eq!(json(&p)["created_at"], 1_790_920_800_i64);
    assert_eq!(hour_floor_secs(CREATED_MS), 1_790_920_800);
    // The last millisecond of the hour and the first of the next.
    assert_eq!(hour_floor_secs(1_790_920_800_000), 1_790_920_800);
    assert_eq!(hour_floor_secs(1_790_924_399_999), 1_790_920_800);
    assert_eq!(hour_floor_secs(1_790_924_400_000), 1_790_924_400);
    assert_eq!(hour_floor_secs(0), 0);
}

#[test]
fn the_summary_is_cut_to_summary_chars_at_a_char_boundary() {
    let mut rec = fetch();
    // 3-byte and 4-byte characters: a byte cut at 1,000 would split one.
    rec.summary = Some("\u{65e5}\u{672c}\u{8a9e}🦀".repeat(600));
    let mut c = ctx(Share::Full);
    assert_eq!(c.summary_chars, 1000);
    let p = build(&rec, &c).unwrap();
    let s = json(&p)["summary"].as_str().unwrap().to_string();
    assert_eq!(s.chars().count(), 1000);
    assert!(rec.summary.as_ref().unwrap().starts_with(&s));

    c.summary_chars = 120;
    let p = build(&rec, &c).unwrap();
    assert_eq!(json(&p)["summary"].as_str().unwrap().chars().count(), 120);

    // `team.summary_chars` can not exceed 2,000, whatever the context says.
    c.summary_chars = 9_999;
    let mut cfg = Config::default();
    cfg.team.summary_chars = 2000;
    let c2 = ShareCtx::new(Share::Full, None, &cfg, &TeamPolicy::default());
    assert_eq!(c2.summary_chars, 2000);
    let p = build(&rec, &c).unwrap();
    assert_eq!(json(&p)["summary"].as_str().unwrap().chars().count(), 2000);

    // The policy can lower it.
    let policy = TeamPolicy {
        summary_chars: Some(300),
        ..TeamPolicy::default()
    };
    let c3 = ShareCtx::new(Share::Full, None, &Config::default(), &policy);
    assert_eq!(c3.summary_chars, 300);
}

#[test]
fn a_link_record_carries_no_summary_query_or_other_full_only_field() {
    let mut rec = search();
    rec.fetch_prompt = Some("a prompt".into());
    rec.http_code = Some(200);
    rec.bytes = Some(5);
    rec.duration_ms = Some(9);
    let p = build(&rec, &ctx(Share::Link)).unwrap();
    let v = json(&p);
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    for k in [
        "summary",
        "query",
        "fetch_prompt",
        "http_code",
        "bytes",
        "duration_ms",
        "repo_key",
    ] {
        assert!(!keys.contains(&k), "{k} in a link record: {keys:?}");
    }
    assert_eq!(v["share"], "link");
    assert_eq!(v["results"].as_array().unwrap().len(), 2);
    assert_eq!(p.share, Share::Link);

    let p = build(&fetch(), &ctx(Share::Link)).unwrap();
    let v = json(&p);
    assert_eq!(v["url"], "https://sqlite.org/fts5.html");
    assert!(v.get("summary").is_none() && v.get("repo_key").is_none());
}

#[test]
fn results_are_capped_per_section_3_2() {
    let mut rec = search();
    rec.results = (1..=14)
        .map(|i| row(i, &format!("https://example.com/p{i}"), Some("t")))
        .collect();
    // A 512-character URL stays, a 513-character one drops its row; a 130-character title is cut to 120.
    let long_ok = format!("https://example.com/{}", "a".repeat(512 - 20));
    assert_eq!(long_ok.chars().count(), 512);
    let long_bad = format!("{long_ok}b");
    rec.results[0] = row(1, &long_ok, Some(&"é".repeat(130)));
    rec.results[1] = row(2, &long_bad, Some("dropped"));
    let p = build(&rec, &ctx(Share::Full)).unwrap();
    let v = json(&p);
    let rows = v["results"].as_array().unwrap();
    // 14 rows, cap 10 taken first; row 2 is then dropped for its URL.
    assert_eq!(rows.len(), 9);
    assert_eq!(rows[0]["url"], long_ok);
    assert_eq!(rows[0]["title"].as_str().unwrap().chars().count(), 120);
    assert!(rows.iter().all(|r| r["rank"] != 2));
    assert!(rows.iter().all(|r| r["rank"].as_u64().unwrap() <= 10));
    assert!(!text(&p).contains(&long_bad));
}

#[test]
fn a_50000_char_summary_and_a_2048_char_url_still_fit_the_envelope() {
    let mut rec = fetch();
    rec.summary = Some("x".repeat(50_000));
    let url = format!("https://example.com/{}", "u".repeat(2048 - 20));
    assert_eq!(url.chars().count(), 2048);
    rec.url = Some(url.clone());
    let p = build(&rec, &ctx(Share::Full)).unwrap();
    assert!(p.fits());
    assert!(p.plaintext.len() <= PLAINTEXT_BUDGET);
    assert_eq!(json(&p)["url"], url);
    assert_eq!(json(&p)["summary"].as_str().unwrap().chars().count(), 1000);

    // One character more and the URL is not shared, so a fetch has nothing to key on.
    rec.url = Some(format!("{url}x"));
    assert!(build(&rec, &ctx(Share::Full)).is_err());

    // A link record with the longest URL fits as well.
    rec.url = Some(url);
    assert!(build(&rec, &ctx(Share::Link)).unwrap().fits());
}

#[test]
fn the_worst_case_is_trimmed_to_the_budget_and_fits() {
    let mut rec = search();
    rec.query = Some("q".repeat(500));
    rec.results = (1..=10)
        .map(|i| {
            row(
                i,
                &format!("https://example.com/{i}/{}", "🦀".repeat(60)),
                Some(&"🦀".repeat(120)),
            )
        })
        .collect();
    rec.summary = Some("🦀".repeat(2000));
    let mut c = ctx(Share::Full);
    c.summary_chars = 2000;
    let p = build(&rec, &c).unwrap();
    assert!(
        p.plaintext.len() <= PLAINTEXT_BUDGET,
        "{}",
        p.plaintext.len()
    );
    assert!(p.fits());
    const { assert!(PLAINTEXT_BUDGET < MAX_PLAINTEXT) };
    // Rows go from the end first, then the summary.
    let t = p.trimmed;
    assert!(t.results_dropped > 0 || t.summary_shortened, "{t:?}");
    if t.summary_shortened {
        assert_eq!(json(&p)["results"].as_array().unwrap().len(), 0);
    }
    assert_eq!(
        json(&p)["results"].as_array().unwrap().len(),
        10 - t.results_dropped
    );
}

#[test]
fn a_placeholder_a_secret_and_an_unknown_source_are_refused() {
    let mut rec = search();
    rec.status = Status::Placeholder;
    assert!(build(&rec, &ctx(Share::Full)).is_err());

    let mut rec = search();
    rec.summary = Some("password=hunter2hunter2 was used".into());
    assert!(build(&rec, &ctx(Share::Full)).is_err());
    // A link record does not carry the summary, so the same record builds as a link.
    assert!(build(&rec, &ctx(Share::Link)).is_ok());

    let mut rec = search();
    rec.source = "something-else".into();
    assert!(build(&rec, &ctx(Share::Full)).is_err());
}

#[test]
fn codex_sources_map_to_hook_and_import_and_the_agent_is_kept() {
    let mut rec = fetch();
    rec.source = "codex-hook".into();
    rec.agent = Agent::Codex;
    let v = json(&build(&rec, &ctx(Share::Full)).unwrap());
    assert_eq!(
        (v["source"].as_str(), v["agent"].as_str()),
        (Some("hook"), Some("codex"))
    );
    rec.source = "codex-rollout".into();
    let v = json(&build(&rec, &ctx(Share::Full)).unwrap());
    assert_eq!(v["source"], "import");
}

#[test]
fn repo_key_is_sent_for_full_when_well_formed_only() {
    let v = json(&build(&fetch(), &ctx(Share::Full)).unwrap());
    assert_eq!(v["repo_key"], REPO_KEY);
    let mut c = ctx(Share::Full);
    c.repo_key = Some("not-a-key".into());
    assert!(json(&build(&fetch(), &c).unwrap())
        .get("repo_key")
        .is_none());
    c.repo_key = None;
    assert!(json(&build(&fetch(), &c).unwrap())
        .get("repo_key")
        .is_none());
}

#[test]
fn the_payload_reports_the_redaction_version() {
    let p = build(&fetch(), &ctx(Share::Full)).unwrap();
    assert_eq!(p.redact_version, redact::VERSION);
    const { assert!(redact::VERSION >= 1) };
    // It is not a wire field.
    assert!(json(&p).get("redact_version").is_none());
}

#[test]
fn golden_full_record() {
    let mut rec = search();
    rec.fetch_prompt = None;
    rec.results = vec![
        row(
            1,
            "https://sqlite.org/fts5.html",
            Some("SQLite FTS5 Extension"),
        ),
        row(2, "https://example.com/bm25", None),
    ];
    let p = build(&rec, &ctx(Share::Full)).unwrap();
    let want = include_str!("golden/sync_payload_full.json").trim_end();
    assert_eq!(text(&p), want);
}

#[test]
fn golden_link_record() {
    let mut rec = fetch();
    rec.url = Some("https://acme.atlassian.net/wiki/spaces/ENG/pages/42".into());
    let p = build(&rec, &ctx(Share::Link)).unwrap();
    let want = include_str!("golden/sync_payload_link.json").trim_end();
    assert_eq!(text(&p), want);
}

#[test]
fn the_payload_constants_match_the_protocol_crate() {
    assert_eq!(payload::SCHEMA, 1);
    assert_eq!(payload::MAX_PLAINTEXT, 16_127);
}

#[cfg(feature = "sync")]
mod proto {
    use super::*;
    use awm_proto::wire::{decode_plaintext, Decoded, RecPlaintext};

    fn roundtrip(p: &Payload) {
        let d = decode_plaintext::<RecPlaintext>(&p.plaintext).expect("decodes");
        let Decoded::Known(rec) = d else {
            panic!("newer schema");
        };
        // Same bytes when TM2's type writes it back: field order, names and skips agree.
        assert_eq!(serde_json::to_vec(&rec).unwrap(), p.plaintext);
    }

    #[test]
    fn payloads_decode_as_the_wire_rec_plaintext_and_serialise_to_the_same_bytes() {
        let mut rec = search();
        rec.results.push(row(3, "https://example.com/3", None));
        for share in [Share::Full, Share::Link] {
            roundtrip(&build(&rec, &ctx(share)).unwrap());
            roundtrip(&build(&fetch(), &ctx(share)).unwrap());
        }
    }

    #[test]
    fn the_envelope_cap_and_schema_match_awm_proto() {
        assert_eq!(payload::MAX_PLAINTEXT, awm_proto::crypto::MAX_PLAINTEXT);
        assert_eq!(payload::SCHEMA, awm_proto::wire::PLAINTEXT_SCHEMA);
    }

    #[test]
    fn a_large_payload_stays_within_the_protocol_cap() {
        let mut rec = fetch();
        rec.summary = Some("🦀".repeat(5_000));
        let p = build(&rec, &ctx(Share::Full)).unwrap();
        assert!(p.plaintext.len() <= awm_proto::crypto::MAX_PLAINTEXT);
    }
}
