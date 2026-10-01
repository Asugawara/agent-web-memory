use awm::note::Status;
use awm::record::{Record, TranscriptCtx};
use serde_json::json;

fn ctx() -> TranscriptCtx {
    TranscriptCtx {
        session_id: "s".into(),
        agent_id: None,
        agent_type: None,
        cwd: "/w".into(),
        created_at_ms: 5,
    }
}

#[test]
fn non_web_tool_is_none() {
    let p = json!({"tool_name": "Bash", "tool_use_id": "x"});
    assert!(Record::from_hook(&p, 1, &[]).unwrap().is_none());
}

#[test]
fn transcript_error_result_is_dead_end() {
    let tu = json!({"id": "t1", "name": "WebFetch",
                    "input": {"url": "https://example.org/x", "prompt": "p"}});
    let tr = json!({"tool_use_id": "t1", "is_error": true,
                    "content": "Request failed with status code 404"});
    let r = Record::from_transcript(&tu, &tr, None, &ctx(), &[])
        .unwrap()
        .unwrap();
    assert_eq!(r.status, Status::DeadEnd);
    assert_eq!(r.source, "import");
    assert_eq!(
        r.summary.as_deref(),
        Some("Request failed with status code 404")
    );
}

#[test]
fn transcript_uses_tool_use_result_shape() {
    let tu = json!({"id": "t2", "name": "WebSearch", "input": {"query": "q"}});
    let tr = json!({"tool_use_id": "t2", "content": "ignored"});
    let res = json!({"query": "q", "durationSeconds": 1.5, "results": [
        {"tool_use_id": "s", "content": [{"title": "A", "url": "https://a.example/x"}]}, "summary text"]});
    let r = Record::from_transcript(&tu, &tr, Some(&res), &ctx(), &[])
        .unwrap()
        .unwrap();
    assert_eq!(r.results.len(), 1);
    assert_eq!(r.duration_ms, Some(1500));
    assert_eq!(r.summary.as_deref(), Some("summary text"));
    assert_eq!(r.match_text, "q\nA\nsummary text");
}

#[test]
fn summary_is_cut_to_8000_chars_after_redaction() {
    let long = "ab ".repeat(3000);
    let p = json!({"tool_name": "WebFetch", "tool_use_id": "t", "session_id": "s", "cwd": "/",
        "tool_input": {"url": "https://example.org/", "prompt": "p"},
        "tool_response": {"code": 200, "result": long}});
    let r = Record::from_hook(&p, 1, &[]).unwrap().unwrap();
    let summary = r.summary.unwrap();
    assert_eq!(summary.chars().count(), 8000);
    assert_eq!(
        r.match_text,
        format!(
            "p\nhttps://example.org/\n{}",
            summary.chars().take(400).collect::<String>()
        )
    );
}

const GHP: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
const AKIA: &str = "AKIAIOSFODNN7EXAMPLE";

#[test]
fn fetch_url_secrets_are_redacted_in_every_column() {
    let url = format!("https://api.example.com/v1?token={GHP}&k={AKIA}");
    let p = json!({"tool_name": "WebFetch", "tool_use_id": "t", "session_id": "s", "cwd": "/",
        "tool_input": {"url": url, "prompt": "p"},
        "tool_response": {"code": 200, "result": "ok"}});
    let r = Record::from_hook(&p, 1, &[]).unwrap().unwrap();
    for text in [
        r.url.as_deref().unwrap(),
        r.url_norm.as_deref().unwrap(),
        &r.match_text,
    ] {
        assert!(!text.contains("ghp_") && !text.contains("AKIA"), "{text}");
    }
}

#[test]
fn search_result_url_secrets_are_redacted() {
    let url = format!("https://a.example/x?key={AKIA}");
    let p = json!({"tool_name": "WebSearch", "tool_use_id": "t", "session_id": "s", "cwd": "/",
        "tool_input": {"query": "q"},
        "tool_response": {"query": "q", "results": [
            {"tool_use_id": "s", "content": [{"title": "A", "url": url}]}, "summary"]}});
    let r = Record::from_hook(&p, 1, &[]).unwrap().unwrap();
    assert_eq!(r.results.len(), 1);
    assert!(!r.results[0].url.contains("AKIA"));
    assert!(!r.results[0].url_norm.contains("AKIA"));
}

#[test]
fn a_url_whose_host_is_a_secret_is_not_recorded() {
    let p = json!({"tool_name": "WebFetch", "tool_use_id": "t", "session_id": "s", "cwd": "/",
        "tool_input": {"url": format!("https://{GHP}/x"), "prompt": "p"},
        "tool_response": {"code": 200, "result": "ok"}});
    assert!(Record::from_hook(&p, 1, &[]).unwrap().is_none());
}

mod codex {
    use std::path::Path;

    use awm::note::{Status, Tool};
    use awm::record::{from_codex_rollout, from_codex_rollout_pair, CodexCtx, Record};
    use serde_json::{json, Value};

    fn lines(name: &str) -> Vec<Value> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/projects-codex/sessions/2026/10/02")
            .join(name);
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn ctx(line: usize, parent: Option<&str>) -> CodexCtx {
        CodexCtx {
            session_id: "sess".into(),
            parent_thread_id: parent.map(str::to_string),
            cwd: "/w".into(),
            created_at_ms: 7,
            turn_id: Some("turn".into()),
            file_stem: "rollout-synthetic".into(),
            line,
        }
    }

    fn rollout(i: usize) -> Option<Record> {
        let l = lines("rollout-synthetic.jsonl");
        from_codex_rollout(&l[i], &ctx(i + 1, None))
    }

    #[test]
    fn search_call_has_query_and_status_ok() {
        let r = rollout(4).unwrap();
        assert_eq!(r.tool, Tool::WebSearch);
        assert_eq!(r.query.as_deref(), Some("http caching headers"));
        assert_eq!(r.status, Status::Ok);
        assert_eq!(r.source, "codex-rollout");
        assert_eq!(r.db_source(), "import");
        assert_eq!(r.tool_use_id, "codex:rollout-synthetic:5");
        assert!(r.results.is_empty() && r.summary.is_none());
        assert_eq!(r.match_text, "http caching headers");
    }

    #[test]
    fn search_without_query_joins_queries() {
        let rec = json!({"payload": {"type": "web_search_call", "action":
            {"type": "search", "queries": ["a b", "c d"]}}});
        let r = from_codex_rollout(&rec, &ctx(1, None)).unwrap();
        assert_eq!(r.query.as_deref(), Some("a b | c d"));
    }

    #[test]
    fn open_page_is_a_fetch_with_url_norm() {
        let r = rollout(5).unwrap();
        assert_eq!(r.tool, Tool::WebFetch);
        assert_eq!(
            r.url_norm.as_deref(),
            Some("https://example.com/docs/caching")
        );
        assert_eq!(r.fetch_prompt, None);
        assert_eq!(r.status, Status::Ok);
    }

    #[test]
    fn find_in_page_keeps_the_pattern_as_fetch_prompt() {
        let r = rollout(6).unwrap();
        assert_eq!(r.fetch_prompt.as_deref(), Some("max-age"));
        assert!(r.match_text.contains("max-age"));
        assert_eq!(r.status, Status::Ok);
    }

    #[test]
    fn web_run_pair_parses_results_and_summary() {
        let l = lines("rollout-synthetic.jsonl");
        let r = from_codex_rollout_pair(&l[7], &l[8], &ctx(8, None), &[]).unwrap();
        assert_eq!(r.query.as_deref(), Some("example caching guide"));
        let urls: Vec<_> = r.results.iter().map(|x| x.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://example.com/r1",
                "https://example.org/r2",
                "https://example.com/r3"
            ]
        );
        assert_eq!(r.results[1].title.as_deref(), Some("Title Two"));
        assert_eq!(r.status, Status::Ok);
        let s = r.summary.unwrap();
        assert!(s.starts_with("Title One (") && !s.contains("Script completed"));
        // the lone call and a mismatched output give nothing
        assert!(from_codex_rollout(&l[7], &ctx(8, None)).is_none());
        let mut other = l[8].clone();
        other["payload"]["call_id"] = json!("different");
        assert!(from_codex_rollout_pair(&l[7], &other, &ctx(8, None), &[]).is_none());
    }

    #[test]
    fn other_records_are_none() {
        for i in [0, 1, 2, 3, 9, 10] {
            assert!(rollout(i).is_none(), "line {i}");
        }
    }

    #[test]
    fn subagent_rollout_joins_the_parent_session() {
        let l = lines("rollout-subagent.jsonl");
        assert_eq!(
            l[0]["payload"]["source"]["subagent"]["thread_spawn"]["parent_thread_id"],
            l[0]["payload"]["parent_thread_id"]
        );
        let parent = l[0]["payload"]["parent_thread_id"].as_str().unwrap();
        let r = from_codex_rollout(&l[2], &ctx(3, Some(parent))).unwrap();
        assert_eq!(r.session_id, parent);
        assert_eq!(r.agent_id.as_deref(), Some("sess"));
        assert_eq!(r.agent_type.as_deref(), Some("subagent"));
    }

    #[test]
    fn hook_payload_parses_results_in_order() {
        let p = json!({"tool_name": "webrun", "tool_use_id": "exec-1", "session_id": "s",
            "tool_input": {"search_query": [{"q": "one"}, {"q": "two"}]},
            "tool_response": [{"type": "input_text", "text":
                "Alpha (https://example.com/a)\nnote\n---\nhttps://example.com/b.\nsee https://example.com/a again"}]});
        let r = Record::from_hook(&p, 3, &[]).unwrap().unwrap();
        assert_eq!(r.query.as_deref(), Some("one | two"));
        assert_eq!(r.source, "codex-hook");
        assert_eq!(r.agent_id, None);
        assert_eq!(r.results.len(), 2);
        assert_eq!(r.results[0].title.as_deref(), Some("Alpha"));
        assert_eq!(r.results[1].url, "https://example.com/b");
        assert_eq!(r.results[1].title, None);
        let other = json!({"tool_name": "exec", "tool_use_id": "x"});
        assert!(Record::from_hook(&other, 1, &[]).unwrap().is_none());
    }
}
