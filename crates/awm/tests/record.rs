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
