//! A captured Web search or fetch, built from hook stdin or a transcript (plan-v2 §3.2, §4.3, §6.1).

use anyhow::bail;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::normalize::norm_url;
use crate::note::{Status, Tool};
use crate::redact::redact;

/// `event.summary` cap in characters, applied after redaction.
pub const SUMMARY_CAP: usize = 8_000;
/// Characters of the summary that go into `match_text`.
const MATCH_SUMMARY_CHARS: usize = 400;
/// Result titles that go into `match_text`.
const MATCH_TITLES: usize = 10;
/// A refusal opens the answer; only the start is inspected.
const REFUSAL_WINDOW: usize = 300;
const REFUSAL_PATTERNS: [&str; 5] = [
    "i cannot",
    "i'm unable to",
    "i apologize",
    "the page content appears to be",
    "i don't have access",
];
const PLACEHOLDER_TEXT: &str = "Web search was not performed";

/// One `result` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultRow {
    pub rank: i64,
    pub url: String,
    pub url_norm: String,
    pub title: Option<String>,
}

/// Mirrors the `event` columns plus its `result` rows.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub tool_use_id: String,
    pub tool: Tool,
    pub session_id: String,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    pub cwd_hash: String,
    pub created_at: i64,
    pub query: Option<String>,
    pub url: Option<String>,
    pub url_norm: Option<String>,
    pub fetch_prompt: Option<String>,
    pub http_code: Option<i64>,
    pub bytes: Option<i64>,
    pub duration_ms: Option<i64>,
    pub status: Status,
    pub summary: Option<String>,
    pub match_text: String,
    /// `hook` or `import`.
    pub source: String,
    pub results: Vec<ResultRow>,
    /// Set by capture; not read from the payload.
    pub quarantine_reason: Option<String>,
}

/// Where a transcript tool call happened.
#[derive(Debug, Clone)]
pub struct TranscriptCtx {
    pub session_id: String,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    pub cwd: String,
    pub created_at_ms: i64,
}

/// sha256 of `s` as lower-case hex.
pub fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn tool_of(name: &str) -> Option<Tool> {
    match name {
        "WebSearch" => Some(Tool::WebSearch),
        "WebFetch" => Some(Tool::WebFetch),
        _ => None,
    }
}

fn text_of(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

fn owned(v: Option<&Value>) -> Option<String> {
    text_of(v).filter(|s| !s.is_empty()).map(str::to_string)
}

fn whole_number(v: Option<&Value>) -> Option<i64> {
    let v = v?;
    v.as_i64().or_else(|| v.as_f64().map(|f| f.round() as i64))
}

fn first_chars(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// Fields common to both constructors.
struct Parts<'a> {
    tool: Tool,
    tool_use_id: &'a str,
    session_id: &'a str,
    agent_id: Option<String>,
    agent_type: Option<String>,
    cwd: &'a str,
    created_at: i64,
    source: &'a str,
    input: &'a Value,
    response: &'a Value,
    duration_ms: Option<i64>,
    /// Summary text to use when `response` carries none (transcript `tool_result.content`).
    fallback_text: Option<String>,
    is_error: bool,
}

impl Record {
    /// Builds a record from a PostToolUse payload. `None` when `tool_name` is
    /// not WebSearch/WebFetch, or when the record has nothing to key on (no query,
    /// no parsable URL).
    pub fn from_hook(
        payload: &Value,
        now_ms: i64,
        redact_terms: &[String],
    ) -> anyhow::Result<Option<Record>> {
        let Some(tool) = text_of(payload.get("tool_name")).and_then(tool_of) else {
            return Ok(None);
        };
        let Some(tool_use_id) = text_of(payload.get("tool_use_id")).filter(|s| !s.is_empty())
        else {
            bail!("payload has no tool_use_id");
        };
        let null = Value::Null;
        let response = payload.get("tool_response").unwrap_or(&null);
        let duration_ms =
            whole_number(payload.get("duration_ms")).or_else(|| duration_of(response));
        Ok(build(
            Parts {
                tool,
                tool_use_id,
                session_id: text_of(payload.get("session_id")).unwrap_or(""),
                agent_id: owned(payload.get("agent_id")),
                agent_type: owned(payload.get("agent_type")),
                cwd: text_of(payload.get("cwd")).unwrap_or(""),
                created_at: now_ms,
                source: "hook",
                input: payload.get("tool_input").unwrap_or(&null),
                response,
                duration_ms,
                fallback_text: None,
                is_error: false,
            },
            redact_terms,
        ))
    }

    /// Builds a record from a transcript: the assistant `tool_use` block, the user
    /// `tool_result` block and the record's `toolUseResult` (hook `tool_response` shape).
    pub fn from_transcript(
        tool_use: &Value,
        tool_result: &Value,
        tool_use_result: Option<&Value>,
        ctx: &TranscriptCtx,
        redact_terms: &[String],
    ) -> anyhow::Result<Option<Record>> {
        let Some(tool) = text_of(tool_use.get("name")).and_then(tool_of) else {
            return Ok(None);
        };
        let Some(tool_use_id) = text_of(tool_use.get("id")).filter(|s| !s.is_empty()) else {
            bail!("tool_use has no id");
        };
        let null = Value::Null;
        let response = tool_use_result.unwrap_or(&null);
        let is_error = tool_result
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(build(
            Parts {
                tool,
                tool_use_id,
                session_id: &ctx.session_id,
                agent_id: ctx.agent_id.clone(),
                agent_type: ctx.agent_type.clone(),
                cwd: &ctx.cwd,
                created_at: ctx.created_at_ms,
                source: "import",
                input: tool_use.get("input").unwrap_or(&null),
                response,
                duration_ms: duration_of(response),
                fallback_text: result_text(tool_result.get("content")),
                is_error,
            },
            redact_terms,
        ))
    }

    /// Record status (§3.2). An imported error result is set to `dead_end` by
    /// [`Record::from_transcript`], which this function cannot see.
    pub fn classify(&self) -> Status {
        let summary = self.summary.as_deref().unwrap_or("");
        match self.tool {
            Tool::WebFetch => {
                if self.http_code.is_some_and(|c| c != 200) {
                    Status::DeadEnd
                } else if is_refusal(summary) {
                    Status::Refusal
                } else {
                    Status::Ok
                }
            }
            Tool::WebSearch => {
                if summary.contains(PLACEHOLDER_TEXT) || self.results.is_empty() {
                    Status::Placeholder
                } else {
                    Status::Ok
                }
            }
        }
    }

    /// The FTS document (§6.1): search = query + up to 10 result titles + first
    /// 400 characters of the summary; fetch = fetch prompt + URL + first 400 characters.
    pub fn match_text(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        match self.tool {
            Tool::WebSearch => {
                parts.extend(self.query.as_deref());
                parts.extend(
                    self.results
                        .iter()
                        .filter_map(|r| r.title.as_deref())
                        .take(MATCH_TITLES),
                );
            }
            Tool::WebFetch => {
                parts.extend(self.fetch_prompt.as_deref());
                parts.extend(self.url.as_deref());
            }
        }
        parts.extend(
            self.summary
                .as_deref()
                .map(|s| first_chars(s, MATCH_SUMMARY_CHARS)),
        );
        parts.retain(|p| !p.is_empty());
        parts.join("\n")
    }
}

fn is_refusal(summary: &str) -> bool {
    let head = first_chars(summary.trim_start(), REFUSAL_WINDOW)
        .to_lowercase()
        .replace('\u{2019}', "'");
    REFUSAL_PATTERNS.iter().any(|p| head.contains(p))
}

fn duration_of(response: &Value) -> Option<i64> {
    whole_number(response.get("durationMs")).or_else(|| {
        response
            .get("durationSeconds")
            .and_then(Value::as_f64)
            .map(|s| (s * 1000.0).round() as i64)
    })
}

/// Text of a transcript `tool_result.content`: a string, or text blocks.
fn result_text(content: Option<&Value>) -> Option<String> {
    let text = match content? {
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .filter_map(|i| i.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => return None,
    };
    (!text.is_empty()).then_some(text)
}

fn red(text: &str, terms: &[String]) -> String {
    redact(text, terms).0
}

fn build(p: Parts, terms: &[String]) -> Option<Record> {
    let mut rec = Record {
        tool_use_id: p.tool_use_id.to_string(),
        tool: p.tool,
        session_id: p.session_id.to_string(),
        agent_id: p.agent_id,
        agent_type: p.agent_type,
        cwd_hash: sha256_hex(p.cwd),
        created_at: p.created_at,
        query: None,
        url: None,
        url_norm: None,
        fetch_prompt: None,
        http_code: None,
        bytes: None,
        duration_ms: p.duration_ms,
        status: Status::Ok,
        summary: None,
        match_text: String::new(),
        source: p.source.to_string(),
        results: Vec::new(),
        quarantine_reason: None,
    };
    let mut summary: Option<String> = None;
    match p.tool {
        Tool::WebSearch => {
            let query = owned(p.input.get("query")).or_else(|| owned(p.response.get("query")))?;
            rec.query = Some(red(&query, terms));
            let mut strings: Vec<&str> = Vec::new();
            if let Some(s) = p.response.as_str() {
                strings.push(s);
            }
            let items = p.response.get("results").and_then(Value::as_array);
            for item in items.into_iter().flatten() {
                match item {
                    Value::String(s) => strings.push(s),
                    Value::Object(_) => {
                        let content = item.get("content").and_then(Value::as_array);
                        for hit in content.into_iter().flatten() {
                            let Some(url) = text_of(hit.get("url")) else {
                                continue;
                            };
                            let Some(url_norm) = norm_url(url) else {
                                continue;
                            };
                            rec.results.push(ResultRow {
                                rank: i64::try_from(rec.results.len()).unwrap_or(i64::MAX) + 1,
                                url: url.to_string(),
                                url_norm,
                                title: owned(hit.get("title")).map(|t| red(&t, terms)),
                            });
                        }
                    }
                    _ => {}
                }
            }
            if !strings.is_empty() {
                summary = Some(strings.join("\n"));
            }
        }
        Tool::WebFetch => {
            let url = owned(p.input.get("url")).or_else(|| owned(p.response.get("url")))?;
            rec.url_norm = Some(norm_url(&url)?);
            rec.url = Some(url);
            rec.fetch_prompt = owned(p.input.get("prompt")).map(|t| red(&t, terms));
            rec.http_code = whole_number(p.response.get("code"));
            rec.bytes = whole_number(p.response.get("bytes"));
            summary = owned(p.response.get("result"));
        }
    }
    let summary = summary.or(p.fallback_text);
    rec.summary = summary.map(|s| red(&s, terms).chars().take(SUMMARY_CAP).collect());
    rec.status = if p.is_error {
        Status::DeadEnd
    } else {
        rec.classify()
    };
    rec.match_text = rec.match_text();
    Some(rec)
}
