//! A captured Web search or fetch, built from hook stdin or a transcript (plan-v2 §3.2, §4.3, §6.1).

use anyhow::bail;
use serde::{Deserialize, Serialize};
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultRow {
    pub rank: i64,
    pub url: String,
    pub url_norm: String,
    pub title: Option<String>,
}

/// `event.agent`: the coding agent that made the call (migration 0002).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Agent {
    #[default]
    Claude,
    Codex,
}

impl Agent {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
        }
    }
}

/// Mirrors the `event` columns plus its `result` rows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// `hook`, `import`, `codex-hook` or `codex-rollout`. The database stores
    /// [`Record::db_source`].
    pub source: String,
    /// Spool files written before migration 0002 have no `agent`; they are Claude's.
    #[serde(default)]
    pub agent: Agent,
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

/// Where a Codex rollout record sits (the importer fills this in per file and line).
#[derive(Debug, Clone)]
pub struct CodexCtx {
    pub session_id: String,
    /// `session_meta.parent_thread_id` of a subagent rollout.
    pub parent_thread_id: Option<String>,
    pub cwd: String,
    pub created_at_ms: i64,
    pub turn_id: Option<String>,
    /// File name without extension, for `tool_use_id`.
    pub file_stem: String,
    /// 1-based line number in the rollout file.
    pub line: usize,
}

/// Results kept from one Codex `webrun` response.
const CODEX_MAX_RESULTS: usize = 20;
/// Script wrapper text that precedes the payload in a `custom_tool_call_output`.
const CODEX_SCRIPT_PREFIX: &str = "Script completed";

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
    agent: Agent,
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
        if text_of(payload.get("tool_name")) == Some("webrun") {
            return codex_hook(payload, now_ms, redact_terms);
        }
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
                agent: if is_codex_payload(payload) {
                    Agent::Codex
                } else {
                    Agent::Claude
                },
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
                agent: Agent::Claude,
                input: tool_use.get("input").unwrap_or(&null),
                response,
                duration_ms: duration_of(response),
                fallback_text: result_text(tool_result.get("content")),
                is_error,
            },
            redact_terms,
        ))
    }

    /// The `event.source` column value: Codex records are stored as `hook` / `import`
    /// (the schema allows only those two).
    pub fn db_source(&self) -> &str {
        match self.source.as_str() {
            "codex-hook" => "hook",
            "codex-rollout" => "import",
            other => other,
        }
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
                // A Codex rollout keeps the query but never the results.
                let resultless_ok = self.source == "codex-rollout";
                if summary.contains(PLACEHOLDER_TEXT) || (self.results.is_empty() && !resultless_ok)
                {
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

/// A hook payload from Codex: tool `webrun`, or a key Claude Code never sends (`turn_id`).
fn is_codex_payload(payload: &Value) -> bool {
    text_of(payload.get("tool_name")) == Some("webrun") || payload.get("turn_id").is_some()
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

/// Redacts `url`; when the result no longer parses, drops the query and
/// fragment and tries again. `None` when it still does not parse.
pub fn redact_url(url: &str, terms: &[String]) -> Option<(String, String)> {
    let redacted = red(url.trim(), terms);
    if let Some(norm) = norm_url(&redacted) {
        return Some((redacted, norm));
    }
    let cut = redacted.find(['?', '#']).map_or(redacted.len(), |i| i);
    let bare = &redacted[..cut];
    norm_url(bare).map(|norm| (bare.to_string(), norm))
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
        agent: p.agent,
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
                            let Some((url, url_norm)) = redact_url(url, terms) else {
                                continue;
                            };
                            rec.results.push(ResultRow {
                                rank: i64::try_from(rec.results.len()).unwrap_or(i64::MAX) + 1,
                                url,
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
            let (url, url_norm) = redact_url(&url, terms)?;
            rec.url_norm = Some(url_norm);
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

/// The `q` values of a Codex `tool_input.search_query`, joined by `" | "`.
pub fn codex_query(input: &Value) -> Option<String> {
    let qs: Vec<&str> = input
        .get("search_query")?
        .as_array()?
        .iter()
        .filter_map(|i| i.get("q").and_then(Value::as_str))
        .map(str::trim)
        .filter(|q| !q.is_empty())
        .collect();
    (!qs.is_empty()).then(|| qs.join(" | "))
}

fn codex_base(
    tool: Tool,
    tool_use_id: String,
    session_id: &str,
    cwd: &str,
    created_at: i64,
    source: &str,
) -> Record {
    Record {
        tool_use_id,
        tool,
        session_id: session_id.to_string(),
        agent_id: None,
        agent_type: None,
        cwd_hash: sha256_hex(cwd),
        created_at,
        query: None,
        url: None,
        url_norm: None,
        fetch_prompt: None,
        http_code: None,
        bytes: None,
        duration_ms: None,
        status: Status::Ok,
        summary: None,
        match_text: String::new(),
        source: source.to_string(),
        agent: Agent::Codex,
        results: Vec::new(),
        quarantine_reason: None,
    }
}

/// Redacts and stores `summary`/`results`, then classifies and builds `match_text`.
fn codex_finish(mut rec: Record, text: &CodexText, terms: &[String]) -> Record {
    for (url, title) in &text.results {
        if rec.results.len() >= CODEX_MAX_RESULTS {
            break;
        }
        let Some((url, url_norm)) = redact_url(url, terms) else {
            continue;
        };
        rec.results.push(ResultRow {
            rank: i64::try_from(rec.results.len()).unwrap_or(i64::MAX) + 1,
            url,
            url_norm,
            title: title.as_deref().map(|t| red(t, terms)),
        });
    }
    rec.summary = (!text.summary.is_empty()).then(|| {
        red(&text.summary, terms)
            .chars()
            .take(SUMMARY_CAP)
            .collect()
    });
    rec.status = rec.classify();
    rec.match_text = rec.match_text();
    rec
}

fn codex_hook(payload: &Value, now_ms: i64, terms: &[String]) -> anyhow::Result<Option<Record>> {
    let Some(tool_use_id) = text_of(payload.get("tool_use_id")).filter(|s| !s.is_empty()) else {
        bail!("payload has no tool_use_id");
    };
    let Some(query) = payload.get("tool_input").and_then(codex_query) else {
        return Ok(None);
    };
    let mut rec = codex_base(
        Tool::WebSearch,
        tool_use_id.to_string(),
        text_of(payload.get("session_id")).unwrap_or(""),
        text_of(payload.get("cwd")).unwrap_or(""),
        now_ms,
        "codex-hook",
    );
    // No Codex payload seen so far names a subagent; honour the Claude Code keys if they appear.
    rec.agent_id = owned(payload.get("agent_id"));
    rec.agent_type = owned(payload.get("agent_type"));
    rec.query = Some(red(&query, terms));
    rec.duration_ms = whole_number(payload.get("duration_ms"));
    let blocks = payload
        .get("tool_response")
        .map(|r| codex_blocks(r, false))
        .unwrap_or_default();
    Ok(Some(codex_finish(rec, &parse_codex_text(&blocks), terms)))
}

/// Text blocks of a Codex tool response: a list of `{type, text}` items (or one string).
/// With `unwrap`, blocks that are a JSON string literal (the `JSON.stringify` output of an
/// `exec` script) are decoded and the script wrapper block is dropped.
fn codex_blocks(response: &Value, unwrap: bool) -> Vec<String> {
    let raw: Vec<&str> = match response {
        Value::String(s) => vec![s.as_str()],
        Value::Array(items) => items
            .iter()
            .filter_map(|i| i.get("text").and_then(Value::as_str))
            .collect(),
        _ => Vec::new(),
    };
    raw.into_iter()
        .filter(|t| !(unwrap && t.starts_with(CODEX_SCRIPT_PREFIX)))
        .map(|t| {
            let trimmed = t.trim();
            if unwrap && trimmed.starts_with('"') {
                if let Ok(Value::String(s)) = serde_json::from_str::<Value>(trimmed) {
                    return s;
                }
            }
            t.to_string()
        })
        .collect()
}

/// What [`parse_codex_text`] finds.
struct CodexText {
    /// (url, title) in order, deduplicated, at most [`CODEX_MAX_RESULTS`].
    results: Vec<(String, Option<String>)>,
    summary: String,
}

/// Parsing rules for `webrun` result text:
/// - `summary` is the blocks joined by `\n`.
/// - Every `https://` URL, in order, is a result (deduplicated by exact text, at most 20). A URL
///   ends at whitespace or one of `)]>"'<` and loses trailing `.,;:`.
/// - The title is the text before ` (URL)` when a line ends with that form; when the line is only
///   the URL (or `(URL)`), the previous line if it is non-empty, a separator (`---`) is not,
///   and it holds no URL; otherwise no title.
fn parse_codex_text(blocks: &[String]) -> CodexText {
    let summary = blocks.join("\n");
    let mut results: Vec<(String, Option<String>)> = Vec::new();
    let mut prev: Option<&str> = None;
    for line in summary.lines() {
        let trimmed = line.trim();
        for (start, url) in urls_in(trimmed) {
            if results.len() >= CODEX_MAX_RESULTS {
                break;
            }
            if results.iter().any(|(u, _)| *u == url) {
                continue;
            }
            let end = start + url.len();
            let before = trimmed[..start].trim_end();
            let after = trimmed[end..].trim();
            let title = if let (true, Some(t)) = (after == ")", before.strip_suffix('(')) {
                Some(t.trim_end())
            } else if before.is_empty() || before == "(" {
                prev.filter(|p| !p.is_empty() && !p.starts_with("---") && !p.contains("https://"))
            } else {
                None
            };
            results.push((url, title.filter(|t| !t.is_empty()).map(str::to_string)));
        }
        prev = Some(trimmed);
    }
    CodexText { results, summary }
}

/// `(byte offset, url)` of every `https://` URL in `line`.
fn urls_in(line: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = line[from..].find("https://") {
        let start = from + i;
        let rest = &line[start..];
        let len = rest
            .find(|c: char| c.is_whitespace() || ")]>\"'<".contains(c))
            .unwrap_or(rest.len());
        let url = rest[..len].trim_end_matches(['.', ',', ';', ':']);
        if url.len() > "https://".len() {
            out.push((start, url.to_string()));
        }
        from = start + len.max(1);
    }
    out
}

/// Builds a record from one Codex rollout line (`{timestamp, type, payload}`), or `None`.
/// Handles `web_search_call` (`search`, `open_page`, `find_in_page`); a `web__run`
/// `custom_tool_call` needs its output: use [`from_codex_rollout_pair`].
pub fn from_codex_rollout(record: &Value, ctx: &CodexCtx) -> Option<Record> {
    from_codex_rollout_with(record, ctx, &[])
}

/// As [`from_codex_rollout`], with the redaction terms of the configuration.
pub fn from_codex_rollout_with(record: &Value, ctx: &CodexCtx, terms: &[String]) -> Option<Record> {
    let payload = record.get("payload")?;
    if text_of(payload.get("type")) != Some("web_search_call") {
        return None;
    }
    let action = payload.get("action")?;
    let (session, agent_id, agent_type) = codex_identity(ctx);
    let mut rec = match text_of(action.get("type"))? {
        "search" => {
            let query = owned(action.get("query")).or_else(|| {
                let qs: Vec<&str> = action
                    .get("queries")?
                    .as_array()?
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|q| !q.is_empty())
                    .collect();
                (!qs.is_empty()).then(|| qs.join(" | "))
            })?;
            let mut rec = codex_base(
                Tool::WebSearch,
                codex_id(ctx),
                &session,
                &ctx.cwd,
                ctx.created_at_ms,
                "codex-rollout",
            );
            rec.query = Some(red(&query, terms));
            rec
        }
        kind @ ("open_page" | "find_in_page") => {
            let (url, url_norm) = redact_url(text_of(action.get("url"))?, terms)?;
            let mut rec = codex_base(
                Tool::WebFetch,
                codex_id(ctx),
                &session,
                &ctx.cwd,
                ctx.created_at_ms,
                "codex-rollout",
            );
            rec.url = Some(url);
            rec.url_norm = Some(url_norm);
            if kind == "find_in_page" {
                rec.fetch_prompt = owned(action.get("pattern")).map(|p| red(&p, terms));
            }
            rec
        }
        _ => return None,
    };
    rec.agent_id = agent_id;
    rec.agent_type = agent_type;
    rec.status = rec.classify();
    rec.match_text = rec.match_text();
    Some(rec)
}

/// A `web__run` `custom_tool_call` and its `custom_tool_call_output` (same `call_id`):
/// a WebSearch with parsed results and summary, like the hook path. `line` of `ctx` is the
/// line of the call. `None` when the call is not a `web__run` search or the ids differ.
pub fn from_codex_rollout_pair(
    call: &Value,
    output: &Value,
    ctx: &CodexCtx,
    terms: &[String],
) -> Option<Record> {
    let call = call.get("payload")?;
    let output = output.get("payload")?;
    if text_of(call.get("type")) != Some("custom_tool_call")
        || text_of(output.get("type")) != Some("custom_tool_call_output")
    {
        return None;
    }
    let id = text_of(call.get("call_id")).filter(|s| !s.is_empty())?;
    if text_of(output.get("call_id")) != Some(id) {
        return None;
    }
    let input = text_of(call.get("input"))?;
    if !input.contains("web__run") {
        return None;
    }
    let query = script_queries(input)?;
    let (session, agent_id, agent_type) = codex_identity(ctx);
    let mut rec = codex_base(
        Tool::WebSearch,
        codex_id(ctx),
        &session,
        &ctx.cwd,
        ctx.created_at_ms,
        "codex-rollout",
    );
    rec.agent_id = agent_id;
    rec.agent_type = agent_type;
    rec.query = Some(red(&query, terms));
    let blocks = codex_blocks(output.get("output")?, true);
    Some(codex_finish(rec, &parse_codex_text(&blocks), terms))
}

fn codex_id(ctx: &CodexCtx) -> String {
    format!("codex:{}:{}", ctx.file_stem, ctx.line)
}

/// A subagent rollout joins its parent's session and is its own agent.
fn codex_identity(ctx: &CodexCtx) -> (String, Option<String>, Option<String>) {
    match &ctx.parent_thread_id {
        Some(parent) if !parent.is_empty() => (
            parent.clone(),
            Some(ctx.session_id.clone()),
            Some("subagent".to_string()),
        ),
        _ => (ctx.session_id.clone(), None, None),
    }
}

/// The `q:"..."` string literals of a `tools.web__run({search_query:[...]})` script, joined by `" | "`.
fn script_queries(script: &str) -> Option<String> {
    let mut qs: Vec<String> = Vec::new();
    let bytes = script.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // a key `q` (bare or quoted) that is not the tail of a longer name
        let key_at = |j: usize| -> Option<usize> {
            let prev_ok = j == 0 || !(bytes[j - 1].is_ascii_alphanumeric() || bytes[j - 1] == b'_');
            if !prev_ok || bytes.get(j) != Some(&b'q') {
                return None;
            }
            let mut k = j + 1;
            if bytes.get(k) == Some(&b'"') {
                k += 1;
            } else if bytes
                .get(k)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
            {
                return None;
            }
            while bytes.get(k).is_some_and(u8::is_ascii_whitespace) {
                k += 1;
            }
            if bytes.get(k) != Some(&b':') {
                return None;
            }
            k += 1;
            while bytes.get(k).is_some_and(u8::is_ascii_whitespace) {
                k += 1;
            }
            (bytes.get(k) == Some(&b'"')).then_some(k)
        };
        if let Some(open) = key_at(i) {
            let mut end = open + 1;
            while end < bytes.len() && bytes[end] != b'"' {
                end += if bytes[end] == b'\\' { 2 } else { 1 };
            }
            if let Some(Ok(Value::String(q))) =
                script.get(open..=end).map(serde_json::from_str::<Value>)
            {
                if !q.trim().is_empty() {
                    qs.push(q.trim().to_string());
                }
            }
            i = end + 1;
        } else {
            i += 1;
        }
    }
    (!qs.is_empty()).then(|| qs.join(" | "))
}
