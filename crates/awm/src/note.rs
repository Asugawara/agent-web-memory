//! Shared note types (plan-v2 §4.1.1): capture, matching, hooks and review all use these.

use serde::{Deserialize, Serialize};

/// `event.tool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tool {
    WebSearch,
    WebFetch,
}

/// `event.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    DeadEnd,
    Refusal,
    Placeholder,
}

/// `injection.channel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Url,
    Query,
    PromptUrl,
    PromptBm25,
}

/// Where a note came from, relative to the caller (computed by matching).
#[derive(Debug, Clone, PartialEq)]
pub enum Relation {
    /// Same session, made by another subagent.
    OtherSubagent { agent_type: String },
    /// Same session, made by the main agent.
    MainAgent,
    /// Other session, same `cwd_hash`.
    SameProject,
    /// Other session, other `cwd_hash`.
    OtherProject,
}

/// One matched record, built by `matching::to_note`.
#[derive(Debug, Clone, PartialEq)]
pub struct Note {
    pub event_id: i64,
    pub tool: Tool,
    pub created_at_ms: i64,
    pub relation: Relation,
    /// Records in its group (§3.1 rule 4), at least 1.
    pub seen: u32,
    /// WebFetch: `event.url`; WebSearch: first result URL passing `sanitize::url_ok`.
    pub url: Option<String>,
    /// WebFetch: `event.fetch_prompt`.
    pub asked: Option<String>,
    /// WebSearch: `event.query`.
    pub searched: Option<String>,
    pub status: Status,
    pub http_code: Option<u16>,
    /// `event.summary` as stored: redacted, not yet sanitised.
    pub summary: Option<String>,
    /// Negated bm25; 1.0 for url matches.
    pub score: f64,
}

/// Everything `render` needs besides the notes.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderCtx {
    pub channel: Channel,
    pub now_ms: i64,
    /// Local offset used for the printed date.
    pub utc_offset_min: i32,
    /// 8 lowercase hex characters.
    pub ref_id: String,
    /// `inject.max_notes`, 1 to 3.
    pub max_notes: usize,
}

/// A rendered block and the event ids it shows, in order.
#[derive(Debug, Clone, PartialEq)]
pub struct Rendered {
    pub text: String,
    pub chars: usize,
    pub event_ids: Vec<i64>,
}

impl Tool {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Tool::WebSearch => "WebSearch",
            Tool::WebFetch => "WebFetch",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Tool> {
        match s {
            "WebSearch" => Some(Tool::WebSearch),
            "WebFetch" => Some(Tool::WebFetch),
            _ => None,
        }
    }
}

impl Status {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::DeadEnd => "dead_end",
            Status::Refusal => "refusal",
            Status::Placeholder => "placeholder",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Status> {
        match s {
            "ok" => Some(Status::Ok),
            "dead_end" => Some(Status::DeadEnd),
            "refusal" => Some(Status::Refusal),
            "placeholder" => Some(Status::Placeholder),
            _ => None,
        }
    }
}

impl Channel {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Channel::Url => "url",
            Channel::Query => "query",
            Channel::PromptUrl => "prompt_url",
            Channel::PromptBm25 => "prompt_bm25",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Channel> {
        match s {
            "url" => Some(Channel::Url),
            "query" => Some(Channel::Query),
            "prompt_url" => Some(Channel::PromptUrl),
            "prompt_bm25" => Some(Channel::PromptBm25),
            _ => None,
        }
    }
}
