//! The record plaintext built from a local row (plan-v3-team §3.2, §4.5; sync-v1 §15.1; TM5).
//!
//! [`build`] is a pure function: it keeps the shared fields only, applies the §3.2 caps, rounds
//! `created_at` down to the hour and serialises to the `rec` plaintext of `docs/sync-v1.md` §15.1.
//! The types below mirror `awm_proto::wire::RecPlaintext` field for field (same names, same
//! order, same serde attributes) so that the default build, which does not link `awm-proto`,
//! can produce and test the bytes; a test under the `sync` feature decodes them with
//! `awm_proto::wire::decode_plaintext::<RecPlaintext>` and compares.
//!
//! Nothing here reads a database or the clock. [`crate::sync::eligible::check`] decides whether a
//! record may leave at all and hands over a cleaned copy; `build` re-applies the per-field
//! checks (credential URLs, secret shapes) so that a caller who skips `check` still cannot
//! leak a never-shared field.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::note::{Status, Tool};
use crate::record::{Agent as RecordAgent, Record};
use crate::sync::eligible::{self, TeamPolicy};

/// `schema` this build writes (`awm_proto::wire::PLAINTEXT_SCHEMA`).
pub const SCHEMA: u32 = 1;
/// `query` and `fetch_prompt`: characters.
pub const MAX_QUERY_CHARS: usize = 500;
/// `url`: characters; a longer URL is not shared.
pub const MAX_URL_CHARS: usize = 2_048;
/// Result rows.
pub const MAX_RESULTS: usize = 10;
/// A result URL: characters; a longer URL drops its row.
pub const MAX_RESULT_URL_CHARS: usize = 512;
/// A result title: characters.
pub const MAX_TITLE_CHARS: usize = 120;
/// `team.summary_chars` can not be set above this (P §9.3).
pub const MAX_SUMMARY_CHARS: usize = 2_000;
/// The builder shortens the plaintext until it is at most this many bytes (plan-v3-team §3.2, 15 KiB).
pub const PLAINTEXT_BUDGET: usize = 15 * 1024;
/// The envelope's plaintext cap (`awm_proto::crypto::MAX_PLAINTEXT`): 16 KiB minus the envelope
/// overhead and one padding byte.
pub const MAX_PLAINTEXT: usize = 16_127;

/// `full`, or `link` (URL, titles, status and hour only) for link-only hosts (§3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Share {
    Full,
    Link,
}

/// The shared statuses (`placeholder` is never shared).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecStatus {
    Ok,
    DeadEnd,
    Refusal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Agent {
    Claude,
    Codex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Hook,
    Import,
}

/// One shared search result row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultItem {
    pub rank: u32,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// Tag `rec` (sync-v1 §15.1). Field order is the wire order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecPlaintext {
    pub schema: u32,
    pub tool: Tool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_code: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<i64>,
    pub status: RecStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub results: Vec<ResultItem>,
    pub agent: Agent,
    pub source: Source,
    /// Unix seconds, rounded down to the hour.
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_key: Option<String>,
    pub share: Share,
}

/// What `build` needs besides the record.
#[derive(Debug, Clone)]
pub struct ShareCtx {
    /// The level [`crate::sync::eligible::check`] chose.
    pub share: Share,
    /// `event.repo_key` (32 hex characters), or `None` outside a git repository. Sent for `full` only.
    pub repo_key: Option<String>,
    /// `team.summary_chars` (the policy's value wins when it is lower); clamped to 2,000.
    pub summary_chars: usize,
    /// `capture.redact_terms` and the policy's `terms`.
    pub terms: Vec<String>,
    /// Extra credential parameter names from the policy.
    pub credential_params: Vec<String>,
}

impl ShareCtx {
    /// The context for `share` from the local configuration and the effective policy.
    pub fn new(
        share: Share,
        repo_key: Option<String>,
        cfg: &Config,
        policy: &TeamPolicy,
    ) -> ShareCtx {
        let mut chars = cfg.team.summary_chars as usize;
        if let Some(p) = policy.summary_chars {
            chars = chars.min(p as usize);
        }
        ShareCtx {
            share,
            repo_key,
            summary_chars: chars.min(MAX_SUMMARY_CHARS),
            terms: eligible::terms(cfg, policy),
            credential_params: policy.credential_params.clone(),
        }
    }
}

/// What `build` did to fit the plaintext.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Trimmed {
    /// Result rows removed for size (from the end), beyond the 10-row cap and the per-row rules.
    pub results_dropped: usize,
    /// The summary was cut for size, below `summary_chars`.
    pub summary_shortened: bool,
}

/// A built payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// UTF-8 JSON, the plaintext to seal (before padding).
    pub plaintext: Vec<u8>,
    pub share: Share,
    /// `redact::VERSION` the fields were checked with. Not part of the wire plaintext (the
    /// schema is fixed and has no such field); the engine records it beside the outbox row.
    pub redact_version: u32,
    pub trimmed: Trimmed,
}

impl Payload {
    /// True when the plaintext fits one envelope (`MAX_PLAINTEXT`, 16,127 bytes). `build`
    /// returns only payloads that also fit the 15 KiB budget, so this holds for every value it
    /// returns; it is here for callers that rebuild or edit one.
    pub fn fits(&self) -> bool {
        self.plaintext.len() <= MAX_PLAINTEXT
    }
}

/// `at` milliseconds (the unit of `event.created_at`) as Unix seconds rounded down to the hour.
pub fn hour_floor_secs(created_at_ms: i64) -> i64 {
    created_at_ms.div_euclid(1000).div_euclid(3600) * 3600
}

fn cut_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn source_of(rec: &Record) -> Result<Source> {
    match rec.db_source() {
        "hook" => Ok(Source::Hook),
        "import" => Ok(Source::Import),
        other => bail!("source {other:?} is not shared"),
    }
}

/// Cleans one text field: replaces personal kinds, refuses secret kinds.
fn text_field(text: &str, terms: &[String], what: &str) -> Result<String> {
    let s = eligible::scrub(text, terms);
    if !s.secrets.is_empty() {
        bail!("{what} holds a secret shape ({})", s.secrets.join(", "));
    }
    Ok(s.text)
}

/// Builds the shared plaintext of `rec` at `ctx.share`.
///
/// Errors (nothing is built): a `placeholder` record, a fetch whose URL is missing, longer than
/// 2,048 characters or fails the credential check, a source other than `hook` or `import`, a
/// secret shape in a shared text field, or a plaintext that still exceeds the budget with no
/// results and no summary left to drop.
pub fn build(rec: &Record, ctx: &ShareCtx) -> Result<Payload> {
    let status = match rec.status {
        Status::Ok => RecStatus::Ok,
        Status::DeadEnd => RecStatus::DeadEnd,
        Status::Refusal => RecStatus::Refusal,
        Status::Placeholder => bail!("a placeholder record is never shared"),
    };
    let full = ctx.share == Share::Full;
    let url = match rec.url.as_deref() {
        Some(u) if u.chars().count() > MAX_URL_CHARS => None,
        Some(u) if eligible::credential_url(u, &ctx.credential_params) => None,
        Some(u) => Some(u.to_string()),
        None => None,
    };
    if rec.tool == Tool::WebFetch && url.is_none() {
        bail!(
            "a fetch needs a URL that is at most 2,048 characters and passes the credential check"
        );
    }

    let mut results = Vec::new();
    for row in rec.results.iter().take(MAX_RESULTS) {
        if row.url.chars().count() > MAX_RESULT_URL_CHARS
            || eligible::credential_url(&row.url, &ctx.credential_params)
        {
            continue;
        }
        let title = match row.title.as_deref() {
            Some(t) => Some(text_field(
                &cut_chars(t, MAX_TITLE_CHARS),
                &ctx.terms,
                "a result title",
            )?),
            None => None,
        };
        results.push(ResultItem {
            rank: u32::try_from(row.rank).unwrap_or(u32::MAX),
            url: row.url.clone(),
            title,
        });
    }

    let mut summary = None;
    let mut query = None;
    let mut fetch_prompt = None;
    if full {
        if let Some(q) = rec.query.as_deref() {
            query = Some(cut_chars(
                &text_field(q, &ctx.terms, "the query")?,
                MAX_QUERY_CHARS,
            ));
        }
        if let Some(p) = rec.fetch_prompt.as_deref() {
            fetch_prompt = Some(cut_chars(
                &text_field(p, &ctx.terms, "the fetch prompt")?,
                MAX_QUERY_CHARS,
            ));
        }
        if let Some(s) = rec.summary.as_deref() {
            // Scrub the whole stored text, then cut: a cut must not leave half a secret.
            summary = Some(cut_chars(
                &text_field(s, &ctx.terms, "the summary")?,
                ctx.summary_chars.min(MAX_SUMMARY_CHARS),
            ));
        }
    }
    let repo_key = ctx
        .repo_key
        .clone()
        .filter(|k| full && k.len() == 32 && k.bytes().all(|b| b.is_ascii_hexdigit()));

    let mut p = RecPlaintext {
        schema: SCHEMA,
        tool: rec.tool,
        query,
        url,
        fetch_prompt,
        http_code: if full { rec.http_code } else { None },
        bytes: if full { rec.bytes } else { None },
        duration_ms: if full { rec.duration_ms } else { None },
        status,
        summary,
        results,
        agent: match rec.agent {
            RecordAgent::Claude => Agent::Claude,
            RecordAgent::Codex => Agent::Codex,
        },
        source: source_of(rec)?,
        created_at: hour_floor_secs(rec.created_at),
        repo_key,
        share: ctx.share,
    };

    let mut trimmed = Trimmed::default();
    let mut bytes = serde_json::to_vec(&p)?;
    while bytes.len() > PLAINTEXT_BUDGET && !p.results.is_empty() {
        p.results.pop();
        trimmed.results_dropped += 1;
        bytes = serde_json::to_vec(&p)?;
    }
    while bytes.len() > PLAINTEXT_BUDGET {
        let Some(s) = p.summary.as_mut().filter(|s| !s.is_empty()) else {
            bail!(
                "the plaintext is {} bytes with nothing left to drop",
                bytes.len()
            );
        };
        let keep = s.chars().count() / 2;
        *s = cut_chars(s, keep);
        trimmed.summary_shortened = true;
        bytes = serde_json::to_vec(&p)?;
    }
    Ok(Payload {
        plaintext: bytes,
        share: ctx.share,
        redact_version: crate::redact::VERSION,
        trimmed,
    })
}
