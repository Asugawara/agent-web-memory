//! The pre-push check (plan-v3-team §3.4, §4.5; TM5): may this local record leave the machine,
//! and in which form. Pure: it reads the record, the configuration and the effective team
//! policy, and returns a verdict plus, when the record may be shared, a cleaned copy.
//!
//! The engine (TM10) selects rows with `origin = 'local' AND shareable = 'no' AND sync_id IS
//! NULL` (not pushed yet; `'never'` is a record the user unshared, RVT1 M4) and calls [`check`],
//! then [`crate::sync::payload::build`] on the cleaned copy.

use std::collections::BTreeMap;

use url::Url;

use crate::config::Config;
use crate::hosts;
use crate::note::{Status, Tool};
use crate::record::{Record, ResultRow};
use crate::redact;
use crate::sanitize;
use crate::sync::payload::{
    Share, MAX_RESULTS, MAX_RESULT_URL_CHARS, MAX_TITLE_CHARS, MAX_URL_CHARS,
};

/// Redaction kinds that block a record when the current patterns find a new one (§4.5).
pub const SECRET_KINDS: [&str; 7] = [
    "pem",
    "jwt",
    "aws-key",
    "gcp-key",
    "github-token",
    "slack-token",
    "secret-assignment",
];

/// URL query parameter names (compared in lower case) that make a URL unshareable (§4.5; an
/// assumption, extended by the policy's `credential_params`).
pub const CREDENTIAL_PARAMS: [&str; 15] = [
    "token",
    "key",
    "api_key",
    "access_token",
    "sig",
    "signature",
    "secret",
    "password",
    "passwd",
    "auth",
    "session",
    "code",
    "state",
    "x-amz-signature",
    "x-goog-signature",
];

/// Built-in link-only host globs (§3.4 item 3): Google Docs and Drive, Notion, Atlassian, Slack.
/// `hosts.rs` is not owned by TM5, so the list lives here; the policy's `link_hosts` extend it.
pub const BUILTIN_LINK_HOSTS: [&str; 10] = [
    "docs.google.com",
    "drive.google.com",
    "notion.so",
    "*.notion.so",
    "*.notion.site",
    "*.atlassian.net",
    "*.atlassian.com",
    "atlassian.com",
    "slack.com",
    "*.slack.com",
];

/// `share_rule.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// `value` is a `repo_key`.
    Repo,
    /// `value` is a `cwd_hash`.
    Cwd,
}

/// One `share_rule` row. `created_at` is in the unit of `event.created_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareRule {
    pub kind: RuleKind,
    pub value: String,
    pub created_at: i64,
}

/// One `project` row: the repository a working directory belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub cwd_hash: String,
    pub repo_key: Option<String>,
}

/// The local opt-in state (§3.4 items 1 and 2), loaded from `share_rule` and `project`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OptIn {
    pub rules: Vec<ShareRule>,
    pub projects: Vec<Project>,
    /// Rule values (`repo_key` or `cwd_hash`) that a backfill run named: their records count
    /// whatever their age.
    pub backfill: Vec<String>,
    /// With `team.share_all_projects`, records from this time on (the unit of
    /// `event.created_at`) are opted in. The engine reads it from `sync_state` key
    /// `share_all_since`, written when the switch is turned on; without it nothing is opted in
    /// through the switch, so turning it on never shares earlier history (RVT1 m14).
    pub share_all_since: Option<i64>,
}

/// The effective team rules of this device: the admin policy (`plaintext.policy`, sync-v1 §15.4)
/// and the local opt-in. Fields are plain data so the check stays pure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TeamPolicy {
    pub deny_hosts: Vec<String>,
    pub link_hosts: Vec<String>,
    pub terms: Vec<String>,
    pub credential_params: Vec<String>,
    pub summary_chars: Option<u32>,
    /// Share only `dead_end` records (the brief names a policy that can ask for it; the v1
    /// policy plaintext has no such field, so the engine sets it `false` today).
    pub dead_end_only: bool,
    pub opt_in: OptIn,
}

#[cfg(feature = "sync")]
impl TeamPolicy {
    /// The policy part from a decoded `policy` record; the opt-in stays empty.
    pub fn from_wire(p: &awm_proto::wire::PolicyPlaintext) -> TeamPolicy {
        TeamPolicy {
            deny_hosts: p.deny_hosts.clone(),
            link_hosts: p.link_hosts.clone(),
            terms: p.terms.clone(),
            credential_params: p.credential_params.clone(),
            summary_chars: p.summary_chars,
            ..TeamPolicy::default()
        }
    }
}

/// `capture.redact_terms` and the policy's terms.
pub fn terms(cfg: &Config, policy: &TeamPolicy) -> Vec<String> {
    let mut t = cfg.capture.redact_terms.clone();
    t.extend(policy.terms.iter().cloned());
    t
}

/// A field edit made in the shared copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    /// `query`, `fetch_prompt`, `summary`, `title` or `result`.
    pub field: &'static str,
    /// A redaction kind (`email`, `ipv4`, `home-path`, `temp-path`, `term`), or `dropped`
    /// for a result row that was removed.
    pub kind: String,
}

/// A record that may be shared.
#[derive(Debug, Clone, PartialEq)]
pub struct Cleared {
    pub share: Share,
    /// The shared copy: personal kinds replaced, unshareable result rows removed. It still
    /// carries local-only fields; `payload::build` keeps the shared ones.
    pub record: Record,
    pub edits: Vec<Edit>,
    /// `redact::VERSION` of the patterns used.
    pub redact_version: u32,
}

/// Why a record is not shared and counts against the sender (`awm team status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    /// A new match of a secret kind in a shared text field.
    Secret { kinds: Vec<String> },
    /// User-info, a credential parameter or a redaction match in a shared URL.
    CredentialUrl,
}

impl BlockReason {
    /// The counter name of §4.5.
    pub fn counter(&self) -> &'static str {
        match self {
            BlockReason::Secret { .. } => "secret",
            BlockReason::CredentialUrl => "credential_url",
        }
    }
}

/// Why a record is not shared by rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    Placeholder,
    /// Stored as quarantined, or the sanitiser quarantines it now.
    Quarantined(String),
    /// The policy shares dead ends only.
    PolicyStatus,
    /// No `share_rule` (or `team.share_all_projects`) covers it, or it predates the rule.
    NotOptedIn,
    /// `hosts::is_private` (a URL of the record).
    PrivateHost,
    /// `team.exclude_hosts` or `capture.exclude_hosts`.
    ExcludedHost,
    /// The policy's `deny_hosts`.
    DeniedHost,
    /// The URL does not parse.
    BadUrl,
    /// A fetch URL above 2,048 characters is not shared, so the record has no key.
    UrlTooLong,
    /// A redaction term (config or policy) occurs in a URL; replacing it would break the URL.
    TermInUrl,
}

impl SkipReason {
    pub fn counter(&self) -> &'static str {
        match self {
            SkipReason::Placeholder => "placeholder",
            SkipReason::Quarantined(_) => "quarantined",
            SkipReason::PolicyStatus => "policy_status",
            SkipReason::NotOptedIn => "not_opted_in",
            SkipReason::PrivateHost => "private_host",
            SkipReason::ExcludedHost => "excluded_host",
            SkipReason::DeniedHost => "denied_host",
            SkipReason::BadUrl => "bad_url",
            SkipReason::UrlTooLong => "url_too_long",
            SkipReason::TermInUrl => "term_in_url",
        }
    }
}

/// The verdict of [`check`].
#[derive(Debug, Clone, PartialEq)]
pub enum Eligibility {
    /// Shared as stored.
    Share(Cleared),
    /// Shared after edits (`Cleared::edits` is not empty).
    Replaced(Cleared),
    /// Not shared: a secret or a credential URL.
    Blocked(BlockReason),
    /// Not shared by rule.
    Skipped(SkipReason),
}

impl Eligibility {
    /// The cleared copy when the record is shared.
    pub fn cleared(&self) -> Option<&Cleared> {
        match self {
            Eligibility::Share(c) | Eligibility::Replaced(c) => Some(c),
            _ => None,
        }
    }
}

/// Result of re-redacting one text.
pub(crate) struct Scrubbed {
    pub text: String,
    /// Secret kinds the current patterns found that the stored text did not show.
    pub secrets: Vec<String>,
    /// Personal kinds that were replaced.
    pub replaced: Vec<String>,
}

fn marker_counts(text: &str) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    let mut rest = text;
    while let Some(i) = rest.find("[redacted:") {
        rest = &rest[i + "[redacted:".len()..];
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .unwrap_or(rest.len());
        if rest[end..].starts_with(']') && end > 0 {
            *out.entry(rest[..end].to_string()).or_insert(0) += 1;
        }
    }
    out
}

/// Re-redacts `text` with the current patterns and `terms`. A kind counts as new when its
/// marker occurs more often afterwards than before, so text already redacted by an earlier
/// run is not reported.
pub(crate) fn scrub(text: &str, terms: &[String]) -> Scrubbed {
    let (out, n) = redact::redact(text, terms);
    if n == 0 {
        return Scrubbed {
            text: out,
            secrets: Vec::new(),
            replaced: Vec::new(),
        };
    }
    let before = marker_counts(text);
    let after = marker_counts(&out);
    let (mut secrets, mut replaced) = (Vec::new(), Vec::new());
    for (kind, count) in after {
        if count > before.get(&kind).copied().unwrap_or(0) {
            if SECRET_KINDS.contains(&kind.as_str()) {
                secrets.push(kind);
            } else {
                replaced.push(kind);
            }
        }
    }
    Scrubbed {
        text: out,
        secrets,
        replaced,
    }
}

/// True when `url` must not be shared (§4.5): it does not parse, carries user-info, a query or
/// fragment parameter named like a credential (case-insensitive, `extra` adds names), an earlier
/// redaction marker, or matches any redaction pattern.
pub fn credential_url(url: &str, extra: &[String]) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return true;
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return true;
    }
    let named = |name: &str| {
        let name = name.to_lowercase();
        CREDENTIAL_PARAMS.contains(&name.as_str()) || extra.iter().any(|e| e.to_lowercase() == name)
    };
    if parsed.query_pairs().any(|(k, _)| named(&k)) {
        return true;
    }
    // `#access_token=...` (OAuth implicit grant) is a parameter list in the fragment.
    if let Some(frag) = parsed.fragment() {
        if url::form_urlencoded::parse(frag.as_bytes()).any(|(k, _)| named(&k)) {
            return true;
        }
    }
    url.contains("[redacted:") || redact::redact(url, &[]).1 > 0
}

fn host_of(url: &str) -> Option<(Url, String)> {
    let u = Url::parse(url.trim()).ok()?;
    let host = u.host_str()?.trim_matches(['[', ']']).to_lowercase();
    Some((u, host))
}

fn opted_in(rec: &Record, cfg: &Config, opt: &OptIn) -> bool {
    if cfg.team.share_all_projects && opt.share_all_since.is_some_and(|t| rec.created_at >= t) {
        return true;
    }
    let repo = opt
        .projects
        .iter()
        .find(|p| p.cwd_hash == rec.cwd_hash)
        .and_then(|p| p.repo_key.as_deref());
    opt.rules.iter().any(|r| {
        let hit = match r.kind {
            RuleKind::Repo => repo == Some(r.value.as_str()),
            RuleKind::Cwd => rec.cwd_hash == r.value,
        };
        hit && (rec.created_at >= r.created_at || opt.backfill.contains(&r.value))
    })
}

/// Decides whether `rec` may be pushed, and in which form. Rows of §4.5, in this order:
///
/// 1. `placeholder` status, a stored or fresh quarantine, a policy that shares dead ends only:
///    `Skipped`.
/// 2. No opt-in (`share_rule` through `project`, or `team.share_all_projects`) or a record older
///    than its rule without a backfill naming it: `Skipped(NotOptedIn)`.
/// 3. Any URL of the record (the fetch URL, a result URL) on a private host, in
///    `team.exclude_hosts` or `capture.exclude_hosts`, or in the policy's `deny_hosts`:
///    `Skipped`. A fetch URL that does not parse or is above 2,048 characters: `Skipped`.
/// 4. The fetch URL fails the credential check: `Blocked(CredentialUrl)`. A result row that
///    fails it (or does not parse, or has a URL above 512 characters) is dropped from the
///    shared copy instead, and the edit says so.
/// 5. A host in the link list (built-in or the policy's) on the fetch URL or any result: the
///    record shares as `link` (URL, titles, status and hour only); otherwise `full`.
/// 6. Re-redaction of every shared text field with the current patterns and the terms: a new
///    secret kind: `Blocked(Secret)`; personal kinds are replaced and the verdict is `Replaced`.
pub fn check(rec: &Record, cfg: &Config, policy: &TeamPolicy) -> Eligibility {
    if rec.status == Status::Placeholder {
        return Eligibility::Skipped(SkipReason::Placeholder);
    }
    let reason = rec.quarantine_reason.clone().or_else(|| {
        sanitize::record_quarantine_reason(
            rec.summary.as_deref(),
            rec.fetch_prompt.as_deref(),
            rec.query.as_deref(),
        )
    });
    if let Some(reason) = reason {
        return Eligibility::Skipped(SkipReason::Quarantined(reason));
    }
    if policy.dead_end_only && rec.status != Status::DeadEnd {
        return Eligibility::Skipped(SkipReason::PolicyStatus);
    }
    if !opted_in(rec, cfg, &policy.opt_in) {
        return Eligibility::Skipped(SkipReason::NotOptedIn);
    }

    let excluded: Vec<String> = cfg
        .team
        .exclude_hosts
        .iter()
        .chain(&cfg.capture.exclude_hosts)
        .cloned()
        .collect();
    let mut link = false;
    let mut edits = Vec::new();
    let all_terms = terms(cfg, policy);

    // The record's own URL, then its result rows.
    if let Some(url) = rec.url.as_deref() {
        if url.chars().count() > MAX_URL_CHARS {
            return Eligibility::Skipped(SkipReason::UrlTooLong);
        }
        match judge_host(url, &excluded, policy) {
            Ok(is_link) => link |= is_link,
            Err(skip) => return Eligibility::Skipped(skip),
        }
        if credential_url(url, &policy.credential_params) {
            return Eligibility::Blocked(BlockReason::CredentialUrl);
        }
        if scrub(url, &all_terms).replaced.iter().any(|k| k == "term") {
            return Eligibility::Skipped(SkipReason::TermInUrl);
        }
    } else if rec.tool == Tool::WebFetch {
        return Eligibility::Skipped(SkipReason::BadUrl);
    }
    let mut rows: Vec<ResultRow> = Vec::new();
    for row in rec.results.iter().take(MAX_RESULTS) {
        match judge_host(&row.url, &excluded, policy) {
            Ok(is_link) => link |= is_link,
            // A result URL that does not parse is dropped below, not a reason to skip.
            Err(SkipReason::BadUrl) => {}
            Err(skip) => return Eligibility::Skipped(skip),
        }
        if row.url.chars().count() > MAX_RESULT_URL_CHARS
            || credential_url(&row.url, &policy.credential_params)
            || scrub(&row.url, &all_terms)
                .replaced
                .iter()
                .any(|k| k == "term")
        {
            edits.push(Edit {
                field: "result",
                kind: "dropped".to_string(),
            });
            continue;
        }
        rows.push(row.clone());
    }

    let share = if link { Share::Link } else { Share::Full };
    let mut out = rec.clone();
    out.results = rows;
    let mut secrets: Vec<String> = Vec::new();
    let mut take = |field: &'static str, s: Scrubbed, edits: &mut Vec<Edit>| -> String {
        for k in s.secrets {
            if !secrets.contains(&k) {
                secrets.push(k);
            }
        }
        for k in s.replaced {
            edits.push(Edit { field, kind: k });
        }
        s.text
    };
    for row in &mut out.results {
        if let Some(t) = row.title.take() {
            // Re-redact the whole title before cutting it, so a secret straddling the cut is
            // still found (RVT1 m1).
            let t = take("title", scrub(&t, &all_terms), &mut edits);
            row.title = Some(t.chars().take(MAX_TITLE_CHARS).collect());
        }
    }
    if share == Share::Full {
        if let Some(q) = out.query.take() {
            out.query = Some(take("query", scrub(&q, &all_terms), &mut edits));
        }
        if let Some(p) = out.fetch_prompt.take() {
            out.fetch_prompt = Some(take("fetch_prompt", scrub(&p, &all_terms), &mut edits));
        }
        if let Some(s) = out.summary.take() {
            out.summary = Some(take("summary", scrub(&s, &all_terms), &mut edits));
        }
    }
    if !secrets.is_empty() {
        secrets.sort();
        return Eligibility::Blocked(BlockReason::Secret { kinds: secrets });
    }
    let cleared = Cleared {
        share,
        record: out,
        edits,
        redact_version: redact::VERSION,
    };
    if cleared.edits.is_empty() {
        Eligibility::Share(cleared)
    } else {
        Eligibility::Replaced(cleared)
    }
}

/// The host rules for one URL: `Ok(true)` for a link-only host, `Ok(false)` for a plain one.
fn judge_host(url: &str, excluded: &[String], policy: &TeamPolicy) -> Result<bool, SkipReason> {
    let Some((parsed, host)) = host_of(url) else {
        return Err(SkipReason::BadUrl);
    };
    if hosts::is_private(&parsed, &[]) {
        return Err(SkipReason::PrivateHost);
    }
    if excluded.iter().any(|g| hosts::host_matches(&host, g)) {
        return Err(SkipReason::ExcludedHost);
    }
    if policy
        .deny_hosts
        .iter()
        .any(|g| hosts::host_matches(&host, g))
    {
        return Err(SkipReason::DeniedHost);
    }
    Ok(BUILTIN_LINK_HOSTS
        .iter()
        .map(|g| g.to_string())
        .chain(policy.link_hosts.iter().cloned())
        .any(|g| hosts::host_matches(&host, &g)))
}
