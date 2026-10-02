//! Session start and totals read from Claude Code's transcripts (plan-quota §6).
//!
//! Per sampled session, at most one 64 KiB head and one 32 KiB tail of
//! `{projects}/*/{session id}.jsonl` are read. Nothing is parsed beyond the first
//! timestamp and the last `cost-state` line, and nothing is stored.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde_json::Value;
use time::format_description::well_known::Rfc3339;

/// The head in which the first timestamp is looked for, read in `HEAD_STEP` steps.
const HEAD_BYTES: u64 = 64 * 1024;
const HEAD_STEP: usize = 8 * 1024;
/// The tail in which the last `cost-state` line is looked for.
const TAIL_BYTES: u64 = 32 * 1024;

const TIMESTAMP_KEY: &[u8] = b"\"timestamp\":\"";
const COST_STATE_TYPE: &str = "\"type\":\"cost-state\"";

/// What the transcript of one session says (§6.2-§6.3).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionInfo {
    /// The session's first event, unix ms. Stays the start after `--resume`.
    pub start_ms: Option<i64>,
    /// `cost-state.totalCostUSD`.
    pub cost_usd: Option<f64>,
    /// Σ cache-read tokens × list price; none when a model has no price or `modelUsage` is absent.
    pub cache_read_usd: Option<f64>,
    /// Some model in `modelUsage` has no cache-read price.
    pub unpriced: bool,
}

/// USD per million cache-read tokens (list prices of plan-quota VF16, fetched 2026-10-02).
/// Exact id, or the id followed by `-` and 8 digits; no prefix matching, so
/// `claude-opus-5-5` never gets Opus 5's price.
pub fn cache_read_price(model: &str) -> Option<f64> {
    let b = model.as_bytes();
    let id = match model.len().checked_sub(9) {
        Some(i)
            if model.is_char_boundary(i)
                && b[i] == b'-'
                && b[i + 1..].iter().all(u8::is_ascii_digit) =>
        {
            &model[..i]
        }
        _ => model,
    };
    Some(match id {
        "claude-fable-5-1" => 0.25,
        "claude-fable-5" => 1.00,
        "claude-opus-5-5" => 0.20,
        "claude-opus-5" => 0.50,
        "claude-opus-4-5" | "claude-opus-4-6" | "claude-opus-4-7" | "claude-opus-4-8" => 0.50,
        "claude-sonnet-5-5" | "claude-sonnet-5" => 0.20,
        "claude-sonnet-4-5" | "claude-sonnet-4-6" => 0.30,
        "claude-haiku-4-5" => 0.10,
        _ => return None,
    })
}

/// Lists `{projects}/*/` once and reads the main transcript of each id in `sids`.
/// An id without a transcript is absent from the result.
pub fn read(projects: &Path, sids: &HashSet<String>) -> HashMap<String, SessionInfo> {
    let mut out = HashMap::new();
    if sids.is_empty() {
        return out;
    }
    let Ok(dirs) = std::fs::read_dir(projects) else {
        return out;
    };
    for dir in dirs.flatten() {
        if !dir.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(files) = std::fs::read_dir(dir.path()) else {
            continue;
        };
        for file in files.flatten() {
            let name = file.file_name();
            let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".jsonl")) else {
                continue;
            };
            if !sids.contains(stem)
                || out.contains_key(stem)
                || !file.file_type().is_ok_and(|t| t.is_file())
            {
                continue;
            }
            if let Some(info) = read_file(&file.path()) {
                out.insert(stem.to_string(), info);
            }
        }
    }
    out
}

fn read_file(path: &Path) -> Option<SessionInfo> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start_ms = first_timestamp(&mut f);
    let mut info = tail_totals(&mut f, len).unwrap_or_default();
    info.start_ms = start_ms;
    Some(info)
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    hay.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

/// The first `"timestamp":"<RFC 3339>"` in the first 64 KiB, read in 8 KiB steps that stop
/// at the first match.
fn first_timestamp(f: &mut File) -> Option<i64> {
    f.seek(SeekFrom::Start(0)).ok()?;
    let mut head = f.take(HEAD_BYTES);
    let mut buf = Vec::new();
    let mut chunk = [0u8; HEAD_STEP];
    loop {
        let n = head.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut from = 0;
        while let Some(at) = find(&buf, TIMESTAMP_KEY, from) {
            let value = at + TIMESTAMP_KEY.len();
            // No closing quote yet: the value runs past this step.
            let Some(end) = buf[value..].iter().position(|&b| b == b'"') else {
                break;
            };
            let parsed = std::str::from_utf8(&buf[value..value + end])
                .ok()
                .and_then(|s| time::OffsetDateTime::parse(s, &Rfc3339).ok());
            if let Some(t) = parsed {
                return i64::try_from(t.unix_timestamp_nanos() / 1_000_000).ok();
            }
            from = value + end;
        }
    }
}

/// The last line containing `"type":"cost-state"` in the last 32 KiB, parsed. A line that
/// does not parse counts as absent (no fallback to an earlier line).
fn tail_totals(f: &mut File, len: u64) -> Option<SessionInfo> {
    let start = len.saturating_sub(TAIL_BYTES);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    f.take(TAIL_BYTES).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    if start > 0 {
        // The first line of the tail may be cut.
        lines.next();
    }
    let line = lines.rfind(|l| l.contains(COST_STATE_TYPE))?;
    let v: Value = serde_json::from_str(line).ok()?;
    if v.get("type").and_then(Value::as_str) != Some("cost-state") {
        return None;
    }
    let cost_usd = v
        .get("totalCostUSD")
        .and_then(Value::as_f64)
        .filter(|c| c.is_finite());
    let mut info = SessionInfo {
        cost_usd,
        ..SessionInfo::default()
    };
    if let Some(usage) = v.get("modelUsage").and_then(Value::as_object) {
        let mut sum = 0.0;
        for (model, u) in usage {
            let tokens = u
                .get("cacheReadInputTokens")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            match cache_read_price(model) {
                Some(price) => sum += tokens * price / 1e6,
                None => info.unpriced = true,
            }
        }
        if !info.unpriced {
            info.cache_read_usd = Some(sum);
        }
    }
    Some(info)
}
