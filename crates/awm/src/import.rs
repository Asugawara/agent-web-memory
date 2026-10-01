//! Transcript import (plan-v2 §6.5): streams `~/.claude/projects/**/*.jsonl`, pairs
//! WebSearch / WebFetch `tool_use` blocks with their `tool_result`, and stores
//! the records the way async capture does. Port of the walk in
//! `spikes/match-bench/src/extract.rs`.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Context;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;
use walkdir::WalkDir;

use crate::config::{self, Config};
use crate::db::{self, Role};
use crate::gate::MACHINE_PREFIXES;
use crate::hosts;
use crate::matching::calibrate;
use crate::matching::{query_channel, MatchOpts};
use crate::note::Tool;
use crate::paths;
use crate::record::{sha256_hex, Record, TranscriptCtx};
use crate::sanitize;

/// Records per transaction.
const BATCH: usize = 500;
/// Bytes of a file that go into `import_source.head_sha256`.
const HEAD_BYTES: usize = 4096;
/// Human prompts kept for the prompt cutoff.
const MAX_PROMPTS: usize = 500;
/// Characters of a prompt that are searched (as the prompt_bm25 channel does).
const PROMPT_CHARS: usize = 1_000;

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Transcript directory (default ~/.claude/projects)
    #[arg(long, value_name = "DIR")]
    pub projects: Option<PathBuf>,
    /// Import only the tool_use ids listed in FILE (one per line)
    #[arg(long, value_name = "FILE")]
    pub only_ids: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ImportOpts {
    pub projects_dir: PathBuf,
    pub data_dir: PathBuf,
    pub config: Config,
    pub only_ids: Option<HashSet<String>>,
    pub now_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImportSummary {
    pub files_total: usize,
    pub files_ok: usize,
    pub files_partial: usize,
    pub files_error: usize,
    /// Web tool calls with a result that became a record candidate.
    pub records_found: usize,
    pub records_inserted: usize,
    pub skipped_private: usize,
    /// Tombstoned ids or URLs, and records older than `meta.purged_before`.
    pub skipped_tombstone: usize,
    pub skipped_duplicate: usize,
    /// `[redacted:...]` markers in the stored records.
    pub redactions: usize,
    pub searches: usize,
    pub fetches: usize,
    pub subagent_records: usize,
    pub secs: f64,
    /// Records sampled by `calibrate::run` (the "{c} recent searches" of S5).
    pub calibrated: usize,
}

/// `~/.claude/projects`.
pub fn default_projects_dir() -> anyhow::Result<PathBuf> {
    let base = directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("cannot find the home directory; use --projects"))?;
    Ok(base.home_dir().join(".claude").join("projects"))
}

/// Every `*.jsonl` under `dir`, sorted.
pub fn transcript_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|x| x == "jsonl"))
        .map(walkdir::DirEntry::into_path)
        .collect();
    files.sort();
    files
}

/// Reads the ids of `--only-ids FILE`.
pub fn read_only_ids(path: &Path) -> anyhow::Result<HashSet<String>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

struct SourceRow {
    head: String,
    size: i64,
    mtime: i64,
    last_offset: i64,
    found: i64,
    inserted: i64,
    status: String,
}

struct Pending {
    tool_use: Value,
    ctx: TranscriptCtx,
    offset: u64,
}

/// A human prompt: time and text, held in memory only.
type Prompt = (i64, String);

struct Run<'a> {
    opts: &'a ImportOpts,
    conn: Connection,
    summary: ImportSummary,
    purged_before: Option<i64>,
    prompts: Vec<Prompt>,
}

/// Imports every transcript under `opts.projects_dir` into `{data_dir}/awm.db`
/// (which must exist and be migrated), then recalibrates.
pub fn import_all(opts: &ImportOpts) -> anyhow::Result<ImportSummary> {
    let start = Instant::now();
    let conn = db::open(&opts.data_dir.join(paths::DB_FILE), Role::Cli)?;
    let purged_before = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'purged_before'",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .and_then(|v| v.trim().parse::<i64>().ok());
    let mut run = Run {
        opts,
        conn,
        summary: ImportSummary::default(),
        purged_before,
        prompts: Vec::new(),
    };
    for path in transcript_files(&opts.projects_dir) {
        run.summary.files_total += 1;
        match run.import_file(&path) {
            Ok(status) => match status.as_str() {
                "partial" => run.summary.files_partial += 1,
                _ => run.summary.files_ok += 1,
            },
            Err(e) => {
                run.summary.files_error += 1;
                run.record_error(&path, &format!("{e:#}"));
            }
        }
    }
    run.finish_prompts()?;
    let calibration = calibrate::run(&run.conn)?;
    let mut summary = run.summary;
    summary.calibrated = calibration.n;
    summary.secs = start.elapsed().as_secs_f64();
    Ok(summary)
}

fn file_times(path: &Path) -> anyhow::Result<(i64, i64)> {
    let meta = std::fs::metadata(path)?;
    let size = i64::try_from(meta.len()).unwrap_or(i64::MAX);
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    Ok((size, mtime))
}

/// sha256 of the first `min(len, 4096)` bytes of the file.
fn head_hash(path: &Path, len: u64) -> anyhow::Result<String> {
    let n = len.min(HEAD_BYTES as u64);
    let mut buf = Vec::with_capacity(HEAD_BYTES);
    std::fs::File::open(path)?.take(n).read_to_end(&mut buf)?;
    Ok(Sha256::digest(&buf)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

impl Run<'_> {
    fn source_row(&self, path: &str) -> anyhow::Result<Option<SourceRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT head_sha256, file_size, file_mtime, last_offset, events_found, \
                 events_inserted, status FROM import_source WHERE path = ?1",
                [path],
                |r| {
                    Ok(SourceRow {
                        head: r.get(0)?,
                        size: r.get(1)?,
                        mtime: r.get(2)?,
                        last_offset: r.get(3)?,
                        found: r.get(4)?,
                        inserted: r.get(5)?,
                        status: r.get(6)?,
                    })
                },
            )
            .optional()?)
    }

    /// Notes a failed file; best effort, the error is already counted.
    fn record_error(&self, path: &Path, error: &str) {
        let key = path.to_string_lossy();
        let (size, mtime) = file_times(path).unwrap_or((0, 0));
        let _ = self.conn.execute(
            "INSERT INTO import_source (path, head_sha256, file_size, file_mtime, last_offset, \
             status, error, imported_at) VALUES (?1, '', ?2, ?3, 0, 'error', ?4, ?5) \
             ON CONFLICT(path) DO UPDATE SET status = 'error', error = excluded.error, \
             imported_at = excluded.imported_at",
            params![key, size, mtime, error, self.opts.now_ms],
        );
    }

    /// Imports one file and returns its stored status (`ok` or `partial`).
    fn import_file(&mut self, path: &Path) -> anyhow::Result<String> {
        let key = path.to_string_lossy().to_string();
        let (size, mtime) = file_times(path)?;
        let head = head_hash(path, u64::try_from(size).unwrap_or(0))?;
        let row = self.source_row(&key)?;

        let mut start: u64 = 0;
        let (mut found_before, mut inserted_before) = (0, 0);
        if let Some(r) = &row {
            // A file shorter than 4096 bytes grows into its own head, so the stored
            // hash covers `min(size, 4096)` bytes and is compared over the same span.
            let old_head = head_hash(path, u64::try_from(r.size).unwrap_or(0))?;
            if r.head == old_head {
                if r.size == size && r.mtime == mtime && r.status != "error" {
                    return Ok(r.status.clone());
                }
                if r.size >= r.last_offset && size >= r.last_offset {
                    start = u64::try_from(r.last_offset).unwrap_or(0);
                    found_before = r.found;
                    inserted_before = r.inserted;
                }
            }
        }
        self.conn.execute(
            "INSERT INTO import_source (path, head_sha256, file_size, file_mtime, last_offset, \
             status, imported_at) VALUES (?1, ?2, ?3, ?4, ?5, 'partial', ?6) \
             ON CONFLICT(path) DO UPDATE SET head_sha256 = excluded.head_sha256, \
             file_size = excluded.file_size, file_mtime = excluded.file_mtime, \
             last_offset = excluded.last_offset, status = 'partial', error = NULL, \
             imported_at = excluded.imported_at",
            params![key, head, size, mtime, start as i64, self.opts.now_ms],
        )?;
        let source_id: i64 = self.conn.query_row(
            "SELECT id FROM import_source WHERE path = ?1",
            [&key],
            |r| r.get(0),
        )?;

        let outcome = self.scan(path, start, source_id)?;
        let status = if outcome.pending > 0 { "partial" } else { "ok" };
        self.conn.execute(
            "UPDATE import_source SET last_offset = ?1, events_found = ?2, events_inserted = ?3, \
             status = ?4, error = NULL, imported_at = ?5 WHERE id = ?6",
            params![
                i64::try_from(outcome.last_offset).unwrap_or(i64::MAX),
                found_before + i64::try_from(outcome.found).unwrap_or(0),
                inserted_before + i64::try_from(outcome.inserted).unwrap_or(0),
                status,
                self.opts.now_ms,
                source_id
            ],
        )?;
        Ok(status.to_string())
    }

    /// Streams `path` from `start`. Only complete lines are consumed.
    fn scan(&mut self, path: &Path, start: u64, source_id: i64) -> anyhow::Result<ScanOutcome> {
        let is_sub = path.components().any(|c| c.as_os_str() == "subagents");
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let file_agent = is_sub.then(|| stem.trim_start_matches("agent-").to_string());
        let file_session = if is_sub {
            path.parent()
                .and_then(Path::parent)
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string()
        } else {
            stem
        };

        let mut file = std::fs::File::open(path)?;
        file.seek(SeekFrom::Start(start))?;
        let mut reader = BufReader::new(file);
        let mut pending: HashMap<String, Pending> = HashMap::new();
        let mut batch: Vec<Record> = Vec::new();
        let (mut found, mut inserted) = (0usize, 0usize);
        let mut offset = start;
        let mut consumed = start;
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = reader.read_until(b'\n', &mut line)?;
            if n == 0 {
                break;
            }
            let line_start = offset;
            offset += n as u64;
            if line.last() != Some(&b'\n') {
                // A line still being written.
                break;
            }
            consumed = offset;
            let Ok(r) = serde_json::from_slice::<Value>(&line) else {
                continue;
            };
            self.handle_line(
                &r,
                line_start,
                &file_session,
                file_agent.as_deref(),
                is_sub,
                &mut pending,
                &mut batch,
                &mut found,
            )?;
            if batch.len() >= BATCH {
                inserted += self.flush(&mut batch, source_id)?;
            }
        }
        inserted += self.flush(&mut batch, source_id)?;
        let last_offset = pending
            .values()
            .map(|p| p.offset)
            .min()
            .map_or(consumed, |earliest| earliest.min(consumed));
        Ok(ScanOutcome {
            last_offset,
            found,
            inserted,
            pending: pending.len(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_line(
        &mut self,
        r: &Value,
        line_start: u64,
        file_session: &str,
        file_agent: Option<&str>,
        is_sub: bool,
        pending: &mut HashMap<String, Pending>,
        batch: &mut Vec<Record>,
        found: &mut usize,
    ) -> anyhow::Result<()> {
        let ty = r.get("type").and_then(Value::as_str).unwrap_or("");
        let content = r.pointer("/message/content");
        let created = r
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok())
            .map_or(self.opts.now_ms, |t| {
                i64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap_or(self.opts.now_ms)
            });
        match ty {
            "assistant" => {
                let Some(items) = content.and_then(Value::as_array) else {
                    return Ok(());
                };
                for item in items {
                    if item.get("type").and_then(Value::as_str) != Some("tool_use") {
                        continue;
                    }
                    let name = item.get("name").and_then(Value::as_str).unwrap_or("");
                    if name != "WebSearch" && name != "WebFetch" {
                        continue;
                    }
                    let Some(id) = item
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    else {
                        continue;
                    };
                    if self.opts.only_ids.as_ref().is_some_and(|s| !s.contains(id)) {
                        continue;
                    }
                    let agent_id = r
                        .get("agentId")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .or_else(|| file_agent.map(str::to_string));
                    let ctx = TranscriptCtx {
                        session_id: r
                            .get("sessionId")
                            .and_then(Value::as_str)
                            .unwrap_or(file_session)
                            .to_string(),
                        agent_id,
                        agent_type: None,
                        cwd: r
                            .get("cwd")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        created_at_ms: created,
                    };
                    pending.insert(
                        id.to_string(),
                        Pending {
                            tool_use: item.clone(),
                            ctx,
                            offset: line_start,
                        },
                    );
                }
            }
            "user" => {
                let Some(content) = content else {
                    return Ok(());
                };
                let has_result = content.as_array().is_some_and(|a| {
                    a.iter()
                        .any(|i| i.get("type").and_then(Value::as_str) == Some("tool_result"))
                });
                if has_result {
                    for item in content.as_array().into_iter().flatten() {
                        if item.get("type").and_then(Value::as_str) != Some("tool_result") {
                            continue;
                        }
                        let Some(id) = item.get("tool_use_id").and_then(Value::as_str) else {
                            continue;
                        };
                        let Some(p) = pending.remove(id) else {
                            continue;
                        };
                        let rec = Record::from_transcript(
                            &p.tool_use,
                            item,
                            r.get("toolUseResult"),
                            &p.ctx,
                            &self.opts.config.capture.redact_terms,
                        )?;
                        if let Some(rec) = rec {
                            *found += 1;
                            self.summary.records_found += 1;
                            batch.push(rec);
                        }
                    }
                } else if !is_sub
                    && r.get("isMeta").and_then(Value::as_bool) != Some(true)
                    && r.get("isSidechain").and_then(Value::as_bool) != Some(true)
                {
                    if let Some(text) = human_text(content) {
                        self.keep_prompt(created, text);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Keeps the newest [`MAX_PROMPTS`] prompts (in memory only).
    fn keep_prompt(&mut self, at: i64, text: String) {
        self.prompts.push((at, text));
        if self.prompts.len() >= MAX_PROMPTS * 2 {
            self.trim_prompts();
        }
    }

    fn trim_prompts(&mut self) {
        self.prompts.sort_by_key(|p| std::cmp::Reverse(p.0));
        self.prompts.truncate(MAX_PROMPTS);
    }

    /// `cutoff.prompt` = 75th percentile of the top-1 scores of the kept prompts.
    fn finish_prompts(&mut self) -> anyhow::Result<()> {
        self.trim_prompts();
        let mut scores = Vec::new();
        for (_, text) in std::mem::take(&mut self.prompts) {
            let text: String = text.chars().take(PROMPT_CHARS).collect();
            let opts = MatchOpts {
                limit: 1,
                ..MatchOpts::default()
            };
            if let Some(hit) = query_channel(&self.conn, &text, f64::NEG_INFINITY, &opts)?.first() {
                scores.push(hit.score);
            }
        }
        // Too few scores would overwrite a better stored value (§3.3 minimum).
        if scores.len() < calibrate::MIN_RECORDS {
            return Ok(());
        }
        calibrate::set_prompt_cutoff(&self.conn, &scores)
    }

    /// Applies the capture rules to each record and inserts the survivors in one transaction.
    fn flush(&mut self, batch: &mut Vec<Record>, source_id: i64) -> anyhow::Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }
        let config = &self.opts.config;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut inserted = 0;
        for mut rec in batch.drain(..) {
            match decide(&tx, &mut rec, config, self.purged_before)? {
                Some(Skip::Private) => {
                    self.summary.skipped_private += 1;
                    continue;
                }
                Some(Skip::Tombstone) => {
                    self.summary.skipped_tombstone += 1;
                    continue;
                }
                None => {}
            }
            quarantine(&mut rec);
            if !insert(&tx, &rec, source_id)? {
                self.summary.skipped_duplicate += 1;
                continue;
            }
            inserted += 1;
            self.summary.records_inserted += 1;
            match rec.tool {
                Tool::WebSearch => self.summary.searches += 1,
                Tool::WebFetch => self.summary.fetches += 1,
            }
            if rec.agent_id.is_some() {
                self.summary.subagent_records += 1;
            }
            self.summary.redactions += redaction_markers(&rec);
        }
        tx.commit()?;
        Ok(inserted)
    }
}

struct ScanOutcome {
    last_offset: u64,
    found: usize,
    inserted: usize,
    pending: usize,
}

/// Prompt text of a human `user` record: a string or text blocks. `None` for
/// machine turns and empty text.
fn human_text(content: &Value) -> Option<String> {
    let text = match content {
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .filter(|i| i.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|i| i.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => return None,
    };
    let trimmed = text.trim_start();
    if trimmed.is_empty() || MACHINE_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
        return None;
    }
    Some(text)
}

fn redaction_markers(rec: &Record) -> usize {
    let count = |s: &Option<String>| s.as_deref().map_or(0, |s| s.matches("[redacted:").count());
    count(&rec.query)
        + count(&rec.fetch_prompt)
        + count(&rec.summary)
        + rec.results.iter().map(|r| count(&r.title)).sum::<usize>()
}

enum Skip {
    Private,
    Tombstone,
}

/// Same rules and order as async capture: private hosts and forgotten result
/// rows, tombstones, `purged_before`. Keep the two copies in step.
fn decide(
    conn: &Connection,
    rec: &mut Record,
    config: &Config,
    purged_before: Option<i64>,
) -> anyhow::Result<Option<Skip>> {
    let exclude = &config.capture.exclude_hosts;
    let private = |u: &str| Url::parse(u).map_or(true, |u| hosts::is_private(&u, exclude));
    let tombstoned = |kind: &str, value: &str| -> anyhow::Result<bool> {
        Ok(conn
            .query_row(
                "SELECT 1 FROM tombstone WHERE kind = ?1 AND value = ?2",
                params![kind, value],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    };
    match &rec.url {
        Some(url) => {
            if private(url) {
                return Ok(Some(Skip::Private));
            }
        }
        None => {
            // Result rows of private hosts and of forgotten URLs (`url_hash`
            // tombstones, §6.4) are dropped; a search left with none is skipped.
            let listed = rec.results.len();
            let (mut private_rows, mut kept) = (0, Vec::with_capacity(listed));
            for r in std::mem::take(&mut rec.results) {
                if private(&r.url) {
                    private_rows += 1;
                } else if !tombstoned("url_hash", &sha256_hex(&r.url_norm))? {
                    kept.push(r);
                }
            }
            if listed > 0 && kept.is_empty() {
                return Ok(Some(if private_rows == listed {
                    Skip::Private
                } else {
                    Skip::Tombstone
                }));
            }
            rec.results = kept;
            for (i, r) in rec.results.iter_mut().enumerate() {
                r.rank = i64::try_from(i).unwrap_or(i64::MAX) + 1;
            }
            rec.match_text = rec.match_text();
        }
    }
    if tombstoned("tool_use_id", &rec.tool_use_id)? {
        return Ok(Some(Skip::Tombstone));
    }
    if let Some(norm) = &rec.url_norm {
        if tombstoned("url_hash", &sha256_hex(norm))? {
            return Ok(Some(Skip::Tombstone));
        }
    }
    if purged_before.is_some_and(|before| rec.created_at < before) {
        return Ok(Some(Skip::Tombstone));
    }
    Ok(None)
}

/// Sets `quarantine_reason` as async capture does.
fn quarantine(rec: &mut Record) {
    rec.quarantine_reason = sanitize::record_quarantine_reason(
        rec.summary.as_deref(),
        rec.fetch_prompt.as_deref(),
        rec.query.as_deref(),
    );
}

/// `false` when the `tool_use_id` already exists.
fn insert(tx: &Connection, rec: &Record, source_id: i64) -> anyhow::Result<bool> {
    let inserted = tx.execute(
        "INSERT INTO event (tool_use_id, tool, session_id, agent_id, agent_type, cwd_hash, \
         created_at, query, url, url_norm, fetch_prompt, http_code, bytes, duration_ms, status, \
         summary, match_text, source, import_source_id, quarantined, quarantine_reason) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
         ?18, ?19, ?20, ?21) ON CONFLICT(tool_use_id) DO NOTHING",
        params![
            rec.tool_use_id,
            rec.tool.as_db_str(),
            rec.session_id,
            rec.agent_id,
            rec.agent_type,
            rec.cwd_hash,
            rec.created_at,
            rec.query,
            rec.url,
            rec.url_norm,
            rec.fetch_prompt,
            rec.http_code,
            rec.bytes,
            rec.duration_ms,
            rec.status.as_db_str(),
            rec.summary,
            rec.match_text,
            rec.source,
            source_id,
            i64::from(rec.quarantine_reason.is_some()),
            rec.quarantine_reason,
        ],
    )?;
    if inserted == 0 {
        return Ok(false);
    }
    let event_id = tx.last_insert_rowid();
    let mut st = tx.prepare_cached(
        "INSERT INTO result (event_id, rank, url, url_norm, title) VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for r in &rec.results {
        st.execute(params![event_id, r.rank, r.url, r.url_norm, r.title])?;
    }
    Ok(true)
}

/// The S5 first line.
pub fn summary_line(s: &ImportSummary, new: bool) -> String {
    let p = if s.records_inserted == 0 {
        0.0
    } else {
        100.0 * s.subagent_records as f64 / s.records_inserted as f64
    };
    format!(
        "Imported {}{} records ({} searches, {} fetches; {:.1}% from subagents) from {} files in {:.1} s.",
        s.records_inserted,
        if new { " new" } else { "" },
        s.searches,
        s.fetches,
        p,
        s.files_total,
        s.secs
    )
}

/// `awm import`: re-runs the import for an initialised database.
pub fn run(args: Args) -> anyhow::Result<()> {
    let data_dir = paths::data_dir()?;
    if !data_dir.join(paths::DB_FILE).is_file() {
        anyhow::bail!("not set up yet. Run: awm init");
    }
    let mut conn = db::open(&data_dir.join(paths::DB_FILE), Role::Cli)?;
    db::migrate(&mut conn)?;
    drop(conn);
    let config = config::load(&data_dir.join(paths::CONFIG_FILE))?;
    let opts = ImportOpts {
        projects_dir: match args.projects {
            Some(p) => p,
            None => default_projects_dir()?,
        },
        data_dir,
        config,
        only_ids: args.only_ids.as_deref().map(read_only_ids).transpose()?,
        now_ms: now_ms(),
    };
    let summary = import_all(&opts)?;
    println!("{}", summary_line(&summary, true));
    Ok(())
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}
