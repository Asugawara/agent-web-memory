//! Claude Code hook entry points and the code the synchronous hooks share
//! (plan-v2 §5). Every path returns exit code 0.
//!
//! The `injection` and `hook_run` rows are written after the output is printed, with one retry
//! after 20 ms when the database is busy. Under contention (a large pull being applied) a write
//! may still be dropped after the retry: the hook never waits longer for its rows.

pub mod capture;
pub mod post_tool;
pub mod pre_fetch;
pub mod pre_search;
pub mod prompt;
pub mod session_start;

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use rusqlite::{params, Connection, ErrorCode, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use crate::config::{self, Config, Mode, Notify};
use crate::db::{self, Role, VersionCheck};
use crate::deadline::Watchdog;
use crate::matching::{self, Hit, MatchOpts};
use crate::note::{Channel, Known, RenderCtx, Tool};
use crate::record::sha256_hex;
use crate::{paths, redact, render, sanitize};

#[derive(clap::Args, Debug, Default)]
pub struct HookArgs {
    /// Version of the plugin that invoked the hook.
    #[arg(long)]
    pub plugin_version: Option<String>,
}

/// Length of `injection.trigger_text`.
pub const TRIGGER_CHARS: usize = 200;

fn de_text<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

/// The hook payload Claude Code writes to stdin. Missing or null fields are empty.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HookInput {
    #[serde(deserialize_with = "de_text")]
    pub hook_event_name: String,
    #[serde(deserialize_with = "de_text")]
    pub session_id: String,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    #[serde(deserialize_with = "de_text")]
    pub cwd: String,
    #[serde(deserialize_with = "de_text")]
    pub tool_name: String,
    pub tool_input: Value,
    pub tool_response: Value,
    pub tool_use_id: Option<String>,
    pub transcript_path: Option<String>,
    pub prompt: Option<String>,
    /// Codex keys (ignored by the handlers; listed so the payload shape is documented).
    pub turn_id: Option<String>,
    pub model: Option<String>,
    pub permission_mode: Option<String>,
    pub stop_hook_active: Option<bool>,
}

impl HookInput {
    /// A string field of `tool_input`.
    pub fn tool_input_str(&self, key: &str) -> Option<&str> {
        self.tool_input.get(key).and_then(Value::as_str)
    }
}

/// Parses a payload; an empty `agent_id` counts as the main agent.
pub fn parse_input(text: &str) -> Option<HookInput> {
    if text.trim().is_empty() {
        return None;
    }
    let mut input: HookInput = serde_json::from_str(text).ok()?;
    input.agent_id = input.agent_id.filter(|a| !a.is_empty());
    input.agent_type = input.agent_type.filter(|a| !a.is_empty());
    Some(input)
}

/// Reads the whole of stdin; empty or invalid JSON gives `None`.
pub fn read_stdin() -> Option<HookInput> {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text).ok()?;
    parse_input(&text)
}

/// `systemMessage` for a database that does not match the binary (§5.4).
pub fn version_notice(check: VersionCheck) -> Option<String> {
    crate::db::refusal(&check).map(|why| format!("agent-web-memory: {why}"))
}

/// `{"systemMessage": ...}` only.
pub fn system_message_json(message: &str) -> String {
    json!({ "systemMessage": message }).to_string()
}

/// Context for the model, with an optional `systemMessage` for the user.
pub fn context_json(event: &str, context: &str, system_message: Option<&str>) -> String {
    let mut out = json!({
        "hookSpecificOutput": { "hookEventName": event, "additionalContext": context }
    });
    if let Some(m) = system_message {
        out["systemMessage"] = Value::String(m.to_string());
    }
    out.to_string()
}

/// PreToolUse deny: a one-line `reason` and, when non-empty, the `context` the model gets next to it.
pub fn deny_json(reason: &str, context: Option<&str>) -> String {
    let mut out = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        }
    });
    if let Some(c) = context.filter(|c| !c.is_empty()) {
        out["hookSpecificOutput"]["additionalContext"] = Value::String(c.to_string());
    }
    out.to_string()
}

pub fn now_ms() -> i64 {
    let ms = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    i64::try_from(ms).unwrap_or(i64::MAX)
}

fn millis(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

/// True when an error is SQLite reporting a busy or locked database.
pub fn is_busy(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        matches!(
            c.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(f, _))
                if matches!(f.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
        )
    })
}

fn debug_enabled() -> bool {
    std::env::var_os("AWM_DEBUG").is_some_and(|v| v == "1")
}

/// `meta.{key}`.
pub fn meta_value(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()?)
}

/// `meta.consent.record` is `yes` (§5.4 "recording declined").
pub fn recording_consented(conn: &Connection) -> Result<bool> {
    Ok(meta_value(conn, "consent.record")?.as_deref() == Some("yes"))
}

/// Longest `AWM_CANARY` value used, in characters, so a canary line cannot push a field over
/// Claude Code's 10,000-character `additionalContext` limit (a block or deny reason is at most 9,500).
pub const CANARY_VALUE_CAP: usize = 64;

/// `AWM-CANARY-{event}-{value}` with the value cut to [`CANARY_VALUE_CAP`] characters.
fn canary_text(event: &str, value: &str) -> String {
    let v: String = value.chars().take(CANARY_VALUE_CAP).collect();
    format!("AWM-CANARY-{event}-{v}")
}

/// `AWM-CANARY-{event}-{value}` when `AWM_CANARY` is set (§5.5).
pub fn canary_line(event: &str) -> Option<String> {
    let v = std::env::var("AWM_CANARY").ok().filter(|v| !v.is_empty())?;
    Some(canary_text(event, &v))
}

/// Appends `\n{line}` to `text` and checks the result is within the 10,000-character field limit.
pub(crate) fn append_canary(text: &mut String, line: &str) {
    text.push('\n');
    text.push_str(line);
    debug_assert!(
        text.chars().count() <= 10_000,
        "canary pushed a field over 10,000 characters"
    );
}

fn print_line(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

/// What a hook run needs to write its `hook_run` row.
#[derive(Debug, Clone)]
pub struct RunMeta {
    pub db_path: PathBuf,
    pub hook: &'static str,
    pub session_id: Option<String>,
    pub agent_kind: &'static str,
    pub started_at_ms: i64,
    pub started: Instant,
}

impl RunMeta {
    fn insert(
        &self,
        conn: &Connection,
        search_ms: Option<i64>,
        outcome: &str,
        error: Option<&str>,
    ) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO hook_run (started_at, hook, session_id, agent_kind, total_ms, search_ms, \
             outcome, error) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                self.started_at_ms,
                self.hook,
                self.session_id,
                self.agent_kind,
                millis(self.started.elapsed()),
                search_ms,
                outcome,
                error
            ],
        )
    }

    /// Best effort on a fresh connection: the row is lost when the database is locked.
    pub fn log_standalone(&self, outcome: &str, error: Option<&str>) {
        if let Ok(conn) = db::open(&self.db_path, Role::HookRead) {
            let _ = self.insert(&conn, None, outcome, error);
        }
    }
}

/// One `injection` row and its items, written after the output is printed.
#[derive(Debug, Clone)]
pub struct Injection {
    /// `UserPromptSubmit`, `PreToolUse` or `PostToolUse`.
    pub hook: &'static str,
    pub channel: Channel,
    /// `inject` or `deny` (rows of older versions may say `shadow` or `shadow_deny`).
    pub mode: &'static str,
    pub tool_use_id: Option<String>,
    pub trigger_text: Option<String>,
    pub cutoff: Option<f64>,
    pub rendered: Option<String>,
    pub rendered_chars: usize,
    pub ref_id: String,
    /// (event id, score) in block order.
    pub items: Vec<(i64, f64)>,
}

/// What a handler decided.
#[derive(Debug, Clone)]
pub struct Verdict {
    /// JSON printed to stdout.
    pub output: Option<String>,
    /// A `hook_run.outcome` value.
    pub outcome: &'static str,
    pub search_ms: Option<i64>,
    pub injection: Option<Injection>,
}

impl Verdict {
    pub fn quiet(outcome: &'static str) -> Verdict {
        Verdict {
            output: None,
            outcome,
            search_ms: None,
            injection: None,
        }
    }
}

/// Everything a handler may read.
pub struct Env {
    pub hook: &'static str,
    pub input: HookInput,
    pub config: Config,
    pub started: Instant,
    pub started_at_ms: i64,
    pub utc_offset_min: i32,
}

impl Env {
    pub fn is_subagent(&self) -> bool {
        self.input.agent_id.is_some()
    }

    pub fn agent_kind(&self) -> &'static str {
        if self.is_subagent() {
            "subagent"
        } else {
            "main"
        }
    }

    /// `MatchOpts` of the caller (§3.1 rules 1, 2 and 5).
    pub fn match_opts(&self, conn: &Connection) -> Result<MatchOpts> {
        Ok(MatchOpts {
            caller_session: self.input.session_id.clone(),
            caller_agent: self.input.agent_id.clone(),
            caller_cwd_hash: sha256_hex(&self.input.cwd),
            caller_tool_use_id: self.input.tool_use_id.clone(),
            before_ms: None,
            since_ms: None,
            exclude_same_agent: true,
            exclude_team: false,
            own_member: None,
            limit: self.config.inject.max_notes as usize,
            shown_event_ids: self.shown_event_ids(conn)?,
        })
    }

    /// Events already in this (session, agent)'s context: shown to it by an inject or a deny, or
    /// recorded by it (`origin = 'local'`, same session and agent).
    fn shown_event_ids(&self, conn: &Connection) -> Result<Vec<i64>> {
        let mut st = conn.prepare_cached(
            "SELECT ii.event_id FROM injection_item ii \
             JOIN injection i ON i.id = ii.injection_id \
             WHERE i.session_id = ?1 AND i.agent_id IS ?2 AND i.mode IN ('inject', 'deny') \
               AND ii.event_id IS NOT NULL \
             UNION \
             SELECT e.id FROM event e \
             WHERE e.session_id = ?1 AND e.agent_id IS ?2 AND e.origin = 'local'",
        )?;
        let rows = st.query_map(params![self.input.session_id, self.input.agent_id], |r| {
            r.get(0)
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The `ref_id` of the newest note (`mode = 'inject'`, any channel) that carried `event_id` to
    /// this (session, agent), or `None` when it never received it in a note. Served by
    /// `injection_agent (session_id, agent_id)`, then the primary key of `injection_item`.
    pub fn shown_note_ref(&self, conn: &Connection, event_id: i64) -> Result<Option<String>> {
        Ok(conn
            .prepare_cached(
                "SELECT i.ref FROM injection i \
                 JOIN injection_item ii ON ii.injection_id = i.id \
                 WHERE i.session_id = ?1 AND i.agent_id IS ?2 AND i.mode = 'inject' \
                   AND ii.event_id = ?3 ORDER BY i.id DESC LIMIT 1",
            )?
            .query_row(
                params![self.input.session_id, self.input.agent_id, event_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Whether `event_id` is already in this (session, agent)'s context: a note it was given (its
    /// ref, checked first) or a result it recorded itself in this session. `None` otherwise.
    pub fn known(&self, conn: &Connection, event_id: i64) -> Result<Option<Known>> {
        if let Some(r) = self.shown_note_ref(conn, event_id)? {
            return Ok(Some(Known::Note(r)));
        }
        let row: Option<(String, Option<String>, Option<String>)> = conn
            .prepare_cached(
                "SELECT tool, fetch_prompt, query FROM event \
                 WHERE id = ?3 AND origin = 'local' AND session_id = ?1 AND agent_id IS ?2",
            )?
            .query_row(
                params![self.input.session_id, self.input.agent_id, event_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(row.map(|(tool, prompt, query)| {
            let (tool, raw) = if tool == "WebFetch" {
                (Tool::WebFetch, prompt)
            } else {
                (Tool::WebSearch, query)
            };
            let text = raw
                .map(|s| sanitize::line_text(&s, render::FIELD_CAP).text)
                .unwrap_or_default();
            Known::Own { tool, text }
        }))
    }

    pub fn render_ctx(&self, channel: Channel, ref_id: &str) -> RenderCtx {
        RenderCtx {
            channel,
            now_ms: self.started_at_ms,
            utc_offset_min: self.utc_offset_min,
            ref_id: ref_id.to_string(),
            max_notes: self.config.inject.max_notes as usize,
        }
    }

    /// 8 hex characters, unique per run.
    pub fn new_ref(&self) -> String {
        let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        let seed = format!(
            "{nanos}:{}:{}:{}",
            std::process::id(),
            self.input.session_id,
            self.input.tool_use_id.as_deref().unwrap_or("")
        );
        sha256_hex(&seed)[..8].to_string()
    }

    /// First `TRIGGER_CHARS` characters of `text`, redacted.
    pub fn trigger_text(&self, text: &str) -> String {
        let (clean, _) = redact::redact(text, &self.config.capture.redact_terms);
        clean.chars().take(TRIGGER_CHARS).collect()
    }
}

fn local_offset_minutes() -> i32 {
    time::UtcOffset::current_local_offset().map_or(0, |o| i32::from(o.whole_minutes()))
}

/// Pause before the one retry of the post-output write when the database is busy.
const WRITE_RETRY_PAUSE: Duration = Duration::from_millis(20);

/// Runs a synchronous hook: stdin, config, deadline, database, `handler`, output,
/// then the `injection` and `hook_run` rows. Never fails.
///
/// The rows are written after the output is printed, with a 50 ms busy timeout
/// ([`Role::HookRead`]). When the database is busy the write is tried once more after 20 ms;
/// the hook's total deadline is unchanged (the watchdog has already been committed). Under
/// heavy contention (for example `awm sync` applying a large pull) the second try can fail too,
/// and the `injection` / `hook_run` rows of that run are then dropped: the hook never waits
/// longer for them.
pub fn run_sync<F>(hook: &'static str, handler: F)
where
    F: FnOnce(&Env, &Connection) -> Result<Verdict>,
{
    let started = Instant::now();
    let started_at_ms = now_ms();
    // Read before the watchdog thread exists: the local offset is only available single-threaded.
    let utc_offset_min = local_offset_minutes();
    let Some(input) = read_stdin() else {
        return;
    };
    let Ok(data_dir) = paths::data_dir() else {
        return;
    };
    let db_path = data_dir.join(paths::DB_FILE);
    if !db_path.is_file() {
        return;
    }
    // A configuration that cannot be read might hold `mode = "off"`: stay silent.
    let Ok(config) = config::load(&data_dir.join(paths::CONFIG_FILE)) else {
        return;
    };
    // `mode = "off"`: nothing is read, written or logged (§2.3).
    if config.mode == Mode::Off {
        return;
    }
    let env = Env {
        hook,
        input,
        config,
        started,
        started_at_ms,
        utc_offset_min,
    };
    let meta = RunMeta {
        db_path: db_path.clone(),
        hook,
        session_id: Some(env.input.session_id.clone()).filter(|s| !s.is_empty()),
        agent_kind: env.agent_kind(),
        started_at_ms,
        started,
    };

    let deadline = Duration::from_millis(u64::from(env.config.hooks.deadline_ms))
        .saturating_sub(started.elapsed());
    let watchdog = {
        let meta = meta.clone();
        Watchdog::start(deadline, move || meta.log_standalone("deadline", None))
    };

    let (mut conn, verdict) = match decide(&env, &db_path, handler) {
        Ok(pair) => pair,
        Err(Stop { outcome, error }) => {
            if !watchdog.commit() {
                park();
            }
            if let Some(outcome) = outcome {
                meta.log_standalone(outcome, error.as_deref());
            }
            return;
        }
    };

    if !watchdog.commit() {
        park();
    }
    if let Some(out) = &verdict.output {
        print_line(out);
    }
    // The output is already printed: a busy database costs one more try after a short pause
    // (the transaction rolled back, nothing is half written).
    let mut written = write_rows(&mut conn, &env, &meta, &verdict);
    if matches!(&written, Err(e) if is_busy(e)) {
        std::thread::sleep(WRITE_RETRY_PAUSE);
        written = write_rows(&mut conn, &env, &meta, &verdict);
    }
    if let Err(e) = written {
        if debug_enabled() {
            eprintln!("awm {hook}: cannot write the log rows: {e:#}");
        }
    }
}

/// Blocks until the watchdog thread exits the process.
fn park() -> ! {
    loop {
        std::thread::park();
    }
}

/// The run ends before the handler. `outcome: None` writes no row: the schema or
/// the consent says this binary must leave the database alone.
struct Stop {
    outcome: Option<&'static str>,
    error: Option<String>,
}

impl Stop {
    fn silent() -> Stop {
        Stop {
            outcome: None,
            error: None,
        }
    }

    fn from_error(e: &anyhow::Error) -> Stop {
        if is_busy(e) {
            return Stop {
                outcome: Some("locked"),
                error: None,
            };
        }
        if debug_enabled() {
            eprintln!("awm: {e:#}");
        }
        Stop {
            outcome: Some("error"),
            error: Some(e.to_string().chars().take(300).collect()),
        }
    }
}

/// Everything before the output: open, version, consent, test delay, handler.
fn decide<F>(
    env: &Env,
    db_path: &std::path::Path,
    handler: F,
) -> Result<(Connection, Verdict), Stop>
where
    F: FnOnce(&Env, &Connection) -> Result<Verdict>,
{
    let conn = db::open(db_path, Role::HookRead).map_err(|e| Stop::from_error(&e))?;
    let check = db::check_version(&conn).map_err(|e| Stop::from_error(&e))?;
    if check != VersionCheck::Current {
        return Err(Stop::silent());
    }
    if !recording_consented(&conn).map_err(|e| Stop::from_error(&e))? {
        return Err(Stop::silent());
    }
    if let Some(ms) = std::env::var("AWM_TEST_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        std::thread::sleep(Duration::from_millis(ms));
    }
    let verdict = handler(env, &conn).map_err(|e| Stop::from_error(&e))?;
    Ok((conn, verdict))
}

/// Writes the injection (with items) and the `hook_run` row in one transaction.
fn write_rows(conn: &mut Connection, env: &Env, meta: &RunMeta, verdict: &Verdict) -> Result<()> {
    let total_ms = millis(env.started.elapsed());
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(inj) = &verdict.injection {
        tx.execute(
            "INSERT INTO injection (ref, created_at, hook, channel, mode, session_id, agent_id, \
             tool_use_id, transcript_path, trigger_text, cutoff, rendered, rendered_chars, \
             latency_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                inj.ref_id,
                env.started_at_ms,
                inj.hook,
                inj.channel.as_db_str(),
                inj.mode,
                env.input.session_id,
                env.input.agent_id,
                inj.tool_use_id,
                env.input.transcript_path,
                inj.trigger_text,
                inj.cutoff,
                inj.rendered,
                i64::try_from(inj.rendered_chars).unwrap_or(i64::MAX),
                total_ms
            ],
        )?;
        let id = tx.last_insert_rowid();
        for (i, (event_id, score)) in inj.items.iter().enumerate() {
            tx.execute(
                "INSERT INTO injection_item (injection_id, position, event_id, score) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    id,
                    i64::try_from(i + 1).unwrap_or(i64::MAX),
                    event_id,
                    score
                ],
            )?;
        }
    }
    meta.insert(&tx, verdict.search_ms, verdict.outcome, None)?;
    tx.commit()?;
    Ok(())
}

/// Inputs of [`deliver`].
pub struct Delivery<'a> {
    /// `hookEventName` of the output.
    pub event: &'static str,
    pub channel: Channel,
    pub hits: Vec<Hit>,
    pub trigger_text: Option<String>,
    pub cutoff: Option<f64>,
    pub search_ms: i64,
    pub opts: &'a MatchOpts,
}

fn injections_in_session(env: &Env, conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM injection WHERE session_id = ?1 AND mode = 'inject'",
        [&env.input.session_id],
        |r| r.get(0),
    )?)
}

/// Turns hits into a verdict: notes, render, canary, S6, injection row.
pub fn deliver(env: &Env, conn: &Connection, d: Delivery<'_>) -> Result<Verdict> {
    let hook_name = d.event;
    let no_match = |extra: Option<Verdict>| -> Verdict {
        if let Some(v) = extra {
            return v;
        }
        Verdict {
            search_ms: Some(d.search_ms),
            ..Verdict::quiet("no_match")
        }
    };
    let canary = canary_line(hook_name);
    let ref_id = env.new_ref();
    let canary_only = |reason_rows: bool| -> Verdict {
        let Some(line) = &canary else {
            return no_match(None);
        };
        Verdict {
            output: Some(context_json(hook_name, line, None)),
            outcome: "injected",
            search_ms: Some(d.search_ms),
            injection: reason_rows.then(|| Injection {
                hook: hook_name,
                channel: d.channel,
                mode: "inject",
                tool_use_id: env.input.tool_use_id.clone(),
                trigger_text: None,
                cutoff: d.cutoff,
                rendered: Some(line.clone()),
                rendered_chars: line.chars().count(),
                ref_id: ref_id.clone(),
                items: Vec::new(),
            }),
        }
    };
    if d.hits.is_empty() {
        return Ok(canary_only(true));
    }
    let mut notes = Vec::new();
    for hit in &d.hits {
        let note = matching::to_note(conn, hit, d.opts)?;
        // `team.show` and `team.mute` (plan-v3-team §3.5).
        if render::team_visible(&note, &env.config.team) {
            notes.push(note);
        }
    }
    let ctx = env.render_ctx(d.channel, &ref_id);
    let Some(rendered) = render::render(&notes, &ctx) else {
        return Ok(canary_only(true));
    };
    let items: Vec<(i64, f64)> = rendered
        .event_ids
        .iter()
        .map(|id| {
            let score = d
                .hits
                .iter()
                .find(|h| h.event_id == *id)
                .map_or(0.0, |h| h.score);
            (*id, score)
        })
        .collect();
    let mut text = rendered.text.clone();
    if let Some(line) = &canary {
        append_canary(&mut text, line);
    }
    let first = injections_in_session(env, conn)? == 0;
    let system_message = match env.config.notify {
        Notify::Always => true,
        Notify::First => first,
        Notify::Never => false,
    }
    .then(|| {
        let newest = notes.iter().map(|n| n.created_at_ms).max().unwrap_or(0);
        let shown = rendered.event_ids.len();
        format!(
            "agent-web-memory: added {shown} note(s) from your earlier research (newest: {}). Show it: awm log --ref {ref_id}",
            render::age_string(newest, env.started_at_ms)
        )
    });
    Ok(Verdict {
        output: Some(context_json(hook_name, &text, system_message.as_deref())),
        outcome: "injected",
        search_ms: Some(d.search_ms),
        injection: Some(Injection {
            hook: hook_name,
            channel: d.channel,
            mode: "inject",
            tool_use_id: env.input.tool_use_id.clone(),
            trigger_text: d.trigger_text.clone(),
            cutoff: d.cutoff,
            rendered_chars: text.chars().count(),
            rendered: Some(text),
            ref_id,
            items,
        }),
    })
}

/// Milliseconds elapsed since `t`.
pub fn elapsed_ms(t: Instant) -> i64 {
    millis(t.elapsed())
}

#[cfg(test)]
mod canary_tests {
    use super::*;

    #[test]
    fn an_over_long_canary_value_is_cut_and_a_maximal_block_stays_under_10000() {
        let line = canary_text("PostToolUse", &"x".repeat(2000));
        assert_eq!(
            line.chars().count(),
            "AWM-CANARY-PostToolUse-".len() + CANARY_VALUE_CAP
        );
        let mut text = "a".repeat(crate::render::MAX_CHARS);
        append_canary(&mut text, &line);
        assert!(text.chars().count() <= 10_000, "{}", text.chars().count());
    }

    #[test]
    fn a_short_canary_value_is_kept() {
        assert_eq!(canary_text("e", "abc"), "AWM-CANARY-e-abc");
    }
}
