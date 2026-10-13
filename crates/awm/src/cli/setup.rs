//! `awm setup`: writes or removes the hook entries in `~/.claude/settings.json` (plan-v2 §5.6)
//! or, for Codex, in `$CODEX_HOME/hooks.json` (default `~/.codex/hooks.json`).
//!
//! Only runs when the user asks. Shows what it adds, keeps a backup, and never
//! touches entries it did not write (a command that runs `awm hook <name>`).

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use serde_json::{json, Map, Value};

const COMMAND_PREFIX: &str = "awm hook ";

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Add the awm hooks to ~/.claude/settings.json
    #[arg(long, conflicts_with = "remove_hooks")]
    pub hooks_in_settings: bool,
    /// Remove the awm hooks from ~/.claude/settings.json
    #[arg(long)]
    pub remove_hooks: bool,
    /// Add the awm hooks to $CODEX_HOME/hooks.json (default ~/.codex/hooks.json)
    #[arg(long, conflicts_with_all = ["hooks_in_settings", "remove_hooks", "remove_codex_hooks"])]
    pub codex_hooks: bool,
    /// Remove the awm hooks from $CODEX_HOME/hooks.json
    #[arg(long, conflicts_with_all = ["hooks_in_settings", "remove_hooks"])]
    pub remove_codex_hooks: bool,
    /// Do not ask for confirmation
    #[arg(long)]
    pub yes: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Claude,
    Codex,
}

type Entry = (&'static str, Option<&'static str>, Value);

/// The command line for one hook. Codex may not inherit PATH, so it gets the absolute
/// path of this binary (quoted when it holds a space).
fn command_for(target: Target, name: &str) -> String {
    match target {
        Target::Claude => format!("{COMMAND_PREFIX}{name}"),
        Target::Codex => {
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "awm".to_string());
            let exe = if exe.contains(' ') {
                format!("'{exe}'")
            } else {
                exe
            };
            format!("{exe} hook {name}")
        }
    }
}

/// (event, matcher, hook) entries, as in `plugin/hooks/hooks.json` for Claude Code.
/// Codex names its web tool `webrun` (spike `docs/reports/codex-hooks.md`) and no `async`
/// flag is known there, so its capture hook runs inline with the 30 s timeout.
fn entries(target: Target) -> Vec<Entry> {
    let claude = target == Target::Claude;
    let cmd = |name: &str, timeout: u32, is_async: bool| {
        let mut h =
            json!({"type": "command", "command": command_for(target, name), "timeout": timeout});
        if is_async && claude {
            h["async"] = json!(true);
        }
        h
    };
    let (tools, fetch_tools) = if claude {
        (Some("WebSearch|WebFetch"), Some("WebFetch|WebSearch"))
    } else {
        (Some("webrun"), Some("webrun"))
    };
    vec![
        (
            "SessionStart",
            claude.then_some("startup"),
            cmd("session-start", 5, false),
        ),
        ("UserPromptSubmit", None, cmd("prompt", 5, false)),
        ("PreToolUse", fetch_tools, cmd("pre-fetch", 5, false)),
        ("PostToolUse", tools, cmd("post-tool", 5, false)),
        ("PostToolUse", tools, cmd("capture", 30, true)),
    ]
}

/// A command written by this module: `awm hook <name>`, or `<path>/awm hook <name>`.
fn is_ours(hook: &Value) -> bool {
    let Some(c) = hook["command"].as_str() else {
        return false;
    };
    if c.starts_with(COMMAND_PREFIX) {
        return true;
    }
    let Some((exe, name)) = c.rsplit_once(" hook ") else {
        return false;
    };
    let exe = exe.trim_matches('\'');
    std::path::Path::new(exe)
        .file_name()
        .is_some_and(|f| f == "awm")
        && !name.is_empty()
        && name.chars().all(|ch| ch.is_ascii_lowercase() || ch == '-')
}

/// Adds the entries that are not there yet. Returns how many were added.
fn add_hooks(settings: &mut Value, entries: Vec<Entry>) -> anyhow::Result<usize> {
    let root = settings
        .as_object_mut()
        .ok_or_else(|| anyhow!("the hooks file is not a JSON object"))?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| anyhow!("\"hooks\" in the hooks file is not an object"))?;
    let mut added = 0;
    for (event, matcher, hook) in entries {
        let groups = hooks
            .entry(event)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| anyhow!("hooks.{event} in the hooks file is not an array"))?;
        // An older entry of ours under another matcher (a `WebFetch` group from before the
        // search deny) would run the same hook twice; a group it leaves empty goes too.
        for g in groups.iter_mut() {
            if g["matcher"].as_str() == matcher {
                continue;
            }
            if let Some(hs) = g["hooks"].as_array_mut() {
                let before = hs.len();
                hs.retain(|h| !(is_ours(h) && h["command"] == hook["command"]));
                if hs.is_empty() && before > 0 {
                    g["hooks"] = Value::Null;
                }
            }
        }
        groups.retain(|g| !g["hooks"].is_null());
        let present = groups.iter().any(|g| {
            g["hooks"]
                .as_array()
                .is_some_and(|hs| hs.iter().any(|h| h["command"] == hook["command"]))
        });
        if present {
            continue;
        }
        let same_group = groups.iter_mut().find(|g| {
            g["matcher"].as_str() == matcher
                && g["hooks"]
                    .as_array()
                    .is_some_and(|hs| hs.iter().all(is_ours))
        });
        match same_group {
            Some(g) => g["hooks"].as_array_mut().expect("checked").push(hook),
            None => {
                let mut g = json!({"hooks": [hook]});
                if let Some(m) = matcher {
                    g["matcher"] = json!(m);
                }
                groups.push(g);
            }
        }
        added += 1;
    }
    Ok(added)
}

/// Removes every entry written by [`add_hooks`], and empty groups, events and `hooks`.
fn remove_hooks(settings: &mut Value) -> usize {
    let Some(root) = settings.as_object_mut() else {
        return 0;
    };
    let mut removed = 0;
    if let Some(hooks) = root.get_mut("hooks").and_then(Value::as_object_mut) {
        for groups in hooks.values_mut() {
            let Some(groups) = groups.as_array_mut() else {
                continue;
            };
            for g in groups.iter_mut() {
                if let Some(hs) = g["hooks"].as_array_mut() {
                    let before = hs.len();
                    hs.retain(|h| !is_ours(h));
                    removed += before - hs.len();
                }
            }
            groups.retain(|g| g["hooks"].as_array().is_none_or(|hs| !hs.is_empty()));
        }
        hooks.retain(|_, v| v.as_array().is_none_or(|a| !a.is_empty()));
    }
    if root
        .get("hooks")
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty)
    {
        root.remove("hooks");
    }
    removed
}

pub fn settings_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".claude").join("settings.json"))
}

/// The Codex hooks file: `$CODEX_HOME/hooks.json`, else `~/.codex/hooks.json`.
pub fn codex_hooks_path() -> anyhow::Result<PathBuf> {
    match std::env::var_os("CODEX_HOME").filter(|h| !h.is_empty()) {
        Some(dir) => Ok(PathBuf::from(dir).join("hooks.json")),
        None => {
            let home = std::env::var_os("HOME")
                .filter(|h| !h.is_empty())
                .ok_or_else(|| anyhow!("HOME is not set"))?;
            Ok(PathBuf::from(home).join(".codex").join("hooks.json"))
        }
    }
}

/// Returned when a Codex change needs a confirmation and there is no terminal.
#[derive(Debug)]
struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

pub fn run(args: Args) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let path = if args.codex_hooks || args.remove_codex_hooks {
        codex_hooks_path()?
    } else {
        settings_path()?
    };
    let result = run_with(
        &args,
        &path,
        stdin.is_terminal(),
        &mut stdin.lock(),
        &mut std::io::stdout().lock(),
    );
    if let Err(e) = &result {
        if e.downcast_ref::<Refused>().is_some() {
            eprintln!("awm: {e}");
            std::process::exit(2);
        }
    }
    result
}

pub fn run_with(
    args: &Args,
    path: &Path,
    terminal: bool,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let adding = args.hooks_in_settings || args.codex_hooks;
    let removing = args.remove_hooks || args.remove_codex_hooks;
    if !adding && !removing {
        bail!("choose --hooks-in-settings, --remove-hooks, --codex-hooks or --remove-codex-hooks");
    }
    let codex = args.codex_hooks || args.remove_codex_hooks;
    let target = if codex { Target::Codex } else { Target::Claude };
    let flag = match (args.hooks_in_settings, args.remove_hooks, args.codex_hooks) {
        (true, _, _) => "--hooks-in-settings",
        (_, true, _) => "--remove-hooks",
        (_, _, true) => "--codex-hooks",
        _ => "--remove-codex-hooks",
    };
    let (mut settings, existed) = match std::fs::read_to_string(path) {
        Ok(text) => (
            serde_json::from_str::<Value>(&text).with_context(|| {
                format!("{} is not valid JSON; nothing changed", path.display())
            })?,
            true,
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (json!({}), false),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let before = settings.clone();
    let changed = if adding {
        add_hooks(&mut settings, entries(target))?
    } else {
        remove_hooks(&mut settings)
    };
    if changed == 0 {
        writeln!(
            out,
            "{}: nothing to {}.",
            path.display(),
            if adding { "add" } else { "remove" }
        )?;
        return Ok(());
    }
    writeln!(
        out,
        "{} {changed} hook entries {} {}:",
        if adding { "Adding" } else { "Removing" },
        if adding { "to" } else { "from" },
        path.display()
    )?;
    for (event, matcher, hook) in entries(target) {
        writeln!(
            out,
            "  {event} {} -> {}",
            matcher.unwrap_or("(all)"),
            hook["command"].as_str().unwrap_or("")
        )?;
    }
    if codex {
        writeln!(
            out,
            "Codex hooks use the absolute path of this binary because Codex may not inherit PATH. \
             Codex has no known async flag, so `hook capture` runs inline (timeout 30)."
        )?;
    }
    if !args.yes {
        if !terminal {
            let msg = format!(
                "no terminal for confirmation; nothing changed. Re-run with --yes: awm setup {flag} --yes"
            );
            if codex {
                return Err(Refused(msg).into());
            }
            bail!(msg);
        }
        write!(out, "Continue? [y/N] ")?;
        out.flush()?;
        let mut answer = String::new();
        input.read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            writeln!(out, "Nothing changed.")?;
            return Ok(());
        }
    }
    if existed {
        let backup = PathBuf::from(format!("{}.awm-backup", path.display()));
        if !backup.exists() {
            std::fs::copy(path, &backup)
                .with_context(|| format!("cannot write the backup {}", backup.display()))?;
            writeln!(out, "Backup: {}", backup.display())?;
        }
    } else if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    debug_assert_ne!(before, settings);
    let mut text = serde_json::to_string_pretty(&settings)?;
    text.push('\n');
    std::fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))?;
    if args.codex_hooks {
        writeln!(
            out,
            "Codex hooks added to {}. Codex loads this file at start; hooks you did not add through /hooks must be trusted once: run codex, type /hooks, and trust the awm entries.",
            path.display()
        )?;
    } else if args.remove_codex_hooks {
        writeln!(out, "Codex hooks removed from {}.", path.display())?;
    } else {
        writeln!(out, "Done.")?;
    }
    Ok(())
}
