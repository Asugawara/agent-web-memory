//! `awm setup`: writes or removes the hook entries in `~/.claude/settings.json` (plan-v2 §5.6).
//!
//! Only runs when the user asks. Shows what it adds, keeps a backup, and never
//! touches entries it did not write (a command starting with `awm hook `).

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
    /// Do not ask for confirmation
    #[arg(long)]
    pub yes: bool,
}

/// (event, matcher, hook) entries, as in `plugin/hooks/hooks.json`.
fn entries() -> Vec<(&'static str, Option<&'static str>, Value)> {
    let cmd = |name: &str, timeout: u32, is_async: bool| {
        let mut h = json!({"type": "command", "command": format!("{COMMAND_PREFIX}{name}"), "timeout": timeout});
        if is_async {
            h["async"] = json!(true);
        }
        h
    };
    vec![
        (
            "SessionStart",
            Some("startup"),
            cmd("session-start", 5, false),
        ),
        ("UserPromptSubmit", None, cmd("prompt", 5, false)),
        ("PreToolUse", Some("WebFetch"), cmd("pre-fetch", 5, false)),
        (
            "PostToolUse",
            Some("WebSearch|WebFetch"),
            cmd("post-tool", 5, false),
        ),
        (
            "PostToolUse",
            Some("WebSearch|WebFetch"),
            cmd("capture", 30, true),
        ),
    ]
}

fn is_ours(hook: &Value) -> bool {
    hook["command"]
        .as_str()
        .is_some_and(|c| c.starts_with(COMMAND_PREFIX))
}

/// Adds the entries that are not there yet. Returns how many were added.
pub fn add_hooks(settings: &mut Value) -> anyhow::Result<usize> {
    let root = settings
        .as_object_mut()
        .ok_or_else(|| anyhow!("settings.json is not a JSON object"))?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| anyhow!("\"hooks\" in settings.json is not an object"))?;
    let mut added = 0;
    for (event, matcher, hook) in entries() {
        let groups = hooks
            .entry(event)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| anyhow!("hooks.{event} in settings.json is not an array"))?;
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
pub fn remove_hooks(settings: &mut Value) -> usize {
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

pub fn run(args: Args) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    run_with(
        &args,
        &settings_path()?,
        stdin.is_terminal(),
        &mut stdin.lock(),
        &mut std::io::stdout().lock(),
    )
}

pub fn run_with(
    args: &Args,
    path: &Path,
    terminal: bool,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    if !args.hooks_in_settings && !args.remove_hooks {
        bail!("choose --hooks-in-settings or --remove-hooks");
    }
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
    let changed = if args.hooks_in_settings {
        add_hooks(&mut settings)?
    } else {
        remove_hooks(&mut settings)
    };
    if changed == 0 {
        writeln!(
            out,
            "{}: nothing to {}.",
            path.display(),
            if args.hooks_in_settings {
                "add"
            } else {
                "remove"
            }
        )?;
        return Ok(());
    }
    writeln!(
        out,
        "{} {changed} hook entries {} {}:",
        if args.hooks_in_settings {
            "Adding"
        } else {
            "Removing"
        },
        if args.hooks_in_settings { "to" } else { "from" },
        path.display()
    )?;
    for (event, matcher, hook) in entries() {
        writeln!(
            out,
            "  {event} {} -> {}",
            matcher.unwrap_or("(all)"),
            hook["command"].as_str().unwrap_or("")
        )?;
    }
    if !args.yes {
        if !terminal {
            bail!(
                "no terminal for confirmation; nothing changed. Re-run with --yes: awm setup {} --yes",
                if args.hooks_in_settings { "--hooks-in-settings" } else { "--remove-hooks" }
            );
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
    writeln!(out, "Done.")?;
    Ok(())
}
