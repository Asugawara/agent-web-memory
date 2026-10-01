//! Configuration (`{data_dir}/config.toml`, plan-v2 §5.7). A missing file means defaults.

use std::path::Path;

use anyhow::{anyhow, bail, Context};
use serde::{Deserialize, Deserializer, Serialize};

macro_rules! string_enum {
    ($(#[$m:meta])* $name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            $(#[serde(rename = $text)] $variant),+
        }

        impl $name {
            pub fn as_str(&self) -> &'static str {
                match self { $($name::$variant => $text),+ }
            }

            pub fn parse(s: &str) -> Option<$name> {
                match s { $($text => Some($name::$variant),)+ _ => None }
            }
        }
    };
}

string_enum!(
    /// `mode`.
    Mode { Inject => "inject", Shadow => "shadow", Off => "off" }
);
string_enum!(
    /// `notify`.
    Notify { First => "first", Always => "always", Never => "never" }
);
string_enum!(
    /// `channels.prompt_bm25`.
    PromptBm25 { Off => "off", Shadow => "shadow", Inject => "inject" }
);
string_enum!(
    /// `short_circuit.mode`.
    ShortCircuitMode { Off => "off", Shadow => "shadow", On => "on" }
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Channels {
    pub url: bool,
    pub query: bool,
    pub prompt_url: bool,
    pub prompt_bm25: PromptBm25,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShortCircuit {
    pub mode: ShortCircuitMode,
    #[serde(deserialize_with = "de_u32")]
    pub window_minutes: u32,
    pub subagents: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Inject {
    #[serde(deserialize_with = "de_u32")]
    pub max_notes: u32,
    #[serde(deserialize_with = "de_u32")]
    pub max_per_agent: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Hooks {
    #[serde(deserialize_with = "de_u32")]
    pub deadline_ms: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureConfig {
    pub exclude_hosts: Vec<String>,
    pub redact_terms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Review {
    #[serde(deserialize_with = "de_u32")]
    pub daily_limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub mode: Mode,
    pub notify: Notify,
    pub channels: Channels,
    pub short_circuit: ShortCircuit,
    pub inject: Inject,
    pub hooks: Hooks,
    pub capture: CaptureConfig,
    pub review: Review,
    /// Out-of-range values that [`load`] clamped; never written by [`Config::save`].
    #[serde(skip)]
    pub warnings: Vec<String>,
}

impl Default for Channels {
    fn default() -> Self {
        Channels {
            url: true,
            query: true,
            prompt_url: true,
            prompt_bm25: PromptBm25::Off,
        }
    }
}

impl Default for ShortCircuit {
    fn default() -> Self {
        ShortCircuit {
            mode: ShortCircuitMode::Shadow,
            window_minutes: 30,
            subagents: false,
        }
    }
}

impl Default for Inject {
    fn default() -> Self {
        Inject {
            max_notes: 3,
            max_per_agent: 10,
        }
    }
}

impl Default for Hooks {
    fn default() -> Self {
        Hooks { deadline_ms: 500 }
    }
}

impl Default for Review {
    fn default() -> Self {
        Review { daily_limit: 10 }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::Inject,
            notify: Notify::First,
            channels: Channels::default(),
            short_circuit: ShortCircuit::default(),
            inject: Inject::default(),
            hooks: Hooks::default(),
            capture: CaptureConfig::default(),
            review: Review::default(),
            warnings: Vec::new(),
        }
    }
}

/// Reads an integer of any sign; negative numbers become 0 so that [`Config::clamp`]
/// can report them like any other out-of-range value.
fn de_u32<'de, D: Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    let v = i64::deserialize(d)?;
    Ok(u32::try_from(v.clamp(0, i64::from(u32::MAX))).unwrap_or(u32::MAX))
}

/// Allowed range of a numeric key (plan-v2 §5.7).
fn range(key: &str) -> Option<(u32, u32)> {
    Some(match key {
        "short_circuit.window_minutes" => (1, 1440),
        "inject.max_notes" => (1, 3),
        "inject.max_per_agent" => (0, 100),
        "hooks.deadline_ms" => (100, 2000),
        "review.daily_limit" => (1, 50),
        _ => return None,
    })
}

fn clamp(key: &str, value: &mut u32, warnings: &mut Vec<String>) {
    if let Some((lo, hi)) = range(key) {
        let clamped = (*value).clamp(lo, hi);
        if clamped != *value {
            warnings.push(format!(
                "config: {key} = {value} is outside {lo}-{hi}; using {clamped}"
            ));
            *value = clamped;
        }
    }
}

impl Config {
    fn clamp_all(&mut self) {
        let mut w = Vec::new();
        clamp(
            "short_circuit.window_minutes",
            &mut self.short_circuit.window_minutes,
            &mut w,
        );
        clamp("inject.max_notes", &mut self.inject.max_notes, &mut w);
        clamp(
            "inject.max_per_agent",
            &mut self.inject.max_per_agent,
            &mut w,
        );
        clamp("hooks.deadline_ms", &mut self.hooks.deadline_ms, &mut w);
        clamp("review.daily_limit", &mut self.review.daily_limit, &mut w);
        self.warnings.extend(w);
    }

    /// Writes the configuration as TOML, creating the parent directory (0700).
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            crate::paths::ensure_private_dir(parent)?;
        }
        let text = toml::to_string_pretty(self).context("cannot serialise the configuration")?;
        std::fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))
    }

    /// The value of a dotted key as text (lists are comma-separated); `None` for an unknown key.
    pub fn get(&self, key: &str) -> Option<String> {
        Some(match key {
            "mode" => self.mode.as_str().to_string(),
            "notify" => self.notify.as_str().to_string(),
            "channels.url" => self.channels.url.to_string(),
            "channels.query" => self.channels.query.to_string(),
            "channels.prompt_url" => self.channels.prompt_url.to_string(),
            "channels.prompt_bm25" => self.channels.prompt_bm25.as_str().to_string(),
            "short_circuit.mode" => self.short_circuit.mode.as_str().to_string(),
            "short_circuit.window_minutes" => self.short_circuit.window_minutes.to_string(),
            "short_circuit.subagents" => self.short_circuit.subagents.to_string(),
            "inject.max_notes" => self.inject.max_notes.to_string(),
            "inject.max_per_agent" => self.inject.max_per_agent.to_string(),
            "hooks.deadline_ms" => self.hooks.deadline_ms.to_string(),
            "capture.exclude_hosts" => self.capture.exclude_hosts.join(","),
            "capture.redact_terms" => self.capture.redact_terms.join(","),
            "review.daily_limit" => self.review.daily_limit.to_string(),
            _ => return None,
        })
    }

    /// Sets a dotted key from text. Unknown keys, bad values and out-of-range
    /// numbers are errors and leave the configuration unchanged.
    pub fn set(&mut self, key: &str, value: &str) -> anyhow::Result<()> {
        fn pick<T>(key: &str, value: &str, parsed: Option<T>, allowed: &str) -> anyhow::Result<T> {
            parsed.ok_or_else(|| anyhow!("{key}: expected one of {allowed}, got {value:?}"))
        }
        fn flag(key: &str, value: &str) -> anyhow::Result<bool> {
            match value {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => bail!("{key}: expected true or false, got {value:?}"),
            }
        }
        fn number(key: &str, value: &str) -> anyhow::Result<u32> {
            let n: u32 = value
                .trim()
                .parse()
                .map_err(|_| anyhow!("{key}: expected a whole number, got {value:?}"))?;
            if let Some((lo, hi)) = range(key) {
                if !(lo..=hi).contains(&n) {
                    bail!("{key}: {n} is outside {lo}-{hi}");
                }
            }
            Ok(n)
        }
        fn list(value: &str) -> Vec<String> {
            value
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        }
        match key {
            "mode" => self.mode = pick(key, value, Mode::parse(value), "inject, shadow, off")?,
            "notify" => {
                self.notify = pick(key, value, Notify::parse(value), "first, always, never")?
            }
            "channels.url" => self.channels.url = flag(key, value)?,
            "channels.query" => self.channels.query = flag(key, value)?,
            "channels.prompt_url" => self.channels.prompt_url = flag(key, value)?,
            "channels.prompt_bm25" => {
                self.channels.prompt_bm25 =
                    pick(key, value, PromptBm25::parse(value), "off, shadow, inject")?
            }
            "short_circuit.mode" => {
                self.short_circuit.mode = pick(
                    key,
                    value,
                    ShortCircuitMode::parse(value),
                    "off, shadow, on",
                )?
            }
            "short_circuit.window_minutes" => {
                self.short_circuit.window_minutes = number(key, value)?
            }
            "short_circuit.subagents" => self.short_circuit.subagents = flag(key, value)?,
            "inject.max_notes" => self.inject.max_notes = number(key, value)?,
            "inject.max_per_agent" => self.inject.max_per_agent = number(key, value)?,
            "hooks.deadline_ms" => self.hooks.deadline_ms = number(key, value)?,
            "capture.exclude_hosts" => self.capture.exclude_hosts = list(value),
            "capture.redact_terms" => self.capture.redact_terms = list(value),
            "review.daily_limit" => self.review.daily_limit = number(key, value)?,
            _ => bail!("unknown configuration key: {key}"),
        }
        Ok(())
    }
}

/// Loads the configuration. A missing file gives the defaults; unknown keys are
/// ignored; out-of-range numbers are clamped and reported in [`Config::warnings`].
pub fn load(path: &Path) -> anyhow::Result<Config> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let mut config: Config = toml::from_str(&text)
        .with_context(|| format!("invalid configuration {}", path.display()))?;
    config.clamp_all();
    Ok(config)
}
