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
    Mode { Inject => "inject", Off => "off" }
);
string_enum!(
    /// `notify`.
    Notify { First => "first", Always => "always", Never => "never" }
);
string_enum!(
    /// `channels.prompt_bm25`.
    PromptBm25 { Off => "off", Inject => "inject" }
);
string_enum!(
    /// `short_circuit.mode` and `short_circuit.query`.
    ShortCircuitMode { Off => "off", On => "on" }
);

/// What a legacy `shadow` value of each key is read as (there is no shadow mode any more):
/// key, the value it is read as, the values to choose from now.
const LEGACY_SHADOW: &[(&str, &str, &str)] = &[
    ("mode", "inject", "inject or off"),
    ("channels.prompt_bm25", "off", "inject or off"),
    ("short_circuit.mode", "on", "on or off"),
    ("short_circuit.query", "off", "on or off"),
];
/// Keys that no longer exist, with what replaces them.
const REMOVED_KEYS: &[(&str, &str)] = &[
    (
        "short_circuit.query_window_minutes",
        "the search deny window is set in days: use short_circuit.query_window_days (default 7)",
    ),
    (
        "short_circuit.window_minutes",
        "the URL deny window is set in days: use short_circuit.window_days (default 7)",
    ),
    (
        "short_circuit.subagents",
        "the URL deny applies in subagents; there is no switch",
    ),
    (
        "inject.max_per_agent",
        "there is no per-agent cap; inject.max_notes still limits one injection",
    ),
    ("quota.capture", "the usage-limit samples were removed"),
    (
        "quota.retention_days",
        "the usage-limit samples were removed",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Channels {
    pub url: bool,
    pub query: bool,
    pub prompt_url: bool,
    pub prompt_bm25: PromptBm25,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShortCircuit {
    pub mode: ShortCircuitMode,
    #[serde(deserialize_with = "de_u32")]
    pub window_days: u32,
    /// The PreToolUse deny on repeated web searches (QD1 §5.3); separate from `mode` (URLs).
    pub query: ShortCircuitMode,
    #[serde(deserialize_with = "de_u32")]
    pub query_window_days: u32,
    /// Fixed score cutoff of the search deny; `None` uses the calibrated `cutoff.query_deny`.
    pub query_min_score: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Inject {
    #[serde(deserialize_with = "de_u32")]
    pub max_notes: u32,
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

/// Team sync settings (`[team]`, plan-v3-team §4.7). Parsing and `config list` only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Team {
    pub auto_sync: bool,
    #[serde(deserialize_with = "de_u32")]
    pub sync_interval_s: u32,
    pub show: bool,
    pub mute: Vec<String>,
    pub share_all_projects: bool,
    pub exclude_hosts: Vec<String>,
    #[serde(deserialize_with = "de_u32")]
    pub summary_chars: u32,
    pub share_stats: bool,
    pub auto_approve: AutoApprove,
    #[serde(deserialize_with = "de_u32")]
    pub push_delay_s: u32,
}

string_enum!(
    /// `team.auto_approve`. `none` (the default, RVT2 m3): every join, a new device of one's
    /// own included, waits for `awm team approve --code N` on an existing device. `devices` and
    /// `all` are opt-ins that let a leaked invite string in without the code.
    AutoApprove { None => "none", Devices => "devices", All => "all" }
);

impl Default for Team {
    fn default() -> Self {
        Team {
            auto_sync: true,
            sync_interval_s: 60,
            show: true,
            mute: Vec::new(),
            share_all_projects: false,
            exclude_hosts: Vec::new(),
            summary_chars: 1000,
            share_stats: false,
            auto_approve: AutoApprove::None,
            push_delay_s: 0,
        }
    }
}

/// Prices for `awm stats --savings` (`[pricing]`); never used to bill anything.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Pricing {
    pub currency: String,
    /// Fetch summariser input, per million tokens (default: Claude Haiku 4.5).
    #[serde(deserialize_with = "de_price")]
    pub summariser_input_per_mtok: f64,
    /// Fetch summariser output (the summary it returns), per million tokens.
    #[serde(deserialize_with = "de_price")]
    pub summariser_output_per_mtok: f64,
    /// Anthropic web search fee per call.
    #[serde(deserialize_with = "de_price")]
    pub search_fee_per_call: f64,
    /// Main model input per million tokens; 0 = not priced.
    #[serde(deserialize_with = "de_price")]
    pub main_input_per_mtok: f64,
}

impl Default for Pricing {
    fn default() -> Self {
        Pricing {
            currency: "USD".into(),
            summariser_input_per_mtok: 1.0,
            summariser_output_per_mtok: 5.0,
            search_fee_per_call: 0.01,
            main_input_per_mtok: 0.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    pub pricing: Pricing,
    pub team: Team,
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
            mode: ShortCircuitMode::On,
            window_days: 7,
            query: ShortCircuitMode::On,
            query_window_days: 7,
            query_min_score: None,
        }
    }
}

impl Default for Inject {
    fn default() -> Self {
        Inject { max_notes: 3 }
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
            pricing: Pricing::default(),
            team: Team::default(),
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

/// Allowed range of `short_circuit.query_min_score`.
const QUERY_MIN_SCORE: (f64, f64) = (0.0, 1000.0);

/// A price: a finite number that is not negative (an error naming the field, unlike the clamped integers).
fn de_price<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    let v = f64::deserialize(d)?;
    if v.is_finite() && v >= 0.0 {
        Ok(v)
    } else {
        Err(serde::de::Error::custom(format!(
            "pricing value must be a number >= 0, got {v}"
        )))
    }
}

/// Allowed range of a numeric key (plan-v2 §5.7).
fn range(key: &str) -> Option<(u32, u32)> {
    Some(match key {
        "short_circuit.window_days" => (1, 365),
        "short_circuit.query_window_days" => (1, 365),
        "inject.max_notes" => (1, 3),
        "hooks.deadline_ms" => (100, 2000),
        "review.daily_limit" => (1, 50),
        "team.sync_interval_s" => (0, 86400),
        "team.summary_chars" => (1, 2000),
        "team.push_delay_s" => (0, 86400),
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
            "short_circuit.window_days",
            &mut self.short_circuit.window_days,
            &mut w,
        );
        clamp(
            "short_circuit.query_window_days",
            &mut self.short_circuit.query_window_days,
            &mut w,
        );
        if let Some(v) = self.short_circuit.query_min_score {
            let (lo, hi) = QUERY_MIN_SCORE;
            if !v.is_finite() {
                w.push("config: short_circuit.query_min_score is not a number; using the calibrated cutoff".into());
                self.short_circuit.query_min_score = None;
            } else if !(lo..=hi).contains(&v) {
                let c = v.clamp(lo, hi);
                w.push(format!(
                    "config: short_circuit.query_min_score = {v} is outside {lo}-{hi}; using {c}"
                ));
                self.short_circuit.query_min_score = Some(c);
            }
        }
        clamp("inject.max_notes", &mut self.inject.max_notes, &mut w);
        clamp("hooks.deadline_ms", &mut self.hooks.deadline_ms, &mut w);
        clamp("review.daily_limit", &mut self.review.daily_limit, &mut w);
        clamp(
            "team.sync_interval_s",
            &mut self.team.sync_interval_s,
            &mut w,
        );
        clamp("team.summary_chars", &mut self.team.summary_chars, &mut w);
        clamp("team.push_delay_s", &mut self.team.push_delay_s, &mut w);
        self.warnings.extend(w);
    }

    /// Writes the configuration as TOML, creating the parent directory (0700).
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            crate::paths::ensure_private_dir(parent)?;
        }
        let text = toml::to_string_pretty(self).context("cannot serialise the configuration")?;
        write_private(path, &text).with_context(|| format!("cannot write {}", path.display()))
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
            "short_circuit.window_days" => self.short_circuit.window_days.to_string(),
            "short_circuit.query" => self.short_circuit.query.as_str().to_string(),
            "short_circuit.query_window_days" => self.short_circuit.query_window_days.to_string(),
            "short_circuit.query_min_score" => self
                .short_circuit
                .query_min_score
                .map_or_else(|| "auto".to_string(), |v| v.to_string()),
            "inject.max_notes" => self.inject.max_notes.to_string(),
            "hooks.deadline_ms" => self.hooks.deadline_ms.to_string(),
            "capture.exclude_hosts" => self.capture.exclude_hosts.join(","),
            "capture.redact_terms" => self.capture.redact_terms.join(","),
            "review.daily_limit" => self.review.daily_limit.to_string(),
            "pricing.currency" => self.pricing.currency.clone(),
            "pricing.summariser_input_per_mtok" => {
                self.pricing.summariser_input_per_mtok.to_string()
            }
            "pricing.summariser_output_per_mtok" => {
                self.pricing.summariser_output_per_mtok.to_string()
            }
            "pricing.search_fee_per_call" => self.pricing.search_fee_per_call.to_string(),
            "pricing.main_input_per_mtok" => self.pricing.main_input_per_mtok.to_string(),
            "team.auto_sync" => self.team.auto_sync.to_string(),
            "team.sync_interval_s" => self.team.sync_interval_s.to_string(),
            "team.show" => self.team.show.to_string(),
            "team.mute" => self.team.mute.join(","),
            "team.share_all_projects" => self.team.share_all_projects.to_string(),
            "team.exclude_hosts" => self.team.exclude_hosts.join(","),
            "team.summary_chars" => self.team.summary_chars.to_string(),
            "team.share_stats" => self.team.share_stats.to_string(),
            "team.auto_approve" => self.team.auto_approve.as_str().to_string(),
            "team.push_delay_s" => self.team.push_delay_s.to_string(),
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
        fn price(key: &str, value: &str) -> anyhow::Result<f64> {
            match value.trim().parse::<f64>() {
                Ok(n) if n.is_finite() && n >= 0.0 => Ok(n),
                _ => bail!("{key}: expected a number >= 0, got {value:?}"),
            }
        }
        // `auto` (or empty) clears the override: the calibrated cutoff applies.
        fn score(key: &str, value: &str) -> anyhow::Result<Option<f64>> {
            let v = value.trim();
            if v.is_empty() || v == "auto" {
                return Ok(None);
            }
            match v.parse::<f64>() {
                Ok(n) if n.is_finite() && (QUERY_MIN_SCORE.0..=QUERY_MIN_SCORE.1).contains(&n) => {
                    Ok(Some(n))
                }
                _ => bail!(
                    "{key}: expected auto or a number in {}-{}, got {value:?}",
                    QUERY_MIN_SCORE.0,
                    QUERY_MIN_SCORE.1
                ),
            }
        }
        fn list(value: &str) -> Vec<String> {
            value
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        }
        // A list of team handles, `@` optional; the offending value is not echoed.
        fn handles(key: &str, value: &str) -> anyhow::Result<Vec<String>> {
            let mut out = Vec::new();
            for (i, item) in list(value).iter().enumerate() {
                let h = item.strip_prefix('@').unwrap_or(item);
                let ok = (1..=24).contains(&h.len())
                    && h.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'
                    });
                if !ok {
                    bail!(
                        "{key}: entry {} is not a handle ([a-z0-9_-], 1-24 characters)",
                        i + 1
                    );
                }
                out.push(h.to_string());
            }
            Ok(out)
        }
        // A list of host names: letters, digits, `-` and `.`, no scheme, port or path.
        fn hosts(key: &str, value: &str) -> anyhow::Result<Vec<String>> {
            let mut out = Vec::new();
            for (i, item) in list(value).iter().enumerate() {
                let h = item.to_ascii_lowercase();
                let labels_ok = h
                    .split('.')
                    .all(|l| !l.is_empty() && !l.starts_with('-') && !l.ends_with('-'));
                let ok = h.len() <= 253
                    && labels_ok
                    && h.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'
                    });
                if !ok {
                    bail!(
                        "{key}: entry {} is not a host name (for example docs.example.com)",
                        i + 1
                    );
                }
                out.push(h);
            }
            Ok(out)
        }
        if value == "shadow" {
            if let Some((_, instead, choices)) = LEGACY_SHADOW.iter().find(|(k, ..)| *k == key) {
                bail!(
                    "{key}: shadow mode was removed (an old file reads it as {instead:?}); use {choices}"
                );
            }
        }
        match key {
            "mode" => self.mode = pick(key, value, Mode::parse(value), "inject, off")?,
            "notify" => {
                self.notify = pick(key, value, Notify::parse(value), "first, always, never")?
            }
            "channels.url" => self.channels.url = flag(key, value)?,
            "channels.query" => self.channels.query = flag(key, value)?,
            "channels.prompt_url" => self.channels.prompt_url = flag(key, value)?,
            "channels.prompt_bm25" => {
                self.channels.prompt_bm25 =
                    pick(key, value, PromptBm25::parse(value), "off, inject")?
            }
            "short_circuit.mode" => {
                self.short_circuit.mode =
                    pick(key, value, ShortCircuitMode::parse(value), "on, off")?
            }
            "short_circuit.window_days" => self.short_circuit.window_days = number(key, value)?,
            "short_circuit.query" => {
                self.short_circuit.query =
                    pick(key, value, ShortCircuitMode::parse(value), "on, off")?
            }
            "short_circuit.query_window_days" => {
                self.short_circuit.query_window_days = number(key, value)?
            }
            "short_circuit.query_min_score" => {
                self.short_circuit.query_min_score = score(key, value)?
            }
            "inject.max_notes" => self.inject.max_notes = number(key, value)?,
            "hooks.deadline_ms" => self.hooks.deadline_ms = number(key, value)?,
            "capture.exclude_hosts" => self.capture.exclude_hosts = list(value),
            "capture.redact_terms" => self.capture.redact_terms = list(value),
            "review.daily_limit" => self.review.daily_limit = number(key, value)?,
            "pricing.currency" => {
                let v = value.trim();
                if v.is_empty() {
                    bail!("{key}: expected a currency code, got {value:?}");
                }
                self.pricing.currency = v.to_string();
            }
            "pricing.summariser_input_per_mtok" => {
                self.pricing.summariser_input_per_mtok = price(key, value)?
            }
            "pricing.summariser_output_per_mtok" => {
                self.pricing.summariser_output_per_mtok = price(key, value)?
            }
            "pricing.search_fee_per_call" => self.pricing.search_fee_per_call = price(key, value)?,
            "pricing.main_input_per_mtok" => self.pricing.main_input_per_mtok = price(key, value)?,
            "team.auto_sync" => self.team.auto_sync = flag(key, value)?,
            "team.sync_interval_s" => self.team.sync_interval_s = number(key, value)?,
            "team.show" => self.team.show = flag(key, value)?,
            "team.mute" => self.team.mute = handles(key, value)?,
            "team.share_all_projects" => self.team.share_all_projects = flag(key, value)?,
            "team.exclude_hosts" => self.team.exclude_hosts = hosts(key, value)?,
            "team.summary_chars" => self.team.summary_chars = number(key, value)?,
            "team.share_stats" => self.team.share_stats = flag(key, value)?,
            "team.auto_approve" => {
                self.team.auto_approve =
                    pick(key, value, AutoApprove::parse(value), "none, devices, all")?
            }
            "team.push_delay_s" => self.team.push_delay_s = number(key, value)?,
            _ => match REMOVED_KEYS.iter().find(|(k, _)| *k == key) {
                Some((_, replacement)) => bail!("{key} was removed: {replacement}"),
                None => bail!("unknown configuration key: {key}"),
            },
        }
        Ok(())
    }
}

/// Loads the configuration. A missing file gives the defaults; unknown keys (the removed
/// `short_circuit.subagents` and `inject.max_per_agent` among them) are ignored; the legacy
/// value `shadow` is read as in [`LEGACY_SHADOW`]; out-of-range numbers are clamped and reported
/// in [`Config::warnings`].
pub fn load(path: &Path) -> anyhow::Result<Config> {
    Ok(load_with_legacy(path)?.0)
}

/// [`load`] plus one line per legacy value or removed key found in the file (`awm doctor`).
pub fn load_with_legacy(path: &Path) -> anyhow::Result<(Config, Vec<String>)> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Config::default(), Vec::new()))
        }
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let invalid = || format!("invalid configuration {}", path.display());
    let mut table: toml::Table = toml::from_str(&text).with_context(invalid)?;
    let legacy = rewrite_legacy(&mut table);
    let mut config: Config = table.try_into().with_context(invalid)?;
    config.clamp_all();
    Ok((config, legacy))
}

/// Replaces `shadow` values and drops removed keys in place; returns a line for each.
fn rewrite_legacy(table: &mut toml::Table) -> Vec<String> {
    let mut lines = Vec::new();
    for (key, replacement, choices) in LEGACY_SHADOW {
        let slot = match key.split_once('.') {
            Some((section, name)) => table
                .get_mut(section)
                .and_then(toml::Value::as_table_mut)
                .and_then(|t| t.get_mut(name)),
            None => table.get_mut(*key),
        };
        let Some(slot) = slot else { continue };
        if slot.as_str() == Some("shadow") {
            *slot = toml::Value::String((*replacement).to_string());
            lines.push(format!(
                "config: {key} = \"shadow\" is read as \"{replacement}\"; set it to {choices}"
            ));
        }
    }
    for (key, replacement) in REMOVED_KEYS {
        let Some((section, name)) = key.split_once('.') else {
            continue;
        };
        let removed = table
            .get_mut(section)
            .and_then(toml::Value::as_table_mut)
            .and_then(|t| t.remove(name));
        if removed.is_some() {
            lines.push(format!(
                "config: {key} was removed and is ignored: {replacement}"
            ));
        }
    }
    lines
}

/// Writes `text` to `path`; the file is 0600 on unix (`capture.redact_terms` may hold names).
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        open.mode(0o600);
        let mut f = open.open(path)?;
        // An existing file keeps its old mode through `open`.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(text.as_bytes())
    }
    #[cfg(not(unix))]
    {
        open.open(path)?.write_all(text.as_bytes())
    }
}
