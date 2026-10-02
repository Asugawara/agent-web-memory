//! Data directory layout (plan-v2 §5.7).
//!
//! The data dir is `AWM_HOME` when it is set and non-empty, else
//! `directories::BaseDirs::data_dir()` joined with `agent-web-memory`
//! (`~/Library/Application Support/agent-web-memory` on macOS,
//! `$XDG_DATA_HOME/agent-web-memory` or `~/.local/share/agent-web-memory` on Linux).
//! It is never `${CLAUDE_PLUGIN_DATA}`, which Claude Code deletes on uninstall.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};

/// Environment variable that overrides the data dir.
pub const AWM_HOME: &str = "AWM_HOME";
/// Directory name under the platform data dir.
pub const APP_DIR: &str = "agent-web-memory";
/// Database file name inside the data dir.
pub const DB_FILE: &str = "awm.db";
/// Configuration file name inside the data dir.
pub const CONFIG_FILE: &str = "config.toml";
/// Spool directory name inside the data dir.
pub const SPOOL_DIR: &str = "spool";
/// Scratch directory inside the data dir (mode 0700): calibration's database copies.
pub const TMP_DIR: &str = "tmp";

/// The data dir, from the process environment.
pub fn data_dir() -> anyhow::Result<PathBuf> {
    data_dir_from(std::env::var_os(AWM_HOME))
}

/// The data dir for a given `AWM_HOME` value (`None` or empty means unset).
/// Lets callers and tests resolve the path without touching process-wide env.
pub fn data_dir_from(awm_home: Option<OsString>) -> anyhow::Result<PathBuf> {
    match awm_home {
        Some(home) if !home.is_empty() => Ok(PathBuf::from(home)),
        _ => {
            let base = directories::BaseDirs::new()
                .ok_or_else(|| anyhow!("cannot find the home directory; set {AWM_HOME}"))?;
            Ok(base.data_dir().join(APP_DIR))
        }
    }
}

/// `{data_dir}/awm.db`.
pub fn db_path() -> anyhow::Result<PathBuf> {
    Ok(data_dir()?.join(DB_FILE))
}

/// `{data_dir}/config.toml`.
pub fn config_path() -> anyhow::Result<PathBuf> {
    Ok(data_dir()?.join(CONFIG_FILE))
}

/// `{data_dir}/spool`.
pub fn spool_dir() -> anyhow::Result<PathBuf> {
    Ok(data_dir()?.join(SPOOL_DIR))
}

/// Creates the data dir with mode 0700 if it is missing and returns it.
pub fn ensure_data_dir() -> anyhow::Result<PathBuf> {
    let dir = data_dir()?;
    ensure_private_dir(&dir)?;
    Ok(dir)
}

/// Creates `dir` (and missing parents) with mode 0700 on unix if it does not
/// exist. An existing directory is left as it is.
pub fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("cannot create directory {}", dir.display()))?;
    // The umask can only remove bits; set the mode explicitly so it is exactly 0700.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot set mode 0700 on {}", dir.display()))?;
    }
    Ok(())
}
