//! `awm uninstall`: the data part of the uninstall path (plan-v2 §2.3).
//!
//! Shows the data dir, its size and record count, deletes it after
//! confirmation (the same path as `awm purge --all`), then prints the commands
//! the owner runs to remove the plugin, the marketplace entry and the binary.

use std::path::Path;

use crate::forget::{self, Io, Outcome};

/// Printed first when this machine is in a team (plan-v3-team §4.9).
const TEAM_OFFER: &str =
    "This machine is in a team. Run awm team leave first (awm team leave --delete \
also deletes your shared records from the server); deleting this directory alone leaves your \
records and this device's token on the server.";
const TEAM_QUESTION: &str = "Continue and delete the data directory without leaving the team?";

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Do not ask for confirmation
    #[arg(long)]
    pub yes: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let exe = std::env::current_exe().ok();
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let outcome = forget::with_stdio(|io| run_with(&args, io, exe.as_deref(), home.as_deref()))?;
    forget::finish(outcome)
}

pub fn run_with(
    args: &Args,
    io: &mut Io<'_>,
    exe: Option<&Path>,
    home: Option<&Path>,
) -> anyhow::Result<Outcome> {
    if io.data_dir.join(crate::paths::TEAM_TOML).exists() {
        writeln!(io.out, "{TEAM_OFFER}")?;
        if !args.yes && io.terminal {
            write!(io.out, "{TEAM_QUESTION} [y/N] ")?;
            io.out.flush()?;
            let mut answer = String::new();
            io.input.read_line(&mut answer)?;
            if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                writeln!(
                    io.out,
                    "Nothing changed. Run awm team leave (or awm team leave --delete), then awm uninstall."
                )?;
                return Ok(Outcome::Declined);
            }
        }
    }
    let (outcome, _) = forget::purge_all(io, args.yes, "awm uninstall")?;
    if matches!(outcome, Outcome::Done | Outcome::Nothing) {
        writeln!(io.out, "To finish:")?;
        writeln!(
            io.out,
            "  claude plugin uninstall agent-web-memory@agent-web-memory"
        )?;
        writeln!(
            io.out,
            "  claude plugin marketplace remove agent-web-memory"
        )?;
        writeln!(io.out, "  {}", binary_removal(exe, home))?;
    }
    Ok(outcome)
}

/// The binary removal line for the detected install method (§2.3 step 4).
pub fn binary_removal(exe: Option<&Path>, home: Option<&Path>) -> String {
    let Some(exe) = exe else {
        return "rm ~/.local/bin/awm".to_string();
    };
    let s = exe.to_string_lossy();
    if s.contains("/Cellar/")
        || s.starts_with("/opt/homebrew/")
        || s.starts_with("/home/linuxbrew/")
    {
        return "brew uninstall awm".to_string();
    }
    if let Some(home) = home {
        if exe.starts_with(home.join(".cargo").join("bin")) {
            return "cargo uninstall agent-web-memory".to_string();
        }
        if let Ok(rest) = exe.strip_prefix(home) {
            return format!("rm ~/{}", rest.display());
        }
    }
    format!("rm {}", exe.display())
}
