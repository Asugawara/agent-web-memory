//! `awm uninstall`: the data part of the uninstall path (plan-v2 §2.3).
//!
//! Shows the data dir, its size and record count, deletes it after
//! confirmation (the same path as `awm purge --all`), then prints the commands
//! the owner runs to remove the plugin, the marketplace entry and the binary.

use std::path::Path;

use crate::forget::{self, Io, Outcome};

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
