use awm::cli;
use awm::hook::{self, HookArgs};
use awm::{forget, import, init, matching};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "awm",
    version,
    about = "Local memory of past Web research for coding agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create the local database
    Init(init::Args),
    /// Import records from past transcripts
    Import(import::Args),
    /// Search stored records
    Search(cli::search::Args),
    /// Show the recent injection log
    Log(cli::log::Args),
    /// Show statistics
    Stats(cli::stats::Args),
    /// Review stored notes
    Review(cli::review::Args),
    /// Forget records
    Forget(forget::Args),
    /// Permanently delete records
    Purge(forget::PurgeArgs),
    /// Quarantine records
    Quarantine(forget::QuarantineArgs),
    /// Lift the quarantine on records
    Unquarantine(forget::QuarantineArgs),
    /// Check the installation
    Doctor(cli::doctor::Args),
    /// Write a report
    Report(cli::report::Args),
    /// Print the data locations
    Where(cli::where_::Args),
    /// Show or change the configuration
    Config(cli::config_cmd::Args),
    /// Export records
    Export(cli::export::Args),
    /// Rebuild the search index
    Reindex(cli::reindex::Args),
    /// Calibrate matching thresholds
    Calibrate(matching::calibrate::Args),
    /// Set up the plugin integration
    Setup(cli::setup::Args),
    /// Remove the plugin integration
    Uninstall(cli::uninstall::Args),
    #[command(hide = true, subcommand)]
    Hook(HookCommand),
    #[cfg(feature = "bench")]
    /// Check benchmark thresholds
    BenchCheck(awm::bench::Args),
}

#[derive(Subcommand, Debug)]
enum HookCommand {
    SessionStart(HookArgs),
    Prompt(HookArgs),
    PreFetch(HookArgs),
    PostTool(HookArgs),
    Capture(HookArgs),
}

fn debug_enabled() -> bool {
    std::env::var_os("AWM_DEBUG").is_some_and(|v| v == "1")
}

/// A hook always exits 0: Claude Code reads exit 2 as "block". Parse errors and
/// panics print nothing (stderr only with `AWM_DEBUG=1`).
fn run_hook() -> ! {
    if !debug_enabled() {
        std::panic::set_hook(Box::new(|_| {}));
    }
    let outcome = std::panic::catch_unwind(|| match Cli::try_parse() {
        Ok(cli) => dispatch(cli.command),
        Err(e) => {
            if debug_enabled() {
                eprintln!("awm: {e}");
            }
            Ok(())
        }
    });
    if debug_enabled() {
        match outcome {
            Ok(Err(e)) => eprintln!("awm: {e:#}"),
            Err(_) => eprintln!("awm: hook panicked"),
            Ok(Ok(())) => {}
        }
    }
    std::process::exit(0);
}

fn main() {
    if std::env::args_os().nth(1).is_some_and(|a| a == "hook") {
        run_hook();
    }
    let cli = Cli::parse();
    if let Err(err) = dispatch(cli.command) {
        eprintln!("awm: {err}");
        std::process::exit(1);
    }
}

fn dispatch(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Init(a) => init::run(a),
        Command::Import(a) => import::run(a),
        Command::Search(a) => cli::search::run(a),
        Command::Log(a) => cli::log::run(a),
        Command::Stats(a) => cli::stats::run(a),
        Command::Review(a) => cli::review::run(a),
        Command::Forget(a) => forget::run(a),
        Command::Purge(a) => forget::run_purge(a),
        Command::Quarantine(a) => forget::run_quarantine(a),
        Command::Unquarantine(a) => forget::run_unquarantine(a),
        Command::Doctor(a) => cli::doctor::run(a),
        Command::Report(a) => cli::report::run(a),
        Command::Where(a) => cli::where_::run(a),
        Command::Config(a) => cli::config_cmd::run(a),
        Command::Export(a) => cli::export::run(a),
        Command::Reindex(a) => cli::reindex::run(a),
        Command::Calibrate(a) => matching::calibrate::run_cli(a),
        Command::Setup(a) => cli::setup::run(a),
        Command::Uninstall(a) => cli::uninstall::run(a),
        Command::Hook(h) => match h {
            HookCommand::SessionStart(a) => hook::session_start::run(a),
            HookCommand::Prompt(a) => hook::prompt::run(a),
            HookCommand::PreFetch(a) => hook::pre_fetch::run(a),
            HookCommand::PostTool(a) => hook::post_tool::run(a),
            HookCommand::Capture(a) => hook::capture::run(a),
        },
        #[cfg(feature = "bench")]
        Command::BenchCheck(a) => awm::bench::run(a),
    }
}
