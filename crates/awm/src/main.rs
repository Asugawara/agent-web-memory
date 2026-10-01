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
    Purge(forget::Args),
    /// Quarantine records
    Quarantine(forget::Args),
    /// Lift the quarantine on records
    Unquarantine(forget::Args),
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

fn main() {
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
        Command::Calibrate(a) => matching::calibrate::run(a),
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
