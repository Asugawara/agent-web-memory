//! Claude Code hook entry points.

pub mod capture;
pub mod post_tool;
pub mod pre_fetch;
pub mod prompt;
pub mod session_start;

#[derive(clap::Args, Debug, Default)]
pub struct HookArgs {
    /// Version of the plugin that invoked the hook.
    #[arg(long)]
    pub plugin_version: Option<String>,
}
