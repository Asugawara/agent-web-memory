//! `awm serve ...` (plan-v3-team §4.8.1). Scaffold (TM1): not implemented.
//! The only module that reaches `awm-server` (§4.1 item 4); compiled with the `serve` feature.

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Flags and subcommands (not implemented in this build)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub rest: Vec<String>,
}

pub fn run(_args: Args) -> anyhow::Result<()> {
    super::not_implemented("serve")
}
