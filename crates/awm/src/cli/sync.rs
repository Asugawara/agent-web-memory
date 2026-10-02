//! `awm sync ...` (plan-v3-team §4.6, §4.8). Scaffold (TM1): not implemented.

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Options (not implemented in this build)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub rest: Vec<String>,
}

pub fn run(_args: Args) -> anyhow::Result<()> {
    super::not_implemented("sync")
}
