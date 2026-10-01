//! Subcommand stub (implemented in a later task).

#[derive(clap::Args, Debug, Default)]
pub struct Args {}

pub fn run(_args: Args) -> anyhow::Result<()> {
    anyhow::bail!("not implemented")
}
