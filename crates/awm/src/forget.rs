//! Subcommand stubs for `forget`, `purge`, `quarantine` and `unquarantine` (implemented in a later task).

#[derive(clap::Args, Debug, Default)]
pub struct Args {}

pub fn run(_args: Args) -> anyhow::Result<()> {
    anyhow::bail!("not implemented")
}

pub fn run_purge(_args: Args) -> anyhow::Result<()> {
    anyhow::bail!("not implemented")
}

pub fn run_quarantine(_args: Args) -> anyhow::Result<()> {
    anyhow::bail!("not implemented")
}

pub fn run_unquarantine(_args: Args) -> anyhow::Result<()> {
    anyhow::bail!("not implemented")
}
