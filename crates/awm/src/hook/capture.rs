//! Hook stub (implemented in a later task).

use super::HookArgs;

pub fn run(_args: HookArgs) -> anyhow::Result<()> {
    anyhow::bail!("not implemented")
}
