//! `awm where`: data locations and sizes.

use std::path::Path;

use crate::paths;

use crate::paths::{TEAM_KEY, TEAM_TOML};

#[derive(clap::Args, Debug, Default)]
pub struct Args {}

fn size_of(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(m) => format!("{} bytes", m.len()),
        Err(_) => "not created".to_string(),
    }
}

pub fn run(_args: Args) -> anyhow::Result<()> {
    let dir = paths::data_dir()?;
    let db = paths::db_path()?;
    let wal = dir.join(format!("{}-wal", paths::DB_FILE));
    let spool = paths::spool_dir()?;
    let spooled = std::fs::read_dir(&spool).map_or(0, Iterator::count);
    println!("data dir: {}", dir.display());
    println!("database: {} ({})", db.display(), size_of(&db));
    println!("wal:      {} ({})", wal.display(), size_of(&wal));
    println!(
        "config:   {} ({})",
        paths::config_path()?.display(),
        size_of(&paths::config_path()?)
    );
    println!("spool:    {} ({spooled} files)", spool.display());
    // Only a machine in a team has these (plan-v3-team §4.7); the output is unchanged without one.
    let team_toml = dir.join(TEAM_TOML);
    if team_toml.exists() {
        let team_key = dir.join(TEAM_KEY);
        println!(
            "team:     {} ({})",
            team_toml.display(),
            size_of(&team_toml)
        );
        println!("team key: {} ({})", team_key.display(), size_of(&team_key));
    }
    Ok(())
}
