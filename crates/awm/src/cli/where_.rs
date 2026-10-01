//! `awm where`: data locations and sizes.

use std::path::Path;

use crate::paths;

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
    Ok(())
}
