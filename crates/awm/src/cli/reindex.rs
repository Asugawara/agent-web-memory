//! `awm reindex`: rebuilds the full-text index.

#[derive(clap::Args, Debug, Default)]
pub struct Args {}

pub fn run(_args: Args) -> anyhow::Result<()> {
    let conn = super::open_db()?;
    conn.execute("INSERT INTO event_fts(event_fts) VALUES('rebuild')", [])?;
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0))?;
    println!("Rebuilt the search index for {n} records.");
    Ok(())
}
