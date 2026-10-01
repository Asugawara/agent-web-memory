//! `awm export`: JSONL of every record. The format is unstable until 1.0.

use std::io::Write;
use std::path::PathBuf;

use anyhow::Context;
use rusqlite::Connection;
use serde_json::json;

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Write to FILE instead of standard output
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let conn = super::open_db()?;
    match &args.out {
        Some(path) => {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let file = opts
                .open(path)
                .with_context(|| format!("cannot write {}", path.display()))?;
            let mut w = std::io::BufWriter::new(file);
            let n = write_all(&conn, &mut w)?;
            w.flush()?;
            println!("Exported {n} records to {}.", path.display());
        }
        None => {
            let mut w = std::io::BufWriter::new(std::io::stdout().lock());
            write_all(&conn, &mut w)?;
            w.flush()?;
        }
    }
    Ok(())
}

/// Header line, then one line per event. Returns the number of events.
pub fn write_all(conn: &Connection, w: &mut dyn Write) -> anyhow::Result<usize> {
    let header = json!({
        "format": "awm-export/0",
        "version": env!("CARGO_PKG_VERSION"),
        "exported_at": super::now_ms(),
    });
    writeln!(w, "{header}")?;
    let mut results = conn.prepare(
        "SELECT rank, url, url_norm, title FROM result WHERE event_id = ?1 ORDER BY rank",
    )?;
    let mut st = conn.prepare(
        "SELECT id, tool_use_id, tool, session_id, agent_id, agent_type, cwd_hash, created_at, \
                query, url, url_norm, fetch_prompt, http_code, bytes, duration_ms, status, \
                summary, source, quarantined, quarantine_reason, agent \
         FROM event ORDER BY id",
    )?;
    let mut rows = st.query([])?;
    let mut n = 0;
    while let Some(r) = rows.next()? {
        let id: i64 = r.get(0)?;
        let res: Vec<serde_json::Value> = results
            .query_map([id], |x| {
                Ok(json!({
                    "rank": x.get::<_, i64>(0)?,
                    "url": x.get::<_, String>(1)?,
                    "url_norm": x.get::<_, String>(2)?,
                    "title": x.get::<_, Option<String>>(3)?,
                }))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let line = json!({
            "id": id,
            "tool_use_id": r.get::<_, String>(1)?,
            "tool": r.get::<_, String>(2)?,
            "session_id": r.get::<_, String>(3)?,
            "agent_id": r.get::<_, Option<String>>(4)?,
            "agent_type": r.get::<_, Option<String>>(5)?,
            "cwd_hash": r.get::<_, String>(6)?,
            "created_at": r.get::<_, i64>(7)?,
            "query": r.get::<_, Option<String>>(8)?,
            "url": r.get::<_, Option<String>>(9)?,
            "url_norm": r.get::<_, Option<String>>(10)?,
            "fetch_prompt": r.get::<_, Option<String>>(11)?,
            "http_code": r.get::<_, Option<i64>>(12)?,
            "bytes": r.get::<_, Option<i64>>(13)?,
            "duration_ms": r.get::<_, Option<i64>>(14)?,
            "status": r.get::<_, String>(15)?,
            "summary": r.get::<_, Option<String>>(16)?,
            "source": r.get::<_, String>(17)?,
            "agent": r.get::<_, String>(20)?,
            "quarantined": r.get::<_, i64>(18)? != 0,
            "quarantine_reason": r.get::<_, Option<String>>(19)?,
            "results": res,
        });
        writeln!(w, "{line}")?;
        n += 1;
    }
    Ok(n)
}
