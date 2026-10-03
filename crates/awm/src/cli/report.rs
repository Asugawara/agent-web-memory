//! `awm report`: a paste-ready summary of counts and rates. No URL, path or query text.

use std::path::PathBuf;

use serde_json::{json, Map, Value};

use super::doctor;

const DAY_MS: i64 = 86_400_000;

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Transcript directory for coverage and delivery (default ~/.claude/projects)
    #[arg(long, value_name = "DIR")]
    pub projects: Option<PathBuf>,
}

fn count(conn: &rusqlite::Connection, sql: &str) -> anyhow::Result<i64> {
    Ok(conn.query_row(sql, [], |r| r.get(0))?)
}

fn grouped(conn: &rusqlite::Connection, sql: &str) -> anyhow::Result<Value> {
    let mut st = conn.prepare(sql)?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    let mut m = Map::new();
    for r in rows {
        let (k, n) = r?;
        m.insert(k, json!(n));
    }
    Ok(Value::Object(m))
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let conn = super::open_db()?;
    let first: Option<i64> =
        conn.query_row("SELECT MIN(applied_at) FROM schema_version", [], |r| {
            r.get(0)
        })?;
    let days = first.map_or(0, |t| (super::now_ms() - t).max(0) / DAY_MS);
    let mut lat: Vec<i64> = conn
        .prepare("SELECT total_ms FROM hook_run WHERE hook IN ('prompt','pre-fetch','post-tool')")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let projects = super::projects_dir(&args.projects)
        .ok()
        .filter(|p| p.is_dir());
    let (cov, del) = match &projects {
        Some(p) => {
            let c = doctor::coverage(&conn, p, None)?;
            let d = doctor::delivery(&conn, None)?;
            (
                doctor::coverage_pct(c.all()),
                super::pct(d.delivered, d.checked),
            )
        }
        None => (None, None),
    };
    let report = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "days_since_init": days,
        "records": count(&conn, "SELECT COUNT(*) FROM event WHERE origin = 'local'")?,
        "records_by_tool": grouped(&conn, "SELECT tool, COUNT(*) FROM event WHERE origin = 'local' GROUP BY tool ORDER BY tool")?,
        "records_by_agent_kind": grouped(&conn, "SELECT CASE WHEN agent_id IS NULL THEN 'main' ELSE 'subagent' END, COUNT(*) FROM event WHERE origin = 'local' GROUP BY 1 ORDER BY 1")?,
        "quarantined": count(&conn, "SELECT COUNT(*) FROM event WHERE quarantined = 1 AND origin = 'local'")?,
        "injections_shown": count(&conn, "SELECT COUNT(*) FROM injection WHERE mode IN ('inject','deny')")?,
        "labels": grouped(&conn, "SELECT label, COUNT(*) FROM outcome GROUP BY label ORDER BY label")?,
        "hook_ms": {
            "runs": lat.len(),
            "p50": super::percentile(&mut lat.clone(), 50.0),
            "p95": super::percentile(&mut lat, 95.0),
        },
        "capture_coverage": cov,
        "delivery": del,
    });
    let mut out = String::new();
    super::render_value(&report, 0, &mut out);
    print!("{out}");
    Ok(())
}
