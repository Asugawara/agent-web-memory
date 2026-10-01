//! `awm log`: recent events, or one injection by `--ref`.

use rusqlite::{params, OptionalExtension};
use serde_json::json;

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Events to show
    #[arg(long, default_value_t = 20)]
    pub limit: u32,
    /// Print JSON lines
    #[arg(long)]
    pub json: bool,
    /// Show the text of the injection with this ref instead
    #[arg(long = "ref", value_name = "REF")]
    pub ref_id: Option<String>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let conn = super::open_db()?;
    if let Some(r) = &args.ref_id {
        return show_ref(&conn, r);
    }
    let mut st = conn.prepare(
        "SELECT created_at, tool, agent_id, query, url, status FROM event \
         ORDER BY created_at DESC, id DESC LIMIT ?1",
    )?;
    let rows = st.query_map(params![args.limit], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, String>(5)?,
        ))
    })?;
    for row in rows {
        let (ts, tool, agent, query, url, status) = row?;
        let agent_kind = if agent.is_some() { "subagent" } else { "main" };
        let target = url.or(query).unwrap_or_default();
        if args.json {
            println!(
                "{}",
                json!({"ts": ts, "tool": tool, "agent": agent_kind, "target": target, "status": status})
            );
        } else {
            println!(
                "{}  {tool:<9}  {agent_kind:<8}  {status:<11}  {}",
                super::fmt_ts(ts),
                target.replace('\n', " ")
            );
        }
    }
    Ok(())
}

fn show_ref(conn: &rusqlite::Connection, r: &str) -> anyhow::Result<()> {
    let row: Option<(i64, String, String, Option<String>)> = conn
        .query_row(
            "SELECT created_at, mode, channel, rendered FROM injection WHERE ref = ?1",
            [r],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((ts, mode, channel, rendered)) = row else {
        anyhow::bail!("no injection with ref {r}");
    };
    println!("{}  {mode}  {channel}", super::fmt_ts(ts));
    match rendered {
        Some(text) => println!("{text}"),
        None => println!("(no text was given to the model in {mode} mode)"),
    }
    Ok(())
}
