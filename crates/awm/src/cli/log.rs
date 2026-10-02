//! `awm log`: recent events, or one injection by `--ref`.

use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

/// Which records `--origin` keeps (`event.origin`).
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Records captured on this machine
    Local,
    /// Records pulled from teammates
    Team,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Local => "local",
            Origin::Team => "team",
        }
    }
}

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
    /// Only your own records or only teammates' records
    #[arg(long, value_enum)]
    pub origin: Option<Origin>,
    /// Only your own records that reached the team server (queued ones are not listed; without
    /// this flag they show a `queued` marker)
    #[arg(long)]
    pub shared: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let conn = super::open_db()?;
    if let Some(r) = &args.ref_id {
        return show_ref(&conn, r);
    }
    // `--shared` means own records: it cannot be combined with `--origin team`.
    if args.shared && args.origin == Some(Origin::Team) {
        anyhow::bail!("--shared lists your own records; it cannot be combined with --origin team");
    }
    let origin = args.origin.map(Origin::as_str);
    let mut st = conn.prepare(
        "SELECT e.created_at, e.tool, e.agent_id, e.query, e.url, e.status, e.agent, e.origin, \
                m.handle, \
                e.origin = 'local' AND e.sync_id IS NOT NULL AND e.pushed_at IS NULL \
         FROM event e LEFT JOIN team_member m ON m.member_id = e.member \
         WHERE (?2 IS NULL OR e.origin = ?2) \
           AND (?3 = 0 OR (e.origin = 'local' AND e.pushed_at IS NOT NULL)) \
         ORDER BY e.created_at DESC, e.id DESC LIMIT ?1",
    )?;
    let rows = st.query_map(params![args.limit, origin, args.shared], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, Option<String>>(8)?,
            r.get::<_, bool>(9)?,
        ))
    })?;
    for row in rows {
        let (ts, tool, agent, query, url, status, coding_agent, row_origin, handle, queued) = row?;
        let agent_kind = if agent.is_some() { "subagent" } else { "main" };
        let target = url.or(query).unwrap_or_default();
        if args.json {
            let mut line = json!({"ts": ts, "tool": tool, "agent": agent_kind, "coding_agent": coding_agent,
                       "target": target, "status": status});
            line["origin"] = Value::from(row_origin.as_str());
            if queued {
                line["queued"] = Value::from(true);
            }
            if row_origin == "team" {
                line["handle"] = handle.map_or(Value::Null, Value::from);
            }
            println!("{line}");
        } else {
            // Claude rows are the default and carry no tag.
            let mut tag = if coding_agent == "claude" {
                String::new()
            } else {
                format!("[{coding_agent}] ")
            };
            if row_origin == "team" {
                tag.push_str(&format!("@{} ", handle.as_deref().unwrap_or("?")));
            }
            if queued {
                tag.push_str("[queued] ");
            }
            println!(
                "{}  {tool:<9}  {agent_kind:<8}  {status:<11}  {tag}{}",
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
