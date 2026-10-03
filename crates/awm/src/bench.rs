//! `awm bench-check`: offline regression check of the matching channels against the labelled
//! bench (plan-v2 §3.6). Built only with the cargo feature `bench`.
//!
//! Exit codes: 0 pass, 1 a threshold failed, 2 `needs labels` (too many returned rows unlabelled).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;

use crate::db::{self, Role};
use crate::matching::{self, calibrate, MatchOpts};

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Frozen bench database (`spikes/data/frozen/awm.db`).
    #[arg(long)]
    pub db: PathBuf,
    /// Judged pairs (`spikes/match-bench/labels/judged.csv`).
    #[arg(long)]
    pub labels: PathBuf,
    /// `query_id,case,tool_use_id` written by `match-bench pool-ids`.
    #[arg(long)]
    pub query_ids: PathBuf,
    /// Pass lines (`bench/thresholds.toml`).
    #[arg(long)]
    pub thresholds: PathBuf,
    /// Also replay the queries at the given scales and print p50/p95 of the search time.
    #[arg(long)]
    pub latency: bool,
    /// Comma separated database scale factors for `--latency`.
    #[arg(long, default_value = "1,10")]
    pub scale: String,
}

#[derive(Debug, Deserialize)]
struct Thresholds {
    url: UrlLines,
    query: QueryLines,
    unlabelled: UnlabelledLine,
    latency: Option<LatencyLine>,
}

#[derive(Debug, Deserialize)]
struct UrlLines {
    strict_min: f64,
}

#[derive(Debug, Deserialize)]
struct QueryLines {
    strict_min: f64,
    loose_min: f64,
    nothing_max: f64,
}

#[derive(Debug, Deserialize)]
struct UnlabelledLine {
    max: f64,
}

#[derive(Debug, Deserialize)]
struct LatencyLine {
    search_p95_ms_max: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Channel {
    Url,
    Query,
    Prompt,
}

impl Channel {
    fn from_case(case: &str) -> Option<Self> {
        match case {
            "url" => Some(Channel::Url),
            "query" => Some(Channel::Query),
            "prompt" => Some(Channel::Prompt),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Channel::Url => "awm-url",
            Channel::Query => "awm-query",
            Channel::Prompt => "awm-prompt",
        }
    }
}

/// One labelled (query, case) group: the judged candidates and the text the prompt channel uses.
struct Group {
    channel: Channel,
    qid: String,
    query_text_anon: String,
    /// Judged candidate `tool_use_id` to label (0, 1, 2).
    labels: HashMap<String, u8>,
}

/// The anchor event of a group: the input of the channel and the context of the call.
struct Anchor {
    tool_use_id: String,
    session: String,
    agent: Option<String>,
    cwd_hash: String,
    created_at: i64,
    url_norm: Option<String>,
    /// Search query or fetch prompt.
    head: String,
}

#[derive(Debug, Default, Clone)]
struct Tally {
    groups: usize,
    nothing: usize,
    returned: usize,
    strict: usize,
    loose: usize,
    unlabelled: usize,
}

impl Tally {
    fn add(&mut self, other: &Tally) {
        self.groups += other.groups;
        self.nothing += other.nothing;
        self.returned += other.returned;
        self.strict += other.strict;
        self.loose += other.loose;
        self.unlabelled += other.unlabelled;
    }

    /// Precision over returned rows; unlabelled rows count as not relevant.
    fn precision(&self, n: usize) -> Option<f64> {
        (self.returned > 0).then(|| n as f64 / self.returned as f64)
    }

    fn nothing_rate(&self) -> f64 {
        ratio(self.nothing, self.groups)
    }

    fn unlabelled_rate(&self) -> f64 {
        ratio(self.unlabelled, self.returned)
    }
}

fn ratio(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        n as f64 / d as f64
    }
}

fn load_groups(labels: &Path) -> Result<Vec<Group>> {
    let mut rdr = csv::Reader::from_path(labels)
        .with_context(|| format!("cannot read labels {}", labels.display()))?;
    let head = rdr.headers()?.clone();
    let col = |name: &str| {
        head.iter()
            .position(|h| h == name)
            .with_context(|| format!("labels file has no column {name}"))
    };
    let (c_q, c_case, c_cand, c_text, c_label) = (
        col("query_id")?,
        col("case")?,
        col("candidate_id")?,
        col("query_text_anon")?,
        col("label")?,
    );
    let mut order: Vec<(String, String)> = Vec::new();
    let mut by_key: HashMap<(String, String), Group> = HashMap::new();
    for rec in rdr.records() {
        let rec = rec?;
        let (qid, case) = (rec[c_q].to_string(), rec[c_case].to_string());
        let Some(channel) = Channel::from_case(&case) else {
            bail!("unknown case {case} in labels");
        };
        let label: u8 = rec[c_label]
            .trim()
            .parse()
            .with_context(|| format!("bad label for {qid}/{case}: {}", &rec[c_label]))?;
        let key = (qid.clone(), case);
        let g = by_key.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            Group {
                channel,
                qid,
                query_text_anon: rec[c_text].to_string(),
                labels: HashMap::new(),
            }
        });
        g.labels.insert(rec[c_cand].to_string(), label);
    }
    Ok(order
        .into_iter()
        .filter_map(|k| by_key.remove(&k))
        .collect())
}

fn load_anchor_ids(path: &Path) -> Result<HashMap<(String, String), String>> {
    let mut rdr = csv::Reader::from_path(path)
        .with_context(|| format!("cannot read query ids {}", path.display()))?;
    let mut out = HashMap::new();
    for rec in rdr.records() {
        let rec = rec?;
        out.insert((rec[0].to_string(), rec[1].to_string()), rec[2].to_string());
    }
    Ok(out)
}

fn load_anchor(conn: &Connection, tool_use_id: &str) -> Result<Option<Anchor>> {
    Ok(conn
        .query_row(
            "SELECT tool_use_id, session_id, agent_id, cwd_hash, created_at, url_norm, \
                    COALESCE(query, fetch_prompt, '') FROM event WHERE tool_use_id = ?1",
            [tool_use_id],
            |r| {
                Ok(Anchor {
                    tool_use_id: r.get(0)?,
                    session: r.get(1)?,
                    agent: r.get(2)?,
                    cwd_hash: r.get(3)?,
                    created_at: r.get(4)?,
                    url_norm: r.get(5)?,
                    head: r.get(6)?,
                })
            },
        )
        .optional()?)
}

fn opts_for(a: &Anchor, exclude_same_agent: bool) -> MatchOpts {
    MatchOpts {
        caller_session: a.session.clone(),
        caller_agent: a.agent.clone(),
        caller_cwd_hash: a.cwd_hash.clone(),
        caller_tool_use_id: Some(a.tool_use_id.clone()),
        before_ms: Some(a.created_at),
        exclude_same_agent,
        limit: 3,
        shown_event_ids: Vec::new(),
        ..MatchOpts::default()
    }
}

struct Cutoffs {
    query: f64,
    prompt: f64,
}

/// Runs the channel of `g` for its anchor and returns the hit event ids.
fn run_channel(
    conn: &Connection,
    g: &Group,
    a: &Anchor,
    cut: &Cutoffs,
    exclude_same_agent: bool,
) -> Result<Vec<i64>> {
    let opts = opts_for(a, exclude_same_agent);
    let hits = match g.channel {
        Channel::Url => match &a.url_norm {
            Some(u) => matching::url_channel(conn, u, &opts)?,
            None => Vec::new(),
        },
        Channel::Query => matching::query_channel(conn, &a.head, cut.query, &opts)?,
        Channel::Prompt => matching::query_channel(conn, &g.query_text_anon, cut.prompt, &opts)?,
    };
    Ok(hits.into_iter().map(|h| h.event_id).collect())
}

fn tool_use_id_of(conn: &Connection, event_id: i64) -> Result<String> {
    Ok(conn.query_row(
        "SELECT tool_use_id FROM event WHERE id = ?1",
        [event_id],
        |r| r.get(0),
    )?)
}

struct Scored {
    /// Per channel, per mode (0 = bench-equivalent, 1 = product default).
    tallies: [[Tally; 2]; 3],
    anchors_missing: usize,
    groups_scored: usize,
}

fn chan_idx(c: Channel) -> usize {
    match c {
        Channel::Url => 0,
        Channel::Query => 1,
        Channel::Prompt => 2,
    }
}

fn score(
    conn: &Connection,
    groups: &[Group],
    anchor_ids: &HashMap<(String, String), String>,
    cut: &Cutoffs,
) -> Result<Scored> {
    let mut out = Scored {
        tallies: Default::default(),
        anchors_missing: 0,
        groups_scored: 0,
    };
    let case_of = |c: Channel| match c {
        Channel::Url => "url",
        Channel::Query => "query",
        Channel::Prompt => "prompt",
    };
    for g in groups {
        let Some(tuid) = anchor_ids.get(&(g.qid.clone(), case_of(g.channel).to_string())) else {
            bail!(
                "{}/{} is not in the query-ids file",
                g.qid,
                case_of(g.channel)
            );
        };
        let Some(a) = load_anchor(conn, tuid)? else {
            out.anchors_missing += 1;
            continue;
        };
        out.groups_scored += 1;
        for (mode, exclude) in [(0usize, false), (1usize, true)] {
            let ids = run_channel(conn, g, &a, cut, exclude)?;
            let t = &mut out.tallies[chan_idx(g.channel)][mode];
            t.groups += 1;
            if ids.is_empty() {
                t.nothing += 1;
            }
            for id in ids {
                t.returned += 1;
                match g.labels.get(&tool_use_id_of(conn, id)?) {
                    None => t.unlabelled += 1,
                    Some(l) => {
                        t.strict += usize::from(*l == 2);
                        t.loose += usize::from(*l >= 1);
                    }
                }
            }
        }
    }
    Ok(out)
}

fn fmt_p(p: Option<f64>) -> String {
    p.map_or("n/a".to_string(), |v| format!("{v:.2}"))
}

fn print_rows(s: &Scored, cut: &Cutoffs) {
    println!(
        "cutoffs: query {:.2}, prompt {:.2}; top 3; precision counts unlabelled rows as not relevant",
        cut.query, cut.prompt
    );
    println!("| channel | mode | groups | rows | precision strict | precision loose | no match | unlabelled |");
    println!("|---|---|---|---|---|---|---|---|");
    for c in [Channel::Url, Channel::Query, Channel::Prompt] {
        for (mode, name) in [(0, "bench-equivalent"), (1, "product default")] {
            let t = &s.tallies[chan_idx(c)][mode];
            println!(
                "| {} | {} | {} | {} | {} | {} | {:.0}% | {:.0}% |",
                c.name(),
                name,
                t.groups,
                t.returned,
                fmt_p(t.precision(t.strict)),
                fmt_p(t.precision(t.loose)),
                t.nothing_rate() * 100.0,
                t.unlabelled_rate() * 100.0,
            );
        }
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

/// Copies the database into a temporary file with every event repeated `scale` times.
fn scaled_copy(src: &Connection, scale: usize, dir: &Path) -> Result<Connection> {
    let path = dir.join(format!("scale-{scale}.db"));
    let _ = std::fs::remove_file(&path);
    src.execute("VACUUM INTO ?1", [path.to_string_lossy().as_ref()])?;
    let conn = db::open(&path, Role::Cli)?;
    for k in 1..scale {
        conn.execute(
            "INSERT INTO event (tool_use_id, tool, session_id, agent_id, agent_type, cwd_hash, \
                created_at, query, url, url_norm, fetch_prompt, http_code, bytes, duration_ms, \
                status, summary, match_text, source, quarantined) \
             SELECT tool_use_id || '#' || ?1, tool, session_id, agent_id, agent_type, cwd_hash, \
                created_at, query, url, url_norm, fetch_prompt, http_code, bytes, duration_ms, \
                status, summary, match_text, source, quarantined \
             FROM event WHERE tool_use_id NOT LIKE '%#%'",
            params![k as i64],
        )?;
    }
    Ok(conn)
}

/// Replays the labelled queries (product default) and returns the search times in ms.
fn replay(
    conn: &Connection,
    groups: &[Group],
    anchors: &[(usize, Anchor)],
    cut: &Cutoffs,
) -> Result<Vec<f64>> {
    let mut times = Vec::new();
    for (gi, a) in anchors {
        let t = Instant::now();
        run_channel(conn, &groups[*gi], a, cut, true)?;
        times.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    Ok(times)
}

/// Prints p50/p95 per scale; returns the worst p95.
fn latency(
    conn: &Connection,
    groups: &[Group],
    anchor_ids: &HashMap<(String, String), String>,
    cut: &Cutoffs,
    scales: &[usize],
) -> Result<f64> {
    let mut anchors = Vec::new();
    for (gi, g) in groups.iter().enumerate() {
        let case = match g.channel {
            Channel::Url => "url",
            Channel::Query => "query",
            Channel::Prompt => "prompt",
        };
        if let Some(tuid) = anchor_ids.get(&(g.qid.clone(), case.to_string())) {
            if let Some(a) = load_anchor(conn, tuid)? {
                anchors.push((gi, a));
            }
        }
    }
    let dir = std::env::temp_dir().join(format!("awm-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    println!("\nlatency of the matching body (search_ms), product default, {} queries per pass, 3 passes", anchors.len());
    println!("| scale | events | calls | p50 ms | p95 ms |");
    println!("|---|---|---|---|---|");
    let mut worst = 0.0f64;
    for &scale in scales {
        let copy = scaled_copy(conn, scale, &dir)?;
        let events: i64 = copy.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0))?;
        replay(&copy, groups, &anchors, cut)?; // warm the page cache
        let mut times = Vec::new();
        for _ in 0..3 {
            times.extend(replay(&copy, groups, &anchors, cut)?);
        }
        times.sort_by(f64::total_cmp);
        let p95 = percentile(&times, 0.95);
        worst = worst.max(p95);
        println!(
            "| {}x | {} | {} | {:.2} | {:.2} |",
            scale,
            events,
            times.len(),
            percentile(&times, 0.5),
            p95
        );
        drop(copy);
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(worst)
}

fn parse_scales(s: &str) -> Result<Vec<usize>> {
    let v: Vec<usize> = s
        .split(',')
        .map(|p| p.trim().parse::<usize>())
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("bad --scale {s}"))?;
    if v.is_empty() || v.contains(&0) {
        bail!("--scale needs positive integers");
    }
    Ok(v)
}

/// Compares the bench-equivalent rows with the pass lines; returns the failures.
fn check(s: &Scored, th: &Thresholds) -> Vec<String> {
    let mut fails = Vec::new();
    let url = &s.tallies[0][0];
    match url.precision(url.strict) {
        Some(p) if p >= th.url.strict_min => {}
        p => fails.push(format!(
            "awm-url strict precision {} < {:.2}",
            fmt_p(p),
            th.url.strict_min
        )),
    }
    let q = &s.tallies[1][0];
    let (strict, loose) = (q.precision(q.strict), q.precision(q.loose));
    if strict.is_none_or(|p| p < th.query.strict_min) {
        fails.push(format!(
            "awm-query strict precision {} < {:.2}",
            fmt_p(strict),
            th.query.strict_min
        ));
    }
    if loose.is_none_or(|p| p < th.query.loose_min) {
        fails.push(format!(
            "awm-query loose precision {} < {:.2}",
            fmt_p(loose),
            th.query.loose_min
        ));
    }
    if q.nothing_rate() > th.query.nothing_max {
        fails.push(format!(
            "awm-query no-match rate {:.0}% > {:.0}%",
            q.nothing_rate() * 100.0,
            th.query.nothing_max * 100.0
        ));
    }
    fails
}

pub fn run(args: Args) -> Result<()> {
    let th: Thresholds = toml::from_str(
        &std::fs::read_to_string(&args.thresholds)
            .with_context(|| format!("cannot read {}", args.thresholds.display()))?,
    )
    .with_context(|| format!("bad thresholds file {}", args.thresholds.display()))?;
    let groups = load_groups(&args.labels)?;
    let anchor_ids = load_anchor_ids(&args.query_ids)?;
    let conn = db::open(&args.db, Role::Cli)?;
    let cut = Cutoffs {
        query: calibrate::cutoff_query(&conn)?,
        prompt: calibrate::cutoff_prompt(&conn)?,
    };
    let s = score(&conn, &groups, &anchor_ids, &cut)?;
    let distinct: HashSet<&str> = groups.iter().map(|g| g.qid.as_str()).collect();
    println!(
        "labelled groups: {} ({} query events); scored: {}; anchors missing: {}",
        groups.len(),
        distinct.len(),
        s.groups_scored,
        s.anchors_missing
    );
    print_rows(&s, &cut);

    let mut bench_total = Tally::default();
    for c in 0..3 {
        bench_total.add(&s.tallies[c][0]);
    }
    let unlabelled = bench_total.unlabelled_rate();
    println!(
        "unlabelled returned rows (bench-equivalent, all channels): {}/{} = {:.1}% (limit {:.0}%)",
        bench_total.unlabelled,
        bench_total.returned,
        unlabelled * 100.0,
        th.unlabelled.max * 100.0
    );

    let fails = check(&s, &th);
    if args.latency {
        let worst = latency(
            &conn,
            &groups,
            &anchor_ids,
            &cut,
            &parse_scales(&args.scale)?,
        )?;
        if let Some(l) = &th.latency {
            println!(
                "search p95 worst {:.2} ms, plan line {:.0} ms: {} (reported, not gated)",
                worst,
                l.search_p95_ms_max,
                if worst <= l.search_p95_ms_max {
                    "within"
                } else {
                    "over"
                }
            );
        }
    }

    if unlabelled > th.unlabelled.max {
        println!("needs labels: label the missing pairs with spikes/match-bench/labels/RUBRIC.md and append them to judged.csv");
        std::process::exit(2);
    }
    if fails.is_empty() {
        println!("bench-check: PASS");
        Ok(())
    } else {
        for f in &fails {
            println!("FAIL: {f}");
        }
        println!("bench-check: FAIL");
        std::process::exit(1);
    }
}
