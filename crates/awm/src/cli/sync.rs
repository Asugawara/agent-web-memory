//! `awm sync [--once] [--quiet] [--push-only | --pull-only] [--status]
//! [--backfill --since DATE --project P [--dry-run]]` (plan-v3-team §4.6, §4.8; TM10).
//!
//! `--push-only` and `--pull-only` skip the other phase of the run (both still take
//! `sync.lock`); `--status` prints what `awm team status` prints and does not sync (RVT3 F5).
//!
//! Exit codes: 0 when the run finished, when another run holds the lock, when a hook-started run
//! waits out a backoff, and when the database is not at this build's schema in a `--quiet` run;
//! 1 when the run failed (the server did not answer within the timeout, a refusal, a bug).
//! With `--quiet` (the hook spawn) nothing is printed, errors included.

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Run one sync cycle and exit (the default; hooks pass it)
    #[arg(long)]
    pub once: bool,
    /// Print nothing; a failure is only the exit status and `sync_state`
    #[arg(long)]
    pub quiet: bool,
    /// Send only: skip the pull, the deletion stream and retention
    #[arg(long, conflicts_with = "pull_only")]
    pub push_only: bool,
    /// Receive only: skip approvals, the key rotation and the push
    #[arg(long)]
    pub pull_only: bool,
    /// Print what `awm team status` prints and do not sync
    #[arg(long, conflicts_with_all = ["push_only", "pull_only", "backfill", "quiet"])]
    pub status: bool,
    /// Share older records of the projects named with --project (their share rules must exist)
    #[arg(long)]
    pub backfill: bool,
    /// With --backfill: only records from this day on (YYYY-MM-DD, UTC)
    #[arg(long, requires = "backfill")]
    pub since: Option<String>,
    /// With --backfill: a project directory, a cwd hash or a repo key (repeatable)
    #[arg(long, requires = "backfill")]
    pub project: Vec<String>,
    /// With --backfill: show what would be shared and send nothing
    #[arg(long, requires = "backfill")]
    pub dry_run: bool,
}

#[cfg(not(feature = "sync"))]
pub fn run(_args: Args) -> anyhow::Result<()> {
    super::not_implemented("sync")
}

#[cfg(feature = "sync")]
pub fn run(args: Args) -> anyhow::Result<()> {
    use crate::sync::{self, Backfill, Env, Opts, Outcome};

    if args.status {
        let env = Env::from_environment()?;
        return super::team::print_status(&env.data_dir, false);
    }
    let quiet = args.quiet;
    let pull_only = args.pull_only;
    let result = (|| -> anyhow::Result<Outcome> {
        let env = Env::from_environment()?;
        let backfill = if args.backfill {
            if args.project.is_empty() {
                anyhow::bail!("--backfill needs --project: name what to share");
            }
            Some(Backfill {
                since_ms: args.since.as_deref().map(super::parse_date).transpose()?,
                values: project_values(&args.project),
            })
        } else {
            None
        };
        let opts = Opts {
            quiet,
            honour_backoff: quiet,
            backfill,
            dry_run: args.dry_run,
            push_only: args.push_only,
            pull_only: args.pull_only,
            ..Opts::default()
        };
        // A joined device takes its keys once approved (TM12); until then there is nothing to do.
        if !args.dry_run {
            if let crate::team::JoinState::Waiting { .. } = crate::team::finish_join(&env.data_dir)?
            {
                return Ok(Outcome::Done(sync::Report {
                    waiting_for_approval: true,
                    ..sync::Report::default()
                }));
            }
        }
        // The daily `stats` record (TM14, `team.share_stats` only): best effort, queued before the
        // run so that this run sends it.
        if !args.dry_run {
            let _ = super::stats::queue_daily_record(&env);
        }
        sync::run(&env, &opts)
    })();
    match result {
        Ok(Outcome::Refused(why)) if !quiet => Err(anyhow::anyhow!(why)),
        Ok(outcome) => {
            if !quiet {
                print_outcome(&outcome, pull_only);
            }
            Ok(())
        }
        Err(e) if quiet => {
            let _ = e;
            std::process::exit(1)
        }
        Err(e) => Err(e),
    }
}

/// `--project` values as share-rule values: a directory is hashed like capture hashes a `cwd`
/// (as given, and canonicalised); a 64-hex value is a `cwd_hash`, a 32-hex value a `repo_key`.
#[cfg(feature = "sync")]
fn project_values(projects: &[String]) -> Vec<String> {
    use crate::record::sha256_hex;
    let hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
    let mut out = Vec::new();
    for p in projects {
        if hex(p, 64) || hex(p, 32) {
            out.push(p.to_lowercase());
            continue;
        }
        out.push(sha256_hex(p));
        if let Ok(canon) = std::fs::canonicalize(p) {
            out.push(sha256_hex(&canon.to_string_lossy()));
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(feature = "sync")]
fn print_outcome(outcome: &crate::sync::Outcome, pull_only: bool) {
    use crate::sync::Outcome;
    match outcome {
        Outcome::Locked => println!("another awm sync is running"),
        Outcome::BackedOff { until_ms } => {
            println!("waiting after an error until {}", super::fmt_ts(*until_ms))
        }
        Outcome::Refused(why) => eprintln!("awm sync: {why}"),
        Outcome::DryRun { would_share, kept } => {
            println!("would share {would_share} record(s)");
            for (reason, n) in kept {
                println!("  stays local: {reason}: {n}");
            }
        }
        Outcome::Done(r) => {
            if r.waiting_for_approval {
                println!("this device is waiting for an approval");
                return;
            }
            println!(
                "synced: pushed {}, pulled {}{}{}{}",
                r.pushed,
                r.pulled,
                if r.dropped > 0 {
                    format!(", dropped {}", r.dropped)
                } else {
                    String::new()
                },
                if r.quarantined > 0 {
                    format!(", quarantined {} (flags sent)", r.quarantined)
                } else {
                    String::new()
                },
                if r.rejected > 0 {
                    format!(
                        ", rejected {} (refused by the server, not sent)",
                        r.rejected
                    )
                } else {
                    String::new()
                }
            );
            // A hook-spawned run has usually pushed already: say so instead of a bare 0 (F21).
            if r.pushed == 0 && !pull_only {
                let n = r.outbox_left + r.unqueued;
                let waiting = if n == 0 {
                    "nothing waiting".to_string()
                } else {
                    format!("{n} item(s) waiting")
                };
                match r.previous_ok_ms {
                    Some(at) => println!(
                        "{waiting}; last successful sync {} s ago",
                        ((crate::hook::now_ms() - at) / 1_000).max(0)
                    ),
                    None => println!("{waiting}; no successful sync yet"),
                }
            }
            if let Some(why) = &r.push_blocked {
                println!("pushes are stopped: {why}");
            }
            if r.reseeded {
                println!("the server was restored: this device re-pushed what it was missing");
            }
            if r.rotated {
                println!("the team key was rotated");
            }
            for (reason, n) in &r.skipped {
                println!("  stays local: {reason}: {n}");
            }
        }
    }
}
