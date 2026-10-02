//! `awm team ...` (plan-v3-team §4.8, §3.4, §3.6, §5.1; `docs/sync-v1-crypto.md` §12; TM12).
//!
//! | command | endpoint(s) | roster entry | files and tables written |
//! |---|---|---|---|
//! | `create URL --token B --handle H` | `POST /v1/bootstrap` | `genesis` (queued; the first `awm sync` pushes it) | `team.toml`, `team.key`, `team.repo`; `sync_own`, `sync_outbox`, `roster_record` |
//! | `invite --handle H [--admin] [--expires 7d]` | `POST /v1/invites` | none | `team.key` (`pending_invites`, with `S`) |
//! | `join URL --token awmi1_...` | `POST /v1/join`, then `GET /v1/keys` once approved | none (the approver writes it) | `team.toml`, `team.key` (`join_invite` until approved), `team.repo` |
//! | `add-device [--for @H]` | `POST /v1/invites` (`kind: device`) | none | `team.key` |
//! | `approve [H] [--code N]` | `GET /v1/status`, `POST /v1/pull`, `POST /v1/devices/{id}/approve`, `POST /v1/records` | `approve` | `team.key`, roster tables |
//! | `members [--trust-admin @H] [--json]` | `GET /v1/members` | none | `team_member`, `team_device`, `sync_state.trusted_admins` |
//! | `remove @H [--delete-records]` | `POST /v1/members/{id}/remove`, `GET /v1/members`, `POST /v1/keys/rotate`, `POST /v1/records` | `revoke`, `epoch` | `team.key` (new epoch) |
//! | `rotate-key` | `GET /v1/members`, `POST /v1/keys/rotate`, `POST /v1/records` | `epoch` | `team.key` |
//! | `share [PATH]` | none | none | `share_rule`, `project` |
//! | `unshare [PATH] [--delete]`, `unshare --record ID` | `POST /v1/delete` | none | `share_rule`, `sync_own`, `sync_outbox`, `tombstone`, `event.shareable` |
//! | `status [--json]` | `GET /v1/status` (and `GET /v1/keys` while a join waits) | none | none |
//! | `leave [--delete]` | `POST /v1/delete {all_mine}`, `POST /v1/records`, `POST /v1/devices/{id}/revoke` | `revoke` (this device) | removes the team files and rows |
//! | `delete-mine` | `POST /v1/delete {all_mine}` | none | `sync_own`, `tombstone` |
//! | `move URL` | `GET /v1/status`, `POST /v1/token/rotate` on the new server, then `awm sync` | none | `team.toml`, `team.key` |
//! | `policy show`, `policy set K=V` | `GET`/`PUT /v1/org/settings`, `POST /v1/records` (tag `policy`) | none | `sync_state.policy_*` |
//! | `audit [--delete]` | `POST /v1/delete {ids}` | none | `event`, `tombstone` |
//! | `audit-log [--json]` | `GET /v1/audit` | none | none |
//! | `flag ID [--reason T]` | `POST /v1/records` (tag `flag`) | none | `sync_own`, `sync_outbox` |
//! | `token rotate` | `POST /v1/token/rotate` | none | `team.key` |
//! | `key export`, `key import` | none (`POST /v1/pull` when the genesis is not stored) | `recover` (an admin's new device) | `team.key`, `team.repo` |
//!
//! No token, key, invite secret or record text is ever part of an error message; `team.key` is
//! never printed (`key export` prints the recovery string the user asked for).

use std::path::PathBuf;

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub command: Sub,
}

#[derive(clap::Subcommand, Debug)]
pub enum Sub {
    /// Create an organisation on a server and become its first admin
    Create {
        /// The server URL (https://, or http:// on loopback)
        url: String,
        /// The bootstrap token that `awm serve init` printed
        #[arg(long)]
        token: String,
        /// Your handle in the team (1-24 of a-z, 0-9, _ and -)
        #[arg(long)]
        handle: String,
        /// A PEM file with the CA of a server behind an internal CA
        #[arg(long)]
        ca_file: Option<PathBuf>,
    },
    /// Invite a new member (admins): prints the join command to send
    Invite {
        /// The new member's handle
        #[arg(long)]
        handle: String,
        /// Invite an admin
        #[arg(long)]
        admin: bool,
        /// How long the invite works (1d-30d)
        #[arg(long, default_value = "7d")]
        expires: String,
    },
    /// Join an organisation with an invite
    Join {
        /// The server URL
        url: String,
        /// The invite string (awmi1_...)
        #[arg(long)]
        token: String,
        /// A PEM file with the CA of a server behind an internal CA
        #[arg(long)]
        ca_file: Option<PathBuf>,
    },
    /// Invite your next machine (or, admins, one for a member who lost every device)
    AddDevice {
        /// Admins: the member who gets the device
        #[arg(long = "for")]
        for_handle: Option<String>,
        /// How long the invite works (1d-30d)
        #[arg(long, default_value = "7d")]
        expires: String,
    },
    /// Approve a pending join after comparing its code
    Approve {
        /// The handle of the pending join
        handle: Option<String>,
        /// The 6-digit code the invitee reads out from `awm team join`
        #[arg(long)]
        code: Option<String>,
    },
    /// List members and devices, verified against the roster
    Members {
        #[arg(long)]
        json: bool,
        /// Trust a server-listed admin while the roster holds no verified admin (after `awm serve promote`)
        #[arg(long = "trust-admin")]
        trust_admin: Vec<String>,
    },
    /// Remove a member (admins): revokes their tokens and rotates the team key
    Remove {
        handle: String,
        /// Also delete the member's shared records
        #[arg(long)]
        delete_records: bool,
    },
    /// Rotate the team key now (admins)
    RotateKey,
    /// Share records of a repository or directory captured from now on
    Share { path: Option<PathBuf> },
    /// Stop sharing a project, or withdraw one record
    Unshare {
        path: Option<PathBuf>,
        /// Also delete the project's shared records from the server
        #[arg(long)]
        delete: bool,
        /// Withdraw one record (an event id or a record id): deleted remotely, never shared again
        #[arg(long, conflicts_with_all = ["path", "delete"])]
        record: Option<String>,
    },
    /// Server, membership, last sync, outbox, skips and pending approvals
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Leave the organisation on this machine
    Leave {
        /// First delete all of your shared records from the server
        #[arg(long)]
        delete: bool,
    },
    /// Delete all of your shared records from the server
    DeleteMine,
    /// Switch to the organisation's new server
    Move { url: String },
    /// The encrypted team policy and the server settings
    Policy {
        #[command(subcommand)]
        command: PolicySub,
    },
    /// Re-check the team's records with the newest patterns (admins)
    Audit {
        /// Delete the records that fail
        #[arg(long)]
        delete: bool,
    },
    /// The server's audit log (admins)
    AuditLog {
        #[arg(long)]
        json: bool,
        /// First row
        #[arg(long, default_value_t = 0)]
        from: u64,
    },
    /// Report a teammate's note
    Flag {
        /// An event id or a record id
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Device token
    Token {
        #[command(subcommand)]
        command: TokenSub,
    },
    /// Recovery string for the team keys
    Key {
        #[command(subcommand)]
        command: KeySub,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum PolicySub {
    /// Print the policy and the server settings
    Show {
        #[arg(long)]
        json: bool,
    },
    /// Change the policy (admins): deny_hosts, link_hosts, terms, credential_params,
    /// summary_chars; server settings: retention_days, min_client, max_members,
    /// cancel_pending_retention
    Set {
        /// KEY=VALUE (lists comma-separated)
        #[arg(required = true)]
        assignments: Vec<String>,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum TokenSub {
    /// Replace this device's token (the old one stops at once)
    Rotate,
}

#[derive(clap::Subcommand, Debug)]
pub enum KeySub {
    /// Print every team key as one string for a password manager
    Export,
    /// Restore the team keys from a recovery string (read from stdin when omitted)
    Import { text: Option<String> },
}

#[cfg(not(feature = "sync"))]
pub fn run(_args: Args) -> anyhow::Result<()> {
    super::not_implemented("team")
}

#[cfg(feature = "sync")]
pub fn run(args: Args) -> anyhow::Result<()> {
    imp::run(args)
}

#[cfg(feature = "sync")]
mod imp {
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::{BufRead, IsTerminal};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use anyhow::{anyhow, bail, Context, Result};
    use awm_proto::crypto::{open_record, RecordAd};
    use awm_proto::keys::{
        self, approve, ApprovalInfo, DeviceKeys, DeviceStatus, Invite, KeyRing, ListedDevice,
        Roster, RosterEntry, ROSTER_TAG,
    };
    use awm_proto::wire::{
        ApproveRequest, BootstrapRequest, BootstrapResponse, Cursor, DeleteRequest, EpochWrap,
        ErrorCode, Handle, Id, InviteKind, InviteRequest, InviteResponse, JoinRequest,
        JoinResponse, Key32, MembersResponse, OrgSettings, PolicyPlaintext, PullRequest,
        PulledItem, RemoveRequest, Role, RosterPlaintext, SettingsUpdate, StatusResponse, Tag,
        Version, B64,
    };
    use rusqlite::{params, Connection, OptionalExtension};
    use serde_json::{json, Value};

    use super::{Args, KeySub, PolicySub, Sub, TokenSub};
    use crate::cli::fmt_ts;
    use crate::db::{self, Role as DbRole, VersionCheck};
    use crate::paths;
    use crate::sync::http::{check_url, CallError, Client};
    use crate::sync::state::{self, Identity, PendingInvite, SyncState, TeamKey, TeamToml};
    use crate::sync::{self, pull, push, roster, Env, Opts, Outcome, Report, Session};
    use crate::team::{self, bare_handle, JoinState};

    const NOT_IN_TEAM: &str =
        "this machine is not in a team: run awm team create or awm team join first";

    pub fn run(args: Args) -> Result<()> {
        let ctx = Ctx {
            env: Env::from_environment()?,
        };
        match args.command {
            Sub::Create {
                url,
                token,
                handle,
                ca_file,
            } => create(&ctx, &url, &token, &handle, ca_file),
            Sub::Invite {
                handle,
                admin,
                expires,
            } => invite(&ctx, &handle, admin, &expires),
            Sub::Join {
                url,
                token,
                ca_file,
            } => join(&ctx, &url, &token, ca_file),
            Sub::AddDevice {
                for_handle,
                expires,
            } => add_device(&ctx, for_handle.as_deref(), &expires),
            Sub::Approve { handle, code } => approve_cmd(&ctx, handle.as_deref(), code.as_deref()),
            Sub::Members { json, trust_admin } => members(&ctx, json, &trust_admin),
            Sub::Remove {
                handle,
                delete_records,
            } => remove(&ctx, &handle, delete_records),
            Sub::RotateKey => rotate_key(&ctx),
            Sub::Share { path } => share(&ctx, path),
            Sub::Unshare {
                path,
                delete,
                record,
            } => match record {
                Some(id) => unshare_record(&ctx, &id),
                None => unshare(&ctx, path, delete),
            },
            Sub::Status { json } => status(&ctx, json),
            Sub::Leave { delete } => leave(&ctx, delete),
            Sub::DeleteMine => delete_mine(&ctx),
            Sub::Move { url } => move_to(&ctx, &url),
            Sub::Policy { command } => match command {
                PolicySub::Show { json } => policy_show(&ctx, json),
                PolicySub::Set { assignments } => policy_set(&ctx, &assignments),
            },
            Sub::Audit { delete } => audit(&ctx, delete),
            Sub::AuditLog { json, from } => audit_log(&ctx, json, from),
            Sub::Flag { id, reason } => flag(&ctx, &id, reason.as_deref()),
            Sub::Token {
                command: TokenSub::Rotate,
            } => token_rotate(&ctx),
            Sub::Key { command } => match command {
                KeySub::Export => key_export(&ctx),
                KeySub::Import { text } => key_import(&ctx, text),
            },
        }
    }

    // -----------------------------------------------------------------------------------------
    // Shared plumbing

    struct Ctx {
        env: Env,
    }

    impl Ctx {
        fn dir(&self) -> &Path {
            &self.env.data_dir
        }
    }

    fn now_ms() -> i64 {
        crate::hook::now_ms()
    }

    fn open_db(dir: &Path, role: DbRole) -> Result<Connection> {
        let path = dir.join(paths::DB_FILE);
        if !path.is_file() {
            bail!("no database at {}. Run: awm init", path.display());
        }
        let conn = db::open(&path, role)?;
        match db::check_version(&conn)? {
            VersionCheck::Current => Ok(conn),
            VersionCheck::Older { .. } => bail!("database needs an upgrade. Run: awm doctor"),
            VersionCheck::Newer { db, .. } => {
                bail!("database is from a newer awm ({db}). Upgrade awm.")
            }
        }
    }

    /// `sync.lock`, waiting up to 10 s (plan-v3-team §3.6), then refusing.
    fn lock(dir: &Path) -> Result<std::fs::File> {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let f = opts
            .open(dir.join(sync::LOCK_FILE))
            .context("cannot open sync.lock")?;
        let start = Instant::now();
        loop {
            match f.try_lock() {
                Ok(()) => return Ok(f),
                Err(std::fs::TryLockError::WouldBlock)
                    if start.elapsed() < Duration::from_secs(10) =>
                {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    bail!("awm sync is running (sync.lock is held): try again in a moment")
                }
                Err(std::fs::TryLockError::Error(e)) => {
                    return Err(e).context("cannot take sync.lock")
                }
            }
        }
    }

    fn client_of(ident: &Identity) -> Result<Client> {
        let ca = ident.team.ca_file.as_deref().map(Path::new);
        Client::new(&ident.team.server_url, Some(&ident.key.device_token), ca)
    }

    fn proto_err(e: awm_proto::crypto::Error) -> anyhow::Error {
        anyhow!("{e}")
    }

    /// The identity of a device that holds the team keys (a waiting join is completed first).
    fn ready(ctx: &Ctx) -> Result<Identity> {
        match team::finish_join(ctx.dir())? {
            JoinState::NotInTeam => bail!(NOT_IN_TEAM),
            JoinState::Waiting { .. } => bail!(
                "this device is waiting for an approval (awm team status shows the code to read out)"
            ),
            JoinState::Ready => Identity::load(ctx.dir()),
        }
    }

    /// The local roster, verified over the stored roster records.
    fn local_roster(conn: &Connection, ident: &Identity) -> Result<Roster> {
        Ok(roster::verify_and_store(conn, &ident.ring()?, now_ms())?.0)
    }

    /// The roster verified with the trusted admins (RVT1 M5: they count only while no verified
    /// admin is left; `extra_admins_ignored` says when they were not used).
    fn verify_trusted(conn: &Connection, ring: &KeyRing) -> Result<keys::RosterReport> {
        let extra: BTreeSet<_> = state::trusted_admins(conn)?
            .iter()
            .filter_map(|m| Id::parse(m).ok().map(|id| *id.as_uuid()))
            .collect();
        Ok(Roster::verify(ring, &roster::blobs(conn)?, &extra))
    }

    /// Runs `f` on an engine session: `sync.lock` held, the database open as `Sync`, the roster
    /// verified; with `fresh`, the status read, new keys taken and every stream pulled first.
    fn with_session<R>(
        ctx: &Ctx,
        fresh: bool,
        f: impl FnOnce(&mut Session<'_>) -> Result<R>,
    ) -> Result<R> {
        let _ = ready(ctx)?;
        let _lock = lock(ctx.dir())?;
        let ident = Identity::load(ctx.dir())?;
        let conn = open_db(ctx.dir(), DbRole::Sync)?;
        let ring = ident.ring()?;
        let client = client_of(&ident)?;
        let opts = Opts::default();
        let mut s = Session {
            env: &ctx.env,
            opts: &opts,
            device: ident.device_keys(),
            conn,
            ident,
            ring,
            client,
            status: None,
            roster: Roster::default(),
            keys_refreshed: false,
            report: Report::default(),
        };
        s.roster = roster::verify_and_store(&s.conn, &s.ring, now_ms())?.0;
        if fresh {
            let st = s.client.status()?;
            let epoch = st.current_epoch;
            s.status = Some(st);
            if epoch > s.ring.current_epoch() {
                push::refresh_keys(&mut s)?;
            }
            pull::run(&mut s)?;
            s.roster = roster::verify_and_store(&s.conn, &s.ring, now_ms())?.0;
        }
        f(&mut s)
    }

    /// Sends what a command queued; a failure leaves it in the outbox for the next `awm sync`.
    fn flush_or_queue(s: &mut Session<'_>) {
        if let Err(e) = push::flush(s) {
            eprintln!("awm: queued for the next awm sync ({e})");
        }
    }

    fn offline(e: &CallError) -> bool {
        matches!(e, CallError::Network(_)) || e.status().is_some_and(|s| s >= 500)
    }

    fn handle_arg(h: &str) -> Result<Handle> {
        Handle::parse(bare_handle(h))
            .map_err(|_| anyhow!("a handle is 1-24 characters of a-z, 0-9, _ and -"))
    }

    fn ca_string(ca: Option<PathBuf>) -> Result<Option<String>> {
        ca.map(|p| {
            let abs = std::fs::canonicalize(&p)
                .with_context(|| format!("cannot read the CA file {}", p.display()))?;
            Ok(abs.to_string_lossy().into_owned())
        })
        .transpose()
    }

    /// The team member of a handle in the verified roster (removed members included when
    /// `removed` is true).
    fn roster_member(roster: &Roster, handle: &str, removed: bool) -> Option<Id> {
        roster
            .members()
            .find(|(_, m)| m.handle == handle && (removed || !m.revoked))
            .map(|(id, _)| Id::from(*id))
    }

    fn handles(conn: &Connection) -> Result<BTreeMap<String, String>> {
        let mut st = conn.prepare("SELECT member_id, handle FROM team_member")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    fn write_identity(dir: &Path, team: &TeamToml, key: &TeamKey) -> Result<()> {
        team.save(dir)?;
        key.save(dir)
    }

    // -----------------------------------------------------------------------------------------
    // create, invite, join, add-device

    fn refuse_if_in_team(dir: &Path) -> Result<()> {
        if state::team_toml_path(dir).exists() || state::team_key_path(dir).exists() {
            bail!(
                "this data directory is already in an organisation (team.toml exists): one \
                 organisation per data directory; awm team leave first"
            );
        }
        Ok(())
    }

    fn create(
        ctx: &Ctx,
        url: &str,
        token: &str,
        handle: &str,
        ca_file: Option<PathBuf>,
    ) -> Result<()> {
        let dir = ctx.dir();
        refuse_if_in_team(dir)?;
        let handle = handle_arg(handle)?;
        let token = awm_proto::wire::BootstrapToken::parse(token.trim()).map_err(|_| {
            anyhow!("--token takes the bootstrap token that awm serve init printed (awm_b_...)")
        })?;
        let url = check_url(url)?;
        let ca = ca_string(ca_file)?;
        let mut conn = open_db(dir, DbRole::Cli)?;

        // Device key and id first, then the organisation key and id (crypto §12 Create).
        let keys = DeviceKeys::generate().map_err(proto_err)?;
        let device = Id::new_v4();
        let (ring, nonce) = KeyRing::create(*device.as_uuid(), &keys.public).map_err(proto_err)?;
        let org = Id::from(ring.org());
        let client = Client::new(&url, None, ca.as_deref().map(Path::new))?;
        let resp: BootstrapResponse = client
            .post(
                "/v1/bootstrap",
                &BootstrapRequest {
                    bootstrap_token: token,
                    org_id: org,
                    handle: handle.clone(),
                    device_id: device,
                    device_pubkey: Key32(keys.public),
                },
            )
            .map_err(|e| match (e.status(), e.code()) {
                (Some(410), _) => anyhow!(
                    "the bootstrap token is used or expired, or the server already has an \
                     admin: run awm serve init for a new one"
                ),
                (Some(409), _) => anyhow!("the server already holds this organisation id"),
                _ => anyhow!(e),
            })?;
        if resp.org_id != org || resp.device_id != device {
            bail!("the server answered for another organisation or device: nothing written");
        }
        let team = TeamToml {
            server_url: url.clone(),
            org_id: org,
            member_id: resp.member_id,
            handle: handle.as_str().to_string(),
            device_id: device,
            ca_file: ca,
        };
        let mut key = TeamKey {
            device_token: resp.device_token.as_str().to_string(),
            previous_device_token: None,
            device_secret: Key32(*keys.secret_bytes()),
            epoch_keys: Vec::new(),
            pending_invites: Vec::new(),
            extra: Default::default(),
        };
        key.set_ring(&ring);
        write_identity(dir, &team, &key)?;
        team::write_repo_key(dir, &ring)?;
        let ident = Identity::load(dir)?;
        push::queue_roster_entry(
            &mut conn,
            &ident,
            &ring,
            &RosterEntry::Genesis {
                member_id: *resp.member_id.as_uuid(),
                handle: handle.as_str().to_string(),
                device_id: *device.as_uuid(),
                device_pub: keys.public,
                org_nonce: nonce,
                created_at: now_ms() / 1_000,
            },
            now_ms(),
        )?;
        roster::verify_and_store(&conn, &ring, now_ms())?;
        println!("created organisation {org} on {url}");
        println!("you are @{} (admin) on device {device}", handle.as_str());
        println!("next: awm sync, then awm team invite --handle NAME");
        Ok(())
    }

    /// The refusal for a 403 or 402 on `POST /v1/invites` (§4.8: beyond `max_members` or the
    /// plan, or not an admin).
    fn invite_refusal(
        ident: &Identity,
        client: &Client,
        conn: &Connection,
        e: CallError,
    ) -> anyhow::Error {
        match e.status() {
            Some(402) => {
                anyhow!("refused: the cloud plan allows no more members (awm cloud billing)")
            }
            Some(403) => {
                let admin = local_roster(conn, ident)
                    .map(|r| roster::own_member_is_admin(&r, ident))
                    .unwrap_or(false);
                if !admin {
                    return anyhow!("refused: only admins invite members");
                }
                match client.get::<OrgSettings>("/v1/org/settings") {
                    Ok(s) => anyhow!(
                        "refused: the organisation is at max_members ({}) counting open \
                         invites; raise it with awm team policy set max_members=N",
                        s.max_members
                    ),
                    Err(_) => anyhow!("refused: the organisation is at max_members"),
                }
            }
            Some(503) => anyhow!("refused for now: the server waits for an admin after a restore"),
            _ => anyhow!(e),
        }
    }

    fn create_invite(
        ctx: &Ctx,
        req: InviteRequest,
        kind: &str,
        member_id: Option<Id>,
    ) -> Result<String> {
        let dir = ctx.dir();
        let _ = ready(ctx)?;
        let _lock = lock(dir)?;
        let mut ident = Identity::load(dir)?;
        let conn = open_db(dir, DbRole::Cli)?;
        let client = client_of(&ident)?;
        let handle = req.handle.as_str().to_string();
        let role = req.role;
        let resp: InviteResponse = client
            .post("/v1/invites", &req)
            .map_err(|e| invite_refusal(&ident, &client, &conn, e))?;
        let invite = Invite::create(
            *ident.team.org_id.as_uuid(),
            &resp.invite_id.to_string(),
            resp.invite_token.as_str(),
            &handle,
        )
        .map_err(proto_err)?;
        let text = invite.encode();
        ident.key.pending_invites.push(PendingInvite {
            invite: text.clone(),
            kind: kind.to_string(),
            member_id: member_id.map(|m| m.to_string()),
            role: role.map(|r| if r == Role::Admin { "admin" } else { "member" }.to_string()),
        });
        ident.save_key(dir)?;
        println!("awm team join {} --token {text}", ident.team.server_url);
        eprintln!(
            "awm: the invite works once, until {} UTC; send it through a channel you trust",
            fmt_ts(resp.expires_at * 1_000)
        );
        Ok(handle)
    }

    fn invite(ctx: &Ctx, handle: &str, admin: bool, expires: &str) -> Result<()> {
        let days = team::parse_expires(expires)?;
        let handle = handle_arg(handle)?;
        let h = create_invite(
            ctx,
            InviteRequest {
                kind: InviteKind::Member,
                handle,
                role: Some(if admin { Role::Admin } else { Role::Member }),
                expires_days: Some(days),
            },
            "member",
            None,
        )?;
        eprintln!("awm: when @{h} has joined, compare the code and run: awm team approve {h}");
        Ok(())
    }

    fn add_device(ctx: &Ctx, for_handle: Option<&str>, expires: &str) -> Result<()> {
        let days = team::parse_expires(expires)?;
        let ident = ready(ctx)?;
        let (handle, member) = match for_handle {
            None => (ident.team.handle.clone(), ident.team.member_id),
            Some(h) => {
                let h = handle_arg(h)?;
                let conn = open_db(ctx.dir(), DbRole::Cli)?;
                let roster = local_roster(&conn, &ident)?;
                if !roster::own_member_is_admin(&roster, &ident) {
                    bail!("--for is for admins: ask an admin of your team");
                }
                let m = roster_member(&roster, h.as_str(), false).ok_or_else(|| {
                    anyhow!("@{} is not a verified member (run awm sync)", h.as_str())
                })?;
                (h.as_str().to_string(), m)
            }
        };
        create_invite(
            ctx,
            InviteRequest {
                kind: InviteKind::Device,
                handle: handle_arg(&handle)?,
                role: None,
                expires_days: Some(days),
            },
            "device",
            Some(member),
        )?;
        if member == ident.team.member_id {
            eprintln!(
                "awm: run it on the new machine; this device approves it at its next awm sync"
            );
        } else {
            eprintln!("awm: when the device has joined, compare the code and run: awm team approve {handle}");
        }
        Ok(())
    }

    fn join(ctx: &Ctx, url: &str, token: &str, ca_file: Option<PathBuf>) -> Result<()> {
        let dir = ctx.dir();
        refuse_if_in_team(dir)?;
        let invite = Invite::parse(token.trim())
            .map_err(|_| anyhow!("--token takes the invite string (awmi1_...) you were sent"))?;
        // RVT1 m8: the invite's organisation must be its token's, before any request.
        let org = team::check_invite_org(&invite)?;
        let url = check_url(url)?;
        let ca = ca_string(ca_file)?;
        let _ = open_db(dir, DbRole::Cli)?;
        let invite_id = Id::parse(&invite.invite_id)
            .map_err(|_| anyhow!("the invite string holds no valid invite id"))?;
        let invite_token = awm_proto::wire::InviteToken::parse(&invite.token)
            .map_err(|_| anyhow!("the invite string holds no valid invite token"))?;
        let handle = handle_arg(&invite.handle)?;
        let keys = DeviceKeys::generate().map_err(proto_err)?;
        let device = Id::new_v4();
        let req = keys::JoinRequest::new(&invite, *device.as_uuid(), &keys);
        let client = Client::new(&url, None, ca.as_deref().map(Path::new))?;
        let resp: JoinResponse = client
            .post(
                "/v1/join",
                &JoinRequest {
                    invite_id,
                    invite_token,
                    handle: handle.clone(),
                    device_id: device,
                    device_pubkey: Key32(keys.public),
                    join_mac: Key32(req.mac),
                },
            )
            .map_err(|e| match (e.status(), e.code()) {
                (Some(410), _) => anyhow!("this invite is used or expired: ask for a new one"),
                (Some(401), _) => anyhow!("the server does not hold this invite's organisation"),
                (Some(400), Some(ErrorCode::InvalidValue)) => {
                    anyhow!("the server refused the join (the handle differs from the invite's)")
                }
                (Some(426), _) => anyhow!("the team requires a newer awm: upgrade, then join"),
                (Some(503), _) => {
                    anyhow!("the server waits for an admin after a restore: try later")
                }
                _ => anyhow!(e),
            })?;
        if resp.org_id != org || resp.device_id != device {
            bail!("the server answered for another organisation or device: nothing written");
        }
        let team = TeamToml {
            server_url: url.clone(),
            org_id: org,
            member_id: resp.member_id,
            handle: handle.as_str().to_string(),
            device_id: device,
            ca_file: ca,
        };
        let mut key = TeamKey {
            device_token: resp.device_token.as_str().to_string(),
            previous_device_token: None,
            device_secret: Key32(*keys.secret_bytes()),
            epoch_keys: Vec::new(),
            pending_invites: Vec::new(),
            extra: Default::default(),
        };
        key.extra.insert(
            team::JOIN_INVITE.to_string(),
            Value::String(invite.encode()),
        );
        write_identity(dir, &team, &key)?;
        println!(
            "joined organisation {org} as @{}: waiting for approval",
            handle.as_str()
        );
        println!(
            "read this code to the person who invited you: {}",
            invite.confirmation_code(*device.as_uuid(), &keys.public)
        );
        println!("device fingerprint: {}", keys.fingerprint());
        println!("then run awm team status (or awm sync) here to take the team key");
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // approve

    fn digits(s: &str) -> String {
        s.chars().filter(char::is_ascii_digit).collect()
    }

    fn confirm_code(expected: &str, given: Option<&str>, handle: &str) -> Result<()> {
        let given = match given {
            Some(c) => c.to_string(),
            None if std::io::stdin().is_terminal() => {
                eprint!("type the 6-digit code @{handle} reads out from awm team join: ");
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line)?;
                line
            }
            None => bail!(
                "compare the code with the one @{handle} reads out, then run: awm team approve \
                 {handle} --code NNNNNN"
            ),
        };
        if digits(&given).len() != 6 || digits(&given) != digits(expected) {
            bail!(
                "the code does not match: not approved. If @{handle} reads out another code, \
                 someone else may have used the invite: send a new one"
            );
        }
        Ok(())
    }

    fn approve_cmd(ctx: &Ctx, handle: Option<&str>, code: Option<&str>) -> Result<()> {
        let wanted = handle.map(handle_arg).transpose()?;
        with_session(ctx, true, |s| {
            let status = s.status.clone().ok_or_else(|| anyhow!("no status"))?;
            let mut mine = Vec::new();
            let mut elsewhere = Vec::new();
            for p in &status.pending {
                if wanted.as_ref().is_some_and(|h| h != &p.handle) {
                    continue;
                }
                match team::find_invite(&s.ident.key, p.invite_id) {
                    Some((pos, record, invite)) => mine.push((p.clone(), pos, record, invite)),
                    None => elsewhere.push(p.handle.as_str().to_string()),
                }
            }
            if mine.is_empty() {
                if let Some(h) = elsewhere.first() {
                    bail!("the invite of @{h} was made on another device: approve it there");
                }
                match &wanted {
                    Some(h) => bail!("no pending join of @{}", h.as_str()),
                    None => {
                        println!("nothing to approve");
                        return Ok(());
                    }
                }
            }
            if mine.len() > 1 && wanted.is_none() {
                for (p, ..) in &mine {
                    println!("pending: @{} ({})", p.handle.as_str(), kind_name(p.kind));
                }
                bail!("name the join to approve: awm team approve HANDLE");
            }
            let (p, pos, record, invite) = mine.remove(0);
            let (kind, member_id, role) = team::approval_plan(&p, &record, s.ident.team.member_id)?;
            if p.handle.as_str() != invite.handle {
                bail!("the server lists another handle for this invite: not approved");
            }
            let request = keys::JoinRequest {
                invite_id: invite.invite_id.clone(),
                handle: invite.handle.clone(),
                device_id: *p.device_id.as_uuid(),
                public_key: p.device_pubkey.0,
                mac: p.join_mac.0,
            };
            let verified = invite.verify_join(&request).map_err(|_| {
                anyhow!(
                    "the join of @{} does not verify with this invite's secret (another key or \
                     a forged request): not approved",
                    invite.handle
                )
            })?;
            println!(
                "@{} ({}), device {}\n  fingerprint {}\n  code {}",
                invite.handle,
                kind_name(p.kind),
                p.device_id,
                verified.fingerprint(),
                verified.code()
            );
            confirm_code(verified.code(), code, &invite.handle)?;
            let now = now_ms();
            let approval = approve(
                &s.ring,
                &s.roster,
                &invite,
                &verified,
                ApprovalInfo {
                    member_id: *member_id.as_uuid(),
                    kind,
                    role,
                    approver_device: *s.ident.team.device_id.as_uuid(),
                    approved_at: now / 1_000,
                },
            )
            .map_err(|e| anyhow!("not approved: {e}"))?;
            let body = ApproveRequest {
                wraps: approval
                    .wraps
                    .iter()
                    .map(|w| EpochWrap {
                        epoch: w.epoch,
                        wrap: B64(w.blob.clone()),
                        auth: Key32(w.auth),
                    })
                    .collect(),
            };
            s.client.approve_device(p.device_id, &body)?;
            push::queue_roster_entry(&mut s.conn, &s.ident, &s.ring, &approval.roster, now)?;
            s.ident.key.pending_invites.remove(pos);
            s.ident.save_key(&s.env.data_dir)?;
            s.roster = roster::verify_and_store(&s.conn, &s.ring, now)?.0;
            flush_or_queue(s);
            println!("approved @{}", invite.handle);
            Ok(())
        })
    }

    fn kind_name(k: InviteKind) -> &'static str {
        match k {
            InviteKind::Member => "member join",
            InviteKind::Device => "new device",
            InviteKind::Unknown => "unknown kind",
        }
    }

    // -----------------------------------------------------------------------------------------
    // members

    fn device_status_name(s: DeviceStatus) -> &'static str {
        match s {
            DeviceStatus::Verified => "verified",
            DeviceStatus::Unverified => "unverified",
            DeviceStatus::Mismatch => "mismatch",
            DeviceStatus::Revoked => "revoked",
        }
    }

    fn members(ctx: &Ctx, json_out: bool, trust: &[String]) -> Result<()> {
        let ident = ready(ctx)?;
        let client = client_of(&ident)?;
        let listed: MembersResponse = client.members().map_err(|e| match e.status() {
            Some(403) => anyhow!("this device is not approved yet"),
            _ => anyhow!(e),
        })?;
        let conn = open_db(ctx.dir(), DbRole::Cli)?;
        if !trust.is_empty() {
            let mut ids = Vec::new();
            for h in trust {
                let h = bare_handle(h);
                let m = listed
                    .members
                    .iter()
                    .find(|m| m.handle.as_str() == h && m.role == Role::Admin && m.active)
                    .ok_or_else(|| {
                        anyhow!("@{h} is not an admin on the server: nothing trusted")
                    })?;
                ids.push(m.member_id.to_string());
            }
            state::add_trusted_admins(&conn, &ids)?;
        }
        let ring = ident.ring()?;
        let roster = roster::verify_and_store(&conn, &ring, now_ms())?.0;
        let report = verify_trusted(&conn, &ring)?;
        let mut out = Vec::new();
        for m in &listed.members {
            let rm = roster.member(*m.member_id.as_uuid());
            let role = match rm {
                Some(r) if r.admin => "admin",
                Some(_) => "member",
                None => "unverified",
            };
            let devices: Vec<Value> = m
                .devices
                .iter()
                .map(|d| {
                    let st = roster.status(&ListedDevice {
                        member_id: *m.member_id.as_uuid(),
                        device_id: *d.device_id.as_uuid(),
                        public_key: d.device_pubkey.0,
                    });
                    let state = if d.revoked {
                        "revoked"
                    } else if !d.approved {
                        "pending"
                    } else {
                        device_status_name(st)
                    };
                    json!({
                        "device_id": d.device_id.to_string(),
                        "fingerprint": keys::fingerprint(&d.device_pubkey.0),
                        "status": state,
                        "this_device": d.device_id == ident.team.device_id,
                    })
                })
                .collect();
            out.push(json!({
                "member_id": m.member_id.to_string(),
                "handle": m.handle.as_str(),
                "role": role,
                "server_role": if m.role == Role::Admin { "admin" } else { "member" },
                "active": m.active && !rm.is_some_and(|r| r.revoked),
                "devices": devices,
            }));
        }
        let trusted = state::trusted_admins(&conn)?;
        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "members": out,
                    "trusted_admins": trusted,
                    "extra_admins_ignored": report.extra_admins_ignored,
                }))?
            );
            return Ok(());
        }
        for m in &out {
            println!(
                "@{}  {}{}{}",
                m["handle"].as_str().unwrap_or(""),
                m["role"].as_str().unwrap_or(""),
                if m["active"].as_bool() == Some(false) {
                    "  removed"
                } else {
                    ""
                },
                if m["member_id"].as_str() == Some(&ident.team.member_id.to_string()) {
                    "  (you)"
                } else {
                    ""
                },
            );
            for d in m["devices"].as_array().into_iter().flatten() {
                println!(
                    "  device {}  {}  {}{}",
                    d["device_id"].as_str().unwrap_or(""),
                    d["fingerprint"].as_str().unwrap_or(""),
                    d["status"].as_str().unwrap_or(""),
                    if d["this_device"].as_bool() == Some(true) {
                        "  (this device)"
                    } else {
                        ""
                    },
                );
            }
        }
        if !trusted.is_empty() {
            if report.extra_admins_ignored {
                println!("trusted admins are ignored: the roster holds a verified admin (RVT1 M5)");
            } else {
                println!(
                    "no verified admin is left: the operator decided who is admin (trusted: {})",
                    trusted.len()
                );
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // remove, rotate-key

    /// Rotates now, whatever the server's `rotation_needed` says, wrapping only to devices the
    /// roster verifies (`roster::rotate_if_needed`, §5.1).
    fn rotate_now(s: &mut Session<'_>) -> Result<bool> {
        if let Some(st) = s.status.as_mut() {
            st.rotation_needed = true;
        }
        roster::rotate_if_needed(s)
    }

    fn rotation_counts(conn: &Connection) -> Result<[i64; 3]> {
        Ok([
            state::get_i64(conn, "dropped.rotation_unverified")?.unwrap_or(0),
            state::get_i64(conn, "dropped.rotation_mismatch")?.unwrap_or(0),
            state::get_i64(conn, "dropped.rotation_approved_by_removed")?.unwrap_or(0),
        ])
    }

    fn report_rotation(s: &Session<'_>, before: [i64; 3]) -> Result<()> {
        let after = rotation_counts(&s.conn)?;
        println!(
            "the team key was rotated to epoch {}",
            s.ring.current_epoch()
        );
        let names = [
            "device(s) without a verified roster entry got no key",
            "device(s) whose server entry differs from the roster got no key",
            "device(s) approved by a removed member or a revoked device got the key: check them",
        ];
        for ((a, b), name) in after.iter().zip(before).zip(names) {
            if a > &b {
                println!("  {} {name}", a - b);
            }
        }
        Ok(())
    }

    fn remove(ctx: &Ctx, handle: &str, delete_records: bool) -> Result<()> {
        let h = handle_arg(handle)?;
        let me = ready(ctx)?;
        if h.as_str() == me.team.handle {
            bail!("to take this machine out of the team, run awm team leave");
        }
        with_session(ctx, true, |s| {
            if !roster::own_member_is_admin(&s.roster, &s.ident) {
                bail!("only admins remove members");
            }
            let member = match roster_member(&s.roster, h.as_str(), false) {
                Some(m) => m,
                None => s
                    .client
                    .members()?
                    .members
                    .iter()
                    .find(|m| m.handle == h && m.active)
                    .map(|m| m.member_id)
                    .ok_or_else(|| anyhow!("@{} is not a member", h.as_str()))?,
            };
            s.client
                .post_unit(
                    &format!("/v1/members/{member}/remove"),
                    &RemoveRequest {
                        delete_records: delete_records.then_some(true),
                    },
                )
                .map_err(|e| match e.code() {
                    Some(ErrorCode::LastAdmin) => {
                        anyhow!("@{} is the last admin: promote another first", h.as_str())
                    }
                    _ => anyhow!(e),
                })?;
            let now = now_ms();
            push::queue_roster_entry(
                &mut s.conn,
                &s.ident,
                &s.ring,
                &RosterEntry::Revoke {
                    member_id: *member.as_uuid(),
                    device_id: None,
                    revoked_at: now / 1_000,
                    by_device_id: *s.ident.team.device_id.as_uuid(),
                },
                now,
            )?;
            s.roster = roster::verify_and_store(&s.conn, &s.ring, now)?.0;
            println!(
                "removed @{}: tokens revoked{}",
                h.as_str(),
                if delete_records {
                    ", records deleted"
                } else {
                    ""
                }
            );
            let before = rotation_counts(&s.conn)?;
            match rotate_now(s) {
                Ok(true) => report_rotation(s, before)?,
                Ok(false) => println!("the key rotation waits for the next awm sync"),
                Err(e) => eprintln!("awm: the key rotation waits for the next awm sync ({e})"),
            }
            flush_or_queue(s);
            Ok(())
        })
    }

    fn rotate_key(ctx: &Ctx) -> Result<()> {
        with_session(ctx, true, |s| {
            if !roster::own_member_is_admin(&s.roster, &s.ident) {
                bail!("only admins rotate the team key");
            }
            let before = rotation_counts(&s.conn)?;
            if !rotate_now(s)? {
                bail!("the key was not rotated (another admin rotated first: run awm sync)");
            }
            report_rotation(s, before)?;
            flush_or_queue(s);
            Ok(())
        })
    }

    // -----------------------------------------------------------------------------------------
    // share, unshare

    /// What `share` and `unshare` name: a repository (by `repo_key`) or a directory.
    struct Project {
        repo: Option<(String, PathBuf)>,
        hashes: Vec<String>,
        shown: String,
    }

    fn project_of(dir: &Path, path: Option<PathBuf>) -> Result<Project> {
        let path = path.unwrap_or_else(|| PathBuf::from("."));
        let canon = std::fs::canonicalize(&path)
            .with_context(|| format!("no directory {}", path.display()))?;
        if !canon.is_dir() {
            bail!("{} is not a directory", path.display());
        }
        let mut hashes = team::cwd_hashes(&path);
        let repo = if team::origin_remote(&canon).is_some() {
            let key = team::read_repo_key(dir).map_err(|_| {
                anyhow!("team.repo is missing: finish the join first (awm team status)")
            })?;
            team::repo_key_for(&canon, &key)
        } else {
            None
        };
        if let Some((_, root)) = &repo {
            hashes.extend(team::cwd_hashes(root));
            hashes.sort();
            hashes.dedup();
        }
        let shown = match &repo {
            Some((_, root)) => format!("the repository at {}", root.display()),
            None => format!("the directory {}", canon.display()),
        };
        Ok(Project {
            repo,
            hashes,
            shown,
        })
    }

    fn share(ctx: &Ctx, path: Option<PathBuf>) -> Result<()> {
        let dir = ctx.dir();
        if !state::configured(dir) {
            bail!("share works inside an organisation: run awm team join or awm team create first");
        }
        let p = project_of(dir, path)?;
        let conn = open_db(dir, DbRole::Cli)?;
        let now = now_ms();
        match &p.repo {
            Some((rk, _)) => {
                conn.execute(
                    "INSERT OR IGNORE INTO share_rule (kind, value, created_at) VALUES ('repo', ?1, ?2)",
                    params![rk, now],
                )?;
                for h in &p.hashes {
                    conn.execute(
                        "INSERT INTO project (cwd_hash, repo_key, updated_at) VALUES (?1, ?2, ?3) \
                         ON CONFLICT(cwd_hash) DO UPDATE SET repo_key = excluded.repo_key, \
                           updated_at = excluded.updated_at",
                        params![h, rk, now],
                    )?;
                }
            }
            None => {
                for h in &p.hashes {
                    conn.execute(
                        "INSERT OR IGNORE INTO share_rule (kind, value, created_at) VALUES ('cwd', ?1, ?2)",
                        params![h, now],
                    )?;
                }
            }
        }
        println!("sharing records of {} captured from now on", p.shown);
        println!(
            "earlier records stay local unless you run: awm sync --backfill --since YYYY-MM-DD --project PATH"
        );
        Ok(())
    }

    /// Withdraws own records: each becomes a deletion marker in `sync_own`, gets its `team:`
    /// tombstone and an outbox `delete` row (TM11's path), all in one transaction under
    /// `sync.lock`; then the deletions are sent in the foreground (§3.6) or stay queued.
    fn delete_own(ctx: &Ctx, ids: &[String], never: bool, drop_rows: bool) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        with_session(ctx, false, |s| {
            let now = now_ms();
            let tx = s.conn.transaction()?;
            for id in ids {
                tx.execute(
                    "UPDATE sync_own SET deleted = 1, blob = NULL, epoch = NULL WHERE record_id = ?1",
                    [id],
                )?;
                tx.execute(
                    "INSERT OR IGNORE INTO tombstone (kind, value, created_at) VALUES ('tool_use_id', ?1, ?2)",
                    params![format!("team:{id}"), now],
                )?;
                tx.execute(
                    "INSERT INTO sync_outbox (kind, ref, created_at) VALUES ('delete', ?1, ?2)",
                    params![id, now],
                )?;
                if never {
                    tx.execute(
                        "UPDATE event SET shareable = 'never' WHERE sync_id = ?1 AND origin = 'local'",
                        [id],
                    )?;
                }
                if drop_rows {
                    tx.execute(
                        "DELETE FROM event WHERE sync_id = ?1 AND origin = 'team'",
                        [id],
                    )?;
                }
            }
            tx.commit()?;
            match push::deletions(s) {
                Ok(_) => println!("deleted {} shared record(s) from the server", ids.len()),
                Err(e) => println!(
                    "{} deletion(s) queued for the next awm sync (the server did not answer: {e})",
                    ids.len()
                ),
            }
            Ok(())
        })
    }

    fn unshare(ctx: &Ctx, path: Option<PathBuf>, delete: bool) -> Result<()> {
        let dir = ctx.dir();
        if !state::configured(dir) {
            bail!(NOT_IN_TEAM);
        }
        let p = project_of(dir, path)?;
        let conn = open_db(dir, DbRole::Cli)?;
        let mut n = 0;
        if let Some((rk, _)) = &p.repo {
            n += conn.execute(
                "DELETE FROM share_rule WHERE kind = 'repo' AND value = ?1",
                [rk],
            )?;
        }
        for h in &p.hashes {
            n += conn.execute(
                "DELETE FROM share_rule WHERE kind = 'cwd' AND value = ?1",
                [h],
            )?;
        }
        if n == 0 {
            println!("{} was not shared", p.shown);
        } else {
            println!("stopped sharing {}", p.shown);
        }
        if delete {
            let mut ids: Vec<String> = Vec::new();
            let hashes = serde_json::to_string(&p.hashes)?;
            let rk = p.repo.as_ref().map(|(k, _)| k.clone());
            let mut st = conn.prepare(
                "SELECT sync_id FROM event WHERE origin = 'local' AND sync_id IS NOT NULL \
                 AND (cwd_hash IN (SELECT value FROM json_each(?1)) \
                   OR cwd_hash IN (SELECT cwd_hash FROM project WHERE repo_key = ?2))",
            )?;
            for r in st.query_map(params![hashes, rk], |r| r.get::<_, String>(0))? {
                ids.push(r?);
            }
            drop(st);
            drop(conn);
            if ids.is_empty() {
                println!("no shared record of it to delete");
            }
            delete_own(ctx, &ids, false, false)?;
        }
        Ok(())
    }

    /// An `event` row named by its id or its record id.
    fn find_event(
        conn: &Connection,
        id: &str,
    ) -> Result<(i64, String, Option<String>, Option<String>)> {
        let by_id = id.trim().parse::<i64>().ok();
        conn.query_row(
            "SELECT id, origin, sync_id, member FROM event WHERE id = ?1 OR sync_id = ?2",
            params![by_id.unwrap_or(-1), id.trim()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?
        .ok_or_else(|| anyhow!("no record {}", id.trim()))
    }

    fn unshare_record(ctx: &Ctx, id: &str) -> Result<()> {
        let dir = ctx.dir();
        if !state::configured(dir) {
            bail!(NOT_IN_TEAM);
        }
        let ident = Identity::load(dir)?;
        let conn = open_db(dir, DbRole::Cli)?;
        let (event, origin, sync_id, member) = find_event(&conn, id)?;
        if origin == "team" && member.as_deref() != Some(&ident.team.member_id.to_string()) {
            bail!(
                "record {event} is a teammate's: only its author or an admin deletes it (awm team \
                 flag {event} reports it)"
            );
        }
        if origin == "local" {
            conn.execute(
                "UPDATE event SET shareable = 'never' WHERE id = ?1",
                [event],
            )?;
        }
        drop(conn);
        println!("record {event} will never be shared");
        if let Some(sid) = sync_id {
            delete_own(ctx, &[sid], origin == "local", origin == "team")?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // status

    fn status(ctx: &Ctx, json_out: bool) -> Result<()> {
        let dir = ctx.dir();
        if !state::configured(dir) {
            if json_out {
                println!("{}", json!({ "in_team": false }));
            } else {
                println!("not in a team");
            }
            return Ok(());
        }
        let join = team::finish_join(dir);
        let ident = Identity::load(dir)?;
        let conn = open_db(dir, DbRole::Cli)?;
        let st = SyncState::load(&conn)?;
        let server: Result<StatusResponse> = client_of(&ident).and_then(|c| Ok(c.status()?));
        let (reachable, server_error) = match &server {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };
        let (approval, push_stop, role) = match &join {
            Ok(JoinState::Waiting { code, fingerprint }) => (
                format!(
                    "waiting for approval: read this code to the person who invited you: {code} \
                     (fingerprint {fingerprint})"
                ),
                Some("this device is waiting for an approval".to_string()),
                "pending".to_string(),
            ),
            _ if ident.key.epoch_keys.is_empty() => (
                "waiting for approval (the server could not be asked)".to_string(),
                Some("this device is waiting for an approval".to_string()),
                "pending".to_string(),
            ),
            _ => {
                let roster = local_roster(&conn, &ident)?;
                let ok = roster::own_approval_ok(&roster, &ident);
                let role = if roster::own_member_is_admin(&roster, &ident) {
                    "admin"
                } else {
                    "member"
                };
                if ok {
                    ("approved".to_string(), None, role.to_string())
                } else {
                    (
                        "approved by the server, but the roster holds no verified approval of \
                         this device"
                            .to_string(),
                        Some(
                            "no verified roster entry for this device: run awm sync; if this \
                             stays, the approval was withheld or forged (ask the admin)"
                                .to_string(),
                        ),
                        role.to_string(),
                    )
                }
            }
        };
        let push_stop = push_stop.or_else(|| {
            st.min_client_block
                .as_ref()
                .map(|m| format!("this awm is older than the team's minimum {m}: upgrade awm"))
        });
        let mut outbox = BTreeMap::new();
        {
            let mut q = conn.prepare("SELECT kind, COUNT(*) FROM sync_outbox GROUP BY kind")?;
            for r in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
                let (k, n) = r?;
                outbox.insert(k, n);
            }
        }
        let skipped = state::skipped(&conn)?;
        let mut pending = Vec::new();
        if let Ok(sr) = &server {
            for p in &sr.pending {
                let mut entry = json!({
                    "handle": p.handle.as_str(),
                    "kind": kind_name(p.kind),
                    "device_id": p.device_id.to_string(),
                    "fingerprint": keys::fingerprint(&p.device_pubkey.0),
                });
                if let Some((_, _, invite)) = team::find_invite(&ident.key, p.invite_id) {
                    entry["code"] =
                        json!(invite.confirmation_code(*p.device_id.as_uuid(), &p.device_pubkey.0));
                    entry["approve_here"] = json!(true);
                }
                pending.push(entry);
            }
        }
        let trusted = state::trusted_admins(&conn)?;
        let extra_ignored = if trusted.is_empty() || ident.key.epoch_keys.is_empty() {
            false
        } else {
            verify_trusted(&conn, &ident.ring()?)?.extra_admins_ignored
        };
        let settings = server.as_ref().ok().map(|s| s.settings.clone());
        let v = json!({
            "in_team": true,
            "server_url": ident.team.server_url,
            "reachable": reachable,
            "server_error": server_error,
            "org_id": ident.team.org_id.to_string(),
            "member_id": ident.team.member_id.to_string(),
            "handle": ident.team.handle,
            "role": role,
            "device_id": ident.team.device_id.to_string(),
            "fingerprint": ident.device_keys().fingerprint(),
            "approval": approval,
            "push_blocked": push_stop,
            "epoch": ident.key.epoch_keys.iter().map(|e| e.epoch).max(),
            "last_ok": st.last_ok.map(fmt_ts),
            "last_error": st.last_error,
            "backoff_until": st.backoff_until.map(fmt_ts),
            "outbox": outbox,
            "skipped": skipped,
            "pending": pending,
            "trusted_admins": trusted,
            "extra_admins_ignored": extra_ignored,
            "settings": settings,
        });
        if json_out {
            println!("{}", serde_json::to_string_pretty(&v)?);
            return Ok(());
        }
        println!(
            "server        {} ({})",
            ident.team.server_url,
            match &server_error {
                None => "reachable".to_string(),
                Some(e) => format!("unreachable: {e}"),
            }
        );
        println!("organisation  {}", ident.team.org_id);
        println!(
            "member        @{} ({}), {role}",
            ident.team.handle, ident.team.member_id
        );
        println!(
            "device        {} (fingerprint {})",
            ident.team.device_id,
            ident.device_keys().fingerprint()
        );
        println!("approval      {approval}");
        if let Some(p) = &push_stop {
            println!("pushes        stopped: {p}");
        }
        println!(
            "last sync     {}",
            st.last_ok.map(fmt_ts).unwrap_or_else(|| "never".into())
        );
        if let Some(e) = &st.last_error {
            println!("last error    {e}");
        }
        let total: i64 = outbox.values().sum();
        println!(
            "outbox        {total}{}",
            if total > 0 {
                format!(
                    " ({})",
                    outbox
                        .iter()
                        .map(|(k, n)| format!("{k} {n}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                String::new()
            }
        );
        if !skipped.is_empty() {
            println!(
                "kept local    {} (last run)",
                skipped
                    .iter()
                    .map(|(k, n)| format!("{k} {n}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        for p in &pending {
            println!(
                "pending       @{} ({}), fingerprint {}{}",
                p["handle"].as_str().unwrap_or(""),
                p["kind"].as_str().unwrap_or(""),
                p["fingerprint"].as_str().unwrap_or(""),
                match p["code"].as_str() {
                    Some(c) => format!(
                        ", code {c}: awm team approve {}",
                        p["handle"].as_str().unwrap_or("")
                    ),
                    None => String::new(),
                }
            );
        }
        if !trusted.is_empty() {
            if extra_ignored {
                println!("admins        the roster's (trusted server admins are ignored while a verified admin exists)");
            } else {
                println!("admins        decided by the server operator: no verified admin is left");
            }
        }
        if let Some(s) = &settings {
            print!("retention     {} days", s.retention_days);
            if let Some(p) = &s.pending_retention {
                print!(
                    "; a decrease to {} days applies at {} UTC",
                    p.retention_days,
                    fmt_ts(p.effective_at * 1_000)
                );
            }
            println!();
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // leave, delete-mine, move

    /// Drops every team row, key and setting of this data directory (plan-v3-team §3.6 leave).
    fn wipe_local(dir: &Path) -> Result<()> {
        let mut conn = open_db(dir, DbRole::Cli)?;
        loop {
            let n = conn.execute(
                "DELETE FROM event WHERE id IN (SELECT id FROM event WHERE origin = 'team' LIMIT 25)",
                [],
            )?;
            if n == 0 {
                break;
            }
        }
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE event SET sync_id = NULL, sync_idx = NULL, pushed_at = NULL, \
               shareable = CASE WHEN shareable = 'never' THEN 'never' ELSE 'no' END \
             WHERE origin = 'local' AND (sync_id IS NOT NULL OR shareable IN ('full','link'))",
            [],
        )?;
        for t in [
            "team_member",
            "team_device",
            "sync_stream",
            "sync_outbox",
            "sync_own",
            "roster_record",
            "sync_state",
            "share_rule",
            "project",
        ] {
            tx.execute(&format!("DELETE FROM {t}"), [])?;
        }
        tx.commit()?;
        for f in [state::TEAM_TOML, state::TEAM_KEY, team::TEAM_REPO] {
            match std::fs::remove_file(dir.join(f)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("cannot remove {f}")),
            }
        }
        Ok(())
    }

    fn leave(ctx: &Ctx, delete: bool) -> Result<()> {
        let dir = ctx.dir();
        if !state::configured(dir) {
            bail!(NOT_IN_TEAM);
        }
        let ident = Identity::load(dir)?;
        let client = client_of(&ident)?;
        if delete {
            match client.delete(&DeleteRequest::AllMine) {
                Ok(r) => println!(
                    "deleted {} shared record(s) of @{} from the server",
                    r.deleted + r.already,
                    ident.team.handle
                ),
                Err(e) if offline(&e) => bail!(
                    "the server cannot be reached ({e}): leave --delete needs it, nothing was \
                     changed. Leave without --delete and ask an admin to delete your records"
                ),
                Err(e) if e.status() == Some(429) => bail!(
                    "the server allows one bulk deletion an hour: try again later (nothing was changed)"
                ),
                Err(e) => bail!("the server refused the deletion ({e}): nothing was changed"),
            }
        }
        // The roster revocation of this device goes out while its token still works.
        if !ident.key.epoch_keys.is_empty() {
            let queued = with_session(ctx, false, |s| {
                let now = now_ms();
                push::queue_roster_entry(
                    &mut s.conn,
                    &s.ident,
                    &s.ring,
                    &RosterEntry::Revoke {
                        member_id: *s.ident.team.member_id.as_uuid(),
                        device_id: Some(*s.ident.team.device_id.as_uuid()),
                        revoked_at: now / 1_000,
                        by_device_id: *s.ident.team.device_id.as_uuid(),
                    },
                    now,
                )?;
                Ok(push::flush(s).is_ok())
            });
            if !matches!(queued, Ok(true)) {
                eprintln!("awm: the roster could not be told that this device left");
            }
        }
        let _lock = lock(dir)?;
        match client.revoke_device(ident.team.device_id) {
            Ok(()) => println!("this device's token is revoked"),
            Err(e) => eprintln!(
                "awm: the server could not revoke this device's token ({e}); ask an admin to \
                 remove the device"
            ),
        }
        wipe_local(dir)?;
        println!("left the organisation; teammates' records and the team keys are gone from this machine");
        Ok(())
    }

    fn delete_mine(ctx: &Ctx) -> Result<()> {
        with_session(ctx, false, |s| {
            let r = s.client.delete(&DeleteRequest::AllMine).map_err(|e| {
                if offline(&e) {
                    anyhow!("the server cannot be reached ({e}): nothing was deleted")
                } else if e.status() == Some(429) {
                    anyhow!("the server allows one bulk deletion an hour: try again later")
                } else {
                    anyhow!(e)
                }
            })?;
            let now = now_ms();
            let ids: Vec<String> = {
                let mut st = s.conn.prepare(
                    "SELECT record_id FROM sync_own WHERE tag IN ('rec','flag','stats') AND deleted = 0",
                )?;
                let rows = st.query_map([], |r| r.get::<_, String>(0))?;
                rows.collect::<std::result::Result<_, _>>()?
            };
            let tx = s.conn.transaction()?;
            for id in &ids {
                tx.execute(
                    "UPDATE sync_own SET deleted = 1, blob = NULL, epoch = NULL WHERE record_id = ?1",
                    [id],
                )?;
                tx.execute(
                    "INSERT OR IGNORE INTO tombstone (kind, value, created_at) VALUES ('tool_use_id', ?1, ?2)",
                    params![format!("team:{id}"), now],
                )?;
            }
            tx.commit()?;
            println!(
                "deleted {} shared record(s) of @{} from the server ({} already deleted); local copies stay",
                r.deleted, s.ident.team.handle, r.already
            );
            Ok(())
        })
    }

    fn move_to(ctx: &Ctx, url: &str) -> Result<()> {
        let dir = ctx.dir();
        let url = check_url(url)?;
        {
            let _ = ready(ctx)?;
            let _lock = lock(dir)?;
            let mut ident = Identity::load(dir)?;
            if url == ident.team.server_url {
                bail!("this machine already uses {url}");
            }
            let ca = ident.team.ca_file.clone();
            let new = Client::new(
                &url,
                Some(&ident.key.device_token),
                ca.as_deref().map(Path::new),
            )?;
            let st = new.status().map_err(|e| match e.status() {
                Some(401) => anyhow!(
                    "the server at {url} does not know this device: the admin moves the \
                     organisation first (or ask for a new invite)"
                ),
                _ => anyhow!(e),
            })?;
            if st.org_id != ident.team.org_id || st.device_id != ident.team.device_id {
                bail!("the server at {url} holds another organisation: not moved");
            }
            let fresh = new.rotate_token()?;
            ident.key.previous_device_token = Some(ident.key.device_token.clone());
            ident.key.device_token = fresh.device_token.as_str().to_string();
            ident.team.server_url = url.clone();
            ident.save_key(dir)?;
            ident.team.save(dir)?;
        }
        println!("moved to {url}; the device token was rotated");
        match sync::run(&ctx.env, &Opts::default()) {
            Ok(Outcome::Done(r)) => println!(
                "synced: pushed {}, pulled {}{}",
                r.pushed,
                r.pulled,
                if r.reseeded {
                    " (this device re-seeded the new server)"
                } else {
                    ""
                }
            ),
            Ok(_) => println!("run awm sync to re-seed the new server"),
            Err(e) => {
                eprintln!("awm: the first sync with the new server failed ({e}); run awm sync")
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // policy

    const POLICY_KEYS: [&str; 5] = [
        "deny_hosts",
        "link_hosts",
        "terms",
        "credential_params",
        "summary_chars",
    ];
    const SETTINGS_KEYS: [&str; 4] = [
        "retention_days",
        "min_client",
        "max_members",
        "cancel_pending_retention",
    ];

    fn current_policy(conn: &Connection) -> Result<PolicyPlaintext> {
        Ok(state::get(conn, state::POLICY_JSON)?
            .and_then(|j| serde_json::from_str::<PolicyPlaintext>(&j).ok())
            .unwrap_or(PolicyPlaintext {
                schema: awm_proto::wire::PLAINTEXT_SCHEMA,
                version: 0,
                deny_hosts: Vec::new(),
                link_hosts: Vec::new(),
                terms: Vec::new(),
                credential_params: Vec::new(),
                summary_chars: None,
            }))
    }

    fn list(v: &str) -> Vec<String> {
        v.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    fn policy_show(ctx: &Ctx, json_out: bool) -> Result<()> {
        let ident = ready(ctx)?;
        let conn = open_db(ctx.dir(), DbRole::Cli)?;
        let p = current_policy(&conn)?;
        let settings = client_of(&ident)?
            .get::<OrgSettings>("/v1/org/settings")
            .ok();
        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "policy": p, "settings": settings }))?
            );
            return Ok(());
        }
        println!("policy version     {}", p.version);
        println!("deny_hosts         {}", p.deny_hosts.join(","));
        println!("link_hosts         {}", p.link_hosts.join(","));
        println!("terms              {}", p.terms.join(","));
        println!("credential_params  {}", p.credential_params.join(","));
        println!(
            "summary_chars      {}",
            p.summary_chars.map_or("-".to_string(), |n| n.to_string())
        );
        match settings {
            Some(s) => {
                println!("retention_days     {}", s.retention_days);
                println!("min_client         {}", s.min_client);
                println!("max_members        {}", s.max_members);
                if let Some(pr) = s.pending_retention {
                    println!(
                        "pending            retention_days {} from {} UTC",
                        pr.retention_days,
                        fmt_ts(pr.effective_at * 1_000)
                    );
                }
            }
            None => println!("server settings    (the server could not be reached)"),
        }
        Ok(())
    }

    fn policy_set(ctx: &Ctx, assignments: &[String]) -> Result<()> {
        let mut pairs = Vec::new();
        for a in assignments {
            let (k, v) = a
                .split_once('=')
                .ok_or_else(|| anyhow!("expected KEY=VALUE, got {a:?}"))?;
            let k = k.trim();
            if !POLICY_KEYS.contains(&k) && !SETTINGS_KEYS.contains(&k) {
                bail!(
                    "unknown policy key {k}: one of {}, {}",
                    POLICY_KEYS.join(", "),
                    SETTINGS_KEYS.join(", ")
                );
            }
            pairs.push((k.to_string(), v.trim().to_string()));
        }
        let ident = ready(ctx)?;
        // Every key is an admin's: refused here, before any request (§4.8; TM10's "a 403 on a
        // pushed item fails the run" never meets a member's policy item).
        {
            let conn = open_db(ctx.dir(), DbRole::Cli)?;
            let roster = local_roster(&conn, &ident)?;
            if !roster::own_member_is_admin(&roster, &ident) {
                bail!(
                    "{} is an admin setting: ask an admin of your team",
                    pairs[0].0
                );
            }
        }
        let mut update = SettingsUpdate {
            retention_days: None,
            min_client: None,
            max_members: None,
            cancel_pending_retention: None,
        };
        let mut policy_changes = Vec::new();
        for (k, v) in &pairs {
            let num = |v: &str| -> Result<u32> {
                v.parse::<u32>()
                    .map_err(|_| anyhow!("{k}: expected a whole number, got {v:?}"))
            };
            match k.as_str() {
                "retention_days" => {
                    let n = num(v)?;
                    if n < 30 {
                        bail!("retention_days is at least 30");
                    }
                    update.retention_days = Some(n);
                }
                "min_client" => {
                    update.min_client = Some(
                        Version::parse(v)
                            .map_err(|_| anyhow!("min_client: expected a version like 0.2.0"))?,
                    )
                }
                "max_members" => {
                    let n = num(v)?;
                    if n == 0 {
                        bail!("max_members is at least 1");
                    }
                    update.max_members = Some(n);
                }
                "cancel_pending_retention" => match v.as_str() {
                    "true" => update.cancel_pending_retention = Some(true),
                    _ => bail!("cancel_pending_retention takes true"),
                },
                "summary_chars" if !v.is_empty() => {
                    let n = num(v)?;
                    if !(1..=2000).contains(&n) {
                        bail!("summary_chars is 1-2000");
                    }
                    policy_changes.push((k.clone(), v.clone()));
                }
                _ => policy_changes.push((k.clone(), v.clone())),
            }
        }
        let settings_change = update.retention_days.is_some()
            || update.min_client.is_some()
            || update.max_members.is_some()
            || update.cancel_pending_retention.is_some();
        if settings_change {
            let s: OrgSettings = client_of(&ident)?
                .put("/v1/org/settings", &update)
                .map_err(
                    |e| match (e.status(), e.body().and_then(|b| b.field.clone())) {
                        (Some(400), Some(f)) => {
                            anyhow!("the server refused {}", f.trim_start_matches('/'))
                        }
                        (Some(403), _) => anyhow!("only admins change the server settings"),
                        _ => anyhow!(e),
                    },
                )?;
            println!(
                "server settings: retention_days {}, min_client {}, max_members {}{}",
                s.retention_days,
                s.min_client,
                s.max_members,
                s.pending_retention
                    .map(|p| format!(
                        " (a decrease to {} days applies at {} UTC)",
                        p.retention_days,
                        fmt_ts(p.effective_at * 1_000)
                    ))
                    .unwrap_or_default()
            );
        }
        if policy_changes.is_empty() {
            return Ok(());
        }
        with_session(ctx, true, |s| {
            let mut p = current_policy(&s.conn)?;
            for (k, v) in &policy_changes {
                match k.as_str() {
                    "deny_hosts" => p.deny_hosts = list(v),
                    "link_hosts" => p.link_hosts = list(v),
                    "terms" => p.terms = list(v),
                    "credential_params" => p.credential_params = list(v),
                    "summary_chars" => p.summary_chars = v.parse().ok(),
                    _ => {}
                }
            }
            let held = state::get_i64(&s.conn, state::POLICY_VERSION)?
                .unwrap_or(0)
                .max(0) as u64;
            p.version = held.max(p.version) + 1;
            p.schema = awm_proto::wire::PLAINTEXT_SCHEMA;
            let plain = serde_json::to_vec(&p)?;
            let now = now_ms();
            push::queue_item(
                &mut s.conn,
                &s.ident,
                &s.ring,
                "policy",
                "policy",
                &plain,
                now,
            )?;
            state::set(&s.conn, state::POLICY_JSON, &serde_json::to_string(&p)?)?;
            state::set(&s.conn, state::POLICY_VERSION, &p.version.to_string())?;
            flush_or_queue(s);
            println!("policy version {} set", p.version);
            Ok(())
        })
    }

    // -----------------------------------------------------------------------------------------
    // audit, audit-log, flag

    fn audit(ctx: &Ctx, delete: bool) -> Result<()> {
        let ident = ready(ctx)?;
        let conn = open_db(ctx.dir(), DbRole::Cli)?;
        let roster = local_roster(&conn, &ident)?;
        if !roster::own_member_is_admin(&roster, &ident) {
            bail!("awm team audit is for admins");
        }
        let policy = push::load_policy(&conn, push::load_opt_in(&conn, &[])?)?;
        let terms = crate::sync::eligible::terms(&ctx.env.config, &policy);
        let names = handles(&conn)?;
        let own = ident.team.member_id.to_string();
        let mut offenders: Vec<(String, String, String, Vec<String>)> = Vec::new();
        {
            let mut st = conn.prepare(
                "SELECT id, origin, sync_id, COALESCE(member, ''), COALESCE(query, ''), \
                   COALESCE(url, ''), COALESCE(fetch_prompt, ''), COALESCE(summary, '') \
                 FROM event WHERE sync_id IS NOT NULL AND (origin = 'team' OR shareable IN ('full','link'))",
            )?;
            let rows = st.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    [
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                    ],
                ))
            })?;
            for row in rows {
                let (event, origin, sync_id, member, fields) = row?;
                let mut texts: Vec<String> = fields.to_vec();
                let mut rs = conn
                    .prepare("SELECT url, COALESCE(title, '') FROM result WHERE event_id = ?1")?;
                for r in rs.query_map([event], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })? {
                    let (u, t) = r?;
                    texts.push(u);
                    texts.push(t);
                }
                let mut kinds = BTreeSet::new();
                for t in &texts {
                    for k in crate::sync::eligible::scrub(t, &terms).secrets {
                        kinds.insert(k);
                    }
                }
                let url = &fields[1];
                if !url.is_empty()
                    && crate::sync::eligible::credential_url(url, &policy.credential_params)
                {
                    kinds.insert("credential_url".to_string());
                }
                if kinds.is_empty() {
                    continue;
                }
                let author = if origin == "local" {
                    own.clone()
                } else {
                    member
                };
                let handle = names
                    .get(&author)
                    .cloned()
                    .unwrap_or_else(|| author.clone());
                offenders.push((handle, sync_id, author, kinds.into_iter().collect()));
            }
        }
        if offenders.is_empty() {
            println!("no shared record fails the current patterns");
            return Ok(());
        }
        for (handle, id, _, kinds) in &offenders {
            println!("@{handle}  record {id}  {}", kinds.join(", "));
        }
        if !delete {
            println!(
                "{} record(s); delete them with: awm team audit --delete",
                offenders.len()
            );
            return Ok(());
        }
        drop(conn);
        let ids: Vec<String> = offenders.iter().map(|o| o.1.clone()).collect();
        with_session(ctx, false, |s| {
            let now = now_ms();
            let tx = s.conn.transaction()?;
            for id in &ids {
                tx.execute(
                    "INSERT INTO sync_outbox (kind, ref, created_at) VALUES ('delete', ?1, ?2)",
                    params![id, now],
                )?;
                tx.execute(
                    "INSERT OR IGNORE INTO tombstone (kind, value, created_at) VALUES ('tool_use_id', ?1, ?2)",
                    params![format!("team:{id}"), now],
                )?;
                tx.execute(
                    "UPDATE sync_own SET deleted = 1, blob = NULL, epoch = NULL WHERE record_id = ?1",
                    [id],
                )?;
                tx.execute(
                    "DELETE FROM event WHERE sync_id = ?1 AND origin = 'team'",
                    [id],
                )?;
                tx.execute(
                    "UPDATE event SET shareable = 'never' WHERE sync_id = ?1 AND origin = 'local'",
                    [id],
                )?;
            }
            tx.commit()?;
            match push::deletions(s) {
                Ok(_) => println!("deleted {} record(s) from the server", ids.len()),
                Err(e) => println!(
                    "{} deletion(s) queued for the next awm sync ({e})",
                    ids.len()
                ),
            }
            Ok(())
        })
    }

    fn audit_log(ctx: &Ctx, json_out: bool, from: u64) -> Result<()> {
        let ident = ready(ctx)?;
        let client = client_of(&ident)?;
        let resp: awm_proto::wire::AuditResponse = client
            .get(&format!("/v1/audit?from={from}&limit=1000"))
            .map_err(|e| match e.status() {
                Some(403) => anyhow!("only admins read the audit log"),
                _ => anyhow!(e),
            })?;
        if json_out {
            println!("{}", serde_json::to_string_pretty(&resp)?);
            return Ok(());
        }
        let conn = open_db(ctx.dir(), DbRole::Cli)?;
        let names = handles(&conn)?;
        for r in &resp.rows {
            let actor = r
                .actor
                .map(|a| {
                    names
                        .get(&a.to_string())
                        .map(|h| format!("@{h}"))
                        .unwrap_or_else(|| a.to_string())
                })
                .unwrap_or_else(|| "server".to_string());
            println!(
                "{:>5}  {}  {actor}  {}{}{}",
                r.idx,
                fmt_ts(r.at * 1_000),
                r.action,
                r.target
                    .as_deref()
                    .map(|t| format!("  {t}"))
                    .unwrap_or_default(),
                r.detail
                    .as_deref()
                    .map(|d| format!("  {d}"))
                    .unwrap_or_default(),
            );
        }
        Ok(())
    }

    fn flag(ctx: &Ctx, id: &str, reason: Option<&str>) -> Result<()> {
        let ident = ready(ctx)?;
        let conn = open_db(ctx.dir(), DbRole::Cli)?;
        let (event, origin, sync_id, member) = find_event(&conn, id)?;
        drop(conn);
        if origin != "team" {
            bail!("record {event} is your own: awm team unshare --record {event} withdraws it");
        }
        if member.as_deref() == Some(&ident.team.member_id.to_string()) {
            bail!(
                "record {event} is your own (another machine): awm team unshare --record {event}"
            );
        }
        let sid = sync_id.ok_or_else(|| anyhow!("record {event} has no record id"))?;
        let record_id =
            Id::parse(&sid).map_err(|_| anyhow!("record {event} has a bad record id"))?;
        with_session(ctx, false, |s| {
            push::queue_flag(
                &mut s.conn,
                &s.ident,
                &s.ring,
                record_id,
                awm_proto::wire::FlagReason::User,
                reason,
                now_ms(),
            )?;
            flush_or_queue(s);
            println!("flagged record {event}");
            Ok(())
        })
    }

    // -----------------------------------------------------------------------------------------
    // token, key

    fn token_rotate(ctx: &Ctx) -> Result<()> {
        let dir = ctx.dir();
        let _ = ready(ctx)?;
        let _lock = lock(dir)?;
        let mut ident = Identity::load(dir)?;
        let fresh = client_of(&ident)?.rotate_token()?;
        ident.key.previous_device_token = Some(ident.key.device_token.clone());
        ident.key.device_token = fresh.device_token.as_str().to_string();
        ident.save_key(dir)?;
        println!("the device token was rotated; the old one no longer works");
        Ok(())
    }

    fn key_export(ctx: &Ctx) -> Result<()> {
        let ident = ready(ctx)?;
        let ring = ident.ring()?;
        eprintln!(
            "awm: this string is every team key (epochs 0-{}): keep it in a password manager",
            ring.current_epoch()
        );
        println!("{}", ring.export_recovery());
        Ok(())
    }

    /// The genesis roster record of the organisation among `blobs`, opened with `ring`: it must
    /// sit at index 0 under epoch 0 of its writer's stream and hash to the ring's organisation
    /// id (`docs/sync-v1-crypto.md` §2, §9; RVT1 m12).
    fn genesis_opens(ring: &KeyRing, blobs: &[keys::RosterBlob]) -> bool {
        blobs
            .iter()
            .filter(|b| b.idx == 0 && b.epoch == 0)
            .any(|b| {
                let ad = RecordAd {
                    org: ring.org(),
                    member: b.member,
                    device: b.device,
                    tag: ROSTER_TAG.to_string(),
                    idx: 0,
                    record_id: b.record_id,
                    epoch: 0,
                };
                let Ok(plain) = open_record(ring, &ad, &b.blob) else {
                    return false;
                };
                match serde_json::from_slice::<RosterPlaintext>(&plain) {
                    Ok(RosterPlaintext {
                        entry:
                            RosterEntry::Genesis {
                                member_id,
                                device_id,
                                device_pub,
                                org_nonce,
                                ..
                            },
                        ..
                    }) => {
                        member_id == b.member
                            && device_id == b.device
                            && keys::org_id(device_id, &device_pub, &org_nonce) == ring.org()
                    }
                    _ => false,
                }
            })
    }

    /// Index-0 roster records from the server, for a device that has none stored.
    fn server_geneses(ident: &Identity) -> Result<Vec<keys::RosterBlob>> {
        let client = client_of(ident)?;
        let st = client.status()?;
        let cursors: Vec<Cursor> = st
            .streams
            .iter()
            .filter(|h| h.tag.as_str() == ROSTER_TAG)
            .map(|h| Cursor {
                member: h.member,
                device: h.device,
                tag: Tag::parse(ROSTER_TAG).expect("a valid tag"),
                from: 0,
            })
            .collect();
        if cursors.is_empty() {
            return Ok(Vec::new());
        }
        let resp = client.pull(&PullRequest {
            cursors,
            limit: awm_proto::wire::limits::PULL_RECORDS,
        })?;
        let mut out = Vec::new();
        for sr in resp.streams {
            for item in sr.records {
                if let PulledItem::Record(r) = item {
                    if r.idx == 0 {
                        out.push(keys::RosterBlob {
                            member: *sr.member.as_uuid(),
                            device: *sr.device.as_uuid(),
                            idx: 0,
                            record_id: *r.id.as_uuid(),
                            epoch: r.epoch,
                            blob: r.blob.0,
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    fn key_import(ctx: &Ctx, text: Option<String>) -> Result<()> {
        let dir = ctx.dir();
        if !state::configured(dir) {
            bail!(NOT_IN_TEAM);
        }
        let text = match text {
            Some(t) => t,
            None => {
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line)?;
                line
            }
        };
        let imported = KeyRing::import_recovery(text.trim()).map_err(|_| {
            anyhow!("not a recovery string (awmk1_...), or a typing error: nothing was written")
        })?;
        let _lock = lock(dir)?;
        let mut ident = Identity::load(dir)?;
        if Id::from(imported.org()) != ident.team.org_id {
            bail!(
                "the recovery string is for another organisation than team.toml: nothing was written"
            );
        }
        let conn = open_db(dir, DbRole::Cli)?;
        let mut blobs = roster::blobs(&conn)?;
        if !genesis_opens(&imported, &blobs) {
            blobs.extend(server_geneses(&ident).unwrap_or_default());
        }
        if !genesis_opens(&imported, &blobs) {
            bail!(
                "the recovery string's keys do not open this organisation's genesis record, or it \
                 does not hash to the organisation id: nothing was written"
            );
        }
        let ring = match ident.ring() {
            Ok(held) => {
                for k in held.epochs() {
                    if let Some(i) = imported.get(k.epoch()) {
                        if i.expose_secret() != k.expose_secret() {
                            bail!(
                                "the recovery string holds another key for epoch {}: nothing was written",
                                k.epoch()
                            );
                        }
                    }
                }
                if held.current_epoch() > imported.current_epoch() {
                    held
                } else {
                    imported
                }
            }
            Err(_) => imported,
        };
        ident.key.set_ring(&ring);
        ident.key.extra.remove(team::JOIN_INVITE);
        ident.save_key(dir)?;
        team::write_repo_key(dir, &ring)?;
        println!(
            "imported the team keys up to epoch {}",
            ring.current_epoch()
        );
        // An admin's new device enrols itself with a `recover` entry (crypto §9).
        let roster = roster::verify_and_store(&conn, &ring, now_ms())?.0;
        let me = *ident.team.device_id.as_uuid();
        if roster.device(me).is_none() && roster::own_member_is_admin(&roster, &ident) {
            let mut conn = conn;
            let now = now_ms();
            push::queue_roster_entry(
                &mut conn,
                &ident,
                &ring,
                &RosterEntry::Recover {
                    member_id: *ident.team.member_id.as_uuid(),
                    handle: ident.team.handle.clone(),
                    device_id: me,
                    device_pub: ident.device_keys().public,
                    recovered_at: now / 1_000,
                },
                now,
            )?;
            println!("this device enrols itself as a recovered admin device at the next awm sync");
        }
        Ok(())
    }
}
