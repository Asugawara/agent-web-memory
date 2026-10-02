//! Team files, invite strings, join completion, repository keys and auto-approval
//! (plan-v3-team §4.7, §5.1; `docs/sync-v1-crypto.md` §4, §6, §12; TM12). The commands are in
//! `cli/team.rs`; `team.toml` and `team.key` are read and written through `sync::state`.
//!
//! What lives where on a machine in a team (all mode 0600 in the data directory):
//!
//! | file | holds |
//! |---|---|
//! | `team.toml` | server URL, organisation id, member id, handle, device id, optional CA file |
//! | `team.key` | device token (and the previous one), device private key, epoch keys, the invites this device created (each with its secret `S`), and while a join waits for approval the joiner's own invite string (`join_invite`) |
//! | `team.repo` | `K_repo` (`RepoKey::encode`), the only key capture reads |

use std::path::{Path, PathBuf};

use crate::config::AutoApprove;

/// Whether a pending join or device is approved automatically under `policy`.
///
/// `is_own_device` is true for a new device of the caller's own member whose MAC verifies.
/// `devices` approves only those; `all` also approves member joins (plan-v3-team §4.7
/// `team.auto_approve`). The caller has already verified the join MAC; this decides policy only.
pub fn auto_approve(policy: AutoApprove, is_own_device: bool) -> bool {
    match policy {
        AutoApprove::All => true,
        AutoApprove::Devices => is_own_device,
    }
}

/// The file holding `K_repo` (plan-v3-team §4.4).
pub const TEAM_REPO: &str = "team.repo";

/// A handle as typed: `@alf` or `alf`.
pub fn bare_handle(h: &str) -> &str {
    h.trim().trim_start_matches('@')
}

/// `--expires 7d` (or `7`): whole days, 1 to 30 (plan-v3-team §4.3.5).
pub fn parse_expires(s: &str) -> anyhow::Result<u32> {
    let t = s.trim();
    let digits = t.strip_suffix('d').unwrap_or(t);
    let days: u32 = digits
        .parse()
        .map_err(|_| anyhow::anyhow!("--expires takes whole days, for example 7d (got {s:?})"))?;
    if !(1..=30).contains(&days) {
        anyhow::bail!("--expires must be 1d to 30d (an invite lives at most 30 days)");
    }
    Ok(days)
}

// ---------------------------------------------------------------------------------------------
// Git remotes (plan-v3-team §4.4: read from `.git/config` without running git)

/// The git directory, common directory and work tree root that hold `dir`, if any.
fn git_dirs(dir: &Path) -> Option<(PathBuf, PathBuf)> {
    let mut cur = Some(dir);
    while let Some(d) = cur {
        let dot = d.join(".git");
        let gitdir = if dot.is_dir() {
            Some(dot)
        } else if dot.is_file() {
            let text = std::fs::read_to_string(&dot).ok()?;
            let rel = text
                .lines()
                .find_map(|l| l.trim().strip_prefix("gitdir:"))?;
            let p = PathBuf::from(rel.trim());
            Some(if p.is_absolute() { p } else { d.join(p) })
        } else {
            None
        };
        if let Some(g) = gitdir {
            // A worktree's git directory names the shared one in `commondir`.
            let common = match std::fs::read_to_string(g.join("commondir")) {
                Ok(text) => {
                    let p = PathBuf::from(text.trim());
                    if p.is_absolute() {
                        p
                    } else {
                        g.join(p)
                    }
                }
                Err(_) => g.clone(),
            };
            return Some((common, d.to_path_buf()));
        }
        cur = d.parent();
    }
    None
}

/// The URL of the `origin` remote of the repository holding `dir`, and the work tree root.
pub fn origin_remote(dir: &Path) -> Option<(String, PathBuf)> {
    let (common, root) = git_dirs(dir)?;
    let text = std::fs::read_to_string(common.join("config")).ok()?;
    let mut in_origin = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            let inner = l.trim_start_matches('[').trim_end_matches(']').trim();
            in_origin = inner
                .strip_prefix("remote")
                .map(|r| r.trim().trim_matches('"') == "origin")
                .unwrap_or(false);
            continue;
        }
        if in_origin {
            if let Some((k, v)) = l.split_once('=') {
                if k.trim() == "url" {
                    let v = v.trim().trim_matches('"').to_string();
                    if !v.is_empty() {
                        return Some((v, root));
                    }
                }
            }
        }
    }
    None
}

/// The normalised remote of plan-v3-team §4.4: lower-case host, no scheme, user, port or
/// `.git`; `git@host:owner/repo` → `host/owner/repo`. `None` for a local path.
pub fn normalize_remote(url: &str) -> Option<String> {
    let u = url.trim().trim_end_matches('/');
    let (host, path) = if let Some((_, rest)) = u.split_once("://") {
        let (authority, path) = rest.split_once('/')?;
        let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let host = hostport.split(':').next().unwrap_or(hostport);
        (host.to_string(), path.to_string())
    } else {
        let (left, path) = u.split_once(':')?;
        if left.contains('/') || path.starts_with("//") {
            return None;
        }
        let host = left.rsplit_once('@').map_or(left, |(_, h)| h);
        (host.to_string(), path.to_string())
    };
    let path = path.trim_matches('/');
    let path = path
        .strip_suffix(".git")
        .unwrap_or(path)
        .trim_end_matches('/');
    if host.is_empty() || path.is_empty() {
        return None;
    }
    Some(format!("{}/{}", host.to_ascii_lowercase(), path))
}

/// The `cwd_hash` values a directory can have in `event`: the path as given (absolute) and
/// canonicalised, so `share` matches what the hooks recorded (`sha256_hex(cwd)`).
pub fn cwd_hashes(path: &Path) -> Vec<String> {
    use crate::record::sha256_hex;
    let mut forms: Vec<PathBuf> = Vec::new();
    let clean = |p: PathBuf| -> PathBuf {
        p.components()
            .filter(|c| !matches!(c, std::path::Component::CurDir))
            .collect()
    };
    if path.is_absolute() {
        forms.push(clean(path.to_path_buf()));
    } else {
        if let Some(pwd) = std::env::var_os("PWD") {
            forms.push(clean(PathBuf::from(pwd).join(path)));
        }
        if let Ok(cwd) = std::env::current_dir() {
            forms.push(clean(cwd.join(path)));
        }
    }
    if let Ok(c) = std::fs::canonicalize(path) {
        forms.push(c);
    }
    let mut out: Vec<String> = forms
        .iter()
        .map(|p| sha256_hex(&p.to_string_lossy()))
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(feature = "sync")]
pub use client::*;

#[cfg(feature = "sync")]
mod client {
    use std::path::Path;

    use anyhow::{anyhow, bail, Context, Result};
    use awm_proto::keys::{
        accept_join, ApprovalKind, Invite, KeyRing, RepoKey, Role as KeyRole, Wrap,
    };
    use awm_proto::wire::{Id, InviteKind, InviteToken, PendingDevice};

    use crate::sync::http::Client;
    use crate::sync::state::{self, PendingInvite, TeamKey, TeamToml};

    /// The `team.key` field that holds a joiner's own invite string until the join is approved:
    /// `accept_join` needs its secret `S` to check the approval's wraps.
    pub const JOIN_INVITE: &str = "join_invite";

    /// Writes `team.repo` (`K_repo` of the ring's epoch 0), mode 0600.
    pub fn write_repo_key(dir: &Path, ring: &KeyRing) -> Result<()> {
        state::write_private(
            &dir.join(super::TEAM_REPO),
            ring.repo_key().encode().as_bytes(),
        )
    }

    /// `K_repo` from `team.repo`.
    pub fn read_repo_key(dir: &Path) -> Result<RepoKey> {
        let text =
            std::fs::read_to_string(dir.join(super::TEAM_REPO)).context("cannot read team.repo")?;
        RepoKey::decode(&text).map_err(|_| anyhow!("team.repo is not a repository key"))
    }

    /// The `repo_key` of the repository holding `dir` (its `origin` remote), if any.
    pub fn repo_key_for(dir: &Path, key: &RepoKey) -> Option<(String, std::path::PathBuf)> {
        let (url, root) = super::origin_remote(dir)?;
        let norm = super::normalize_remote(&url)?;
        Some((key.repo_key(&norm), root))
    }

    /// The joiner's check before any request (RVT1 m8, sync-v1 §3.2): the organisation inside
    /// the invite string must be the `{org}` of its invite token.
    pub fn check_invite_org(invite: &Invite) -> Result<Id> {
        let token = InviteToken::parse(&invite.token)
            .map_err(|_| anyhow!("the invite string holds no valid invite token"))?;
        let org = Id::from(invite.org);
        if token.org() != org {
            bail!(
                "the invite string names another organisation than its token: refused (ask for a \
                 new invite through a channel you trust)"
            );
        }
        Ok(org)
    }

    /// The approval an approver makes for one pending device, taken from its own invite record
    /// and never from the server's pending list (RVT1 M2, sync-v1 §5.2): kind, member id and
    /// role. A pending entry of a kind this build does not know is never approved (RVT1 m3).
    pub fn approval_plan(
        pending: &PendingDevice,
        record: &PendingInvite,
        own_member: Id,
    ) -> Result<(ApprovalKind, Id, KeyRole)> {
        if pending.kind == InviteKind::Unknown {
            bail!("the server lists a join of an unknown kind: not approved");
        }
        match record.kind.as_str() {
            "device" => {
                let member = match record.member_id.as_deref() {
                    Some(m) => Id::parse(m).map_err(|_| anyhow!("team.key: bad member id"))?,
                    None => own_member,
                };
                Ok((ApprovalKind::Device, member, KeyRole::Member))
            }
            "member" => Ok((
                ApprovalKind::Member,
                pending.member_id,
                if record.role.as_deref() == Some("admin") {
                    KeyRole::Admin
                } else {
                    KeyRole::Member
                },
            )),
            _ => bail!("the local invite record has an unknown kind: not approved"),
        }
    }

    /// The local invite record (and the parsed invite) for a pending join.
    pub fn find_invite(key: &TeamKey, invite_id: Id) -> Option<(usize, PendingInvite, Invite)> {
        key.pending_invites.iter().enumerate().find_map(|(i, pi)| {
            Invite::parse(&pi.invite)
                .ok()
                .filter(|inv| inv.invite_id == invite_id.to_string())
                .map(|inv| (i, pi.clone(), inv))
        })
    }

    /// Where a joined device stands.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum JoinState {
        /// No `team.toml` / `team.key`.
        NotInTeam,
        /// The device holds the epoch keys.
        Ready,
        /// The join waits for an approval; the code and fingerprint to read out.
        Waiting { code: String, fingerprint: String },
    }

    /// The joiner's invite while its join waits.
    pub fn join_invite(key: &TeamKey) -> Option<Invite> {
        key.extra
            .get(JOIN_INVITE)
            .and_then(|v| v.as_str())
            .and_then(|s| Invite::parse(s).ok())
    }

    fn waiting(team: &TeamToml, key: &TeamKey, invite: &Invite) -> JoinState {
        let device = key.device_keys();
        JoinState::Waiting {
            code: invite.confirmation_code(*team.device_id.as_uuid(), &device.public),
            fingerprint: device.fingerprint(),
        }
    }

    /// Completes a join once it is approved (`docs/sync-v1-crypto.md` §12 Join): `GET /v1/keys`,
    /// `accept_join` on the wraps (each must be authenticated with this invite's `S`, so the
    /// server cannot slip in a key it knows), then `team.key` gets the epoch keys and
    /// `team.repo` is written. Wraps of later rotations are left to `awm sync`. No network call
    /// when the device already holds keys.
    pub fn finish_join(dir: &Path) -> Result<JoinState> {
        if !state::configured(dir) {
            return Ok(JoinState::NotInTeam);
        }
        let team = TeamToml::load(dir)?;
        let mut key = TeamKey::load(dir)?;
        if !key.epoch_keys.is_empty() {
            return Ok(JoinState::Ready);
        }
        let Some(invite) = join_invite(&key) else {
            bail!("team.key holds no epoch keys and no pending join: import them with awm team key import");
        };
        let ca = team.ca_file.as_deref().map(Path::new);
        let client = Client::new(&team.server_url, Some(&key.device_token), ca)?;
        let resp = client.keys()?;
        if resp.wraps.is_empty() {
            return Ok(waiting(&team, &key, &invite));
        }
        let device = key.device_keys();
        let device_id = *team.device_id.as_uuid();
        let mut wraps: Vec<Wrap> = resp
            .wraps
            .iter()
            .map(|w| Wrap {
                device_id,
                epoch: w.epoch,
                approver_device: *w.created_by.as_uuid(),
                blob: w.wrap.0.clone(),
                auth: w.auth.0,
            })
            .collect();
        wraps.sort_by_key(|w| w.epoch);
        // The approval wrapped epochs 0..=n with `S`; a rotation after it adds n+1 under K_n,
        // which `accept_join` would refuse. The longest prefix that verifies is the approval.
        let mut ring = None;
        for n in (1..=wraps.len()).rev() {
            if let Ok(r) = accept_join(&invite, device_id, &device, &wraps[..n]) {
                ring = Some(r);
                break;
            }
        }
        let Some(ring) = ring else {
            bail!(
                "the keys sent for this device are not authenticated with this invite's secret: \
                 not accepted (ask for a new invite)"
            );
        };
        if Id::from(ring.org()) != team.org_id {
            bail!("the approval is for another organisation: not accepted");
        }
        key.set_ring(&ring);
        key.extra.remove(JOIN_INVITE);
        key.save(dir)?;
        write_repo_key(dir, &ring)?;
        Ok(JoinState::Ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_approve_follows_the_policy() {
        assert!(auto_approve(AutoApprove::Devices, true));
        assert!(!auto_approve(AutoApprove::Devices, false));
        assert!(auto_approve(AutoApprove::All, true));
        assert!(auto_approve(AutoApprove::All, false));
    }

    #[test]
    fn remotes_normalise_to_host_owner_repo() {
        for (url, want) in [
            ("git@github.com:Owner/Repo.git", "github.com/Owner/Repo"),
            ("https://GitHub.com/Owner/Repo.git", "github.com/Owner/Repo"),
            (
                "https://user:pw@github.com:443/owner/repo/",
                "github.com/owner/repo",
            ),
            (
                "ssh://git@gitlab.example.org/group/sub/repo.git",
                "gitlab.example.org/group/sub/repo",
            ),
        ] {
            assert_eq!(normalize_remote(url).as_deref(), Some(want), "{url}");
        }
        assert_eq!(normalize_remote("/srv/git/repo.git"), None);
        assert_eq!(normalize_remote("../repo"), None);
    }

    #[test]
    fn expiry_is_one_to_thirty_days() {
        assert_eq!(parse_expires("7d").unwrap(), 7);
        assert_eq!(parse_expires("30").unwrap(), 30);
        assert!(parse_expires("31d").is_err());
        assert!(parse_expires("0d").is_err());
        assert!(parse_expires("1w").is_err());
    }
}
