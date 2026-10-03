//! Epoch keys, device key pairs, wraps, invites and the join MAC, approval, the roster,
//! rotation and recovery (plan-v3-team §5.1, TM3; `docs/sync-v1-crypto.md`).
//!
//! Every label below is an HKDF `info` or a MAC domain label; none is reused for two purposes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::digest::zeroize::{Zeroize, ZeroizeOnDrop};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{
    aead_open, aead_seal, hkdf32, open_record, seal_record_with, Error, OsRng, RecordAd, Rng,
    Secret32, NONCE_LEN, TAG_LEN,
};
use crate::wire::RosterPlaintext;

type HmacSha256 = Hmac<Sha256>;

const INFO_REPO: &[u8] = b"awm repo v1";
const INFO_ROT_AUTH: &[u8] = b"awm rot-auth v1";
const INFO_WRAP: &[u8] = b"awm wrap v1";
const INFO_WRAP_AUTH: &[u8] = b"awm wrap-auth v1";
const INFO_JOIN: &[u8] = b"awm join v1";
const INFO_CODE: &[u8] = b"awm code v1";
const LABEL_FP: &[u8] = b"awm fp v1";
const LABEL_EXPORT: &[u8] = b"awm export v1";
const LABEL_ORG: &[u8] = b"awm org v1";

/// Length of the organisation nonce in the genesis entry.
pub const ORG_NONCE_LEN: usize = 16;

/// Prefix of an invite string.
pub const INVITE_PREFIX: &str = "awmi1_";
/// Prefix of a recovery export string.
pub const EXPORT_PREFIX: &str = "awmk1_";
/// Version byte of a wrap.
pub const WRAP_VERSION: u8 = 0x01;
/// Length of a wrap blob: version, ephemeral public key, nonce, sealed 32-byte key.
pub const WRAP_LEN: usize = 1 + 32 + NONCE_LEN + 32 + TAG_LEN;
/// The stream tag of roster records.
pub const ROSTER_TAG: &str = "roster";
/// The roster plaintext schema this crate writes and reads.
pub const ROSTER_SCHEMA: u32 = 1;

const MODE_JOIN: u8 = 1;
const MODE_ROTATION: u8 = 2;

fn hmac32(key: &Secret32, data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key.expose()).expect("HMAC takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hmac_verify(key: &Secret32, data: &[u8], tag: &[u8; 32]) -> Result<(), Error> {
    let mut mac = HmacSha256::new_from_slice(key.expose()).expect("HMAC takes any key length");
    mac.update(data);
    mac.verify_slice(tag).map_err(|_| Error::BadMac)
}

fn push_lp8(out: &mut Vec<u8>, field: &[u8]) -> Result<(), Error> {
    let len = u8::try_from(field.len()).map_err(|_| Error::Malformed("field longer than 255"))?;
    out.push(len);
    out.extend_from_slice(field);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Checks a handle: 1-24 characters of `[a-z0-9_-]` (plan-v3-team §4.3.5).
pub fn valid_handle(handle: &str) -> bool {
    crate::wire::Handle::parse(handle).is_ok()
}

// ---------------------------------------------------------------------------------------
// Epoch keys and the key ring

/// One epoch key `K_e`: 32 random bytes, zeroed on drop.
#[derive(Clone)]
pub struct EpochKey {
    epoch: u32,
    key: Secret32,
}

impl EpochKey {
    /// A fresh epoch key from the system random source.
    pub fn generate(epoch: u32) -> Result<EpochKey, Error> {
        EpochKey::generate_with(&mut OsRng, epoch)
    }

    /// [`EpochKey::generate`] with an explicit random source (tests and vectors).
    pub fn generate_with(rng: &mut dyn Rng, epoch: u32) -> Result<EpochKey, Error> {
        Ok(EpochKey {
            epoch,
            key: Secret32::random_with(rng)?,
        })
    }

    /// An epoch key loaded from `team.key` or a recovery export.
    pub fn from_bytes(epoch: u32, bytes: [u8; 32]) -> EpochKey {
        EpochKey {
            epoch,
            key: Secret32::from_bytes(bytes),
        }
    }

    /// The epoch number.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The raw key, for `team.key`.
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.key.expose()
    }

    /// `HKDF-SHA256(K_e, "awm rot-auth v1")`: authenticates the wraps of epoch `e + 1`.
    fn rotation_auth_key(&self) -> Secret32 {
        hkdf32(None, self.key.expose(), INFO_ROT_AUTH)
    }
}

impl ZeroizeOnDrop for EpochKey {}

impl fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EpochKey {{ epoch: {}, .. }}", self.epoch)
    }
}

/// The organisation id of a genesis: the first 16 bytes of `SHA-256("awm org v1" ‖ device id
/// ‖ device public key ‖ org nonce)` with the UUIDv4 version and variant bits set (RVT1 B1).
///
/// The id is self-certifying: every member receives it through the invite string, over the
/// channel the admin trusts, so a genesis roster entry counts only if it hashes to it. Binding
/// the device id as well as the key means a member cannot copy the genuine key and nonce into
/// a genesis of their own stream (FT1).
pub fn org_id(device_id: Uuid, device_pub: &[u8; 32], org_nonce: &[u8; ORG_NONCE_LEN]) -> Uuid {
    let mut h = Sha256::new();
    h.update(LABEL_ORG);
    h.update(device_id.as_bytes());
    h.update(device_pub);
    h.update(org_nonce);
    let d = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&d[..16]);
    uuid::Builder::from_random_bytes(id).into_uuid()
}

/// An organisation's id and every epoch key a device holds, contiguous from epoch 0.
#[derive(Clone, Debug)]
pub struct KeyRing {
    org: Uuid,
    keys: BTreeMap<u32, EpochKey>,
}

impl KeyRing {
    /// A new organisation (`awm team create`, `awm cloud login`): `K_0` and the organisation
    /// id derived from the first admin's device ([`org_id`]) and a random nonce. The device key
    /// is made first; the nonce goes into the `genesis` roster entry.
    pub fn create(
        genesis_device: Uuid,
        genesis_pub: &[u8; 32],
    ) -> Result<(KeyRing, [u8; ORG_NONCE_LEN]), Error> {
        KeyRing::create_with(&mut OsRng, genesis_device, genesis_pub)
    }

    /// [`KeyRing::create`] with an explicit random source (tests and vectors).
    pub fn create_with(
        rng: &mut dyn Rng,
        genesis_device: Uuid,
        genesis_pub: &[u8; 32],
    ) -> Result<(KeyRing, [u8; ORG_NONCE_LEN]), Error> {
        let mut nonce = [0u8; ORG_NONCE_LEN];
        rng.fill(&mut nonce)?;
        let org = org_id(genesis_device, genesis_pub, &nonce);
        let k0 = EpochKey::generate_with(rng, 0)?;
        Ok((KeyRing::from_keys(org, vec![k0])?, nonce))
    }

    /// A key ring from stored keys; the epochs must be exactly 0, 1, ..., n.
    pub fn from_keys(org: Uuid, keys: Vec<EpochKey>) -> Result<KeyRing, Error> {
        let mut map = BTreeMap::new();
        for k in keys {
            if map.insert(k.epoch, k).is_some() {
                return Err(Error::Rejected("duplicate epoch"));
            }
        }
        if map.is_empty() || map.keys().copied().ne(0..map.len() as u32) {
            return Err(Error::Rejected("epochs must be contiguous from 0"));
        }
        Ok(KeyRing { org, keys: map })
    }

    /// The organisation id (bound into every record's AD).
    pub fn org(&self) -> Uuid {
        self.org
    }

    /// The highest epoch's key.
    pub fn current(&self) -> &EpochKey {
        self.keys
            .values()
            .next_back()
            .expect("a key ring is never empty")
    }

    /// The highest epoch.
    pub fn current_epoch(&self) -> u32 {
        self.current().epoch
    }

    /// The key of `epoch`, if held.
    pub fn get(&self, epoch: u32) -> Option<&EpochKey> {
        self.keys.get(&epoch)
    }

    /// Every key, ascending by epoch.
    pub fn epochs(&self) -> impl Iterator<Item = &EpochKey> {
        self.keys.values()
    }

    /// `K_repo = HKDF-SHA256(K_0, "awm repo v1")`, fixed for the organisation's life
    /// (plan-v3-team §4.4, RV8-team M4).
    pub fn repo_key(&self) -> RepoKey {
        let k0 = self.keys.get(&0).expect("a key ring always holds epoch 0");
        RepoKey(hkdf32(None, k0.key.expose(), INFO_REPO))
    }

    /// Adds the key this device created in [`rotate`] (it needs no wrap for itself).
    pub fn adopt_own_rotation(&mut self, rotation: &Rotation) -> Result<(), Error> {
        self.push_next(rotation.key.clone())
    }

    fn push_next(&mut self, key: EpochKey) -> Result<(), Error> {
        if key.epoch != self.current_epoch() + 1 {
            return Err(Error::Rejected("a new epoch must be current + 1"));
        }
        self.keys.insert(key.epoch, key);
        Ok(())
    }

    /// Accepts the wrap of epoch `current + 1` sent by a rotating admin. The wrap must be for
    /// this device and authenticated with the current epoch key, so the server alone cannot
    /// make the device accept a key it knows (P2 at rotation).
    pub fn accept_rotation(
        &mut self,
        device_id: Uuid,
        device: &DeviceKeys,
        wrap: &Wrap,
    ) -> Result<u32, Error> {
        let next = self.current_epoch() + 1;
        if wrap.epoch != next {
            return Err(Error::Rejected("rotation wrap is not for current + 1"));
        }
        if wrap.device_id != device_id {
            return Err(Error::Rejected("wrap is for another device"));
        }
        let auth_key = self.current().rotation_auth_key();
        let transcript = wrap_auth_transcript(MODE_ROTATION, self.org, wrap, &device.public)?;
        hmac_verify(&auth_key, &transcript, &wrap.auth)?;
        let key = open_wrap(self.org, device_id, device, wrap.epoch, &wrap.blob)?;
        self.push_next(key)?;
        Ok(next)
    }

    /// `awm team key export`: every epoch key as one string for a password manager.
    ///
    /// The string is the secret itself (no password); it holds the organisation id, the
    /// keys and a 4-byte checksum against typing errors.
    pub fn export_recovery(&self) -> String {
        let mut body = Vec::with_capacity(16 + 4 + self.keys.len() * 36 + 4);
        body.extend_from_slice(self.org.as_bytes());
        body.extend_from_slice(&(self.keys.len() as u32).to_be_bytes());
        for k in self.keys.values() {
            body.extend_from_slice(&k.epoch.to_be_bytes());
            body.extend_from_slice(k.key.expose());
        }
        let check = export_check(&body);
        body.extend_from_slice(&check);
        let out = format!("{EXPORT_PREFIX}{}", URL_SAFE_NO_PAD.encode(&body));
        body.as_mut_slice().zeroize();
        out
    }

    /// Reads a string made by [`KeyRing::export_recovery`].
    pub fn import_recovery(text: &str) -> Result<KeyRing, Error> {
        let b64 = text
            .trim()
            .strip_prefix(EXPORT_PREFIX)
            .ok_or(Error::Malformed("recovery export prefix"))?;
        let mut body = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| Error::Malformed("recovery export encoding"))?;
        let result = parse_export(&body);
        body.as_mut_slice().zeroize();
        result
    }
}

fn export_check(body: &[u8]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(LABEL_EXPORT);
    h.update(body);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

fn parse_export(body: &[u8]) -> Result<KeyRing, Error> {
    if body.len() < 16 + 4 + 4 {
        return Err(Error::Malformed("recovery export length"));
    }
    let (data, check) = body.split_at(body.len() - 4);
    if export_check(data) != check {
        return Err(Error::Malformed("recovery export checksum"));
    }
    let org = Uuid::from_slice(&data[..16]).map_err(|_| Error::Malformed("organisation id"))?;
    let n = u32::from_be_bytes(data[16..20].try_into().expect("4 bytes")) as usize;
    let rest = &data[20..];
    if rest.len() != n * 36 {
        return Err(Error::Malformed("recovery export length"));
    }
    let mut keys = Vec::with_capacity(n);
    for chunk in rest.chunks_exact(36) {
        let epoch = u32::from_be_bytes(chunk[..4].try_into().expect("4 bytes"));
        let mut k = [0u8; 32];
        k.copy_from_slice(&chunk[4..]);
        keys.push(EpochKey::from_bytes(epoch, k));
        k.zeroize();
    }
    KeyRing::from_keys(org, keys)
}

/// `K_repo`, the key of `repo_key` hashes; written to `team.repo` so capture never reads
/// `team.key` (plan-v3-team §4.4).
#[derive(Clone, Debug)]
pub struct RepoKey(Secret32);

impl RepoKey {
    /// `repo_key` of a normalised remote (`host/owner/repo`): the first 32 hex characters
    /// of `HMAC-SHA256(K_repo, remote)`. Normalising the remote is the caller's job.
    pub fn repo_key(&self, normalized_remote: &str) -> String {
        hex(&hmac32(&self.0, normalized_remote.as_bytes())[..16])
    }

    /// The content of `team.repo` (base64url, no padding).
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.expose())
    }

    /// Reads the content of `team.repo`.
    pub fn decode(text: &str) -> Result<RepoKey, Error> {
        let mut raw = URL_SAFE_NO_PAD
            .decode(text.trim())
            .map_err(|_| Error::Malformed("team.repo"))?;
        let arr: Result<[u8; 32], _> = raw.as_slice().try_into();
        raw.as_mut_slice().zeroize();
        let mut arr = arr.map_err(|_| Error::Malformed("team.repo length"))?;
        let key = RepoKey(Secret32::from_bytes(arr));
        arr.zeroize();
        Ok(key)
    }
}

// ---------------------------------------------------------------------------------------
// Device keys and fingerprints

/// A device key pair (X25519). The secret half is zeroed on drop by `x25519-dalek`.
#[derive(Clone)]
pub struct DeviceKeys {
    /// The public key, sent with the join request.
    pub public: [u8; 32],
    secret: StaticSecret,
}

impl DeviceKeys {
    /// Generates a fresh key pair from the system random source.
    pub fn generate() -> Result<DeviceKeys, Error> {
        DeviceKeys::generate_with(&mut OsRng)
    }

    /// [`DeviceKeys::generate`] with an explicit random source (tests and vectors).
    pub fn generate_with(rng: &mut dyn Rng) -> Result<DeviceKeys, Error> {
        let seed = Secret32::random_with(rng)?;
        Ok(DeviceKeys::from_secret_bytes(*seed.expose()))
    }

    /// The key pair of a stored secret half.
    pub fn from_secret_bytes(secret: [u8; 32]) -> DeviceKeys {
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret).to_bytes();
        DeviceKeys { public, secret }
    }

    /// The secret half, for storing in `team.key`.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.secret.as_bytes()
    }

    /// The fingerprint of this device's public key.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }
}

impl ZeroizeOnDrop for DeviceKeys {}

impl fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceKeys {{ public: {}, .. }}", hex(&self.public))
    }
}

/// A device key's fingerprint: the first 16 bytes of `SHA-256("awm fp v1" ‖ public key)` as
/// eight groups of four hex digits. `awm team approve` and `awm team members` show it.
pub fn fingerprint(public: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(LABEL_FP);
    h.update(public);
    let d = h.finalize();
    d[..16].chunks(2).map(hex).collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------------------------
// Invites and joins

/// An invite: what the server issued (id and token), the handle the admin fixed, the
/// organisation id and the secret `S`, which never leaves the creating device except inside
/// the invite string the admin hands over.
#[derive(Clone)]
pub struct Invite {
    /// Organisation id.
    pub org: Uuid,
    /// Invite id issued by the server.
    pub invite_id: String,
    /// Invite token issued by the server.
    pub token: String,
    /// The handle the invite is for.
    pub handle: String,
    secret: Secret32,
}

impl Invite {
    /// `awm team invite` / `add-device`: wraps the server's id and token with a fresh `S`.
    pub fn create(org: Uuid, invite_id: &str, token: &str, handle: &str) -> Result<Invite, Error> {
        Invite::create_with(&mut OsRng, org, invite_id, token, handle)
    }

    /// [`Invite::create`] with an explicit random source (tests and vectors).
    pub fn create_with(
        rng: &mut dyn Rng,
        org: Uuid,
        invite_id: &str,
        token: &str,
        handle: &str,
    ) -> Result<Invite, Error> {
        let secret = Secret32::random_with(rng)?;
        Invite::from_parts(org, invite_id, token, handle, secret)
    }

    /// An invite loaded from `team.key` (pending invite secrets).
    pub fn from_parts(
        org: Uuid,
        invite_id: &str,
        token: &str,
        handle: &str,
        secret: Secret32,
    ) -> Result<Invite, Error> {
        if !valid_handle(handle) {
            return Err(Error::Malformed("handle"));
        }
        if invite_id.is_empty() || invite_id.len() > 255 || token.is_empty() || token.len() > 255 {
            return Err(Error::Malformed("invite id or token"));
        }
        Ok(Invite {
            org,
            invite_id: invite_id.to_string(),
            token: token.to_string(),
            handle: handle.to_string(),
            secret,
        })
    }

    /// The secret `S`, for `team.key` on the creating device only.
    pub fn secret(&self) -> &Secret32 {
        &self.secret
    }

    /// The invite string `awmi1_` + base64url(org ‖ S ‖ lp(invite id) ‖ lp(token) ‖
    /// lp(handle)), where lp is a one-byte length prefix.
    pub fn encode(&self) -> String {
        let mut body = Vec::with_capacity(16 + 32 + 3 + 64);
        body.extend_from_slice(self.org.as_bytes());
        body.extend_from_slice(self.secret.expose());
        for field in [&self.invite_id, &self.token, &self.handle] {
            push_lp8(&mut body, field.as_bytes()).expect("validated at creation");
        }
        let out = format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(&body));
        body.as_mut_slice().zeroize();
        out
    }

    /// Parses an invite string made by [`Invite::encode`].
    pub fn parse(text: &str) -> Result<Invite, Error> {
        let b64 = text
            .trim()
            .strip_prefix(INVITE_PREFIX)
            .ok_or(Error::Malformed("invite prefix"))?;
        let mut body = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| Error::Malformed("invite encoding"))?;
        let result = parse_invite_body(&body);
        body.as_mut_slice().zeroize();
        result
    }

    fn join_transcript(&self, device_id: Uuid, public: &[u8; 32]) -> Vec<u8> {
        let mut t = Vec::with_capacity(INFO_JOIN.len() + 16 + 2 + 64 + 16 + 32);
        t.extend_from_slice(INFO_JOIN);
        t.extend_from_slice(self.org.as_bytes());
        push_lp8(&mut t, self.invite_id.as_bytes()).expect("validated at creation");
        push_lp8(&mut t, self.handle.as_bytes()).expect("validated at creation");
        t.extend_from_slice(device_id.as_bytes());
        t.extend_from_slice(public);
        t
    }

    /// `join_mac = HMAC-SHA256(HKDF(S, "awm join v1"), "awm join v1" ‖ org ‖ lp(invite id) ‖
    /// lp(handle) ‖ device id ‖ public key)`.
    pub fn join_mac(&self, device_id: Uuid, public: &[u8; 32]) -> [u8; 32] {
        let key = hkdf32(None, self.secret.expose(), INFO_JOIN);
        hmac32(&key, &self.join_transcript(device_id, public))
    }

    /// The 6-digit code the invitee reads out from `awm team join` and the admin compares in
    /// `awm team approve`: HMAC-SHA256 under `HKDF(S, "awm code v1")` over the join
    /// transcript, first 8 bytes big-endian modulo 10^6, shown as `123 456`.
    pub fn confirmation_code(&self, device_id: Uuid, public: &[u8; 32]) -> String {
        let key = hkdf32(None, self.secret.expose(), INFO_CODE);
        let tag = hmac32(&key, &self.join_transcript(device_id, public));
        let n = u64::from_be_bytes(tag[..8].try_into().expect("8 bytes")) % 1_000_000;
        format!("{:03} {:03}", n / 1000, n % 1000)
    }

    /// The admin's check of a pending join: the MAC must verify under this invite's `S`,
    /// organisation id, invite id and handle. Only a verified join can be approved.
    pub fn verify_join(&self, request: &JoinRequest) -> Result<VerifiedJoin, Error> {
        if request.invite_id != self.invite_id {
            return Err(Error::Rejected("join request for another invite"));
        }
        if request.handle != self.handle {
            return Err(Error::Rejected("join request for another handle"));
        }
        let key = hkdf32(None, self.secret.expose(), INFO_JOIN);
        let transcript = self.join_transcript(request.device_id, &request.public_key);
        hmac_verify(&key, &transcript, &request.mac)?;
        Ok(VerifiedJoin {
            device_id: request.device_id,
            public_key: request.public_key,
            handle: request.handle.clone(),
            fingerprint: fingerprint(&request.public_key),
            code: self.confirmation_code(request.device_id, &request.public_key),
        })
    }
}

fn parse_invite_body(body: &[u8]) -> Result<Invite, Error> {
    if body.len() < 16 + 32 {
        return Err(Error::Malformed("invite length"));
    }
    let org = Uuid::from_slice(&body[..16]).map_err(|_| Error::Malformed("organisation id"))?;
    let mut s = [0u8; 32];
    s.copy_from_slice(&body[16..48]);
    let secret = Secret32::from_bytes(s);
    s.zeroize();
    let mut rest = &body[48..];
    let mut fields = Vec::with_capacity(3);
    for _ in 0..3 {
        let (&len, tail) = rest
            .split_first()
            .ok_or(Error::Malformed("invite length"))?;
        let len = len as usize;
        if tail.len() < len {
            return Err(Error::Malformed("invite length"));
        }
        let field =
            std::str::from_utf8(&tail[..len]).map_err(|_| Error::Malformed("invite field"))?;
        fields.push(field);
        rest = &tail[len..];
    }
    if !rest.is_empty() {
        return Err(Error::Malformed("invite trailing bytes"));
    }
    Invite::from_parts(org, fields[0], fields[1], fields[2], secret)
}

impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("org", &self.org)
            .field("invite_id", &self.invite_id)
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

/// What a joining device sends with `POST /v1/join` (besides the invite token). It holds no
/// secret: `S` stays out of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    /// Invite id.
    pub invite_id: String,
    /// Handle (equal to the invite's).
    pub handle: String,
    /// The joining device's id (UUIDv4 chosen by the device).
    pub device_id: Uuid,
    /// The joining device's X25519 public key.
    pub public_key: [u8; 32],
    /// [`Invite::join_mac`].
    pub mac: [u8; 32],
}

impl JoinRequest {
    /// The join request of a device holding `invite` (`awm team join`).
    pub fn new(invite: &Invite, device_id: Uuid, device: &DeviceKeys) -> JoinRequest {
        JoinRequest {
            invite_id: invite.invite_id.clone(),
            handle: invite.handle.clone(),
            device_id,
            public_key: device.public,
            mac: invite.join_mac(device_id, &device.public),
        }
    }
}

/// A join whose MAC verified ([`Invite::verify_join`]); the only input [`approve`] accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJoin {
    device_id: Uuid,
    public_key: [u8; 32],
    handle: String,
    fingerprint: String,
    code: String,
}

impl VerifiedJoin {
    /// The joining device's id.
    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    /// The joining device's public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// The handle.
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// The key fingerprint `awm team approve` shows.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The 6-digit code `awm team approve` compares with the one the invitee reads out.
    pub fn code(&self) -> &str {
        &self.code
    }
}

// ---------------------------------------------------------------------------------------
// Wraps

/// An epoch key wrapped to one device, with its authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrap {
    /// The receiving device.
    pub device_id: Uuid,
    /// The epoch of the wrapped key.
    pub epoch: u32,
    /// The device that made the wrap (the approver or the rotating admin).
    pub approver_device: Uuid,
    /// `0x01 ‖ ephemeral public key (32) ‖ nonce (24) ‖ XChaCha20-Poly1305(K_wrap, K_e)`.
    pub blob: Vec<u8>,
    /// HMAC-SHA256 over the wrap transcript, under `HKDF(S, "awm wrap-auth v1")` at a join
    /// and under `HKDF(K_{e-1}, "awm rot-auth v1")` at a rotation.
    pub auth: [u8; 32],
}

fn wrap_ad(
    org: Uuid,
    device_id: Uuid,
    epoch: u32,
    recipient: &[u8; 32],
    eph: &[u8; 32],
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(INFO_WRAP.len() + 16 + 16 + 4 + 64);
    ad.extend_from_slice(INFO_WRAP);
    ad.extend_from_slice(org.as_bytes());
    ad.extend_from_slice(device_id.as_bytes());
    ad.extend_from_slice(&epoch.to_be_bytes());
    ad.extend_from_slice(recipient);
    ad.extend_from_slice(eph);
    ad
}

fn wrap_key(shared: &[u8; 32], eph: &[u8; 32], recipient: &[u8; 32]) -> Secret32 {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph);
    salt[32..].copy_from_slice(recipient);
    hkdf32(Some(&salt), shared, INFO_WRAP)
}

/// Seals `key` to the device public key `recipient`: ephemeral X25519, HKDF-SHA256 (salt
/// ephemeral ‖ recipient public key, info "awm wrap v1"), XChaCha20-Poly1305 with AD
/// binding the organisation, device, epoch and both public keys.
fn seal_wrap(
    rng: &mut dyn Rng,
    org: Uuid,
    device_id: Uuid,
    recipient: &[u8; 32],
    key: &EpochKey,
) -> Result<Vec<u8>, Error> {
    let seed = Secret32::random_with(rng)?;
    let eph_secret = StaticSecret::from(*seed.expose());
    let eph = PublicKey::from(&eph_secret).to_bytes();
    let shared = eph_secret.diffie_hellman(&PublicKey::from(*recipient));
    if !shared.was_contributory() {
        return Err(Error::Rejected("low-order device public key"));
    }
    let k = wrap_key(shared.as_bytes(), &eph, recipient);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce)?;
    let ct = aead_seal(
        &k,
        &nonce,
        &wrap_ad(org, device_id, key.epoch, recipient, &eph),
        key.expose_secret(),
    )?;
    let mut blob = Vec::with_capacity(WRAP_LEN);
    blob.push(WRAP_VERSION);
    blob.extend_from_slice(&eph);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

fn open_wrap(
    org: Uuid,
    device_id: Uuid,
    device: &DeviceKeys,
    epoch: u32,
    blob: &[u8],
) -> Result<EpochKey, Error> {
    if blob.len() != WRAP_LEN || blob[0] != WRAP_VERSION {
        return Err(Error::Malformed("wrap"));
    }
    let eph: [u8; 32] = blob[1..33].try_into().expect("32 bytes");
    let nonce: [u8; NONCE_LEN] = blob[33..33 + NONCE_LEN].try_into().expect("24 bytes");
    let shared = device.secret.diffie_hellman(&PublicKey::from(eph));
    if !shared.was_contributory() {
        return Err(Error::Rejected("low-order ephemeral key"));
    }
    let k = wrap_key(shared.as_bytes(), &eph, &device.public);
    let mut raw = aead_open(
        &k,
        &nonce,
        &wrap_ad(org, device_id, epoch, &device.public, &eph),
        &blob[33 + NONCE_LEN..],
    )?;
    let arr: Result<[u8; 32], _> = raw.as_slice().try_into();
    raw.as_mut_slice().zeroize();
    let mut arr = arr.map_err(|_| Error::Malformed("wrapped key length"))?;
    let key = EpochKey::from_bytes(epoch, arr);
    arr.zeroize();
    Ok(key)
}

fn wrap_auth_transcript(
    mode: u8,
    org: Uuid,
    wrap: &Wrap,
    recipient: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let mut t = Vec::with_capacity(INFO_WRAP_AUTH.len() + 1 + 16 * 3 + 4 + 32 + 2 + WRAP_LEN);
    t.extend_from_slice(INFO_WRAP_AUTH);
    t.push(mode);
    t.extend_from_slice(org.as_bytes());
    t.extend_from_slice(wrap.device_id.as_bytes());
    t.extend_from_slice(&wrap.epoch.to_be_bytes());
    t.extend_from_slice(recipient);
    t.extend_from_slice(wrap.approver_device.as_bytes());
    let len = u16::try_from(wrap.blob.len()).map_err(|_| Error::Malformed("wrap"))?;
    t.extend_from_slice(&len.to_be_bytes());
    t.extend_from_slice(&wrap.blob);
    Ok(t)
}

/// Who authenticates a wrap, and how: the join (`S`) or the rotation (`K_e`) mode.
struct WrapAuth<'a> {
    mode: u8,
    key: &'a Secret32,
    approver_device: Uuid,
}

fn make_wrap(
    rng: &mut dyn Rng,
    auth: &WrapAuth<'_>,
    org: Uuid,
    device_id: Uuid,
    recipient: &[u8; 32],
    key: &EpochKey,
) -> Result<Wrap, Error> {
    let blob = seal_wrap(rng, org, device_id, recipient, key)?;
    let mut wrap = Wrap {
        device_id,
        epoch: key.epoch,
        approver_device: auth.approver_device,
        blob,
        auth: [0u8; 32],
    };
    wrap.auth = hmac32(
        auth.key,
        &wrap_auth_transcript(auth.mode, org, &wrap, recipient)?,
    );
    Ok(wrap)
}

// ---------------------------------------------------------------------------------------
// Approval

/// A member's role, as the roster records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// A member.
    Member,
    /// An admin.
    Admin,
}

/// What an approval adds: a new member with its first device, or a device of an existing
/// member (own second machine, or an admin's re-enrolment of a member who lost every
/// device, RV8-team M6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// A new member.
    Member,
    /// A device of an existing member.
    Device,
}

/// The output of an approval: the wraps for `POST /v1/devices/{id}/approve` and the roster
/// entry the approving device appends to its own `roster` stream.
#[derive(Debug, Clone)]
pub struct Approval {
    /// One wrap per epoch, 0 to current.
    pub wraps: Vec<Wrap>,
    /// The roster entry to seal with [`seal_roster`].
    pub roster: RosterEntry,
}

/// Fields of an approval that the verified join does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalInfo {
    /// The member the device belongs to (the server's id for a new member, the existing id
    /// for a device invite).
    pub member_id: Uuid,
    /// New member or another device of an existing one.
    pub kind: ApprovalKind,
    /// The member's role (ignored by verifiers for `Device`).
    pub role: Role,
    /// The approving device.
    pub approver_device: Uuid,
    /// Unix seconds.
    pub approved_at: i64,
}

/// Approves a verified join: wraps every epoch key to the device, authenticates each wrap
/// with `S`, and builds the roster entry.
///
/// `roster` is the approver's verified roster. The approver takes the kind, handle and (for a
/// device invite) the member id from its own invite record, never from the server's `pending`
/// list; a `member` approval whose member id the roster already holds is refused, and a
/// `device` approval needs the member in the roster under the invite's handle (RVT1 M2).
pub fn approve(
    ring: &KeyRing,
    roster: &Roster,
    invite: &Invite,
    join: &VerifiedJoin,
    info: ApprovalInfo,
) -> Result<Approval, Error> {
    approve_with(&mut OsRng, ring, roster, invite, join, info)
}

/// [`approve`] with an explicit random source (tests and vectors).
pub fn approve_with(
    rng: &mut dyn Rng,
    ring: &KeyRing,
    roster: &Roster,
    invite: &Invite,
    join: &VerifiedJoin,
    info: ApprovalInfo,
) -> Result<Approval, Error> {
    if invite.org != ring.org {
        return Err(Error::Rejected("invite of another organisation"));
    }
    if join.handle != invite.handle {
        return Err(Error::Rejected("verified join of another invite"));
    }
    match info.kind {
        ApprovalKind::Member => {
            if roster.members.contains_key(&info.member_id) {
                return Err(Error::Rejected("member id already in the roster"));
            }
        }
        ApprovalKind::Device => match roster.members.get(&info.member_id) {
            None => {
                return Err(Error::Rejected(
                    "device approval for a member not in the roster",
                ))
            }
            Some(m) if m.handle != join.handle => {
                return Err(Error::Rejected("handle does not match the member"))
            }
            Some(_) => {}
        },
    }
    if roster.devices.contains_key(&join.device_id) {
        return Err(Error::Rejected("device id already in the roster"));
    }
    let auth_key = hkdf32(None, invite.secret.expose(), INFO_WRAP_AUTH);
    let auth = WrapAuth {
        mode: MODE_JOIN,
        key: &auth_key,
        approver_device: info.approver_device,
    };
    let mut wraps = Vec::with_capacity(ring.keys.len());
    for key in ring.epochs() {
        wraps.push(make_wrap(
            rng,
            &auth,
            ring.org,
            join.device_id,
            &join.public_key,
            key,
        )?);
    }
    Ok(Approval {
        wraps,
        roster: RosterEntry::Approve {
            member_id: info.member_id,
            handle: join.handle.clone(),
            role: info.role,
            kind: info.kind,
            device_id: join.device_id,
            device_pub: join.public_key,
            approved_at: info.approved_at,
            approver_device_id: info.approver_device,
        },
    })
}

/// The joining device's check of its approval: every wrap must be for this device,
/// authenticated with `S` and open with the device key, and together they must hold epochs
/// 0 to n. The server never sees `S`, so it cannot slip in a key it knows (P2 at join).
pub fn accept_join(
    invite: &Invite,
    device_id: Uuid,
    device: &DeviceKeys,
    wraps: &[Wrap],
) -> Result<KeyRing, Error> {
    if wraps.is_empty() {
        return Err(Error::Rejected("no wraps: the join is not approved"));
    }
    let auth_key = hkdf32(None, invite.secret.expose(), INFO_WRAP_AUTH);
    let mut keys = Vec::with_capacity(wraps.len());
    for wrap in wraps {
        if wrap.device_id != device_id {
            return Err(Error::Rejected("wrap is for another device"));
        }
        let transcript = wrap_auth_transcript(MODE_JOIN, invite.org, wrap, &device.public)?;
        hmac_verify(&auth_key, &transcript, &wrap.auth)?;
        keys.push(open_wrap(
            invite.org, device_id, device, wrap.epoch, &wrap.blob,
        )?);
    }
    KeyRing::from_keys(invite.org, keys)
}

// ---------------------------------------------------------------------------------------
// Roster

mod b64_fixed {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let text = String::deserialize(d)?;
        let raw = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(serde::de::Error::custom)?;
        raw.as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom(format!("expected {N} bytes")))
    }
}

/// One roster record's content (tag `roster`, RV8-team X1). It travels sealed under an epoch
/// key in the writing device's `roster` stream, so the AD binds it to that stream, its index
/// and its epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RosterEntry {
    /// The first admin's first device (`awm team create`), at index 0 under epoch 0. It counts
    /// only if [`org_id`] of its device id, key and nonce is the organisation id (RVT1 B1).
    Genesis {
        /// The first admin's member id.
        member_id: Uuid,
        /// Handle.
        handle: String,
        /// Device id (the writer).
        device_id: Uuid,
        /// Device public key.
        #[serde(with = "b64_fixed")]
        device_pub: [u8; 32],
        /// The random nonce of [`KeyRing::create`].
        #[serde(with = "b64_fixed")]
        org_nonce: [u8; ORG_NONCE_LEN],
        /// Unix seconds.
        created_at: i64,
    },
    /// An approval: `(member id, handle, device id, device public key, approved_at,
    /// approver device id)` plus role and kind.
    Approve {
        /// The member the device belongs to.
        member_id: Uuid,
        /// The member's handle.
        handle: String,
        /// The member's role (for `Member` approvals).
        role: Role,
        /// New member or another device.
        kind: ApprovalKind,
        /// The approved device.
        device_id: Uuid,
        /// Its public key.
        #[serde(with = "b64_fixed")]
        device_pub: [u8; 32],
        /// Unix seconds.
        approved_at: i64,
        /// The approving device (the writer of this record).
        approver_device_id: Uuid,
    },
    /// An admin who restored a recovery export on a new device enrols that device itself.
    Recover {
        /// The admin's member id (the writer's).
        member_id: Uuid,
        /// Handle.
        handle: String,
        /// The new device (the writer).
        device_id: Uuid,
        /// Its public key.
        #[serde(with = "b64_fixed")]
        device_pub: [u8; 32],
        /// Unix seconds.
        recovered_at: i64,
    },
    /// A removal (`device_id` absent: the whole member) or a device revocation.
    Revoke {
        /// The member.
        member_id: Uuid,
        /// One device, or every device of the member when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<Uuid>,
        /// Unix seconds.
        revoked_at: i64,
        /// The writing device.
        by_device_id: Uuid,
    },
    /// Epoch membership after a rotation: the devices the new epoch was wrapped to.
    Epoch {
        /// The new epoch (the record is sealed under it).
        epoch: u32,
        /// Devices wrapped to.
        devices: Vec<Uuid>,
        /// Unix seconds.
        created_at: i64,
        /// The rotating device.
        by_device_id: Uuid,
    },
}

/// A sealed roster record with the stream metadata the server holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterBlob {
    /// Writer's member id.
    pub member: Uuid,
    /// Writer's device id.
    pub device: Uuid,
    /// Index in the writer's `roster` stream.
    pub idx: u64,
    /// Record id.
    pub record_id: Uuid,
    /// Epoch the record is sealed under.
    pub epoch: u32,
    /// The envelope.
    pub blob: Vec<u8>,
}

impl RosterBlob {
    /// The AD this record is sealed under (the writer's own `roster` stream).
    pub fn ad(&self, org: Uuid) -> RecordAd {
        RecordAd::new(
            org,
            self.member,
            self.device,
            ROSTER_TAG,
            self.idx,
            self.record_id,
            self.epoch,
        )
    }
}

/// Where a roster record goes: the writer's own `roster` stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RosterSlot {
    /// Writer's member id.
    pub member: Uuid,
    /// Writer's device id.
    pub device: Uuid,
    /// Next index in the writer's `roster` stream.
    pub idx: u64,
    /// Record id.
    pub record_id: Uuid,
}

/// Seals a roster entry under `key` (the current epoch key; for an `Epoch` entry, the new
/// epoch's key).
pub fn seal_roster(
    org: Uuid,
    key: &EpochKey,
    slot: RosterSlot,
    entry: &RosterEntry,
) -> Result<RosterBlob, Error> {
    seal_roster_with(&mut OsRng, org, key, slot, entry)
}

/// [`seal_roster`] with an explicit random source (tests and vectors).
pub fn seal_roster_with(
    rng: &mut dyn Rng,
    org: Uuid,
    key: &EpochKey,
    slot: RosterSlot,
    entry: &RosterEntry,
) -> Result<RosterBlob, Error> {
    let plain = serde_json::to_vec(&RosterPlaintext {
        schema: ROSTER_SCHEMA,
        entry: entry.clone(),
    })
    .map_err(|_| Error::Malformed("roster entry"))?;
    let mut out = RosterBlob {
        member: slot.member,
        device: slot.device,
        idx: slot.idx,
        record_id: slot.record_id,
        epoch: key.epoch(),
        blob: Vec::new(),
    };
    out.blob = seal_record_with(rng, key, &out.ad(org), &plain)?;
    Ok(out)
}

/// A device the roster has verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterDevice {
    /// Its member.
    pub member_id: Uuid,
    /// Its public key, as approved.
    pub public_key: [u8; 32],
    /// The device that approved it (itself for the genesis and recovery entries).
    pub approver: Uuid,
    /// Revoked by a roster revocation (or its member was removed).
    pub revoked: bool,
}

/// A member the roster has verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterMember {
    /// Handle.
    pub handle: String,
    /// Admin per the roster (genesis or an admin approval by an admin).
    pub admin: bool,
    /// Removed.
    pub revoked: bool,
}

/// A roster record that did not verify, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterRejection {
    /// Writer's member id.
    pub member: Uuid,
    /// Writer's device id.
    pub device: Uuid,
    /// Index.
    pub idx: u64,
    /// The rule it broke.
    pub reason: &'static str,
}

/// The roster a client has verified (`team_member`, `team_device`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roster {
    members: BTreeMap<Uuid, RosterMember>,
    devices: BTreeMap<Uuid, RosterDevice>,
    epochs: BTreeMap<u32, Vec<Uuid>>,
}

/// The result of [`Roster::verify`].
#[derive(Debug, Clone, Default)]
pub struct RosterReport {
    /// The verified roster.
    pub roster: Roster,
    /// Records that did not verify (never trusted, never wrapped to).
    pub rejected: Vec<RosterRejection>,
    /// `extra_admins` was given but not used, because the roster holds a verified,
    /// non-revoked admin (RVT1 M5).
    pub extra_admins_ignored: bool,
}

struct Pending {
    meta: RosterBlob,
    entry: RosterEntry,
}

impl Roster {
    /// Verifies roster records from every `roster` stream.
    ///
    /// A record counts only if it opens under the key ring with the AD of the stream it was
    /// served from (so the server can neither forge one nor move one), the writer device is
    /// itself verified and belongs to the stream's member, and the writer may make that
    /// change: a member approves only their own devices; admins approve anyone, revoke anyone
    /// and record epochs. The genesis counts only if it hashes to the organisation id
    /// ([`org_id`]).
    ///
    /// `extra_admins` are members the caller treats as admins beyond the roster (the server's
    /// role list after `awm serve promote`, confirmed by the user). They apply only when the
    /// roster verified without them holds no non-revoked admin; otherwise they are ignored and
    /// [`RosterReport::extra_admins_ignored`] is set (RVT1 M5).
    pub fn verify(
        ring: &KeyRing,
        blobs: &[RosterBlob],
        extra_admins: &BTreeSet<Uuid>,
    ) -> RosterReport {
        let mut report = Roster::verify_with(ring, blobs, &BTreeSet::new());
        if extra_admins.is_empty() {
            return report;
        }
        if report
            .roster
            .members
            .values()
            .any(|m| m.admin && !m.revoked)
        {
            report.extra_admins_ignored = true;
            return report;
        }
        Roster::verify_with(ring, blobs, extra_admins)
    }

    fn verify_with(
        ring: &KeyRing,
        blobs: &[RosterBlob],
        extra_admins: &BTreeSet<Uuid>,
    ) -> RosterReport {
        let mut report = RosterReport::default();
        let mut pending = Vec::new();
        let mut sorted: Vec<&RosterBlob> = blobs.iter().collect();
        sorted.sort_by(|a, b| {
            (a.member, a.device, a.idx, a.record_id, a.epoch, &a.blob).cmp(&(
                b.member,
                b.device,
                b.idx,
                b.record_id,
                b.epoch,
                &b.blob,
            ))
        });
        // The same record served twice counts once.
        sorted.dedup();
        for b in sorted {
            let reject = |reason| rejection(b, reason);
            let plain = match open_record(ring, &b.ad(ring.org), &b.blob) {
                Ok(p) => p,
                Err(_) => {
                    report
                        .rejected
                        .push(reject("does not open with this stream's AD"));
                    continue;
                }
            };
            match serde_json::from_slice::<RosterPlaintext>(&plain) {
                Ok(p) if p.schema == ROSTER_SCHEMA => pending.push(Pending {
                    meta: b.clone(),
                    entry: p.entry,
                }),
                Ok(_) => report.rejected.push(reject("unknown roster schema")),
                Err(_) => report.rejected.push(reject("not a roster entry")),
            }
        }
        let roster = &mut report.roster;

        // The genesis: index 0 under epoch 0 in the first admin's own stream, hashing to the
        // organisation id. Its order or time is never trusted (RVT1 B1). Two passing geneses
        // need a second preimage or a server that let a stream reuse the genesis device id;
        // both are rejected then, so the failure is closed.
        let mut done = vec![false; pending.len()];
        let mut passing = Vec::new();
        for (i, p) in pending.iter().enumerate() {
            let RosterEntry::Genesis {
                member_id,
                device_id,
                device_pub,
                org_nonce,
                ..
            } = &p.entry
            else {
                continue;
            };
            done[i] = true;
            let reason = if p.meta.idx != 0 || p.meta.epoch != 0 {
                Some("genesis not at index 0 under epoch 0")
            } else if *member_id != p.meta.member || *device_id != p.meta.device {
                Some("genesis not written by its own device")
            } else if org_id(*device_id, device_pub, org_nonce) != ring.org {
                Some("genesis does not hash to the organisation id")
            } else {
                None
            };
            match reason {
                Some(r) => report.rejected.push(rejection(&p.meta, r)),
                None => passing.push(i),
            }
        }
        if passing.len() > 1 {
            for &i in &passing {
                report
                    .rejected
                    .push(rejection(&pending[i].meta, "more than one genesis"));
            }
        } else if let Some(&i) = passing.first() {
            let RosterEntry::Genesis {
                member_id,
                handle,
                device_id,
                device_pub,
                ..
            } = &pending[i].entry
            else {
                unreachable!()
            };
            roster.members.insert(
                *member_id,
                RosterMember {
                    handle: handle.clone(),
                    admin: true,
                    revoked: false,
                },
            );
            roster.devices.insert(
                *device_id,
                RosterDevice {
                    member_id: *member_id,
                    public_key: *device_pub,
                    approver: *device_id,
                    revoked: false,
                },
            );
        }

        // Approvals and recoveries, to a fixpoint: an entry waits until its writer (and, for
        // a device approval, its member) is verified.
        loop {
            let mut progress = false;
            for i in 0..pending.len() {
                if done[i] {
                    continue;
                }
                let p = &pending[i];
                let outcome = match &p.entry {
                    RosterEntry::Approve { .. } => roster.check_approve(p, extra_admins),
                    RosterEntry::Recover { .. } => roster.check_recover(p, extra_admins),
                    _ => continue,
                };
                match outcome {
                    Step::Wait => continue,
                    Step::Apply => roster.apply(&p.entry),
                    Step::Same => {}
                    Step::Reject(r) => report.rejected.push(rejection(&p.meta, r)),
                }
                done[i] = true;
                progress = true;
            }
            if !progress {
                break;
            }
        }

        // Revocations and epoch records, by verified writers.
        for i in 0..pending.len() {
            if done[i] {
                continue;
            }
            done[i] = true;
            let p = &pending[i];
            let outcome = match &p.entry {
                RosterEntry::Revoke { .. } | RosterEntry::Epoch { .. } => {
                    roster.check_late(p, extra_admins)
                }
                _ => Step::Reject("approver not verified"),
            };
            match outcome {
                Step::Apply => roster.apply(&p.entry),
                Step::Reject(r) => report.rejected.push(rejection(&p.meta, r)),
                Step::Wait | Step::Same => {}
            }
        }
        let revoked_members: BTreeSet<Uuid> = roster
            .members
            .iter()
            .filter(|(_, m)| m.revoked)
            .map(|(id, _)| *id)
            .collect();
        for d in roster.devices.values_mut() {
            if revoked_members.contains(&d.member_id) {
                d.revoked = true;
            }
        }
        report
    }

    fn writer_ok(&self, meta: &RosterBlob) -> Result<(), &'static str> {
        match self.devices.get(&meta.device) {
            None => Err("writer device not verified"),
            Some(d) if d.member_id != meta.member => Err("writer device of another member"),
            Some(_) => Ok(()),
        }
    }

    fn is_admin(&self, member: Uuid, extra_admins: &BTreeSet<Uuid>) -> bool {
        self.members.get(&member).is_some_and(|m| m.admin) || extra_admins.contains(&member)
    }

    fn check_approve(&self, p: &Pending, extra_admins: &BTreeSet<Uuid>) -> Step {
        let RosterEntry::Approve {
            member_id,
            handle,
            kind,
            device_id,
            device_pub,
            approver_device_id,
            ..
        } = &p.entry
        else {
            unreachable!()
        };
        if *approver_device_id != p.meta.device {
            return Step::Reject("approver is not the writer");
        }
        if let Err(r) = self.writer_ok(&p.meta) {
            return if self.devices.contains_key(&p.meta.device) {
                Step::Reject(r)
            } else {
                Step::Wait
            };
        }
        if !valid_handle(handle) {
            return Step::Reject("handle");
        }
        let writer_admin = self.is_admin(p.meta.member, extra_admins);
        match kind {
            ApprovalKind::Member => {
                if !writer_admin {
                    return Step::Reject("only an admin approves a new member");
                }
                if let Some(m) = self.members.get(member_id) {
                    // The same approval seen twice is harmless; anything else reuses an id.
                    let same = m.handle == *handle
                        && self.devices.get(device_id).is_some_and(|d| {
                            d.member_id == *member_id && d.public_key == *device_pub
                        });
                    return if same {
                        Step::Same
                    } else {
                        Step::Reject("member id already in the roster")
                    };
                }
            }
            ApprovalKind::Device => {
                let Some(m) = self.members.get(member_id) else {
                    return Step::Wait;
                };
                if *member_id != p.meta.member && !writer_admin {
                    return Step::Reject("a member approves only their own devices");
                }
                if m.handle != *handle {
                    return Step::Reject("handle does not match the member");
                }
            }
        }
        match self.devices.get(device_id) {
            Some(d) if d.member_id == *member_id && d.public_key == *device_pub => Step::Same,
            Some(_) => Step::Reject("device id already in the roster"),
            None => Step::Apply,
        }
    }

    fn check_recover(&self, p: &Pending, extra_admins: &BTreeSet<Uuid>) -> Step {
        let RosterEntry::Recover {
            member_id,
            handle,
            device_id,
            device_pub,
            ..
        } = &p.entry
        else {
            unreachable!()
        };
        if *member_id != p.meta.member || *device_id != p.meta.device {
            return Step::Reject("recovery not written by the recovered device");
        }
        let Some(m) = self.members.get(member_id) else {
            return Step::Wait;
        };
        if !self.is_admin(*member_id, extra_admins) {
            return Step::Reject("only an admin recovers from an export");
        }
        if m.handle != *handle {
            return Step::Reject("handle does not match the member");
        }
        match self.devices.get(device_id) {
            Some(d) if d.member_id == *member_id && d.public_key == *device_pub => Step::Same,
            Some(_) => Step::Reject("device id already in the roster"),
            None => Step::Apply,
        }
    }

    fn check_late(&self, p: &Pending, extra_admins: &BTreeSet<Uuid>) -> Step {
        if let Err(r) = self.writer_ok(&p.meta) {
            return Step::Reject(r);
        }
        let writer_admin = self.is_admin(p.meta.member, extra_admins);
        match &p.entry {
            RosterEntry::Revoke {
                member_id,
                device_id,
                by_device_id,
                ..
            } => {
                if *by_device_id != p.meta.device {
                    return Step::Reject("revoker is not the writer");
                }
                if !writer_admin && *member_id != p.meta.member {
                    return Step::Reject("a member revokes only their own devices");
                }
                if !self.members.contains_key(member_id) {
                    return Step::Reject("unknown member");
                }
                if let Some(d) = device_id {
                    if self
                        .devices
                        .get(d)
                        .is_none_or(|d| d.member_id != *member_id)
                    {
                        return Step::Reject("device of another member");
                    }
                }
                Step::Apply
            }
            RosterEntry::Epoch {
                epoch,
                by_device_id,
                ..
            } => {
                if *by_device_id != p.meta.device {
                    return Step::Reject("rotator is not the writer");
                }
                if !writer_admin {
                    return Step::Reject("only an admin rotates");
                }
                if *epoch != p.meta.epoch {
                    return Step::Reject("epoch record not sealed under its epoch");
                }
                Step::Apply
            }
            _ => Step::Reject("unexpected entry"),
        }
    }

    fn apply(&mut self, entry: &RosterEntry) {
        match entry {
            RosterEntry::Approve {
                member_id,
                handle,
                role,
                kind,
                device_id,
                device_pub,
                approver_device_id,
                ..
            } => {
                if *kind == ApprovalKind::Member {
                    self.members.insert(
                        *member_id,
                        RosterMember {
                            handle: handle.clone(),
                            admin: *role == Role::Admin,
                            revoked: false,
                        },
                    );
                }
                self.devices.insert(
                    *device_id,
                    RosterDevice {
                        member_id: *member_id,
                        public_key: *device_pub,
                        approver: *approver_device_id,
                        revoked: false,
                    },
                );
            }
            RosterEntry::Recover {
                member_id,
                device_id,
                device_pub,
                ..
            } => {
                self.devices.insert(
                    *device_id,
                    RosterDevice {
                        member_id: *member_id,
                        public_key: *device_pub,
                        approver: *device_id,
                        revoked: false,
                    },
                );
            }
            RosterEntry::Revoke {
                member_id,
                device_id,
                ..
            } => match device_id {
                Some(d) => {
                    if let Some(d) = self.devices.get_mut(d) {
                        d.revoked = true;
                    }
                }
                None => {
                    if let Some(m) = self.members.get_mut(member_id) {
                        m.revoked = true;
                    }
                }
            },
            RosterEntry::Epoch { epoch, devices, .. } => {
                self.epochs.insert(*epoch, devices.clone());
            }
            RosterEntry::Genesis { .. } => {}
        }
    }

    /// A verified device, revoked or not.
    pub fn device(&self, device_id: Uuid) -> Option<&RosterDevice> {
        self.devices.get(&device_id)
    }

    /// A verified member.
    pub fn member(&self, member_id: Uuid) -> Option<&RosterMember> {
        self.members.get(&member_id)
    }

    /// Every verified device.
    pub fn devices(&self) -> impl Iterator<Item = (&Uuid, &RosterDevice)> {
        self.devices.iter()
    }

    /// Every verified member.
    pub fn members(&self) -> impl Iterator<Item = (&Uuid, &RosterMember)> {
        self.members.iter()
    }

    /// The devices an epoch record lists.
    pub fn epoch_devices(&self, epoch: u32) -> Option<&[Uuid]> {
        self.epochs.get(&epoch).map(Vec::as_slice)
    }

    /// The joining device's check before its first push (RVT1 M2): a verified, non-revoked
    /// roster entry names this device with the member id and handle of its join response and
    /// with its own public key. The approval wraps do not bind the member id; this does. A
    /// device refuses to push until it passes.
    pub fn check_own_approval(
        &self,
        device_id: Uuid,
        member_id: Uuid,
        handle: &str,
        public: &[u8; 32],
    ) -> Result<(), Error> {
        let d = self
            .devices
            .get(&device_id)
            .ok_or(Error::Rejected("no verified roster entry for this device"))?;
        if d.member_id != member_id {
            return Err(Error::Rejected(
                "the roster names another member for this device",
            ));
        }
        if d.public_key != *public {
            return Err(Error::Rejected(
                "the roster names another key for this device",
            ));
        }
        let m = self
            .members
            .get(&member_id)
            .ok_or(Error::Rejected("member not in the roster"))?;
        if m.handle != handle {
            return Err(Error::Rejected(
                "the roster names another handle for this member",
            ));
        }
        if d.revoked || m.revoked {
            return Err(Error::Rejected("this device or its member is revoked"));
        }
        Ok(())
    }

    /// How `awm team members` shows a device the server lists.
    pub fn status(&self, listed: &ListedDevice) -> DeviceStatus {
        match self.devices.get(&listed.device_id) {
            None => DeviceStatus::Unverified,
            Some(d) if d.member_id != listed.member_id || d.public_key != listed.public_key => {
                DeviceStatus::Mismatch
            }
            Some(d) if d.revoked => DeviceStatus::Revoked,
            Some(_) => DeviceStatus::Verified,
        }
    }
}

enum Step {
    Wait,
    Apply,
    Same,
    Reject(&'static str),
}

fn rejection(meta: &RosterBlob, reason: &'static str) -> RosterRejection {
    RosterRejection {
        member: meta.member,
        device: meta.device,
        idx: meta.idx,
        reason,
    }
}

/// A device as the server lists it in `GET /v1/members` (untrusted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedDevice {
    /// Member id the server claims.
    pub member_id: Uuid,
    /// Device id.
    pub device_id: Uuid,
    /// Public key the server claims.
    pub public_key: [u8; 32],
}

/// A listed device compared with the verified roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    /// A verified, non-revoked roster entry with the same member and key.
    Verified,
    /// No verified roster entry (`unverified` in `awm team members`).
    Unverified,
    /// The roster entry names another member or another key than the server lists.
    Mismatch,
    /// Revoked in the roster.
    Revoked,
}

// ---------------------------------------------------------------------------------------
// Rotation

/// Which devices a rotation wraps to, and which it leaves out and why. Built only by
/// [`plan_rotation`], so a wrap to an unverified, revoked or removed device cannot be asked
/// for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationPlan {
    new_epoch: u32,
    wrap_to: Vec<ListedDevice>,
    unverified: Vec<Uuid>,
    mismatch: Vec<Uuid>,
    revoked: Vec<Uuid>,
    removed: Vec<Uuid>,
    not_listed: Vec<Uuid>,
    approved_by_removed: Vec<Uuid>,
}

impl RotationPlan {
    /// The epoch the rotation creates.
    pub fn new_epoch(&self) -> u32 {
        self.new_epoch
    }

    /// Devices that get a wrap (verified, not revoked, not removed; keys from the roster).
    pub fn wrap_to(&self) -> &[ListedDevice] {
        &self.wrap_to
    }

    /// Listed by the server without a verified roster entry: no wrap.
    pub fn unverified(&self) -> &[Uuid] {
        &self.unverified
    }

    /// Listed with another member or key than the roster holds: no wrap.
    pub fn mismatch(&self) -> &[Uuid] {
        &self.mismatch
    }

    /// Revoked in the roster: no wrap.
    pub fn revoked(&self) -> &[Uuid] {
        &self.revoked
    }

    /// Devices of the removed members: no wrap.
    pub fn removed(&self) -> &[Uuid] {
        &self.removed
    }

    /// Verified and not revoked, but not listed by the server (it cannot store a wrap).
    pub fn not_listed(&self) -> &[Uuid] {
        &self.not_listed
    }

    /// Devices of other members that a removed member approved, and devices whose approving
    /// device is revoked; wrapped, but shown to the rotating admin (an admin could have enrolled
    /// a device for someone else before removal, and a lost device could have approved one
    /// before its revocation; RVT1 m6).
    pub fn approved_by_removed(&self) -> &[Uuid] {
        &self.approved_by_removed
    }
}

/// Plans a rotation to `current + 1`: wraps go only to devices the server lists that have a
/// verified roster entry with the same member and key, are not revoked and are not
/// `removed_members`' (RV8-team X1).
pub fn plan_rotation(
    ring: &KeyRing,
    roster: &Roster,
    listed: &[ListedDevice],
    removed_members: &BTreeSet<Uuid>,
) -> RotationPlan {
    let mut plan = RotationPlan {
        new_epoch: ring.current_epoch() + 1,
        wrap_to: Vec::new(),
        unverified: Vec::new(),
        mismatch: Vec::new(),
        revoked: Vec::new(),
        removed: Vec::new(),
        not_listed: Vec::new(),
        approved_by_removed: Vec::new(),
    };
    let mut seen = BTreeSet::new();
    for l in listed {
        if !seen.insert(l.device_id) {
            continue;
        }
        let Some(d) = roster.devices.get(&l.device_id) else {
            plan.unverified.push(l.device_id);
            continue;
        };
        if d.member_id != l.member_id || d.public_key != l.public_key {
            plan.mismatch.push(l.device_id);
        } else if removed_members.contains(&d.member_id) {
            plan.removed.push(l.device_id);
        } else if d.revoked || roster.members.get(&d.member_id).is_none_or(|m| m.revoked) {
            plan.revoked.push(l.device_id);
        } else {
            let suspect = d.approver != l.device_id
                && roster.devices.get(&d.approver).is_some_and(|a| {
                    a.revoked
                        || (a.member_id != d.member_id && removed_members.contains(&a.member_id))
                });
            if suspect {
                plan.approved_by_removed.push(l.device_id);
            }
            plan.wrap_to.push(ListedDevice {
                member_id: d.member_id,
                device_id: l.device_id,
                public_key: d.public_key,
            });
        }
    }
    for (id, d) in &roster.devices {
        let member_revoked = roster.members.get(&d.member_id).is_none_or(|m| m.revoked);
        if !seen.contains(id)
            && !d.revoked
            && !member_revoked
            && !removed_members.contains(&d.member_id)
        {
            plan.not_listed.push(*id);
        }
    }
    plan
}

/// A rotation's output: the new key (kept by the rotating device through
/// [`KeyRing::adopt_own_rotation`]), the wraps for `POST /v1/keys/rotate`, and the `Epoch`
/// roster entry to seal under the new key.
#[derive(Debug, Clone)]
pub struct Rotation {
    /// `K_{e+1}`.
    pub key: EpochKey,
    /// One wrap per planned device, authenticated with `K_e`.
    pub wraps: Vec<Wrap>,
    /// The epoch membership record.
    pub roster: RosterEntry,
}

/// Creates `K_{e+1}` and wraps it to the planned devices.
pub fn rotate(
    ring: &KeyRing,
    plan: &RotationPlan,
    by_device: Uuid,
    created_at: i64,
) -> Result<Rotation, Error> {
    rotate_with(&mut OsRng, ring, plan, by_device, created_at)
}

/// [`rotate`] with an explicit random source (tests and vectors).
pub fn rotate_with(
    rng: &mut dyn Rng,
    ring: &KeyRing,
    plan: &RotationPlan,
    by_device: Uuid,
    created_at: i64,
) -> Result<Rotation, Error> {
    if plan.new_epoch != ring.current_epoch() + 1 {
        return Err(Error::Rejected("the plan is not for current + 1"));
    }
    let key = EpochKey::generate_with(rng, plan.new_epoch)?;
    let auth_key = ring.current().rotation_auth_key();
    let auth = WrapAuth {
        mode: MODE_ROTATION,
        key: &auth_key,
        approver_device: by_device,
    };
    let mut wraps = Vec::with_capacity(plan.wrap_to.len());
    for d in &plan.wrap_to {
        wraps.push(make_wrap(
            rng,
            &auth,
            ring.org,
            d.device_id,
            &d.public_key,
            &key,
        )?);
    }
    Ok(Rotation {
        roster: RosterEntry::Epoch {
            epoch: plan.new_epoch,
            devices: plan.wrap_to.iter().map(|d| d.device_id).collect(),
            created_at,
            by_device_id: by_device,
        },
        key,
        wraps,
    })
}
