//! Record envelope v1: XChaCha20-Poly1305 with associated data and padding
//! (plan-v3-team §5.1, TM3; the construction is written down in `docs/sync-v1-crypto.md`).
//!
//! ```text
//! envelope = 0x01 ‖ nonce (24) ‖ XChaCha20-Poly1305(K_rec, nonce, pad(plaintext), AD)
//! K_rec    = HKDF-SHA256(salt none, ikm K_e, info "awm rec v1")
//! pad(p)   = p ‖ 0x80 ‖ 0x00 … up to the next multiple of 256 bytes (ISO/IEC 7816-4)
//! AD       = "awm1" ‖ org (16) ‖ member (16) ‖ device (16) ‖ len (1) ‖ tag ‖ idx (u64 BE)
//!            ‖ record id (16) ‖ epoch (u32 BE)
//! ```
//!
//! The record kind is the stream tag (`rec`, `flag`, `stats`, `policy`, `roster`), so the AD
//! binds it together with the stream, the position and the epoch.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::digest::zeroize::{Zeroize, ZeroizeOnDrop};
use sha2::Sha256;
use uuid::Uuid;

use crate::keys::{EpochKey, KeyRing};

/// The version byte of envelope v1.
pub const ENVELOPE_VERSION: u8 = 0x01;
/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Version byte plus nonce.
pub const HEADER_LEN: usize = 1 + NONCE_LEN;
/// Bytes an envelope adds to the padded plaintext (41).
pub const OVERHEAD: usize = HEADER_LEN + TAG_LEN;
/// Padding bucket: every padded plaintext is a multiple of this.
pub const PAD_BUCKET: usize = 256;
/// Largest envelope the server accepts (plan-v3-team §4.3.5: blob ≤ 16 KiB).
pub const MAX_ENVELOPE: usize = 16 * 1024;
/// Largest plaintext that fits [`MAX_ENVELOPE`] after padding (16,127 bytes).
pub const MAX_PLAINTEXT: usize = (MAX_ENVELOPE - OVERHEAD) / PAD_BUCKET * PAD_BUCKET - 1;
/// Longest stream tag the AD encodes.
pub const MAX_TAG_LEN: usize = 32;

const AD_LABEL: &[u8; 4] = b"awm1";
const INFO_REC: &[u8] = b"awm rec v1";

/// Errors of the envelope and the key flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The operating system's random source failed.
    Rng,
    /// The plaintext does not fit [`MAX_ENVELOPE`].
    TooLarge,
    /// Bytes that do not parse (wrong version byte, length, encoding, field).
    Malformed(&'static str),
    /// AEAD authentication failed: wrong key, wrong associated data or modified bytes.
    Open,
    /// A join MAC or a wrap authenticator did not verify.
    BadMac,
    /// No key for this epoch in the key ring.
    UnknownEpoch(u32),
    /// A key-flow rule was broken (the message names the rule).
    Rejected(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rng => write!(f, "the system random source failed"),
            Error::TooLarge => write!(f, "plaintext too large for one envelope"),
            Error::Malformed(what) => write!(f, "malformed {what}"),
            Error::Open => write!(f, "decryption failed (wrong key or associated data)"),
            Error::BadMac => write!(f, "authenticator did not verify"),
            Error::UnknownEpoch(e) => write!(f, "no key for epoch {e}"),
            Error::Rejected(why) => write!(f, "rejected: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// A source of random bytes.
///
/// Production code uses [`OsRng`] (the plain functions such as [`seal_record`] do). The
/// `*_with` variants take any `Rng` so that tests can produce known-answer vectors with a
/// deterministic generator; such a generator must never be used outside tests.
pub trait Rng {
    /// Fills `out` with random bytes.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error>;
}

/// Randomness from the operating system through `getrandom`.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

impl Rng for OsRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(out).map_err(|_| Error::Rng)
    }
}

/// 32 secret bytes, overwritten with zeros on drop.
#[derive(Clone)]
pub struct Secret32([u8; 32]);

impl Secret32 {
    /// Wraps `bytes`; the caller's copy is the caller's to clear.
    pub fn from_bytes(bytes: [u8; 32]) -> Secret32 {
        Secret32(bytes)
    }

    /// Fresh random bytes.
    pub fn random_with(rng: &mut dyn Rng) -> Result<Secret32, Error> {
        let mut s = Secret32([0u8; 32]);
        rng.fill(&mut s.0)?;
        Ok(s)
    }

    /// The secret bytes.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Zeroize for Secret32 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Secret32 {}

impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32(..)")
    }
}

/// HKDF-SHA256 with a 32-byte output.
pub(crate) fn hkdf32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Secret32 {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = Secret32([0u8; 32]);
    // 32 bytes is far below HKDF-SHA256's limit of 255 * 32.
    hk.expand(info, &mut out.0)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// XChaCha20-Poly1305 encryption under a 32-byte key.
pub(crate) fn aead_seal(
    key: &Secret32,
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(Key::cast_from_core(key.expose()));
    cipher
        .encrypt(XNonce::cast_from_core(nonce), Payload { msg, aad: ad })
        .map_err(|_| Error::TooLarge)
}

/// XChaCha20-Poly1305 decryption under a 32-byte key.
pub(crate) fn aead_open(
    key: &Secret32,
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(Key::cast_from_core(key.expose()));
    cipher
        .decrypt(XNonce::cast_from_core(nonce), Payload { msg: ct, aad: ad })
        .map_err(|_| Error::Open)
}

/// The record key of an epoch: `K_rec = HKDF-SHA256(K_e, "awm rec v1")`.
pub fn record_key(epoch_key: &EpochKey) -> Secret32 {
    hkdf32(None, epoch_key.expose_secret(), INFO_REC)
}

/// The fields the associated data binds (plan-v3-team §5.1). Every field is metadata the
/// server already holds; binding them stops the server from moving a record to another
/// organisation, stream, position, epoch or kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordAd {
    /// Organisation id (UUIDv4, fixed for the organisation's life).
    pub org: Uuid,
    /// Author's member id (the stream's member).
    pub member: Uuid,
    /// Author's device id (the stream's device).
    pub device: Uuid,
    /// Stream tag, which is the record kind: `rec`, `flag`, `stats`, `policy` or `roster`.
    pub tag: String,
    /// Index in the stream (contiguous from 0).
    pub idx: u64,
    /// Record id (`sync_id`, UUIDv4).
    pub record_id: Uuid,
    /// Key epoch the record is sealed under.
    pub epoch: u32,
}

impl RecordAd {
    /// The canonical AD bytes. Fixed-width fields and a length-prefixed tag make the
    /// encoding injective.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let tag = self.tag.as_bytes();
        if tag.is_empty()
            || tag.len() > MAX_TAG_LEN
            || !tag
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
        {
            return Err(Error::Malformed("stream tag"));
        }
        let mut ad = Vec::with_capacity(4 + 16 * 4 + 1 + tag.len() + 8 + 4);
        ad.extend_from_slice(AD_LABEL);
        ad.extend_from_slice(self.org.as_bytes());
        ad.extend_from_slice(self.member.as_bytes());
        ad.extend_from_slice(self.device.as_bytes());
        ad.push(tag.len() as u8);
        ad.extend_from_slice(tag);
        ad.extend_from_slice(&self.idx.to_be_bytes());
        ad.extend_from_slice(self.record_id.as_bytes());
        ad.extend_from_slice(&self.epoch.to_be_bytes());
        Ok(ad)
    }
}

/// The parsed fixed header of an envelope; what a server may check without any key
/// (plan-v3-team §4.3.6, 422 "envelope structure invalid").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeHeader {
    /// Always [`ENVELOPE_VERSION`] for v1.
    pub version: u8,
    /// The 24-byte nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Length of the padded plaintext (a multiple of [`PAD_BUCKET`]).
    pub padded_len: usize,
}

/// Checks an envelope's structure without a key: version byte, minimum length, size cap
/// and bucket alignment. A server answers 422 when this fails.
pub fn check_structure(envelope: &[u8]) -> Result<EnvelopeHeader, Error> {
    if envelope.len() > MAX_ENVELOPE {
        return Err(Error::TooLarge);
    }
    if envelope.len() < OVERHEAD + PAD_BUCKET {
        return Err(Error::Malformed("envelope length"));
    }
    if envelope[0] != ENVELOPE_VERSION {
        return Err(Error::Malformed("envelope version"));
    }
    let padded_len = envelope.len() - OVERHEAD;
    if !padded_len.is_multiple_of(PAD_BUCKET) {
        return Err(Error::Malformed("envelope padding"));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&envelope[1..HEADER_LEN]);
    Ok(EnvelopeHeader {
        version: envelope[0],
        nonce,
        padded_len,
    })
}

/// Envelope length for a plaintext of `len` bytes.
pub fn envelope_len(len: usize) -> usize {
    padded_len(len) + OVERHEAD
}

fn padded_len(len: usize) -> usize {
    (len + 1).div_ceil(PAD_BUCKET) * PAD_BUCKET
}

fn pad(plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(padded_len(plaintext.len()));
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(padded_len(plaintext.len()), 0);
    out
}

fn unpad(mut padded: Vec<u8>) -> Result<Vec<u8>, Error> {
    let Some(end) = padded.iter().rposition(|b| *b != 0) else {
        padded.as_mut_slice().zeroize();
        return Err(Error::Malformed("padding"));
    };
    if padded[end] != 0x80 {
        padded.as_mut_slice().zeroize();
        return Err(Error::Malformed("padding"));
    }
    padded[end..].zeroize();
    padded.truncate(end);
    Ok(padded)
}

/// Seals `plaintext` under the record key `k_rec` with raw associated data `ad`.
///
/// Low level: [`seal_record`] derives the key and builds the AD.
pub fn seal_with(
    rng: &mut dyn Rng,
    k_rec: &Secret32,
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(Error::TooLarge);
    }
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce)?;
    let mut padded = pad(plaintext);
    let ct = aead_seal(k_rec, &nonce, ad, &padded);
    padded.as_mut_slice().zeroize();
    let ct = ct?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.push(ENVELOPE_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens an envelope made by [`seal_with`] and removes the padding.
pub fn open_with_key(k_rec: &Secret32, ad: &[u8], envelope: &[u8]) -> Result<Vec<u8>, Error> {
    let header = check_structure(envelope)?;
    let padded = aead_open(k_rec, &header.nonce, ad, &envelope[HEADER_LEN..])?;
    unpad(padded)
}

/// Seals a record of stream `ad` under the epoch key `key` (`ad.epoch` must be its epoch).
pub fn seal_record(key: &EpochKey, ad: &RecordAd, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    seal_record_with(&mut OsRng, key, ad, plaintext)
}

/// [`seal_record`] with an explicit random source (tests and vectors).
pub fn seal_record_with(
    rng: &mut dyn Rng,
    key: &EpochKey,
    ad: &RecordAd,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if ad.epoch != key.epoch() {
        return Err(Error::Rejected("the AD epoch is not the key's epoch"));
    }
    let ad_bytes = ad.to_bytes()?;
    seal_with(rng, &record_key(key), &ad_bytes, plaintext)
}

/// Opens a record with the key ring's key for `ad.epoch`.
pub fn open_record(ring: &KeyRing, ad: &RecordAd, envelope: &[u8]) -> Result<Vec<u8>, Error> {
    let key = ring.get(ad.epoch).ok_or(Error::UnknownEpoch(ad.epoch))?;
    let ad_bytes = ad.to_bytes()?;
    open_with_key(&record_key(key), &ad_bytes, envelope)
}

/// Seals `plaintext` under a raw 32-byte record key with raw associated data.
///
/// Kept from the TM1 scaffold; new code calls [`seal_record`].
pub fn seal(key: &[u8; 32], ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    seal_with(&mut OsRng, &Secret32::from_bytes(*key), ad, plaintext)
}

/// Opens an envelope made by [`seal`]; `None` when authentication or parsing fails.
pub fn open(key: &[u8; 32], ad: &[u8], envelope: &[u8]) -> Option<Vec<u8>> {
    open_with_key(&Secret32::from_bytes(*key), ad, envelope).ok()
}
