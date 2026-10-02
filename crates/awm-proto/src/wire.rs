//! Serde wire types of sync protocol v1 (`docs/sync-v1.md`; plan-v3-team §4.3, TM2).
//!
//! Request bodies and query strings reject unknown fields (`deny_unknown_fields`): a v1 server
//! answers them with 400 `unknown_field` (`docs/sync-v1.md` §14). Responses, error bodies and
//! record plaintexts accept unknown fields, so an older client keeps working against a newer
//! server. Optional fields are omitted when absent, never sent as `null`. The JSON Schema
//! snapshots in `crates/awm-proto/schemas/v1/` and the fixtures in `tests/fixtures/v1/` are
//! checked against these types by `tests/wire_snapshots.rs`.

use std::cmp::Ordering;
use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The protocol version this crate speaks (`docs/sync-v1.md`, TM2).
pub const PROTOCOL_VERSION: u32 = 1;

/// The record plaintext `schema` this crate writes and reads (`docs/sync-v1.md` §15).
pub const PLAINTEXT_SCHEMA: u32 = 1;

/// The first byte of a record envelope v1 (plan-v3-team §5.1).
pub const ENVELOPE_VERSION: u8 = 1;

/// The request header that names the client (`docs/sync-v1.md` §2.2).
pub const CLIENT_HEADER: &str = "Awm-Client";

/// Limits of `docs/sync-v1.md` §12. Sizes are bytes; body sizes are measured on the encoded
/// JSON body as received, blob sizes on the decoded envelope.
pub mod limits {
    /// A decoded record envelope.
    pub const BLOB_BYTES: usize = 16_384;
    /// Version byte, 24-byte nonce and 16-byte tag around the padded plaintext.
    pub const ENVELOPE_OVERHEAD: usize = 41;
    /// The plaintext is padded to a multiple of this.
    pub const PAD_BUCKET: usize = 256;
    /// Records in one `POST /v1/records`.
    pub const BATCH_RECORDS: usize = 100;
    /// The encoded body of one `POST /v1/records` (1.5 MiB).
    pub const BATCH_BYTES: usize = 1_572_864;
    /// Any request body (2 MiB).
    pub const BODY_BYTES: usize = 2_097_152;
    /// Records in one `GET /v1/records` or `POST /v1/pull` response.
    pub const PULL_RECORDS: u32 = 500;
    /// Cursors in one `POST /v1/pull`.
    pub const PULL_CURSORS: usize = 1_000;
    /// A pull response is cut (with `more: true`) before it exceeds this (8 MiB).
    pub const PULL_RESPONSE_BYTES: usize = 8_388_608;
    /// Entries in one `GET /v1/deletions` response.
    pub const DELETIONS_PAGE: u32 = 5_000;
    /// Ids in one `POST /v1/delete`.
    pub const DELETE_IDS: usize = 1_000;
    /// Rows in one `GET /v1/audit` response.
    pub const AUDIT_PAGE: u32 = 1_000;
    /// Records pushed per member per UTC day.
    pub const RECORDS_PER_DAY: u32 = 5_000;
    /// Authenticated requests per token per minute, and the burst.
    pub const REQUESTS_PER_MINUTE: u32 = 60;
    pub const REQUEST_BURST: u32 = 120;
    /// Unauthenticated requests per IP address per minute, and joins per IP per hour.
    pub const ANONYMOUS_PER_MINUTE: u32 = 30;
    pub const JOINS_PER_HOUR: u32 = 10;
    /// `POST /v1/delete` with `all_mine` or `member`, per token per hour.
    pub const BULK_DELETES_PER_HOUR: u32 = 1;
    /// Invite lifetime in days: default and maximum.
    pub const INVITE_DAYS_DEFAULT: u32 = 7;
    pub const INVITE_DAYS_MAX: u32 = 30;
    /// The lowest `retention_days` and the delay before a decrease takes effect (seconds).
    pub const RETENTION_DAYS_MIN: u32 = 30;
    pub const RETENTION_DECREASE_DELAY_S: i64 = 7 * 86_400;
    /// The `Awm-Client` header value.
    pub const CLIENT_HEADER_BYTES: usize = 256;
}

// ---------------------------------------------------------------------------------------------
// Errors of this module

/// A value that does not have its wire form (bad id, token, handle, version or shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(String);

impl WireError {
    fn new(msg: impl Into<String>) -> WireError {
        WireError(msg.into())
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WireError {}

// ---------------------------------------------------------------------------------------------
// Scalars

/// A UUID in its canonical wire form: 36 characters, lower-case, hyphenated (`docs/sync-v1.md`
/// §3.1). Organisation, member, device, record and invite ids and `generation` use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Id(Uuid);

impl Id {
    /// A fresh random (version 4) id.
    pub fn new_v4() -> Id {
        Id(Uuid::new_v4())
    }

    /// Parses the canonical form only; upper case, braces, URNs and the simple form are refused.
    pub fn parse(s: &str) -> Result<Id, WireError> {
        let u = Uuid::try_parse(s).map_err(|_| WireError::new("not a uuid"))?;
        if u.hyphenated().to_string() != s {
            return Err(WireError::new("uuid not in canonical form"));
        }
        Ok(Id(u))
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// The 16 bytes, as associated data binds them (TM3 decides the encoding of the AD).
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl From<Uuid> for Id {
    fn from(u: Uuid) -> Id {
        Id(u)
    }
}

impl TryFrom<String> for Id {
    type Error = WireError;
    fn try_from(s: String) -> Result<Id, WireError> {
        Id::parse(&s)
    }
}

impl From<Id> for String {
    fn from(id: Id) -> String {
        id.to_string()
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}

/// A member handle: 1-24 characters of `[a-z0-9_-]` (plan-v3-team §3.5).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Handle(String);

impl Handle {
    pub fn parse(s: &str) -> Result<Handle, WireError> {
        let ok = (1..=24).contains(&s.len())
            && s.bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));
        if ok {
            Ok(Handle(s.to_string()))
        } else {
            Err(WireError::new(
                "handle must be 1-24 characters of [a-z0-9_-]",
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Handle {
    type Error = WireError;
    fn try_from(s: String) -> Result<Handle, WireError> {
        Handle::parse(&s)
    }
}

impl From<Handle> for String {
    fn from(h: Handle) -> String {
        h.0
    }
}

/// The tags v1 defines (`docs/sync-v1.md` §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KnownTag {
    Rec,
    Flag,
    Stats,
    Policy,
    Roster,
}

impl KnownTag {
    pub const ALL: [KnownTag; 5] = [
        KnownTag::Rec,
        KnownTag::Flag,
        KnownTag::Stats,
        KnownTag::Policy,
        KnownTag::Roster,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            KnownTag::Rec => "rec",
            KnownTag::Flag => "flag",
            KnownTag::Stats => "stats",
            KnownTag::Policy => "policy",
            KnownTag::Roster => "roster",
        }
    }
}

/// A stream tag: `[a-z][a-z0-9_]{0,15}`. Kept as a string so that a client can carry the
/// cursor of a tag added after it was built (§14.3); [`Tag::known`] names the v1 tags.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Tag(String);

impl Tag {
    pub fn parse(s: &str) -> Result<Tag, WireError> {
        let b = s.as_bytes();
        let ok = (1..=16).contains(&b.len())
            && b[0].is_ascii_lowercase()
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_');
        if ok {
            Ok(Tag(s.to_string()))
        } else {
            Err(WireError::new("tag must match [a-z][a-z0-9_]{0,15}"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The v1 tag this is, or `None` for a tag this build does not know.
    pub fn known(&self) -> Option<KnownTag> {
        KnownTag::ALL.into_iter().find(|k| k.as_str() == self.0)
    }
}

impl From<KnownTag> for Tag {
    fn from(k: KnownTag) -> Tag {
        Tag(k.as_str().to_string())
    }
}

impl TryFrom<String> for Tag {
    type Error = WireError;
    fn try_from(s: String) -> Result<Tag, WireError> {
        Tag::parse(&s)
    }
}

impl From<Tag> for String {
    fn from(t: Tag) -> String {
        t.0
    }
}

/// Bytes as unpadded base64url (RFC 4648 §5). Padding and non-zero trailing bits are refused,
/// so every value has exactly one encoding.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct B64(pub Vec<u8>);

impl fmt::Debug for B64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "B64({} bytes)", self.0.len())
    }
}

impl TryFrom<String> for B64 {
    type Error = WireError;
    fn try_from(s: String) -> Result<B64, WireError> {
        URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map(B64)
            .map_err(|_| WireError::new("not unpadded base64url"))
    }
}

impl From<B64> for String {
    fn from(b: B64) -> String {
        URL_SAFE_NO_PAD.encode(b.0)
    }
}

/// 32 bytes as unpadded base64url (43 characters): public keys, MACs and wrap authenticators.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Key32(pub [u8; 32]);

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key32({})", String::from(*self))
    }
}

impl TryFrom<String> for Key32 {
    type Error = WireError;
    fn try_from(s: String) -> Result<Key32, WireError> {
        let v = B64::try_from(s)?.0;
        let a: [u8; 32] = v
            .try_into()
            .map_err(|_| WireError::new("expected 32 bytes"))?;
        Ok(Key32(a))
    }
}

impl From<Key32> for String {
    fn from(k: Key32) -> String {
        URL_SAFE_NO_PAD.encode(k.0)
    }
}

// ---------------------------------------------------------------------------------------------
// Tokens (`docs/sync-v1.md` §3.2)

const SECRET_CHARS: usize = 43;
const ID_CHARS: usize = 36;

fn parse_secret(s: &str) -> Result<[u8; 32], WireError> {
    if s.len() != SECRET_CHARS {
        return Err(WireError::new("token secret must be 43 characters"));
    }
    Key32::try_from(s.to_string()).map(|k| k.0)
}

/// `{prefix}{org}_{secret}`: the organisation id is fixed-length, so the `_` and `-` that
/// base64url allows in the secret never make the split ambiguous.
fn parse_org_token(prefix: &str, s: &str) -> Result<Id, WireError> {
    let rest = s
        .strip_prefix(prefix)
        .ok_or_else(|| WireError::new(format!("token must start with {prefix}")))?;
    if rest.len() != ID_CHARS + 1 + SECRET_CHARS || rest.as_bytes()[ID_CHARS] != b'_' {
        return Err(WireError::new("token has the wrong length"));
    }
    let org = Id::parse(&rest[..ID_CHARS])?;
    parse_secret(&rest[ID_CHARS + 1..])?;
    Ok(org)
}

fn redacted(f: &mut fmt::Formatter<'_>, name: &str, s: &str, keep: usize) -> fmt::Result {
    write!(f, "{name}({}…)", &s[..keep])
}

macro_rules! org_token {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub fn new(org: Id, secret: &[u8; 32]) -> $name {
                $name(format!(
                    "{}{}_{}",
                    $prefix,
                    org,
                    URL_SAFE_NO_PAD.encode(secret)
                ))
            }

            pub fn parse(s: &str) -> Result<$name, WireError> {
                parse_org_token($prefix, s).map(|_| $name(s.to_string()))
            }

            /// The organisation id inside the token, read before any lookup (§3.2).
            pub fn org(&self) -> Id {
                Id::parse(&self.0[$prefix.len()..$prefix.len() + ID_CHARS])
                    .expect("validated at construction")
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                redacted(f, stringify!($name), &self.0, $prefix.len() + ID_CHARS + 1)
            }
        }

        impl TryFrom<String> for $name {
            type Error = WireError;
            fn try_from(s: String) -> Result<$name, WireError> {
                $name::parse(&s)
            }
        }

        impl From<$name> for String {
            fn from(t: $name) -> String {
                t.0
            }
        }
    };
}

org_token!(
    DeviceToken,
    "awm_t_",
    "A device token `awm_t_{org}_{secret}` (plan-v3-team §4.10). `Debug` hides the secret."
);
org_token!(
    InviteToken,
    "awm_i_",
    "An invite token `awm_i_{org}_{secret}`: the server's half of an invite (the invite secret \
     `S` never reaches the server). `Debug` hides the secret."
);

/// A bootstrap token `awm_b_{secret}` (`awm serve init`, or the cloud's device flow).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BootstrapToken(String);

impl BootstrapToken {
    pub const PREFIX: &'static str = "awm_b_";

    pub fn new(secret: &[u8; 32]) -> BootstrapToken {
        BootstrapToken(format!(
            "{}{}",
            Self::PREFIX,
            URL_SAFE_NO_PAD.encode(secret)
        ))
    }

    pub fn parse(s: &str) -> Result<BootstrapToken, WireError> {
        let rest = s
            .strip_prefix(Self::PREFIX)
            .ok_or_else(|| WireError::new("token must start with awm_b_"))?;
        parse_secret(rest)?;
        Ok(BootstrapToken(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BootstrapToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "BootstrapToken", &self.0, Self::PREFIX.len())
    }
}

impl TryFrom<String> for BootstrapToken {
    type Error = WireError;
    fn try_from(s: String) -> Result<BootstrapToken, WireError> {
        BootstrapToken::parse(&s)
    }
}

impl From<BootstrapToken> for String {
    fn from(t: BootstrapToken) -> String {
        t.0
    }
}

// ---------------------------------------------------------------------------------------------
// Versions and the `Awm-Client` header (`docs/sync-v1.md` §2.2)

/// `MAJOR.MINOR.PATCH` with an optional `-PRE` suffix, compared by semantic-versioning
/// precedence (a pre-release sorts below its release). Build metadata (`+...`) is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre: Option<String>,
}

impl Version {
    pub fn new(major: u32, minor: u32, patch: u32) -> Version {
        Version {
            major,
            minor,
            patch,
            pre: None,
        }
    }

    pub fn parse(s: &str) -> Result<Version, WireError> {
        let bad = || WireError::new(format!("not a version: {s:?}"));
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (s, None),
        };
        let mut parts = core.split('.');
        let mut num = || -> Result<u32, WireError> {
            let p = parts.next().ok_or_else(bad)?;
            let ok = (1..=5).contains(&p.len())
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p == "0" || !p.starts_with('0'));
            if !ok {
                return Err(bad());
            }
            p.parse().map_err(|_| bad())
        };
        let (major, minor, patch) = (num()?, num()?, num()?);
        if parts.next().is_some() {
            return Err(bad());
        }
        if let Some(p) = pre {
            let ok = (1..=32).contains(&p.len())
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
            if !ok {
                return Err(bad());
            }
        }
        Ok(Version {
            major,
            minor,
            patch,
            pre: pre.map(str::to_string),
        })
    }
}

fn cmp_pre(a: &str, b: &str) -> Ordering {
    let mut x = a.split('.');
    let mut y = b.split('.');
    loop {
        match (x.next(), y.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(p), Some(q)) => {
                let o = match (p.parse::<u64>(), q.parse::<u64>()) {
                    (Ok(m), Ok(n)) => m.cmp(&n),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => p.cmp(q),
                };
                if o != Ordering::Equal {
                    return o;
                }
            }
        }
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Version) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                // The byte order breaks ties such as `01` against `1`, so `Ord` agrees with `Eq`.
                (Some(a), Some(b)) => cmp_pre(a, b).then_with(|| a.cmp(b)),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Version) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(p) = &self.pre {
            write!(f, "-{p}")?;
        }
        Ok(())
    }
}

impl TryFrom<String> for Version {
    type Error = WireError;
    fn try_from(s: String) -> Result<Version, WireError> {
        Version::parse(&s)
    }
}

impl From<Version> for String {
    fn from(v: Version) -> String {
        v.to_string()
    }
}

/// The parsed `Awm-Client: awm/{version} proto/{n} redact/{n}` header (§2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHeader {
    pub awm: Version,
    /// The highest protocol version the client speaks; the request path selects the one used.
    pub proto: u32,
    /// The client's `redact::VERSION`.
    pub redact: u32,
}

impl ClientHeader {
    /// Parses the header value. The three tokens come first, in this order, separated by one
    /// space; further `name/value` tokens are extensions and are ignored.
    pub fn parse(s: &str) -> Result<ClientHeader, WireError> {
        if s.is_empty() || s.len() > limits::CLIENT_HEADER_BYTES {
            return Err(WireError::new(
                "Awm-Client is empty or longer than 256 bytes",
            ));
        }
        let mut tokens = s.split(' ');
        let mut field = |name: &str| -> Result<&str, WireError> {
            tokens
                .next()
                .and_then(|t| t.strip_prefix(name))
                .and_then(|t| t.strip_prefix('/'))
                .ok_or_else(|| WireError::new(format!("Awm-Client: expected {name}/...")))
        };
        let awm = Version::parse(field("awm")?)?;
        let proto = parse_small(field("proto")?)?;
        let redact = parse_small(field("redact")?)?;
        if proto == 0 {
            return Err(WireError::new("Awm-Client: proto must be at least 1"));
        }
        for t in tokens {
            let ok = matches!(t.split_once('/'), Some((n, v))
                if !n.is_empty()
                    && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && !v.is_empty()
                    && v.bytes().all(|b| b.is_ascii_graphic()));
            if !ok {
                return Err(WireError::new(format!("Awm-Client: bad token {t:?}")));
            }
        }
        Ok(ClientHeader { awm, proto, redact })
    }

    /// Whether a write that `min_client` gates is refused with 426 (§2.3).
    pub fn below(&self, min_client: &Version) -> bool {
        self.awm < *min_client
    }
}

fn parse_small(s: &str) -> Result<u32, WireError> {
    let ok = (1..=6).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    if !ok {
        return Err(WireError::new(format!("Awm-Client: bad number {s:?}")));
    }
    s.parse()
        .map_err(|_| WireError::new(format!("Awm-Client: bad number {s:?}")))
}

impl fmt::Display for ClientHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "awm/{} proto/{} redact/{}",
            self.awm, self.proto, self.redact
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Enums shared by several messages

/// A member's role. Responses accept a role this build does not know as `Unknown` (treated as
/// `member`); a server refuses `Unknown` in a request with 400 `invalid_value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Member,
    Admin,
    #[serde(other)]
    Unknown,
}

/// What an invite admits: a new member, or a further device of an existing member. Responses
/// (`status.pending`) accept a kind this build does not know as `Unknown`, which an approver
/// never approves; a server refuses `Unknown` in a request with 400 `invalid_value` (RVT1 m3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteKind {
    Member,
    Device,
    #[serde(other)]
    Unknown,
}

// ---------------------------------------------------------------------------------------------
// Errors on the wire (`docs/sync-v1.md` §13)

/// The `error` field of every error body. Codes this build does not know decode as `Unknown`;
/// the client then acts on the HTTP status alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Malformed,
    UnknownField,
    InvalidValue,
    BadClientHeader,
    Unauthenticated,
    PaymentRequired,
    Forbidden,
    NotApproved,
    NotFound,
    StreamConflict,
    IdConflict,
    StaleEpoch,
    EpochConflict,
    DeviceConflict,
    LastAdmin,
    InviteGone,
    Deleted,
    TooLarge,
    BadEnvelope,
    ClientTooOld,
    RateLimited,
    Maintenance,
    RestorePending,
    #[serde(other)]
    Unknown,
}

impl ErrorCode {
    /// The HTTP status that carries this code; `None` for `Unknown`.
    pub fn status(self) -> Option<u16> {
        use ErrorCode::*;
        Some(match self {
            Malformed | UnknownField | InvalidValue | BadClientHeader => 400,
            Unauthenticated => 401,
            PaymentRequired => 402,
            Forbidden | NotApproved => 403,
            NotFound => 404,
            StreamConflict | IdConflict | StaleEpoch | EpochConflict | DeviceConflict
            | LastAdmin => 409,
            InviteGone | Deleted => 410,
            TooLarge => 413,
            BadEnvelope => 422,
            ClientTooOld => 426,
            RateLimited => 429,
            Maintenance | RestorePending => 503,
            Unknown => return None,
        })
    }
}

/// Every non-2xx response body. Only `error` and `message` are always present; the other
/// fields belong to particular codes (§13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorCode,
    /// English text for logs and `awm doctor`; clients never parse it.
    pub message: String,
    /// `unknown_field`, `invalid_value`: the offending field (a JSON pointer into the body,
    /// or a query parameter name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Push errors: the 0-based position of the item in `records` that failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<u32>,
    /// `stream_conflict`: the stream's head on the server (-1 when empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<i64>,
    /// `stale_epoch`, `epoch_conflict`: the server's current epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_epoch: Option<u32>,
    /// `deleted`: every pushed record id of the batch that is in the deletion stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<Id>>,
    /// `too_large`: which limit (`blob`, `batch_records`, `batch_bytes`, `body`,
    /// `pull_cursors`, `delete_ids`) and its value; `rate_limited` names `records_per_day`
    /// when the daily push quota is spent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u64>,
    /// `client_too_old`: the organisation's `min_client`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_client: Option<Version>,
    /// 429 and 503: the same value as the `Retry-After` header, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u32>,
    /// `payment_required` (cloud): the entitlement state and the billing page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_url: Option<String>,
    /// `restore_pending`: the generation the server now runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<Id>,
}

impl ErrorBody {
    pub fn new(error: ErrorCode, message: impl Into<String>) -> ErrorBody {
        ErrorBody {
            error,
            message: message.into(),
            field: None,
            item: None,
            head: None,
            current_epoch: None,
            ids: None,
            limit: None,
            max: None,
            min_client: None,
            retry_after_s: None,
            state: None,
            billing_url: None,
            generation: None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// GET /v1/info

/// The limits a server enforces, as `GET /v1/info` publishes them (§12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub blob_bytes: u64,
    pub batch_records: u64,
    pub batch_bytes: u64,
    pub body_bytes: u64,
    pub pull_records: u64,
    pub pull_cursors: u64,
    pub pull_response_bytes: u64,
    pub deletions_page: u64,
    pub delete_ids: u64,
    pub records_per_day: u64,
    pub requests_per_minute: u64,
    pub request_burst: u64,
}

impl Limits {
    /// The v1 defaults of [`limits`].
    pub fn v1() -> Limits {
        use limits::*;
        Limits {
            blob_bytes: BLOB_BYTES as u64,
            batch_records: BATCH_RECORDS as u64,
            batch_bytes: BATCH_BYTES as u64,
            body_bytes: BODY_BYTES as u64,
            pull_records: PULL_RECORDS.into(),
            pull_cursors: PULL_CURSORS as u64,
            pull_response_bytes: PULL_RESPONSE_BYTES as u64,
            deletions_page: DELETIONS_PAGE.into(),
            delete_ids: DELETE_IDS as u64,
            records_per_day: RECORDS_PER_DAY.into(),
            requests_per_minute: REQUESTS_PER_MINUTE.into(),
            request_burst: REQUEST_BURST.into(),
        }
    }
}

/// `GET /v1/info` (anonymous; `Cache-Control: max-age=3600`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfoResponse {
    /// Protocol versions served, ascending (`[1]` for a v1 server).
    pub protocols: Vec<u32>,
    /// The server's own version (`awm serve` or `awm-cloud`).
    pub server: Version,
    pub cloud: bool,
    /// Changes on every restore (§11). Cached with the rest of this body: the re-seed decision
    /// uses the `generation` of `GET /v1/status`, which is never cached.
    pub generation: Id,
    /// The release floor of this server; the organisation's own `min_client` is in
    /// `GET /v1/status` and `GET /v1/org/settings` (cloud: one server, many organisations).
    pub min_client: Version,
    pub limits: Limits,
    /// Optional request fields and endpoints added within v1 (§14.2); empty in v1.0.
    pub features: Vec<String>,
}

// ---------------------------------------------------------------------------------------------
// POST /v1/bootstrap, POST /v1/join

/// `POST /v1/bootstrap`: the first admin registers the organisation (`awm team create`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRequest {
    pub bootstrap_token: BootstrapToken,
    /// Created by the client together with `K_0`; never changes (plan-v3-team §5.1).
    pub org_id: Id,
    pub handle: Handle,
    pub device_id: Id,
    pub device_pubkey: Key32,
}

/// The response to `POST /v1/bootstrap`: an approved admin device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapResponse {
    pub org_id: Id,
    pub member_id: Id,
    pub device_id: Id,
    /// Shown once; the server keeps only its SHA-256.
    pub device_token: DeviceToken,
    pub role: Role,
}

/// `POST /v1/join` (anonymous; the invite token authenticates).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub invite_id: Id,
    pub invite_token: InviteToken,
    /// Must equal the invite's handle.
    pub handle: Handle,
    pub device_id: Id,
    pub device_pubkey: Key32,
    /// `HMAC-SHA256(HKDF(S, "awm join v1"), "awm join v1" ‖ org ‖ lp(invite id) ‖ lp(handle) ‖
    /// device id ‖ public key)`, the invite id as its canonical 36-character text
    /// (`docs/sync-v1-crypto.md` §4.2, `keys::Invite::join_mac`).
    pub join_mac: Key32,
}

/// The response to `POST /v1/join`: a device that waits for approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinResponse {
    pub org_id: Id,
    pub member_id: Id,
    pub device_id: Id,
    pub device_token: DeviceToken,
    pub pending: bool,
}

// ---------------------------------------------------------------------------------------------
// GET /v1/status

/// One stream's head. Streams appear once they hold index 0, so `head` ≥ 0 here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StreamHead {
    pub member: Id,
    pub device: Id,
    pub tag: Tag,
    pub head: i64,
}

/// The deletion stream: `head` is its highest index (-1 when empty), `oldest` the lowest kept
/// index (`head + 1` when no entry is kept).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionHeads {
    pub head: i64,
    pub oldest: i64,
}

/// A decrease of `retention_days` waiting for its 7 days (§10.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRetention {
    pub retention_days: u32,
    pub effective_at: i64,
}

/// `GET /v1/org/settings`, also inside `GET /v1/status`: the only settings the server reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgSettings {
    pub retention_days: u32,
    pub min_client: Version,
    pub max_members: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_retention: Option<PendingRetention>,
}

/// A device that joined and waits for approval, as an approver sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDevice {
    pub device_id: Id,
    pub member_id: Id,
    pub handle: Handle,
    pub kind: InviteKind,
    pub invite_id: Id,
    pub device_pubkey: Key32,
    pub join_mac: Key32,
    /// Hour of the join (Unix seconds, rounded down to the hour).
    pub joined_at: i64,
}

/// `GET /v1/status`: the cursor source of every sync run (§8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub generation: Id,
    pub org_id: Id,
    pub member_id: Id,
    pub device_id: Id,
    pub role: Role,
    /// The calling device's own approval state.
    pub approved: bool,
    pub current_epoch: u32,
    pub rotation_needed: bool,
    /// Non-admin pushes get 503 `restore_pending` while this is true (§11).
    pub restore_pending: bool,
    pub settings: OrgSettings,
    pub streams: Vec<StreamHead>,
    pub deletions: DeletionHeads,
    /// Admins: every pending device; members: their own pending devices.
    pub pending: Vec<PendingDevice>,
}

// ---------------------------------------------------------------------------------------------
// POST /v1/records

/// A record to append to one of the caller's own streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRecord {
    pub tag: Tag,
    pub idx: u64,
    pub id: Id,
    pub epoch: u32,
    pub blob: B64,
}

/// A deletion marker at an index whose record the writer deleted (re-seed, §11; or a record
/// deleted before it was ever stored, §10.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushDeleted {
    pub tag: Tag,
    pub idx: u64,
    pub id: Id,
}

/// One item of `POST /v1/records`: `{tag, idx, id, epoch, blob}` or `{tag, idx, id, deleted: true}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PushItemWire", into = "PushItemWire")]
pub enum PushItem {
    Record(PushRecord),
    Deleted(PushDeleted),
}

impl PushItem {
    pub fn tag(&self) -> &Tag {
        match self {
            PushItem::Record(r) => &r.tag,
            PushItem::Deleted(d) => &d.tag,
        }
    }

    pub fn idx(&self) -> u64 {
        match self {
            PushItem::Record(r) => r.idx,
            PushItem::Deleted(d) => d.idx,
        }
    }

    pub fn id(&self) -> Id {
        match self {
            PushItem::Record(r) => r.id,
            PushItem::Deleted(d) => d.id,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PushItemWire {
    tag: Tag,
    idx: u64,
    id: Id,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epoch: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blob: Option<B64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deleted: Option<bool>,
}

impl TryFrom<PushItemWire> for PushItem {
    type Error = WireError;
    fn try_from(w: PushItemWire) -> Result<PushItem, WireError> {
        match (w.epoch, w.blob, w.deleted) {
            (Some(epoch), Some(blob), None) => Ok(PushItem::Record(PushRecord {
                tag: w.tag,
                idx: w.idx,
                id: w.id,
                epoch,
                blob,
            })),
            (None, None, Some(true)) => Ok(PushItem::Deleted(PushDeleted {
                tag: w.tag,
                idx: w.idx,
                id: w.id,
            })),
            _ => Err(WireError::new(
                "a record item has epoch and blob; a marker has only deleted: true",
            )),
        }
    }
}

impl From<PushItem> for PushItemWire {
    fn from(p: PushItem) -> PushItemWire {
        match p {
            PushItem::Record(r) => PushItemWire {
                tag: r.tag,
                idx: r.idx,
                id: r.id,
                epoch: Some(r.epoch),
                blob: Some(r.blob),
                deleted: None,
            },
            PushItem::Deleted(d) => PushItemWire {
                tag: d.tag,
                idx: d.idx,
                id: d.id,
                epoch: None,
                blob: None,
                deleted: Some(true),
            },
        }
    }
}

/// `POST /v1/records`: at most 100 items and 1.5 MiB encoded, applied atomically (§9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRequest {
    pub records: Vec<PushItem>,
}

/// A head of one of the caller's own streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnHead {
    pub tag: Tag,
    pub head: i64,
}

/// The response to `POST /v1/records`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResponse {
    /// The new head of every stream the batch touched.
    pub heads: Vec<OwnHead>,
    /// Items stored by this request.
    pub accepted: u32,
    /// Items already stored at their stream and index with the same id (no change, §9.2).
    pub replayed: u32,
}

// ---------------------------------------------------------------------------------------------
// GET /v1/records, POST /v1/pull

/// A record as a reader receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulledRecord {
    pub idx: u64,
    pub id: Id,
    pub epoch: u32,
    pub blob: B64,
    /// The hour the server received it (Unix seconds); server-supplied and not bound (§5.2).
    pub received_at: i64,
}

/// A deletion marker as a reader receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulledDeleted {
    pub idx: u64,
    pub id: Id,
}

/// One index of a stream: `{idx, id, epoch, blob, received_at}` or `{idx, id, deleted: true}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PulledItemWire", into = "PulledItemWire")]
pub enum PulledItem {
    Record(PulledRecord),
    Deleted(PulledDeleted),
}

impl PulledItem {
    pub fn idx(&self) -> u64 {
        match self {
            PulledItem::Record(r) => r.idx,
            PulledItem::Deleted(d) => d.idx,
        }
    }

    pub fn id(&self) -> Id {
        match self {
            PulledItem::Record(r) => r.id,
            PulledItem::Deleted(d) => d.id,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct PulledItemWire {
    idx: u64,
    id: Id,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epoch: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blob: Option<B64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    received_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deleted: Option<bool>,
}

impl TryFrom<PulledItemWire> for PulledItem {
    type Error = WireError;
    fn try_from(w: PulledItemWire) -> Result<PulledItem, WireError> {
        match (w.epoch, w.blob, w.received_at, w.deleted) {
            (Some(epoch), Some(blob), Some(received_at), None) => {
                Ok(PulledItem::Record(PulledRecord {
                    idx: w.idx,
                    id: w.id,
                    epoch,
                    blob,
                    received_at,
                }))
            }
            (None, None, None, Some(true)) => Ok(PulledItem::Deleted(PulledDeleted {
                idx: w.idx,
                id: w.id,
            })),
            _ => Err(WireError::new(
                "a record has epoch, blob and received_at; a marker has only deleted: true",
            )),
        }
    }
}

impl From<PulledItem> for PulledItemWire {
    fn from(p: PulledItem) -> PulledItemWire {
        match p {
            PulledItem::Record(r) => PulledItemWire {
                idx: r.idx,
                id: r.id,
                epoch: Some(r.epoch),
                blob: Some(r.blob),
                received_at: Some(r.received_at),
                deleted: None,
            },
            PulledItem::Deleted(d) => PulledItemWire {
                idx: d.idx,
                id: d.id,
                epoch: None,
                blob: None,
                received_at: None,
                deleted: Some(true),
            },
        }
    }
}

/// The query string of `GET /v1/records`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordsQuery {
    pub member: Id,
    pub device: Id,
    pub tag: Tag,
    pub from: u64,
    /// At most 500; the server's page size when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Records of one stream from a cursor, ascending by `idx`, contiguous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamRecords {
    pub member: Id,
    pub device: Id,
    pub tag: Tag,
    /// The stream's head when the server read it (-1 when the stream does not exist).
    pub head: i64,
    pub records: Vec<PulledItem>,
}

/// One stream to read from in `POST /v1/pull`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub member: Id,
    pub device: Id,
    pub tag: Tag,
    /// The first index wanted: the reader's head + 1.
    pub from: u64,
}

/// `POST /v1/pull`: up to 1,000 cursors, at most `limit` (≤ 500) records in total (§8.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequest {
    pub cursors: Vec<Cursor>,
    pub limit: u32,
}

/// The response to `POST /v1/pull`: one entry per cursor served, in request order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullResponse {
    pub streams: Vec<StreamRecords>,
    /// True when a served stream has records beyond those returned, or cursors were not served.
    pub more: bool,
}

// ---------------------------------------------------------------------------------------------
// GET /v1/deletions, POST /v1/delete

/// The query string of `GET /v1/deletions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionsQuery {
    pub from: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One entry of the server-written deletion stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionEntry {
    pub idx: u64,
    pub record_id: Id,
}

/// The response to `GET /v1/deletions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionsResponse {
    pub head: i64,
    pub oldest: i64,
    pub entries: Vec<DeletionEntry>,
}

/// `POST /v1/delete`: exactly one of `{ids}`, `{all_mine: true}` or, admins only, `{member}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DeleteRequestWire", into = "DeleteRequestWire")]
pub enum DeleteRequest {
    /// Record ids: at least 1, at most 1,000 (more get 413 `delete_ids`).
    Ids(Vec<Id>),
    /// Every record of the caller's member, on every device.
    AllMine,
    /// Every record of that member (admin).
    Member(Id),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteRequestWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ids: Option<Vec<Id>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    all_mine: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    member: Option<Id>,
}

impl TryFrom<DeleteRequestWire> for DeleteRequest {
    type Error = WireError;
    fn try_from(w: DeleteRequestWire) -> Result<DeleteRequest, WireError> {
        match (w.ids, w.all_mine, w.member) {
            // More than DELETE_IDS parses; the server answers it with 413 (§12).
            (Some(ids), None, None) if !ids.is_empty() => Ok(DeleteRequest::Ids(ids)),
            (None, Some(true), None) => Ok(DeleteRequest::AllMine),
            (None, None, Some(m)) => Ok(DeleteRequest::Member(m)),
            _ => Err(WireError::new(
                "exactly one of ids (not empty), all_mine: true or member",
            )),
        }
    }
}

impl From<DeleteRequest> for DeleteRequestWire {
    fn from(d: DeleteRequest) -> DeleteRequestWire {
        let mut w = DeleteRequestWire {
            ids: None,
            all_mine: None,
            member: None,
        };
        match d {
            DeleteRequest::Ids(ids) => w.ids = Some(ids),
            DeleteRequest::AllMine => w.all_mine = Some(true),
            DeleteRequest::Member(m) => w.member = Some(m),
        }
        w
    }
}

/// The response to `POST /v1/delete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteResponse {
    /// Ids this request appended to the deletion stream.
    pub deleted: u64,
    /// Ids that were already in it (a repeated request returns them here).
    pub already: u64,
}

// ---------------------------------------------------------------------------------------------
// Members, invites, approvals

/// A device as `GET /v1/members` lists it. Unverified until a `roster` record names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: Id,
    pub device_pubkey: Key32,
    pub approved: bool,
    pub revoked: bool,
}

/// A member as `GET /v1/members` lists it (no emails).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberInfo {
    pub member_id: Id,
    pub handle: Handle,
    pub role: Role,
    pub active: bool,
    pub devices: Vec<DeviceInfo>,
}

/// The response to `GET /v1/members`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembersResponse {
    pub members: Vec<MemberInfo>,
}

/// `POST /v1/invites`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRequest {
    pub kind: InviteKind,
    /// `member`: the new member's handle; `device`: the existing member's handle.
    pub handle: Handle,
    /// `member` invites only (default `member`); refused on `device` invites.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    /// 1-30, default 7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_days: Option<u32>,
}

/// The response to `POST /v1/invites`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteResponse {
    pub invite_id: Id,
    pub invite_token: InviteToken,
    pub expires_at: i64,
}

/// One wrapped epoch key for the device being approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochWrap {
    pub epoch: u32,
    pub wrap: B64,
    /// The join-mode wrap authenticator under `HKDF(S, "awm wrap-auth v1")` (§5.3,
    /// `docs/sync-v1-crypto.md` §5).
    pub auth: Key32,
}

/// `POST /v1/devices/{id}/approve`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    pub wraps: Vec<EpochWrap>,
}

/// `POST /v1/members/{id}/remove`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_records: Option<bool>,
}

/// `POST /v1/members/{id}/role`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleRequest {
    pub role: Role,
}

// ---------------------------------------------------------------------------------------------
// Keys and tokens

/// A wrap stored for the calling device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWrap {
    pub epoch: u32,
    pub wrap: B64,
    pub auth: Key32,
    /// The device that made the wrap.
    pub created_by: Id,
}

/// The response to `GET /v1/keys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysResponse {
    pub current_epoch: u32,
    pub rotation_needed: bool,
    pub wraps: Vec<StoredWrap>,
}

/// One device's wrap of the new epoch key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceWrap {
    pub device_id: Id,
    pub wrap: B64,
    /// `MAC_{K_e}` over the wrap and its bindings (TM3, §5.3).
    pub auth: Key32,
}

/// `POST /v1/keys/rotate`: `epoch` must be the current epoch + 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateRequest {
    pub epoch: u32,
    pub wraps: Vec<DeviceWrap>,
}

/// The response to `POST /v1/token/rotate`: the new token (once); the old one is revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRotateResponse {
    pub device_token: DeviceToken,
}

// ---------------------------------------------------------------------------------------------
// Audit, settings, restore

/// The query string of `GET /v1/audit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    pub from: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One audit row (never record content).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRow {
    pub idx: u64,
    pub at: i64,
    /// The acting member; absent for the server itself (retention, restore).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Id>,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The response to `GET /v1/audit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditResponse {
    pub head: i64,
    pub rows: Vec<AuditRow>,
}

/// `PUT /v1/org/settings` (admin): only the fields given change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsUpdate {
    /// ≥ 30; a decrease takes effect 7 days later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,
    /// Raise only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_client: Option<Version>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_members: Option<u32>,
    /// Cancels a pending retention decrease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_pending_retention: Option<bool>,
}

/// `POST /v1/restore/complete` (admin): ends `restore_pending` for this generation (§11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreCompleteRequest {
    pub generation: Id,
}

// ---------------------------------------------------------------------------------------------
// Record plaintexts (`docs/sync-v1.md` §15): what the envelope encrypts, after padding is removed

/// A decoded plaintext: one this build reads, or a higher `schema` it skips (the index still
/// counts as applied, so the cursor moves on).
#[derive(Debug, Clone, PartialEq)]
pub enum Decoded<T> {
    Known(T),
    Newer { schema: u32 },
}

/// Decodes a plaintext of any tag: reads `schema` first, returns [`Decoded::Newer`] above
/// [`PLAINTEXT_SCHEMA`] without looking at the other fields, and parses `T` otherwise.
pub fn decode_plaintext<T: DeserializeOwned>(bytes: &[u8]) -> Result<Decoded<T>, WireError> {
    #[derive(Deserialize)]
    struct Probe {
        schema: u32,
    }
    let probe: Probe = serde_json::from_slice(bytes)
        .map_err(|e| WireError::new(format!("plaintext without schema: {e}")))?;
    if probe.schema == 0 {
        return Err(WireError::new("plaintext schema 0"));
    }
    if probe.schema > PLAINTEXT_SCHEMA {
        return Ok(Decoded::Newer {
            schema: probe.schema,
        });
    }
    serde_json::from_slice(bytes)
        .map(Decoded::Known)
        .map_err(|e| WireError::new(format!("plaintext schema {}: {e}", probe.schema)))
}

/// `event.tool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tool {
    WebSearch,
    WebFetch,
}

/// The shared statuses (`placeholder` is never shared).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecStatus {
    Ok,
    DeadEnd,
    Refusal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Agent {
    Claude,
    Codex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Hook,
    Import,
}

/// `full`, or `link` (URL, titles, status and hour only) for link-only hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Share {
    Full,
    Link,
}

/// One search result row of a shared record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultItem {
    pub rank: u32,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// Tag `rec`: a shared research record (plan-v3-team §3.2). Caps are applied by the writer
/// (TM5) and re-checked by readers (§4.5); the schema snapshot states them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecPlaintext {
    pub schema: u32,
    pub tool: Tool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_code: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<i64>,
    pub status: RecStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub results: Vec<ResultItem>,
    pub agent: Agent,
    pub source: Source,
    /// Unix seconds, rounded down to the hour.
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_key: Option<String>,
    pub share: Share,
}

/// Why a member flagged a teammate's record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagReason {
    /// The pull-side check quarantined it (§4.5).
    Quarantine,
    /// `awm team flag` or review label `h`.
    User,
}

/// Tag `flag`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlagPlaintext {
    pub schema: u32,
    pub record_id: Id,
    pub reason: FlagReason,
    /// At most 200 characters, redacted by the writer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub created_at: i64,
}

/// Tag `stats`: one member's daily totals (opt-in, plan-v3-team §3.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsPlaintext {
    pub schema: u32,
    /// `YYYY-MM-DD`, UTC.
    pub day: String,
    pub shown: u64,
    pub avoided: u64,
    pub est_minutes: u64,
    pub est_tokens: u64,
}

/// Tag `policy` (admins): the encrypted team policy. `retention_days`, `min_client` and
/// `max_members` are server settings and never appear here (RV8-team M26).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPlaintext {
    pub schema: u32,
    /// Only increases; the highest version a reader holds wins.
    pub version: u64,
    pub deny_hosts: Vec<String>,
    pub link_hosts: Vec<String>,
    pub terms: Vec<String>,
    /// Extra query-parameter names for the pre-push URL check (§4.5).
    pub credential_params: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_chars: Option<u32>,
}

/// Tag `roster` (plan-v3-team §5.1, RV8-team X1): `{schema, entry}`, where `entry` is the
/// [`crate::keys::RosterEntry`] that `keys::seal_roster` seals and `keys::Roster::verify`
/// checks (`docs/sync-v1-crypto.md` §7). One type serves the wire and the key flows (RVT1 M1).
/// TM12 may add optional fields only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterPlaintext {
    pub schema: u32,
    pub entry: crate::keys::RosterEntry,
}

// ---------------------------------------------------------------------------------------------
// Envelope structure (the server's only look at a blob)

/// The server's structural check of a pushed blob (§9.1 step 3): 413 above 16 KiB, 422 unless
/// the first byte is [`ENVELOPE_VERSION`] and the length is `41 + 256·k` with `k ≥ 1`. It is
/// [`crate::crypto::check_structure`], so the server and the envelope code share one accept
/// set (RVT1 m9).
pub fn check_envelope(blob: &[u8]) -> Result<(), ErrorCode> {
    match crate::crypto::check_structure(blob) {
        Ok(_) => Ok(()),
        Err(crate::crypto::Error::TooLarge) => Err(ErrorCode::TooLarge),
        Err(_) => Err(ErrorCode::BadEnvelope),
    }
}
