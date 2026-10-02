//! Format v1 of the backup objects and their JSON manifests (plan-v3-team §6.2, TM27).
//!
//! Layout under the target prefix:
//!
//! ```text
//! full/{generation}/{seq}.db     a full snapshot (`VACUUM INTO`), seq = its `backup_log` head;
//!                                 or a canonical export (`PgStore`), seq = its time
//! full/{generation}/{seq}.json   its manifest
//! incr/{generation}/{seq}.db     a change set, `backup_log` range (after, to], seq = to
//! incr/{generation}/{seq}.json   its manifest
//! ```
//!
//! A manifest is one compact JSON object (fields in the order of [`Manifest`]): the format
//! (1), the kind, the generation, the sequence number, the cursor range, the time, the server
//! version, why it was written, the writing process, the SHA-256 and size of the data object,
//! row counts per table of the data object, and `check`, the SHA-256 of the same JSON with
//! `check` empty. A reader accepts a manifest only when it parses with no unknown field,
//! re-serialises to exactly the stored bytes and `check` matches, so a flipped byte anywhere in
//! it is refused; the data object is accepted only when its SHA-256 and size match. A manifest
//! holds no row value: counts, hashes, sequence numbers and times only.

use std::collections::BTreeMap;

use awm_proto::wire::Id;
use serde::{Deserialize, Serialize};

use crate::store::checksum;

/// The format version written into every manifest.
pub const FORMAT: u32 = 1;

/// What a data object is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A full snapshot of a `SqliteStore` (`backup_log` and every `meta` key included).
    Full,
    /// A change set (`Store::export_changes`).
    Incr,
    /// A canonical export (`Store::export_canonical`, `PgStore`'s daily backup).
    Export,
}

impl Kind {
    /// The top-level directory of the kind.
    pub fn dir(self) -> &'static str {
        match self {
            Kind::Full | Kind::Export => "full",
            Kind::Incr => "incr",
        }
    }
}

/// Why an object was written (§6.2 cadence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    /// The full snapshot at the start of `awm serve`.
    Start,
    /// The daily full snapshot or export.
    Daily,
    /// A full snapshot after a migration (TM15's hook).
    Migration,
    /// The first full snapshot after a restore.
    Restore,
    /// A full snapshot because the store's `generation` changed under the running server.
    Generation,
    /// `awm serve backup` (on demand; it never moves the server's cursor).
    OnDemand,
    /// An incremental change set.
    Incremental,
}

/// A manifest (format v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    pub kind: Kind,
    pub generation: Id,
    pub seq: i64,
    /// Change sets: the cursor the set starts after; `None` for full snapshots and exports.
    pub after: Option<i64>,
    /// The `backup_log` head the object reaches; `None` for exports (`PgStore` has no log).
    pub to: Option<i64>,
    /// Unix seconds when the object was written.
    pub time: i64,
    pub server_version: String,
    pub origin: Origin,
    /// The writing process (a random id per backup runner or command).
    pub writer: Id,
    /// SHA-256 (lower-case hex) and size of the data object.
    pub sha256: String,
    pub size: u64,
    /// Rows per table in the data object (the canonical tables and `backup_log`).
    pub rows: BTreeMap<String, u64>,
    /// SHA-256 of this manifest serialised with `check` empty.
    pub check: String,
}

/// Why a manifest was refused (the caller names the object).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError(pub &'static str);

impl Manifest {
    /// A manifest for `data`, with its hash, size and `check` filled in.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: Kind,
        generation: Id,
        seq: i64,
        after: Option<i64>,
        to: Option<i64>,
        time: i64,
        origin: Origin,
        writer: Id,
        data: &[u8],
        rows: BTreeMap<String, u64>,
    ) -> Manifest {
        let mut m = Manifest {
            format: FORMAT,
            kind,
            generation,
            seq,
            after,
            to,
            time,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            origin,
            writer,
            sha256: checksum(data),
            size: data.len() as u64,
            rows,
            check: String::new(),
        };
        m.check = m.compute_check();
        m
    }

    fn compute_check(&self) -> String {
        let mut body = self.clone();
        body.check = String::new();
        checksum(&serde_json::to_vec(&body).unwrap_or_default())
    }

    /// The stored form.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Parses and checks a stored manifest: no unknown field, the exact serialised bytes, the
    /// format, `check`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Manifest, ManifestError> {
        let m: Manifest =
            serde_json::from_slice(bytes).map_err(|_| ManifestError("not a v1 manifest"))?;
        if m.to_bytes() != bytes {
            return Err(ManifestError(
                "bytes differ from the manifest's own serialisation",
            ));
        }
        if m.format != FORMAT {
            return Err(ManifestError("unknown format"));
        }
        if m.check != m.compute_check() {
            return Err(ManifestError("check mismatch"));
        }
        Ok(m)
    }

    /// Whether `data` is the object this manifest describes.
    pub fn matches(&self, data: &[u8]) -> bool {
        data.len() as u64 == self.size && checksum(data) == self.sha256
    }

    /// The data object's key.
    pub fn data_key(&self) -> String {
        data_key(self.kind, self.generation, self.seq)
    }

    /// This manifest's key.
    pub fn key(&self) -> String {
        manifest_key(self.kind, self.generation, self.seq)
    }
}

/// `{full|incr}/{generation}/{seq}.db`.
pub fn data_key(kind: Kind, generation: Id, seq: i64) -> String {
    format!("{}/{generation}/{seq}.db", kind.dir())
}

/// `{full|incr}/{generation}/{seq}.json`.
pub fn manifest_key(kind: Kind, generation: Id, seq: i64) -> String {
    format!("{}/{generation}/{seq}.json", kind.dir())
}

/// Splits an object name `{seq}.db` or `{seq}.json` into the number and whether it is a
/// manifest; `None` for any other name (never touched by the backup).
pub fn parse_name(name: &str) -> Option<(i64, bool)> {
    let (num, manifest) = if let Some(n) = name.strip_suffix(".json") {
        (n, true)
    } else {
        (name.strip_suffix(".db")?, false)
    };
    if num.is_empty() || num.len() > 19 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if num.len() > 1 && num.starts_with('0') {
        return None;
    }
    Some((num.parse().ok()?, manifest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        let mut rows = BTreeMap::new();
        rows.insert("record".to_string(), 3);
        Manifest::new(
            Kind::Incr,
            Id::new_v4(),
            12,
            Some(9),
            Some(12),
            1_790_000_000,
            Origin::Incremental,
            Id::new_v4(),
            b"data",
            rows,
        )
    }

    #[test]
    fn a_manifest_round_trips_and_every_flipped_byte_is_refused() {
        let m = sample();
        let bytes = m.to_bytes();
        assert_eq!(Manifest::from_bytes(&bytes).unwrap(), m);
        assert!(m.matches(b"data") && !m.matches(b"datb"));
        for i in 0..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 0x01;
            assert!(Manifest::from_bytes(&b).is_err(), "byte {i} flipped");
        }
    }

    #[test]
    fn names_parse_strictly() {
        assert_eq!(parse_name("12.db"), Some((12, false)));
        assert_eq!(parse_name("0.json"), Some((0, true)));
        for bad in ["012.db", "x.db", ".db", "12.txt", "-1.db", "12.db.tmp"] {
            assert_eq!(parse_name(bad), None, "{bad}");
        }
    }
}
