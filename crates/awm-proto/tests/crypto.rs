//! Envelope v1 (plan-v3-team §5.1, TM3): known-answer vectors, AD binding, padding, the
//! structure check a server runs without keys, and what the server can learn (P1).
//!
//! Set `AWM_WRITE_VECTORS=1` to rewrite `tests/vectors/v1/envelope.json` after an intended
//! format change (there should be none within v1: written ciphertext must stay readable).

use std::path::PathBuf;

use awm_proto::crypto::{
    check_structure, envelope_len, open_record, record_key, seal_record, seal_record_with, Error,
    RecordAd, Rng, ENVELOPE_VERSION, MAX_ENVELOPE, MAX_PLAINTEXT, OVERHEAD, PAD_BUCKET,
};
use awm_proto::keys::{EpochKey, KeyRing};
use serde_json::{json, Value};
use uuid::Uuid;

/// Hands out exactly the bytes it was given; a test-only stand-in for the system source.
struct FixedRng(Vec<u8>);

impl Rng for FixedRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if self.0.len() < out.len() {
            return Err(Error::Rng);
        }
        let rest = self.0.split_off(out.len());
        out.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/v1")
        .join(name)
}

/// Compares `computed` with the stored vector, or writes it when `AWM_WRITE_VECTORS=1`.
fn check_vector(name: &str, computed: &Value) -> Value {
    let path = vector_path(name);
    if std::env::var("AWM_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(computed).unwrap() + "\n",
        )
        .unwrap();
    }
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(&stored, computed, "vector {name} changed");
    stored
}

fn ring_with(org: Uuid, epochs: &[[u8; 32]]) -> KeyRing {
    let keys = epochs
        .iter()
        .enumerate()
        .map(|(e, k)| EpochKey::from_bytes(e as u32, *k))
        .collect();
    KeyRing::from_keys(org, keys).unwrap()
}

fn sample_ad() -> RecordAd {
    RecordAd {
        org: Uuid::parse_str("6f1c2a9e-3b4d-4e5f-8a7b-0c1d2e3f4a5b").unwrap(),
        member: Uuid::parse_str("1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d").unwrap(),
        device: Uuid::parse_str("9d8c7b6a-5f4e-4d3c-8b2a-1f0e9d8c7b6a").unwrap(),
        tag: "rec".to_string(),
        idx: 41,
        record_id: Uuid::parse_str("0b1c2d3e-4f5a-4b6c-ad7e-8f9a0b1c2d3e").unwrap(),
        epoch: 1,
    }
}

#[test]
fn vectors_v1_envelope_known_answer() {
    let k0 = [0x11u8; 32];
    let k1: [u8; 32] = std::array::from_fn(|i| i as u8);
    let nonce: [u8; 24] = std::array::from_fn(|i| 0x40 + i as u8);
    let ad = sample_ad();
    let ring = ring_with(ad.org, &[k0, k1]);
    let plaintext = br#"{"schema":1,"tool":"WebSearch","query":"rust hkdf example"}"#;
    let envelope = seal_record_with(
        &mut FixedRng(nonce.to_vec()),
        ring.get(1).unwrap(),
        &ad,
        plaintext,
    )
    .unwrap();
    let computed = json!({
        "construction": "0x01 || nonce || XChaCha20-Poly1305(HKDF-SHA256(K_e, 'awm rec v1'), nonce, pad256(plaintext), AD)",
        "epoch_key": hex(&k1),
        "k_rec": hex(record_key(ring.get(1).unwrap()).expose()),
        "ad": {
            "org": ad.org, "member": ad.member, "device": ad.device, "tag": ad.tag,
            "idx": ad.idx, "record_id": ad.record_id, "epoch": ad.epoch,
        },
        "ad_bytes": hex(&ad.to_bytes().unwrap()),
        "nonce": hex(&nonce),
        "plaintext": String::from_utf8(plaintext.to_vec()).unwrap(),
        "envelope": hex(&envelope),
    });
    let stored = check_vector("envelope.json", &computed);
    // The stored bytes open (v1 ciphertext stays readable).
    let stored_env = unhex(stored["envelope"].as_str().unwrap());
    assert_eq!(open_record(&ring, &ad, &stored_env).unwrap(), plaintext);
    assert_eq!(stored_env.len(), OVERHEAD + PAD_BUCKET);
    assert_eq!(stored_env[0], ENVELOPE_VERSION);
}

#[test]
fn changing_any_single_ad_field_fails_decryption() {
    let base = sample_ad();
    let ring = ring_with(base.org, &[[1u8; 32], [2u8; 32]]);
    let env = seal_record(ring.get(1).unwrap(), &base, b"payload").unwrap();
    assert_eq!(open_record(&ring, &base, &env).unwrap(), b"payload");

    let other = Uuid::new_v4();
    let variants: Vec<(&str, RecordAd)> = vec![
        (
            "org",
            RecordAd {
                org: other,
                ..base.clone()
            },
        ),
        (
            "member",
            RecordAd {
                member: other,
                ..base.clone()
            },
        ),
        (
            "device",
            RecordAd {
                device: other,
                ..base.clone()
            },
        ),
        (
            "tag (record kind)",
            RecordAd {
                tag: "flag".into(),
                ..base.clone()
            },
        ),
        (
            "tag (roster)",
            RecordAd {
                tag: "roster".into(),
                ..base.clone()
            },
        ),
        (
            "idx",
            RecordAd {
                idx: base.idx + 1,
                ..base.clone()
            },
        ),
        (
            "record id",
            RecordAd {
                record_id: other,
                ..base.clone()
            },
        ),
    ];
    for (field, ad) in variants {
        // The org variant needs a ring under that org id; the key is the same.
        let ring = ring_with(ad.org, &[[1u8; 32], [2u8; 32]]);
        assert_eq!(
            open_record(&ring, &ad, &env),
            Err(Error::Open),
            "{field} swap must fail"
        );
    }
    // Epoch: the same bytes claimed under epoch 0 fail (different key and AD) …
    let e0 = RecordAd {
        epoch: 0,
        ..base.clone()
    };
    assert_eq!(open_record(&ring, &e0, &env), Err(Error::Open));
    // … and also when both epochs held the same key, because the AD binds the epoch.
    let same = ring_with(base.org, &[[2u8; 32], [2u8; 32]]);
    let env_same = seal_record(same.get(1).unwrap(), &base, b"payload").unwrap();
    assert_eq!(open_record(&same, &e0, &env_same), Err(Error::Open));
}

#[test]
fn ad_encoding_is_injective_on_the_tag() {
    // A length-prefixed tag: "re" + idx bytes cannot collide with "rec" + other bytes.
    let a = RecordAd {
        tag: "re".into(),
        ..sample_ad()
    };
    let b = RecordAd {
        tag: "rec".into(),
        ..sample_ad()
    };
    assert_ne!(a.to_bytes().unwrap(), b.to_bytes().unwrap());
    let bad = RecordAd {
        tag: "Rec".into(),
        ..sample_ad()
    };
    assert!(matches!(bad.to_bytes(), Err(Error::Malformed(_))));
    let empty = RecordAd {
        tag: String::new(),
        ..sample_ad()
    };
    assert!(empty.to_bytes().is_err());
}

#[test]
fn wrong_key_or_tampered_bytes_fail() {
    let ad = sample_ad();
    let ring = ring_with(ad.org, &[[1u8; 32], [2u8; 32]]);
    let env = seal_record(ring.get(1).unwrap(), &ad, b"secret text").unwrap();
    let wrong = ring_with(ad.org, &[[1u8; 32], [3u8; 32]]);
    assert_eq!(open_record(&wrong, &ad, &env), Err(Error::Open));
    for i in [1usize, 24, 25, env.len() - 1] {
        let mut t = env.clone();
        t[i] ^= 0x01;
        assert_eq!(open_record(&ring, &ad, &t), Err(Error::Open), "byte {i}");
    }
    let mut v2 = env.clone();
    v2[0] = 0x02;
    assert_eq!(
        open_record(&ring, &ad, &v2),
        Err(Error::Malformed("envelope version"))
    );
    assert_eq!(
        open_record(&ring, &RecordAd { epoch: 7, ..ad }, &env),
        Err(Error::UnknownEpoch(7))
    );
}

#[test]
fn sealing_requires_the_ads_epoch() {
    let ad = sample_ad(); // epoch 1
    let k0 = EpochKey::from_bytes(0, [1u8; 32]);
    assert!(matches!(
        seal_record(&k0, &ad, b"x"),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn structure_check_needs_no_key() {
    let ad = sample_ad();
    let ring = ring_with(ad.org, &[[1u8; 32], [2u8; 32]]);
    let env = seal_record(ring.get(1).unwrap(), &ad, &[7u8; 300]).unwrap();
    let h = check_structure(&env).unwrap();
    assert_eq!(h.version, 1);
    assert_eq!(h.padded_len, 512);
    assert_eq!(&h.nonce[..], &env[1..25]);
    assert!(check_structure(&env[..env.len() - 1]).is_err());
    assert!(check_structure(&[1u8; 40]).is_err());
    let mut bad = env.clone();
    bad[0] = 0;
    assert_eq!(
        check_structure(&bad),
        Err(Error::Malformed("envelope version"))
    );
    assert_eq!(
        check_structure(&vec![1u8; MAX_ENVELOPE + 1]),
        Err(Error::TooLarge)
    );
}

#[test]
fn padding_hides_lengths_within_a_256_byte_bucket() {
    let ad = sample_ad();
    let ring = ring_with(ad.org, &[[1u8; 32], [2u8; 32]]);
    let key = ring.get(1).unwrap();
    // Every plaintext of 0..=255 bytes gives the same envelope length, 256..=511 the next.
    for len in 0..=255usize {
        let env = seal_record(key, &ad, &vec![b'a'; len]).unwrap();
        assert_eq!(env.len(), OVERHEAD + 256, "len {len}");
        assert_eq!(open_record(&ring, &ad, &env).unwrap().len(), len);
    }
    for len in [256usize, 300, 511] {
        assert_eq!(
            seal_record(key, &ad, &vec![0u8; len]).unwrap().len(),
            OVERHEAD + 512
        );
    }
    // Trailing zero bytes of the plaintext survive the padding.
    let tricky = [b'x', 0, 0, 0x80, 0];
    let env = seal_record(key, &ad, &tricky).unwrap();
    assert_eq!(open_record(&ring, &ad, &env).unwrap(), tricky);
}

#[test]
fn plaintext_cap_matches_the_16_kib_blob_limit() {
    let ad = sample_ad();
    let ring = ring_with(ad.org, &[[1u8; 32], [2u8; 32]]);
    let key = ring.get(1).unwrap();
    let max = seal_record(key, &ad, &vec![1u8; MAX_PLAINTEXT]).unwrap();
    assert!(max.len() <= MAX_ENVELOPE);
    assert_eq!(max.len(), envelope_len(MAX_PLAINTEXT));
    assert_eq!(
        seal_record(key, &ad, &vec![1u8; MAX_PLAINTEXT + 1]),
        Err(Error::TooLarge)
    );
    // §3.2: 15 KiB of plaintext fits.
    assert!(envelope_len(15 * 1024) <= MAX_ENVELOPE);
}

/// Synthetic payloads at the §3.2 caps; TM5 builds the real ones.
fn link_record(url_len: usize, title_len: usize) -> Vec<u8> {
    let url = format!(
        "https://docs.example.com/{}",
        "a".repeat(url_len.saturating_sub(25))
    );
    serde_json::to_vec(&json!({
        "schema": 1, "share": "link", "tool": "WebFetch", "url": url,
        "title": "t".repeat(title_len), "status": "ok", "created_at": 1_790_000_000i64,
        "agent": "claude", "source": "hook", "repo_key": "0123456789abcdef0123456789abcdef",
    }))
    .unwrap()
}

fn full_record(query_len: usize, summary_len: usize, results: usize) -> Vec<u8> {
    let rows: Vec<Value> = (0..results)
        .map(|i| {
            json!({"rank": i + 1, "url": format!("https://example.com/{}", "p".repeat(60)),
                   "title": "r".repeat(60)})
        })
        .collect();
    serde_json::to_vec(&json!({
        "schema": 1, "share": "full", "tool": "WebSearch", "query": "q".repeat(query_len),
        "url": null, "fetch_prompt": null, "http_code": 200, "bytes": 51234, "duration_ms": 812,
        "status": "ok", "summary": "s".repeat(summary_len), "results": rows,
        "created_at": 1_790_000_000i64, "agent": "claude", "source": "hook",
        "repo_key": "0123456789abcdef0123456789abcdef",
    }))
    .unwrap()
}

fn buckets(plaintext_len: usize) -> usize {
    (envelope_len(plaintext_len) - OVERHEAD) / PAD_BUCKET
}

/// Measures the residual the padding leaves (§4.3.1, RV8-team M14): the numbers below are
/// the ones `docs/sync-v1-crypto.md` states.
#[test]
fn padding_residual_link_versus_full_size_classes() {
    let cases = [
        ("link, short URL", link_record(40, 30)),
        ("link, typical", link_record(120, 70)),
        ("link, URL 2,048 and title 120", link_record(2048, 120)),
        ("full, dead end, no summary", full_record(30, 0, 0)),
        ("full, 300-char summary, 3 results", full_record(40, 300, 3)),
        (
            "full, typical: 1,000-char summary, 10 results",
            full_record(60, 1000, 10),
        ),
        (
            "full, cap: 2,000-char summary, 10 results",
            full_record(500, 2000, 10),
        ),
    ];
    let measured: Vec<(&str, usize, usize)> = cases
        .iter()
        .map(|(name, p)| (*name, p.len(), buckets(p.len())))
        .collect();
    for (name, len, b) in &measured {
        eprintln!(
            "{name}: plaintext {len} B, {b} bucket(s), envelope {} B",
            b * 256 + OVERHEAD
        );
    }
    let b = |i: usize| measured[i].2;
    assert_eq!(b(0), 1, "short link");
    assert_eq!(b(1), 2, "typical link");
    assert_eq!(b(2), 10, "longest link");
    assert_eq!(b(3), 2, "dead-end full record");
    assert_eq!(b(4), 5, "small full record");
    assert_eq!(b(5), 12, "typical full record");
    assert_eq!(b(6), 18, "capped full record");
    // Residual: typical links (1-2 buckets) and typical full records (12) are apart, but the
    // classes overlap at the edges: a dead-end full record looks like a typical link, and a
    // link with a very long URL falls between small and typical full records.
    assert_eq!(b(3), b(1));
    assert!(b(4) < b(2) && b(2) < b(5));
}

#[test]
fn p1_envelope_shows_the_server_nothing_but_its_length() {
    let ad = sample_ad();
    let ring = ring_with(ad.org, &[[1u8; 32], [9u8; 32]]);
    let text = b"internal project kestrel: customer acme vulnerability CVE-2026-0001";
    let env = seal_record(ring.get(1).unwrap(), &ad, text).unwrap();
    // No plaintext window, no key, no record key in the bytes the server stores.
    for window in text.windows(6) {
        assert!(!env.windows(6).any(|w| w == window));
    }
    let k_rec = record_key(ring.get(1).unwrap());
    assert!(!env
        .windows(32)
        .any(|w| w == ring.get(1).unwrap().expose_secret()));
    assert!(!env.windows(32).any(|w| w == k_rec.expose()));
    // Everything the server holds is the envelope and the AD fields; a key built from
    // metadata alone (org id, record id, a zero key) opens nothing.
    for guess in [
        [0u8; 32],
        *ad.org.as_bytes().repeat(2).first_chunk::<32>().unwrap(),
    ] {
        let g = ring_with(ad.org, &[guess, guess]);
        assert_eq!(open_record(&g, &ad, &env), Err(Error::Open));
    }
    // Two seals of the same plaintext differ (random nonce), so equal records do not show.
    let env2 = seal_record(ring.get(1).unwrap(), &ad, text).unwrap();
    assert_ne!(env, env2);
}
