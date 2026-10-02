//! Just enough DER to read a certificate: the validity, the serial and the authority key
//! identifier (plan-v3-team §3.9.3: ARI identifies a certificate by `base64url(AKI keyIdentifier)
//! "." base64url(serial)`; `check` prints the days left). No dependency parses X.509 here.

/// One DER element: tag, content, and what follows it.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&l0, rest) = rest.split_first()?;
    let (len, rest) = if l0 < 0x80 {
        (usize::from(l0), rest)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let mut len = 0usize;
        for &x in &rest[..n] {
            len = (len << 8) | usize::from(x);
        }
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// What the server needs to know about a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub not_before: i64,
    pub not_after: i64,
    /// The DER INTEGER of the serial number, content octets only (RFC 9773 §4.1).
    pub serial: Vec<u8>,
    /// The `keyIdentifier` of the authority key identifier extension.
    pub authority_key_id: Option<Vec<u8>>,
}

impl CertInfo {
    /// Parses a DER certificate.
    pub fn parse(der: &[u8]) -> Option<CertInfo> {
        let (t, cert, _) = tlv(der)?;
        if t != 0x30 {
            return None;
        }
        let (t, tbs, _) = tlv(cert)?;
        if t != 0x30 {
            return None;
        }
        let mut rest = tbs;
        let (mut tag, mut content, mut after) = tlv(rest)?;
        if tag == 0xa0 {
            // The explicit version.
            rest = after;
            (tag, content, after) = tlv(rest)?;
        }
        if tag != 0x02 {
            return None;
        }
        let serial = content.to_vec();
        rest = after;
        // signature AlgorithmIdentifier, issuer
        for _ in 0..2 {
            let (_, _, a) = tlv(rest)?;
            rest = a;
        }
        let (t, validity, a) = tlv(rest)?;
        if t != 0x30 {
            return None;
        }
        rest = a;
        let (tn, nb, v) = tlv(validity)?;
        let (ta, na, _) = tlv(v)?;
        let not_before = time(tn, nb)?;
        let not_after = time(ta, na)?;
        // subject, subjectPublicKeyInfo
        for _ in 0..2 {
            let (_, _, a) = tlv(rest)?;
            rest = a;
        }
        let mut authority_key_id = None;
        while !rest.is_empty() {
            let (t, c, a) = tlv(rest)?;
            rest = a;
            if t == 0xa3 {
                // extensions [3] EXPLICIT SEQUENCE OF Extension
                let (_, mut exts, _) = tlv(c)?;
                while !exts.is_empty() {
                    let (_, ext, a) = tlv(exts)?;
                    exts = a;
                    let (_, oid, mut r) = tlv(ext)?;
                    if oid != [0x55, 0x1d, 0x23] {
                        continue;
                    }
                    let (mut t, mut v, mut a) = tlv(r)?;
                    if t == 0x01 {
                        // the critical flag
                        r = a;
                        (t, v, a) = tlv(r)?;
                    }
                    let _ = a;
                    if t != 0x04 {
                        return None;
                    }
                    // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT ... }
                    let (_, seq, _) = tlv(v)?;
                    let (tag, id, _) = tlv(seq)?;
                    if tag == 0x80 {
                        authority_key_id = Some(id.to_vec());
                    }
                }
            }
        }
        Some(CertInfo {
            not_before,
            not_after,
            serial,
            authority_key_id,
        })
    }
}

/// `UTCTime` (0x17) or `GeneralizedTime` (0x18) as Unix seconds.
fn time(tag: u8, b: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(b).ok()?;
    let s = s.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if s.len() == 12 => {
            let yy: i64 = s[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
        }
        0x18 if s.len() == 14 => (s[..4].parse().ok()?, &s[4..]),
        _ => return None,
    };
    let n = |i: usize| rest.get(i..i + 2)?.parse::<i64>().ok();
    let (month, day, hour, min, sec) = (n(0)?, n(2)?, n(4)?, n(6)?, n(8)?);
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + min * 60 + sec)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The PEM blocks of `text` labelled `label`, decoded (standard base64, whitespace ignored).
pub fn pem_blocks(text: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(&begin) {
        let after = &rest[i + begin.len()..];
        let Some(j) = after.find(&end) else { break };
        if let Some(der) = base64_decode(&after[..j]) {
            out.push(der);
        }
        rest = &after[j + end.len()..];
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_match_known_unix_times() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(time(0x17, b"260102030405Z"), Some(1_767_323_045));
        assert_eq!(time(0x18, b"20260102030405Z"), Some(1_767_323_045));
    }

    #[test]
    fn base64_and_pem_round_trip_a_known_block() {
        let pem = "junk\n-----BEGIN X-----\nAAEC\nAwQF\n-----END X-----\n";
        assert_eq!(pem_blocks(pem, "X"), vec![vec![0, 1, 2, 3, 4, 5]]);
        assert!(pem_blocks(pem, "Y").is_empty());
    }
}
