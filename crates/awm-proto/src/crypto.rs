//! Record envelope v1: XChaCha20-Poly1305 with associated data and padding
//! (plan-v3-team §5.1, TM3).

/// Seals `plaintext` under the epoch key `key` with associated data `ad` into an envelope.
///
/// Implements plan-v3-team §5.1 (TM3).
pub fn seal(_key: &[u8; 32], _ad: &[u8], _plaintext: &[u8]) -> Vec<u8> {
    todo!("TM3: envelope v1")
}

/// Opens an envelope made by [`seal`]; `None` when authentication fails.
///
/// Implements plan-v3-team §5.1 (TM3).
pub fn open(_key: &[u8; 32], _ad: &[u8], _envelope: &[u8]) -> Option<Vec<u8>> {
    todo!("TM3: envelope v1")
}
