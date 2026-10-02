//! Epoch keys, device key pairs, wraps and the join MAC (plan-v3-team §5.1, TM3).

/// A device key pair (X25519).
///
/// Implements plan-v3-team §5.1 (TM3).
pub struct DeviceKeys {
    pub public: [u8; 32],
    secret: [u8; 32],
}

impl DeviceKeys {
    /// Generates a fresh key pair.
    pub fn generate() -> DeviceKeys {
        todo!("TM3: device key pairs")
    }

    /// The secret half, for storing in `team.key`.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}
