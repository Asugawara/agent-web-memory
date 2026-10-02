//! Body, rate and quota limits (plan-v3-team §4.11).

/// Server limits; defaults are set in §4.11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_body_bytes: usize,
    pub max_members: u32,
}
