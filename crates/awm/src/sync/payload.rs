//! The encrypted record payload built from a local row (plan-v3-team §3, §4.6 step 3; TM10).

/// Builds the payload JSON for the local `event` row `event_id`.
///
/// Implements plan-v3-team §4.6 step 3.
pub fn build(_event_id: i64) -> anyhow::Result<Vec<u8>> {
    todo!("TM10: payload")
}
