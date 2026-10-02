//! `sync_state` and the outbox (plan-v3-team §4.4, §4.6 step 8; TM10).

/// The `sync_state` row written at the end of a run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncState {
    pub generation: Option<u64>,
    pub last_ok: Option<String>,
    pub last_error: Option<String>,
    pub backoff_until: Option<String>,
}
