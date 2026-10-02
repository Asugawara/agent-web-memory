//! The `Store` trait (plan-v3-team §4.2) and its implementations.

#[cfg(feature = "pg")]
pub mod pg;
#[cfg(feature = "sqlite")]
pub mod sqlite;

/// A store failure; the HTTP layer maps it to a status code.
#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

pub type StoreResult<T> = Result<T, StoreError>;

/// Server-side storage of opaque record blobs, rosters and wraps (plan-v3-team §4.2).
pub trait Store: Send + Sync {
    /// The highest contiguous `idx` of the stream `(member_id, device_id, tag)`; 0 when empty.
    fn stream_head(&self, member_id: &str, device_id: &str, tag: &str) -> StoreResult<u64>;

    /// Appends one blob at `idx = head + 1`; a retry of the same blob is idempotent.
    fn append(&self, record: &NewRecord<'_>) -> StoreResult<()>;
}

/// One record to append (the `record` table of §4.2).
#[derive(Debug, Clone, Copy)]
pub struct NewRecord<'a> {
    pub member_id: &'a str,
    pub device_id: &'a str,
    pub tag: &'a str,
    pub idx: u64,
    pub id: &'a str,
    pub epoch: u32,
    pub blob: &'a [u8],
}
