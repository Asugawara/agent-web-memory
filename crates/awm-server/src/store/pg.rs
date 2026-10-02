//! `PgStore`: pooled Postgres with `org_id` row-level security (plan-v3-team §4.2).

use super::{NewRecord, Store, StoreResult};

/// The Postgres-backed store (path A and the cloud).
pub struct PgStore {
    _private: (),
}

impl PgStore {
    /// Connects to `url` with a pool of at most 10 connections.
    pub fn connect(_url: &str) -> StoreResult<PgStore> {
        todo!("TM26: PgStore")
    }
}

impl Store for PgStore {
    fn stream_head(&self, _member_id: &str, _device_id: &str, _tag: &str) -> StoreResult<u64> {
        todo!("TM26: PgStore")
    }

    fn append(&self, _record: &NewRecord<'_>) -> StoreResult<()> {
        todo!("TM26: PgStore")
    }
}
