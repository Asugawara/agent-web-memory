//! `SqliteStore`: one SQLite file `{data}/server.db` (plan-v3-team §4.2).

use super::{NewRecord, Store, StoreResult};

/// The SQLite-backed store (paths B, C and D of §3.9).
pub struct SqliteStore {
    _private: (),
}

impl SqliteStore {
    /// Opens or creates `{data}/server.db` (0700 directory, 0600 file).
    pub fn open(_data_dir: &std::path::Path) -> StoreResult<SqliteStore> {
        todo!("TM5: SqliteStore")
    }
}

impl Store for SqliteStore {
    fn stream_head(&self, _member_id: &str, _device_id: &str, _tag: &str) -> StoreResult<u64> {
        todo!("TM5: SqliteStore")
    }

    fn append(&self, _record: &NewRecord<'_>) -> StoreResult<()> {
        todo!("TM5: SqliteStore")
    }
}
