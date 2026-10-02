//! Incremental change sets from `backup_log` (plan-v3-team §6.2, TM27).
//!
//! `Store::export_changes(cursor, file)` writes a small SQLite file with the `backup_log` rows
//! after the cursor and, read in the same snapshot, the current row of every key they name
//! (a key deleted in the window has no row and is deleted on apply, so a blob deleted inside
//! the window never ships). The set is named after the head it reaches,
//! `incr/{generation}/{to}.db`, and its manifest records the range `(after, to]`. A set with
//! no rows is not uploaded; the cursor (`meta.backup_cursor`) moves only after both objects
//! are stored, so a failed or interrupted upload is shipped again, whole, by the next one.

use std::path::Path;

use awm_proto::wire::Id;

use super::full::{prepare, Prepared, TempFile};
use super::manifest::{Kind, Origin};
use super::BackupError;
use crate::store::Store;

/// The change set after `cursor`, ready to upload; `None` when `backup_log` did not grow.
pub(crate) async fn prepare_incremental(
    store: &dyn Store,
    generation: Id,
    cursor: i64,
    now: i64,
    writer: Id,
    scratch: &Path,
) -> Result<Option<Prepared>, BackupError> {
    let tmp = TempFile::new(scratch, "incr");
    let cs = store.export_changes(cursor, tmp.path()).await?;
    if cs.rows == 0 {
        return Ok(None);
    }
    let p = prepare(
        tmp,
        Kind::Incr,
        generation,
        cs.to,
        Some(cs.after),
        Some(cs.to),
        now,
        Origin::Incremental,
        writer,
    )
    .await?;
    Ok(Some(p))
}
