//! `{data}/server.lock` (RVT2 M5): `awm serve` with `SqliteStore` holds an exclusive advisory
//! lock on it for as long as it runs, and `awm serve restore` (also `--mark-restored`) holds it
//! for the restore, so a restore never renames the database under a running server and a second
//! server never opens the same data directory. The lock is the operating system's (`flock`
//! through `File::try_lock`): it is released when the file is closed, on a clean shutdown and
//! when the process dies, so a crash never blocks the next start. The file itself stays; it
//! holds nothing.

use std::fs::{File, TryLockError};
use std::path::{Path, PathBuf};

use crate::fsutil::open_or_create_private_file;

/// The lock file's name in the data directory.
pub const LOCK_FILE: &str = "server.lock";

/// A held lock; dropping it releases the lock.
#[derive(Debug)]
pub struct DataLock {
    _file: File,
    path: PathBuf,
}

impl DataLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Why [`try_lock`] did not lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    /// Another process (or another open of the file in this one) holds the lock.
    Held(PathBuf),
    /// The file could not be created, opened or locked.
    Io(String),
}

/// Locks `{dir}/server.lock` (created mode 0600 when missing) without waiting. `dir` must exist.
pub fn try_lock(dir: &Path) -> Result<DataLock, LockError> {
    let path = dir.join(LOCK_FILE);
    let file = open_or_create_private_file(&path)
        .map_err(|e| LockError::Io(format!("cannot open {}: {}", path.display(), e.kind())))?;
    match file.try_lock() {
        Ok(()) => Ok(DataLock { _file: file, path }),
        Err(TryLockError::WouldBlock) => Err(LockError::Held(path)),
        Err(TryLockError::Error(e)) => Err(LockError::Io(format!(
            "cannot lock {}: {}",
            path.display(),
            e.kind()
        ))),
    }
}
