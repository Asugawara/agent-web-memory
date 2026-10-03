//! Private (0700 directory, 0600 file) creation and directory sync, shared by the store, the
//! backup, the ACME cache, `serve` and the data lock. Callers keep their own error mapping.
//!
//! The umask can only remove bits from the creation mode, so every helper sets the mode
//! explicitly after creating: the result is exactly 0700 / 0600 whatever the umask.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::path::Path;

/// Creates `dir` (and missing parents) with mode 0700 when it is not a directory yet.
pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    make_dir(dir, true)
}

/// Creates `dir` (not its parents) with mode 0700; an existing path (a directory, a file or a
/// link) is an error.
#[cfg(feature = "sqlite")]
pub(crate) fn create_new_private_dir(dir: &Path) -> io::Result<()> {
    make_dir(dir, false)
}

fn make_dir(dir: &Path, recursive: bool) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Creates a new file with mode 0600 and returns it open for writing; fails if `path` exists.
pub(crate) fn create_new_private_file(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Opens `path` for writing, creating it with mode 0600 when missing; an existing file keeps
/// its mode and content.
pub(crate) fn open_or_create_private_file(path: &Path) -> io::Result<File> {
    match create_new_private_file(path) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            OpenOptions::new().write(true).open(path)
        }
        other => other,
    }
}

/// Syncs the directory `dir`, so a new name in it survives a power cut. A no-op off unix,
/// where directories cannot be opened.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir).and_then(|f| f.sync_all())?;
    let _ = dir;
    Ok(())
}
