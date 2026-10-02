//! Backup targets `gs://`, `s3://` and `file://` (plan-v3-team §6.2, §4.8.1, TM27).
//!
//! [`Target::parse`] reads a `--backup URL`; [`Target::open`] turns it into a [`Bucket`], the
//! four operations the backup needs (a create-only upload, a read, a one-level listing and a
//! delete) over keys relative to the URL's prefix.
//!
//! - `gs://BUCKET/PREFIX` and `s3://BUCKET/PREFIX` go through object_store (features
//!   `backup-gcs` and `backup-s3`). Credentials come from the environment only, read the way
//!   object_store's `from_env` reads them (`GOOGLE_*`, `AWS_*`, so `AWS_ENDPOINT_URL` names an
//!   S3-compatible endpoint), or from the host's service account or instance role when none is
//!   set (§3.9.2). The URL itself never carries credentials or options: a query string, a
//!   fragment or a `user:password@` part is refused, so no key file path or secret can reach a
//!   flag, `server.toml` or a log line through it.
//! - `file:///PATH` is a local directory, implemented here over `std::fs` (object_store's
//!   `LocalFileSystem` needs its `fs` feature, which would add crates to `Cargo.lock`). A
//!   create-only upload writes a private temporary file (0600) in the destination directory,
//!   syncs it, then hard-links it to its name, which fails when the name exists; so a reader
//!   never sees a partial object and two writers never overwrite each other. Directories are
//!   created 0700.
//! - Tests use object_store's `InMemory` through [`ObjectStoreBucket`] (feature
//!   `object-store-ring`).
//!
//! Errors name the operation and the key and carry the backend's message with query strings
//! and URL credentials removed ([`redact`]); never a credential, a row value or blob bytes.

use std::fmt;
use std::future::Future;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The future every [`Bucket`] method returns.
pub type BucketFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, TargetError>> + Send + 'a>>;

/// What `--backup` accepts (§4.8.1); the text of the refusal for anything else.
pub const ACCEPTED: &str = "gs://BUCKET/PREFIX, s3://BUCKET/PREFIX (an S3-compatible endpoint \
                            through AWS_ENDPOINT_URL) or file:///PATH";

/// A backup target failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// The URL is refused (a configuration error: exit 2 for `awm serve`).
    Invalid(String),
    /// The scheme needs a cargo feature this binary was built without.
    NotBuilt(&'static str),
    /// A create-only upload found an object under that key.
    AlreadyExists { key: String },
    /// The target cannot do what the backup needs (create-only uploads, hard links).
    Unsupported(String),
    /// Any other failure: the operation, the key, the backend's message (redacted).
    Io {
        op: &'static str,
        key: String,
        msg: String,
    },
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetError::Invalid(m) => write!(f, "backup URL refused: {m}"),
            TargetError::NotBuilt(feature) => write!(
                f,
                "this binary was built without the `{feature}` feature for that backup URL"
            ),
            TargetError::AlreadyExists { key } => write!(f, "{key} already exists"),
            TargetError::Unsupported(m) => write!(f, "backup target unsupported: {m}"),
            TargetError::Io { op, key, msg } => write!(f, "backup target: {op} {key}: {msg}"),
        }
    }
}

impl std::error::Error for TargetError {}

fn io_error(op: &'static str, key: &str, e: impl fmt::Display) -> TargetError {
    TargetError::Io {
        op,
        key: key.to_string(),
        msg: redact(&e.to_string()),
    }
}

/// Removes what could carry a secret from a backend message: query strings (`?...` up to the
/// next whitespace or quote) and the `user:password@` part of URLs.
pub fn redact(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut chars = msg.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '?' {
            out.push_str("?…");
            while let Some(&(_, n)) = chars.peek() {
                if n.is_whitespace() || n == '"' || n == '\'' || n == ')' {
                    break;
                }
                chars.next();
            }
            continue;
        }
        if c == ':' && msg[i..].starts_with("://") {
            out.push_str("://");
            chars.next();
            chars.next();
            // A `user[:password]@` before the host: drop it.
            let rest = &msg[i + 3..];
            let end = rest
                .find(|ch: char| ch.is_whitespace() || ch == '/' || ch == '"' || ch == '\'')
                .unwrap_or(rest.len());
            if let Some(at) = rest[..end].rfind('@') {
                out.push_str("…@");
                for _ in 0..rest[..=at].chars().count() {
                    chars.next();
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------------------------
// URLs

/// A parsed `--backup URL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Gcs { bucket: String, prefix: String },
    S3 { bucket: String, prefix: String },
    File { path: PathBuf },
}

impl fmt::Display for Target {
    /// The URL in its normal form (no credentials: the URL never has any).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let joined = |scheme: &str, bucket: &str, prefix: &str| {
            if prefix.is_empty() {
                format!("{scheme}://{bucket}")
            } else {
                format!("{scheme}://{bucket}/{prefix}")
            }
        };
        match self {
            Target::Gcs { bucket, prefix } => f.write_str(&joined("gs", bucket, prefix)),
            Target::S3 { bucket, prefix } => f.write_str(&joined("s3", bucket, prefix)),
            Target::File { path } => write!(f, "file://{}", path.display()),
        }
    }
}

fn invalid(msg: impl Into<String>) -> TargetError {
    TargetError::Invalid(msg.into())
}

/// A prefix or file path segment: printable, no separators, not `.` or `..`.
fn check_segment(seg: &str, what: &str) -> Result<(), TargetError> {
    if seg.is_empty() {
        return Err(invalid(format!("empty segment in the {what}")));
    }
    if seg == "." || seg == ".." {
        return Err(invalid(format!("`.` or `..` in the {what}")));
    }
    if seg.chars().any(|c| c.is_control() || c == '\\' || c == '%') {
        return Err(invalid(format!(
            "control characters, `\\` or `%` in the {what}"
        )));
    }
    Ok(())
}

impl Target {
    /// Parses `gs://BUCKET/PREFIX`, `s3://BUCKET/PREFIX` or `file:///PATH` (§4.8.1). Refuses
    /// any other scheme, a query string or fragment (credentials and options come from the
    /// environment, §6.2), a `user:password@` part, a bucket name outside `[a-z0-9._-]{3,222}`,
    /// `.` and `..` segments, and a relative file path. Error texts never repeat the URL.
    pub fn parse(url: &str) -> Result<Target, TargetError> {
        let Some((scheme, rest)) = url.split_once("://") else {
            return Err(invalid(format!("not a URL: use {ACCEPTED}")));
        };
        if !matches!(scheme, "gs" | "s3" | "file") {
            // Shown only when it looks like a scheme, so a pasted secret is never repeated.
            let shown = if !scheme.is_empty()
                && scheme.len() <= 8
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            {
                scheme
            } else {
                "(invalid)"
            };
            return Err(invalid(format!(
                "unsupported scheme `{shown}`: use {ACCEPTED}"
            )));
        }
        if rest.contains('?') || rest.contains('#') {
            return Err(invalid(
                "a backup URL takes no query string or fragment: credentials and options come \
                 from the environment or the host's service account, never from the URL or a \
                 key file named in it",
            ));
        }
        if scheme == "file" {
            let path = match rest.strip_prefix("localhost/") {
                Some(p) => format!("/{p}"),
                None if rest.starts_with('/') => rest.to_string(),
                None => {
                    return Err(invalid(
                        "file:// needs an absolute path on this host: file:///PATH",
                    ))
                }
            };
            for seg in path.split('/').skip(1).filter(|s| !s.is_empty()) {
                check_segment(seg, "path")?;
            }
            let trimmed = path.trim_end_matches('/');
            if trimmed.is_empty() {
                return Err(invalid("file:/// needs a directory below the root"));
            }
            return Ok(Target::File {
                path: PathBuf::from(trimmed),
            });
        }
        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        if bucket.contains('@') || bucket.contains(':') {
            return Err(invalid(
                "no credentials or port in a bucket URL: credentials come from the environment",
            ));
        }
        if !(3..=222).contains(&bucket.len())
            || !bucket.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_')
            })
        {
            return Err(invalid(
                "the bucket name must be 3-222 characters of a-z, 0-9, `.`, `-` and `_`",
            ));
        }
        let prefix = prefix.trim_matches('/');
        if !prefix.is_empty() {
            for seg in prefix.split('/') {
                check_segment(seg, "prefix")?;
            }
        }
        let (bucket, prefix) = (bucket.to_string(), prefix.to_string());
        Ok(if scheme == "gs" {
            Target::Gcs { bucket, prefix }
        } else {
            Target::S3 { bucket, prefix }
        })
    }

    /// Opens the target with the process environment ([`Target::open_with_env`]).
    pub fn open(&self) -> Result<Arc<dyn Bucket>, TargetError> {
        self.open_with_env(std::env::vars())
    }

    /// Opens the target, reading credentials and endpoints from `env` the way object_store's
    /// `from_env` reads the process environment (tests pass their own). A `file://` directory
    /// is created 0700 when missing.
    pub fn open_with_env(
        &self,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Arc<dyn Bucket>, TargetError> {
        match self {
            Target::File { path } => Ok(Arc::new(FileBucket::open(path)?)),
            Target::Gcs { bucket, prefix } => {
                #[cfg(feature = "backup-gcs")]
                {
                    cloud::gcs(bucket, prefix, env, self.to_string())
                }
                #[cfg(not(feature = "backup-gcs"))]
                {
                    let _ = (bucket, prefix, env.into_iter().next());
                    Err(TargetError::NotBuilt("backup-gcs"))
                }
            }
            Target::S3 { bucket, prefix } => {
                #[cfg(feature = "backup-s3")]
                {
                    cloud::s3(bucket, prefix, env, self.to_string())
                }
                #[cfg(not(feature = "backup-s3"))]
                {
                    let _ = (bucket, prefix, env.into_iter().next());
                    Err(TargetError::NotBuilt("backup-s3"))
                }
            }
        }
    }
}

/// Environment variables that point the Google client at a key file or carry a key (§3.9.2:
/// "a JSON key file named by `GOOGLE_APPLICATION_CREDENTIALS` is a warning"), for TM15's
/// `credentials` line. Returns the names only, never the values.
pub fn key_file_env(env: impl IntoIterator<Item = (String, String)>) -> Vec<String> {
    const NAMES: &[&str] = &[
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_SERVICE_ACCOUNT",
        "GOOGLE_SERVICE_ACCOUNT_PATH",
        "GOOGLE_SERVICE_ACCOUNT_KEY",
        "SERVICE_ACCOUNT",
    ];
    let mut found: Vec<String> = env
        .into_iter()
        .filter(|(k, v)| NAMES.contains(&k.as_str()) && !v.is_empty())
        .map(|(k, _)| k)
        .collect();
    found.sort();
    found
}

// ---------------------------------------------------------------------------------------------
// Buckets

/// One level of a listing: the names of the sub-directories and of the objects directly under
/// a directory key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    pub dirs: Vec<String>,
    pub objects: Vec<String>,
}

/// The operations the backup needs, over `/`-separated keys relative to the target's prefix.
/// Keys are segments of `[A-Za-z0-9._-]` (no leading `.`).
pub trait Bucket: Send + Sync + fmt::Debug {
    /// The target's URL, for messages (it holds no credentials).
    fn url(&self) -> String;

    /// Uploads `bytes` under `key` only when nothing is stored there (`AlreadyExists`
    /// otherwise); atomic: a reader sees the whole object or none.
    fn put_new(&self, key: String, bytes: Vec<u8>) -> BucketFuture<'_, ()>;

    /// The object under `key`, `None` when absent.
    fn get(&self, key: String) -> BucketFuture<'_, Option<Vec<u8>>>;

    /// One level under `dir` (`""` for the prefix itself); empty when `dir` does not exist.
    fn list(&self, dir: String) -> BucketFuture<'_, Listing>;

    /// Deletes `key`; deleting an absent key succeeds.
    fn delete(&self, key: String) -> BucketFuture<'_, ()>;
}

/// Checks a key: `/`-separated segments of `[A-Za-z0-9._-]`, none empty or starting with `.`.
pub fn check_key(key: &str) -> Result<(), TargetError> {
    let ok = !key.is_empty()
        && key.split('/').all(|seg| {
            !seg.is_empty()
                && !seg.starts_with('.')
                && seg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        });
    if ok {
        Ok(())
    } else {
        Err(TargetError::Invalid(format!("bad object key {key:?}")))
    }
}

fn check_dir(dir: &str) -> Result<(), TargetError> {
    if dir.is_empty() {
        Ok(())
    } else {
        check_key(dir)
    }
}

// --- file:// ---------------------------------------------------------------------------------

/// A local directory as a bucket (`file:///PATH`).
#[derive(Debug, Clone)]
pub struct FileBucket {
    root: PathBuf,
}

static TMP_N: AtomicU64 = AtomicU64::new(0);

fn mkdir_private(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

fn sync_dir(dir: &Path) {
    // Durability of the new name; a failure here (some filesystems refuse) is not an error.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

impl FileBucket {
    /// Opens (creating 0700 when missing) the directory `root`.
    pub fn open(root: &Path) -> Result<FileBucket, TargetError> {
        mkdir_private(root).map_err(|e| io_error("create directory", "", e))?;
        if !root.is_dir() {
            return Err(invalid("file:// target is not a directory"));
        }
        Ok(FileBucket {
            root: root.to_path_buf(),
        })
    }

    fn put_blocking(root: &Path, key: &str, bytes: &[u8]) -> Result<(), TargetError> {
        let dest = root.join(key);
        let parent = dest.parent().unwrap_or(root);
        mkdir_private(parent).map_err(|e| io_error("create directory for", key, e))?;
        let tmp = parent.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            TMP_N.fetch_add(1, Ordering::Relaxed)
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let result = (|| {
            let mut f = opts.open(&tmp).map_err(|e| io_error("upload", key, e))?;
            f.write_all(bytes).map_err(|e| io_error("upload", key, e))?;
            f.sync_all().map_err(|e| io_error("upload", key, e))?;
            match std::fs::hard_link(&tmp, &dest) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    Err(TargetError::AlreadyExists {
                        key: key.to_string(),
                    })
                }
                Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                    Err(TargetError::Unsupported(
                        "hard links (create-only uploads) on this filesystem".into(),
                    ))
                }
                Err(e) => Err(io_error("upload", key, e)),
            }
        })();
        let _ = std::fs::remove_file(&tmp);
        if result.is_ok() {
            sync_dir(parent);
        }
        result
    }
}

fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, TargetError> + Send + 'static,
) -> BucketFuture<'static, T> {
    Box::pin(async move {
        tokio::task::spawn_blocking(f)
            .await
            .map_err(|e| io_error("run", "", e))?
    })
}

impl Bucket for FileBucket {
    fn url(&self) -> String {
        format!("file://{}", self.root.display())
    }

    fn put_new(&self, key: String, bytes: Vec<u8>) -> BucketFuture<'_, ()> {
        let root = self.root.clone();
        blocking(move || {
            check_key(&key)?;
            FileBucket::put_blocking(&root, &key, &bytes)
        })
    }

    fn get(&self, key: String) -> BucketFuture<'_, Option<Vec<u8>>> {
        let root = self.root.clone();
        blocking(move || {
            check_key(&key)?;
            match std::fs::read(root.join(&key)) {
                Ok(b) => Ok(Some(b)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(io_error("read", &key, e)),
            }
        })
    }

    fn list(&self, dir: String) -> BucketFuture<'_, Listing> {
        let root = self.root.clone();
        blocking(move || {
            check_dir(&dir)?;
            let path = if dir.is_empty() {
                root
            } else {
                root.join(&dir)
            };
            let entries = match std::fs::read_dir(&path) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Listing::default()),
                Err(e) => return Err(io_error("list", &dir, e)),
            };
            let mut out = Listing::default();
            for entry in entries {
                let entry = entry.map_err(|e| io_error("list", &dir, e))?;
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if name.starts_with('.') {
                    continue;
                }
                let ty = entry.file_type().map_err(|e| io_error("list", &dir, e))?;
                if ty.is_dir() {
                    out.dirs.push(name);
                } else if ty.is_file() {
                    out.objects.push(name);
                }
            }
            out.dirs.sort();
            out.objects.sort();
            Ok(out)
        })
    }

    fn delete(&self, key: String) -> BucketFuture<'_, ()> {
        let root = self.root.clone();
        blocking(move || {
            check_key(&key)?;
            match std::fs::remove_file(root.join(&key)) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(io_error("delete", &key, e)),
            }
        })
    }
}

// --- object_store ----------------------------------------------------------------------------

#[cfg(feature = "object-store-ring")]
pub use self::objects::ObjectStoreBucket;

#[cfg(feature = "object-store-ring")]
mod objects {
    use std::sync::Arc;

    use object_store::path::Path as ObjPath;
    use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload};

    use super::{check_dir, check_key, io_error, Bucket, BucketFuture, Listing, TargetError};

    /// An object_store store under a prefix: Cloud Storage, S3 or (tests) `InMemory`.
    pub struct ObjectStoreBucket {
        store: Arc<dyn ObjectStore>,
        prefix: String,
        url: String,
    }

    impl std::fmt::Debug for ObjectStoreBucket {
        // Never the store's own `Debug`: a static credential provider would print its key.
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ObjectStoreBucket")
                .field("url", &self.url)
                .finish()
        }
    }

    impl ObjectStoreBucket {
        /// `store` under `prefix` (`/`-separated, may be empty); `url` is what messages show.
        pub fn new(
            store: Arc<dyn ObjectStore>,
            prefix: &str,
            url: impl Into<String>,
        ) -> ObjectStoreBucket {
            ObjectStoreBucket {
                store,
                prefix: prefix.trim_matches('/').to_string(),
                url: url.into(),
            }
        }

        fn path(&self, key: &str) -> ObjPath {
            match (self.prefix.is_empty(), key.is_empty()) {
                (true, _) => ObjPath::from(key),
                (false, true) => ObjPath::from(self.prefix.as_str()),
                (false, false) => ObjPath::from(format!("{}/{key}", self.prefix)),
            }
        }
    }

    impl Bucket for ObjectStoreBucket {
        fn url(&self) -> String {
            self.url.clone()
        }

        fn put_new(&self, key: String, bytes: Vec<u8>) -> BucketFuture<'_, ()> {
            Box::pin(async move {
                check_key(&key)?;
                let opts = PutOptions::from(PutMode::Create);
                match self
                    .store
                    .put_opts(&self.path(&key), PutPayload::from(bytes), opts)
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(object_store::Error::AlreadyExists { .. })
                    | Err(object_store::Error::Precondition { .. }) => {
                        Err(TargetError::AlreadyExists { key })
                    }
                    Err(object_store::Error::NotImplemented { .. })
                    | Err(object_store::Error::NotSupported { .. }) => {
                        Err(TargetError::Unsupported(
                            "create-only uploads (conditional put) are not available on this \
                             target"
                                .into(),
                        ))
                    }
                    Err(e) => Err(io_error("upload", &key, e)),
                }
            })
        }

        fn get(&self, key: String) -> BucketFuture<'_, Option<Vec<u8>>> {
            Box::pin(async move {
                check_key(&key)?;
                match self.store.get(&self.path(&key)).await {
                    Ok(r) => match r.bytes().await {
                        Ok(b) => Ok(Some(b.to_vec())),
                        Err(e) => Err(io_error("read", &key, e)),
                    },
                    Err(object_store::Error::NotFound { .. }) => Ok(None),
                    Err(e) => Err(io_error("read", &key, e)),
                }
            })
        }

        fn list(&self, dir: String) -> BucketFuture<'_, Listing> {
            Box::pin(async move {
                check_dir(&dir)?;
                let base = self.path(&dir);
                let r = self
                    .store
                    .list_with_delimiter(Some(&base))
                    .await
                    .map_err(|e| io_error("list", &dir, e))?;
                let mut out = Listing {
                    dirs: r
                        .common_prefixes
                        .iter()
                        .filter_map(|p| p.filename().map(str::to_string))
                        .collect(),
                    objects: r
                        .objects
                        .iter()
                        .filter_map(|m| m.location.filename().map(str::to_string))
                        .collect(),
                };
                out.dirs.sort();
                out.objects.sort();
                Ok(out)
            })
        }

        fn delete(&self, key: String) -> BucketFuture<'_, ()> {
            Box::pin(async move {
                check_key(&key)?;
                match self.store.delete(&self.path(&key)).await {
                    Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
                    Err(e) => Err(io_error("delete", &key, e)),
                }
            })
        }
    }
}

#[cfg(any(feature = "backup-gcs", feature = "backup-s3"))]
mod cloud {
    use std::sync::Arc;

    use super::{redact, Bucket, ObjectStoreBucket, TargetError};

    fn install_ring() {
        // reqwest is built with `rustls-no-provider`: ring is the one provider (Cargo.toml).
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn build_error(scheme: &str, e: impl std::fmt::Display) -> TargetError {
        TargetError::Invalid(format!(
            "cannot configure the {scheme} client from the environment: {}",
            redact(&e.to_string())
        ))
    }

    #[cfg(feature = "backup-gcs")]
    pub fn gcs(
        bucket: &str,
        prefix: &str,
        env: impl IntoIterator<Item = (String, String)>,
        url: String,
    ) -> Result<Arc<dyn Bucket>, TargetError> {
        use object_store::gcp::{GoogleCloudStorageBuilder, GoogleConfigKey};
        install_ring();
        let mut b = GoogleCloudStorageBuilder::new();
        for (key, value) in env {
            if key == "SERVICE_ACCOUNT" {
                b = b.with_config(GoogleConfigKey::ServiceAccount, value);
            } else if key.starts_with("GOOGLE_") {
                if let Ok(k) = key.to_ascii_lowercase().parse::<GoogleConfigKey>() {
                    b = b.with_config(k, value);
                }
            }
        }
        let store = b
            .with_bucket_name(bucket)
            .build()
            .map_err(|e| build_error("gs://", e))?;
        Ok(Arc::new(ObjectStoreBucket::new(
            Arc::new(store),
            prefix,
            url,
        )))
    }

    #[cfg(feature = "backup-s3")]
    pub fn s3(
        bucket: &str,
        prefix: &str,
        env: impl IntoIterator<Item = (String, String)>,
        url: String,
    ) -> Result<Arc<dyn Bucket>, TargetError> {
        use object_store::aws::{AmazonS3Builder, AmazonS3ConfigKey};
        install_ring();
        let mut b = AmazonS3Builder::new();
        for (key, value) in env {
            if key.starts_with("AWS_") {
                if let Ok(k) = key.to_ascii_lowercase().parse::<AmazonS3ConfigKey>() {
                    b = b.with_config(k, value);
                }
            }
        }
        let store = b
            .with_bucket_name(bucket)
            .build()
            .map_err(|e| build_error("s3://", e))?;
        Ok(Arc::new(ObjectStoreBucket::new(
            Arc::new(store),
            prefix,
            url,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_drops_query_strings_and_url_credentials() {
        assert_eq!(
            redact("GET https://u:secret@h.example/b/k?X-Amz-Signature=abc failed"),
            "GET https://…@h.example/b/k?… failed"
        );
        assert_eq!(redact("plain text"), "plain text");
        assert_eq!(redact("a? b"), "a?… b");
    }

    #[test]
    fn keys_are_plain_segments() {
        assert!(check_key("full/0b5e0a3c-7d1e-4bb1-9a7d-6a3c2a1f0e9d/12.db").is_ok());
        for bad in ["", "/a", "a//b", "../a", "a/.tmp", "a b", "a\\b"] {
            assert!(check_key(bad).is_err(), "{bad:?}");
        }
    }
}
