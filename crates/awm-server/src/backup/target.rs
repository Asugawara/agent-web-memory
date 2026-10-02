//! Backup targets `gs://`, `s3://` and `file://` (plan-v3-team §6.2, TM27).

/// A parsed `--backup URL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Gcs { bucket: String, prefix: String },
    S3 { bucket: String, prefix: String },
    File { path: String },
}
