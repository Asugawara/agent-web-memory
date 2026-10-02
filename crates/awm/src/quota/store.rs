//! The sample files: `{data_dir}/quota/samples-YYYY-MM.ndjson` (plan-quota §4.2, §5.1).

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::sample::Sample;

/// How much of the month file's end the dedupe reads.
const TAIL_BYTES: u64 = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    Written,
    Unchanged,
}

/// `samples-` + 4 digits + `-` + 01-12 + `.ndjson`, and nothing else.
pub fn is_sample_file(name: &str) -> bool {
    let Some(rest) = name
        .strip_prefix("samples-")
        .and_then(|r| r.strip_suffix(".ndjson"))
    else {
        return false;
    };
    let b = rest.as_bytes();
    b.len() == 7
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && matches!(
            &rest[5..],
            "01" | "02" | "03" | "04" | "05" | "06" | "07" | "08" | "09" | "10" | "11" | "12"
        )
}

/// The file of the UTC month of `t_ms`.
pub fn month_file(dir: &Path, t_ms: i64) -> PathBuf {
    let fmt = time::macros::format_description!("[year]-[month]");
    let month = time::OffsetDateTime::from_unix_timestamp(t_ms.div_euclid(1000))
        .ok()
        .and_then(|t| t.format(&fmt).ok())
        .unwrap_or_else(|| "1970-01".to_string());
    dir.join(format!("samples-{month}.ndjson"))
}

/// The newest sample of `sid` in the last 8 KiB of `path`.
fn last_of_session(path: &Path, sid: &str) -> Option<Sample> {
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(TAIL_BYTES);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    f.take(TAIL_BYTES).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    if start > 0 {
        // The first line of the tail may be cut.
        lines.next();
    }
    lines.filter_map(Sample::parse_line).rfind(|s| s.sid == sid)
}

/// Appends `s` to its month file unless the newest line of the same session
/// has equal `h5`, `d7` and `cost`. `dir` is created (0700) when missing; the
/// file is created 0600 and written with one `write` on an `O_APPEND` handle.
pub fn record(dir: &Path, s: &Sample) -> io::Result<Recorded> {
    crate::paths::ensure_private_dir(dir).map_err(|e| io::Error::other(e.to_string()))?;
    let path = month_file(dir, s.t);
    if let Some(prev) = last_of_session(&path, &s.sid) {
        if prev.h5 == s.h5 && prev.d7 == s.d7 && prev.cost == s.cost {
            return Ok(Recorded::Unchanged);
        }
    }
    let mut open = OpenOptions::new();
    open.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut f = open.open(&path)?;
    let mut line = s.to_line();
    line.push('\n');
    f.write_all(line.as_bytes())?;
    Ok(Recorded::Written)
}

/// Every sample of every sample file, malformed lines skipped, sorted by `t`.
pub fn read_all(dir: &Path) -> Vec<Sample> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let is_file = entry.file_type().is_ok_and(|t| t.is_file());
        if !is_file || !name.to_str().is_some_and(is_sample_file) {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        out.extend(
            String::from_utf8_lossy(&bytes)
                .lines()
                .filter_map(Sample::parse_line),
        );
    }
    out.sort_by_key(|s| s.t);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_sample_file_accepts_only_month_files() {
        assert!(is_sample_file("samples-2026-10.ndjson"));
        assert!(is_sample_file("samples-2026-01.ndjson"));
        for bad in [
            "samples-2026-13.ndjson",
            "samples-2026-00.ndjson",
            "samples-2026-10.ndjson.tmp",
            "samples-26-10.ndjson",
            "xsamples-2026-10.ndjson",
            "samples-2026-1.ndjson",
            "samples-2026-10",
            "samples-2026-1a.ndjson",
            "",
        ] {
            assert!(!is_sample_file(bad), "{bad}");
        }
    }

    #[test]
    fn month_file_uses_the_utc_month() {
        let d = Path::new("/q");
        // 2026-10-31T23:59:59Z and one second later.
        assert_eq!(
            month_file(d, 1_793_491_199_000),
            d.join("samples-2026-10.ndjson")
        );
        assert_eq!(
            month_file(d, 1_793_491_200_000),
            d.join("samples-2026-11.ndjson")
        );
    }
}
