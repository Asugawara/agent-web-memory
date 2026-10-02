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

/// False only when `path` is non-empty and its last byte is not `\n`. Unreadable counts as fine.
fn ends_with_newline_or_empty(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return true;
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return true;
    };
    if len == 0 {
        return true;
    }
    let mut b = [0u8; 1];
    f.seek(SeekFrom::Start(len - 1)).is_err() || f.read_exact(&mut b).is_err() || b[0] == b'\n'
}

/// Appends `s` to its month file unless the newest line of the same session
/// has equal `h5`, `d7` and `cost`. `dir` is created (0700) when missing; the
/// file is created 0600 and written with one `write` on an `O_APPEND` handle (led by a
/// `\n` when the file ends in an unterminated fragment).
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
    let mut line = String::new();
    if !ends_with_newline_or_empty(&path) {
        // A fragment left by a failed write must not swallow this sample.
        line.push('\n');
    }
    line.push_str(&s.to_line());
    line.push('\n');
    f.write_all(line.as_bytes())?;
    Ok(Recorded::Written)
}

/// Unix ms at 00:00 UTC of the first day after the month of the sample file `name`.
/// `None` when `name` is not a sample file or the next month is out of range.
fn month_end_ms(name: &str) -> Option<i64> {
    if !is_sample_file(name) {
        return None;
    }
    let year: i32 = name.get(8..12)?.parse().ok()?;
    let month: u8 = name.get(13..15)?.parse().ok()?;
    let (year, month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let month = time::Month::try_from(month).ok()?;
    let start = time::Date::from_calendar_date(year, month, 1).ok()?;
    Some(start.midnight().assume_utc().unix_timestamp() * 1000)
}

/// Deletes the entries of `dir` that are regular files (checked with
/// `symlink_metadata`, so links are never followed), pass [`is_sample_file`],
/// and whose month ended more than `retention_days` days before `now_ms`
/// (plan-quota §4.2 step 4, §5.2). The month of `now_ms` is never deleted.
/// Returns how many files were deleted. An error on one file does not stop the
/// others; only a `dir` that cannot be read is an error.
pub fn prune(dir: &Path, now_ms: i64, retention_days: u32) -> io::Result<usize> {
    let keep_ms = i64::from(retention_days) * 86_400_000;
    let current = month_file(dir, now_ms);
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .map(|e| e.path())
        .collect();
    // A fixed order, so one failing file is always tried before the next.
    paths.sort();
    let mut deleted = 0;
    for path in paths {
        let Some(end) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(month_end_ms)
        else {
            continue;
        };
        if path == current || now_ms.saturating_sub(end) <= keep_ms {
            continue;
        }
        if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_file()) {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Samples at or after `since_ms` and the newest `t`, from the last 1 MiB of the two
/// newest sample files (`awm doctor`).
pub fn recent(dir: &Path, since_ms: i64) -> (usize, Option<i64>) {
    const DOCTOR_TAIL: u64 = 1 << 20;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (0, None);
    };
    let mut names: Vec<_> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| e.file_name().to_str().is_some_and(is_sample_file))
        .map(|e| e.path())
        .collect();
    names.sort();
    let (mut n, mut newest) = (0, None::<i64>);
    for path in names.iter().rev().take(2) {
        let Ok(mut f) = std::fs::File::open(path) else {
            continue;
        };
        let len = f.metadata().map_or(0, |m| m.len());
        let start = len.saturating_sub(DOCTOR_TAIL);
        let mut buf = Vec::new();
        if f.seek(SeekFrom::Start(start)).is_err()
            || f.take(DOCTOR_TAIL).read_to_end(&mut buf).is_err()
        {
            continue;
        }
        let text = String::from_utf8_lossy(&buf);
        let mut lines = text.lines();
        if start > 0 {
            lines.next();
        }
        for s in lines.filter_map(Sample::parse_line) {
            newest = newest.max(Some(s.t));
            if s.t >= since_ms {
                n += 1;
            }
        }
    }
    (n, newest)
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
    fn month_end_is_the_first_instant_of_the_next_utc_month() {
        // 2026-07-01T00:00Z, 2027-01-01T00:00Z, 2024-03-01T00:00Z (leap year).
        assert_eq!(
            month_end_ms("samples-2026-06.ndjson"),
            Some(1_782_864_000_000)
        );
        assert_eq!(
            month_end_ms("samples-2026-12.ndjson"),
            Some(1_798_761_600_000)
        );
        assert_eq!(
            month_end_ms("samples-2024-02.ndjson"),
            Some(1_709_251_200_000)
        );
        assert_eq!(month_end_ms("samples-9999-12.ndjson"), None);
        assert_eq!(month_end_ms("samples-2026-13.ndjson"), None);
        assert_eq!(month_end_ms("notes.ndjson"), None);
    }

    #[test]
    fn prune_never_deletes_the_current_or_a_later_month() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        for m in ["2026-09", "2026-10", "2026-11", "9999-12"] {
            std::fs::write(d.join(format!("samples-{m}.ndjson")), "x\n").unwrap();
        }
        // Names that only look like old month files.
        for name in [
            "samples-2026-08.ndjson.tmp",
            "samples-2026-08.json",
            "samples-2026-8.ndjson",
        ] {
            std::fs::write(d.join(name), "x\n").unwrap();
        }
        // 2026-10-01T00:00:00.001Z, retention 0: September ended 1 ms before.
        let now = 1_790_812_800_001;
        assert_eq!(prune(d, now, 0).unwrap(), 1);
        let mut left: Vec<String> = std::fs::read_dir(d)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "samples-2026-08.json",
                "samples-2026-08.ndjson.tmp",
                "samples-2026-10.ndjson",
                "samples-2026-11.ndjson",
                "samples-2026-8.ndjson",
                "samples-9999-12.ndjson"
            ]
        );
        // Exactly `retention_days` after the end is kept; one ms more is not.
        std::fs::write(d.join("samples-2026-09.ndjson"), "x\n").unwrap();
        assert_eq!(prune(d, 1_790_812_800_000 + 86_400_000, 1).unwrap(), 0);
        assert_eq!(prune(d, 1_790_812_800_001 + 86_400_000, 1).unwrap(), 1);
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
