//! The member's daily record quota (plan-v3-team §4.3.5; `docs/sync-v1.md` §10.3, §12): at most
//! `records_per_day` records a UTC day per member. It counts what grows a stream or the
//! deletion stream: record items, pre-deletions (ids the store does not hold) and markers with a
//! new id (RVT2 M1). Neither counts in the 24 hours after a new generation (the re-seed, §11).
//! `POST /v1/records` and `POST /v1/delete` refuse what would exceed it with 429
//! `rate_limited` (`limit: records_per_day`) and `Retry-After` until 00:00 UTC.

use awm_proto::wire::Id;

use crate::store::{Store, StoreError};

const DAY_S: i64 = 86_400;

/// Whether `adding` more fit the member's quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quota {
    Within,
    /// Over the quota: the seconds until 00:00 UTC.
    Exceeded {
        retry_after_s: u32,
    },
}

/// Checks `adding` items against the quota of `member` at `now` (nothing is taken: the store's
/// count is the state, `Store::pushed_since`).
pub async fn check(
    store: &dyn Store,
    member: Id,
    adding: u64,
    per_day: u32,
    now: i64,
) -> Result<Quota, StoreError> {
    if adding == 0 {
        return Ok(Quota::Within);
    }
    let state = store.restore_state().await?;
    if state.restored_at.is_some_and(|t| now - t < DAY_S) {
        return Ok(Quota::Within);
    }
    let day_start = now - now.rem_euclid(DAY_S);
    let used = store.pushed_since(member, day_start).await?;
    if used + adding > u64::from(per_day) {
        let retry_after_s = u32::try_from((day_start + DAY_S - now).max(1)).unwrap_or(u32::MAX);
        return Ok(Quota::Exceeded { retry_after_s });
    }
    Ok(Quota::Within)
}
