//! Body, rate and quota limits (plan-v3-team §4.3.5, §4.11; `docs/sync-v1.md` §12).
//!
//! [`Limits`] holds the numbers; its default is `wire::limits`, the constants that
//! `GET /v1/info` publishes. [`RateLimiter`] is the in-memory token-bucket state of the
//! per-token, per-IP, join and bulk-delete limits. It is per server instance and resets when
//! the instance stops (`docs/sync-v1.md` §12, RV8-team m13). Time is passed in (Unix seconds),
//! so tests control the clock.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use awm_proto::wire::{limits as wire, Id};

/// The limits one server enforces. Tests lower or raise single fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Any request body.
    pub max_body_bytes: usize,
    pub max_members: u32,
    /// `POST /v1/records`: encoded body and items.
    pub batch_bytes: usize,
    pub batch_records: usize,
    /// A decoded blob.
    pub blob_bytes: usize,
    pub pull_records: u32,
    pub pull_cursors: usize,
    pub pull_response_bytes: usize,
    pub deletions_page: u32,
    pub delete_ids: usize,
    pub audit_page: u32,
    pub records_per_day: u32,
    /// Authenticated requests per token per minute, and the burst.
    pub requests_per_minute: u32,
    pub request_burst: u32,
    /// Unauthenticated requests per client address per minute; joins per address per hour.
    pub anonymous_per_minute: u32,
    pub joins_per_hour: u32,
    /// `POST /v1/delete` with `all_mine` or `member`, per token per hour.
    pub bulk_deletes_per_hour: u32,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_body_bytes: wire::BODY_BYTES,
            max_members: 100,
            batch_bytes: wire::BATCH_BYTES,
            batch_records: wire::BATCH_RECORDS,
            blob_bytes: wire::BLOB_BYTES,
            pull_records: wire::PULL_RECORDS,
            pull_cursors: wire::PULL_CURSORS,
            pull_response_bytes: wire::PULL_RESPONSE_BYTES,
            deletions_page: wire::DELETIONS_PAGE,
            delete_ids: wire::DELETE_IDS,
            audit_page: wire::AUDIT_PAGE,
            records_per_day: wire::RECORDS_PER_DAY,
            requests_per_minute: wire::REQUESTS_PER_MINUTE,
            request_burst: wire::REQUEST_BURST,
            anonymous_per_minute: wire::ANONYMOUS_PER_MINUTE,
            joins_per_hour: wire::JOINS_PER_HOUR,
            bulk_deletes_per_hour: wire::BULK_DELETES_PER_HOUR,
        }
    }
}

impl Limits {
    /// What `GET /v1/info` publishes.
    pub fn published(&self) -> awm_proto::wire::Limits {
        awm_proto::wire::Limits {
            blob_bytes: self.blob_bytes as u64,
            batch_records: self.batch_records as u64,
            batch_bytes: self.batch_bytes as u64,
            body_bytes: self.max_body_bytes as u64,
            pull_records: self.pull_records.into(),
            pull_cursors: self.pull_cursors as u64,
            pull_response_bytes: self.pull_response_bytes as u64,
            deletions_page: self.deletions_page.into(),
            delete_ids: self.delete_ids as u64,
            records_per_day: self.records_per_day.into(),
            requests_per_minute: self.requests_per_minute.into(),
            request_burst: self.request_burst.into(),
        }
    }

    pub(crate) fn token_rule(&self) -> Rule {
        Rule::per_minute(self.requests_per_minute, self.request_burst)
    }

    pub(crate) fn anonymous_rule(&self) -> Rule {
        Rule::per_minute(self.anonymous_per_minute, self.anonymous_per_minute)
    }

    pub(crate) fn join_rule(&self) -> Rule {
        Rule::per_hour(self.joins_per_hour)
    }
}

/// What a bucket is keyed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateKey {
    /// A request without a usable token, by client address.
    Anonymous(IpAddr),
    /// A request whose token failed authentication, by client address: guessed tokens cost.
    FailedAuth(IpAddr),
    /// Joins, by client address.
    Join(IpAddr),
    /// An authenticated device (one token per device, so rotating the token does not reset it).
    Device(Id),
}

/// The address a per-address bucket is keyed on (RVT2 m5): an IPv4 address (a v4-mapped IPv6
/// address counts as its IPv4 form) as it is, an IPv6 address by its /64, the smallest prefix
/// a client is usually given, so rotating through a /64 gives no new budget.
pub fn bucket_addr(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
    }
}

/// A token bucket: `capacity` tokens, refilled at `per_s` tokens per second.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rule {
    pub capacity: u32,
    pub per_s: f64,
}

impl Rule {
    pub fn per_minute(n: u32, burst: u32) -> Rule {
        Rule {
            capacity: burst.max(1),
            per_s: f64::from(n) / 60.0,
        }
    }

    pub fn per_hour(n: u32) -> Rule {
        Rule {
            capacity: n.max(1),
            per_s: f64::from(n) / 3_600.0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: i64,
    rule: Rule,
}

impl Bucket {
    fn refilled(&self, now: i64) -> f64 {
        let elapsed = (now - self.at).max(0) as f64;
        (self.tokens + elapsed * self.rule.per_s).min(f64::from(self.rule.capacity))
    }
}

/// Above this many buckets, buckets that have refilled completely are dropped.
const PRUNE_ABOVE: usize = 50_000;

/// In-memory rate-limit state of one server instance.
#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<RateKey, Bucket>>,
}

impl RateLimiter {
    pub fn new() -> RateLimiter {
        RateLimiter::default()
    }

    /// Takes one token. `Err(seconds)` is the `Retry-After`: the time until one is available.
    pub fn take(&self, key: RateKey, rule: Rule, now: i64) -> Result<(), u32> {
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() > PRUNE_ABOVE {
            map.retain(|_, b| b.refilled(now) < f64::from(b.rule.capacity));
        }
        let bucket = map.entry(key).or_insert(Bucket {
            tokens: f64::from(rule.capacity),
            at: now,
            rule,
        });
        bucket.rule = rule;
        let have = bucket.refilled(now);
        if have >= 1.0 {
            bucket.tokens = have - 1.0;
            bucket.at = now;
            Ok(())
        } else {
            bucket.tokens = have;
            bucket.at = now;
            Err(retry_after(have, rule))
        }
    }

    /// Gives back a token taken by [`take`] for work that turned out not to count (a token
    /// that authenticated, RVT2 B1), up to the bucket's capacity.
    ///
    /// [`take`]: RateLimiter::take
    pub fn refund(&self, key: RateKey, now: i64) {
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(b) = map.get_mut(&key) {
            b.tokens = (b.refilled(now) + 1.0).min(f64::from(b.rule.capacity));
            b.at = now;
        }
    }

    /// Whether a token is available, without taking it. `Err(seconds)` as for [`take`].
    ///
    /// [`take`]: RateLimiter::take
    pub fn check(&self, key: RateKey, rule: Rule, now: i64) -> Result<(), u32> {
        let map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let have = match map.get(&key) {
            Some(b) => b.refilled(now),
            None => f64::from(rule.capacity),
        };
        if have >= 1.0 {
            Ok(())
        } else {
            Err(retry_after(have, rule))
        }
    }

    /// Number of buckets held (tests of the pruning).
    pub fn len(&self) -> usize {
        self.buckets.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn retry_after(have: f64, rule: Rule) -> u32 {
    let wait = ((1.0 - have) / rule.per_s).ceil();
    (wait.max(1.0).min(f64::from(u32::MAX))) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn a_bucket_allows_its_capacity_then_refuses_with_the_time_to_the_next_token() {
        let l = RateLimiter::new();
        let rule = Rule::per_minute(60, 120);
        for _ in 0..120 {
            assert_eq!(l.take(RateKey::Anonymous(ip(1)), rule, 1_000), Ok(()));
        }
        assert_eq!(l.take(RateKey::Anonymous(ip(1)), rule, 1_000), Err(1));
        // One token per second.
        assert_eq!(l.take(RateKey::Anonymous(ip(1)), rule, 1_001), Ok(()));
        assert_eq!(l.take(RateKey::Anonymous(ip(1)), rule, 1_001), Err(1));
        // A different key has its own bucket.
        assert_eq!(l.take(RateKey::Anonymous(ip(2)), rule, 1_001), Ok(()));
    }

    #[test]
    fn an_hourly_rule_waits_up_to_an_hour() {
        let l = RateLimiter::new();
        let rule = Rule::per_hour(1);
        let key = RateKey::Device(Id::new_v4());
        assert_eq!(l.take(key, rule, 0), Ok(()));
        let wait = l.take(key, rule, 10).unwrap_err();
        assert!((3_590..=3_591).contains(&wait), "{wait}");
        assert_eq!(l.take(key, rule, 3_600), Ok(()));
    }

    #[test]
    fn check_does_not_take() {
        let l = RateLimiter::new();
        let rule = Rule::per_minute(30, 2);
        let key = RateKey::FailedAuth(ip(3));
        for _ in 0..5 {
            assert_eq!(l.check(key, rule, 0), Ok(()));
        }
        assert_eq!(l.take(key, rule, 0), Ok(()));
        assert_eq!(l.take(key, rule, 0), Ok(()));
        assert_eq!(l.check(key, rule, 0), Err(2));
    }

    #[test]
    fn ipv6_buckets_are_keyed_on_the_64_and_v4_mapped_on_the_v4_address() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(bucket_addr(a), bucket_addr(b));
        assert_eq!(bucket_addr(a), "2001:db8:1:2::".parse::<IpAddr>().unwrap());
        assert_ne!(bucket_addr(a), bucket_addr(c));
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(bucket_addr(mapped), "192.0.2.7".parse::<IpAddr>().unwrap());
        assert_eq!(bucket_addr(ip(9)), ip(9));
    }

    #[test]
    fn refund_gives_back_one_token_up_to_the_capacity() {
        let l = RateLimiter::new();
        let rule = Rule::per_minute(30, 2);
        let key = RateKey::FailedAuth(ip(4));
        assert_eq!(l.take(key, rule, 0), Ok(()));
        assert_eq!(l.take(key, rule, 0), Ok(()));
        assert_eq!(l.check(key, rule, 0), Err(2));
        l.refund(key, 0);
        assert_eq!(l.take(key, rule, 0), Ok(()));
        // Never above the capacity.
        for _ in 0..5 {
            l.refund(key, 0);
        }
        assert_eq!(l.take(key, rule, 0), Ok(()));
        assert_eq!(l.take(key, rule, 0), Ok(()));
        assert_eq!(l.take(key, rule, 0), Err(2));
        // A key without a bucket stays without one.
        l.refund(RateKey::FailedAuth(ip(5)), 0);
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn defaults_are_the_published_wire_limits() {
        assert_eq!(Limits::default().published(), awm_proto::wire::Limits::v1());
    }
}
