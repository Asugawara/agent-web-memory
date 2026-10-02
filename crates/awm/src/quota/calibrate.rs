//! Calibration: percent of a window per list-price dollar (plan-quota §7.2-§7.6).
//!
//! `calibrate` is the one entry point. It reads samples and transcript facts only; it
//! stores nothing and never touches the network. The field names of the types are those
//! of `savings.quota` in plan-quota §10.2, so `Calibration` serializes into that block.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;

use super::sample::Sample;
use super::totals::SessionInfo;

pub const WINDOW_S: i64 = 18_000;
pub const MIN_DP5: f64 = 10.0;
pub const MIN_COST_USD: f64 = 20.0;
pub const MIN_DP7_SUM: f64 = 10.0;
/// A kept sample this far (or more) below the largest earlier kept percentage marks the window mixed.
pub const FALL: f64 = 0.5;
pub const FULL: f64 = 100.0;
pub const MIN_WINDOWS: usize = 5;
pub const MIN_DAYS: usize = 2;
pub const RECENT_DAYS: i64 = 7;
pub const MAX_RATES: usize = 4;
pub const MIN_TOTALS: usize = 3;
pub const W_HIGH: f64 = 10.0;

const DAY_S: i64 = 86_400;
/// Float noise of a sum of cost steps must not turn $20.00 into $19.999999999999996.
const COST_EPS: f64 = 1e-9;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    NoSamples,
    /// Set by the caller (plan-quota §8.3) when the cost column is not in USD; `calibrate` never returns it.
    NotUsd,
    Collecting,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Valid,
    TooSmall,
    Mixed,
    BeforeCapture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Selection {
    Recent,
    Newest,
    Pooled,
}

/// A rate (or a figure scaled by it) at cache-read weight 0, 1 and 10 times list price.
/// `w0` and `w10` are none while σ is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Band {
    pub w0: Option<f64>,
    pub w1: f64,
    pub w10: Option<f64>,
}

impl Band {
    /// Every part times `s` (a saved cost times a rate gives a percentage).
    pub fn scale(&self, s: f64) -> Band {
        Band {
            w0: self.w0.map(|v| v * s),
            w1: self.w1 * s,
            w10: self.w10.map(|v| v * s),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Spread {
    pub median: f64,
    pub p25: f64,
    pub p75: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WindowStat {
    /// `minute(h5.r)`, Unix seconds.
    pub h5_reset: i64,
    /// `minute(d7.r)`, Unix seconds; 0 = the window's samples carry no 7-day window.
    pub d7_reset: i64,
    pub first_ms: i64,
    pub last_ms: i64,
    pub dp5: f64,
    pub dp7: Option<f64>,
    pub cost_usd: f64,
    pub r5: Option<f64>,
    pub verdict: Verdict,
    pub saturated: bool,
    pub fresh_sessions: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Group {
    pub d7_reset: i64,
    pub valid: usize,
    pub days: usize,
    pub qualifies: bool,
    pub k5: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Windows {
    pub seen: usize,
    pub valid: usize,
    pub too_small: usize,
    pub mixed: usize,
    pub before_capture: usize,
    pub saturated: usize,
    /// Sessions whose start came from `t − dur` (no transcript) and were tested for
    /// freshness in a valid window.
    pub start_from_dur: usize,
    pub list: Vec<WindowStat>,
}

/// One rate (`savings.quota.rates[]`). The percentage fields of §10.2 need the saved cost
/// and are the caller's: `k5.scale(saved_usd)`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Rate {
    pub selection: Selection,
    /// None for `pooled`.
    pub d7_reset: Option<i64>,
    pub windows: usize,
    pub days: usize,
    /// Account-weeks behind the rate: 1, or all of them for `pooled`.
    pub account_weeks: usize,
    pub k5: Band,
    /// None until Σ Δp7 ≥ 10.
    pub k7: Option<Band>,
    pub dp7_sum: f64,
    pub spread5: Spread,
    pub cache_read_share: Option<f64>,
    pub sessions_with_totals: usize,
    pub sessions_without_totals: usize,
    pub unpriced_sessions: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Calibration {
    pub status: Status,
    pub samples: usize,
    pub sessions: usize,
    pub first_sample_ms: Option<i64>,
    pub windows: Windows,
    pub groups: Vec<Group>,
    pub rates: Vec<Rate>,
}

/// A window with what the rates need beyond its `WindowStat`.
struct Win {
    stat: WindowStat,
    sids: BTreeSet<String>,
    dur_sids: BTreeSet<String>,
}

fn minute(s: i64) -> i64 {
    s - s.rem_euclid(60)
}

fn day_of(ms: i64) -> i64 {
    ms.div_euclid(DAY_S * 1000)
}

/// Nearest rank, as `cli::percentile`, on f64.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn days(wins: &[&Win]) -> usize {
    wins.iter()
        .map(|w| day_of(w.stat.first_ms))
        .collect::<BTreeSet<_>>()
        .len()
}

fn qualifies(wins: &[&Win]) -> bool {
    wins.len() >= MIN_WINDOWS && days(wins) >= MIN_DAYS
}

fn k5_of(wins: &[&Win]) -> f64 {
    let dp: f64 = wins.iter().map(|w| w.stat.dp5).sum();
    let c: f64 = wins.iter().map(|w| w.stat.cost_usd).sum();
    dp / c
}

fn empty(samples: usize) -> Calibration {
    Calibration {
        status: if samples == 0 {
            Status::NoSamples
        } else {
            Status::Collecting
        },
        samples,
        sessions: 0,
        first_sample_ms: None,
        windows: Windows {
            seen: 0,
            valid: 0,
            too_small: 0,
            mixed: 0,
            before_capture: 0,
            saturated: 0,
            start_from_dur: 0,
            list: Vec::new(),
        },
        groups: Vec::new(),
        rates: Vec::new(),
    }
}

/// The calibration of §7.2-§7.6. `samples` need not be sorted; `now_ms` only decides which
/// account-weeks are recent.
pub fn calibrate(
    samples: &[Sample],
    sessions: &HashMap<String, SessionInfo>,
    now_ms: i64,
) -> Calibration {
    if samples.is_empty() {
        return empty(0);
    }
    let mut order: Vec<&Sample> = samples.iter().collect();
    order.sort_by_key(|s| s.t);
    let t_capture = order[0].t;

    // first(s): the session's first sample in all files.
    let mut first: HashMap<&str, usize> = HashMap::new();
    for (i, s) in order.iter().enumerate() {
        first.entry(s.sid.as_str()).or_insert(i);
    }

    // One window per key; a sample is used only inside [T0, h5.r).
    // A sample without `seven_day` joins the first non-zero `d7.r` seen for its `h5.r`.
    let in_use = |s: &Sample| -> Option<i64> {
        let r0 = minute(s.h5?.r);
        (s.t >= (r0 - WINDOW_S) * 1000 && s.t < s.h5?.r * 1000).then_some(r0)
    };
    let mut first_d7: HashMap<i64, i64> = HashMap::new();
    for s in &order {
        if let (Some(r0), Some(w)) = (in_use(s), s.d7) {
            first_d7.entry(r0).or_insert_with(|| minute(w.r));
        }
    }
    let mut by_key: BTreeMap<(i64, i64), Vec<usize>> = BTreeMap::new();
    for (i, s) in order.iter().enumerate() {
        let Some(r0) = in_use(s) else { continue };
        let d7 =
            s.d7.map_or_else(|| first_d7.get(&r0).copied().unwrap_or(0), |w| minute(w.r));
        by_key.entry((r0, d7)).or_default().push(i);
    }

    let wins: Vec<Win> = by_key
        .iter()
        .map(|(&(r0, d7), idx)| window(&order, &first, sessions, t_capture, r0, d7, idx))
        .collect();

    let valid: Vec<&Win> = wins
        .iter()
        .filter(|w| w.stat.verdict == Verdict::Valid)
        .collect();
    let count = |v: Verdict| wins.iter().filter(|w| w.stat.verdict == v).count();
    let start_from_dur = valid
        .iter()
        .flat_map(|w| w.dur_sids.iter())
        .collect::<BTreeSet<_>>()
        .len();

    // Groups: valid windows per account-week.
    let mut by_group: BTreeMap<i64, Vec<&Win>> = BTreeMap::new();
    for w in &valid {
        by_group.entry(w.stat.d7_reset).or_default().push(w);
    }
    let groups: Vec<Group> = by_group
        .iter()
        .map(|(&d7, ws)| Group {
            d7_reset: d7,
            valid: ws.len(),
            days: days(ws),
            qualifies: qualifies(ws),
            k5: k5_of(ws),
        })
        .collect();

    let rates = select(&by_group, &valid, sessions, now_ms);

    Calibration {
        status: if rates.is_empty() {
            Status::Collecting
        } else {
            Status::Ready
        },
        samples: samples.len(),
        sessions: first.len(),
        first_sample_ms: Some(t_capture),
        windows: Windows {
            seen: wins.len(),
            valid: valid.len(),
            too_small: count(Verdict::TooSmall),
            mixed: count(Verdict::Mixed),
            before_capture: count(Verdict::BeforeCapture),
            saturated: wins.iter().filter(|w| w.stat.saturated).count(),
            start_from_dur,
            list: wins.iter().map(|w| w.stat.clone()).collect(),
        },
        groups,
        rates,
    }
}

/// §7.2 for one window: cut, mixed, Δp, C_W, verdict.
fn window(
    order: &[&Sample],
    first: &HashMap<&str, usize>,
    sessions: &HashMap<String, SessionInfo>,
    t_capture: i64,
    r0: i64,
    d7: i64,
    idx: &[usize],
) -> Win {
    let t0 = (r0 - WINDOW_S) * 1000;

    // cut: samples after the first one at 100 % are dropped; that one stays.
    let mut kept: Vec<usize> = Vec::new();
    let mut saturated = false;
    for &i in idx {
        kept.push(i);
        let s = order[i];
        if s.h5.is_some_and(|w| w.p >= FULL) || s.d7.is_some_and(|w| w.p >= FULL) {
            saturated = true;
            break;
        }
    }

    // mixed: a fall below the largest earlier kept value, in either window.
    let mut mixed = false;
    let (mut max5, mut max7): (Option<f64>, Option<f64>) = (None, None);
    for &i in &kept {
        let s = order[i];
        if let Some(w) = s.h5 {
            mixed |= max5.is_some_and(|m| m - w.p >= FALL);
            max5 = Some(max5.map_or(w.p, |m| m.max(w.p)));
        }
        if let Some(w) = s.d7 {
            mixed |= max7.is_some_and(|m| m - w.p >= FALL);
            max7 = Some(max7.map_or(w.p, |m| m.max(w.p)));
        }
    }

    // Δp from the first kept sample.
    let base5 = order[kept[0]].h5.map_or(0.0, |w| w.p);
    let dp5 = max5.map_or(0.0, |m| m - base5);
    let dp7 = kept
        .iter()
        .find_map(|&i| order[i].d7)
        .map(|w| max7.unwrap_or(w.p) - w.p);

    // C_W: steps between consecutive kept samples of a session, plus the first cost of
    // each fresh session.
    let mut cost = 0.0;
    let mut last: HashMap<&str, &Sample> = HashMap::new();
    let mut sids = BTreeSet::new();
    let mut dur_sids = BTreeSet::new();
    let mut fresh = 0;
    for &i in &kept {
        let s = order[i];
        sids.insert(s.sid.clone());
        if let (Some(prev), Some(b)) = (last.get(s.sid.as_str()), s.cost) {
            if let Some(a) = prev.cost {
                cost += (b - a).max(0.0);
            }
        }
        last.insert(s.sid.as_str(), s);
        if i != kept[0] && first.get(s.sid.as_str()) == Some(&i) {
            if let (Some(c), Some((start, from_dur))) = (s.cost, start_of(s, sessions)) {
                if start >= t0 {
                    cost += c;
                    fresh += 1;
                    if from_dur {
                        dur_sids.insert(s.sid.clone());
                    }
                }
            }
        }
    }

    let verdict = if t0 < t_capture {
        Verdict::BeforeCapture
    } else if mixed {
        Verdict::Mixed
    } else if dp5 < MIN_DP5 || cost + COST_EPS < MIN_COST_USD {
        Verdict::TooSmall
    } else {
        Verdict::Valid
    };

    Win {
        stat: WindowStat {
            h5_reset: r0,
            d7_reset: d7,
            first_ms: order[kept[0]].t,
            last_ms: order[*kept.last().unwrap_or(&kept[0])].t,
            dp5,
            dp7,
            cost_usd: cost,
            r5: (cost > 0.0).then(|| dp5 / cost),
            verdict,
            saturated,
            fresh_sessions: fresh,
        },
        sids,
        dur_sids,
    }
}

/// start(s): the transcript start, else `t − dur` of the session's first sample (`true`).
fn start_of(first_sample: &Sample, sessions: &HashMap<String, SessionInfo>) -> Option<(i64, bool)> {
    if let Some(ms) = sessions.get(&first_sample.sid).and_then(|i| i.start_ms) {
        return Some((ms, false));
    }
    first_sample.dur.map(|d| (first_sample.t - d, true))
}

/// §7.3 selection: recent, else newest, else pooled, else none.
fn select(
    by_group: &BTreeMap<i64, Vec<&Win>>,
    valid: &[&Win],
    sessions: &HashMap<String, SessionInfo>,
    now_ms: i64,
) -> Vec<Rate> {
    let recent_from = now_ms.div_euclid(1000) - RECENT_DAYS * DAY_S;
    // Newest first.
    let qualifying: Vec<(i64, &Vec<&Win>)> = by_group
        .iter()
        .rev()
        .filter(|(_, ws)| qualifies(ws))
        .map(|(&d7, ws)| (d7, ws))
        .collect();
    let recent: Vec<_> = qualifying
        .iter()
        .filter(|(d7, _)| *d7 >= recent_from)
        .take(MAX_RATES)
        .collect();
    if !recent.is_empty() {
        return recent
            .iter()
            .map(|(d7, ws)| rate(Selection::Recent, Some(*d7), ws, 1, sessions))
            .collect();
    }
    if let Some((d7, ws)) = qualifying.first() {
        return vec![rate(Selection::Newest, Some(*d7), ws, 1, sessions)];
    }
    if qualifies(valid) {
        return vec![rate(
            Selection::Pooled,
            None,
            valid,
            by_group.len(),
            sessions,
        )];
    }
    Vec::new()
}

/// §7.3 spread, §7.4 k7 and §7.6 band for the windows of one rate.
fn rate(
    selection: Selection,
    d7_reset: Option<i64>,
    wins: &[&Win],
    account_weeks: usize,
    sessions: &HashMap<String, SessionInfo>,
) -> Rate {
    let k5 = k5_of(wins);

    // σ over the sessions behind the rate that have priced totals.
    let sids: BTreeSet<&String> = wins.iter().flat_map(|w| w.sids.iter()).collect();
    let mut totals = Vec::new();
    let mut unpriced = 0;
    for sid in &sids {
        let Some(info) = sessions.get(*sid) else {
            continue;
        };
        unpriced += usize::from(info.unpriced);
        if let (false, Some(c), Some(cr)) = (info.unpriced, info.cost_usd, info.cache_read_usd) {
            totals.push((c, cr));
        }
    }
    let cost_sum: f64 = totals.iter().map(|t| t.0).sum();
    let cr_sum: f64 = totals.iter().map(|t| t.1).sum();
    let sigma = (totals.len() >= MIN_TOTALS && cost_sum > 0.0).then(|| cr_sum / cost_sum);
    let band = |k: f64| {
        let at = |w: f64| {
            let d = 1.0 + (w - 1.0) * sigma?;
            (d > 0.0).then(|| k / d)
        };
        Band {
            w0: at(0.0),
            w1: k,
            w10: at(W_HIGH),
        }
    };

    // k7 over the windows that have a 7-day rise, shown from Σ Δp7 ≥ 10.
    let with7: Vec<&&Win> = wins.iter().filter(|w| w.stat.dp7.is_some()).collect();
    let dp7_sum: f64 = with7.iter().filter_map(|w| w.stat.dp7).sum();
    let c7: f64 = with7.iter().map(|w| w.stat.cost_usd).sum();
    let k7 = (dp7_sum >= MIN_DP7_SUM && c7 > 0.0).then(|| band(dp7_sum / c7));

    let mut ratios: Vec<f64> = wins.iter().filter_map(|w| w.stat.r5).collect();
    ratios.sort_by(f64::total_cmp);
    let spread5 = Spread {
        median: percentile(&ratios, 50.0),
        p25: percentile(&ratios, 25.0),
        p75: percentile(&ratios, 75.0),
    };

    Rate {
        selection,
        d7_reset,
        windows: wins.len(),
        days: days(wins),
        account_weeks,
        k5: band(k5),
        k7,
        dp7_sum,
        spread5,
        cache_read_share: sigma,
        sessions_with_totals: totals.len(),
        sessions_without_totals: sids.len() - totals.len(),
        unpriced_sessions: unpriced,
    }
}
