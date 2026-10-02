//! The calibration library (plan-quota §7) and the transcript reads (§6).
//! Synthetic samples and transcripts only; hand-computed figures are in the comments.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use awm::quota::calibrate::{calibrate, Calibration, Selection, Status, Verdict, WindowStat};
use awm::quota::sample::{Sample, Window};
use awm::quota::totals::{self, cache_read_price, SessionInfo};

/// An `h5.r` (seconds, a multiple of 60) and a `d7.r`.
const R: i64 = 1_790_910_000;
const D7: i64 = 1_791_300_000;
const HOUR: i64 = 3_600_000;
const DAY: i64 = 86_400;

/// Start of the window that resets at `r` (seconds), in ms.
fn t0(r: i64) -> i64 {
    (r - 18_000) * 1000
}

fn smp(sid: &str, t: i64, p5: f64, r5: i64, d7: Option<(f64, i64)>, cost: Option<f64>) -> Sample {
    Sample {
        t,
        sid: sid.to_string(),
        model: None,
        h5: Some(Window { p: p5, r: r5 }),
        d7: d7.map(|(p, r)| Window { p, r }),
        cost,
        dur: None,
    }
}

/// A sample with a constant 7-day window (percent 50, reset `D7`).
fn at(sid: &str, t: i64, p5: f64, r5: i64, cost: f64) -> Sample {
    smp(sid, t, p5, r5, Some((50.0, D7)), Some(cost))
}

/// A 7-day-only sample long before everything: it only fixes `t_capture` early.
fn anchor() -> Sample {
    Sample {
        t: 1000,
        sid: "anchor".into(),
        model: None,
        h5: None,
        d7: Some(Window { p: 1.0, r: D7 }),
        cost: None,
        dur: None,
    }
}

/// One window of one session: two samples, p `p0` → `p1`, cost `c0` → `c1`, at T0 + 1 h and T0 + 2 h.
fn pair(r: i64, d7: i64, sid: &str, p0: f64, p1: f64, c0: f64, c1: f64) -> Vec<Sample> {
    let d = Some((50.0, d7));
    vec![
        smp(sid, t0(r) + HOUR, p0, r, d, Some(c0)),
        smp(sid, t0(r) + 2 * HOUR, p1, r, d, Some(c1)),
    ]
}

/// `n` valid windows (Δp 12, C $100) of one account-week, 12 h apart, one session each.
fn valid_windows(d7: i64, base_r: i64, n: i64, tag: &str) -> Vec<Sample> {
    (0..n)
        .flat_map(|i| {
            pair(
                base_r + i * 43_200,
                d7,
                &format!("{tag}-{i}"),
                10.0,
                22.0,
                0.0,
                100.0,
            )
        })
        .collect()
}

fn with_anchor(mut v: Vec<Sample>) -> Vec<Sample> {
    v.push(anchor());
    v
}

fn run(samples: &[Sample]) -> Calibration {
    calibrate(samples, &HashMap::new(), R * 1000)
}

fn win(c: &Calibration, r: i64) -> &WindowStat {
    c.windows
        .list
        .iter()
        .find(|w| w.h5_reset == r)
        .expect("window")
}

fn info(start_ms: Option<i64>) -> SessionInfo {
    SessionInfo {
        start_ms,
        ..SessionInfo::default()
    }
}

fn close(a: f64, b: f64) {
    assert!((a - b).abs() < 1e-12, "{a} != {b}");
}

/// The windows of the four tests that need one controlled window: T0 = R − 5 h.
fn base() -> i64 {
    t0(R)
}

#[test]
fn ratio_of_sums_over_valid_windows() {
    // (Δp, C): (12, 100), (20, 150), (10, 50), (15, 60), (30, 200).
    // k = 87 / 560 = 0.15536; the median of the ratios would be 0.15.
    let rows = [
        (12.0, 100.0),
        (20.0, 150.0),
        (10.0, 50.0),
        (15.0, 60.0),
        (30.0, 200.0),
    ];
    let mut v = vec![anchor()];
    for (i, (dp, c)) in rows.iter().enumerate() {
        let r = R + i as i64 * 43_200;
        v.extend(pair(r, D7, &format!("s{i}"), 5.0, 5.0 + dp, 10.0, 10.0 + c));
    }
    let cal = run(&v);
    assert_eq!(cal.status, Status::Ready);
    assert_eq!(cal.windows.valid, 5);
    assert_eq!(cal.rates.len(), 1);
    assert_eq!(cal.rates[0].selection, Selection::Recent);
    assert_eq!(cal.rates[0].k5.w1, 87.0 / 560.0);
    assert_eq!(cal.groups[0].k5, 87.0 / 560.0);
    assert_eq!(cal.rates[0].windows, 5);
}

#[test]
fn integer_and_fractional_percentages() {
    // Four integer windows (10/50, 12/60, 14/70, 16/80) and one fractional (20.25 → 30.75 = 10.5, $55).
    // k = (10 + 12 + 14 + 16 + 10.5) / (50 + 60 + 70 + 80 + 55) = 62.5 / 315.
    let mut v = vec![anchor()];
    let ints = [(10.0, 50.0), (12.0, 60.0), (14.0, 70.0), (16.0, 80.0)];
    for (i, (dp, c)) in ints.iter().enumerate() {
        v.extend(pair(
            R + i as i64 * 43_200,
            D7,
            &format!("i{i}"),
            5.0,
            5.0 + dp,
            0.0,
            *c,
        ));
    }
    v.extend(pair(R + 4 * 43_200, D7, "f", 20.25, 30.75, 0.0, 55.0));
    let cal = run(&v);
    assert_eq!(cal.windows.valid, 5);
    assert_eq!(cal.rates[0].k5.w1, 62.5 / 315.0);
}

#[test]
fn thresholds_drop_small_windows() {
    // Δp 9 with $100; Δp 10 with $19.99; Δp 10 with $20 is valid.
    let mut v = vec![anchor()];
    v.extend(pair(R, D7, "a", 5.0, 14.0, 0.0, 100.0));
    v.extend(pair(R + 43_200, D7, "b", 5.0, 15.0, 100.0, 119.99));
    v.extend(pair(R + 86_400, D7, "c", 5.0, 15.0, 100.0, 120.0));
    let cal = run(&v);
    assert_eq!(win(&cal, R).verdict, Verdict::TooSmall);
    assert_eq!(win(&cal, R + 43_200).verdict, Verdict::TooSmall);
    assert_eq!(win(&cal, R + 86_400).verdict, Verdict::Valid);
    assert_eq!(cal.windows.too_small, 2);
    assert_eq!(cal.windows.valid, 1);
}

#[test]
fn window_start_is_reset_minus_five_hours() {
    // Samples (p, cost):
    //   A 1h (10, 5) = W's first kept sample; A 4h (30, 25)          pair +20
    //   B 2h (15, 40), transcript start T0 + 10 min → fresh, +40; B 3h (20, 60)   +20
    //   X 2.5h (18, 30), transcript start T0 − 1 min → not fresh; X 3.5h (24, 50) +20
    // Δp = 30 − 10 = 20, C = 20 + 40 + 20 + 20 = 100, one fresh session.
    let b = base();
    let v = with_anchor(vec![
        at("A", b + HOUR, 10.0, R, 5.0),
        at("B", b + 2 * HOUR, 15.0, R, 40.0),
        at("X", b + 2 * HOUR + HOUR / 2, 18.0, R, 30.0),
        at("B", b + 3 * HOUR, 20.0, R, 60.0),
        at("X", b + 3 * HOUR + HOUR / 2, 24.0, R, 50.0),
        at("A", b + 4 * HOUR, 30.0, R, 25.0),
    ]);
    let s = HashMap::from([
        ("B".to_string(), info(Some(b + 600_000))),
        ("X".to_string(), info(Some(b - 60_000))),
    ]);
    let cal = calibrate(&v, &s, R * 1000);
    let w = win(&cal, R);
    assert_eq!(w.dp5, 20.0);
    assert_eq!(w.cost_usd, 100.0);
    assert_eq!(w.fresh_sessions, 1);
    assert_eq!(cal.windows.start_from_dur, 0);
}

#[test]
fn first_sample_session_cost_before_it_is_not_counted() {
    // A's first sample is W's first kept sample, with cost 80 already spent: it is in the
    // base. Even with a transcript start inside the window, only the step 80 → 130 counts.
    let b = base();
    let v = with_anchor(vec![
        at("A", b + HOUR, 10.0, R, 80.0),
        at("A", b + 2 * HOUR, 22.0, R, 130.0),
    ]);
    let s = HashMap::from([("A".to_string(), info(Some(b + 300_000)))]);
    let cal = calibrate(&v, &s, R * 1000);
    let w = win(&cal, R);
    assert_eq!(w.cost_usd, 50.0);
    assert_eq!(w.fresh_sessions, 0);
}

#[test]
fn resumed_session_transcript_start_wins_over_dur() {
    // Session S resumes with restored cost 300 and dur 10 min: t − dur is T0 + 1 h 50 min,
    // inside the window, but its transcript started 2 days before T0. Not fresh: only the
    // step 300 → 320 counts. C = A's 30 + 20 = 50.
    let b = base();
    let mut resumed = at("S", b + 2 * HOUR, 15.0, R, 300.0);
    resumed.dur = Some(600_000);
    let v = with_anchor(vec![
        at("A", b + HOUR, 10.0, R, 0.0),
        resumed,
        at("S", b + 3 * HOUR, 20.0, R, 320.0),
        at("A", b + 4 * HOUR, 25.0, R, 30.0),
    ]);
    let s = HashMap::from([("S".to_string(), info(Some(b - 2 * DAY * 1000)))]);
    let cal = calibrate(&v, &s, R * 1000);
    let w = win(&cal, R);
    assert_eq!(w.cost_usd, 50.0);
    assert_eq!(w.fresh_sessions, 0);
    assert_eq!(cal.windows.start_from_dur, 0);
}

#[test]
fn missing_transcript_falls_back_to_dur_and_is_counted() {
    // B has no transcript: t − dur = T0 + 1.5 h ≥ T0 → fresh, its first cost 40 counts.
    // C = A's 25 + B's 40 + 20 = 85; one session started from dur.
    let b = base();
    let mut fresh = at("B", b + 2 * HOUR, 15.0, R, 40.0);
    fresh.dur = Some(HOUR / 2);
    let v = with_anchor(vec![
        at("A", b + HOUR, 10.0, R, 0.0),
        fresh,
        at("B", b + 3 * HOUR, 20.0, R, 60.0),
        at("A", b + 4 * HOUR, 25.0, R, 25.0),
    ]);
    let cal = run(&v);
    let w = win(&cal, R);
    assert_eq!(w.cost_usd, 85.0);
    assert_eq!(w.fresh_sessions, 1);
    assert_eq!(w.verdict, Verdict::Valid);
    assert_eq!(cal.windows.start_from_dur, 1);
}

#[test]
fn window_before_capture_is_not_used() {
    // The first sample of all arrives 30 min after T0: the window began before capture.
    let b = base();
    let v = vec![
        at("A", b + HOUR / 2, 10.0, R, 0.0),
        at("A", b + 2 * HOUR, 25.0, R, 100.0),
    ];
    let cal = run(&v);
    assert_eq!(win(&cal, R).verdict, Verdict::BeforeCapture);
    assert_eq!(cal.windows.before_capture, 1);
    assert_eq!(cal.windows.valid, 0);
    assert_eq!(cal.status, Status::Collecting);
}

#[test]
fn negative_cost_step_counts_zero() {
    // Cost 100 → 80 counts 0, 80 → 130 counts 50.
    let b = base();
    let v = with_anchor(vec![
        at("A", b + HOUR, 10.0, R, 100.0),
        at("A", b + 2 * HOUR, 15.0, R, 80.0),
        at("A", b + 3 * HOUR, 25.0, R, 130.0),
    ]);
    assert_eq!(win(&run(&v), R).cost_usd, 50.0);
}

#[test]
fn pair_straddling_a_reset_is_dropped() {
    // S's samples: cost 100 in W1 (alone), 160 in W2 (alone). The +60 is in neither window.
    // W1: A 0 → 30 = 30. W2 has one kept sample: Δp 0, C 0.
    let b = base();
    let r2 = R + 18_000;
    let v = with_anchor(vec![
        at("A", b + HOUR, 10.0, R, 0.0),
        at("A", b + 2 * HOUR, 20.0, R, 30.0),
        at("S", b + 4 * HOUR + HOUR / 2, 25.0, R, 100.0),
        at("S", t0(r2) + 360_000, 5.0, r2, 160.0),
    ]);
    let cal = run(&v);
    assert_eq!(win(&cal, R).cost_usd, 30.0);
    assert_eq!(win(&cal, r2).cost_usd, 0.0);
    assert_eq!(win(&cal, r2).dp5, 0.0);
}

#[test]
fn resumed_pair_spanning_the_gap_is_not_counted() {
    // RVQ1 check 5. Session R: W1 samples cost 40, 50; resumed in W2 with restored cost 50 →
    // first W2 sample cost 90, then 110. The step 50 → 90 spans windows and is in neither.
    // W2: A 0 → 30 = 30, R 90 → 110 = 20; R is not fresh (first(R) is in W1). C = 50.
    let b = base();
    let r2 = R + 18_000;
    let t2 = t0(r2);
    let v = with_anchor(vec![
        at("R", b + HOUR, 10.0, R, 40.0),
        at("R", b + 2 * HOUR, 15.0, R, 50.0),
        at("A", t2 + HOUR, 20.0, r2, 0.0),
        at("R", t2 + 2 * HOUR, 25.0, r2, 90.0),
        at("R", t2 + 3 * HOUR, 30.0, r2, 110.0),
        at("A", t2 + 4 * HOUR, 45.0, r2, 30.0),
    ]);
    let cal = run(&v);
    assert_eq!(win(&cal, r2).cost_usd, 50.0);
    assert_eq!(win(&cal, r2).fresh_sessions, 0);
    assert_eq!(win(&cal, R).cost_usd, 10.0);
}

#[test]
fn a_fall_marks_the_window_mixed() {
    // 24 → 23 is a fall; 24 → 23.6 (0.4) is not.
    let b = base();
    let mut v = with_anchor(vec![
        at("A", b + HOUR, 10.0, R, 0.0),
        at("A", b + 2 * HOUR, 24.0, R, 50.0),
        at("A", b + 3 * HOUR, 23.0, R, 80.0),
        at("A", b + 4 * HOUR, 30.0, R, 120.0),
    ]);
    let r2 = R + 43_200;
    v.extend(pair(r2, D7, "B", 10.0, 24.0, 0.0, 50.0));
    v.extend(vec![at("B", t0(r2) + 3 * HOUR, 23.6, r2, 80.0)]);
    v.extend(vec![at("B", t0(r2) + 4 * HOUR, 30.0, r2, 120.0)]);
    let cal = run(&v);
    assert_eq!(win(&cal, R).verdict, Verdict::Mixed);
    assert_eq!(win(&cal, r2).verdict, Verdict::Valid);
    assert_eq!(cal.windows.mixed, 1);
}

#[test]
fn samples_after_reaching_100_are_not_used() {
    // p 88, 95, 100, 100 with cost 0, 50, 70, 120: kept 88, 95, 100 → Δp 12, C 50 + 20 = 70.
    let b = base();
    let v = with_anchor(vec![
        at("A", b + HOUR, 88.0, R, 0.0),
        at("A", b + 2 * HOUR, 95.0, R, 50.0),
        at("A", b + 3 * HOUR, 100.0, R, 70.0),
        at("A", b + 4 * HOUR, 100.0, R, 120.0),
    ]);
    let cal = run(&v);
    let w = win(&cal, R);
    assert_eq!(w.dp5, 12.0);
    assert_eq!(w.cost_usd, 70.0);
    assert!(w.saturated);
    assert_eq!(cal.windows.saturated, 1);
    assert_eq!(w.last_ms, b + 3 * HOUR);
}

#[test]
fn seven_day_100_also_cuts() {
    let b = base();
    let d = |p| Some((p, D7));
    let v = with_anchor(vec![
        smp("A", b + HOUR, 10.0, R, d(97.0), Some(0.0)),
        smp("A", b + 2 * HOUR, 20.0, R, d(100.0), Some(40.0)),
        smp("A", b + 3 * HOUR, 30.0, R, d(100.0), Some(90.0)),
    ]);
    let w = win(&run(&v), R).clone();
    assert!(w.saturated);
    assert_eq!(w.dp5, 10.0);
    assert_eq!(w.cost_usd, 40.0);
}

#[test]
fn d7_only_samples_start_no_window() {
    let v = vec![
        anchor(),
        Sample {
            t: R * 1000 - HOUR,
            ..anchor()
        },
    ];
    let cal = run(&v);
    assert_eq!(cal.windows.seen, 0);
    assert_eq!(cal.status, Status::Collecting);
    assert_eq!(run(&[]).status, Status::NoSamples);
}

#[test]
fn second_account_in_the_same_hour() {
    // Same h5.r, different d7.r, interleaved: account A p 10 → 22 ($100), account B p 5 → 15
    // ($80). Pooled by h5.r alone they would fall (10 → 5) and be mixed.
    let b = base();
    let d7b = D7 + 86_400;
    let v = with_anchor(vec![
        smp("sa", b + HOUR, 10.0, R, Some((50.0, D7)), Some(0.0)),
        smp(
            "sb",
            b + HOUR + 600_000,
            5.0,
            R,
            Some((20.0, d7b)),
            Some(0.0),
        ),
        smp("sa", b + 2 * HOUR, 22.0, R, Some((51.0, D7)), Some(100.0)),
        smp(
            "sb",
            b + 2 * HOUR + 600_000,
            15.0,
            R,
            Some((21.0, d7b)),
            Some(80.0),
        ),
    ]);
    let cal = run(&v);
    assert_eq!(cal.windows.seen, 2);
    assert_eq!(cal.windows.mixed, 0);
    assert_eq!(cal.windows.valid, 2);
    assert_eq!(cal.groups.len(), 2);
    assert_ne!(cal.groups[0].d7_reset, cal.groups[1].d7_reset);
}

#[test]
fn selection_recent_newest_pooled_collecting() {
    let now_s = D7 - DAY;
    let run_at = |v: Vec<Sample>| calibrate(&with_anchor(v), &HashMap::new(), now_s * 1000);

    // recent: two groups newer than now − 7 d (plus one older); newest first.
    let mut v = valid_windows(now_s - 8 * DAY, R, 5, "old");
    v.extend(valid_windows(now_s + DAY, R + 10 * DAY, 5, "a"));
    v.extend(valid_windows(now_s + 2 * DAY, R + 20 * DAY, 5, "b"));
    let cal = run_at(v);
    assert_eq!(cal.status, Status::Ready);
    let d7s: Vec<_> = cal.rates.iter().map(|r| r.d7_reset).collect();
    assert_eq!(d7s, vec![Some(now_s + 2 * DAY), Some(now_s + DAY)]);
    assert!(cal.rates.iter().all(|r| r.selection == Selection::Recent));
    assert_eq!(cal.groups.len(), 3);

    // The cap of 4.
    let mut v = Vec::new();
    for i in 1..=6 {
        v.extend(valid_windows(
            now_s + i * DAY,
            R + i * 10 * DAY,
            5,
            &format!("g{i}"),
        ));
    }
    let cal = run_at(v);
    assert_eq!(cal.rates.len(), 4);
    assert_eq!(cal.rates[0].d7_reset, Some(now_s + 6 * DAY));
    assert_eq!(cal.rates[3].d7_reset, Some(now_s + 3 * DAY));

    // newest: nothing within 7 days; the newest qualifying group alone.
    let mut v = valid_windows(now_s - 20 * DAY, R, 5, "x");
    v.extend(valid_windows(now_s - 10 * DAY, R + 10 * DAY, 5, "y"));
    let cal = run_at(v);
    assert_eq!(cal.rates.len(), 1);
    assert_eq!(cal.rates[0].selection, Selection::Newest);
    assert_eq!(cal.rates[0].d7_reset, Some(now_s - 10 * DAY));

    // pooled: no group qualifies (2 windows each), all six together do.
    let mut v = Vec::new();
    for i in 0..3 {
        v.extend(valid_windows(
            now_s + (i + 1) * DAY,
            R + i * 10 * DAY,
            2,
            &format!("p{i}"),
        ));
    }
    let cal = run_at(v);
    assert_eq!(cal.rates.len(), 1);
    let r = &cal.rates[0];
    assert_eq!(r.selection, Selection::Pooled);
    assert_eq!(r.d7_reset, None);
    assert_eq!((r.windows, r.account_weeks), (6, 3));

    // collecting: three valid windows only.
    let cal = run_at(valid_windows(now_s + DAY, R, 3, "c"));
    assert_eq!(cal.status, Status::Collecting);
    assert!(cal.rates.is_empty());
    assert_eq!(cal.windows.valid, 3);
}

#[test]
fn needs_five_windows_on_two_days() {
    // Four valid windows on three days: collecting.
    let cal = run(&with_anchor(valid_windows(D7, R, 4, "a")));
    assert_eq!(cal.status, Status::Collecting);
    assert!(!cal.groups[0].qualifies);

    // Five windows 30 min apart, all first samples at noon UTC: one day.
    let noon = (R / DAY + 1) * DAY + 12 * 3600 + 14_400;
    let mut v = Vec::new();
    for i in 0..5 {
        v.extend(pair(
            noon + i * 1800,
            D7,
            &format!("d{i}"),
            10.0,
            22.0,
            0.0,
            100.0,
        ));
    }
    let cal = run(&with_anchor(v));
    assert_eq!(cal.windows.valid, 5);
    assert_eq!(cal.groups[0].days, 1);
    assert!(!cal.groups[0].qualifies);
    assert_eq!(cal.status, Status::Collecting);
}

#[test]
fn seven_day_rate_needs_ten_points() {
    // Five windows, Δp5 12 and C $100 each (ΣC = 500). Σ Δp7 = 9, then 10.
    let build = |rises: [f64; 5]| {
        let mut v = vec![anchor()];
        for (i, up) in rises.iter().enumerate() {
            let r = R + i as i64 * 43_200;
            let (a, b) = (30.0 + i as f64 * 3.0, 30.0 + i as f64 * 3.0 + up);
            v.push(smp(
                &format!("s{i}"),
                t0(r) + HOUR,
                10.0,
                r,
                Some((a, D7)),
                Some(0.0),
            ));
            v.push(smp(
                &format!("s{i}"),
                t0(r) + 2 * HOUR,
                22.0,
                r,
                Some((b, D7)),
                Some(100.0),
            ));
        }
        run(&v)
    };
    let nine = build([2.0, 2.0, 2.0, 2.0, 1.0]);
    assert_eq!(nine.rates[0].dp7_sum, 9.0);
    assert!(nine.rates[0].k7.is_none());
    let ten = build([2.0, 2.0, 2.0, 2.0, 2.0]);
    assert_eq!(ten.rates[0].dp7_sum, 10.0);
    assert_eq!(ten.rates[0].k7.unwrap().w1, 10.0 / 500.0);
}

#[test]
fn spread_is_nearest_rank() {
    // Ratios 0.5, 1, ..., 3.5 (Δp 10..70 over $20; ratios 1-7 would need Δp > 100):
    // median rank 4 = 2.0, p25 rank 2 = 1.0, p75 rank 6 = 3.0.
    let mut v = vec![anchor()];
    for i in 0..7 {
        let dp = 10.0 + 10.0 * i as f64;
        v.extend(pair(
            R + i * 43_200,
            D7,
            &format!("s{i}"),
            5.0,
            5.0 + dp,
            0.0,
            20.0,
        ));
    }
    let cal = run(&v);
    let s = cal.rates[0].spread5;
    assert_eq!((s.median, s.p25, s.p75), (2.0, 1.0, 3.0));
}

fn priced(cost: f64, cr: f64) -> SessionInfo {
    SessionInfo {
        start_ms: None,
        cost_usd: Some(cost),
        cache_read_usd: Some(cr),
        unpriced: false,
    }
}

#[test]
fn cache_read_band() {
    // Five windows (Δp 12, $100) = k 0.12. Three sessions with σ = 45 / 100 = 0.45:
    // w0 = k / 0.55, w10 = k / (1 + 9 × 0.45) = k / 5.05.
    let v = with_anchor(valid_windows(D7, R, 5, "s"));
    let k = 0.12;
    let mut s: HashMap<String, SessionInfo> = (0..3)
        .map(|i| (format!("s-{i}"), priced(100.0, 45.0)))
        .collect();
    let cal = calibrate(&v, &s, R * 1000);
    let r = &cal.rates[0];
    close(r.k5.w1, k);
    close(r.k5.w0.unwrap(), k / 0.55);
    close(r.k5.w10.unwrap(), k / 5.05);
    close(r.cache_read_share.unwrap(), 0.45);
    assert_eq!((r.sessions_with_totals, r.sessions_without_totals), (3, 2));
    assert_eq!(r.unpriced_sessions, 0);

    // An unpriced session is left out and counted; the three priced ones still give σ.
    s.insert(
        "s-3".into(),
        SessionInfo {
            cost_usd: Some(500.0),
            unpriced: true,
            ..SessionInfo::default()
        },
    );
    let r = &calibrate(&v, &s, R * 1000).rates[0];
    close(r.cache_read_share.unwrap(), 0.45);
    assert_eq!((r.sessions_with_totals, r.unpriced_sessions), (3, 1));

    // Two priced sessions: no band, only w1.
    s.remove("s-2");
    let r = &calibrate(&v, &s, R * 1000).rates[0];
    assert!(r.cache_read_share.is_none());
    assert!(r.k5.w0.is_none() && r.k5.w10.is_none());
    close(r.k5.w1, k);
    assert_eq!((r.sessions_with_totals, r.unpriced_sessions), (2, 1));
}

// ---- transcripts ---------------------------------------------------------------------

fn write(dir: &Path, project: &str, sid: &str, content: &str) {
    let d = dir.join(project);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join(format!("{sid}.jsonl")), content).unwrap();
}

fn pad(bytes: usize) -> String {
    let line = format!(
        "{{\"type\":\"assistant\",\"pad\":\"{}\"}}\n",
        "a".repeat(990)
    );
    line.repeat(bytes / line.len() + 1)
}

fn cost_state(total: f64, usage: &str) -> String {
    format!(
        "{{\"type\":\"cost-state\",\"sessionId\":\"x\",\"totalCostUSD\":{total},\"modelUsage\":{usage}}}\n"
    )
}

#[test]
fn totals_read_head_and_tail() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let ts = |s: &str| format!("{{\"type\":\"user\",\"timestamp\":\"{s}\",\"x\":1}}\n");
    let usage = r#"{"claude-opus-5-5":{"cacheReadInputTokens":1000000,"costUSD":9},"claude-haiku-4-5-20251001":{"cacheReadInputTokens":2000000,"costUSD":1}}"#;

    // s1: timestamp on line 1; two cost-state lines, the last one wins.
    // cache reads: 1M × 0.20 + 2M × 0.10 = $0.40.
    write(
        dir,
        "proj-a",
        "s1",
        &format!(
            "{}{}{}{}{}",
            ts("2026-10-01T00:00:00.000Z"),
            cost_state(1.0, "{}"),
            pad(5000),
            cost_state(10.0, usage),
            "",
        ),
    );
    // s2: first timestamp 20 KiB in (inside the head, after two 8 KiB steps); no cost-state.
    write(
        dir,
        "proj-a",
        "s2",
        &format!("{}{}", pad(20_000), ts("2026-09-30T16:00:00+00:00")),
    );
    // s3: timestamp after 70 KiB: not in the first 64 KiB. cost-state in the last 32 KiB.
    write(
        dir,
        "proj-b",
        "s3",
        &format!(
            "{}{}{}",
            pad(70_000),
            ts("2026-10-01T02:00:00Z"),
            cost_state(3.5, "{}")
        ),
    );
    // s4: cost-state lies before the last 32 KiB.
    write(
        dir,
        "proj-b",
        "s4",
        &format!(
            "{}{}{}",
            ts("2026-10-01T03:00:00Z"),
            cost_state(4.0, "{}"),
            pad(40_000)
        ),
    );
    // s5: a model without a price. s6: a cost-state line that does not parse.
    write(
        dir,
        "proj-b",
        "s5",
        &cost_state(
            5.0,
            r#"{"claude-opus-5-5":{"cacheReadInputTokens":1000000},"claude-mystery-9":{"cacheReadInputTokens":5}}"#,
        ),
    );
    write(
        dir,
        "proj-b",
        "s6",
        &format!(
            "{}{}",
            cost_state(6.0, "{}"),
            "{\"type\":\"cost-state\",\"totalCostUSD\":"
        ),
    );
    // other: a session nobody asked for.
    write(dir, "proj-b", "other", &cost_state(99.0, "{}"));

    let want: HashSet<String> = ["s1", "s2", "s3", "s4", "s5", "s6", "gone"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let got = totals::read(dir, &want);
    assert!(!got.contains_key("other") && !got.contains_key("gone"));
    assert_eq!(got.len(), 6);

    let ms = |s: &str| {
        time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .unwrap()
            .unix_timestamp()
            * 1000
    };
    let s1 = &got["s1"];
    assert_eq!(s1.start_ms, Some(ms("2026-10-01T00:00:00Z")));
    assert_eq!(s1.cost_usd, Some(10.0));
    close(s1.cache_read_usd.unwrap(), 0.40);
    assert!(!s1.unpriced);

    let s2 = &got["s2"];
    assert_eq!(s2.start_ms, Some(ms("2026-09-30T16:00:00+00:00")));
    assert_eq!((s2.cost_usd, s2.cache_read_usd), (None, None));

    let s3 = &got["s3"];
    assert_eq!(s3.start_ms, None);
    assert_eq!(s3.cost_usd, Some(3.5));
    assert_eq!(s3.cache_read_usd, Some(0.0));

    let s4 = &got["s4"];
    assert_eq!(s4.start_ms, Some(ms("2026-10-01T03:00:00Z")));
    assert_eq!(s4.cost_usd, None);

    let s5 = &got["s5"];
    assert!(s5.unpriced);
    assert_eq!((s5.cost_usd, s5.cache_read_usd), (Some(5.0), None));

    // The broken last line is absent; the earlier valid line is not used instead.
    assert_eq!(got["s6"].cost_usd, None);
}

#[test]
fn cache_read_price_matches_exact_or_dated_ids() {
    assert_eq!(cache_read_price("claude-haiku-4-5-20251001"), Some(0.10));
    assert_eq!(cache_read_price("claude-haiku-4-5"), Some(0.10));
    assert_eq!(cache_read_price("claude-opus-5-5"), Some(0.20));
    assert_eq!(cache_read_price("claude-opus-5"), Some(0.50));
    assert_eq!(cache_read_price("claude-opus-5-5-20260101"), Some(0.20));
    assert_eq!(cache_read_price("claude-opus-5-5-preview"), None);
    assert_eq!(cache_read_price("claude-opus-5-5-2026"), None);
    assert_eq!(cache_read_price("claude-fable-5-1"), Some(0.25));
    assert_eq!(cache_read_price("claude-fable-5"), Some(1.00));
    assert_eq!(cache_read_price("claude-sonnet-4-6"), Some(0.30));
    assert_eq!(cache_read_price("claude-sonnet-5-5"), Some(0.20));
    assert_eq!(cache_read_price("claude-opus-4-8"), Some(0.50));
    assert_eq!(cache_read_price("claude-opus-4-9"), None);
    assert_eq!(cache_read_price("gpt-5"), None);
    assert_eq!(cache_read_price(""), None);
}
