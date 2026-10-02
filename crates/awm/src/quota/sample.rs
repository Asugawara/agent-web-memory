//! One status line sample (plan-quota §4.1).

use serde_json::Value;

/// Longest session id that is recorded. Keeps a line far below the 8 KiB tail the
/// dedupe reads.
const MAX_SID: usize = 128;
const MAX_MODEL: usize = 64;

/// One usage window: percent used and the Unix second at which it resets.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Window {
    pub p: f64,
    pub r: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// awm's clock at capture, unix ms.
    pub t: i64,
    pub sid: String,
    pub model: Option<String>,
    pub h5: Option<Window>,
    pub d7: Option<Window>,
    pub cost: Option<f64>,
    pub dur: Option<i64>,
}

/// A window of `rate_limits` when `0 <= used_percentage <= 100` and `resets_at > 0`.
pub(crate) fn window(v: &Value) -> Option<Window> {
    let p = v.get("used_percentage")?.as_f64()?;
    let r = v.get("resets_at")?;
    let r = r.as_i64().or_else(|| {
        let f = r.as_f64()?;
        (f.is_finite() && f.abs() < 9e15).then_some(f as i64)
    })?;
    ((0.0..=100.0).contains(&p) && r > 0).then_some(Window { p, r })
}

fn num(p: f64) -> String {
    if p.fract() == 0.0 {
        format!("{}", p as i64)
    } else {
        format!("{p}")
    }
}

impl Sample {
    /// The sample of one status line payload; `None` when nothing may be written
    /// (no session id, or no window).
    pub fn from_statusline(v: &Value, now_ms: i64) -> Option<Sample> {
        let sid = v.get("session_id")?.as_str()?;
        if sid.is_empty() || sid.len() > MAX_SID {
            return None;
        }
        let limits = v.get("rate_limits");
        let h5 = limits.and_then(|l| l.get("five_hour")).and_then(window);
        let d7 = limits.and_then(|l| l.get("seven_day")).and_then(window);
        if h5.is_none() && d7.is_none() {
            return None;
        }
        let model = v
            .pointer("/model/id")
            .and_then(Value::as_str)
            .filter(|m| {
                !m.is_empty()
                    && m.len() <= MAX_MODEL
                    && m.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
            })
            .map(str::to_string);
        let cost = v
            .pointer("/cost/total_cost_usd")
            .and_then(Value::as_f64)
            .filter(|c| c.is_finite() && *c >= 0.0);
        let dur = v
            .pointer("/cost/total_duration_ms")
            .and_then(Value::as_f64)
            .filter(|d| d.is_finite() && *d >= 0.0 && *d < 9e15)
            .map(|d| d as i64);
        Some(Sample {
            t: now_ms,
            sid: sid.to_string(),
            model,
            h5,
            d7,
            cost,
            dur,
        })
    }

    /// The JSON line (no newline), keys in the order of plan-quota §4.1.
    pub fn to_line(&self) -> String {
        let mut s = format!(
            "{{\"v\":1,\"t\":{},\"sid\":{}",
            self.t,
            Value::String(self.sid.clone())
        );
        if let Some(m) = &self.model {
            s.push_str(&format!(",\"model\":{}", Value::String(m.clone())));
        }
        for (key, w) in [("h5", &self.h5), ("d7", &self.d7)] {
            if let Some(w) = w {
                s.push_str(&format!(",\"{key}\":{{\"p\":{},\"r\":{}}}", num(w.p), w.r));
            }
        }
        if let Some(c) = self.cost {
            s.push_str(&format!(",\"cost\":{c}"));
        }
        if let Some(d) = self.dur {
            s.push_str(&format!(",\"dur\":{d}"));
        }
        s.push('}');
        s
    }

    /// Parses one line; `v` must be 1 and `t` and `sid` must be present.
    pub fn parse_line(line: &str) -> Option<Sample> {
        let v: Value = serde_json::from_str(line.trim()).ok()?;
        if v.get("v")?.as_i64()? != 1 {
            return None;
        }
        let win = |key: &str| {
            let w = v.get(key)?;
            Some(Window {
                p: w.get("p")?.as_f64()?,
                r: w.get("r")?.as_i64()?,
            })
        };
        Some(Sample {
            t: v.get("t")?.as_i64()?,
            sid: v.get("sid")?.as_str()?.to_string(),
            model: v.get("model").and_then(Value::as_str).map(str::to_string),
            h5: win("h5"),
            d7: win("d7"),
            cost: v.get("cost").and_then(Value::as_f64),
            dur: v.get("dur").and_then(Value::as_i64),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn payload() -> Value {
        json!({
            "session_id": "s1",
            "model": {"id": "claude-opus-5-5"},
            "cost": {"total_cost_usd": 1.5, "total_duration_ms": 1000.0},
            "rate_limits": {
                "five_hour": {"used_percentage": 24, "resets_at": 100},
                "seven_day": {"used_percentage": 41.5, "resets_at": 200}
            }
        })
    }

    #[test]
    fn line_round_trips_with_keys_in_order() {
        let s = Sample::from_statusline(&payload(), 5).unwrap();
        let line = s.to_line();
        assert_eq!(
            line,
            r#"{"v":1,"t":5,"sid":"s1","model":"claude-opus-5-5","h5":{"p":24,"r":100},"d7":{"p":41.5,"r":200},"cost":1.5,"dur":1000}"#
        );
        assert_eq!(Sample::parse_line(&line), Some(s));
    }

    #[test]
    fn parse_line_rejects_other_versions_and_garbage() {
        assert!(Sample::parse_line(r#"{"v":2,"t":1,"sid":"a"}"#).is_none());
        assert!(Sample::parse_line(r#"{"v":1,"t":1,"sid":"a""#).is_none());
        assert!(Sample::parse_line(r#"{"v":1,"t":1,"sid":"a"}"#).is_some());
    }

    #[test]
    fn rules_drop_invalid_fields() {
        let mut v = payload();
        v["model"]["id"] = json!("modèle");
        v["cost"]["total_cost_usd"] = json!(-1.0);
        v["cost"]["total_duration_ms"] = json!(-5);
        v["rate_limits"]["five_hour"]["used_percentage"] = json!(100.5);
        let s = Sample::from_statusline(&v, 1).unwrap();
        assert!(s.model.is_none() && s.cost.is_none() && s.dur.is_none());
        assert!(s.h5.is_none() && s.d7.is_some());
        v["model"]["id"] = json!("a".repeat(65));
        assert!(Sample::from_statusline(&v, 1).unwrap().model.is_none());
        v["model"]["id"] = json!("a".repeat(64));
        assert!(Sample::from_statusline(&v, 1).unwrap().model.is_some());
    }

    #[test]
    fn no_sample_without_session_or_window() {
        let mut v = payload();
        v["session_id"] = json!("");
        assert!(Sample::from_statusline(&v, 1).is_none());
        let mut v = payload();
        v["rate_limits"]["five_hour"]["resets_at"] = json!(0);
        v["rate_limits"]["seven_day"]["used_percentage"] = json!(-1);
        assert!(Sample::from_statusline(&v, 1).is_none());
    }

    #[test]
    fn boundary_percentages_are_kept() {
        let mut v = payload();
        v["rate_limits"]["five_hour"]["used_percentage"] = json!(0);
        v["rate_limits"]["seven_day"]["used_percentage"] = json!(100);
        let s = Sample::from_statusline(&v, 1).unwrap();
        assert_eq!(s.h5.unwrap().p, 0.0);
        assert_eq!(s.d7.unwrap().p, 100.0);
    }
}
