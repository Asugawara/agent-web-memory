//! Which local rows may be shared (plan-v3-team §3.4, §4.6 step 3; TM9).

/// Whether a record from `project_path` fetching `host` may be shared.
///
/// Implements plan-v3-team §3.4.
pub fn is_eligible(_project_path: &str, _host: &str) -> bool {
    todo!("TM9: eligibility")
}
