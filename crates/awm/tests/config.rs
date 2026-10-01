use awm::config::{self, Config, Mode, PromptBm25, ShortCircuitMode};

#[test]
fn defaults_match_the_plan() {
    let c = Config::default();
    assert_eq!(c.mode, Mode::Inject);
    assert_eq!(c.get("notify").unwrap(), "first");
    assert!(c.channels.url && c.channels.query && c.channels.prompt_url);
    assert_eq!(c.channels.prompt_bm25, PromptBm25::Off);
    assert_eq!(c.short_circuit.mode, ShortCircuitMode::Shadow);
    assert_eq!(c.short_circuit.window_minutes, 30);
    assert!(!c.short_circuit.subagents);
    assert_eq!((c.inject.max_notes, c.inject.max_per_agent), (3, 10));
    assert_eq!(c.hooks.deadline_ms, 500);
    assert!(c.capture.exclude_hosts.is_empty() && c.capture.redact_terms.is_empty());
    assert_eq!(c.review.daily_limit, 10);
}

#[test]
fn missing_file_gives_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let c = config::load(&dir.path().join("config.toml")).unwrap();
    assert_eq!(c, Config::default());
    assert!(c.warnings.is_empty());
}

#[test]
fn round_trip_through_save_and_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub/config.toml");
    let mut c = Config::default();
    c.set("mode", "shadow").unwrap();
    c.set("channels.prompt_bm25", "shadow").unwrap();
    c.set("short_circuit.subagents", "true").unwrap();
    c.set("hooks.deadline_ms", "800").unwrap();
    c.set("capture.exclude_hosts", "*.corp.example, wiki.example")
        .unwrap();
    c.set("capture.redact_terms", "Acme").unwrap();
    c.save(&path).unwrap();
    let back = config::load(&path).unwrap();
    assert_eq!(back, c);
    assert_eq!(
        back.get("capture.exclude_hosts").unwrap(),
        "*.corp.example,wiki.example"
    );
}

#[test]
fn out_of_range_values_are_clamped_with_warnings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[inject]\nmax_notes = 9\nmax_per_agent = -4\n[hooks]\ndeadline_ms = 50\n\
         [short_circuit]\nwindow_minutes = 5000\n[review]\ndaily_limit = 0\n",
    )
    .unwrap();
    let c = config::load(&path).unwrap();
    assert_eq!(c.inject.max_notes, 3);
    assert_eq!(c.inject.max_per_agent, 0);
    assert_eq!(c.hooks.deadline_ms, 100);
    assert_eq!(c.short_circuit.window_minutes, 1440);
    assert_eq!(c.review.daily_limit, 1);
    // max_per_agent 0 is in range (0-100) after the negative becomes 0.
    assert_eq!(c.warnings.len(), 4, "{:?}", c.warnings);
    assert!(c.warnings.iter().any(|w| w.contains("hooks.deadline_ms")));
}

#[test]
fn unknown_keys_are_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "future = 1\nmode = \"off\"\n[channels]\nurl = false\nnew_channel = true\n[nope]\nx = 1\n",
    )
    .unwrap();
    let c = config::load(&path).unwrap();
    assert_eq!(c.mode, Mode::Off);
    assert!(!c.channels.url);
    assert!(c.channels.query);
    assert!(c.warnings.is_empty());
}

#[test]
fn set_rejects_bad_keys_and_values() {
    let mut c = Config::default();
    assert!(c.set("nope", "1").is_err());
    assert!(c.set("mode", "loud").is_err());
    assert!(c.set("inject.max_notes", "4").is_err());
    assert!(c.set("channels.url", "yes").is_err());
    assert_eq!(c, Config::default());
    assert_eq!(c.get("nope"), None);
}
