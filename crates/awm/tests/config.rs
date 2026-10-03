use awm::config::{self, Config, Mode, PromptBm25, ShortCircuitMode};

#[test]
fn defaults_match_the_plan() {
    let c = Config::default();
    assert_eq!(c.mode, Mode::Inject);
    assert_eq!(c.get("notify").unwrap(), "first");
    assert!(c.channels.url && c.channels.query && c.channels.prompt_url);
    assert_eq!(c.channels.prompt_bm25, PromptBm25::Off);
    assert_eq!(c.short_circuit.mode, ShortCircuitMode::On);
    assert_eq!(c.short_circuit.window_days, 7);
    assert_eq!(c.short_circuit.query, ShortCircuitMode::On);
    assert_eq!(c.short_circuit.query_window_days, 7);
    assert_eq!(c.get("short_circuit.mode").unwrap(), "on");
    assert_eq!(c.get("short_circuit.query").unwrap(), "on");
    assert_eq!(c.get("short_circuit.window_days").unwrap(), "7");
    assert_eq!(c.get("short_circuit.query_window_days").unwrap(), "7");
    assert_eq!(c.inject.max_notes, 3);
    assert_eq!(c.hooks.deadline_ms, 500);
    assert!(c.capture.exclude_hosts.is_empty() && c.capture.redact_terms.is_empty());
    assert_eq!(c.review.daily_limit, 10);
    assert_eq!(c.pricing.currency, "USD");
    assert_eq!(c.pricing.summariser_input_per_mtok, 1.0);
    assert_eq!(c.pricing.summariser_output_per_mtok, 5.0);
    assert_eq!(c.pricing.search_fee_per_call, 0.01);
    assert_eq!(c.pricing.main_input_per_mtok, 0.0);
    assert_eq!(c.get("pricing.search_fee_per_call").unwrap(), "0.01");
}

#[test]
fn pricing_file_overrides_two_rates_and_keeps_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[pricing]\nsummariser_input_per_mtok = 0.8\nmain_input_per_mtok = 3\n",
    )
    .unwrap();
    let c = config::load(&path).unwrap();
    assert_eq!(c.pricing.summariser_input_per_mtok, 0.8);
    assert_eq!(c.pricing.main_input_per_mtok, 3.0);
    assert_eq!(c.pricing.summariser_output_per_mtok, 5.0);
    assert_eq!(c.pricing.currency, "USD");
    c.save(&path).unwrap();
    assert_eq!(config::load(&path).unwrap(), c);
}

#[test]
fn negative_pricing_is_a_config_error_naming_the_field() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "[pricing]\nsearch_fee_per_call = -0.01\n").unwrap();
    let err = format!("{:#}", config::load(&path).unwrap_err());
    assert!(err.contains("search_fee_per_call"), "{err}");
    let mut c = Config::default();
    let err = c.set("pricing.main_input_per_mtok", "-1").unwrap_err();
    assert!(
        err.to_string().contains("pricing.main_input_per_mtok"),
        "{err}"
    );
    assert_eq!(c, Config::default());
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
    c.set("mode", "off").unwrap();
    c.set("channels.prompt_bm25", "inject").unwrap();
    c.set("short_circuit.mode", "off").unwrap();
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
        "[inject]\nmax_notes = 9\n[hooks]\ndeadline_ms = 50\n\
         [short_circuit]\nwindow_days = 5000\n[review]\ndaily_limit = 0\n",
    )
    .unwrap();
    let c = config::load(&path).unwrap();
    assert_eq!(c.inject.max_notes, 3);
    assert_eq!(c.hooks.deadline_ms, 100);
    assert_eq!(c.short_circuit.window_days, 365);
    assert_eq!(c.review.daily_limit, 1);
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

#[cfg(unix)]
#[test]
fn save_writes_the_file_with_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    // An existing world-readable file is tightened too.
    std::fs::write(&path, "").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    Config::default().save(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn query_min_score_is_optional_ranged_and_round_trips() {
    let mut c = Config::default();
    assert_eq!(c.short_circuit.query_min_score, None);
    assert_eq!(c.get("short_circuit.query_min_score").unwrap(), "auto");
    c.set("short_circuit.query_min_score", "42.5").unwrap();
    assert_eq!(c.short_circuit.query_min_score, Some(42.5));
    assert_eq!(c.get("short_circuit.query_min_score").unwrap(), "42.5");
    c.set("short_circuit.query_min_score", "0").unwrap();
    c.set("short_circuit.query_min_score", "1000").unwrap();
    assert_eq!(c.short_circuit.query_min_score, Some(1000.0));
    for bad in ["-1", "1000.5", "nan", "inf", "high"] {
        assert!(
            c.set("short_circuit.query_min_score", bad).is_err(),
            "{bad}"
        );
    }
    assert_eq!(c.short_circuit.query_min_score, Some(1000.0));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    c.set("short_circuit.query_min_score", "40").unwrap();
    c.save(&path).unwrap();
    assert_eq!(config::load(&path).unwrap(), c);
    // An integer in the file reads as a float; an out-of-range value is clamped with a warning.
    std::fs::write(&path, "[short_circuit]\nquery_min_score = 55\n").unwrap();
    let loaded = config::load(&path).unwrap();
    assert_eq!(loaded.short_circuit.query_min_score, Some(55.0));
    assert!(loaded.warnings.is_empty());
    std::fs::write(&path, "[short_circuit]\nquery_min_score = 5000.0\n").unwrap();
    let loaded = config::load(&path).unwrap();
    assert_eq!(loaded.short_circuit.query_min_score, Some(1000.0));
    assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
    // `auto` clears it again and nothing is written for a default file.
    c.set("short_circuit.query_min_score", "auto").unwrap();
    assert_eq!(c.short_circuit.query_min_score, None);
}

#[test]
fn the_query_deny_keys_set_validate_and_clamp() {
    let mut c = Config::default();
    c.set("short_circuit.query", "on").unwrap();
    c.set("short_circuit.query_window_days", "365").unwrap();
    assert_eq!(c.short_circuit.query, ShortCircuitMode::On);
    assert_eq!(c.get("short_circuit.query_window_days").unwrap(), "365");
    assert!(c.set("short_circuit.query", "maybe").is_err());
    assert!(c.set("short_circuit.query_window_days", "0").is_err());
    assert!(c.set("short_circuit.query_window_days", "366").is_err());
    assert_eq!(c.short_circuit.query_window_days, 365);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    c.save(&path).unwrap();
    assert_eq!(config::load(&path).unwrap(), c);
    std::fs::write(
        &path,
        "[short_circuit]\nquery = \"off\"\nquery_window_days = 99999\n",
    )
    .unwrap();
    let loaded = config::load(&path).unwrap();
    assert_eq!(loaded.short_circuit.query, ShortCircuitMode::Off);
    assert_eq!(loaded.short_circuit.query_window_days, 365);
    assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
}

#[test]
fn team_defaults_parse_set_and_clamp() {
    use awm::config::AutoApprove;
    let c = Config::default();
    assert!(c.team.auto_sync && c.team.show);
    assert_eq!(c.team.sync_interval_s, 60);
    assert!(c.team.mute.is_empty() && c.team.exclude_hosts.is_empty());
    assert!(!c.team.share_all_projects && !c.team.share_stats);
    assert_eq!(c.team.summary_chars, 1000);
    // RVT2 m3: no join is approved without the 6-digit code unless the user opts in.
    assert_eq!(c.team.auto_approve, AutoApprove::None);
    assert_eq!(c.team.push_delay_s, 0);
    for (key, want) in [
        ("team.auto_sync", "true"),
        ("team.sync_interval_s", "60"),
        ("team.show", "true"),
        ("team.mute", ""),
        ("team.share_all_projects", "false"),
        ("team.exclude_hosts", ""),
        ("team.summary_chars", "1000"),
        ("team.share_stats", "false"),
        ("team.auto_approve", "none"),
        ("team.push_delay_s", "0"),
    ] {
        assert_eq!(c.get(key).as_deref(), Some(want), "{key}");
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[team]\nmute = [\"@a\", \"@b\"]\nauto_approve = \"all\"\nsummary_chars = 5000\n",
    )
    .unwrap();
    let loaded = config::load(&path).unwrap();
    assert_eq!(loaded.team.mute, ["@a", "@b"]);
    assert_eq!(loaded.team.auto_approve, AutoApprove::All);
    assert_eq!(loaded.team.summary_chars, 2000);
    assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
    assert!(loaded.warnings[0].contains("team.summary_chars"));
    assert!(loaded.team.auto_sync);

    let mut c = Config::default();
    assert!(c.set("team.summary_chars", "2001").is_err());
    assert!(c.set("team.auto_approve", "everyone").is_err());
    assert!(c.set("team.show", "maybe").is_err());
    assert_eq!(c, Config::default());
    c.set("team.mute", "@a, @b").unwrap();
    c.set("team.auto_approve", "all").unwrap();
    c.set("team.push_delay_s", "900").unwrap();
    // TM14: `set` stores bare handles (an `@` is accepted and dropped).
    assert_eq!(c.get("team.mute").unwrap(), "a,b");
    assert_eq!(c.get("team.auto_approve").unwrap(), "all");
    c.set("team.auto_approve", "devices").unwrap();
    assert_eq!(c.team.auto_approve, AutoApprove::Devices);
    c.set("team.auto_approve", "none").unwrap();
    assert_eq!(c.team.auto_approve, AutoApprove::None);
    assert_eq!(c.get("team.push_delay_s").unwrap(), "900");
}

#[test]
fn quota_defaults_ranges_and_set_errors() {
    let c = Config::default();
    assert!(c.quota.capture);
    assert_eq!(c.quota.retention_days, 92);
    assert_eq!(c.get("quota.capture").unwrap(), "true");
    assert_eq!(c.get("quota.retention_days").unwrap(), "92");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "[quota]\nretention_days = 5\n").unwrap();
    let loaded = config::load(&path).unwrap();
    assert_eq!(loaded.quota.retention_days, 7);
    assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
    assert!(loaded.warnings[0].contains("quota.retention_days"));
    assert!(loaded.quota.capture);
    std::fs::write(&path, "[quota]\nretention_days = 99999\n").unwrap();
    assert_eq!(config::load(&path).unwrap().quota.retention_days, 3650);

    let mut c = Config::default();
    c.save(&path).unwrap();
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(c.set("quota.retention_days", "3651").is_err());
    assert!(c.set("quota.retention_days", "6").is_err());
    assert!(c.set("quota.capture", "maybe").is_err());
    assert_eq!(c, Config::default());
    c.set("quota.retention_days", "7").unwrap();
    c.set("quota.capture", "false").unwrap();
    assert_eq!(c.get("quota.retention_days").unwrap(), "7");
    assert_eq!(c.get("quota.capture").unwrap(), "false");
    // The file the failed sets would have written is untouched (`save` runs after `set`).
    assert_eq!(std::fs::read_to_string(&path).unwrap(), saved);
}

#[test]
fn legacy_shadow_values_load_with_the_mapping_and_removed_keys_are_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "mode = \"shadow\"\n[channels]\nprompt_bm25 = \"shadow\"\n\
         [short_circuit]\nmode = \"shadow\"\nquery = \"shadow\"\nsubagents = true\nwindow_minutes = 30\nquery_window_minutes = 60\n\
         [inject]\nmax_per_agent = 4\nmax_notes = 2\n",
    )
    .unwrap();
    let (c, legacy) = config::load_with_legacy(&path).unwrap();
    assert_eq!(c.mode, Mode::Inject);
    assert_eq!(c.channels.prompt_bm25, PromptBm25::Off);
    assert_eq!(c.short_circuit.mode, ShortCircuitMode::On);
    assert_eq!(c.short_circuit.query, ShortCircuitMode::Off);
    assert_eq!(c.inject.max_notes, 2);
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    // One line per legacy value or key, with the replacement.
    assert_eq!(legacy.len(), 8, "{legacy:?}");
    assert_eq!(c.short_circuit.query_window_days, 7);
    assert!(legacy
        .iter()
        .any(|l| l.contains("query_window_minutes") && l.contains("query_window_days")));
    assert_eq!(c.short_circuit.window_days, 7);
    assert!(legacy
        .iter()
        .any(|l| l.contains("short_circuit.window_minutes")
            && l.contains("short_circuit.window_days")));
    assert!(legacy.contains(
        &"config: mode = \"shadow\" is read as \"inject\"; set it to inject or off".to_string()
    ));
    assert!(legacy.iter().any(|l| l.contains("short_circuit.subagents")));
    assert!(legacy.iter().any(|l| l.contains("inject.max_per_agent")));
    // `load` reads the same and saving drops the removed keys.
    assert_eq!(config::load(&path).unwrap(), c);
    c.save(&path).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !text.contains("shadow") && !text.contains("subagents"),
        "{text}"
    );
    assert!(!text.contains("max_per_agent"), "{text}");
    assert!(config::load_with_legacy(&path).unwrap().1.is_empty());
}

#[test]
fn set_refuses_shadow_and_the_removed_keys_naming_the_replacement() {
    let mut c = Config::default();
    for (key, hint) in [
        ("mode", "inject or off"),
        ("channels.prompt_bm25", "inject or off"),
        ("short_circuit.mode", "on or off"),
        ("short_circuit.query", "on or off"),
    ] {
        let err = c.set(key, "shadow").unwrap_err().to_string();
        assert!(err.contains("shadow mode was removed"), "{key}: {err}");
        assert!(err.contains(hint), "{key}: {err}");
    }
    let err = c.set("short_circuit.subagents", "true").unwrap_err();
    assert!(err.to_string().contains("was removed"), "{err}");
    let err = c.set("short_circuit.window_minutes", "30").unwrap_err();
    assert!(
        err.to_string().contains("short_circuit.window_days"),
        "{err}"
    );
    let err = c
        .set("short_circuit.query_window_minutes", "60")
        .unwrap_err();
    assert!(err.to_string().contains("query_window_days"), "{err}");
    let err = c.set("inject.max_per_agent", "5").unwrap_err();
    assert!(err.to_string().contains("inject.max_notes"), "{err}");
    assert_eq!(c.get("short_circuit.subagents"), None);
    assert_eq!(c.get("inject.max_per_agent"), None);
    assert_eq!(c, Config::default());
    assert!(c.set("short_circuit.window_days", "366").is_err());
    c.set("short_circuit.window_days", "365").unwrap();
}
