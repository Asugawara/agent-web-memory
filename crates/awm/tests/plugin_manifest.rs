use serde_json::Value;
use std::fs;
use std::path::Path;

#[test]
fn test_plugin_manifest() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let repo_root = Path::new(&manifest_dir)
        .join("../..")
        .canonicalize()
        .expect("Failed to canonicalize repo root");

    // Read and parse plugin.json
    let plugin_json_path = repo_root.join("plugin/.claude-plugin/plugin.json");
    let plugin_json_text =
        fs::read_to_string(&plugin_json_path).expect("Failed to read plugin.json");
    let plugin_json: Value =
        serde_json::from_str(&plugin_json_text).expect("Failed to parse plugin.json");

    // Read and parse hooks.json
    let hooks_json_path = repo_root.join("plugin/hooks/hooks.json");
    let hooks_json_text = fs::read_to_string(&hooks_json_path).expect("Failed to read hooks.json");
    let hooks_json: Value =
        serde_json::from_str(&hooks_json_text).expect("Failed to parse hooks.json");

    // Read and parse marketplace.json
    let marketplace_json_path = repo_root.join(".claude-plugin/marketplace.json");
    let marketplace_json_text =
        fs::read_to_string(&marketplace_json_path).expect("Failed to read marketplace.json");
    let marketplace_json: Value =
        serde_json::from_str(&marketplace_json_text).expect("Failed to parse marketplace.json");

    // Read awm-hook script
    let awm_hook_path = repo_root.join("plugin/hooks/awm-hook");
    let awm_hook_text = fs::read_to_string(&awm_hook_path).expect("Failed to read awm-hook");

    // Assert four hook events present
    let hooks = hooks_json["hooks"]
        .as_object()
        .expect("hooks should be an object");
    assert_eq!(hooks.len(), 4, "Expected 4 hook events");
    assert!(
        hooks.contains_key("SessionStart"),
        "SessionStart hook missing"
    );
    assert!(
        hooks.contains_key("UserPromptSubmit"),
        "UserPromptSubmit hook missing"
    );
    assert!(hooks.contains_key("PreToolUse"), "PreToolUse hook missing");
    assert!(
        hooks.contains_key("PostToolUse"),
        "PostToolUse hook missing"
    );

    // Assert matchers
    let session_start = &hooks["SessionStart"][0];
    assert_eq!(
        session_start["matcher"], "startup",
        "SessionStart matcher should be 'startup'"
    );

    let pre_tool_use = &hooks["PreToolUse"][0];
    assert_eq!(
        pre_tool_use["matcher"], "WebFetch|WebSearch",
        "PreToolUse matcher should be 'WebFetch|WebSearch'"
    );

    let post_tool_use = &hooks["PostToolUse"][0];
    assert_eq!(
        post_tool_use["matcher"], "WebSearch|WebFetch",
        "PostToolUse matcher should be 'WebSearch|WebFetch'"
    );

    // Count async: true entries - should be exactly one
    let mut async_count = 0;
    for (_, hook_event) in hooks.iter() {
        if let Some(hook_array) = hook_event.as_array() {
            for hook_item in hook_array {
                if let Some(hook_list) = hook_item["hooks"].as_array() {
                    for hook in hook_list {
                        if hook.get("async").and_then(|v| v.as_bool()) == Some(true) {
                            async_count += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(
        async_count, 1,
        "Expected exactly one async: true hook entry"
    );

    // Assert every command starts with the correct prefix
    for (_, hook_event) in hooks.iter() {
        if let Some(hook_array) = hook_event.as_array() {
            for hook_item in hook_array {
                if let Some(hook_list) = hook_item["hooks"].as_array() {
                    for hook in hook_list {
                        if let Some(command) = hook["command"].as_str() {
                            assert!(
                                command.starts_with("sh ${CLAUDE_PLUGIN_ROOT}/hooks/awm-hook "),
                                "Command '{}' does not start with expected prefix",
                                command
                            );
                        }
                    }
                }
            }
        }
    }

    // Assert plugin.json and marketplace.json versions both equal the crate version
    let crate_version = env!("CARGO_PKG_VERSION");
    let plugin_version = plugin_json["version"]
        .as_str()
        .expect("plugin.json version missing");
    let marketplace_version = marketplace_json["plugins"][0]["version"]
        .as_str()
        .expect("marketplace.json version missing");
    assert_eq!(
        plugin_version, crate_version,
        "plugin.json version should match the crate version"
    );
    assert_eq!(
        marketplace_version, crate_version,
        "marketplace.json version should match the crate version"
    );

    // Assert marketplace plugins[0].source is ./plugin
    let source = marketplace_json["plugins"][0]["source"]
        .as_str()
        .expect("marketplace.json source missing");
    assert_eq!(
        source, "./plugin",
        "marketplace.json plugins[0].source should be './plugin'"
    );

    // Assert awm-hook passes the crate version as --plugin-version
    let expected = format!("--plugin-version {crate_version}");
    assert!(
        awm_hook_text.contains(&expected),
        "awm-hook should contain '{expected}'"
    );
}
