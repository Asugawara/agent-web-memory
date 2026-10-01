# Hook Event Fixtures

Contract test fixtures derived from cc-hooks hook event recordings. Each fixture captures a real hook payload from the Claude Code plugin/settings logging system.

| File | Hook Event | Tool | Path | Run # | Subagent |
|------|-----------|------|------|-------|----------|
| `PostToolUse-WebSearch-plugin-2.json` | PostToolUse | WebSearch | plugin | 2 | — |
| `PostToolUse-WebSearch-settings-6.json` | PostToolUse | WebSearch | settings | 6 | — |
| `PostToolUse-WebSearch-plugin-8.json` | PostToolUse | WebSearch | plugin | 8 | ✓ |
| `PostToolUse-WebFetch-plugin-3.json` | PostToolUse | WebFetch | plugin | 3 | — |
| `PreToolUse-WebFetch-plugin-4.json` | PreToolUse | WebFetch | plugin | 4 | — |
| `UserPromptSubmit-none-plugin-1.json` | UserPromptSubmit | N/A | plugin | 1 | — |
| `UserPromptSubmit-none-plugin-8.json` | UserPromptSubmit | N/A | plugin | 8 | no (main session, `<task-notification>` turn after a subagent finished) |

## Notes

- **Path**: plugin fixtures use plugin variant configuration; settings fixtures use settings variant.
- **Run #**: number from the source cc-hooks run ID (file suffix).
- **Subagent**: ✓ indicates fixture contains subagent metadata (agent_id, agent_type for PostToolUse; task-notification turn marker for UserPromptSubmit).
- **Data Anonymization**: All absolute paths have been normalized to `/home/user/` prefix; non-ASCII text has been replaced with `(redacted)` for test stability.
