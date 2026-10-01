# Hook Event Fixtures

Contract test fixtures derived from cc-hooks hook event recordings. Each fixture captures a real hook payload from the Claude Code plugin/settings logging system.

| File | Agent | Hook Event | Tool | Path | Run # | Subagent |
|------|-------|-----------|------|------|-------|----------|
| `PostToolUse-WebSearch-plugin-2.json` | claude-code | PostToolUse | WebSearch | plugin | 2 | — |
| `PostToolUse-WebSearch-settings-6.json` | claude-code | PostToolUse | WebSearch | settings | 6 | — |
| `PostToolUse-WebSearch-plugin-8.json` | claude-code | PostToolUse | WebSearch | plugin | 8 | ✓ |
| `PostToolUse-WebFetch-plugin-3.json` | claude-code | PostToolUse | WebFetch | plugin | 3 | — |
| `PreToolUse-WebFetch-plugin-4.json` | claude-code | PreToolUse | WebFetch | plugin | 4 | — |
| `UserPromptSubmit-none-plugin-1.json` | claude-code | UserPromptSubmit | N/A | plugin | 1 | — |
| `UserPromptSubmit-none-plugin-8.json` | claude-code | UserPromptSubmit | N/A | plugin | 8 | no (main session, `<task-notification>` turn after a subagent finished) |
| `PreToolUse-WebSearch-main-cc-1.json` | claude-code | PreToolUse | WebSearch | plugin (`--plugin-dir`) | QD1 cc-1 | — |
| `PreToolUse-WebSearch-sub-cc-2.json` | claude-code | PreToolUse | WebSearch | plugin (`--plugin-dir`) | QD1 cc-2 | ✓ (`agent_id`, `agent_type`) |
| `PreToolUse-WebSearch-main-cc-3.json` | claude-code | PreToolUse | WebSearch (`allowed_domains` filter) | plugin (`--plugin-dir`) | QD1 cc-3 | — |
| `codex-PreToolUse-webrun-main-codex-1.json` | codex | PreToolUse | webrun (`search_query`) | hook | QD1 codex-1 | — |
| `codex-PreToolUse-webrun-search-1.json` | codex | PreToolUse | webrun | hook | 1 | — |
| `codex-PostToolUse-webrun-search-1.json` | codex | PostToolUse | webrun | hook | 1 | — |
| `codex-Stop-none-search-1.json` | codex | Stop | N/A | hook | 1 | — |
| `codex-SessionStart-none-search-1.json` | codex | SessionStart | N/A | hook | 1 | — |

## Notes

- **Path**: plugin fixtures use plugin variant configuration; settings fixtures use settings variant.
- **Run #**: number from the source cc-hooks run ID (file suffix).
- **Subagent**: ✓ indicates fixture contains subagent metadata (agent_id, agent_type for PostToolUse; task-notification turn marker for UserPromptSubmit).
- **Data Anonymization**: All absolute paths have been normalized to `/home/user/` prefix; non-ASCII text has been replaced with `(redacted)` for test stability.
- **Codex**: `codex-*` fixtures come from the CX1 spike (Codex CLI 0.159.3). Result URLs in `tool_response` are replaced by `https://example.com/rN` / `https://example.org/rN` (text structure kept); Codex payloads carry no subagent field.
- **QD1**: the four QD1 rows come from the query-deny spike (Claude Code 2.1.287, Codex 0.159.3); paths are already `/home/user/...` and non-ASCII text is removed. They are the stdin of the PreToolUse WebSearch / `webrun` deny (`awm hook pre-fetch`).
