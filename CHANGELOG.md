# Changelog

## Unreleased

### Database migration
- **Schema version 2** (`0002_event_agent`): adds `event.agent` (`claude` or `codex`); existing records become `claude`. Run `awm doctor` once after upgrading: it writes a backup `awm.db.bak-v1` next to the database and migrates. Until then hooks show nothing and spool their captures, and other commands ask you to run `awm doctor`; `awm doctor` migrates and then ingests the spool, so nothing captured in between is lost. An older `awm` run against the migrated database skips its captures and discards any pending spool files (that binary cannot be fixed), so run `awm doctor` with the new binary before any old one can run, and keep `~/.local/bin/awm` first in `PATH`. Rollback: install the previous `awm`, close every agent session, delete `awm.db-wal` and `awm.db-shm` if present, and copy `awm.db.bak-v1` over `awm.db`.

### Added
- **Record web research**: Every WebSearch and WebFetch call in Claude Code (main agent and subagents) is recorded to a local SQLite database.
- **Exact URL matching**: When an agent fetches a URL it or a sibling subagent fetched before, the earlier result is shown (precision 1.00).
- **Search by query**: When an agent searches the web or fetches a URL with a new question, search for earlier answers using BM25 full-text search (precision 0.52–0.70).
- **URL in prompt**: If you name a URL in your prompt, the tool shows any earlier research on that URL before the agent decides.
- **Note injection**: Earlier research arrives alongside the result of the new call, never blocking or replacing it.
- **Short-circuit deny** (optional): Block an exact repeat fetch within 30 minutes and show the earlier result instead (off by default; opt-in via `awm config`).
- **Search deny** (optional, shadow by default): `awm hook pre-fetch` now also sees WebSearch (Claude Code) and `webrun` (Codex); with `short_circuit.query = "on"` a search whose words (any order) match a usable search of another agent within `short_circuit.query_window_minutes` (24 h) is denied once with that finding, and the retry passes. Shadow mode only logs it.
- **Subagent support**: Notes are shown to the subagent that made the call, with sibling research visible.
- **Import past research**: `awm init` extracts your research from Claude Code transcript files and imports it in seconds.
- **Redaction**: API keys, secrets, private IPs, file paths, and email addresses are redacted before storage.
- **Deletion**: `awm forget` marks records for deletion, `awm purge` removes them permanently.
- **Quarantine**: Mark records or URLs as unreliable with `awm quarantine` to keep them from being shown.
- **Search locally**: `awm search` queries your stored research without leaving your machine.
- **Review notes**: `awm review` shows you the notes your agents saw and lets you label them (saved time, relevant, irrelevant, misleading).
- **Statistics**: `awm stats` shows record counts by tool and agent, quarantined records, and injection metrics.
- **Savings estimate**: `awm stats --savings` estimates time and tokens saved by shown notes, and prints a separate upper-bound line for the page bytes the fetch summariser did not read (summariser tokens = bytes / 4; searches add 0).
- **Savings in money**: `awm stats --savings` adds a `cost` column (fetch summariser tokens at Haiku 4.5 rates plus the web search fee per avoided search) and JSON `est_cost`/`pricing`; rates are the new `[pricing]` section of `config.toml`. A subscription pays none of this per call.
- **Logging**: `awm log` shows the notes injected into your agents this session.
- **Configuration**: `awm config` lets you enable/disable channels, adjust matching thresholds, and control when notes are shown.
- **Installation verification**: `awm doctor` checks that the plugin and binary are correctly installed.
- **Report for bugs**: `awm report` generates a summary with no personal data for bug reports.
- **Plugin marketplace**: Install from a local path with `claude plugin marketplace add` and `claude plugin install`.
- **Local install script**: `bash scripts/install-local.sh` builds and installs the binary locally.
