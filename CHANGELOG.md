# Changelog

## Unreleased

### Database migration
- **Schema version 2** (`0002_event_agent`): adds `event.agent` (`claude` or `codex`); existing records become `claude`. Run `awm doctor` once after upgrading: it writes a backup `awm.db.bak-v1` next to the database and migrates. Until then hooks show nothing and spool their captures, and other commands ask you to run `awm doctor`; `awm doctor` migrates and then ingests the spool, so nothing captured in between is lost. An older `awm` run against the migrated database skips its captures and discards any pending spool files (that binary cannot be fixed), so run `awm doctor` with the new binary before any old one can run, and keep `~/.local/bin/awm` first in `PATH`. Rollback: install the previous `awm`, close every agent session, delete `awm.db-wal` and `awm.db-shm` if present, and copy `awm.db.bak-v1` over `awm.db`.

### Changed
- **Notes carry the full earlier result**: the `found:` line shows the whole sanitised summary (up to 8,000 characters) instead of a 200-character excerpt, and a note block and a deny reason may be up to 9,500 characters (was 2,200 and 800), under Claude Code's 10,000-character `additionalContext` cap. A note that does not fit is cut to the remaining space or dropped. A shown-but-unused note costs about 2,100 tokens (8,410 characters) instead of about 150; a full block about 2,400 tokens (9,500 characters) instead of about 550.

### Added
- **Team sync (opt-in)**: `awm team create` starts an organisation; `awm team invite` adds members; `awm team join` accepts and prints a 6-digit code and fingerprint to compare with `awm team approve` on the inviter's machine; `awm team share` opts in projects (default unshared); `awm team unshare` withdraws; `awm team remove` evicts and rotates keys; `awm team leave` and `delete-mine` remove the caller. End-to-end encrypted with the server never seeing plaintext. `[team]` config keys including `team.auto_approve = none` (default: waits for manual approval), `devices` (auto-approves your own new devices), or `all` (also auto-approves member joins). `awm serve` hosts the server (SQLite or Postgres, built-in ACME TLS, `awm serve restore` and `awm serve backup`). The default build has no network code; `sync` and `serve` are feature flags.
- **Usage-limit savings**: `awm statusline` records usage-limit samples (5-hour and 7-day percentages, resets, session cost) from Claude Code's status line into `quota/` in the data directory; `awm setup --statusline` and `--remove-statusline`; `[quota]` keys `capture` and `retention_days`. `awm stats --savings` adds a quota block (estimated and proven savings as a share of the 5-hour and 7-day limits, with a cache-read range) and takes `--projects`. `awm purge --all` and `awm uninstall` delete the samples. The per-tool fallback medians of `awm stats --savings` now use only calls before the note.
- **Record web research**: Every WebSearch and WebFetch call in Claude Code (main agent and subagents) is recorded to a local SQLite database.
- **Exact URL matching**: When an agent fetches a URL it or a sibling subagent fetched before, the earlier result is shown (precision 1.00).
- **Search by query**: When an agent searches the web or fetches a URL with a new question, search for earlier answers using BM25 full-text search (precision 0.52–0.70).
- **URL in prompt**: If you name a URL in your prompt, the tool shows any earlier research on that URL before the agent decides.
- **Note injection**: Earlier research arrives alongside the result of the new call, never blocking or replacing it.
- **Short-circuit deny** (optional): Block an exact repeat fetch within 30 minutes and show the earlier result instead (off by default; opt-in via `awm config`).
- **Search deny** (optional, shadow by default): `awm hook pre-fetch` now also sees WebSearch (Claude Code) and `webrun` (Codex); with `short_circuit.query = "on"` a search whose words (any order) match a usable search of another agent within `short_circuit.query_window_minutes` (24 h) is denied once with that finding, and the retry passes. Shadow mode only logs it. `awm stats` prints a `query_deny` summary and `awm review` shows these items with their reason.
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
