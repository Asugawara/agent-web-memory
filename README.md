# agent-web-memory

Local memory for your Claude Code agents. Records every WebSearch and WebFetch call into one local SQLite file, and shows your agents their earlier findings when they repeat web research — without sending data anywhere.

## Install

### 1. Build and install the binary

```bash
cd path/to/agent-web-memory
bash scripts/install-local.sh
```

This builds the `awm` binary and installs it to `~/.local/bin/awm`. Add that directory to your PATH if needed.

### 2. Add the plugin to Claude Code

```bash
claude plugin marketplace add path/to/agent-web-memory
claude plugin install agent-web-memory@agent-web-memory
```

### 3. Initialize the database

```bash
awm init
```

This asks whether to record future research and whether to import your past research from transcript files. Answer `y` to both to start with your full research history. After that, every WebSearch and WebFetch call in Claude Code (main agent and subagents) is recorded.

## What is stored

**Recorded for every WebSearch and WebFetch call in Claude Code:**
- The search query or fetch prompt (first 200 characters kept in logs when matching a URL in your prompt)
- The URL fetched, query terms, result titles and URLs, HTTP status
- Time, session ID, and which agent made the call (main agent or subagent name)
- A hash of your working directory

**Never recorded:**
- Your full prompts or code
- File contents
- Your API keys (redacted before storage)
- Private network URLs

**Stored in:**
- One file only: `~/Library/Application Support/agent-web-memory/awm.db` on macOS, `~/.local/share/agent-web-memory/awm.db` on Linux
- This machine only; `awm` makes no network requests

**Delete everything at any time:**
```bash
awm purge --all
```

## Commands

| Command | Does |
|---------|------|
| `awm init` | Create the local database and import past research |
| `awm import` | Import again from transcript files |
| `awm search {query}` | Search stored records |
| `awm log` | Show recent notes injected into your agents |
| `awm stats` | Show statistics (records by tool and agent, quarantined count) |
| `awm stats --savings` | Estimate time and tokens the shown notes saved (`--since YYYY-MM-DD`, `--json`) |
| `awm review` | Review and label notes you were shown |
| `awm forget` | Delete records: `awm forget last`, `awm forget <url>`, `awm forget --id N`, `awm forget --ref REF` (asks first; `--yes` skips the question) |
| `awm purge` | `awm purge --before YYYY-MM-DD` deletes everything older than the date; `awm purge --all` deletes the whole data directory |
| `awm quarantine` | Mark records as unreliable |
| `awm unquarantine` | Lift quarantine |
| `awm calibrate` | Calibrate matching thresholds |
| `awm setup` | Set up the plugin integration |
| `awm export` | Export records |
| `awm reindex` | Rebuild the search index |
| `awm config` | Show or change settings (mode, channels, cutoffs) |
| `awm doctor` | Check the installation |
| `awm where` | Print data directory and database path |
| `awm report` | Write a summary for bug reports (no personal data) |

### How savings are estimated

`awm stats --savings` counts a shown note as avoided when the same session and agent did not call its URL or query again afterwards, and prices it at the median duration and summary length (chars / 4) of earlier calls of the same URL or query. This is an estimate of something that did not happen, so it also prints the part you confirmed in `awm review` (label 2), the token overhead of the notes, and the repeat calls in your history as an upper bound. It also prints a separate line, the page bytes not fetched: for each avoided fetch, the median size of earlier fetches of that URL, with summariser tokens = bytes / 4. That is an upper bound and is kept apart from the token figures above, because the page is read by Claude Code's fetch summariser and the main model never sees those tokens; on API billing they are cost, on a subscription they are usage, not dollars. Searches add 0.

The `cost` column prices these figures in money: each avoided fetch costs its summariser tokens at the input rate plus its summary at the output rate, and each avoided search costs the web search fee. The rates live in `config.toml` (change them with `awm config set pricing.<key> <value>`; negative values are an error) and default to Claude Haiku 4.5 prices:

```toml
[pricing]
currency = "USD"
summariser_input_per_mtok = 1.0    # Claude Haiku 4.5 input, USD per million tokens
summariser_output_per_mtok = 5.0   # Claude Haiku 4.5 output (the summary it returns)
search_fee_per_call = 0.01         # Anthropic web search: USD 10 per 1,000 searches
main_input_per_mtok = 0.0          # your main model's input price; 0 = not priced
```

Main-model tokens are priced only when `main_input_per_mtok` is set; the summary line then also shows a net cost after the note overhead. A subscription pays none of this per call, so read the cost as what the same calls would cost on API billing.

## Codex

Codex support is experimental (started 2026-10-02; spike in `docs/reports/codex-hooks.md`, tested with Codex CLI 0.159.3).

**What works**
- Notes about earlier research are shown with your prompt (`UserPromptSubmit`).
- Notes are shown after a web search through Codex's `webrun` tool, and searches are captured with their full results on current models.

**What is missing**
- Older hosted web searches leave only the query and URL in the rollout, with no result text, and may not trigger hooks at all (not verified).
- Codex has no fetch tool, so there are no fetch notes.
- Project-level `.codex/hooks.json` files are not loaded; hooks must live in `~/.codex/hooks.json`.

**Enable**
```bash
awm setup --codex-hooks
```
This shows the entries, asks first (`--yes` skips the question), keeps a backup `hooks.json.awm-backup` and leaves your other hooks alone. It writes the absolute path of the `awm` binary, because Codex may not inherit your PATH. Then run `codex`, type `/hooks`, and trust the awm entries once. `$CODEX_HOME` is honoured if set.

**Disable**
```bash
awm setup --remove-codex-hooks
```

## Privacy

- **Local only**: All research stays on your machine. No servers, no sync, no API calls.
- **Redacted**: API keys and secrets are redacted before storage.
- **Deletable**: `awm forget` and `awm purge` permanently remove records. `awm config set mode off` pauses recording without deleting anything.
- **Your control**: `awm config` lets you turn off channels, adjust matching thresholds, and pause recording.

## Uninstall

To pause without deleting anything:
```bash
awm config set mode off
```

To delete everything:

1. **Delete the database:**
   ```bash
   awm uninstall
   ```
   This shows the data directory size and record count, then deletes it after you confirm.

2. **Remove the plugin from Claude Code:**
   ```bash
   claude plugin uninstall agent-web-memory@agent-web-memory
   claude plugin marketplace remove agent-web-memory
   ```

3. **Remove the binary:**
   ```bash
   bash scripts/uninstall-local.sh
   ```

## FAQ

### Why not a cache?

A cache returns saved results in place of the tool call. agent-web-memory never blocks or replaces a call — it just shows your agent the earlier question, URL, and finding *alongside* the new result. The agent reads both and decides what to do. This keeps agents safe and lets them notice when pages change.

### Why local only?

Uploading research creates a privacy boundary you lose control of. Local-first means your data never leaves your machine unless you copy it. Team sync is planned for v0.2 if users ask for it — it will be optional and you'll control which machine it runs on.

### Does it work in subagents?

Yes.agent-web-memory shows each subagent notes from earlier research *in the same session* (other subagents) *and across sessions* (your past research). The main agent never hears about research that only the subagents did — it keeps your session contexts lightweight.

## Bugs or feedback

Create an issue on GitHub, or run `awm report` to get a summary for the issue template. Include the output of `awm doctor` if something is broken.
