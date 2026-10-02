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

**With status line samples on (`awm setup --statusline`):**
- Time, session ID, model, the 5-hour and 7-day usage percentages and reset times, and the session's estimated cost
- Kept at least 92 days and deleted by whole months (so up to 123 days); `awm purge --all` and `awm uninstall` delete them, `awm purge --before` does not

**Stored in:**
- The data directory, ~/Library/Application Support/agent-web-memory/ on macOS or ~/.local/share/agent-web-memory/ on Linux: the database awm.db and, with status line samples on, quota/samples-YYYY-MM.ndjson
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
| `awm stats --savings` | Estimate time and tokens the shown notes saved, and their share of your usage limits (`--since YYYY-MM-DD`, `--json`) |
| `awm review` | Review and label notes you were shown |
| `awm forget` | Delete records: `awm forget last`, `awm forget <url>`, `awm forget --id N`, `awm forget --ref REF` (asks first; `--yes` skips the question) |
| `awm purge` | `awm purge --before YYYY-MM-DD` deletes records older than the date (usage-limit samples expire on their own); `awm purge --all` deletes the whole data directory |
| `awm quarantine` | Mark records as unreliable |
| `awm unquarantine` | Lift quarantine |
| `awm calibrate` | Calibrate matching thresholds |
| `awm setup` | Set up the plugin integration (`--statusline` adds usage-limit samples) |
| `awm statusline` | Record usage-limit samples from Claude Code's status line (`--quiet` prints nothing) |
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

### Savings in your usage limits (subscription)

On a Claude Pro or Max subscription the `cost` column is what the same calls would cost on API billing. `awm stats --savings` can also show the savings as a share of your 5-hour and 7-day usage limits. It needs the limit usage that Claude Code passes to your status line, so run `awm setup --statusline` once. When you have no status line, it adds one. When you have your own, it changes nothing and prints one line to paste into your script right after the line that reads stdin; keep the `>/dev/null 2>&1 &` at its end, or Claude Code waits for awm before it draws the status line. The samples stay in `quota/` in the data directory for at least 92 days (`quota.retention_days`, deleted by whole months); `awm purge --all` and `awm uninstall` delete them, `awm purge --before` does not.

In each 5-hour window, awm compares the rise of the usage percentage with the list-price cost that your Claude Code sessions on this machine reported over the same time. The total rise over all windows with at least 10 points and $20 of use, divided by their total cost, is the share of a window per dollar. Accounts are told apart by their 7-day reset, and each account-week gets its own rate once it has 5 such windows on 2 days. The savings in the `cost` column times that rate give the share. Two figures are shown: `estimated` counts every note whose page or search was not repeated afterwards, which is an upper bound because the agent might not have needed it; `proven` counts only calls that were denied and items you labelled 2 in `awm review`. The range comes from how the limits count cached tokens, which Anthropic does not document: from free (the high end) to ten times their list price (the low end). awm reads the cache-read share of your sessions from the totals Claude Code writes at the end of each transcript, and their start times from the first line; nothing from them is stored. The figures leave out the context the notes replaced or added and the requests they saved, and use on claude.ai or on other machines, which the samples cannot see, makes them too high. awm assumes the limits weigh models and other token kinds like list prices, and needs `[pricing]` in USD. Codex calls are not part of these figures; Codex has its own limits.

### Blocking repeats (short-circuit, optional)

Two settings can block a repeated call once and hand over the earlier answer instead. Both are in shadow mode by default: they only log what they would have blocked (`awm stats`, `awm review`), and nothing is denied until you turn one on.

| Key | Default | Values | Meaning |
|-----|---------|--------|---------|
| `short_circuit.mode` | `shadow` | off, shadow, on | WebFetch of a URL a sibling agent of the same session already fetched (`short_circuit.window_minutes`, default 30) |
| `short_circuit.query` | `shadow` | off, shadow, on | WebSearch (Claude Code) or `webrun` (Codex) with the same words, in any order, as a search made by another agent |
| `short_circuit.query_window_minutes` | 1440 | 1-10080 | how far back a query deny looks (24 hours) |
| `short_circuit.subagents` | false | true, false | allow either deny inside subagents (needs the installed plugin check, `scripts/verify-hooks.sh`) |

A **query deny** needs an earlier WebSearch by another agent (a sibling subagent, another session or project, or the other coding agent; never the agent's own earlier search) inside the window, with status ok and a non-empty finding, and the same token set (case, order and punctuation ignored, at least 3 words). Searches with `allowed_domains` / `blocked_domains` and Codex calls other than a plain search are never denied. The agent gets a reason with the earlier query, top result and the earlier finding, and the same search run again (same words, any order, any length) always passes; at most one deny per search and 3 per agent. The global `mode = "shadow"` also downgrades `on` to shadow.

Turn it on with `awm config set short_circuit.query on`, and back with `awm config set short_circuit.query shadow`. The suggested bar for `on` is at least 20 shadow denies labelled in `awm review`, at least 80% of them label 2 and none h, and at least 1 shadow deny per 100 searches.

`awm stats` prints a `query_deny` object: `shadow` and `denied` counts, by agent kind (main, subagent), by relation (sibling, other session in the same project or another project, other coding agent), by age (within 30 minutes, within 24 hours, cumulative), labels 2 / 1 / 0 / h from `awm review`, `per_100_searches`, and `research_after_deny` (denies followed within 2 minutes by the same agent repeating the same search, with its share). `refetch_after_deny` counts URL denies only. In `awm review` a query deny shows the earlier search's relation and age and the reason text (label 2: the earlier finding covered what the agent did next; 1: relevant, but the agent needed the new results; 0: not the same need; h: the earlier finding was wrong or stale).

## Codex

Codex support is experimental (started 2026-10-02; spike in `docs/reports/codex-hooks.md`, tested with Codex CLI 0.159.3).

**What works**
- Notes about earlier research are shown with your prompt (`UserPromptSubmit`). A note holds the earlier result in full (sanitised, up to 8,000 characters); a block of notes is at most 9,500 characters, about 2,400 tokens.
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
   This shows the data directory size and record count, then deletes it after you confirm, including usage-limit samples.

2. **Remove the plugin from Claude Code:**
   ```bash
   claude plugin uninstall agent-web-memory@agent-web-memory
   claude plugin marketplace remove agent-web-memory
   ```

3. **Remove the status line sample capture:** run `awm setup --remove-statusline --yes` if awm wrote your status line, or remove the `awm statusline` line from your status line script.

4. **Remove the binary:**
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
