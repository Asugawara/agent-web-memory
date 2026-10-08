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
- This machine only, unless you join a team; hooks never make network requests

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
| `awm stats --by repo` | The same headline numbers per repository: records, notes shown, denied, refetched after a deny (`--by dir` per directory; with `--savings`, the savings columns per group) |
| `awm stats --repo .` | Every section for one repository only, including its worktrees (`--dir PATH` for a directory and everything under it) |
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

`awm stats --by repo|dir` and `--repo [PATH]` / `--dir [PATH]` (default `.`) split or limit the numbers by where the agent was working. A repository is the main checkout that holds the directory, found by walking up to a `.git` (a linked worktree counts toward the checkout it was made from); a directory outside git is listed on its own as `(no repository) PATH`. `--dir PATH` takes that directory and everything under it. `--by` prints one row per group and a `total` row (JSON: `by_repo` / `by_dir`, last element `total`); `--repo` and `--dir` print every section for the one scope, with a `scope:` line first (JSON: a top-level `scope` object with `kind`, `path` and `directories`), and work with `--savings`, `--status`, `--value` and `--followups`. Rows from before awm remembered working directories are placed from the transcripts on the first run of any of these flags: an injection takes the directory of the nearest line of its transcript, or, when the transcript is gone, of the first record of its session (this assumes a session stays in one directory, which is not verified), and a record takes the directory a transcript under `~/.claude/projects` or `~/.codex/sessions` starts in. **This writes to the database** (the `cwd` table and `injection.cwd_hash`); what no transcript names is listed as `(unknown)` and reported on stderr. A directory first seen outside git that has become a checkout since is placed in it on the same run. A worktree directory that no longer exists (`.../worktrees/REPO/BRANCH`) is placed with the repository of the same name when there is exactly one. The call-cost medians the savings use stay global (what a call costs does not depend on the directory), and so does the quota block of `--savings`; the ceilings are limited to the scope. The paths are stored and printed on this machine only, and are never synced or exported.

`awm stats --savings` counts a shown note as avoided when the same session and agent did not call its URL or query again afterwards, and prices it at the median duration and summary length (chars / 4) of earlier calls of the same URL or query. This is an estimate of something that did not happen, so it also prints the part you confirmed in `awm review` (label 2), the token overhead of the notes, and the repeat calls in your history as an upper bound. It also prints a separate line, the page bytes not fetched: for each avoided fetch, the median size of earlier fetches of that URL, with summariser tokens = bytes / 4. That is an upper bound, and the table keeps it in its own column, because the page is read by Claude Code's fetch summariser and the main model never sees those tokens; on API billing they are cost, on a subscription they are usage, not dollars. Searches add 0. The first summary line adds the summariser tokens and the main-model net into one net and prints both parts, since not running the summariser is most of what an avoided fetch saves.

The `cost` column prices these figures in money: each avoided fetch costs its summariser tokens at the input rate plus its summary at the output rate, and each avoided search costs the web search fee. The rates live in `config.toml` (change them with `awm config set pricing.<key> <value>`; negative values are an error) and default to Claude Haiku 4.5 prices:

```toml
[pricing]
currency = "USD"
summariser_input_per_mtok = 1.0    # Claude Haiku 4.5 input, USD per million tokens
summariser_output_per_mtok = 5.0   # Claude Haiku 4.5 output (the summary it returns)
search_fee_per_call = 0.01         # Anthropic web search: USD 10 per 1,000 searches
main_input_per_mtok = 0.0          # your main model's input price; 0 = not priced
```

Main-model tokens are priced only when `main_input_per_mtok` is set; the first summary line then also shows a net cost after the note overhead. A subscription pays none of this per call, so read the cost as what the same calls would cost on API billing.

### Savings in your usage limits (subscription)

On a Claude Pro or Max subscription the `cost` column is what the same calls would cost on API billing. `awm stats --savings` can also show the savings as a share of your 5-hour and 7-day usage limits. It needs the limit usage that Claude Code passes to your status line, so run `awm setup --statusline` once. When you have no status line, it adds one. When you have your own, it changes nothing and prints one line to paste into your script right after the line that reads stdin; keep the `>/dev/null 2>&1 &` at its end, or Claude Code waits for awm before it draws the status line. The samples stay in `quota/` in the data directory for at least 92 days (`quota.retention_days`, deleted by whole months); `awm purge --all` and `awm uninstall` delete them, `awm purge --before` does not.

In each 5-hour window, awm compares the rise of the usage percentage with the list-price cost that your Claude Code sessions on this machine reported over the same time. The total rise over all windows with at least 10 points and $20 of use, divided by their total cost, is the share of a window per dollar. Accounts are told apart by their 7-day reset, and each account-week gets its own rate once it has 5 such windows on 2 days. The savings in the `cost` column times that rate give the share. Two figures are shown: `estimated` counts every note whose page or search was not repeated afterwards, which is an upper bound because the agent might not have needed it; `proven` counts only calls that were denied and items you labelled 2 in `awm review`. The range comes from how the limits count cached tokens, which Anthropic does not document: from free (the high end) to ten times their list price (the low end). awm reads the cache-read share of your sessions from the totals Claude Code writes at the end of each transcript, and their start times from the first line; nothing from them is stored. The figures leave out the context the notes replaced or added and the requests they saved, and use on claude.ai or on other machines, which the samples cannot see, makes them too high. awm assumes the limits weigh models and other token kinds like list prices, and needs `[pricing]` in USD. Codex calls are not part of these figures; Codex has its own limits.

### Blocking repeats (short-circuit)

A fetch of a URL awm already holds is answered from the record instead: **WebFetch is a per-URL cache**, on by default with a 7-day window. A search that earlier research already answers is denied once as well. The deny reason is one line (the Claude Code TUI shows it as the hook error); the earlier answer arrives next to it as additional context (Claude Code) or below that line (Codex), with no who, when or question. When this agent was already shown the record in an earlier `<awm-notes>` block, the deny still blocks the call but its one line only says the answer is already in the agent's context (with the note ref) instead of repeating the text. There is no shadow mode; a setting is on or off.

| Key | Default | Values | Meaning |
|-----|---------|--------|---------|
| `short_circuit.mode` | `on` | on, off | deny a WebFetch of a URL that awm holds a usable earlier fetch of |
| `short_circuit.window_days` | 7 | 1-365 | how old the earlier fetch may be, in days |
| `short_circuit.query` | `on` | on, off | deny a WebSearch (Claude Code) or `webrun` (Codex) that earlier research matches |
| `short_circuit.query_window_days` | 7 | 1-365 | how far back a query deny looks, in days |
| `short_circuit.query_min_score` | `auto` | 0-1000, `auto` | a fixed score cutoff for the query deny instead of the calibrated one |

A **URL deny** needs an earlier fetch of the same URL inside the window by anyone on your side: the same agent, a sibling subagent, another session or project, or your other machine. The earlier fetch must have status ok and HTTP code 200, or be a dead end that came with an HTTP code of 202, 3xx or 4xx other than 429 (a URL that returned 403, 404 or a redirect that gave no content has not worked on a repeat; the reason then says "this URL returned HTTP 404 when fetched earlier and gave no usable content", with no body). It must not be quarantined or deleted, and a teammate's record never counts. Timeouts and other failures without a code, 429, 5xx and refusals never deny. The newest usable record decides the kind of deny; when a URL holds several earlier answers, the one handed over is the one BM25 rates closest to your question over the stored question and answer (the newest on a tie), scored in Rust over that URL's newest 20 answers only, with the idf and average length taken from those answers, so the cost does not grow with your database. It applies in subagents too. The reason is one line, "agent-web-memory: an earlier answer for this URL is attached as additional context. If it does not answer your prompt, call WebFetch again with the same URL; it will not be blocked again.", and the earlier answer (only the answer text, up to 8,000 characters, no who or when) is delivered as additional context next to the error, unless the agent already has that record (it was shown it in an `<awm-notes>` block earlier in the session, or it fetched the URL itself earlier in the session): then the call is still denied, but the line only says so ("the earlier answer for this URL is already in your context (agent-web-memory note ref ...)" or "you fetched this URL earlier in this session and its result is already in your context") and there is no body; a subagent has its own context, so it gets the answer. The same call again always passes: the deny happens once per session, agent and URL, so a new question about the same page is one retry away.

A **query deny** is similarity-based: awm runs the same BM25 match that adds notes after a search (`matching::query_channel`, read-only) on the search text. When earlier records score at or above the deny cutoff, the search is denied once and the one-line reason ("agent-web-memory: earlier research matching this search is attached as additional context. If it does not answer your question, call WebSearch again with the same query; it will not be blocked again.") comes with up to `inject.max_notes` of them as additional context: each one's URL and found text, nothing else (Codex gets them below the line). Any earlier usable record counts (the same agent, a sibling, another session or project, your other machine; never a teammate's) inside `short_circuit.query_window_days`, with status ok and a non-empty finding. A note already shown to that agent is not handed over again. A record the agent already has in its context, a note it was given or a result it fetched or searched itself earlier in the same session, is not repeated either: the call is still denied, and the one line points at what it has ("earlier research matching this search is already in your context (agent-web-memory note ref ...; your own WebSearch "..." earlier in this session)"). Searches with `allowed_domains` / `blocked_domains` and Codex calls other than a plain search are never denied. The same search text again always passes (once per session, agent and text). The search deny uses a stricter calibrated cutoff than the notes (the 75th percentile of the top scores, `cutoff.query_deny`; `awm calibrate` prints it); override it with `short_circuit.query_min_score`. BM25 is a similarity match, not an equality: its measured strict precision was 0.52 at the median cutoff, so some denies still hand over a note that does not answer the question; `awm stats` `query_deny.research_after_deny` shows how often the agent searched again within 2 minutes. Turn it off with `awm config set short_circuit.query off`.

Turn the URL deny off with `awm config set short_circuit.mode off`. Notes are not capped per agent; `inject.max_notes` (3) limits one injection.

Settings of older versions keep working: `shadow` reads as `inject` for `mode`, as `on` for `short_circuit.mode` and as `off` for `short_circuit.query` and `channels.prompt_bm25`, and `short_circuit.subagents`, `short_circuit.window_minutes` (use `short_circuit.window_days`), `short_circuit.query_window_minutes` (use `short_circuit.query_window_days`) and `inject.max_per_agent` are ignored. `awm doctor` lists each one with its replacement, and `awm config set` refuses them.

`awm stats` prints a `query_deny` object: the `denied` count, by agent kind (main, subagent), by relation (same agent, sibling, other session in the same project or another project, other coding agent), by age (within 30 minutes, within 24 hours, cumulative), labels 2 / 1 / 0 / h from `awm review`, `per_100_searches`, and `research_after_deny` (denies followed within 2 minutes by the same agent repeating the same search, with its share), `cutoff_used` (the deny cutoff and whether it is `calibrated` or from `config`) and `by_top_score` (denies and retried denies by the score of the best note: `<30`, `30-40`, `40-60`, `60+`). `injections.refetch_after_deny` counts URL denies followed by another fetch of the same URL by the same agent. `awm stats --followups` splits the notes followed by a fetch of the same URL by the gap (`by_age`) and by who made the earlier fetch (`by_who`: same agent, sibling, other session). In `awm review` a query deny shows the earlier search's relation and age and the reason it got (label 2: the earlier finding covered what the agent did next; 1: relevant, but the agent needed the new results; 0: not the same need; h: the earlier finding was wrong or stale). `injections.deny_by_kind` splits URL denies into `cached` (the answer was handed over), `cached_shown` (it was already in the agent's context) and `dead_url`.

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

- **Local first**: Research stays on your machine. If you join a team, a background `awm sync` sends the records of the projects you share, end-to-end encrypted; hooks never wait on the network.
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

For a fetch of a URL it already holds, it is one: the call is denied once with a one-line reason and the full earlier answer as additional context (see "Blocking repeats"). The same call again always passes, so the agent can still get a fresh page, and a changed page costs one retry. A search that earlier research answers is denied once in the same way. Everywhere else (a new URL, a search that only resembles earlier ones) awm never blocks a call: it shows the earlier question, URL and finding *alongside* the new result, and the agent decides what to do. Turn the denies off with `awm config set short_circuit.mode off` and `short_circuit.query off`.

### Why local first?

Uploading research creates a privacy boundary you lose control of. Local-first means your data never leaves your machine unless you copy it. Team sync is optional: when you join a team, see `docs/self-host.md` for self-hosting options and `docs/plan-v3-team.md` §3.2 for what fields are shared (your prompts, transcripts and file paths never leave your machine; summaries are cut to 1,000 characters by default; authenticated-SaaS pages share only the URL and title).

### Does it work in subagents?

Yes.agent-web-memory shows each subagent notes from earlier research *in the same session* (other subagents) *and across sessions* (your past research). The main agent never hears about research that only the subagents did — it keeps your session contexts lightweight.

## Bugs or feedback

Create an issue on GitHub, or run `awm report` to get a summary for the issue template. Include the output of `awm doctor` if something is broken.
