# Contributing

This project is a research tool for Claude Code agents. Development is currently a solo effort.

## Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Asugawara/agent-web-memory.git
   cd agent-web-memory
   ```

2. **Check your Rust version:**
   ```bash
   rustup show
   ```
   This project uses Rust 1.97.1 as specified in `rust-toolchain.toml`.

3. **Run the build and test suite:**
   ```bash
   bash scripts/check.sh
   ```
   This checks formatting, runs linters, and runs all tests without network.

## Development

- **One branch per task**: Each feature or fix gets its own branch named after the task (e.g., `T14-deletion-layer`).
- **English only**: All code, comments, and documentation must be in English.
- **No telemetry**: The binary has no network dependencies. CI checks that no HTTP client is linked.
- **No external network**: The build and tests must work offline (after dependencies are cached).

## Testing

```bash
# Run all tests
cargo test --workspace --locked

# Run tests for one crate
cargo test -p agent-web-memory

# Run a specific test
cargo test -p agent-web-memory test_name

# Run tests in release mode (faster)
cargo test --release --locked
```

Red-team unit and pipeline tests verify the security guarantees:
```bash
cargo test -p agent-web-memory --test redteam_unit
cargo test -p agent-web-memory --test redteam_pipeline
```

## Code quality

```bash
# Format code
cargo fmt --all

# Check for issues
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The check script runs these automatically:
```bash
bash scripts/check.sh
```

## Building a release

Local builds are unsigned. To create a release candidate:

```bash
bash scripts/install-local.sh
awm --version
```

The binary is installed to `~/.local/bin/awm` by default. To install elsewhere:

```bash
AWM_INSTALL_PREFIX=/opt/custom bash scripts/install-local.sh
```

## Architecture

The project is organized into modules:

- `record.rs`: Parse WebSearch and WebFetch events from hooks and transcripts
- `capture.rs`: Store records to the database
- `import.rs`: Import research from Claude Code transcripts
- `matching/`: URL and query matching with FTS5 (the query channel ranks in the index); `bm25.rs` ranks one URL's stored answers in Rust for the fetch deny
- `paths.rs`: Data directory and the team files
- `gate.rs`: Gate UserPromptSubmit injections
- `render.rs`: Format notes for injection
- `sanitize.rs`: Redact and bound note text
- `config.rs`: Read and write configuration
- `db.rs`: Database connection and migrations
- `hook/`: Entry points for Claude Code hooks (session start, tool use, etc.)

## Reporting issues

File an issue on GitHub with:
- Steps to reproduce
- Expected and actual behavior
- Output of `awm --version`, `claude --version`, and `awm doctor`
- Your OS and installation method (scripts/install-local.sh, cargo install --path crates/awm, or other)
- Output of `awm report` (contains no personal data)
