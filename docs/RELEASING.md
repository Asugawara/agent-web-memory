# Releasing agent-web-memory (draft)

> **Not in use for v0.1.0-rc.** There is no GitHub repository, CI or release
> pipeline yet. For now install locally with `scripts/install-local.sh` and
> remove with `scripts/uninstall-local.sh`. This file is a draft of the public
> procedure for when the project is published.

## Before any release
1. `bash scripts/check.sh` passes (fmt, clippy, test, no-network, shellcheck).
2. Version bumped in `crates/awm/Cargo.toml` and `plugin/.claude-plugin/plugin.json`; `CHANGELOG.md` updated.
3. Tag locally: `git tag vX.Y.Z`.

## GitHub Releases
1. Build per target with `cargo build --release --locked --target <triple>`:
   `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`.
2. Package each as `awm-<version>-<triple>.tar.gz` containing the `awm` binary and `LICENSE`.
3. Write `SHA256SUMS` over all archives (`shasum -a 256 *.tar.gz > SHA256SUMS`).
4. Push the tag, create the release, upload archives, `SHA256SUMS` and `install.sh`.

## install.sh
- Detect OS and architecture; map to a target triple.
- Download the archive and `SHA256SUMS`; verify with `shasum -a 256` or `sha256sum`; abort on mismatch.
- Install to `~/.local/bin` atomically; print the post-install text (S3 in plan-v2 §2.2).
- `AWM_INSTALL_BASE_URL` overrides the download base for tests (`file://` URLs, good and tampered checksum).

## Homebrew tap
1. Update the formula `url`, `sha256` and `version` for the new release (`scripts/bump-tap.sh`).
2. Commit and push to the tap repository; verify with `brew install <owner>/tap/awm`.

## crates.io
1. `cargo publish --dry-run -p agent-web-memory`, then `cargo publish -p agent-web-memory`.
2. Verify with `cargo install agent-web-memory --locked`.

## After release
- Run `awm --version` from the installed binary and `awm init` on a clean `AWM_HOME`.
- Check that the plugin shim finds `awm` on PATH (`~/.local/bin` or `~/.cargo/bin`).
