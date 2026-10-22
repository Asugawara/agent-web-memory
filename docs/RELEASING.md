# Releasing agent-web-memory

A release is made by pushing a tag `vX.Y.Z`. `.github/workflows/release.yml` then verifies the tag and the version, waits for `ci` on the same commit, builds four targets, tests `scripts/install.sh` against a local mirror, and publishes the GitHub release.

## Before tagging

1. The `ci` push run of the commit you tag must be `success`:
   ```bash
   gh run list --workflow ci.yml --branch main --event push --commit <sha>
   ```
   If a later push cancelled it, rerun it with `gh run rerun <run-id>`. The tag must be on a commit that is on `main`.
2. Bump the version in:
   - `crates/awm/Cargo.toml`
   - `crates/awm-proto/Cargo.toml`
   - `crates/awm-server/Cargo.toml`
   - `Cargo.lock` (run `cargo check` so it follows)
   - `plugin/.claude-plugin/plugin.json`
   - `.claude-plugin/marketplace.json`
   - the `--plugin-version` in `plugin/hooks/awm-hook`

   `crates/awm/tests/plugin_manifest.rs` follows `CARGO_PKG_VERSION`, so it needs no edit.
3. In `CHANGELOG.md`, rename `## Unreleased` to `## X.Y.Z` and add a fresh `## Unreleased` above it.
4. Run `sh scripts/release-verify.sh X.Y.Z`. It checks every version location above and the `## X.Y.Z` heading in `CHANGELOG.md`.
5. Tag and push:
   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

Tag a stable version. A tag with a hyphen (for example `v0.1.0-rc.1`) is published as a prerelease, and `releases/latest` ignores prereleases. So the curl URL keeps returning 404 until a stable release exists.

## Plugin and binary versions

The plugin comes from the default branch, while the binary comes from the latest release. Merge a minor or major bump right before tagging. If the release fails, hold further version bumps on `main` until it is fixed; otherwise users see an "Upgrade awm" prompt that `install.sh` cannot resolve.

## If publish fails

The draft release stays and `latest` does not move, so users keep the previous release. To retry:

1. If `gh release view vX.Y.Z` shows a draft, delete it with `gh release delete vX.Y.Z`. Do not delete a published release, and do not add `--cleanup-tag`: without the tag the failed jobs cannot be re-run. A failure before the draft exists (build, sums, install-sh) leaves nothing to delete.
2. Re-run the failed jobs of the workflow run: `gh run rerun <run-id> --failed`.

## Release assets

- `awm-<version>-<triple>.tar.gz` for `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`. Each unpacks to a directory `awm-<version>-<triple>/` with `awm`, `LICENSE` and `THIRD_PARTY_LICENSES.md`.
- `SHA256SUMS`
- `install.sh`

## Testing install.sh

`sh scripts/install-test.sh` runs offline against a `file://` mirror. The workflow repeats it against the real archives.

## After release

Check the published installer with a clean `HOME`:

```bash
curl -fsSL https://github.com/Asugawara/agent-web-memory/releases/latest/download/install.sh | sh
awm --version
```

Then run `awm init` on a clean `AWM_HOME`, and check that the plugin shim finds `awm` on PATH (`~/.local/bin` or `~/.cargo/bin`).

## Homebrew tap (Not done yet)

1. Update the formula `url`, `sha256` and `version` for the new release (`scripts/bump-tap.sh`).
2. Commit and push to the tap repository; verify with `brew install <owner>/tap/awm`.

## crates.io (Not done yet)

1. `cargo publish --dry-run -p agent-web-memory`, then `cargo publish -p agent-web-memory`.
2. Verify with `cargo install agent-web-memory --locked`.
