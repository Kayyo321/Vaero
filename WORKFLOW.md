# Vaero Development Workflow

This document defines how Vaero is developed, tested, built, and released. It is intentionally designed for a Rust/Cargo workspace, as described in `PROJECT.md`.

## Branches and release flow

The repository has exactly two long-lived branches:

| Branch | Purpose | Who pushes |
| --- | --- | --- |
| `devel` | Integration branch for all day-to-day development. | Contributors through reviewed pull requests. |
| `main` | Stable, releasable code only. | Maintainers, by merging a tested `devel` release candidate. |

All feature work, fixes, refactors, documentation updates, and dependency updates start from and merge into `devel`. Do not commit directly to `main`.

Use short-lived branches based on `devel`, named for their purpose, for example `feat/phrase-codec` or `fix/archive-path-validation`. Open pull requests back to `devel`; require review and passing CI before merging.

Promote a release by opening a pull request from `devel` to `main`. That pull request must be green, reviewed, and use a version already set in the Cargo workspace. Merging it is the only normal route to `main`.

Protect both long-lived branches:

- No force-pushes or branch deletion.
- Pull requests and at least one approving review are required.
- Required checks must pass before merging.
- Keep `main` up to date with `devel` only through a release pull request.

## GitHub automation

### Pushes to `devel`: nightly build

The `nightly` GitHub Actions workflow runs on every push to `devel` (including merged pull requests). It must:

1. Check out the exact commit and lock dependencies using `Cargo.lock`.
2. Build the complete workspace in debug and release modes.
3. Run formatting, linting, unit, integration, property, and compatibility tests.
4. Generate a coverage report and fail when the configured coverage gate is not met.
5. Build the Windows x86_64 release artifact and upload it as a non-release CI artifact, named with the commit SHA.
6. Run dependency/security checks and retain reports as CI artifacts.

The nightly result is a verification artifact, not a GitHub Release and not a versioned installer.

### Pushes to `main`: release

The `release` GitHub Actions workflow runs on every push to `main`. It must:

1. Repeat the release-quality checks from the nightly workflow on the pushed commit.
2. Read the canonical Cargo workspace version (`X.X.X`) and require a matching annotated Git tag, `vX.X.X`, created by the workflow only after all checks pass.
3. Build signed, reproducible-where-practical Windows release binaries and installers.
4. Generate SHA-256 checksums and, when signing is configured, signatures for every published artifact.
5. Create the GitHub Release titled `Release X.X.X`, attach binaries, installers, checksums, signatures, and release notes.
6. Fail if the tag or GitHub Release already exists; releases must never silently overwrite an existing version.

Only publish a version once. To correct a released build, increment the version, promote it through `devel`, and create a new release.

## Local development, testing, and coverage

Every contributor should be able to run the same quality gates before opening a pull request. The planned Rust workspace should expose these commands through a `justfile` (or an equivalent documented task runner), keeping the exact commands out of individual developer memory:

```powershell
just fmt-check       # cargo fmt --all -- --check
just lint            # cargo clippy --workspace --all-targets -- -D warnings
just test             # unit, integration, property, and compatibility tests
just test-fuzz-smoke  # bounded parser/decompressor fuzz smoke tests
just coverage         # produce and enforce local coverage report
just verify           # fmt-check + lint + test + fuzz-smoke + coverage
```

`just verify` is the local pull-request gate. It should be required before requesting review, and CI must run the same logical checks independently.

### Plan for 100% local code coverage

The target is **100% line and branch coverage for production code**, measured locally with `cargo llvm-cov`. Tests, generated code, platform shims that cannot be exercised on the current host, and intentionally unreachable defensive abort paths may be excluded only through a reviewed, documented allowlist. The coverage report itself must list every exclusion and its justification.

Implement coverage in stages:

1. Add `cargo-llvm-cov`, LLVM tools, and a `just coverage` target that runs `cargo llvm-cov --workspace --all-features --lcov --output-path target/coverage/lcov.info` and emits HTML under `target/coverage/html`.
2. Enforce `--fail-under-lines 100` and `--fail-under-regions 100` locally and in CI once the first production crates exist. Treat regions as the practical branch-coverage proxy used by LLVM coverage.
3. Test every success path and every defined failure path: malformed headers, authentication failures, unsafe archive paths, capacity failures, cancellation, interrupted writes, and filesystem permission errors.
4. Use table-driven unit tests for parsers and validation; integration tests for CLI exit codes and output; property tests for round trips and deterministic modes; and retained golden fixtures for format compatibility.
5. Supplement coverage with coverage-guided fuzzing of all parsers, decompressors, and container readers. Coverage is necessary but does not prove security.

Run the full coverage gate on supported Windows locally before a release promotion. Developers working elsewhere may run the same suite where supported, but Windows is authoritative for Windows-specific behavior.

## Local build plan

The initial supported local build is 64-bit Windows. Keep a pinned toolchain in `rust-toolchain.toml` and commit `Cargo.lock`.

Prerequisites:

- Git
- Rust installed through `rustup`, including the repository-pinned toolchain
- Visual Studio Build Tools with the MSVC C++ build tools and Windows SDK
- `just` task runner
- LLVM tools and `cargo-llvm-cov` for coverage

Once the workspace exists, a clean build should be:

```powershell
git clone https://github.com/Kayyo321/Vaero.git
Set-Location Vaero
rustup show
cargo build --workspace
cargo test --workspace
```

Use `cargo build --workspace --release` (or `just build-release`) for an optimized local binary. Output belongs under `target\release`; do not commit build output. The build task should print the binary location and its version.

Add reproducibility checks over time: build from a clean checkout, capture the Rust toolchain and dependency-lock versions in build metadata, and compare artifact hashes for two clean builds on the same supported environment.

## Portability and contributor onboarding plan

The project should be cloneable and buildable without undocumented local state.

- Keep all source, format fixtures, test vectors, build scripts, and task definitions in Git. Store large test corpora via a documented fetch script with pinned hashes, never in an implicit local path.
- Commit `Cargo.lock`, `rust-toolchain.toml`, `.cargo/config.toml` when needed, `justfile`, and GitHub workflow files. Pin action versions and Rust toolchain versions.
- Maintain a concise `README.md` quick start and a detailed `docs/development.md` with prerequisites, setup, common commands, troubleshooting, supported-platform matrix, and how to run a minimal test subset.
- Provide `scripts/bootstrap.ps1` that checks prerequisites, installs only approved developer tools when requested, verifies versions, and reports exactly what remains missing. It must not require administrator rights except where a Windows dependency genuinely does.
- Provide matching CI containers or a dev container only for non-Windows-compatible portions; preserve a native Windows job as the source of truth for Windows features.
- Make paths configurable and avoid hard-coded usernames, drive letters, and machine-specific SDK locations. Test paths with spaces, Unicode, and long Windows paths.
- Document every external dependency, its license, source, version, and update procedure. Run `cargo deny` (licenses, advisories, bans, sources) and `cargo audit` in CI.
- Publish release checksums, signatures when available, supported Windows versions, and a verification command so downstream users can independently validate downloads.

## Definition of ready

A change is ready for `devel` when it is reviewed, `just verify` passes locally and in GitHub Actions, and it includes tests for its behavior and failure modes. A change is ready for `main` only when the `devel` release pull request is green, the workspace version is final, release notes are prepared, and the team is willing to publish that exact commit as `Release X.X.X`.
