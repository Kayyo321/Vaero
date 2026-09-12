# Developing Vaero

Vaero currently supports native 64-bit Windows builds. Rust is pinned by `rust-toolchain.toml`; `Cargo.lock` is authoritative.

## Prerequisites

- Git and `rustup`
- Visual Studio 2022 Build Tools with **Desktop development with C++** and a Windows SDK
- PowerShell 7 or Windows PowerShell 5.1
- `just`, `cargo-llvm-cov`, `cargo-deny`, and `cargo-audit`

Check the machine without installing Cargo tools:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/bootstrap.ps1
```

Install the approved Cargo tools in the current user's Cargo bin directory (no administrator rights required):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/bootstrap.ps1 -InstallTools
```

Visual Studio components may require an administrator-managed installer. The script never installs them silently.

## Common commands

```powershell
cargo build --workspace --locked
cargo test --workspace --locked
just verify
just audit
just build-release
just package
```

`just verify` is the pull-request gate. It checks formatting and Clippy, runs all tests plus the bounded fuzz-smoke subset, and enforces 100% line and region coverage. HTML coverage is written to `target/coverage/html/index.html`; LCOV is written to `target/coverage/lcov.info`.

For a quick edit/test loop, run `cargo test -p vaero-core`. CI remains authoritative for the whole workspace.

## Branch and review flow

Create a short-lived branch from `devel`, open a reviewed pull request back to `devel`, and merge only after required checks pass. Releases use a reviewed `devel` to `main` pull request. Never force-push or directly develop on either long-lived branch.

Repository administrators should protect `devel` and `main`, require at least one approval and the `quality / verify` check, prohibit force-pushes and deletion, and restrict direct pushes to `main`.

## Formats

On-disk container formats are specified under `docs/formats/`. The Phase 1 encrypted container is `docs/formats/crypt-v1.md`; it is a draft and remains experimental until independent review. Code and format documents must change together.

Known Phase 1 CLI limitations, tracked deliberately rather than worked around:

- Interactive no-echo phrase entry is not implemented yet; `--phrase-file` and `--phrase-stdin` are the supported inputs, and the phrase is never accepted as a command-line argument value.
- There is no overwrite flag; commands always refuse an existing destination.
- Destination free-space estimation is not implemented yet.

## Coverage exclusions

There are currently no coverage exclusions. Any future exclusion must be listed here with the exact module or path, affected lines, and a reviewed justification. Tests, generated files, unexercisable platform shims, and defensive aborts are not implicitly excluded.

## Platform notes and troubleshooting

| Area | Windows x86_64 | Other platforms |
| --- | --- | --- |
| Core format logic | Supported | Best effort until CI is added |
| CLI | Supported | Best effort |
| Windows metadata and future VCD features | Authoritative | Not applicable |

- If linking fails, launch a Visual Studio Developer PowerShell and confirm the MSVC C++ tools and Windows SDK are installed.
- If `cargo llvm-cov` cannot find LLVM tools, run `rustup component add llvm-tools-preview`.
- If locked builds reject a dependency change, intentionally regenerate and review `Cargo.lock` with `cargo update`.
- Keep corpora and fixtures in the repository. A future large-corpus fetch script must pin and verify every hash.

Paths must not depend on a username or drive. New filesystem tests should cover spaces, Unicode, long Windows paths, case collisions, reserved names, and links without following hostile reparse points.
