# AGENTS.md

This file applies to the entire repository. More-specific `AGENTS.md` files may refine these rules for a subtree but must not weaken the security or verification requirements below.

## Project intent

Vaero is a Windows-first Rust CLI for packaging, compressing, encrypting, verifying, and restoring directories and devices with memorable recovery phrases. The project is pre-release: cryptographic and on-disk format decisions in `PROJECT.md` are proposals until explicitly stabilized and reviewed.

Read these before substantial changes:

1. `PROJECT.md` for product behavior, threat model, architecture, and format direction.
2. `WORKFLOW.md` for branches, CI, releases, coverage, and readiness criteria.
3. `docs/development.md` for supported commands and Windows prerequisites.

When those documents disagree, preserve security and data safety, call out the conflict, and avoid silently inventing a format or cryptographic decision.

## Repository map

- `crates/vaero-cli`: command parsing, terminal behavior, exit codes, and integration tests.
- `crates/vaero-core`: shared policy and orchestration primitives; it must not prompt or perform hidden writes.
- `scripts`: PowerShell bootstrap, coverage, auditing, and packaging tasks.
- `.github/workflows`: pull-request quality checks, `devel` nightly artifacts, and `main` releases.
- `docs`: development, dependency, and release documentation.

Future crates should follow the boundaries in `PROJECT.md`; keep parsing, formats, crypto, archives, compression, devices, OpenPGP, and Windows integration independently testable.

## Development workflow

- Base work on `devel` and use a short-lived purpose-named branch. Do not develop directly on `main`.
- Do not change release versions, create tags, publish releases, or weaken branch protections unless the task explicitly requires it.
- Keep `Cargo.lock`, `rust-toolchain.toml`, task definitions, fixtures, and build scripts committed.
- Preserve unrelated user changes in a dirty worktree.
- Prefer workspace-scoped commands and locked dependencies.

Run the narrowest relevant checks while iterating. Before handing off a code or build-system change, run:

```powershell
just verify
just audit
```

If required tools are missing:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/bootstrap.ps1 -InstallTools
```

For documentation-only changes, formatting/link inspection and `git diff --check` are normally sufficient. State any check you could not run and why.

## Rust standards

- Use the pinned Rust toolchain and the workspace edition, lints, version, license, and `rust-version` fields.
- Keep `unsafe` code forbidden unless a narrowly reviewed platform boundary makes it unavoidable; never relax the workspace lint globally as a shortcut.
- Treat Clippy pedantic warnings as errors. Prefer explicit errors and bounded resource use over panics in production paths.
- Public APIs require useful rustdoc, including `# Errors` and `# Panics` where applicable.
- Keep production dependencies minimal. Pin compatible versions, review licenses and advisories, document additions in `docs/dependencies.md`, and regenerate `Cargo.lock` intentionally.
- Separate pure parsing and validation from filesystem access and UI. Libraries must not prompt, print secrets, or write implicitly.

## Security and data-safety invariants

Treat all containers, archive entries, metadata, paths, indexes, and KDF parameters as hostile input.

- Never invent cryptography. Use maintained, reviewed primitives only after the format and dependency choice is approved.
- Never log, echo, serialize casually, or expose phrases, keys, derived secrets, plaintext metadata, or signing credentials.
- Authenticate before releasing plaintext. Fail closed on wrong keys, corruption, truncation, reordering, unknown mandatory features, or excessive resource requests.
- Validate archive paths before joining them to an extraction root. Reject absolute/rooted paths, platform or drive prefixes, parent traversal, reserved Windows names, collisions, and link/reparse-point escapes.
- Bound memory, path length, nesting, entry count, metadata size, expanded bytes, decompression ratio, and KDF cost.
- Write output transactionally: create beside the destination, finalize and flush, verify, then atomically commit where possible. Preserve the source and do not overwrite by default.
- Cancellation, disk exhaustion, permission failures, and interrupted writes must not commit partial output or destroy source data.
- Do not claim secure deletion, complete malware resistance, stable formats, or production readiness without the reviews required by `PROJECT.md`.

## Testing expectations

Every behavior change needs tests for success and defined failure modes.

- Use table-driven unit tests for parsers, path rules, limits, and error mapping.
- Use CLI integration tests for stdout/stderr separation, stable exit codes, redirection, and cancellation behavior.
- Use property tests for round trips and deterministic output when those components are introduced.
- Retain golden compatibility fixtures permanently once an on-disk format exists.
- Add bounded fuzz-smoke coverage for every parser, decompressor, and container reader; fuzzing supplements rather than replaces tests.
- Keep production code at 100% line and region coverage. Any exclusion must be narrowly reviewed and documented in `docs/development.md` with its justification.
- Windows x86_64 is authoritative for Windows paths, metadata, packaging, and device behavior. Include spaces, Unicode, long paths, case collisions, reserved names, sparse files, and reparse points where relevant.

The core invariant is: verified extraction reproduces the selected source data and permitted metadata, or fails without committing partial results.

## CLI and format compatibility

- Human-readable status belongs on stderr; versioned machine-readable output belongs on stdout.
- Do not accept phrases directly as command-line argument values.
- Use stable, documented exit codes for invalid input, authentication failure, corruption, unsafe paths, capacity, permissions, and interruption.
- Detect authenticated formats from magic/version data, never from filename suffixes alone.
- Every on-disk structure needs unique magic, a version, explicit limits, canonical encoding rules, and compatibility tests.
- Unknown mandatory features fail cleanly. Optional features may be skipped only when the format explicitly makes that safe.

## Documentation and delivery

Update the relevant documentation whenever behavior, commands, dependencies, supported platforms, formats, or release requirements change. Keep examples runnable in PowerShell and avoid usernames, drive letters, machine-specific SDK paths, or undocumented local state.

Summaries should identify changed files, security-relevant decisions, tests run, coverage results, and remaining risks. Never describe unimplemented or unreviewed security properties as complete.
