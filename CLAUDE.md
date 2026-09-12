# CLAUDE.md

Vaero is a pre-release, Windows-first Rust security CLI. Work as a cautious maintainer: protect user data, treat input as hostile, keep changes reviewable, and never overstate the maturity of cryptography or file formats.

Follow `AGENTS.md` as the canonical repository instructions. Before substantial work, read `PROJECT.md`, `WORKFLOW.md`, and `docs/development.md`.

## Fast context

- Work from `devel`; `main` is stable/release-only.
- Rust is pinned in `rust-toolchain.toml`; use `--workspace` and locked dependencies.
- Current crates are `crates/vaero-cli`, `crates/vaero-core`, and `crates/vaero-crypto`.
- `vaero-core` contains reusable policy and orchestration and must not prompt or perform hidden writes.
- Human CLI output goes to stderr; versioned machine output goes to stdout.
- Windows x86_64 is authoritative for path, metadata, packaging, and future device behavior.

## Required validation

During development, run targeted Cargo tests. Before completing code or build changes, run:

```powershell
just verify
just audit
```

Bootstrap missing tools with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/bootstrap.ps1 -InstallTools
```

For documentation-only edits, use `git diff --check` and inspect rendered structure and links. Report checks not run.

## Non-negotiable rules

- Do not invent cryptography, silently finalize a proposed format, or add a cryptographic dependency without documenting and reviewing the choice.
- Never print or log phrases, keys, plaintext metadata, or signing secrets.
- Authenticate before exposing plaintext and fail closed on malformed, corrupt, truncated, reordered, unknown, or resource-exhausting input.
- Validate extraction paths and prevent traversal, absolute or drive-prefixed paths, Windows reserved names, collisions, and reparse-point escapes.
- Bound all hostile-input resources, including allocation, KDF cost, nesting, counts, path lengths, and decompression expansion.
- Preserve sources. Use temporary output, finalize, flush, verify, and atomically commit; do not overwrite by default.
- Test success, failure, interruption, permissions, and capacity behavior. Maintain 100% line and region coverage for production code.
- Keep dependencies minimal, versioned, locked, audited, license-approved, and documented in `docs/dependencies.md`.
- Never create tags, publish releases, alter branch protections, or bypass required checks unless explicitly requested.
- Do not claim production readiness or secure deletion; retain the pre-release warnings until independent review and stable-format criteria are met.

When requirements are ambiguous, choose the behavior that releases the least information, modifies the least data, preserves recovery, and fails most safely. Surface decisions that affect compatibility, cryptography, destructive behavior, or user-visible guarantees before committing to them.
