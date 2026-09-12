# External dependencies

## Rust toolchain

| Dependency | Version | License/source | Update procedure |
| --- | --- | --- | --- |
| Rust compiler and Cargo | 1.98.0 | Apache-2.0/MIT, https://github.com/rust-lang/rust | Update `rust-toolchain.toml`, `workspace.package.rust-version`, then run `just verify`. |
| LLVM tools preview | Rust 1.98.0 component | Apache-2.0 with LLVM exceptions | Updated with the pinned Rust toolchain. |

The production workspace currently has no third-party Rust crates. `Cargo.lock`, `cargo deny`, and `cargo audit` must be reviewed whenever dependencies change.

## Developer and CI tools

`just`, `cargo-llvm-cov`, `cargo-deny`, and `cargo-audit` are installed from crates.io with Cargo's locked installation mode. GitHub Actions are pinned to immutable commit SHAs in each workflow. Review release notes, licenses, and the pinned revision before updating any tool or action.
