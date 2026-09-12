# External dependencies

## Rust toolchain

| Dependency | Version | License/source | Update procedure |
| --- | --- | --- | --- |
| Rust compiler and Cargo | 1.98.0 | Apache-2.0/MIT, https://github.com/rust-lang/rust | Update `rust-toolchain.toml`, `workspace.package.rust-version`, then run `just verify`. |
| LLVM tools preview | Rust 1.98.0 component | Apache-2.0 with LLVM exceptions | Updated with the pinned Rust toolchain. |

## Production crates

All production dependencies below were added for the Phase 1 `.crypt` container (`docs/formats/crypt-v1.md`). Each implements a primitive that `PROJECT.md` §4–§5 proposes; none is a novel construction. They are maintained RustCrypto/rust-random projects, pinned through `Cargo.lock`, and checked by `cargo deny` and `cargo audit`. The cryptographic selection remains provisional until the independent review required before the format is declared stable.

| Crate | Version | License | Role | Update procedure |
| --- | --- | --- | --- | --- |
| `argon2` | 0.5.3 | Apache-2.0/MIT, RustCrypto | Argon2id key derivation from phrase entropy (RFC 9106 implementation) | Review changelog and advisories, bump `[workspace.dependencies]`, regenerate `Cargo.lock`, run `just verify` and `just audit`. |
| `chacha20poly1305` | 0.10.1 | Apache-2.0/MIT, RustCrypto | XChaCha20-Poly1305 AEAD for frames and CEK wrapping (NCC Group audit, 2020) | Same as above. |
| `sha2` | 0.10.9 | Apache-2.0/MIT, RustCrypto | SHA-256 for the BIP-39 phrase checksum and plaintext commitment | Same as above. |
| `getrandom` | 0.3.4 | Apache-2.0/MIT, rust-random | Operating-system CSPRNG for entropy, salts, ids, and nonces | Same as above. |
| `zeroize` | 1.9.0 | Apache-2.0/MIT, RustCrypto | Best-effort zeroization of phrase entropy and keys | Same as above. |

Transitive crates (`aead`, `chacha20`, `cipher`, `poly1305`, `digest`, `subtle`, `password-hash`, `base64ct`, and related RustCrypto utility crates) are locked in `Cargo.lock` and covered by the same license and advisory gates. `Cargo.lock`, `cargo deny`, and `cargo audit` must be reviewed whenever dependencies change.

## Developer and CI tools

`just`, `cargo-llvm-cov`, `cargo-deny`, and `cargo-audit` are installed from crates.io with Cargo's locked installation mode. GitHub Actions are pinned to immutable commit SHAs in each workflow. Review release notes, licenses, and the pinned revision before updating any tool or action.
