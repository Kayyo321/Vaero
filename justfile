set shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

default:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
    cargo test --workspace --all-features

test-fuzz-smoke:
    cargo test --workspace --all-features fuzz_smoke

coverage:
    powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/coverage.ps1

audit:
    powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/audit.ps1

verify: fmt-check lint test test-fuzz-smoke coverage

build-release:
    cargo build --workspace --release --locked
    @Write-Host "Built vaero {{invocation_directory()}}\target\release\vaero.exe (version $(cargo metadata --no-deps --format-version 1 | ConvertFrom-Json | Select-Object -ExpandProperty packages | Select-Object -First 1 -ExpandProperty version))"

package:
    powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/package.ps1
