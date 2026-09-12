# Vaero

Vaero is a Windows-first, open-source command-line project for protecting directories and devices with memorable recovery phrases.

> Vaero is pre-release software. Its encryption and archive formats are not yet implemented or independently reviewed. Do not use it to protect the only copy of data.

## Quick start

Install Git, Rust through `rustup`, and Visual Studio 2022 Build Tools with the MSVC C++ tools and Windows SDK. Then run:

```powershell
git clone https://github.com/Kayyo321/Vaero.git
Set-Location Vaero
rustup show
cargo build --workspace --locked
cargo test --workspace --locked
cargo run -p vaero-cli -- --help
```

Contributors should run `powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/bootstrap.ps1 -InstallTools` once and `just verify` before requesting review. See [the development guide](docs/development.md), [the project specification](PROJECT.md), and [the development workflow](WORKFLOW.md).
