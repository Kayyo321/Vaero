# Vaero

Vaero is a Windows-first, open-source command-line project for protecting directories and devices with memorable recovery phrases.

> Vaero is pre-release software. Its encrypted container format is an experimental draft and has not been independently reviewed; its archive and compression formats are not yet implemented. Containers written today may be unreadable by later builds. Do not use Vaero to protect the only copy of data.

## What works today (Phase 1, experimental)

Single-file encryption with a generated recovery phrase, per the draft format in [docs/formats/crypt-v1.md](docs/formats/crypt-v1.md):

```powershell
vaero encrypt secrets.db --phrase-out phrase.txt   # writes secrets.db.crypt, phrase to a new file
vaero inspect secrets.db.crypt                      # public header as JSON on stdout
vaero verify  secrets.db.crypt --phrase-file phrase.txt
vaero decrypt secrets.db.crypt --phrase-file phrase.txt
```

The phrase is the key: losing it means losing the data. Phrases are never accepted directly on the command line; interactively, the generated phrase is printed once to the terminal unless `--phrase-out` is given.

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
