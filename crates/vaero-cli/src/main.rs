//! Binary entry point for `vaero`: argument handling, terminal detection,
//! and command execution all live in the `vaero-cli` library.

use std::io::IsTerminal;
use std::process::ExitCode;

fn main() -> ExitCode {
    let code = vaero_cli::run(std::env::args_os().skip(1), std::io::stderr().is_terminal());
    ExitCode::from(code)
}
