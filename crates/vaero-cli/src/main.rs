use std::process::ExitCode;

const HELP: &str = "Vaero protects directories and devices with recoverable encryption.\n\nUsage: vaero [--help | --version]";

fn main() -> ExitCode {
    match std::env::args_os().nth(1).as_deref() {
        None => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        Some(arg) if arg == "--help" || arg == "-h" => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        Some(arg) if arg == "--version" || arg == "-V" => {
            println!("vaero {}", vaero_core::VERSION);
            ExitCode::SUCCESS
        }
        Some(_) => {
            eprintln!("invalid arguments; run `vaero --help`");
            ExitCode::from(2)
        }
    }
}
