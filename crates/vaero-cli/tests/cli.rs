use std::process::Command;

#[test]
fn help_and_version_succeed() {
    for argument in ["--help", "-h", "--version", "-V"] {
        let output = Command::new(env!("CARGO_BIN_EXE_vaero"))
            .arg(argument)
            .output()
            .expect("vaero should run");
        assert!(output.status.success());
        assert!(!output.stdout.is_empty());
    }
}

#[test]
fn no_arguments_prints_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_vaero"))
        .output()
        .expect("vaero should run");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
}

#[test]
fn unknown_argument_uses_invalid_argument_exit_code() {
    let output = Command::new(env!("CARGO_BIN_EXE_vaero"))
        .arg("unknown")
        .output()
        .expect("vaero should run");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid arguments"));
}
