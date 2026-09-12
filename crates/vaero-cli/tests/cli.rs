//! End-to-end integration tests for the `vaero` binary: stdout/stderr
//! separation, the documented exit codes, redirection behavior, and the
//! transactional file guarantees observable from outside the process.

use std::ffi::OsStr;
use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

/// A valid BIP-39 test phrase (all-zero entropy) that no generated phrase
/// will ever match.
const KNOWN_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon about";

/// A unique, self-cleaning directory under the system temp directory.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vaero-cli-e2e-{tag}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test directory should be creatable");
        Self { path }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn assert_no_partial_files(&self) {
        for entry in fs::read_dir(&self.path).expect("test directory should be readable") {
            let name = entry
                .expect("directory entry should be readable")
                .file_name();
            assert!(
                !name.to_string_lossy().contains("vaero-partial"),
                "leftover temporary file: {}",
                name.display()
            );
        }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.path);
    }
}

/// Run the real binary with stdin attached to the null device.
fn vaero(args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vaero"))
        .args(args)
        .output()
        .expect("vaero should run")
}

/// Run the real binary with `stdin_bytes` piped to standard input.
fn vaero_with_stdin(args: &[&OsStr], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_vaero"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("vaero should spawn");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(stdin_bytes)
        .expect("stdin should accept the phrase");
    child.wait_with_output().expect("vaero should run")
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("vaero should exit with a code")
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn help_and_version_succeed() {
    for argument in ["--help", "-h", "--version", "-V"] {
        let output = vaero(&[OsStr::new(argument)]);
        assert!(output.status.success(), "{argument} should succeed");
        assert!(!output.stdout.is_empty(), "{argument} should write stdout");
        assert!(
            output.stderr.is_empty(),
            "{argument} should not write stderr"
        );
    }
    let help = vaero(&[OsStr::new("--help")]);
    let text = stdout_text(&help);
    assert!(text.contains("Usage:"));
    assert!(text.contains("Exit codes:"));
}

#[test]
fn no_arguments_prints_help() {
    let output = vaero(&[]);
    assert!(output.status.success());
    assert!(stdout_text(&output).contains("Usage:"));
}

#[test]
fn unknown_command_is_a_usage_error() {
    let output = vaero(&[OsStr::new("unknown")]);
    assert_eq!(code(&output), 2);
    assert!(stderr_text(&output).contains("unrecognized command `unknown`"));
    assert!(output.stdout.is_empty());
}

#[test]
fn phrase_option_is_rejected() {
    let output = vaero(&[
        OsStr::new("encrypt"),
        OsStr::new("in.bin"),
        OsStr::new("--phrase"),
        OsStr::new("abandon"),
    ]);
    assert_eq!(code(&output), 2);
    let stderr = stderr_text(&output);
    assert!(stderr.contains("option `--phrase` does not exist"));
    assert!(stderr.contains("--phrase-stdin"));
}

#[test]
fn round_trip_encrypt_inspect_verify_decrypt() {
    let dir = TempDir::new("round-trip");
    let source = dir.file("data.bin");
    let plaintext: Vec<u8> = (0u32..4_096)
        .map(|i| u8::try_from((i * 31 + 7) % 251).unwrap())
        .collect();
    fs::write(&source, &plaintext).unwrap();
    let phrase_file = dir.file("phrase.txt");

    // Encrypt with the default output name and a phrase file.
    let encrypt = vaero(&[
        OsStr::new("encrypt"),
        source.as_os_str(),
        OsStr::new("--phrase-out"),
        phrase_file.as_os_str(),
    ]);
    assert_eq!(code(&encrypt), 0, "stderr: {}", stderr_text(&encrypt));
    assert!(encrypt.stdout.is_empty(), "encrypt must not write stdout");
    let container = dir.file("data.bin.crypt");
    assert!(container.exists(), "default output must be <input>.crypt");
    assert_eq!(fs::read(&source).unwrap(), plaintext, "source preserved");

    // The phrase file holds space-separated words plus a newline, and the
    // phrase never appears on the redirected stderr.
    let phrase_text = fs::read_to_string(&phrase_file).unwrap();
    assert!(phrase_text.ends_with('\n'));
    let words: Vec<&str> = phrase_text.trim_end_matches('\n').split(' ').collect();
    assert_eq!(words.len(), 12);
    for word in &words {
        assert!(!word.is_empty());
        assert!(word.chars().all(|c| c.is_ascii_lowercase()));
    }
    assert!(
        !stderr_text(&encrypt).contains(phrase_text.trim_end_matches('\n')),
        "the phrase must never reach a redirected stderr"
    );

    // Inspect emits exactly the documented one-line JSON on stdout.
    let inspect = vaero(&[OsStr::new("inspect"), container.as_os_str()]);
    assert_eq!(code(&inspect), 0);
    assert!(inspect.stderr.is_empty(), "inspect status is stdout-only");
    let json = stdout_text(&inspect);
    let expected_prefix = "{\"schema\":1,\"format\":\"vaero-crypt\",\"formatVersion\":1,\
                           \"suite\":1,\"kdf\":{\"memoryKib\":65536,\"iterations\":3,\
                           \"parallelism\":1},\"containerId\":\"";
    assert!(
        json.starts_with(expected_prefix),
        "unexpected inspect JSON: {json}"
    );
    let container_id = &json[expected_prefix.len()..json.len() - 3];
    assert_eq!(container_id.len(), 32);
    assert!(
        container_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "containerId must be lowercase hex: {container_id}"
    );
    assert!(json.ends_with("\"}\n"));

    // Verify with the phrase file.
    let verify = vaero(&[
        OsStr::new("verify"),
        container.as_os_str(),
        OsStr::new("--phrase-file"),
        phrase_file.as_os_str(),
    ]);
    assert_eq!(code(&verify), 0, "stderr: {}", stderr_text(&verify));
    assert!(verify.stdout.is_empty());
    assert!(stderr_text(&verify).contains("verified"));

    // Decrypt with the phrase file; output must be byte-identical.
    let restored = dir.file("restored.bin");
    let decrypt = vaero(&[
        OsStr::new("decrypt"),
        container.as_os_str(),
        OsStr::new("-o"),
        restored.as_os_str(),
        OsStr::new("--phrase-file"),
        phrase_file.as_os_str(),
    ]);
    assert_eq!(code(&decrypt), 0, "stderr: {}", stderr_text(&decrypt));
    assert_eq!(fs::read(&restored).unwrap(), plaintext);

    // Decrypt again with the phrase piped to stdin.
    let restored_stdin = dir.file("restored-stdin.bin");
    let decrypt_stdin = vaero_with_stdin(
        &[
            OsStr::new("decrypt"),
            container.as_os_str(),
            OsStr::new("-o"),
            restored_stdin.as_os_str(),
            OsStr::new("--phrase-stdin"),
        ],
        phrase_text.as_bytes(),
    );
    assert_eq!(
        code(&decrypt_stdin),
        0,
        "stderr: {}",
        stderr_text(&decrypt_stdin)
    );
    assert_eq!(fs::read(&restored_stdin).unwrap(), plaintext);

    dir.assert_no_partial_files();
}

#[test]
fn wrong_phrase_and_corruption_are_classified() {
    let dir = TempDir::new("failure-matrix");
    let source = dir.file("data.bin");
    fs::write(&source, b"classified failure payload").unwrap();
    let phrase_file = dir.file("phrase.txt");
    let encrypt = vaero(&[
        OsStr::new("encrypt"),
        source.as_os_str(),
        OsStr::new("--phrase-out"),
        phrase_file.as_os_str(),
    ]);
    assert_eq!(code(&encrypt), 0, "stderr: {}", stderr_text(&encrypt));
    let container = dir.file("data.bin.crypt");
    let container_bytes = fs::read(&container).unwrap();

    // A wrong (but well-formed) phrase is an authentication failure.
    let wrong_phrase = dir.file("wrong-phrase.txt");
    fs::write(&wrong_phrase, KNOWN_PHRASE).unwrap();
    let restored = dir.file("restored.bin");
    let wrong = vaero(&[
        OsStr::new("decrypt"),
        container.as_os_str(),
        OsStr::new("-o"),
        restored.as_os_str(),
        OsStr::new("--phrase-file"),
        wrong_phrase.as_os_str(),
    ]);
    assert_eq!(code(&wrong), 3);
    assert!(stderr_text(&wrong).contains("authentication failed"));
    assert!(!restored.exists(), "no plaintext may be committed");

    // A byte flipped inside the wrapped key slot is an authentication
    // failure even with the correct phrase.
    let tampered = dir.file("tampered.crypt");
    let mut tampered_bytes = container_bytes.clone();
    tampered_bytes[120] ^= 0x01;
    fs::write(&tampered, &tampered_bytes).unwrap();
    let auth = vaero(&[
        OsStr::new("verify"),
        tampered.as_os_str(),
        OsStr::new("--phrase-file"),
        phrase_file.as_os_str(),
    ]);
    assert_eq!(code(&auth), 3);

    // A byte flipped in the magic is a format failure.
    let bad_magic = dir.file("bad-magic.crypt");
    let mut bad_magic_bytes = container_bytes.clone();
    bad_magic_bytes[0] ^= 0xFF;
    fs::write(&bad_magic, &bad_magic_bytes).unwrap();
    let magic = vaero(&[
        OsStr::new("verify"),
        bad_magic.as_os_str(),
        OsStr::new("--phrase-file"),
        phrase_file.as_os_str(),
    ]);
    assert_eq!(code(&magic), 4);
    assert!(stderr_text(&magic).contains("corrupt or unsupported container"));

    // A container truncated inside the header is a format failure.
    let truncated = dir.file("truncated.crypt");
    fs::write(&truncated, &container_bytes[..100]).unwrap();
    let short = vaero(&[
        OsStr::new("verify"),
        truncated.as_os_str(),
        OsStr::new("--phrase-file"),
        phrase_file.as_os_str(),
    ]);
    assert_eq!(code(&short), 4);

    dir.assert_no_partial_files();
}

#[test]
fn missing_inputs_are_io_failures() {
    let dir = TempDir::new("missing-inputs");
    let phrase_file = dir.file("phrase.txt");
    fs::write(&phrase_file, KNOWN_PHRASE).unwrap();
    let missing = dir.file("missing.crypt");

    let encrypt = vaero(&[
        OsStr::new("encrypt"),
        dir.file("missing.bin").as_os_str(),
        OsStr::new("--phrase-out"),
        dir.file("phrase.out").as_os_str(),
    ]);
    assert_eq!(code(&encrypt), 5);
    assert!(stderr_text(&encrypt).contains("i/o failure"));
    assert!(
        !dir.file("phrase.out").exists(),
        "no phrase file on failure"
    );

    // Decrypt infers `missing` from `missing.crypt`, then fails to open.
    let decrypt = vaero(&[
        OsStr::new("decrypt"),
        missing.as_os_str(),
        OsStr::new("--phrase-file"),
        phrase_file.as_os_str(),
    ]);
    assert_eq!(code(&decrypt), 5);

    let verify = vaero(&[
        OsStr::new("verify"),
        missing.as_os_str(),
        OsStr::new("--phrase-file"),
        phrase_file.as_os_str(),
    ]);
    assert_eq!(code(&verify), 5);

    let inspect = vaero(&[OsStr::new("inspect"), missing.as_os_str()]);
    assert_eq!(code(&inspect), 5);
    assert!(inspect.stdout.is_empty(), "no JSON on failure");

    // A missing phrase file is also an I/O failure, reported before the
    // container is touched.
    let no_phrase = vaero(&[
        OsStr::new("verify"),
        missing.as_os_str(),
        OsStr::new("--phrase-file"),
        dir.file("no-phrase.txt").as_os_str(),
    ]);
    assert_eq!(code(&no_phrase), 5);
    assert!(stderr_text(&no_phrase).contains("failed to read the recovery phrase"));
}

#[test]
fn existing_destinations_are_refused() {
    let dir = TempDir::new("existing-destination");
    let source = dir.file("data.bin");
    fs::write(&source, b"do not overwrite me").unwrap();
    let taken = dir.file("taken.crypt");
    fs::write(&taken, b"already here").unwrap();

    let encrypt = vaero(&[
        OsStr::new("encrypt"),
        source.as_os_str(),
        OsStr::new("-o"),
        taken.as_os_str(),
        OsStr::new("--phrase-out"),
        dir.file("phrase.txt").as_os_str(),
    ]);
    assert_eq!(code(&encrypt), 6);
    assert!(stderr_text(&encrypt).contains("destination already exists"));
    assert_eq!(fs::read(&taken).unwrap(), b"already here");

    // The destination check fires before the container is even opened.
    let phrase_file = dir.file("phrase-known.txt");
    fs::write(&phrase_file, KNOWN_PHRASE).unwrap();
    let decrypt = vaero(&[
        OsStr::new("decrypt"),
        dir.file("bogus.crypt").as_os_str(),
        OsStr::new("-o"),
        source.as_os_str(),
        OsStr::new("--phrase-file"),
        phrase_file.as_os_str(),
    ]);
    assert_eq!(code(&decrypt), 6);
    assert_eq!(fs::read(&source).unwrap(), b"do not overwrite me");
}

#[test]
fn redirected_stderr_requires_phrase_out() {
    let dir = TempDir::new("redirected-stderr");
    let source = dir.file("data.bin");
    fs::write(&source, b"phrase must not leak").unwrap();
    let output = vaero(&[OsStr::new("encrypt"), source.as_os_str()]);
    assert_eq!(code(&output), 2);
    assert!(stderr_text(&output).contains("--phrase-out"));
    assert!(
        !dir.file("data.bin.crypt").exists(),
        "nothing may be encrypted before the phrase policy is satisfied"
    );
    assert_eq!(fs::read(&source).unwrap(), b"phrase must not leak");
}

#[test]
fn invalid_phrase_text_is_a_usage_error() {
    let dir = TempDir::new("invalid-phrase");
    let container = dir.file("input.crypt");

    let two_words = dir.file("two-words.txt");
    fs::write(&two_words, "hello world").unwrap();
    let word_count = vaero(&[
        OsStr::new("decrypt"),
        container.as_os_str(),
        OsStr::new("--phrase-file"),
        two_words.as_os_str(),
    ]);
    assert_eq!(code(&word_count), 2);
    assert!(stderr_text(&word_count).contains("phrase must contain 12, 18, or 24 words, found 2"));

    let bad_checksum = dir.file("bad-checksum.txt");
    fs::write(&bad_checksum, KNOWN_PHRASE.replace("about", "abandon")).unwrap();
    let checksum = vaero(&[
        OsStr::new("verify"),
        container.as_os_str(),
        OsStr::new("--phrase-file"),
        bad_checksum.as_os_str(),
    ]);
    assert_eq!(code(&checksum), 2);
    assert!(stderr_text(&checksum).contains("phrase checksum mismatch"));

    let unknown_word = vaero_with_stdin(
        &[
            OsStr::new("decrypt"),
            container.as_os_str(),
            OsStr::new("--phrase-stdin"),
        ],
        KNOWN_PHRASE.replace("about", "zzzz").as_bytes(),
    );
    assert_eq!(code(&unknown_word), 2);
    assert!(
        stderr_text(&unknown_word).contains("phrase word at position 11 is not in the word list")
    );
}

#[test]
fn decrypt_without_crypt_suffix_requires_output() {
    let dir = TempDir::new("no-suffix");
    let output = vaero_with_stdin(
        &[
            OsStr::new("decrypt"),
            dir.file("archive.bin").as_os_str(),
            OsStr::new("--phrase-stdin"),
        ],
        KNOWN_PHRASE.as_bytes(),
    );
    assert_eq!(code(&output), 2);
    let stderr = stderr_text(&output);
    assert!(stderr.contains("does not end in `.crypt`"));
    assert!(stderr.contains("-o <file>"));
}

#[test]
fn phrase_out_must_be_a_new_file() {
    let dir = TempDir::new("phrase-out-exists");
    let source = dir.file("data.bin");
    fs::write(&source, b"phrase file collision payload").unwrap();
    let phrase_file = dir.file("phrase.txt");
    fs::write(&phrase_file, b"pre-existing user data").unwrap();

    let output = vaero(&[
        OsStr::new("encrypt"),
        source.as_os_str(),
        OsStr::new("--phrase-out"),
        phrase_file.as_os_str(),
    ]);
    assert_eq!(code(&output), 5);
    let stderr = stderr_text(&output);
    assert!(stderr.contains("failed to write the recovery phrase"));
    assert!(stderr.contains("discarded"));
    assert!(
        !dir.file("data.bin.crypt").exists(),
        "an unrecoverable container must not be left behind"
    );
    assert_eq!(
        fs::read(&phrase_file).unwrap(),
        b"pre-existing user data",
        "the existing file must be preserved"
    );
    assert_eq!(fs::read(&source).unwrap(), b"phrase file collision payload");
    dir.assert_no_partial_files();
}
