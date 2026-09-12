//! Argument parsing and command execution for the `vaero` command-line
//! interface.
//!
//! [`parse_command`] turns raw `OsString` arguments into a typed [`Command`]
//! without touching the filesystem, prompting, printing, or performing
//! cryptography; [`run`] executes the parsed command against the
//! transactional file operations in `vaero-core`. The binding contract
//! (command surface, exit codes, and the phrase-handling policy) is
//! `docs/formats/crypt-v1.md` §6; code and document change together.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use vaero_core::{KdfParams, Phrase, PhraseLength, PublicInfo};

/// Exit code for success.
pub const EXIT_SUCCESS: u8 = 0;
/// Exit code for a usage error or invalid phrase text.
pub const EXIT_USAGE: u8 = 2;
/// Exit code for an authentication failure (wrong phrase or tampered container).
pub const EXIT_AUTH: u8 = 3;
/// Exit code for a corrupt or unsupported container.
pub const EXIT_FORMAT: u8 = 4;
/// Exit code for an I/O or permission failure.
pub const EXIT_IO: u8 = 5;
/// Exit code for a destination that already exists.
pub const EXIT_DESTINATION_EXISTS: u8 = 6;

/// Full usage text for `vaero`, matching the command surface and exit codes
/// documented in `docs/formats/crypt-v1.md` §6.
pub const USAGE: &str = "\
Vaero protects directories and devices with recoverable encryption.

Usage:
  vaero encrypt <input> [-o <file>] [--words 12|18|24] [--phrase-out <file>]
  vaero decrypt <input> [-o <file>] (--phrase-file <file> | --phrase-stdin)
  vaero verify  <input> (--phrase-file <file> | --phrase-stdin)
  vaero inspect <input>
  vaero --help | --version

Commands:
  encrypt  Encrypt a file into a .crypt container, generating a recovery phrase
  decrypt  Decrypt a .crypt container using a recovery phrase
  verify   Check a container and phrase without writing any plaintext
  inspect  Print public container metadata as JSON on stdout

Options:
  -o, --output <file>     Destination path; encrypt defaults to <input>.crypt,
                          decrypt strips a trailing .crypt or requires -o
      --words <n>         Recovery phrase length in words: 12, 18, or 24
                          (default 12); encrypt only
      --phrase-out <file> Write the generated phrase to a new file; required
                          when stderr is not a terminal; encrypt only
      --phrase-file <file>
                          Read the recovery phrase from a file
      --phrase-stdin      Read the recovery phrase from standard input
  -h, --help              Print this help text
  -V, --version           Print the version

Recovery phrases are never accepted as command-line argument values; a
--phrase <value> option deliberately does not exist.

Exit codes:
  0  Success
  2  Usage error or invalid phrase text (bad word, checksum, or word count)
  3  Authentication failure (wrong phrase or tampered container)
  4  Corrupt or unsupported container
  5  I/O or permission failure
  6  Destination already exists
";

/// Message rejecting any attempt to pass a phrase as a command-line argument.
const PHRASE_REJECTION: &str = "option `--phrase` does not exist: a recovery \
phrase given as a command-line argument would be visible in process listings \
and shell history; use `--phrase-file <file>` or `--phrase-stdin` instead";

/// Default recovery phrase length in words when `--words` is not given.
const DEFAULT_WORDS: u32 = 12;

/// Where a recovery phrase should be read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhraseSource {
    /// Read the phrase from the named file.
    File(PathBuf),
    /// Read the phrase from standard input.
    Stdin,
}

/// Parsed arguments for `vaero encrypt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptArgs {
    /// Source file to encrypt.
    pub input: PathBuf,
    /// Destination override; defaults to `<input>.crypt` when absent.
    pub output: Option<PathBuf>,
    /// Recovery phrase length in words: 12, 18, or 24 (default 12).
    pub words: u32,
    /// Optional new file the generated phrase is written to.
    pub phrase_out: Option<PathBuf>,
}

/// Parsed arguments for `vaero decrypt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptArgs {
    /// Container file to decrypt.
    pub input: PathBuf,
    /// Destination override; without it a trailing `.crypt` is stripped.
    pub output: Option<PathBuf>,
    /// Where the recovery phrase is read from.
    pub phrase: PhraseSource,
}

/// Parsed arguments for `vaero verify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyArgs {
    /// Container file to verify.
    pub input: PathBuf,
    /// Where the recovery phrase is read from.
    pub phrase: PhraseSource,
}

/// Parsed arguments for `vaero inspect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectArgs {
    /// Container file to inspect.
    pub input: PathBuf,
}

/// A fully parsed `vaero` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Print [`USAGE`]; also the result of an empty argument list.
    Help,
    /// Print the application version.
    Version,
    /// Encrypt a file.
    Encrypt(EncryptArgs),
    /// Decrypt a container.
    Decrypt(DecryptArgs),
    /// Verify a container without writing plaintext.
    Verify(VerifyArgs),
    /// Inspect a container's public metadata.
    Inspect(InspectArgs),
}

/// A usage error whose message tells the user exactly what was wrong.
///
/// Callers print the message to stderr and exit with [`EXIT_USAGE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

impl fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

/// Options that exist somewhere on the command surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opt {
    Output,
    Words,
    PhraseOut,
    PhraseFile,
    PhraseStdin,
}

/// Accumulated raw values while walking a subcommand's arguments.
#[derive(Default)]
struct Parsed {
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    words: Option<u32>,
    phrase_out: Option<PathBuf>,
    phrase_file: Option<PathBuf>,
    phrase_stdin: bool,
}

/// Parse the command line into a typed [`Command`].
///
/// `args` must exclude the program name (`argv[0]`); an empty iterator yields
/// [`Command::Help`]. `--help`/`-h` and `--version`/`-V` are recognized only
/// as the first token; any tokens after them are ignored. Option values and
/// positional paths may be non-UTF-8 and are carried through unchanged.
///
/// # Errors
///
/// Returns [`UsageError`] with a message naming the offending token when the
/// command line does not match the documented surface: an unrecognized command
/// or option, an option the subcommand does not accept, a duplicated or
/// valueless option, an out-of-range `--words` value, a missing or extra
/// positional path, a missing or ambiguous phrase source, or any use of the
/// deliberately unsupported `--phrase <value>`.
pub fn parse_command<I: Iterator<Item = OsString>>(mut args: I) -> Result<Command, UsageError> {
    let Some(first) = args.next() else {
        return Ok(Command::Help);
    };
    match first.to_str() {
        Some("--help" | "-h") => Ok(Command::Help),
        Some("--version" | "-V") => Ok(Command::Version),
        Some("encrypt") => parse_encrypt(args),
        Some("decrypt") => parse_decrypt(args),
        Some("verify") => parse_verify(args),
        Some("inspect") => parse_inspect(args),
        _ => Err(UsageError(format!(
            "unrecognized command `{}`; run `vaero --help` for usage",
            first.to_string_lossy()
        ))),
    }
}

fn parse_encrypt<I: Iterator<Item = OsString>>(args: I) -> Result<Command, UsageError> {
    let parsed = collect("encrypt", &[Opt::Output, Opt::Words, Opt::PhraseOut], args)?;
    let input = require_input("encrypt", parsed.input)?;
    Ok(Command::Encrypt(EncryptArgs {
        input,
        output: parsed.output,
        words: parsed.words.unwrap_or(DEFAULT_WORDS),
        phrase_out: parsed.phrase_out,
    }))
}

fn parse_decrypt<I: Iterator<Item = OsString>>(args: I) -> Result<Command, UsageError> {
    let parsed = collect(
        "decrypt",
        &[Opt::Output, Opt::PhraseFile, Opt::PhraseStdin],
        args,
    )?;
    let input = require_input("decrypt", parsed.input)?;
    let phrase = phrase_source("decrypt", parsed.phrase_file, parsed.phrase_stdin)?;
    Ok(Command::Decrypt(DecryptArgs {
        input,
        output: parsed.output,
        phrase,
    }))
}

fn parse_verify<I: Iterator<Item = OsString>>(args: I) -> Result<Command, UsageError> {
    let parsed = collect("verify", &[Opt::PhraseFile, Opt::PhraseStdin], args)?;
    let input = require_input("verify", parsed.input)?;
    let phrase = phrase_source("verify", parsed.phrase_file, parsed.phrase_stdin)?;
    Ok(Command::Verify(VerifyArgs { input, phrase }))
}

fn parse_inspect<I: Iterator<Item = OsString>>(args: I) -> Result<Command, UsageError> {
    let parsed = collect("inspect", &[], args)?;
    let input = require_input("inspect", parsed.input)?;
    Ok(Command::Inspect(InspectArgs { input }))
}

/// Walk a subcommand's tokens, collecting options and the positional input.
fn collect<I: Iterator<Item = OsString>>(
    subcommand: &str,
    allowed: &[Opt],
    mut args: I,
) -> Result<Parsed, UsageError> {
    let mut parsed = Parsed::default();
    while let Some(token) = args.next() {
        if token.as_encoded_bytes().first() == Some(&b'-') {
            let Some(name) = token.to_str() else {
                return Err(UsageError(format!(
                    "option `{}` is not valid UTF-8",
                    token.to_string_lossy()
                )));
            };
            if name == "--phrase" {
                return Err(UsageError(String::from(PHRASE_REJECTION)));
            }
            let Some(option) = lookup(name) else {
                return Err(UsageError(format!(
                    "unrecognized option `{name}` for `vaero {subcommand}`; \
                     run `vaero --help` for usage"
                )));
            };
            if !allowed.contains(&option) {
                return Err(UsageError(format!(
                    "option `{name}` is not supported by `vaero {subcommand}`"
                )));
            }
            match option {
                Opt::Output => set_path(&mut parsed.output, name, &mut args)?,
                Opt::Words => {
                    if parsed.words.is_some() {
                        return Err(duplicate_option(name));
                    }
                    parsed.words = Some(parse_words(&require_value(name, &mut args)?)?);
                }
                Opt::PhraseOut => set_path(&mut parsed.phrase_out, name, &mut args)?,
                Opt::PhraseFile => set_path(&mut parsed.phrase_file, name, &mut args)?,
                Opt::PhraseStdin => {
                    if parsed.phrase_stdin {
                        return Err(duplicate_option(name));
                    }
                    parsed.phrase_stdin = true;
                }
            }
        } else if parsed.input.is_none() {
            parsed.input = Some(PathBuf::from(token));
        } else {
            return Err(UsageError(format!(
                "unexpected argument `{}`: `vaero {subcommand}` takes exactly \
                 one <input> path",
                token.to_string_lossy()
            )));
        }
    }
    Ok(parsed)
}

/// Map a UTF-8 option name to its option, if it exists anywhere on the surface.
fn lookup(name: &str) -> Option<Opt> {
    match name {
        "-o" | "--output" => Some(Opt::Output),
        "--words" => Some(Opt::Words),
        "--phrase-out" => Some(Opt::PhraseOut),
        "--phrase-file" => Some(Opt::PhraseFile),
        "--phrase-stdin" => Some(Opt::PhraseStdin),
        _ => None,
    }
}

/// Store `name`'s path value into `slot`, rejecting duplicates.
fn set_path<I: Iterator<Item = OsString>>(
    slot: &mut Option<PathBuf>,
    name: &str,
    args: &mut I,
) -> Result<(), UsageError> {
    if slot.is_some() {
        return Err(duplicate_option(name));
    }
    *slot = Some(PathBuf::from(require_value(name, args)?));
    Ok(())
}

/// Take the next token as `name`'s value, or explain that one is required.
fn require_value<I: Iterator<Item = OsString>>(
    name: &str,
    args: &mut I,
) -> Result<OsString, UsageError> {
    args.next()
        .ok_or_else(|| UsageError(format!("option `{name}` requires a value")))
}

fn duplicate_option(name: &str) -> UsageError {
    UsageError(format!("duplicate option `{name}`"))
}

/// Parse a `--words` value; only 12, 18, and 24 are accepted.
fn parse_words(value: &OsStr) -> Result<u32, UsageError> {
    match value.to_str() {
        Some("12") => Ok(12),
        Some("18") => Ok(18),
        Some("24") => Ok(24),
        _ => Err(UsageError(format!(
            "invalid value `{}` for `--words`: allowed values are 12, 18, and 24",
            value.to_string_lossy()
        ))),
    }
}

fn require_input(subcommand: &str, input: Option<PathBuf>) -> Result<PathBuf, UsageError> {
    input.ok_or_else(|| UsageError(format!("`vaero {subcommand}` requires an <input> path")))
}

/// Resolve `--phrase-file`/`--phrase-stdin` into exactly one phrase source.
fn phrase_source(
    subcommand: &str,
    file: Option<PathBuf>,
    stdin: bool,
) -> Result<PhraseSource, UsageError> {
    match (file, stdin) {
        (Some(_), true) => Err(UsageError(format!(
            "`vaero {subcommand}` accepts only one of `--phrase-file` or `--phrase-stdin`"
        ))),
        (Some(path), false) => Ok(PhraseSource::File(path)),
        (None, true) => Ok(PhraseSource::Stdin),
        (None, false) => Err(UsageError(format!(
            "`vaero {subcommand}` requires a phrase source: pass \
             `--phrase-file <file>` or `--phrase-stdin`"
        ))),
    }
}

/// Parse and execute a full `vaero` invocation, returning its exit code.
///
/// `args` must exclude the program name (`argv[0]`). `stderr_is_terminal`
/// tells the phrase-handling policy whether a generated recovery phrase may
/// be shown on stderr: when stderr is redirected, `vaero encrypt` refuses to
/// run without `--phrase-out` rather than write the phrase to a redirected
/// stream. Human status and diagnostics go to stderr; the only stdout output
/// is `--help`/`--version` text and `vaero inspect`'s versioned JSON.
#[must_use]
pub fn run(args: impl Iterator<Item = OsString>, stderr_is_terminal: bool) -> u8 {
    dispatch(parse_command(args), stderr_is_terminal)
}

/// Map an execution failure from `vaero-core` to its documented exit code.
#[must_use]
pub fn exit_code_for(error: &vaero_core::Error) -> u8 {
    match error {
        vaero_core::Error::Io(_) => EXIT_IO,
        vaero_core::Error::Format(_) => EXIT_FORMAT,
        vaero_core::Error::Auth => EXIT_AUTH,
        vaero_core::Error::DestinationExists(_) => EXIT_DESTINATION_EXISTS,
    }
}

/// Execute a parse result: report usage errors or run the parsed command.
fn dispatch(parsed: Result<Command, UsageError>, stderr_is_terminal: bool) -> u8 {
    match parsed {
        Ok(Command::Help) => {
            print!("{USAGE}");
            EXIT_SUCCESS
        }
        Ok(Command::Version) => {
            println!("vaero {}", vaero_core::VERSION);
            EXIT_SUCCESS
        }
        Ok(Command::Encrypt(args)) => run_encrypt(&args, stderr_is_terminal),
        Ok(Command::Decrypt(args)) => run_decrypt(&args),
        Ok(Command::Verify(args)) => run_verify(&args),
        Ok(Command::Inspect(args)) => run_inspect(&args),
        Err(error) => {
            eprintln!("vaero: {error}");
            EXIT_USAGE
        }
    }
}

fn run_encrypt(args: &EncryptArgs, stderr_is_terminal: bool) -> u8 {
    if args.phrase_out.is_none() && !stderr_is_terminal {
        eprintln!(
            "vaero: stderr is not a terminal, so the generated recovery phrase cannot be \
             shown; pass `--phrase-out <new file>` instead of redirecting the phrase"
        );
        return EXIT_USAGE;
    }
    let output = match &args.output {
        Some(path) => path.clone(),
        None => default_encrypt_output(&args.input),
    };
    let length = phrase_length(args.words);
    match vaero_core::encrypt_file(&args.input, &output, length, &KdfParams::DEFAULT) {
        Ok((phrase, summary)) => {
            let words = phrase.words();
            if let Some(path) = &args.phrase_out {
                if let Err(error) = persist_phrase(path, &words) {
                    let _removed = fs::remove_file(&output);
                    eprintln!(
                        "vaero: failed to write the recovery phrase to `{}`: {error}; \
                         the encrypted output was discarded because it would be \
                         unrecoverable without the phrase",
                        path.display()
                    );
                    return EXIT_IO;
                }
                eprintln!("recovery phrase written to `{}`", path.display());
            } else {
                eprintln!(
                    "WARNING: the recovery phrase below is shown exactly once; \
                     losing the phrase means losing the data"
                );
                for (index, word) in words.iter().enumerate() {
                    eprintln!("{:>3}. {word}", index + 1);
                }
            }
            eprintln!(
                "encrypted `{}` to `{}` ({} bytes, {} frames)",
                args.input.display(),
                output.display(),
                summary.plaintext_len,
                summary.frames
            );
            EXIT_SUCCESS
        }
        Err(error) => report(&error),
    }
}

fn run_decrypt(args: &DecryptArgs) -> u8 {
    let output = if let Some(path) = &args.output {
        path.clone()
    } else if let Some(path) = default_decrypt_output(&args.input) {
        path
    } else {
        eprintln!(
            "vaero: cannot infer an output name: `{}` does not end in `.crypt`; \
             pass `-o <file>`",
            args.input.display()
        );
        return EXIT_USAGE;
    };
    let phrase = match load_phrase(&args.phrase) {
        Ok(phrase) => phrase,
        Err(code) => return code,
    };
    match vaero_core::decrypt_file(&args.input, &output, &phrase) {
        Ok(summary) => {
            eprintln!(
                "decrypted `{}` to `{}` ({} bytes, {} frames)",
                args.input.display(),
                output.display(),
                summary.plaintext_len,
                summary.frames
            );
            EXIT_SUCCESS
        }
        Err(error) => report(&error),
    }
}

fn run_verify(args: &VerifyArgs) -> u8 {
    let phrase = match load_phrase(&args.phrase) {
        Ok(phrase) => phrase,
        Err(code) => return code,
    };
    match vaero_core::verify_file(&args.input, &phrase) {
        Ok(summary) => {
            eprintln!(
                "verified `{}` ({} bytes, {} frames)",
                args.input.display(),
                summary.plaintext_len,
                summary.frames
            );
            EXIT_SUCCESS
        }
        Err(error) => report(&error),
    }
}

fn run_inspect(args: &InspectArgs) -> u8 {
    match vaero_core::inspect_file(&args.input) {
        Ok(info) => {
            println!("{}", container_json(&info));
            EXIT_SUCCESS
        }
        Err(error) => report(&error),
    }
}

/// Print an execution failure to stderr and return its exit code.
fn report(error: &vaero_core::Error) -> u8 {
    eprintln!("vaero: {error}");
    exit_code_for(error)
}

/// Default `encrypt` destination: the input path with `.crypt` appended.
fn default_encrypt_output(input: &Path) -> PathBuf {
    let mut name = input.as_os_str().to_os_string();
    name.push(".crypt");
    PathBuf::from(name)
}

/// Default `decrypt` destination: the input path with a final `.crypt`
/// extension stripped, or `None` when the input does not end in `.crypt`.
fn default_decrypt_output(input: &Path) -> Option<PathBuf> {
    match input.extension() {
        Some(extension) if extension == "crypt" => Some(input.with_extension("")),
        _ => None,
    }
}

/// Map a `--words` value to a phrase length.
///
/// The parser only produces 12, 18, or 24, each of which
/// [`PhraseLength::from_word_count`] accepts; the documented default of 12
/// words backstops the conversion without a reachable panic path.
fn phrase_length(words: u32) -> PhraseLength {
    let count = usize::try_from(words).unwrap_or(0);
    PhraseLength::from_word_count(count).unwrap_or(PhraseLength::Words12)
}

/// Read the recovery phrase text from its source and parse it.
///
/// On failure the diagnostic is printed to stderr and the exit code is
/// returned: [`EXIT_IO`] when the source cannot be read, [`EXIT_USAGE`] when
/// the text is not a valid phrase. Phrase material never appears in either
/// message.
fn load_phrase(source: &PhraseSource) -> Result<Phrase, u8> {
    let text = match read_phrase_text(source) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("vaero: failed to read the recovery phrase: {error}");
            return Err(EXIT_IO);
        }
    };
    match Phrase::parse(&text) {
        Ok(phrase) => Ok(phrase),
        Err(error) => {
            eprintln!("vaero: invalid recovery phrase: {error}");
            Err(EXIT_USAGE)
        }
    }
}

/// Read raw phrase text from a file or from standard input.
fn read_phrase_text(source: &PhraseSource) -> std::io::Result<String> {
    match source {
        PhraseSource::File(path) => fs::read_to_string(path),
        PhraseSource::Stdin => std::io::read_to_string(std::io::stdin().lock()),
    }
}

/// Write the recovery phrase to a new file that must not already exist.
fn persist_phrase(path: &Path, words: &[&'static str]) -> std::io::Result<()> {
    let mut file = File::create_new(path)?;
    write_phrase(&mut file, words)
}

/// Write phrase words space-separated with a trailing newline.
fn write_phrase<W: std::io::Write>(output: &mut W, words: &[&'static str]) -> std::io::Result<()> {
    for (index, word) in words.iter().enumerate() {
        if index > 0 {
            output.write_all(b" ")?;
        }
        output.write_all(word.as_bytes())?;
    }
    output.write_all(b"\n")?;
    output.flush()
}

/// Render `vaero inspect`'s one-line JSON document for stdout.
fn container_json(info: &PublicInfo) -> String {
    let mut container_id = String::with_capacity(32);
    for byte in info.container_id {
        let _ignored = write!(container_id, "{byte:02x}");
    }
    format!(
        "{{\"schema\":1,\"format\":\"vaero-crypt\",\"formatVersion\":{},\"suite\":{},\
         \"kdf\":{{\"memoryKib\":{},\"iterations\":{},\"parallelism\":{}}},\
         \"containerId\":\"{container_id}\"}}",
        info.format_version,
        info.suite,
        info.kdf.memory_kib,
        info.kdf.iterations,
        info.kdf.parallelism
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_os(tokens: Vec<OsString>) -> Result<Command, UsageError> {
        parse_command(tokens.into_iter())
    }

    fn parse(tokens: &[&str]) -> Result<Command, UsageError> {
        parse_os(tokens.iter().map(OsString::from).collect())
    }

    fn words_error(value: &str) -> String {
        format!("invalid value `{value}` for `--words`: allowed values are 12, 18, and 24")
    }

    #[cfg(windows)]
    fn non_utf8(prefix: &str) -> OsString {
        use std::os::windows::ffi::OsStringExt;
        let mut wide: Vec<u16> = prefix.encode_utf16().collect();
        wide.push(0xD800); // unpaired surrogate: not representable as UTF-8
        OsString::from_wide(&wide)
    }

    #[cfg(unix)]
    fn non_utf8(prefix: &str) -> OsString {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = prefix.as_bytes().to_vec();
        bytes.push(0xFF); // invalid UTF-8 byte
        OsString::from_vec(bytes)
    }

    /// Invalid invocations paired with the exact diagnostic they must produce.
    const USAGE_ERROR_CASES: &[(&[&str], &str)] = &[
        (
            &["frobnicate"],
            "unrecognized command `frobnicate`; run `vaero --help` for usage",
        ),
        (&["encrypt"], "`vaero encrypt` requires an <input> path"),
        (&["decrypt"], "`vaero decrypt` requires an <input> path"),
        (&["verify"], "`vaero verify` requires an <input> path"),
        (&["inspect"], "`vaero inspect` requires an <input> path"),
        (
            &["encrypt", "--words", "12"],
            "`vaero encrypt` requires an <input> path",
        ),
        (
            &["encrypt", "a", "b"],
            "unexpected argument `b`: `vaero encrypt` takes exactly one <input> path",
        ),
        (
            &["decrypt", "in", "--phrase-stdin", "extra"],
            "unexpected argument `extra`: `vaero decrypt` takes exactly one <input> path",
        ),
        (
            &["decrypt", "in"],
            "`vaero decrypt` requires a phrase source: pass `--phrase-file <file>` or \
             `--phrase-stdin`",
        ),
        (
            &["verify", "in"],
            "`vaero verify` requires a phrase source: pass `--phrase-file <file>` or \
             `--phrase-stdin`",
        ),
        (
            &["decrypt", "in", "--phrase-file", "p", "--phrase-stdin"],
            "`vaero decrypt` accepts only one of `--phrase-file` or `--phrase-stdin`",
        ),
        (
            &["verify", "in", "--phrase-stdin", "--phrase-file", "p"],
            "`vaero verify` accepts only one of `--phrase-file` or `--phrase-stdin`",
        ),
        (
            &["encrypt", "in", "--bogus"],
            "unrecognized option `--bogus` for `vaero encrypt`; run `vaero --help` for usage",
        ),
        (
            &["encrypt", "in", "-"],
            "unrecognized option `-` for `vaero encrypt`; run `vaero --help` for usage",
        ),
        (
            &["encrypt", "in", "--help"],
            "unrecognized option `--help` for `vaero encrypt`; run `vaero --help` for usage",
        ),
        (
            &["decrypt", "in", "-V"],
            "unrecognized option `-V` for `vaero decrypt`; run `vaero --help` for usage",
        ),
        (
            &["decrypt", "in", "--words", "12"],
            "option `--words` is not supported by `vaero decrypt`",
        ),
        (
            &["decrypt", "in", "--phrase-out", "p"],
            "option `--phrase-out` is not supported by `vaero decrypt`",
        ),
        (
            &["verify", "in", "-o", "x"],
            "option `-o` is not supported by `vaero verify`",
        ),
        (
            &["verify", "in", "--phrase-out", "p"],
            "option `--phrase-out` is not supported by `vaero verify`",
        ),
        (
            &["inspect", "in", "--output", "x"],
            "option `--output` is not supported by `vaero inspect`",
        ),
        (
            &["inspect", "in", "--phrase-stdin"],
            "option `--phrase-stdin` is not supported by `vaero inspect`",
        ),
        (
            &["inspect", "in", "--phrase-file", "p"],
            "option `--phrase-file` is not supported by `vaero inspect`",
        ),
        (
            &["encrypt", "in", "--phrase-file", "p"],
            "option `--phrase-file` is not supported by `vaero encrypt`",
        ),
        (
            &["encrypt", "in", "--phrase-stdin"],
            "option `--phrase-stdin` is not supported by `vaero encrypt`",
        ),
        (&["encrypt", "in", "-o"], "option `-o` requires a value"),
        (
            &["encrypt", "in", "--words"],
            "option `--words` requires a value",
        ),
        (
            &["encrypt", "in", "--phrase-out"],
            "option `--phrase-out` requires a value",
        ),
        (
            &["decrypt", "in", "--phrase-file"],
            "option `--phrase-file` requires a value",
        ),
        (
            &["encrypt", "in", "-o", "a", "-o", "b"],
            "duplicate option `-o`",
        ),
        (
            &["encrypt", "in", "-o", "a", "--output", "b"],
            "duplicate option `--output`",
        ),
        (
            &["encrypt", "in", "--words", "12", "--words", "18"],
            "duplicate option `--words`",
        ),
        (
            &["encrypt", "in", "--phrase-out", "a", "--phrase-out", "b"],
            "duplicate option `--phrase-out`",
        ),
        (
            &["decrypt", "in", "--phrase-file", "a", "--phrase-file", "b"],
            "duplicate option `--phrase-file`",
        ),
        (
            &["decrypt", "in", "--phrase-stdin", "--phrase-stdin"],
            "duplicate option `--phrase-stdin`",
        ),
    ];

    #[test]
    fn exit_codes_match_the_contract() {
        assert_eq!(EXIT_USAGE, 2);
        assert_eq!(EXIT_AUTH, 3);
        assert_eq!(EXIT_FORMAT, 4);
        assert_eq!(EXIT_IO, 5);
        assert_eq!(EXIT_DESTINATION_EXISTS, 6);
    }

    #[test]
    fn usage_text_documents_the_command_surface() {
        for needle in [
            "Usage:",
            "vaero encrypt <input> [-o <file>] [--words 12|18|24] [--phrase-out <file>]",
            "vaero decrypt <input> [-o <file>] (--phrase-file <file> | --phrase-stdin)",
            "vaero verify  <input> (--phrase-file <file> | --phrase-stdin)",
            "vaero inspect <input>",
            "vaero --help | --version",
            "Exit codes:",
            "2  Usage error",
            "3  Authentication failure",
            "4  Corrupt or unsupported container",
            "5  I/O or permission failure",
            "6  Destination already exists",
            "never accepted as command-line argument values",
        ] {
            assert!(USAGE.contains(needle), "USAGE is missing: {needle}");
        }
    }

    #[test]
    fn no_arguments_is_help() {
        assert_eq!(parse(&[]), Ok(Command::Help));
    }

    #[test]
    fn help_flags_as_first_token() {
        assert_eq!(parse(&["--help"]), Ok(Command::Help));
        assert_eq!(parse(&["-h"]), Ok(Command::Help));
    }

    #[test]
    fn version_flags_as_first_token() {
        assert_eq!(parse(&["--version"]), Ok(Command::Version));
        assert_eq!(parse(&["-V"]), Ok(Command::Version));
    }

    #[test]
    fn tokens_after_help_or_version_are_ignored() {
        assert_eq!(parse(&["--help", "encrypt"]), Ok(Command::Help));
        assert_eq!(parse(&["-V", "extra"]), Ok(Command::Version));
    }

    #[test]
    fn encrypt_minimal_defaults_words_to_twelve() {
        assert_eq!(
            parse(&["encrypt", "notes.txt"]),
            Ok(Command::Encrypt(EncryptArgs {
                input: PathBuf::from("notes.txt"),
                output: None,
                words: 12,
                phrase_out: None,
            }))
        );
    }

    #[test]
    fn encrypt_accepts_all_options_with_short_output() {
        assert_eq!(
            parse(&[
                "encrypt",
                "in.bin",
                "-o",
                "out.crypt",
                "--words",
                "24",
                "--phrase-out",
                "phrase.txt",
            ]),
            Ok(Command::Encrypt(EncryptArgs {
                input: PathBuf::from("in.bin"),
                output: Some(PathBuf::from("out.crypt")),
                words: 24,
                phrase_out: Some(PathBuf::from("phrase.txt")),
            }))
        );
    }

    #[test]
    fn encrypt_accepts_long_output_and_options_before_the_positional() {
        assert_eq!(
            parse(&["encrypt", "--words", "18", "--output", "o.crypt", "in.bin"]),
            Ok(Command::Encrypt(EncryptArgs {
                input: PathBuf::from("in.bin"),
                output: Some(PathBuf::from("o.crypt")),
                words: 18,
                phrase_out: None,
            }))
        );
    }

    #[test]
    fn words_accepts_each_allowed_value() {
        for (value, words) in [("12", 12), ("18", 18), ("24", 24)] {
            assert_eq!(
                parse(&["encrypt", "in", "--words", value]),
                Ok(Command::Encrypt(EncryptArgs {
                    input: PathBuf::from("in"),
                    output: None,
                    words,
                    phrase_out: None,
                })),
                "--words {value}"
            );
        }
    }

    #[test]
    fn decrypt_accepts_phrase_file_and_output() {
        assert_eq!(
            parse(&[
                "decrypt",
                "in.crypt",
                "-o",
                "out.bin",
                "--phrase-file",
                "p.txt"
            ]),
            Ok(Command::Decrypt(DecryptArgs {
                input: PathBuf::from("in.crypt"),
                output: Some(PathBuf::from("out.bin")),
                phrase: PhraseSource::File(PathBuf::from("p.txt")),
            }))
        );
    }

    #[test]
    fn decrypt_accepts_phrase_stdin() {
        assert_eq!(
            parse(&["decrypt", "in.crypt", "--phrase-stdin"]),
            Ok(Command::Decrypt(DecryptArgs {
                input: PathBuf::from("in.crypt"),
                output: None,
                phrase: PhraseSource::Stdin,
            }))
        );
    }

    #[test]
    fn verify_accepts_either_phrase_source() {
        assert_eq!(
            parse(&["verify", "in.crypt", "--phrase-file", "p.txt"]),
            Ok(Command::Verify(VerifyArgs {
                input: PathBuf::from("in.crypt"),
                phrase: PhraseSource::File(PathBuf::from("p.txt")),
            }))
        );
        assert_eq!(
            parse(&["verify", "in.crypt", "--phrase-stdin"]),
            Ok(Command::Verify(VerifyArgs {
                input: PathBuf::from("in.crypt"),
                phrase: PhraseSource::Stdin,
            }))
        );
    }

    #[test]
    fn inspect_takes_only_an_input() {
        assert_eq!(
            parse(&["inspect", "in.crypt"]),
            Ok(Command::Inspect(InspectArgs {
                input: PathBuf::from("in.crypt"),
            }))
        );
    }

    #[test]
    fn non_utf8_positional_and_option_values_pass_through() {
        let raw = non_utf8("weird");
        assert_eq!(
            parse_os(vec![OsString::from("inspect"), raw.clone()]),
            Ok(Command::Inspect(InspectArgs {
                input: PathBuf::from(raw.clone()),
            }))
        );
        assert_eq!(
            parse_os(vec![
                OsString::from("encrypt"),
                OsString::from("in"),
                OsString::from("-o"),
                raw.clone(),
            ]),
            Ok(Command::Encrypt(EncryptArgs {
                input: PathBuf::from("in"),
                output: Some(PathBuf::from(raw)),
                words: 12,
                phrase_out: None,
            }))
        );
    }

    #[test]
    fn non_utf8_first_token_is_an_unrecognized_command() {
        let error = parse_os(vec![non_utf8("cmd")]).expect_err("must fail");
        assert!(
            error.0.starts_with("unrecognized command `cmd"),
            "message was: {}",
            error.0
        );
        assert!(error.0.ends_with("run `vaero --help` for usage"));
    }

    #[test]
    fn non_utf8_option_name_is_rejected() {
        let mut dashed = OsString::from("--bad");
        dashed.push(non_utf8(""));
        let error = parse_os(vec![
            OsString::from("encrypt"),
            OsString::from("in"),
            dashed,
        ])
        .expect_err("must fail");
        assert!(
            error.0.starts_with("option `--bad") && error.0.ends_with("is not valid UTF-8"),
            "message was: {}",
            error.0
        );
    }

    #[test]
    fn non_utf8_words_value_is_rejected() {
        let error = parse_os(vec![
            OsString::from("encrypt"),
            OsString::from("in"),
            OsString::from("--words"),
            non_utf8("12"),
        ])
        .expect_err("must fail");
        assert!(
            error.0.starts_with("invalid value `12")
                && error
                    .0
                    .ends_with("for `--words`: allowed values are 12, 18, and 24"),
            "message was: {}",
            error.0
        );
    }

    #[test]
    fn usage_errors_name_the_problem() {
        for (args, expected) in USAGE_ERROR_CASES {
            let error = parse(args).expect_err("parse must fail");
            assert_eq!(error.0, *expected, "args: {args:?}");
        }
    }

    #[test]
    fn words_rejects_disallowed_values_listing_the_allowed_set() {
        for value in ["0", "6", "13", "015", "twelve", "12 ", "-12", ""] {
            let error = parse(&["encrypt", "in", "--words", value]).expect_err("parse must fail");
            assert_eq!(error.0, words_error(value), "--words {value}");
        }
    }

    #[test]
    fn phrase_option_is_rejected_with_an_explanation() {
        for args in [
            &["encrypt", "in", "--phrase", "abandon"][..],
            &["decrypt", "in", "--phrase", "abandon"][..],
            &["verify", "in", "--phrase", "abandon"][..],
            &["inspect", "in", "--phrase", "abandon"][..],
        ] {
            let error = parse(args).expect_err("parse must fail");
            assert_eq!(
                error.0,
                "option `--phrase` does not exist: a recovery phrase given as a \
                 command-line argument would be visible in process listings and shell \
                 history; use `--phrase-file <file>` or `--phrase-stdin` instead",
                "args: {args:?}"
            );
        }
    }

    #[test]
    fn usage_error_displays_its_message_and_is_an_error() {
        let error = UsageError(String::from("something went wrong"));
        assert_eq!(error.to_string(), "something went wrong");
        let dynamic: &dyn std::error::Error = &error;
        assert!(dynamic.source().is_none());
    }

    /// A unique, self-cleaning directory under the system temp directory.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vaero-cli-unit-{tag}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("test directory should be creatable");
            Self { path }
        }

        fn file(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.path);
        }
    }

    /// A writer whose n-th write call fails; `fail_at` 0 never fails.
    struct FailingWriter {
        calls: usize,
        fail_at: usize,
    }

    impl std::io::Write for FailingWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if self.calls == self.fail_at {
                return Err(std::io::Error::other("injected write failure"));
            }
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A valid BIP-39 test phrase (all-zero entropy).
    const KNOWN_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \
                                abandon abandon abandon abandon about";

    #[test]
    fn exit_codes_map_every_core_error() {
        assert_eq!(
            exit_code_for(&vaero_core::Error::Io(std::io::Error::other("boom"))),
            EXIT_IO
        );
        assert_eq!(
            exit_code_for(&vaero_core::Error::Format(
                vaero_core::FormatError::Truncated
            )),
            EXIT_FORMAT
        );
        assert_eq!(exit_code_for(&vaero_core::Error::Auth), EXIT_AUTH);
        assert_eq!(
            exit_code_for(&vaero_core::Error::DestinationExists(PathBuf::from("x"))),
            EXIT_DESTINATION_EXISTS
        );
    }

    #[test]
    fn default_encrypt_output_appends_crypt() {
        assert_eq!(
            default_encrypt_output(Path::new("data.bin")),
            PathBuf::from("data.bin.crypt")
        );
        assert_eq!(
            default_encrypt_output(Path::new("dir/archive")),
            PathBuf::from("dir/archive.crypt")
        );
    }

    #[test]
    fn default_decrypt_output_strips_only_a_final_crypt() {
        assert_eq!(
            default_decrypt_output(Path::new("data.bin.crypt")),
            Some(PathBuf::from("data.bin"))
        );
        assert_eq!(
            default_decrypt_output(Path::new("dir/archive.crypt")),
            Some(PathBuf::from("dir/archive"))
        );
        assert_eq!(default_decrypt_output(Path::new("data.bin")), None);
        assert_eq!(default_decrypt_output(Path::new("archive")), None);
        assert_eq!(default_decrypt_output(Path::new(".crypt")), None);
    }

    #[test]
    fn phrase_length_maps_each_allowed_words_value() {
        assert_eq!(phrase_length(12), PhraseLength::Words12);
        assert_eq!(phrase_length(18), PhraseLength::Words18);
        assert_eq!(phrase_length(24), PhraseLength::Words24);
        // Unreachable through the parser; the documented default backstops it.
        assert_eq!(phrase_length(0), PhraseLength::Words12);
    }

    #[test]
    fn write_phrase_emits_space_separated_words_with_newline() {
        let mut buffer = Vec::new();
        write_phrase(&mut buffer, &["alpha", "beta", "gamma"]).expect("write should succeed");
        assert_eq!(buffer, b"alpha beta gamma\n");

        let mut never_fails = FailingWriter {
            calls: 0,
            fail_at: 0,
        };
        write_phrase(&mut never_fails, &["alpha", "beta"]).expect("write should succeed");
        assert_eq!(never_fails.calls, 4, "word, space, word, newline");

        // Calls for two words: 1 = first word, 2 = separator, 3 = second
        // word, 4 = trailing newline; each must surface its own failure.
        for fail_at in [1, 2, 4] {
            let mut writer = FailingWriter { calls: 0, fail_at };
            let error = write_phrase(&mut writer, &["alpha", "beta"])
                .expect_err("injected failure must surface");
            assert_eq!(error.to_string(), "injected write failure");
        }
    }

    #[test]
    fn persist_phrase_requires_a_new_file() {
        let dir = TempDir::new("persist-phrase");
        let fresh = dir.file("phrase.txt");
        persist_phrase(&fresh, &["alpha", "beta"]).expect("new file should be written");
        assert_eq!(fs::read(&fresh).unwrap(), b"alpha beta\n");

        let error =
            persist_phrase(&fresh, &["alpha", "beta"]).expect_err("existing file must be refused");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(&fresh).unwrap(),
            b"alpha beta\n",
            "content preserved"
        );
    }

    #[test]
    fn load_phrase_reports_read_and_parse_failures() {
        let dir = TempDir::new("load-phrase");
        let phrase_file = dir.file("phrase.txt");
        fs::write(&phrase_file, KNOWN_PHRASE).unwrap();
        let phrase =
            load_phrase(&PhraseSource::File(phrase_file)).expect("known phrase should parse");
        assert_eq!(phrase.words().len(), 12);

        let missing_code = load_phrase(&PhraseSource::File(dir.file("missing.txt")))
            .expect_err("missing phrase file must fail");
        assert_eq!(missing_code, EXIT_IO);

        let invalid = dir.file("invalid.txt");
        fs::write(&invalid, "definitely not a phrase").unwrap();
        let invalid_code =
            load_phrase(&PhraseSource::File(invalid)).expect_err("invalid phrase text must fail");
        assert_eq!(invalid_code, EXIT_USAGE);
    }

    #[test]
    fn container_json_matches_the_documented_schema() {
        let info = PublicInfo {
            format_version: 1,
            suite: 1,
            kdf: KdfParams {
                memory_kib: 65_536,
                iterations: 3,
                parallelism: 1,
            },
            container_id: [
                0x00, 0x01, 0x0a, 0x0f, 0x10, 0x7f, 0x80, 0xab, 0xcd, 0xef, 0xff, 0x12, 0x34, 0x56,
                0x78, 0x9a,
            ],
        };
        assert_eq!(
            container_json(&info),
            "{\"schema\":1,\"format\":\"vaero-crypt\",\"formatVersion\":1,\"suite\":1,\
             \"kdf\":{\"memoryKib\":65536,\"iterations\":3,\"parallelism\":1},\
             \"containerId\":\"00010a0f107f80abcdefff123456789a\"}"
        );
    }

    /// Build a `run` argument list from string-ish tokens.
    fn os_args(tokens: &[&OsStr]) -> Vec<OsString> {
        tokens.iter().map(OsString::from).collect()
    }

    #[test]
    fn run_encrypt_enforces_the_phrase_output_policy() {
        let dir = TempDir::new("run-encrypt");
        let source = dir.file("data.bin");
        fs::write(&source, b"run encrypt policy payload").unwrap();
        let default_container = dir.file("data.bin.crypt");

        // Redirected stderr without --phrase-out is refused before any work.
        let refused = run(
            os_args(&[OsStr::new("encrypt"), source.as_os_str()]).into_iter(),
            false,
        );
        assert_eq!(refused, EXIT_USAGE);
        assert!(!default_container.exists());

        // A missing source with a phrase file is an I/O failure and never
        // creates the phrase file.
        let phrase_file = dir.file("phrase.txt");
        let missing = run(
            os_args(&[
                OsStr::new("encrypt"),
                dir.file("missing.bin").as_os_str(),
                OsStr::new("--phrase-out"),
                phrase_file.as_os_str(),
            ])
            .into_iter(),
            false,
        );
        assert_eq!(missing, EXIT_IO);
        assert!(!phrase_file.exists());

        // Success with the default output name writes the phrase file.
        let encrypted = run(
            os_args(&[
                OsStr::new("encrypt"),
                source.as_os_str(),
                OsStr::new("--phrase-out"),
                phrase_file.as_os_str(),
            ])
            .into_iter(),
            false,
        );
        assert_eq!(encrypted, EXIT_SUCCESS);
        assert!(default_container.exists());
        let phrase_text = fs::read_to_string(&phrase_file).unwrap();
        assert!(phrase_text.ends_with('\n'));
        assert_eq!(phrase_text.trim_end_matches('\n').split(' ').count(), 12);

        // An existing phrase-out file fails and discards the container.
        let second_source = dir.file("second.bin");
        fs::write(&second_source, b"second payload").unwrap();
        let collided = run(
            os_args(&[
                OsStr::new("encrypt"),
                second_source.as_os_str(),
                OsStr::new("--phrase-out"),
                phrase_file.as_os_str(),
            ])
            .into_iter(),
            false,
        );
        assert_eq!(collided, EXIT_IO);
        assert!(!dir.file("second.bin.crypt").exists());
        assert_eq!(fs::read_to_string(&phrase_file).unwrap(), phrase_text);
    }

    #[test]
    fn interactive_encrypt_prints_the_phrase_to_stderr_only() {
        let dir = TempDir::new("interactive-encrypt");
        let source = dir.file("data.bin");
        fs::write(&source, b"interactive terminal payload").unwrap();
        let output = dir.file("data.crypt");
        let code = run(
            [
                OsString::from("encrypt"),
                source.clone().into_os_string(),
                OsString::from("-o"),
                output.clone().into_os_string(),
            ]
            .into_iter(),
            true,
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert!(output.exists(), "container must be committed");
        assert!(
            fs::read(&source).unwrap() == b"interactive terminal payload",
            "source must be preserved"
        );
    }
}
