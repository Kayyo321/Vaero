//! Transactional `.crypt` file orchestration.
//!
//! These functions bind the pure streaming primitives in `vaero-crypto` to
//! the filesystem with the semantics required by `docs/formats/crypt-v1.md`
//! §6: refuse an existing destination, stage output in a clearly named
//! temporary sibling, flush and sync, re-verify encrypt output before commit,
//! rename atomically into place, and best-effort delete the temporary on any
//! failure. Sources are never modified or deleted, and nothing here prompts
//! or prints.

use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use vaero_crypto::{FormatError, KdfParams, Phrase, PhraseLength, PublicInfo, StreamSummary};

/// Failure surfaced by transactional file operations.
#[derive(Debug)]
pub enum Error {
    /// Underlying I/O failure other than an unexpected end of input.
    Io(std::io::Error),
    /// The container is corrupt or unsupported.
    Format(FormatError),
    /// Wrong phrase or tampered container; no unauthenticated plaintext was
    /// released.
    Auth,
    /// The destination already exists; no overwrite mode exists in Phase 1.
    DestinationExists(PathBuf),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "i/o failure: {error}"),
            Self::Format(error) => {
                write!(formatter, "corrupt or unsupported container: {error}")
            }
            Self::Auth => {
                formatter.write_str("authentication failed: wrong phrase or tampered container")
            }
            Self::DestinationExists(path) => {
                write!(formatter, "destination already exists: {}", path.display())
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Format(error) => Some(error),
            Self::Auth | Self::DestinationExists(_) => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<vaero_crypto::Error> for Error {
    fn from(error: vaero_crypto::Error) -> Self {
        match error {
            vaero_crypto::Error::Io(inner) => Self::Io(inner),
            vaero_crypto::Error::Format(inner) => Self::Format(inner),
            vaero_crypto::Error::Auth => Self::Auth,
        }
    }
}

/// A staging sink that can be flushed to stable storage and re-read.
///
/// [`File`] is the production implementation; tests substitute failing
/// implementations to exercise every error path of the staging pipeline.
trait Stage: Read + Write {
    /// Flush buffered data and metadata to stable storage.
    fn sync(&mut self) -> std::io::Result<()>;
    /// Reposition the sink to its start so staged output can be re-read.
    fn rewind_start(&mut self) -> std::io::Result<()>;
}

impl Stage for File {
    fn sync(&mut self) -> std::io::Result<()> {
        self.sync_all()
    }

    fn rewind_start(&mut self) -> std::io::Result<()> {
        self.rewind()
    }
}

/// Encrypt `source` into a new `.crypt` container at `destination`.
///
/// A fresh recovery phrase of `length` words is generated from operating
/// system randomness and returned; it is the only way to decrypt the
/// container. Output is staged in a temporary sibling, synced, re-verified by
/// decrypting it with the same phrase on the same handle, and only then
/// renamed into place. The source is never modified.
///
/// # Errors
///
/// Returns [`Error::DestinationExists`] when `destination` already exists,
/// [`Error::Format`] when `kdf` is outside the documented bounds, and
/// [`Error::Io`] when any filesystem operation fails (including a
/// `destination` with no final file name, which cannot host a temporary
/// sibling). On any failure after the temporary file is created it is
/// best-effort deleted and `destination` is left absent.
///
/// # Panics
///
/// Panics when the operating system CSPRNG is unavailable; no fallback
/// randomness source exists by design.
pub fn encrypt_file(
    source: &Path,
    destination: &Path,
    length: PhraseLength,
    kdf: &KdfParams,
) -> Result<(Phrase, StreamSummary), Error> {
    if destination.exists() {
        return Err(Error::DestinationExists(destination.to_path_buf()));
    }
    let temp_path = temp_sibling(destination)?;
    let mut input = File::open(source)?;
    let phrase = Phrase::generate(length);
    let mut temp = File::create_new(&temp_path)?;
    let staged = stage_encrypt(&mut input, &mut temp, &phrase, kdf);
    let summary = commit(temp, &temp_path, staged, || {
        fs::rename(&temp_path, destination)
    })?;
    Ok((phrase, summary))
}

/// Decrypt the container at `source` into a new plaintext file at
/// `destination`.
///
/// Plaintext is staged in a temporary sibling while every frame
/// authenticates, synced, and renamed into place only after the whole
/// container verifies. The source is never modified.
///
/// # Errors
///
/// Returns [`Error::DestinationExists`] when `destination` already exists,
/// [`Error::Auth`] for a wrong phrase or tampered container, [`Error::Format`]
/// for a corrupt or unsupported container, and [`Error::Io`] when any
/// filesystem operation fails (including a `destination` with no final file
/// name). On any failure after the temporary file is created it is
/// best-effort deleted and `destination` is left absent.
///
/// # Panics
///
/// Panics when the operating system CSPRNG is unavailable; no fallback
/// randomness source exists by design.
pub fn decrypt_file(
    source: &Path,
    destination: &Path,
    phrase: &Phrase,
) -> Result<StreamSummary, Error> {
    if destination.exists() {
        return Err(Error::DestinationExists(destination.to_path_buf()));
    }
    let temp_path = temp_sibling(destination)?;
    let mut input = File::open(source)?;
    let mut temp = File::create_new(&temp_path)?;
    let staged = stage_decrypt(&mut input, &mut temp, phrase);
    commit(temp, &temp_path, staged, || {
        fs::rename(&temp_path, destination)
    })
}

/// Verify the container at `source` against `phrase` without writing any
/// plaintext.
///
/// # Errors
///
/// Returns [`Error::Auth`] for a wrong phrase or tampered container,
/// [`Error::Format`] for a corrupt or unsupported container, and
/// [`Error::Io`] when the source cannot be opened or read.
pub fn verify_file(source: &Path, phrase: &Phrase) -> Result<StreamSummary, Error> {
    let mut input = File::open(source)?;
    let summary = vaero_crypto::verify_stream(&mut input, phrase)?;
    Ok(summary)
}

/// Read the non-sensitive public metadata of the container at `source`.
///
/// # Errors
///
/// Returns [`Error::Format`] when the header is malformed, truncated, or
/// stores out-of-bounds parameters, and [`Error::Io`] when the source cannot
/// be opened or read.
pub fn inspect_file(source: &Path) -> Result<PublicInfo, Error> {
    let mut input = File::open(source)?;
    let info = vaero_crypto::inspect_stream(&mut input)?;
    Ok(info)
}

/// Encrypt `input` into `temp`, then sync and re-verify the staged container
/// on the same handle before it may be committed.
fn stage_encrypt<S: Stage>(
    input: &mut impl Read,
    temp: &mut S,
    phrase: &Phrase,
    kdf: &KdfParams,
) -> Result<StreamSummary, Error> {
    let summary = vaero_crypto::encrypt_stream(input, temp, phrase, kdf)?;
    temp.sync()?;
    temp.rewind_start()?;
    vaero_crypto::verify_stream(temp, phrase)?;
    Ok(summary)
}

/// Decrypt `input` into `temp` (authenticating every frame), then sync the
/// staged plaintext before it may be committed.
fn stage_decrypt<S: Stage>(
    input: &mut impl Read,
    temp: &mut S,
    phrase: &Phrase,
) -> Result<StreamSummary, Error> {
    let summary = vaero_crypto::decrypt_stream(input, temp, phrase)?;
    temp.sync()?;
    Ok(summary)
}

/// Close the staged temporary and either rename it into place or best-effort
/// delete it, so a failure never leaves a committed destination.
fn commit<F: FnOnce() -> std::io::Result<()>>(
    temp: File,
    temp_path: &Path,
    staged: Result<StreamSummary, Error>,
    rename: F,
) -> Result<StreamSummary, Error> {
    drop(temp);
    match staged {
        Ok(summary) => match rename() {
            Ok(()) => Ok(summary),
            Err(error) => {
                let _removed = fs::remove_file(temp_path);
                Err(Error::Io(error))
            }
        },
        Err(error) => {
            let _removed = fs::remove_file(temp_path);
            Err(error)
        }
    }
}

/// Name a temporary sibling of `destination`:
/// `.<file name>.vaero-partial-<8 random hex digits>`.
///
/// # Panics
///
/// Panics when the operating system CSPRNG is unavailable; no fallback
/// randomness source exists by design.
fn temp_sibling(destination: &Path) -> Result<PathBuf, Error> {
    let Some(name) = destination.file_name() else {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination path has no file name to stage a temporary sibling beside",
        )));
    };
    let mut suffix = [0u8; 4];
    getrandom::fill(&mut suffix).expect("operating system randomness is unavailable");
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".vaero-partial-{:08x}", u32::from_be_bytes(suffix)));
    Ok(destination.with_file_name(temp_name))
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// Cheap in-bounds Argon2id parameters for tests.
    const TEST_KDF: KdfParams = KdfParams {
        memory_kib: 8_192,
        iterations: 1,
        parallelism: 1,
    };

    /// A unique, self-cleaning directory under the system temp directory.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("vaero-core-{tag}-{}-{unique}", std::process::id()));
            fs::create_dir_all(&path).expect("test directory should be creatable");
            Self { path }
        }

        fn file(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }

        fn assert_no_partial_files(&self) {
            let leftovers: Vec<String> = fs::read_dir(&self.path)
                .expect("test directory should be readable")
                .map(|entry| {
                    entry
                        .expect("directory entry should be readable")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .filter(|name| name.contains("vaero-partial"))
                .collect();
            assert_eq!(leftovers, Vec::<String>::new());
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.path);
        }
    }

    /// The single staging operation an in-memory [`Stage`] should fail at.
    #[derive(Default, Clone, Copy, PartialEq, Eq)]
    enum FailPoint {
        #[default]
        None,
        Read,
        Write,
        Sync,
        Rewind,
    }

    /// In-memory [`Stage`] whose individual operations can be made to fail.
    #[derive(Default)]
    struct MockStage {
        cursor: Cursor<Vec<u8>>,
        fail: FailPoint,
    }

    impl MockStage {
        fn failing(fail: FailPoint) -> Self {
            Self {
                cursor: Cursor::default(),
                fail,
            }
        }
    }

    impl Read for MockStage {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.fail == FailPoint::Read {
                return Err(std::io::Error::other("injected read failure"));
            }
            self.cursor.read(buffer)
        }
    }

    impl Write for MockStage {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            if self.fail == FailPoint::Write {
                return Err(std::io::Error::other("injected write failure"));
            }
            self.cursor.write(buffer)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Stage for MockStage {
        fn sync(&mut self) -> std::io::Result<()> {
            if self.fail == FailPoint::Sync {
                return Err(std::io::Error::other("injected sync failure"));
            }
            Ok(())
        }

        fn rewind_start(&mut self) -> std::io::Result<()> {
            if self.fail == FailPoint::Rewind {
                return Err(std::io::Error::other("injected rewind failure"));
            }
            self.cursor.set_position(0);
            Ok(())
        }
    }

    /// Total, comparable description of an [`Error`] for assertions: every
    /// arm is exercised by the suite, so no assertion needs an unreachable
    /// `panic!` arm of its own.
    fn describe(error: &Error) -> String {
        match error {
            Error::Io(inner) => format!("io/{:?}/{inner}", inner.kind()),
            Error::Format(inner) => format!("format/{inner:?}"),
            Error::Auth => String::from("auth"),
            Error::DestinationExists(path) => format!("exists/{}", path.display()),
        }
    }

    fn describe_err<T: std::fmt::Debug>(result: Result<T, Error>) -> String {
        describe(&result.expect_err("operation must fail"))
    }

    fn assert_io(result: Result<StreamSummary, Error>, expected: &str) {
        assert_eq!(describe_err(result), format!("io/Other/{expected}"));
    }

    fn container_bytes(plaintext: &[u8], phrase: &Phrase) -> Vec<u8> {
        let mut container = Vec::new();
        vaero_crypto::encrypt_stream(&mut &plaintext[..], &mut container, phrase, &TEST_KDF)
            .expect("in-memory encryption should succeed");
        container
    }

    #[test]
    fn error_display_is_stable() {
        assert_eq!(
            Error::Io(std::io::Error::other("disk on fire")).to_string(),
            "i/o failure: disk on fire"
        );
        assert_eq!(
            Error::Format(FormatError::Magic).to_string(),
            "corrupt or unsupported container: unrecognized container magic"
        );
        assert_eq!(
            Error::Auth.to_string(),
            "authentication failed: wrong phrase or tampered container"
        );
        assert_eq!(
            Error::DestinationExists(PathBuf::from("out.crypt")).to_string(),
            "destination already exists: out.crypt"
        );
    }

    #[test]
    fn error_source_exposes_causes() {
        assert!(Error::Io(std::io::Error::other("boom")).source().is_some());
        assert!(Error::Format(FormatError::Truncated).source().is_some());
        assert!(Error::Auth.source().is_none());
        assert!(
            Error::DestinationExists(PathBuf::from("x"))
                .source()
                .is_none()
        );
    }

    #[test]
    fn error_converts_from_io_and_crypto_errors() {
        assert_eq!(
            describe(&Error::from(std::io::Error::other("boom"))),
            "io/Other/boom"
        );
        assert_eq!(
            describe(&Error::from(vaero_crypto::Error::Io(
                std::io::Error::other("boom")
            ))),
            "io/Other/boom"
        );
        assert_eq!(
            describe(&Error::from(vaero_crypto::Error::Format(
                FormatError::Magic
            ))),
            "format/Magic"
        );
        assert_eq!(describe(&Error::from(vaero_crypto::Error::Auth)), "auth");
    }

    #[test]
    fn temp_sibling_is_hidden_named_and_random() {
        let first = temp_sibling(Path::new("dir/out.crypt")).expect("path has a file name");
        let name = first
            .file_name()
            .expect("temporary has a file name")
            .to_string_lossy()
            .into_owned();
        let suffix = name
            .strip_prefix(".out.crypt.vaero-partial-")
            .expect("temporary name should embed the destination name");
        assert_eq!(suffix.len(), 8);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(first.parent(), Some(Path::new("dir")));
    }

    #[test]
    fn round_trip_preserves_bytes_and_source() {
        let dir = TempDir::new("round-trip");
        let source = dir.file("data.bin");
        let plaintext: Vec<u8> = (0u32..2_048)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        fs::write(&source, &plaintext).unwrap();

        let container = dir.file("data.bin.crypt");
        let (phrase, summary) = encrypt_file(&source, &container, PhraseLength::Words12, &TEST_KDF)
            .expect("encryption should succeed");
        assert_eq!(summary.plaintext_len, plaintext.len() as u64);
        assert_eq!(summary.frames, 2);
        assert_eq!(phrase.words().len(), 12);
        assert_eq!(
            fs::read(&source).unwrap(),
            plaintext,
            "source must be preserved"
        );
        dir.assert_no_partial_files();

        let verified = verify_file(&container, &phrase).expect("verification should succeed");
        assert_eq!(verified, summary);

        let info = inspect_file(&container).expect("inspection should succeed");
        assert_eq!(info.format_version, 1);
        assert_eq!(info.suite, 1);
        assert_eq!(info.kdf, TEST_KDF);

        let restored = dir.file("restored.bin");
        let decrypted =
            decrypt_file(&container, &restored, &phrase).expect("decryption should succeed");
        assert_eq!(decrypted, summary);
        assert_eq!(fs::read(&restored).unwrap(), plaintext);
        dir.assert_no_partial_files();
    }

    #[test]
    fn encrypt_refuses_existing_destination() {
        let dir = TempDir::new("encrypt-exists");
        let source = dir.file("data.bin");
        fs::write(&source, b"payload").unwrap();
        let destination = dir.file("taken.crypt");
        fs::write(&destination, b"already here").unwrap();
        assert_eq!(
            describe_err(encrypt_file(
                &source,
                &destination,
                PhraseLength::Words12,
                &TEST_KDF
            )),
            format!("exists/{}", destination.display())
        );
        assert_eq!(fs::read(&destination).unwrap(), b"already here");
    }

    #[test]
    fn decrypt_refuses_existing_destination() {
        let dir = TempDir::new("decrypt-exists");
        let phrase = Phrase::generate(PhraseLength::Words12);
        let container = dir.file("data.crypt");
        fs::write(&container, container_bytes(b"payload", &phrase)).unwrap();
        let destination = dir.file("taken.bin");
        fs::write(&destination, b"already here").unwrap();
        assert_eq!(
            describe_err(decrypt_file(&container, &destination, &phrase)),
            format!("exists/{}", destination.display())
        );
        assert_eq!(fs::read(&destination).unwrap(), b"already here");
    }

    #[test]
    fn missing_sources_are_io_errors() {
        let dir = TempDir::new("missing-source");
        let missing = dir.file("missing.bin");
        let phrase = Phrase::generate(PhraseLength::Words12);
        let described = [
            describe_err(encrypt_file(
                &missing,
                &dir.file("out.crypt"),
                PhraseLength::Words12,
                &TEST_KDF,
            )),
            describe_err(decrypt_file(&missing, &dir.file("out.bin"), &phrase)),
            describe_err(verify_file(&missing, &phrase)),
            describe_err(inspect_file(&missing)),
        ];
        for description in described {
            assert!(description.starts_with("io/NotFound/"));
        }
        dir.assert_no_partial_files();
    }

    #[test]
    fn destinations_without_a_file_name_are_rejected() {
        let dir = TempDir::new("no-file-name");
        let source = dir.file("data.bin");
        fs::write(&source, b"payload").unwrap();
        let phrase = Phrase::generate(PhraseLength::Words12);
        let expected = "io/InvalidInput/destination path has no file name to stage a \
                        temporary sibling beside";
        assert_eq!(
            describe_err(encrypt_file(
                &source,
                Path::new(""),
                PhraseLength::Words12,
                &TEST_KDF
            )),
            expected
        );
        assert_eq!(
            describe_err(decrypt_file(&source, Path::new(""), &phrase)),
            expected
        );
    }

    #[test]
    fn unwritable_temporary_locations_are_io_errors() {
        let dir = TempDir::new("bad-parent");
        let source = dir.file("data.bin");
        fs::write(&source, b"payload").unwrap();
        let phrase = Phrase::generate(PhraseLength::Words12);
        let orphan_out = dir.file("no-such-dir").join("out.crypt");
        assert!(
            describe_err(encrypt_file(
                &source,
                &orphan_out,
                PhraseLength::Words12,
                &TEST_KDF
            ))
            .starts_with("io/NotFound/")
        );
        let orphan_plain = dir.file("no-such-dir").join("out.bin");
        assert!(
            describe_err(decrypt_file(&source, &orphan_plain, &phrase)).starts_with("io/NotFound/")
        );
    }

    #[test]
    fn failed_encrypt_cleans_up_and_commits_nothing() {
        let dir = TempDir::new("encrypt-fails");
        let source = dir.file("data.bin");
        fs::write(&source, b"payload").unwrap();
        let destination = dir.file("out.crypt");
        let out_of_bounds = KdfParams {
            memory_kib: 0,
            iterations: 1,
            parallelism: 1,
        };
        assert_eq!(
            describe_err(encrypt_file(
                &source,
                &destination,
                PhraseLength::Words12,
                &out_of_bounds
            )),
            "format/KdfBounds"
        );
        assert!(
            !destination.exists(),
            "no output may be committed on failure"
        );
        dir.assert_no_partial_files();
    }

    #[test]
    fn failed_decrypt_cleans_up_and_commits_nothing() {
        let dir = TempDir::new("decrypt-fails");
        let phrase = Phrase::generate(PhraseLength::Words12);
        let container = container_bytes(b"payload", &phrase);

        let wrong_phrase_container = dir.file("wrong.crypt");
        fs::write(&wrong_phrase_container, &container).unwrap();
        let destination = dir.file("wrong.bin");
        let wrong = Phrase::generate(PhraseLength::Words12);
        assert_eq!(
            describe_err(decrypt_file(&wrong_phrase_container, &destination, &wrong)),
            "auth"
        );
        assert!(!destination.exists());

        let truncated_container = dir.file("truncated.crypt");
        fs::write(&truncated_container, &container[..container.len() - 1]).unwrap();
        let truncated_out = dir.file("truncated.bin");
        assert_eq!(
            describe_err(decrypt_file(&truncated_container, &truncated_out, &phrase)),
            "format/Truncated"
        );
        assert!(!truncated_out.exists());
        dir.assert_no_partial_files();
    }

    #[test]
    fn inspect_rejects_corrupt_containers() {
        let dir = TempDir::new("inspect-corrupt");
        let bogus = dir.file("bogus.crypt");
        fs::write(&bogus, b"not a container").unwrap();
        assert_eq!(describe_err(inspect_file(&bogus)), "format/Truncated");
    }

    #[test]
    fn stage_encrypt_surfaces_each_pipeline_failure() {
        let phrase = Phrase::generate(PhraseLength::Words12);
        let plaintext = b"staged pipeline payload";

        let mut ok = MockStage::default();
        let summary = stage_encrypt(&mut &plaintext[..], &mut ok, &phrase, &TEST_KDF)
            .expect("staging should succeed");
        assert_eq!(summary.plaintext_len, plaintext.len() as u64);

        for (fail, message) in [
            (FailPoint::Write, "injected write failure"),
            (FailPoint::Sync, "injected sync failure"),
            (FailPoint::Rewind, "injected rewind failure"),
            (FailPoint::Read, "injected read failure"),
        ] {
            let mut stage = MockStage::failing(fail);
            assert_io(
                stage_encrypt(&mut &plaintext[..], &mut stage, &phrase, &TEST_KDF),
                message,
            );
        }
    }

    #[test]
    fn stage_decrypt_surfaces_each_pipeline_failure() {
        let phrase = Phrase::generate(PhraseLength::Words12);
        let plaintext = b"staged pipeline payload";
        let container = container_bytes(plaintext, &phrase);

        let mut ok = MockStage::default();
        let summary =
            stage_decrypt(&mut &container[..], &mut ok, &phrase).expect("staging should succeed");
        assert_eq!(summary.plaintext_len, plaintext.len() as u64);
        assert_eq!(ok.cursor.into_inner(), plaintext);

        for (fail, message) in [
            (FailPoint::Write, "injected write failure"),
            (FailPoint::Sync, "injected sync failure"),
        ] {
            let mut stage = MockStage::failing(fail);
            assert_io(
                stage_decrypt(&mut &container[..], &mut stage, &phrase),
                message,
            );
        }
    }

    /// A commit whose rename succeeds by doing nothing.
    // The wrapped return value is required: this stands in for `fs::rename`
    // behind `commit`'s `fn() -> std::io::Result<()>` pointer type.
    #[allow(clippy::unnecessary_wraps)]
    fn rename_ok() -> std::io::Result<()> {
        Ok(())
    }

    /// A commit whose rename fails.
    fn rename_fails() -> std::io::Result<()> {
        Err(std::io::Error::other("injected rename failure"))
    }

    const SUMMARY: StreamSummary = StreamSummary {
        plaintext_len: 7,
        frames: 2,
    };

    fn staged_temp(dir: &TempDir, name: &str) -> (File, PathBuf) {
        let path = dir.file(name);
        let temp = File::create_new(&path).expect("staging file should be creatable");
        (temp, path)
    }

    #[test]
    fn commit_renames_only_successful_stages() {
        let dir = TempDir::new("commit");
        let rename: fn() -> std::io::Result<()> = rename_ok;

        let (temp, path) = staged_temp(&dir, "success");
        let committed =
            commit(temp, &path, Ok(SUMMARY), rename).expect("successful stages must commit");
        assert_eq!(committed, SUMMARY);
        assert!(
            path.exists(),
            "successful commit leaves rename to the caller-supplied action"
        );

        let (temp, path) = staged_temp(&dir, "rename-fails");
        let failing: fn() -> std::io::Result<()> = rename_fails;
        assert_io(
            commit(temp, &path, Ok(SUMMARY), failing),
            "injected rename failure",
        );
        assert!(!path.exists(), "failed rename must remove the temporary");

        let (temp, path) = staged_temp(&dir, "stage-failed");
        assert_eq!(
            describe_err(commit(temp, &path, Err(Error::Auth), rename)),
            "auth"
        );
        assert!(!path.exists(), "failed staging must remove the temporary");
    }
}
