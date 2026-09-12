//! Phrase encoding, key derivation, and framed authenticated encryption for Vaero.
//!
//! The `.crypt` container implemented here is **experimental and unreviewed**;
//! see `docs/formats/crypt-v1.md`. Do not rely on it for long-lived data until
//! the format is declared stable after independent review.
//!
//! This crate is a pure library: it never touches the filesystem, never
//! prints, and never prompts. Callers stream containers through
//! [`std::io::Read`] and [`std::io::Write`] implementations.

use std::fmt;

mod format;
mod kdf;
mod phrase;
mod stream;

pub use format::{FormatError, PublicInfo};
pub use kdf::KdfParams;
pub use phrase::{Phrase, PhraseError, PhraseLength};
pub use stream::{StreamSummary, decrypt_stream, encrypt_stream, inspect_stream, verify_stream};

/// Failure surfaced by container operations.
#[derive(Debug)]
pub enum Error {
    /// Underlying I/O failure other than an unexpected end of input.
    Io(std::io::Error),
    /// The container is corrupt or unsupported.
    Format(FormatError),
    /// Wrong phrase or tampered container; no unauthenticated plaintext was
    /// released.
    Auth,
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
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Format(error) => Some(error),
            Self::Auth => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Fill `buffer` with operating-system randomness.
///
/// Panics when the operating system CSPRNG is unavailable; no fallback
/// randomness source exists by design.
pub(crate) fn fill_random(buffer: &mut [u8]) {
    getrandom::fill(buffer).expect("operating system randomness is unavailable");
}

#[cfg(test)]
mod tests {
    use super::{Error, FormatError};
    use std::error::Error as _;

    #[test]
    fn error_display_is_stable() {
        let io = Error::Io(std::io::Error::other("disk on fire"));
        assert_eq!(io.to_string(), "i/o failure: disk on fire");
        let format = Error::Format(FormatError::Magic);
        assert_eq!(
            format.to_string(),
            "corrupt or unsupported container: unrecognized container magic"
        );
        assert_eq!(
            Error::Auth.to_string(),
            "authentication failed: wrong phrase or tampered container"
        );
    }

    #[test]
    fn error_source_exposes_causes() {
        let io = Error::Io(std::io::Error::other("boom"));
        assert!(io.source().is_some());
        let format = Error::Format(FormatError::Truncated);
        assert!(format.source().is_some());
        assert!(Error::Auth.source().is_none());
    }

    #[test]
    fn error_converts_from_io() {
        let error = Error::from(std::io::Error::other("boom"));
        assert_eq!(error.to_string(), "i/o failure: boom");
    }
}
