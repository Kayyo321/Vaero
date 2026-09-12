//! Shared policy and orchestration primitives for the Vaero command-line
//! application.
//!
//! Besides pure policy checks such as [`validate_archive_path`], this crate
//! provides the transactional `.crypt` file operations ([`encrypt_file`],
//! [`decrypt_file`], [`verify_file`], [`inspect_file`]) defined by
//! `docs/formats/crypt-v1.md` §6. It never prompts, never prints, and never
//! writes anywhere except the explicitly requested destination and its
//! temporary sibling.

use std::fmt;
use std::path::{Component, Path};

mod container;

pub use container::{Error, decrypt_file, encrypt_file, inspect_file, verify_file};
pub use vaero_crypto::{
    FormatError, KdfParams, Phrase, PhraseError, PhraseLength, PublicInfo, StreamSummary,
};

/// Current application version, sourced from the Cargo workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Reasons an archive entry path cannot safely be extracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsafePath {
    Empty,
    Absolute,
    ParentTraversal,
    PlatformPrefix,
}

impl fmt::Display for UnsafePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "archive path is empty",
            Self::Absolute => "archive path is absolute",
            Self::ParentTraversal => "archive path contains parent traversal",
            Self::PlatformPrefix => "archive path contains a platform prefix",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for UnsafePath {}

/// Validate a hostile archive path before joining it to an extraction root.
///
/// This deliberately performs no filesystem access. Callers must separately
/// prevent link traversal and destination collisions while extracting.
///
/// # Errors
///
/// Returns [`UnsafePath`] when the path is empty, rooted, prefixed by a drive or
/// platform namespace, or contains a parent-directory component.
pub fn validate_archive_path(path: &Path) -> Result<(), UnsafePath> {
    if path.as_os_str().is_empty() {
        return Err(UnsafePath::Empty);
    }
    if path.is_absolute() {
        return Err(UnsafePath::Absolute);
    }

    for component in path.components() {
        match component {
            Component::ParentDir => return Err(UnsafePath::ParentTraversal),
            Component::Prefix(_) => return Err(UnsafePath::PlatformPrefix),
            Component::RootDir => return Err(UnsafePath::Absolute),
            Component::CurDir | Component::Normal(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{UnsafePath, VERSION, validate_archive_path};
    use std::path::Path;

    #[test]
    fn version_is_workspace_version() {
        assert_eq!(VERSION, "0.1.0");
    }

    #[test]
    fn accepts_normal_relative_paths() {
        for path in ["file.txt", "folder/file.txt", "./folder/file.txt"] {
            assert_eq!(validate_archive_path(Path::new(path)), Ok(()));
        }
    }

    #[test]
    fn rejects_empty_absolute_and_traversing_paths() {
        assert_eq!(validate_archive_path(Path::new("")), Err(UnsafePath::Empty));
        assert_eq!(
            validate_archive_path(Path::new("/rooted")),
            Err(UnsafePath::Absolute)
        );
        assert_eq!(
            validate_archive_path(Path::new("../escape")),
            Err(UnsafePath::ParentTraversal)
        );
    }

    #[test]
    fn errors_have_stable_messages() {
        assert_eq!(UnsafePath::Empty.to_string(), "archive path is empty");
        assert_eq!(UnsafePath::Absolute.to_string(), "archive path is absolute");
        assert_eq!(
            UnsafePath::ParentTraversal.to_string(),
            "archive path contains parent traversal"
        );
        assert_eq!(
            UnsafePath::PlatformPrefix.to_string(),
            "archive path contains a platform prefix"
        );
    }

    #[test]
    fn fuzz_smoke_path_components() {
        let atoms = ["safe", ".", "..", "nested", "file.txt"];
        for first in atoms {
            for second in atoms {
                let candidate = format!("{first}/{second}");
                let result = validate_archive_path(Path::new(&candidate));
                assert_eq!(result.is_err(), first == ".." || second == "..");
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_drive_prefixes() {
        assert_eq!(
            validate_archive_path(Path::new(r"C:\data")),
            Err(UnsafePath::Absolute)
        );
        assert_eq!(
            validate_archive_path(Path::new(r"C:data")),
            Err(UnsafePath::PlatformPrefix)
        );
    }
}
