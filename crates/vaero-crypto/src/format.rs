//! `.crypt` container header serialization and public metadata.

use std::fmt;

use crate::kdf::KdfParams;

/// Container magic, `VAEROCPT`.
pub(crate) const MAGIC: [u8; 8] = *b"VAEROCPT";
/// Supported format version.
pub(crate) const FORMAT_VERSION: u16 = 1;
/// Supported cryptographic suite id.
pub(crate) const SUITE_ID: u16 = 1;
/// Full header size in bytes.
pub(crate) const HEADER_LEN: usize = 160;
/// Header prefix size in bytes (everything before the phrase slot).
pub(crate) const HEADER_PREFIX_LEN: usize = 88;

/// Reasons a container is corrupt or unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// The container does not start with the `VAEROCPT` magic.
    Magic,
    /// Unknown format version; carries the stored value.
    Version(u16),
    /// Unknown cryptographic suite; carries the stored value.
    Suite(u16),
    /// Stored key-derivation parameters are outside the accepted bounds.
    KdfBounds,
    /// The container ends before an expected structure is complete.
    Truncated,
    /// Bytes follow the final frame.
    TrailingData,
    /// Unrecognized frame flag; carries the stored value.
    FrameFlag(u8),
    /// A frame ciphertext length is outside the accepted range; carries the
    /// stored value.
    FrameLength(u32),
    /// The container ends without a final frame.
    MissingFinal,
    /// The final frame's plaintext length or SHA-256 commitment does not
    /// match the decrypted stream.
    Commitment,
}

impl fmt::Display for FormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Magic => formatter.write_str("unrecognized container magic"),
            Self::Version(version) => write!(formatter, "unsupported format version {version}"),
            Self::Suite(suite) => write!(formatter, "unsupported cryptographic suite {suite}"),
            Self::KdfBounds => {
                formatter.write_str("key-derivation parameters are outside the accepted bounds")
            }
            Self::Truncated => {
                formatter.write_str("container ends before an expected structure is complete")
            }
            Self::TrailingData => formatter.write_str("unexpected bytes after the final frame"),
            Self::FrameFlag(flag) => write!(formatter, "unrecognized frame flag {flag}"),
            Self::FrameLength(length) => {
                write!(formatter, "frame ciphertext length {length} is invalid")
            }
            Self::MissingFinal => formatter.write_str("container ends without a final frame"),
            Self::Commitment => {
                formatter.write_str("plaintext commitment mismatch in the final frame")
            }
        }
    }
}

impl std::error::Error for FormatError {}

/// Non-sensitive metadata readable without a phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicInfo {
    /// Container format version.
    pub format_version: u16,
    /// Cryptographic suite id.
    pub suite: u16,
    /// Stored Argon2id parameters.
    pub kdf: KdfParams,
    /// Random per-container identifier.
    pub container_id: [u8; 16],
}

/// Parsed 160-byte container header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Header {
    /// Stored Argon2id parameters.
    pub kdf: KdfParams,
    /// Random per-container KDF salt.
    pub salt: [u8; 32],
    /// Random per-container identifier.
    pub container_id: [u8; 16],
    /// Random per-container frame nonce prefix.
    pub nonce_prefix: [u8; 16],
    /// Phrase slot: random CEK wrap nonce.
    pub wrap_nonce: [u8; 24],
    /// Phrase slot: wrapped CEK (32-byte CEK plus 16-byte Poly1305 tag).
    pub wrapped_cek: [u8; 48],
}

impl Header {
    /// Serialize to the 160-byte wire form.
    pub(crate) fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&SUITE_ID.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.kdf.memory_kib.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.kdf.iterations.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.kdf.parallelism.to_le_bytes());
        bytes[24..56].copy_from_slice(&self.salt);
        bytes[56..72].copy_from_slice(&self.container_id);
        bytes[72..88].copy_from_slice(&self.nonce_prefix);
        bytes[88..112].copy_from_slice(&self.wrap_nonce);
        bytes[112..160].copy_from_slice(&self.wrapped_cek);
        bytes
    }

    /// Parse and validate the 160-byte wire form.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::Magic`], [`FormatError::Version`], or
    /// [`FormatError::Suite`] for unrecognized identifiers, and
    /// [`FormatError::KdfBounds`] when the stored Argon2id parameters fall
    /// outside the accepted bounds.
    pub(crate) fn parse(bytes: &[u8; HEADER_LEN]) -> Result<Self, FormatError> {
        if bytes[..8] != MAGIC {
            return Err(FormatError::Magic);
        }
        let version = u16::from_le_bytes(field(bytes, 8));
        if version != FORMAT_VERSION {
            return Err(FormatError::Version(version));
        }
        let suite = u16::from_le_bytes(field(bytes, 10));
        if suite != SUITE_ID {
            return Err(FormatError::Suite(suite));
        }
        let kdf = KdfParams {
            memory_kib: u32::from_le_bytes(field(bytes, 12)),
            iterations: u32::from_le_bytes(field(bytes, 16)),
            parallelism: u32::from_le_bytes(field(bytes, 20)),
        };
        kdf.validate()?;
        Ok(Self {
            kdf,
            salt: field(bytes, 24),
            container_id: field(bytes, 56),
            nonce_prefix: field(bytes, 72),
            wrap_nonce: field(bytes, 88),
            wrapped_cek: field(bytes, 112),
        })
    }

    /// The non-sensitive metadata this header exposes.
    pub(crate) fn public_info(&self) -> PublicInfo {
        PublicInfo {
            format_version: FORMAT_VERSION,
            suite: SUITE_ID,
            kdf: self.kdf,
            container_id: self.container_id,
        }
    }
}

/// Copy a fixed-width field out of the header bytes.
fn field<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("header field ranges are in bounds by construction")
}

#[cfg(test)]
mod tests {
    use super::{FORMAT_VERSION, FormatError, HEADER_LEN, Header, SUITE_ID};
    use crate::kdf::KdfParams;

    fn sample_header() -> Header {
        Header {
            kdf: KdfParams {
                memory_kib: 8_192,
                iterations: 1,
                parallelism: 1,
            },
            salt: [3u8; 32],
            container_id: [5u8; 16],
            nonce_prefix: [7u8; 16],
            wrap_nonce: [9u8; 24],
            wrapped_cek: [11u8; 48],
        }
    }

    #[test]
    fn header_round_trips() {
        let header = sample_header();
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN);
        let parsed = Header::parse(&bytes).expect("serialized headers parse");
        assert_eq!(parsed, header);
        let info = parsed.public_info();
        assert_eq!(info.format_version, FORMAT_VERSION);
        assert_eq!(info.suite, SUITE_ID);
        assert_eq!(info.kdf, header.kdf);
        assert_eq!(info.container_id, header.container_id);
    }

    #[test]
    fn parse_rejects_malformed_headers() {
        let cases: &[(usize, u8, FormatError)] = &[
            (0, 0x00, FormatError::Magic),
            (7, 0xFF, FormatError::Magic),
            (8, 0x02, FormatError::Version(2)),
            (9, 0x01, FormatError::Version(0x0101)),
            (10, 0x02, FormatError::Suite(2)),
            (11, 0x01, FormatError::Suite(0x0101)),
            (13, 0x00, FormatError::KdfBounds),
            (16, 0x00, FormatError::KdfBounds),
            (20, 0x00, FormatError::KdfBounds),
        ];
        for &(offset, value, expected) in cases {
            let mut bytes = sample_header().to_bytes();
            bytes[offset] = value;
            assert_eq!(Header::parse(&bytes).unwrap_err(), expected);
        }
    }

    #[test]
    fn parse_rejects_out_of_bounds_kdf_maxima() {
        let mut header = sample_header();
        header.kdf.memory_kib = 1_048_577;
        assert_eq!(
            Header::parse(&header.to_bytes()).unwrap_err(),
            FormatError::KdfBounds
        );
    }

    #[test]
    fn format_error_display_is_stable() {
        let cases: &[(FormatError, &str)] = &[
            (FormatError::Magic, "unrecognized container magic"),
            (FormatError::Version(9), "unsupported format version 9"),
            (FormatError::Suite(9), "unsupported cryptographic suite 9"),
            (
                FormatError::KdfBounds,
                "key-derivation parameters are outside the accepted bounds",
            ),
            (
                FormatError::Truncated,
                "container ends before an expected structure is complete",
            ),
            (
                FormatError::TrailingData,
                "unexpected bytes after the final frame",
            ),
            (FormatError::FrameFlag(9), "unrecognized frame flag 9"),
            (
                FormatError::FrameLength(9),
                "frame ciphertext length 9 is invalid",
            ),
            (
                FormatError::MissingFinal,
                "container ends without a final frame",
            ),
            (
                FormatError::Commitment,
                "plaintext commitment mismatch in the final frame",
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), *message);
        }
    }
}
