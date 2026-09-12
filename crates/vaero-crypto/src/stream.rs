//! Framed authenticated encryption over `std::io` streams.

use std::io::{ErrorKind, Read, Write};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::format::{FormatError, HEADER_LEN, HEADER_PREFIX_LEN, Header, PublicInfo};
use crate::{Error, KdfParams, Phrase, kdf};

/// Data frame flag byte.
pub(crate) const FLAG_DATA: u8 = 0;
/// Final frame flag byte.
pub(crate) const FLAG_FINAL: u8 = 1;
/// Maximum data frame plaintext size (256 KiB).
pub(crate) const DATA_FRAME_PLAINTEXT_MAX: usize = 262_144;
/// Minimum data frame ciphertext length (1 plaintext byte plus the tag).
pub(crate) const DATA_FRAME_CIPHERTEXT_MIN: u32 = 17;
/// Maximum data frame ciphertext length (256 KiB plaintext plus the tag).
pub(crate) const DATA_FRAME_CIPHERTEXT_MAX: u32 = 262_160;
/// Final frame plaintext length: total length u64 LE plus SHA-256 digest.
pub(crate) const FINAL_FRAME_PLAINTEXT_LEN: usize = 40;
/// Final frame ciphertext length (40 plaintext bytes plus the tag).
pub(crate) const FINAL_FRAME_CIPHERTEXT_LEN: u32 = 56;
/// Frame AAD length: full header, index u64 LE, flag byte.
const FRAME_AAD_LEN: usize = HEADER_LEN + 8 + 1;

/// Outcome of a successful whole-stream operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamSummary {
    /// Total plaintext bytes processed.
    pub plaintext_len: u64,
    /// Total frames processed, including the final frame.
    pub frames: u64,
}

/// Encrypt `input` into a `.crypt` container written to `output`.
///
/// # Errors
///
/// Returns [`Error::Format`] with [`FormatError::KdfBounds`] when `kdf` is
/// outside the documented bounds, and [`Error::Io`] when reading `input` or
/// writing `output` fails.
///
/// # Panics
///
/// Panics when the operating system CSPRNG is unavailable; no fallback
/// randomness source exists by design.
pub fn encrypt_stream(
    input: &mut impl Read,
    output: &mut impl Write,
    phrase: &Phrase,
    kdf_params: &KdfParams,
) -> Result<StreamSummary, Error> {
    kdf_params.validate().map_err(Error::Format)?;

    let mut salt = [0u8; 32];
    crate::fill_random(&mut salt);
    let mut container_id = [0u8; 16];
    crate::fill_random(&mut container_id);
    let mut nonce_prefix = [0u8; 16];
    crate::fill_random(&mut nonce_prefix);
    let mut wrap_nonce = [0u8; 24];
    crate::fill_random(&mut wrap_nonce);
    let mut cek = Zeroizing::new([0u8; 32]);
    crate::fill_random(cek.as_mut_slice());

    let kek = kdf::derive_kek(phrase.entropy(), &salt, kdf_params);
    let mut header = Header {
        kdf: *kdf_params,
        salt,
        container_id,
        nonce_prefix,
        wrap_nonce,
        wrapped_cek: [0u8; 48],
    };
    let prefix_source = header.to_bytes();
    header.wrapped_cek = wrap_cek(&kek, &prefix_source[..HEADER_PREFIX_LEN], &wrap_nonce, &cek);
    let header_bytes = header.to_bytes();
    output.write_all(&header_bytes).map_err(Error::Io)?;

    let mut buffer = Zeroizing::new(vec![0u8; DATA_FRAME_PLAINTEXT_MAX]);
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut index: u64 = 0;
    loop {
        let filled = fill_buffer(input, buffer.as_mut_slice())?;
        if filled == 0 {
            break;
        }
        let chunk = &buffer[..filled];
        hasher.update(chunk);
        total += filled as u64;
        let ciphertext = seal_frame(&cek, &header_bytes, index, FLAG_DATA, chunk);
        write_frame(output, FLAG_DATA, &ciphertext)?;
        index += 1;
    }

    let mut final_plaintext = [0u8; FINAL_FRAME_PLAINTEXT_LEN];
    final_plaintext[..8].copy_from_slice(&total.to_le_bytes());
    final_plaintext[8..].copy_from_slice(&hasher.finalize());
    let ciphertext = seal_frame(&cek, &header_bytes, index, FLAG_FINAL, &final_plaintext);
    write_frame(output, FLAG_FINAL, &ciphertext)?;
    output.flush().map_err(Error::Io)?;
    Ok(StreamSummary {
        plaintext_len: total,
        frames: index + 1,
    })
}

/// Decrypt a `.crypt` container from `input`, writing plaintext to `output`.
///
/// Plaintext streams out frame by frame only after each frame authenticates.
/// Any error after partial output is still surfaced as failure; callers must
/// discard the partial output.
///
/// # Errors
///
/// Returns [`Error::Auth`] for a wrong phrase or any tampered header, slot,
/// or frame; [`Error::Format`] for a corrupt or unsupported container; and
/// [`Error::Io`] for underlying I/O failures other than an unexpected end of
/// input.
pub fn decrypt_stream(
    input: &mut impl Read,
    output: &mut impl Write,
    phrase: &Phrase,
) -> Result<StreamSummary, Error> {
    process_frames(input, Some(output), phrase)
}

/// Verify a `.crypt` container without writing any plaintext.
///
/// # Errors
///
/// Fails exactly as [`decrypt_stream`] does: [`Error::Auth`] for a wrong
/// phrase or tampering, [`Error::Format`] for corruption, [`Error::Io`] for
/// underlying I/O failures other than an unexpected end of input.
pub fn verify_stream(input: &mut impl Read, phrase: &Phrase) -> Result<StreamSummary, Error> {
    process_frames(input, None, phrase)
}

/// Read the non-sensitive public metadata of a `.crypt` container.
///
/// # Errors
///
/// Returns [`Error::Format`] when the header is malformed, truncated, or
/// stores out-of-bounds parameters, and [`Error::Io`] for underlying I/O
/// failures other than an unexpected end of input.
pub fn inspect_stream(input: &mut impl Read) -> Result<PublicInfo, Error> {
    let (_, header) = read_header(input)?;
    Ok(header.public_info())
}

/// Shared decrypt/verify engine; `output` is `None` when verifying.
fn process_frames<R: Read>(
    input: &mut R,
    mut output: Option<&mut dyn Write>,
    phrase: &Phrase,
) -> Result<StreamSummary, Error> {
    let (header_bytes, header) = read_header(input)?;
    let kek = kdf::derive_kek(phrase.entropy(), &header.salt, &header.kdf);
    let cek = unwrap_cek(
        &kek,
        &header_bytes[..HEADER_PREFIX_LEN],
        &header.wrap_nonce,
        &header.wrapped_cek,
    )?;

    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut index: u64 = 0;
    loop {
        let Some(flag) = read_flag(input)? else {
            return Err(Error::Format(FormatError::MissingFinal));
        };
        match flag {
            FLAG_DATA => {
                let length = read_u32(input)?;
                if !(DATA_FRAME_CIPHERTEXT_MIN..=DATA_FRAME_CIPHERTEXT_MAX).contains(&length) {
                    return Err(Error::Format(FormatError::FrameLength(length)));
                }
                let mut ciphertext =
                    vec![0u8; usize::try_from(length).expect("bounded frame length fits usize")];
                read_exact_or_truncated(input, &mut ciphertext)?;
                let plaintext = open_frame(&cek, &header_bytes, index, FLAG_DATA, &ciphertext)?;
                hasher.update(plaintext.as_slice());
                total += plaintext.len() as u64;
                if let Some(sink) = output.as_deref_mut() {
                    sink.write_all(&plaintext).map_err(Error::Io)?;
                }
                index += 1;
            }
            FLAG_FINAL => {
                let length = read_u32(input)?;
                if length != FINAL_FRAME_CIPHERTEXT_LEN {
                    return Err(Error::Format(FormatError::FrameLength(length)));
                }
                let mut ciphertext = [0u8; 56];
                read_exact_or_truncated(input, &mut ciphertext)?;
                let plaintext = open_frame(&cek, &header_bytes, index, FLAG_FINAL, &ciphertext)?;
                let stored_len = u64::from_le_bytes(
                    plaintext[..8]
                        .try_into()
                        .expect("final frame length field is eight bytes"),
                );
                let digest = hasher.finalize_reset();
                if stored_len != total || plaintext[8..] != digest[..] {
                    return Err(Error::Format(FormatError::Commitment));
                }
                if read_flag(input)?.is_some() {
                    return Err(Error::Format(FormatError::TrailingData));
                }
                return Ok(StreamSummary {
                    plaintext_len: total,
                    frames: index + 1,
                });
            }
            other => return Err(Error::Format(FormatError::FrameFlag(other))),
        }
    }
}

/// Read and validate the 160-byte header.
fn read_header(input: &mut impl Read) -> Result<([u8; HEADER_LEN], Header), Error> {
    let mut bytes = [0u8; HEADER_LEN];
    read_exact_or_truncated(input, &mut bytes)?;
    let header = Header::parse(&bytes).map_err(Error::Format)?;
    Ok((bytes, header))
}

/// Read exactly `buffer.len()` bytes, classifying an unexpected end of input
/// as [`FormatError::Truncated`].
fn read_exact_or_truncated(input: &mut impl Read, buffer: &mut [u8]) -> Result<(), Error> {
    input.read_exact(buffer).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            Error::Format(FormatError::Truncated)
        } else {
            Error::Io(error)
        }
    })
}

/// Read one frame flag byte; `None` on a clean end of input.
fn read_flag(input: &mut impl Read) -> Result<Option<u8>, Error> {
    let mut byte = [0u8; 1];
    match input.read(&mut byte) {
        Ok(0) => Ok(None),
        Ok(_) => Ok(Some(byte[0])),
        Err(error) => Err(Error::Io(error)),
    }
}

/// Read a little-endian u32.
fn read_u32(input: &mut impl Read) -> Result<u32, Error> {
    let mut bytes = [0u8; 4];
    read_exact_or_truncated(input, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Fill `buffer` from `input`, returning how many bytes were read before a
/// clean end of input.
fn fill_buffer(input: &mut impl Read, buffer: &mut [u8]) -> Result<usize, Error> {
    let mut filled = 0;
    while filled < buffer.len() {
        let count = input.read(&mut buffer[filled..]).map_err(Error::Io)?;
        if count == 0 {
            break;
        }
        filled += count;
    }
    Ok(filled)
}

/// Write one frame: flag byte, ciphertext length u32 LE, ciphertext.
fn write_frame(output: &mut impl Write, flag: u8, ciphertext: &[u8]) -> Result<(), Error> {
    let length = u32::try_from(ciphertext.len()).expect("frame ciphertext length fits u32");
    let mut frame = Vec::with_capacity(5 + ciphertext.len());
    frame.push(flag);
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(ciphertext);
    output.write_all(&frame).map_err(Error::Io)
}

/// Frame nonce: nonce prefix (header bytes 72..88) then index u64 BE.
pub(crate) fn frame_nonce(header_bytes: &[u8; HEADER_LEN], index: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(&header_bytes[72..88]);
    nonce[16..].copy_from_slice(&index.to_be_bytes());
    nonce
}

/// Frame AAD: full header, index u64 LE, flag byte.
pub(crate) fn frame_aad(
    header_bytes: &[u8; HEADER_LEN],
    index: u64,
    flag: u8,
) -> [u8; FRAME_AAD_LEN] {
    let mut aad = [0u8; FRAME_AAD_LEN];
    aad[..HEADER_LEN].copy_from_slice(header_bytes);
    aad[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&index.to_le_bytes());
    aad[FRAME_AAD_LEN - 1] = flag;
    aad
}

/// Seal one frame with the CEK.
///
/// # Panics
///
/// XChaCha20-Poly1305 encryption with heap allocation cannot fail; a failure
/// panics rather than adding an unreachable error branch.
pub(crate) fn seal_frame(
    cek: &[u8; 32],
    header_bytes: &[u8; HEADER_LEN],
    index: u64,
    flag: u8,
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(cek));
    let nonce = frame_nonce(header_bytes, index);
    let aad = frame_aad(header_bytes, index, flag);
    cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption with allocation cannot fail")
}

/// Open one frame with the CEK.
///
/// # Errors
///
/// Returns [`Error::Auth`] when the frame does not authenticate under this
/// key, nonce, and associated data.
pub(crate) fn open_frame(
    cek: &[u8; 32],
    header_bytes: &[u8; HEADER_LEN],
    index: u64,
    flag: u8,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(cek));
    let nonce = frame_nonce(header_bytes, index);
    let aad = frame_aad(header_bytes, index, flag);
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Auth)
}

/// Wrap the CEK under the KEK, binding the header prefix as AAD.
///
/// # Panics
///
/// XChaCha20-Poly1305 encryption with heap allocation cannot fail; a failure
/// panics rather than adding an unreachable error branch.
pub(crate) fn wrap_cek(
    kek: &[u8; 32],
    header_prefix: &[u8],
    wrap_nonce: &[u8; 24],
    cek: &[u8; 32],
) -> [u8; 48] {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek));
    cipher
        .encrypt(
            XNonce::from_slice(wrap_nonce),
            Payload {
                msg: cek.as_slice(),
                aad: header_prefix,
            },
        )
        .expect("XChaCha20-Poly1305 encryption with allocation cannot fail")
        .try_into()
        .expect("wrapped CEK is exactly 48 bytes")
}

/// Unwrap the CEK; a wrong phrase or tampered prefix or slot fails here.
///
/// # Errors
///
/// Returns [`Error::Auth`] when the wrap tag does not verify.
pub(crate) fn unwrap_cek(
    kek: &[u8; 32],
    header_prefix: &[u8],
    wrap_nonce: &[u8; 24],
    wrapped_cek: &[u8; 48],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(kek));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(wrap_nonce),
            Payload {
                msg: wrapped_cek.as_slice(),
                aad: header_prefix,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Auth)?;
    let mut cek = Zeroizing::new([0u8; 32]);
    cek.copy_from_slice(&plaintext);
    Ok(cek)
}

#[cfg(test)]
mod tests {
    use super::{
        FINAL_FRAME_CIPHERTEXT_LEN, FLAG_FINAL, StreamSummary, decrypt_stream, encrypt_stream,
        inspect_stream, seal_frame, unwrap_cek, verify_stream,
    };
    use crate::format::{HEADER_PREFIX_LEN, Header};
    use crate::{Error, FormatError, KdfParams, Phrase, kdf};
    use sha2::{Digest, Sha256};
    use std::io::{Cursor, Read, Write};

    /// Small in-bounds KDF parameters keeping the test suite fast.
    const TEST_KDF: KdfParams = KdfParams {
        memory_kib: 8_192,
        iterations: 1,
        parallelism: 1,
    };

    /// Byte size of one full data frame on the wire.
    const FULL_FRAME: usize = 5 + 262_160;

    /// Comparable classification of an [`Error`] for assertions.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Kind {
        Io,
        Format(FormatError),
        Auth,
    }

    fn kind(error: &Error) -> Kind {
        match error {
            Error::Io(_) => Kind::Io,
            Error::Format(inner) => Kind::Format(*inner),
            Error::Auth => Kind::Auth,
        }
    }

    fn err_kind<T: std::fmt::Debug>(result: Result<T, Error>) -> Kind {
        kind(&result.expect_err("operation must fail"))
    }

    fn test_phrase() -> Phrase {
        Phrase::parse("legal winner thank year wave sausage worth useful legal winner thank yellow")
            .expect("test phrase parses")
    }

    fn wrong_phrase() -> Phrase {
        Phrase::parse("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
            .expect("wrong phrase parses")
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|position| u8::try_from(position % 251).expect("residue fits a byte"))
            .collect()
    }

    /// The one `Read` implementation used by every unit test, so a single
    /// instantiation of each generic stream function covers both its success
    /// paths and its injected-failure paths. Its N-th read operation can be
    /// made to fail with a non-EOF error.
    struct TestReader<'a> {
        inner: Cursor<&'a [u8]>,
        ok_ops: usize,
    }

    impl<'a> TestReader<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self::failing_after(data, usize::MAX)
        }

        fn failing_after(data: &'a [u8], ok_ops: usize) -> Self {
            Self {
                inner: Cursor::new(data),
                ok_ops,
            }
        }
    }

    impl Read for TestReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.ok_ops == 0 {
                return Err(std::io::Error::other("injected read failure"));
            }
            self.ok_ops -= 1;
            self.inner.read(buffer)
        }
    }

    /// The one `Write` implementation used by every unit-test encrypt call;
    /// its N-th write or flush operation can be made to fail.
    struct TestWriter {
        written: Vec<u8>,
        ok_ops: usize,
    }

    impl TestWriter {
        fn new() -> Self {
            Self::failing_after(usize::MAX)
        }

        fn failing_after(ok_ops: usize) -> Self {
            Self {
                written: Vec::new(),
                ok_ops,
            }
        }
    }

    impl Write for TestWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            if self.ok_ops == 0 {
                return Err(std::io::Error::other("injected write failure"));
            }
            self.ok_ops -= 1;
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if self.ok_ops == 0 {
                return Err(std::io::Error::other("injected flush failure"));
            }
            self.ok_ops -= 1;
            Ok(())
        }
    }

    fn encrypt_vec(plaintext: &[u8]) -> Vec<u8> {
        let mut writer = TestWriter::new();
        encrypt_stream(
            &mut TestReader::new(plaintext),
            &mut writer,
            &test_phrase(),
            &TEST_KDF,
        )
        .expect("encryption to memory succeeds");
        writer.written
    }

    fn decrypt_vec(container: &[u8], phrase: &Phrase) -> (Vec<u8>, Result<StreamSummary, Error>) {
        let mut plaintext = Vec::new();
        let result = decrypt_stream(&mut TestReader::new(container), &mut plaintext, phrase);
        (plaintext, result)
    }

    #[test]
    fn round_trips_across_frame_boundaries() {
        let phrase = test_phrase();
        for len in [0usize, 1, 262_144, 262_145, 600_000] {
            let plaintext = pattern(len);
            let container = encrypt_vec(&plaintext);
            let expected_frames = u64::try_from(len.div_ceil(262_144) + 1).expect("small count");
            let expected = StreamSummary {
                plaintext_len: u64::try_from(len).expect("small length"),
                frames: expected_frames,
            };

            let (decrypted, decrypt_result) = decrypt_vec(&container, &phrase);
            assert_eq!(decrypt_result.expect("round trip decrypts"), expected);
            assert_eq!(decrypted, plaintext);

            let verified = verify_stream(&mut TestReader::new(&container), &phrase)
                .expect("round trip verifies");
            assert_eq!(verified, expected);

            let info =
                inspect_stream(&mut TestReader::new(&container)).expect("round trip inspects");
            assert_eq!(info.format_version, 1);
            assert_eq!(info.suite, 1);
            assert_eq!(info.kdf, TEST_KDF);
            assert_eq!(info.container_id.as_slice(), &container[56..72]);
        }
    }

    #[test]
    fn wrong_phrase_fails_authentication_before_any_output() {
        let container = encrypt_vec(b"attacker visible nothing");
        let (plaintext, result) = decrypt_vec(&container, &wrong_phrase());
        assert_eq!(err_kind(result), Kind::Auth);
        assert!(plaintext.is_empty());
        let verify = verify_stream(&mut TestReader::new(&container), &wrong_phrase());
        assert_eq!(err_kind(verify), Kind::Auth);
    }

    #[test]
    fn encrypt_rejects_out_of_bounds_kdf_parameters() {
        let bad = KdfParams {
            iterations: 0,
            ..TEST_KDF
        };
        let result = encrypt_stream(
            &mut TestReader::new(b"data"),
            &mut TestWriter::new(),
            &test_phrase(),
            &bad,
        );
        assert_eq!(err_kind(result), Kind::Format(FormatError::KdfBounds));
    }

    /// One data frame of 19 plaintext bytes: flag 160, length 161..165,
    /// ciphertext 165..200; final frame: flag 200, length 201..205,
    /// ciphertext 205..261.
    fn small_container() -> Vec<u8> {
        encrypt_vec(b"vaero tamper matrix")
    }

    #[test]
    fn tampered_bytes_fail_closed_with_classified_errors() {
        let container = small_container();
        let cases: &[(usize, u8, Kind)] = &[
            (30, 0xA5, Kind::Auth),  // KDF salt (header prefix, wrap AAD)
            (60, 0xA5, Kind::Auth),  // container id (header prefix, wrap AAD)
            (75, 0xA5, Kind::Auth),  // frame nonce prefix (header prefix, wrap AAD)
            (90, 0xA5, Kind::Auth),  // wrap nonce (phrase slot)
            (120, 0xA5, Kind::Auth), // wrapped CEK (phrase slot)
            (170, 0xA5, Kind::Auth), // data frame ciphertext
            (210, 0xA5, Kind::Auth), // final frame ciphertext
            (0, 0x00, Kind::Format(FormatError::Magic)),
            (8, 0x03, Kind::Format(FormatError::Version(3))),
            (10, 0x03, Kind::Format(FormatError::Suite(3))),
            (13, 0x00, Kind::Format(FormatError::KdfBounds)),
            (160, 0x02, Kind::Format(FormatError::FrameFlag(2))),
            // Data frame re-flagged as final: its 35-byte length is invalid.
            (160, 0x01, Kind::Format(FormatError::FrameLength(35))),
            // Data frame length below the 17-byte minimum.
            (161, 0x10, Kind::Format(FormatError::FrameLength(16))),
            // Data frame length in range but wrong: authentication fails.
            (161, 0x38, Kind::Auth),
            // Final frame re-flagged as data: 56 is in range, AAD differs.
            (200, 0x00, Kind::Auth),
            (200, 0x05, Kind::Format(FormatError::FrameFlag(5))),
            (201, 0x39, Kind::Format(FormatError::FrameLength(57))),
        ];
        for &(offset, value, expected) in cases {
            let mut tampered = container.clone();
            tampered[offset] = value;
            let (_, result) = decrypt_vec(&tampered, &test_phrase());
            assert_eq!(err_kind(result), expected, "offset {offset}");
        }
    }

    #[test]
    fn data_frame_length_above_maximum_is_rejected() {
        let mut tampered = small_container();
        tampered[161..165].copy_from_slice(&262_161u32.to_le_bytes());
        let (_, result) = decrypt_vec(&tampered, &test_phrase());
        assert_eq!(
            err_kind(result),
            Kind::Format(FormatError::FrameLength(262_161))
        );
    }

    #[test]
    fn truncation_and_trailing_bytes_are_classified() {
        let container = small_container();
        let truncated_cases: &[(usize, FormatError)] = &[
            (100, FormatError::Truncated),    // inside the header
            (160, FormatError::MissingFinal), // clean end where a flag belongs
            (163, FormatError::Truncated),    // inside a frame length field
            (180, FormatError::Truncated),    // inside a data frame ciphertext
            (200, FormatError::MissingFinal), // clean end before the final frame
            (215, FormatError::Truncated),    // inside the final frame
        ];
        for &(len, expected) in truncated_cases {
            let (_, result) = decrypt_vec(&container[..len], &test_phrase());
            assert_eq!(err_kind(result), Kind::Format(expected), "length {len}");
        }

        let mut trailing = container.clone();
        trailing.push(0);
        let (_, result) = decrypt_vec(&trailing, &test_phrase());
        assert_eq!(err_kind(result), Kind::Format(FormatError::TrailingData));
    }

    #[test]
    fn swapped_and_duplicated_frames_fail_authentication() {
        let plaintext = pattern(524_288);
        let container = encrypt_vec(&plaintext);
        let frame0 = &container[160..160 + FULL_FRAME];
        let frame1 = &container[160 + FULL_FRAME..160 + 2 * FULL_FRAME];
        let tail = &container[160 + 2 * FULL_FRAME..];

        let mut swapped = container[..160].to_vec();
        swapped.extend_from_slice(frame1);
        swapped.extend_from_slice(frame0);
        swapped.extend_from_slice(tail);
        let (_, result) = decrypt_vec(&swapped, &test_phrase());
        assert_eq!(err_kind(result), Kind::Auth);

        let mut duplicated = container[..160].to_vec();
        duplicated.extend_from_slice(frame0);
        duplicated.extend_from_slice(frame0);
        duplicated.extend_from_slice(frame1);
        duplicated.extend_from_slice(tail);
        let (_, result) = decrypt_vec(&duplicated, &test_phrase());
        assert_eq!(err_kind(result), Kind::Auth);
    }

    #[test]
    fn partial_output_is_reported_as_failure() {
        let plaintext = pattern(262_145);
        let mut container = encrypt_vec(&plaintext);
        // Corrupt the second data frame's ciphertext.
        container[160 + FULL_FRAME + 5] ^= 1;
        let (partial, result) = decrypt_vec(&container, &test_phrase());
        assert_eq!(err_kind(result), Kind::Auth);
        assert_eq!(partial, &plaintext[..262_144]);
    }

    /// Rebuild `small_container`'s final frame with the real CEK but a
    /// corrupted commitment, exercising the commitment check itself.
    fn forge_final_frame(corrupt_len: bool, corrupt_hash: bool) -> Vec<u8> {
        let plaintext = b"vaero tamper matrix";
        let container = small_container();
        let header_bytes: [u8; 160] = container[..160].try_into().expect("header is 160 bytes");
        let header = Header::parse(&header_bytes).expect("own header parses");
        let kek = kdf::derive_kek(test_phrase().entropy(), &header.salt, &header.kdf);
        let cek = unwrap_cek(
            &kek,
            &header_bytes[..HEADER_PREFIX_LEN],
            &header.wrap_nonce,
            &header.wrapped_cek,
        )
        .expect("own slot unwraps");

        let mut stored_len = u64::try_from(plaintext.len()).expect("small length");
        if corrupt_len {
            stored_len += 1;
        }
        let mut final_plaintext = [0u8; 40];
        final_plaintext[..8].copy_from_slice(&stored_len.to_le_bytes());
        final_plaintext[8..].copy_from_slice(&Sha256::digest(plaintext));
        if corrupt_hash {
            final_plaintext[9] ^= 1;
        }
        let sealed = seal_frame(&cek, &header_bytes, 1, FLAG_FINAL, &final_plaintext);

        let data_end = 160 + 5 + plaintext.len() + 16;
        let mut forged = container[..data_end].to_vec();
        forged.push(FLAG_FINAL);
        forged.extend_from_slice(&FINAL_FRAME_CIPHERTEXT_LEN.to_le_bytes());
        forged.extend_from_slice(&sealed);
        forged
    }

    #[test]
    fn commitment_mismatch_is_detected_despite_valid_frames() {
        let honest = forge_final_frame(false, false);
        let (plaintext, result) = decrypt_vec(&honest, &test_phrase());
        result.expect("honest re-sealed final frame decrypts");
        assert_eq!(plaintext, b"vaero tamper matrix");

        for (corrupt_len, corrupt_hash) in [(true, false), (false, true)] {
            let forged = forge_final_frame(corrupt_len, corrupt_hash);
            let (_, result) = decrypt_vec(&forged, &test_phrase());
            assert_eq!(err_kind(result), Kind::Format(FormatError::Commitment));
        }
    }

    #[test]
    fn inspect_reports_truncated_header() {
        let container = small_container();
        let result = inspect_stream(&mut TestReader::new(&container[..100]));
        assert_eq!(err_kind(result), Kind::Format(FormatError::Truncated));
    }

    #[test]
    fn decrypt_surfaces_read_failures_at_every_call_site() {
        let plaintext = pattern(262_145);
        let container = encrypt_vec(&plaintext);
        let phrase = test_phrase();
        let mut succeeded = false;
        for ok_ops in 0..32 {
            let mut reader = TestReader::failing_after(&container, ok_ops);
            let mut sink = Vec::new();
            match decrypt_stream(&mut reader, &mut sink, &phrase) {
                Ok(summary) => {
                    assert_eq!(summary.plaintext_len, 262_145);
                    succeeded = true;
                    break;
                }
                Err(error) => assert_eq!(kind(&error), Kind::Io, "ok_ops {ok_ops}"),
            }
        }
        assert!(succeeded, "sweep must eventually succeed");
    }

    #[test]
    fn encrypt_surfaces_write_failures_at_every_call_site() {
        let plaintext = pattern(262_145);
        let phrase = test_phrase();
        let mut succeeded = false;
        for ok_ops in 0..16 {
            let mut writer = TestWriter::failing_after(ok_ops);
            match encrypt_stream(
                &mut TestReader::new(&plaintext),
                &mut writer,
                &phrase,
                &TEST_KDF,
            ) {
                Ok(summary) => {
                    assert_eq!(summary.frames, 3);
                    succeeded = true;
                    break;
                }
                Err(error) => assert_eq!(kind(&error), Kind::Io, "ok_ops {ok_ops}"),
            }
        }
        assert!(succeeded, "sweep must eventually succeed");
    }

    #[test]
    fn encrypt_surfaces_input_read_failures() {
        let mut reader = TestReader::failing_after(b"unreadable", 0);
        let result = encrypt_stream(
            &mut reader,
            &mut TestWriter::new(),
            &test_phrase(),
            &TEST_KDF,
        );
        assert_eq!(err_kind(result), Kind::Io);
    }

    #[test]
    fn decrypt_surfaces_output_write_failures() {
        let container = small_container();
        let mut writer = TestWriter::failing_after(0);
        let result = decrypt_stream(
            &mut TestReader::new(&container),
            &mut writer,
            &test_phrase(),
        );
        assert_eq!(err_kind(result), Kind::Io);
    }

    #[test]
    fn fuzz_smoke_random_garbage_never_panics() {
        let phrase = test_phrase();
        for round in 0..256usize {
            let mut garbage = vec![0u8; round * 2];
            crate::fill_random(&mut garbage);
            // A random 8-byte magic collision is beyond reach, so the
            // classification of garbage is deterministic.
            let expected = if garbage.len() < 160 {
                Kind::Format(FormatError::Truncated)
            } else {
                Kind::Format(FormatError::Magic)
            };
            let inspect = inspect_stream(&mut TestReader::new(&garbage));
            assert_eq!(err_kind(inspect), expected, "round {round}");
            let (_, result) = decrypt_vec(&garbage, &phrase);
            assert_eq!(err_kind(result), expected, "round {round}");
        }
    }

    #[test]
    fn fuzz_smoke_single_byte_flips_fail_closed() {
        let container = encrypt_vec(b"");
        let phrase = test_phrase();
        for position in 0..container.len() {
            let mut flipped = container.clone();
            flipped[position] ^= 0xFF;
            let (_, result) = decrypt_vec(&flipped, &phrase);
            // Fails closed with a format or authentication error, never I/O.
            assert_ne!(err_kind(result), Kind::Io, "position {position}");
        }
    }
}
