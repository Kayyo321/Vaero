//! Golden fixture compatibility test.
//!
//! The committed container was produced by a build of this crate and must
//! keep decrypting byte-identically. Until format version 1 is declared
//! stable, the fixture is regenerated only together with a version bump of
//! `docs/formats/crypt-v1.md`.

use std::io::Cursor;

use vaero_crypto::{Phrase, StreamSummary, decrypt_stream, inspect_stream, verify_stream};

const GOLDEN_CONTAINER: &[u8] = include_bytes!("fixtures/golden-v1.crypt");
const GOLDEN_PHRASE: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const GOLDEN_PLAINTEXT: &[u8] = b"Vaero golden container fixture, format version 1.\n";

fn golden_phrase() -> Phrase {
    Phrase::parse(GOLDEN_PHRASE).expect("golden phrase parses")
}

fn golden_summary() -> StreamSummary {
    StreamSummary {
        plaintext_len: 50,
        frames: 2,
    }
}

#[test]
fn golden_container_decrypts_byte_identically() {
    let mut plaintext = Vec::new();
    let summary = decrypt_stream(
        &mut Cursor::new(GOLDEN_CONTAINER),
        &mut plaintext,
        &golden_phrase(),
    )
    .expect("golden container decrypts");
    assert_eq!(plaintext, GOLDEN_PLAINTEXT);
    assert_eq!(summary, golden_summary());
}

#[test]
fn golden_container_verifies() {
    let summary = verify_stream(&mut Cursor::new(GOLDEN_CONTAINER), &golden_phrase())
        .expect("golden container verifies");
    assert_eq!(summary, golden_summary());
}

#[test]
fn golden_container_public_info_is_stable() {
    let info =
        inspect_stream(&mut Cursor::new(GOLDEN_CONTAINER)).expect("golden container inspects");
    assert_eq!(info.format_version, 1);
    assert_eq!(info.suite, 1);
    assert_eq!(info.kdf.memory_kib, 8_192);
    assert_eq!(info.kdf.iterations, 1);
    assert_eq!(info.kdf.parallelism, 1);
    assert_eq!(info.container_id.as_slice(), &GOLDEN_CONTAINER[56..72]);
}
