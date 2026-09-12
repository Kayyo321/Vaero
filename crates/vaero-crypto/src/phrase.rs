//! BIP-39 English recovery phrases.
//!
//! The canonical state of a [`Phrase`] is its decoded entropy; words are
//! derived on demand. Entropy, never the string form, feeds key derivation,
//! so presentation differences cannot change derived keys.

use std::fmt;
use std::sync::LazyLock;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Embedded BIP-39 English word list, word list version 1.
///
/// Byte-identical to the canonical list published with the BIP-39
/// specification: 2048 lowercase ASCII words, sorted ascending, LF separated.
const WORD_LIST_TEXT: &str = include_str!("wordlist/english.txt");

/// Number of words in the BIP-39 English word list.
const WORD_COUNT: usize = 2048;

/// The word list split into individual words, in ascending order.
static WORDS: LazyLock<[&str; WORD_COUNT]> = LazyLock::new(|| {
    WORD_LIST_TEXT
        .lines()
        .collect::<Vec<&str>>()
        .try_into()
        .expect("embedded BIP-39 English word list holds exactly 2048 words")
});

/// Bits encoded by each BIP-39 word.
const BITS_PER_WORD: usize = 11;

/// Reasons a phrase string cannot be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhraseError {
    /// The phrase does not contain exactly 12, 18, or 24 words; carries the
    /// observed word count.
    WordCount(usize),
    /// A word is not in the BIP-39 English word list; carries the zero-based
    /// position of the offending word. No correction is ever suggested.
    UnknownWord {
        /// Zero-based position of the unrecognized word.
        index: usize,
    },
    /// The embedded SHA-256 checksum bits do not match the entropy.
    Checksum,
}

impl fmt::Display for PhraseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WordCount(count) => {
                write!(
                    formatter,
                    "phrase must contain 12, 18, or 24 words, found {count}"
                )
            }
            Self::UnknownWord { index } => {
                write!(
                    formatter,
                    "phrase word at position {index} is not in the word list"
                )
            }
            Self::Checksum => formatter.write_str("phrase checksum mismatch"),
        }
    }
}

impl std::error::Error for PhraseError {}

/// Supported phrase sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhraseLength {
    /// 12 words: 128 bits of entropy plus a 4-bit checksum.
    Words12,
    /// 18 words: 192 bits of entropy plus a 6-bit checksum.
    Words18,
    /// 24 words: 256 bits of entropy plus an 8-bit checksum.
    Words24,
}

impl PhraseLength {
    /// Number of words a phrase of this length contains.
    #[must_use]
    pub const fn word_count(self) -> usize {
        match self {
            Self::Words12 => 12,
            Self::Words18 => 18,
            Self::Words24 => 24,
        }
    }

    /// Number of entropy bytes a phrase of this length encodes.
    #[must_use]
    pub const fn entropy_len(self) -> usize {
        match self {
            Self::Words12 => 16,
            Self::Words18 => 24,
            Self::Words24 => 32,
        }
    }

    /// Map a word count to a phrase length, if supported.
    #[must_use]
    pub const fn from_word_count(count: usize) -> Option<Self> {
        match count {
            12 => Some(Self::Words12),
            18 => Some(Self::Words18),
            24 => Some(Self::Words24),
            _ => None,
        }
    }
}

/// A decoded recovery phrase.
///
/// Holds only the decoded entropy, wrapped in [`Zeroizing`] so it is wiped on
/// drop. There is deliberately no `Display` implementation and no serde
/// support; [`Phrase::words`] is the only way to render the phrase.
pub struct Phrase {
    entropy: Zeroizing<Vec<u8>>,
}

impl Phrase {
    /// Generate a fresh phrase from operating-system randomness.
    ///
    /// # Panics
    ///
    /// Panics when the operating system CSPRNG is unavailable; no fallback
    /// randomness source exists by design.
    #[must_use]
    pub fn generate(length: PhraseLength) -> Self {
        let mut entropy = Zeroizing::new(vec![0u8; length.entropy_len()]);
        crate::fill_random(&mut entropy);
        Self { entropy }
    }

    /// Decode a phrase string.
    ///
    /// Folds case and collapses whitespace, but never guesses misspelled
    /// words.
    ///
    /// # Errors
    ///
    /// Returns [`PhraseError::WordCount`] when the phrase is not exactly 12,
    /// 18, or 24 words, [`PhraseError::UnknownWord`] with the position of the
    /// first word missing from the word list, and [`PhraseError::Checksum`]
    /// when the embedded checksum bits do not match the entropy.
    pub fn parse(text: &str) -> Result<Self, PhraseError> {
        let lowered = Zeroizing::new(text.to_lowercase());
        let words: Vec<&str> = lowered.split_whitespace().collect();
        let length = PhraseLength::from_word_count(words.len())
            .ok_or(PhraseError::WordCount(words.len()))?;

        let mut indices = Vec::with_capacity(words.len());
        for (position, word) in words.iter().enumerate() {
            let index = WORDS
                .binary_search(word)
                .map_err(|_| PhraseError::UnknownWord { index: position })?;
            indices.push(index);
        }

        let entropy_bits = length.entropy_len() * 8;
        let checksum_bits = length.entropy_len() / 4;
        let total_bits = entropy_bits + checksum_bits;
        let mut bits = Zeroizing::new(vec![0u8; total_bits.div_ceil(8)]);
        for (word_position, &index) in indices.iter().enumerate() {
            for bit_offset in 0..BITS_PER_WORD {
                if (index >> (BITS_PER_WORD - 1 - bit_offset)) & 1 == 1 {
                    let position = word_position * BITS_PER_WORD + bit_offset;
                    bits[position / 8] |= 1u8 << (7 - position % 8);
                }
            }
        }

        let entropy = Zeroizing::new(bits[..length.entropy_len()].to_vec());
        let digest = Sha256::digest(entropy.as_slice());
        for position in 0..checksum_bits {
            if bit_at(&bits, entropy_bits + position) != bit_at(&digest, position) {
                return Err(PhraseError::Checksum);
            }
        }
        Ok(Self { entropy })
    }

    /// Render the phrase words, derived on demand from the entropy.
    #[must_use]
    pub fn words(&self) -> Vec<&'static str> {
        let entropy_bits = self.entropy.len() * 8;
        let checksum_bits = self.entropy.len() / 4;
        let word_count = (entropy_bits + checksum_bits) / BITS_PER_WORD;
        let digest = Sha256::digest(self.entropy.as_slice());

        let mut words = Vec::with_capacity(word_count);
        for word_position in 0..word_count {
            let mut index = 0usize;
            for bit_offset in 0..BITS_PER_WORD {
                let position = word_position * BITS_PER_WORD + bit_offset;
                let bit = if position < entropy_bits {
                    bit_at(&self.entropy, position)
                } else {
                    bit_at(&digest, position - entropy_bits)
                };
                index = (index << 1) | usize::from(bit);
            }
            words.push(WORDS[index]);
        }
        words
    }

    /// The decoded entropy bytes (16, 24, or 32 bytes).
    #[must_use]
    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }
}

impl fmt::Debug for Phrase {
    /// Redacted: never prints words or entropy.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Phrase(<redacted>)")
    }
}

/// Read the bit at `position` (most-significant bit first) from `bytes`.
fn bit_at(bytes: &[u8], position: usize) -> bool {
    (bytes[position / 8] >> (7 - position % 8)) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::{Phrase, PhraseError, PhraseLength, WORDS};

    /// English vectors from the reference `trezor/python-mnemonic`
    /// `vectors.json` (entropy and mnemonic columns only).
    const VECTORS: &[(&str, &str)] = &[
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon about",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ),
        (
            "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
            "gravity machine north sort system female filter attitude volume fold club stay \
             feature office ecology stable narrow fog",
        ),
        (
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "hamster diagram private dutch cause delay private meat slide toddler razor book \
             happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        ),
        (
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open \
             amazing screen patrol group space point ten exist slush involve unfold",
        ),
    ];

    fn entropy_from_hex(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                    .expect("test vectors contain valid hex")
            })
            .collect()
    }

    #[test]
    fn word_list_is_canonical() {
        assert_eq!(WORDS.len(), 2048);
        assert_eq!(WORDS[0], "abandon");
        assert_eq!(WORDS[2047], "zoo");
        for pair in WORDS.windows(2) {
            assert!(pair[0] < pair[1], "word list must be sorted ascending");
        }
        for word in WORDS.iter() {
            assert!(word.bytes().all(|byte| byte.is_ascii_lowercase()));
        }
    }

    #[test]
    fn reference_vectors_round_trip() {
        for (hex, mnemonic) in VECTORS {
            let phrase = Phrase::parse(mnemonic).expect("reference mnemonics parse");
            assert_eq!(phrase.entropy(), entropy_from_hex(hex).as_slice());
            assert_eq!(phrase.words().join(" "), *mnemonic);
        }
    }

    #[test]
    fn generate_parse_round_trip() {
        for length in [
            PhraseLength::Words12,
            PhraseLength::Words18,
            PhraseLength::Words24,
        ] {
            let phrase = Phrase::generate(length);
            assert_eq!(phrase.entropy().len(), length.entropy_len());
            let words = phrase.words();
            assert_eq!(words.len(), length.word_count());
            let reparsed = Phrase::parse(&words.join(" ")).expect("own phrases parse");
            assert_eq!(reparsed.entropy(), phrase.entropy());
        }
    }

    #[test]
    fn parse_normalizes_case_and_whitespace() {
        let messy = "  Legal WINNER thank\tyear wave sausage worth useful\r\nlegal winner \
                     thank  yellow  ";
        let phrase = Phrase::parse(messy).expect("normalized phrase parses");
        assert_eq!(
            phrase.entropy(),
            entropy_from_hex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").as_slice()
        );
    }

    #[test]
    fn parse_rejects_bad_word_counts() {
        assert_eq!(Phrase::parse("").unwrap_err(), PhraseError::WordCount(0));
        let eleven = ["abandon"; 11].join(" ");
        assert_eq!(
            Phrase::parse(&eleven).unwrap_err(),
            PhraseError::WordCount(11)
        );
        let thirteen = ["abandon"; 13].join(" ");
        assert_eq!(
            Phrase::parse(&thirteen).unwrap_err(),
            PhraseError::WordCount(13)
        );
    }

    #[test]
    fn parse_reports_first_unknown_word_position() {
        let text = "abandon abandon abandon vaerozz abandon abandon abandon abandon abandon \
                    abandon abandon about";
        assert_eq!(
            Phrase::parse(text).unwrap_err(),
            PhraseError::UnknownWord { index: 3 }
        );
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        let text = ["abandon"; 12].join(" ");
        assert_eq!(Phrase::parse(&text).unwrap_err(), PhraseError::Checksum);
    }

    #[test]
    fn debug_is_redacted() {
        let phrase =
            Phrase::parse("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong").expect("parses");
        let rendered = format!("{phrase:?}");
        assert_eq!(rendered, "Phrase(<redacted>)");
        assert!(!rendered.contains("zoo"));
    }

    #[test]
    fn phrase_length_conversions() {
        assert_eq!(PhraseLength::Words12.word_count(), 12);
        assert_eq!(PhraseLength::Words18.word_count(), 18);
        assert_eq!(PhraseLength::Words24.word_count(), 24);
        assert_eq!(PhraseLength::Words12.entropy_len(), 16);
        assert_eq!(PhraseLength::Words18.entropy_len(), 24);
        assert_eq!(PhraseLength::Words24.entropy_len(), 32);
        assert_eq!(
            PhraseLength::from_word_count(12),
            Some(PhraseLength::Words12)
        );
        assert_eq!(
            PhraseLength::from_word_count(18),
            Some(PhraseLength::Words18)
        );
        assert_eq!(
            PhraseLength::from_word_count(24),
            Some(PhraseLength::Words24)
        );
        assert_eq!(PhraseLength::from_word_count(15), None);
    }

    #[test]
    fn phrase_error_display_is_stable() {
        assert_eq!(
            PhraseError::WordCount(7).to_string(),
            "phrase must contain 12, 18, or 24 words, found 7"
        );
        assert_eq!(
            PhraseError::UnknownWord { index: 4 }.to_string(),
            "phrase word at position 4 is not in the word list"
        );
        assert_eq!(
            PhraseError::Checksum.to_string(),
            "phrase checksum mismatch"
        );
    }

    #[test]
    fn fuzz_smoke_random_phrase_text_never_panics() {
        let mut seed = [0u8; 32];
        crate::fill_random(&mut seed);
        for round in 0..256usize {
            let mut text = String::new();
            for position in 0..(round % 30) {
                let index = (usize::from(seed[position % 32]) * 8 + round) % 2048;
                text.push_str(WORDS[index]);
                text.push(' ');
            }
            let _unused = Phrase::parse(&text);
        }
    }
}
