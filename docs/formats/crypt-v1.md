# Vaero `.crypt` container, format version 1 (DRAFT)

> **Status: EXPERIMENTAL / UNREVIEWED.** This document is a draft proposal for
> the Phase 1 encrypted container. Every choice here (primitives, layout,
> limits, wire encoding) remains open to change until the format is declared
> stable after the independent review required by `PROJECT.md` §12 and §17.
> Containers written by pre-release builds may become unreadable by later
> builds. Do not protect the only copy of any data with this format.

This is also the implementation contract for `vaero-crypto`, `vaero-core`, and
`vaero-cli`. Code and this document must not diverge; change both together.

## 1. Cryptographic suite (suite id 1)

| Role | Primitive | Source |
| --- | --- | --- |
| Phrase encoding | BIP-39 English word list (2048 words, 11 bits/word, SHA-256 checksum) | BIP-39 specification |
| Key derivation | Argon2id v1.3, 32-byte output | `argon2` crate (RustCrypto) |
| AEAD (payload frames and CEK wrap) | XChaCha20-Poly1305 | `chacha20poly1305` crate (RustCrypto) |
| Plaintext commitment and phrase checksum | SHA-256 | `sha2` crate (RustCrypto) |
| Randomness | Operating system CSPRNG only | `getrandom` crate |

Nothing here is a novel primitive. The phrase's decoded entropy (16/24/32
bytes), never its string form, is the Argon2id input, so presentation
normalization cannot change derived keys.

Key hierarchy: `phrase entropy --Argon2id(salt, params)--> KEK (32 bytes)`.
A fresh random 32-byte content-encryption key (CEK) encrypts the payload; the
KEK only wraps the CEK inside a key slot. Future revisions can add more slot
types (second phrase, hardware, PGP recipients) without re-encrypting payloads.
Keys and phrase entropy are zeroized on drop where the language permits.

## 2. Wire layout

All integers are little-endian unless stated otherwise. The container is:
`header (160 bytes) || frame*`. There is no plaintext anywhere outside AEAD
ciphertexts. The public header intentionally reveals only what decryption
requires: format/suite ids, KDF parameters and salt, a random container id,
and random nonce material.

### 2.1 Header (160 bytes)

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | Magic `VAEROCPT` (`56 41 45 52 4F 43 50 54`) |
| 8 | 2 | Format version, u16 = 1 |
| 10 | 2 | Suite id, u16 = 1 |
| 12 | 4 | KDF memory cost, u32, KiB |
| 16 | 4 | KDF iterations, u32 |
| 20 | 4 | KDF parallelism, u32 |
| 24 | 32 | KDF salt (random per container) |
| 56 | 16 | Container id (random per container) |
| 72 | 16 | Frame nonce prefix (random per container) |
| 88 | 24 | Phrase slot: wrap nonce (random) |
| 112 | 48 | Phrase slot: wrapped CEK (32-byte CEK + 16-byte Poly1305 tag) |

Bytes 0..88 are the **header prefix**; bytes 0..160 are the **full header**.

CEK wrap: `XChaCha20-Poly1305(key = KEK, nonce = wrap nonce, plaintext = CEK,
aad = header prefix)`. A wrong phrase, a tampered header prefix, or a tampered
slot all fail the wrap tag and must be reported as authentication failure
without reading any payload frame.

### 2.2 Frames

Frames follow the header in order, implicitly indexed 0, 1, 2, … Each frame is:

| Field | Size | Meaning |
| --- | --- | --- |
| flag | u8 | 0 = data frame, 1 = final frame; any other value is malformed |
| length | u32 | ciphertext length in bytes |
| ciphertext | length | XChaCha20-Poly1305 ciphertext (plaintext + 16-byte tag) |

- Frame nonce: `nonce prefix (16 bytes) || frame index as u64 big-endian`.
- Frame AAD: `full header (160 bytes) || frame index as u64 little-endian ||
  flag (1 byte)`.
- Frame key: the CEK. The CEK is random per container and the index is
  monotonic, so no (key, nonce) pair ever repeats.
- Data frame plaintext: 1..=262 144 bytes (256 KiB). Writers emit full 256 KiB
  frames except the last data frame. Readers accept any length in range.
- Final frame plaintext (exactly 40 bytes): total plaintext length as u64 LE,
  then SHA-256 of the whole plaintext. Exactly one final frame is required; it
  is the last frame; end of input must follow immediately.
- An empty plaintext produces a single final frame at index 0.

The final frame's commitment is defense in depth over the per-frame
authentication; both must pass before a decrypt or verify reports success.

## 3. Bounds on hostile input

Readers enforce all of the following before allocating or deriving anything
expensive; violations fail closed with a format or authentication error:

| Bound | Value |
| --- | --- |
| KDF memory | 8 192..=1 048 576 KiB (8 MiB..=1 GiB) |
| KDF iterations | 1..=64 |
| KDF parallelism | 1..=8 |
| Data frame ciphertext length | 17..=262 160 bytes |
| Final frame ciphertext length | exactly 56 bytes |
| Reader buffer allocation | one frame maximum (≤ 262 160 bytes) |

Writer defaults: memory 65 536 KiB (64 MiB), iterations 3, parallelism 1.
Defaults may rise over time; readers honor the stored parameters within the
bounds above.

## 4. Failure taxonomy

| Condition | Classification |
| --- | --- |
| Wrong phrase; tampered header, slot, frame; reordered/duplicated/reindexed frames | Authentication (fail closed, no plaintext released) |
| Bad magic, unknown version/suite, out-of-bounds KDF params, bad flag, bad frame length, truncation (unexpected EOF anywhere), missing final frame, trailing bytes after final frame, commitment or length mismatch | Format/corrupt |
| Underlying I/O failure other than unexpected EOF | I/O |

Decrypt streams plaintext frame-by-frame only after each frame authenticates;
an authentication or format failure after partial output must be surfaced as
failure, and file-level callers must discard the partial output (see §6).

## 5. Recovery phrases

- Generated with OS randomness only; 12, 18, or 24 words (128/192/256-bit
  entropy plus BIP-39 SHA-256 checksum bits).
- Word list: BIP-39 English, embedded and versioned (word list version 1);
  first word `abandon`, last word `zoo`, exactly 2048 entries.
- Parsing folds case and collapses whitespace but never guesses misspelled
  words. Diagnostics may report the position of an unrecognized word; they
  never print derived keys or suggest near-miss corrections that would leak
  entropy.
- Phrases are never accepted as command-line argument values, never logged,
  and never echoed to redirected output by default.

## 6. Public API contract (Phase 1)

`vaero-crypto` (pure; no filesystem access, no prompting, no printing):

```rust
pub enum Error { Io(std::io::Error), Format(FormatError), Auth }
pub enum FormatError {
    Magic, Version(u16), Suite(u16), KdfBounds, Truncated, TrailingData,
    FrameFlag(u8), FrameLength(u32), MissingFinal, Commitment,
}
pub enum PhraseError { WordCount(usize), UnknownWord { index: usize }, Checksum }
pub enum PhraseLength { Words12, Words18, Words24 }   // word_count(), entropy_len(), from_word_count()
pub struct Phrase;                                     // generate(PhraseLength), parse(&str), words(), entropy(); Debug is redacted; zeroizes on drop
pub struct KdfParams { pub memory_kib: u32, pub iterations: u32, pub parallelism: u32 } // DEFAULT, validate()
pub struct PublicInfo { pub format_version: u16, pub suite: u16, pub kdf: KdfParams, pub container_id: [u8; 16] }
pub struct StreamSummary { pub plaintext_len: u64, pub frames: u64 }

pub fn encrypt_stream(input: &mut impl Read, output: &mut impl Write, phrase: &Phrase, kdf: &KdfParams) -> Result<StreamSummary, Error>;
pub fn decrypt_stream(input: &mut impl Read, output: &mut impl Write, phrase: &Phrase) -> Result<StreamSummary, Error>;
pub fn verify_stream(input: &mut impl Read, phrase: &Phrase) -> Result<StreamSummary, Error>;
pub fn inspect_stream(input: &mut impl Read) -> Result<PublicInfo, Error>;
```

`vaero-core` (transactional file orchestration; no prompting, no printing):

```rust
pub enum Error { Io(std::io::Error), Format(FormatError), Auth, DestinationExists(PathBuf) }

pub fn encrypt_file(source: &Path, destination: &Path, length: PhraseLength, kdf: &KdfParams) -> Result<(Phrase, StreamSummary), Error>;
pub fn decrypt_file(source: &Path, destination: &Path, phrase: &Phrase) -> Result<StreamSummary, Error>;
pub fn verify_file(source: &Path, phrase: &Phrase) -> Result<StreamSummary, Error>;
pub fn inspect_file(source: &Path) -> Result<PublicInfo, Error>;
```

File semantics: refuse an existing destination (no overwrite mode exists in
Phase 1); write to a clearly named temporary sibling (`.<name>.vaero-partial-
<random>`), flush and sync, re-verify encrypt output by decrypting it before
commit, atomically rename into place, and best-effort delete the temporary on
any failure. Sources are never modified or deleted.

`vaero-cli` exit codes (stable, documented):

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 2 | Usage error or invalid phrase text (bad word/checksum/word count) |
| 3 | Authentication failure (wrong phrase or tampered container) |
| 4 | Corrupt or unsupported container |
| 5 | I/O or permission failure |
| 6 | Destination already exists |

Command surface:

```text
vaero encrypt <input> [-o <file>] [--words 12|18|24] [--phrase-out <file>]
vaero decrypt <input> [-o <file>] (--phrase-file <file> | --phrase-stdin)
vaero verify  <input> (--phrase-file <file> | --phrase-stdin)
vaero inspect <input>
vaero --help | --version
```

- `encrypt` defaults to `<input>.crypt`; `decrypt` strips a trailing `.crypt`
  or requires `-o`.
- The generated phrase is printed once, numbered, to stderr only when stderr
  is a terminal; otherwise `--phrase-out <new file>` is required and the
  command fails without it rather than writing the phrase to a redirected
  stream. On Windows, Vaero creates that phrase file empty, removes inherited
  DACL entries, grants full access to the current user's numerical SID, and
  only then writes the phrase. Windows-managed explicit SYSTEM or Administrators
  entries may remain; the protection boundary is other ordinary local accounts,
  not administrators who take ownership, SYSTEM, or code running as the same
  user. ACL setup failure removes the empty file and discards the encrypted
  output. Interactive no-echo phrase entry is deferred; `--phrase-file` and
  `--phrase-stdin` are the Phase 1 inputs, and a bare `--phrase <value>`
  option deliberately does not exist.
- Human status goes to stderr. `inspect` writes versioned JSON to stdout:
  `{"schema":1,"format":"vaero-crypt","formatVersion":1,"suite":1,
  "kdf":{"memoryKib":…,"iterations":…,"parallelism":…},"containerId":"<hex>"}`.

## 7. Compatibility

Unknown magic, versions, suites, flags, or out-of-bounds parameters are
rejected; nothing is skipped silently. A golden fixture container and phrase
are committed under `crates/vaero-crypto/tests/fixtures/` and must decrypt
byte-identically forever once format version 1 is stabilized; until then the
fixture is regenerated only together with a version bump of this document.
