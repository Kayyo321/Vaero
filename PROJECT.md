# Vaero Project Specification

## 1. Vision

Vaero is a Windows-first, open-source command-line application for protecting directories and drives with memorable recovery phrases. It should make strong encryption approachable without hiding the consequences: a Vaero phrase is the key to the data, and losing it means losing access.

Vaero packages a directory into a portable archive, optionally compresses that archive with the Vaero compression format, and encrypts the result:

```text
my-pictures.vro.crypt
my-pictures.vro.vip.crypt
```

The external naming scheme is deliberately small: `.vro` identifies Vaero data and subsequent suffixes describe the device or transforms wrapped around it. A suffix chain is read from left to right; `my-pictures.vro.vip.crypt`, for example, is Vaero data packaged as a Vaero virtual image package (`vip`, meaning *Vaero + zip*) and then encrypted.

The first release is a CLI. A GUI may later call the same versioned core library rather than reimplementing archive, compression, or cryptographic behavior.

### Product principles

1. **Secure by construction.** Use audited cryptographic primitives and formats; never invent cryptography.
2. **Recoverable by phrase.** Encrypted content can be opened using its phrase and the file itself, without an online account.
3. **Safe failure.** Interruption, insufficient disk space, or a wrong phrase must not destroy the source or expose partial plaintext.
4. **Inspectable and versioned.** File formats and security choices are documented, testable, and designed for future migration.
5. **Private by default.** Filenames, directory structure, timestamps, and compression metadata are protected by encryption.
6. **Honest behavior.** Vaero must clearly explain what it can and cannot protect, especially for live drives, SSD deletion, malware, and forgotten phrases.

## 2. Scope

### Initial CLI release

- Create and extract Vaero directory archives represented externally as `.vro`.
- Create and extract `vip` (Vaero + zip) compressed virtual-image packages.
- Encrypt and decrypt files using a generated phrase of 12 or more words.
- Provide a single pipeline command for archive + compression + encryption.
- Verify encrypted artifacts without writing extracted plaintext.
- Inspect non-sensitive container metadata.
- Estimate required space and refuse unsafe in-place operations.
- Support resumable or transactional output where practical.
- Run on currently supported 64-bit Windows editions.

### Later releases

- Prepare existing removable drives as **Vaero Compatible Drives (VCDs)**: Vaero-owned filesystems whose contents are represented by one mutable `.vro` drive archive.
- Mount encrypted containers as virtual drives.
- GUI built on the same core and format specifications.
- Hardware-backed key wrapping through Windows Hello/TPM as an optional convenience; the recovery phrase remains portable.
- Additional operating systems after the on-disk formats and Windows implementation stabilize.

### Explicit non-goals for the first release

- Replacing BitLocker for an active Windows system volume.
- Encrypting a mounted drive in place.
- Cloud accounts, phrase recovery services, or key escrow.
- Promising secure deletion on SSDs, flash media, snapshots, or journaled filesystems.
- Creating a novel cipher, password hash, or other cryptographic primitive.

## 3. Terminology and file types

### File naming

`.vro` is the single Vaero base extension. It may contain an archive, a VCD filesystem image, or another versioned Vaero object; its authenticated internal header is authoritative, never the filename. Optional suffixes describe wrappers in the order they were applied:

| Suffix | Meaning | Example |
| --- | --- | --- |
| `.vro` | Base Vaero object: archive or VCD filesystem payload, manifest, and integrity records | `photos.vro` |
| `.vip` | **Vaero Image Package**: Vaero + zip; seekable chunk compression, index, and optional deduplication | `photos.vro.vip` |
| `.crypt` | Authenticated encrypted wrapper | `photos.vro.vip.crypt` |

Thus, `photos.vro.vip.crypt` is decrypted first, then read as a compressed virtual-device/image package, then restored from the contained Vaero object. A simple `.vro.crypt` is valid when compression is deliberately omitted. Tools must detect the actual authenticated format rather than infer security properties from suffixes, and should preserve unfamiliar optional suffixes on copy or move. The older terms “Vaero Archive” and “Vortex compression stream” remain useful internal format names, but are not user-facing filename extensions.

The encrypted container should reveal as little as possible. By default, the original filename, file tree, timestamps, sizes, compression choices, and manifest belong inside the encrypted payload. The public header exposes only format/version information and the parameters required to derive a key and decrypt the container.

## 4. Recovery phrases and key derivation

### Phrase generation

- Generate phrases exclusively with the operating system cryptographically secure random number generator.
- Use a fixed, versioned word list with unambiguous words and normalized spelling.
- A 12-word phrase should encode at least 128 bits of randomness plus an error-detecting checksum.
- Offer stronger phrase sizes such as 18 and 24 words for long-lived or high-value archives.
- Display words with numbers and a confirmation step to catch copying mistakes.
- Never write the phrase to logs, command history, crash reports, filenames, the clipboard by default, or terminal output when redirected unless the user explicitly requests a machine-readable destination.

The word list and encoding scheme are part of the public format specification. Phrase parsing should tolerate harmless presentation differences such as case and repeated whitespace, but it must not silently guess misspelled words. Helpful diagnostics may identify an invalid word without revealing any key material.

### Deriving encryption keys

The phrase is not used directly as an encryption key. A memory-hard KDF such as **Argon2id** derives a master key using a unique random salt stored in the public header. Parameters are stored with the artifact so they can increase over time while old files remain readable. Defaults should be benchmarked to a reasonable delay on the current machine and bounded to prevent malicious files from requesting dangerous resource levels.

Domain-separated subkeys should be derived from the master key for header authentication, payload encryption, and any keyed identifiers. Sensitive buffers should be zeroized where the platform and language permit. Keys must never be reused with the same nonce.

Because generated 12-word phrases already carry high entropy, the KDF is primarily defense in depth and protection for a future mode that accepts user-supplied passphrases. Vaero should strongly discourage short human-created phrases.

## 5. Encryption wrapper (`.crypt`)

Vaero should use a well-reviewed authenticated-encryption construction, such as XChaCha20-Poly1305, through a maintained cryptographic library. The exact primitive must be fixed by the format version and reviewed before the format is declared stable.

### Proposed structure

```text
Public header
  magic, format version, algorithm identifiers
  KDF salt and bounded KDF parameters
  random container identifier
  encrypted/authenticated private-header descriptor

Encrypted frames
  monotonically numbered frame
  authenticated ciphertext chunk
  final-frame marker

Encrypted footer
  private manifest and optional index
  whole-stream commitment
```

Each frame is independently authenticated and binds its position, container identifier, format version, and relevant header data as associated data. Reordering, truncation, duplication, corruption, or use of a wrong phrase must fail closed. Chunking allows bounded memory usage, progress reporting, verification, and recovery from an interrupted output write without weakening integrity.

Encryption output is written to a new temporary file in the destination directory. Vaero authenticates and finalizes it, flushes it to disk, and then atomically renames it where Windows permits. Source deletion is never the default.

### Recovery, recipient, and PGP unlock policy

Every encrypted object has a random content-encryption key (CEK). The recovery phrase unlocks a protected CEK slot; future slots may additionally use a second phrase or hardware-backed key without re-encrypting the payload.

Vaero must also support an optional policy expressed in plain language as: **“Only accept decryption from these PGP keys.”** The policy stores canonical OpenPGP certificate fingerprints, never ambiguous user IDs or display names. For each authorized fingerprint, the CEK is wrapped to an eligible encryption-capable subkey. When the policy is required, Vaero releases plaintext only after the required private key(s) successfully unwrap their slot; a phrase alone is insufficient. Supported policy modes should be explicit: `any-of`, `all-of`, and `phrase-and-any-pgp`. The default remains phrase-only for portability.

This is an access-control mechanism, not merely a signature check. A signature proves who signed something but does not stop a phrase holder from decrypting it; CEK recipient slots do. The private policy, recipient fingerprints, and human-readable labels should be encrypted where possible, while the minimum needed to locate a candidate PGP key may be exposed in the authenticated public header. Revoking a key cannot retract copies already decrypted; rotation creates a new CEK/recipient set or re-encrypts the object as appropriate. The exact OpenPGP interoperability profile, allowed algorithms, subkey handling, expiry semantics, and revocation behavior require a focused security review before stabilizing.

## 6. Vaero Archive (`.vro` base object)

The archive is a deterministic, streaming representation of a directory tree. It should support:

- Unicode and long Windows paths.
- Regular files, empty files, and empty directories.
- Creation, modification, and access timestamps with explicit precision.
- Windows attributes and, when requested, ACL/security descriptors.
- Sparse-file extents.
- Reparse points and symbolic links represented as links, never followed by default.
- Optional NTFS alternate data streams, with an explicit warning when restoring to an unsupported filesystem.
- Per-entry hashes and a final manifest hash.
- Stable path ordering for reproducible archives when metadata settings permit it.

Archive paths must be relative and normalized. Extraction must reject absolute paths, drive prefixes, `..` traversal, reserved device names, unsafe reparse-point traversal, and case-collision surprises. Existing destination files are not overwritten unless the user selects an explicit policy.

The archive reader must impose limits on path length, entry count, nesting, metadata size, sparse expansion, and total expanded bytes. Treat every archive as hostile input.

## 7. Vaero Image Package (`.vip`)

### Concept: Vortex Adaptive Compression

`vip` means **Vaero + zip**. A `.vip` wrapper is not merely one compressor: it is a seekable, content-aware compression package that divides a `.vro` object or virtual-device payload into chunks and chooses the best safe encoding for each chunk. Its advantage is the system around compression: strong mixed-workload performance, deduplication, parallelism, random access, damage isolation, and predictable memory—not a claim that one new entropy coder beats 7z or RAR for every file.

The proposed engine, **Vortex**, has four stages:

1. **Content-defined chunking.** Rolling fingerprints choose chunk boundaries, so inserted bytes do not invalidate deduplication for the remainder of a large file.
2. **Fast classification.** A bounded sample estimates entropy and recognizes data families such as text/source, executables, structured numeric data, media, and already-compressed or encrypted content.
3. **Codec tournament.** A small, time-budgeted trial selects among store, a fast LZ-family mode, a high-ratio context mode, and specialized reversible transforms. Selection includes decompression cost and memory, not ratio alone.
4. **Chunk index and deduplication.** Repeated chunks are referenced within the same artifact. The index supports parallel decompression, partial extraction, verification, and localized recovery.

### Differentiators

- **Goal-driven profiles:** `fast`, `balanced`, `small`, and `archive` optimize for different combinations of time, ratio, memory, and restore speed.
- **Do-no-harm rule:** incompressible chunks are stored rather than expanded beyond a small bounded overhead.
- **Delta families:** similar files in one archive may share a base chunk and encode bounded deltas, useful for source trees, backups, and versioned assets.
- **Structured transforms:** reversible preprocessing can improve compression of UTF-8 text, repeated paths, numeric arrays, and executable sections.
- **Restore-first optimization:** the index can place bootstrapping dictionaries and commonly accessed metadata early, reducing time-to-first-file.
- **Resilience frames:** optional parity information can recover a limited number of damaged chunks. This is not a backup and must remain separate from cryptographic authentication.
- **Deterministic mode:** identical normalized inputs and settings produce identical `.vip` output, useful for testing and deduplication before encryption.

### Practical implementation strategy

The first format version should use mature, well-tested codec implementations behind Vaero's chunking, selection, and indexing layer. New Vaero-specific transforms or codecs can be introduced only after corpus benchmarks, fuzzing, and independent review. Every chunk records its codec and parameters, so newer readers can retain backward compatibility and unknown codecs fail cleanly.

Benchmarks should compare compression ratio, compression time, decompression time, peak memory, random-access latency, and corruption behavior across source code, office files, photos, video, VM images, databases, and mixed directories. “Better” is reported per workload and metric, never as an unconditional marketing claim.

## 8. Directory workflow

The safe default pipeline is:

```text
scan -> estimate -> archive -> compress -> encrypt -> verify -> commit
```

Intermediate archive and compressed data should stream directly into encryption whenever possible, avoiding plaintext temporary files. If staging is unavoidable, Vaero must disclose its location and clean it up after success or failure; it must not imply that cleanup securely erases SSD data.

Files that change during a scan are detected and reported. The default behavior should fail rather than silently create an inconsistent backup. A future snapshot-assisted mode may use Windows Volume Shadow Copy Service (VSS) for consistent reads when privileges and filesystem support allow it.

## 9. Virtual devices and Vaero Compatible Drives

Vaero treats a VCD as its own filesystem, not as a conventional filesystem with Vaero files placed on it. Its logical filesystem is one mutable, drive-root `.vro` object: effectively a glorified archive with filesystem semantics. Vaero alone reads and writes that object, exposing normal file and directory operations through its program (and a future Vaero mount), while the host OS need not understand the VCD's internal layout.

The `.vro` object contains the VCD root, file tree, metadata, allocation/index records, integrity commitments, and transactional journal. It must support incremental updates so ordinary file operations do not require rebuilding the drive from scratch, while retaining archive-style portability, verification, and restore behavior. A VCD may be copied or exported as a standalone `.vro` artifact; a virtual VCD is ordinarily saved as `name.vro`, then optionally wrapped as `name.vro.vip.crypt`.

### In-place VCD transforms

Vaero can apply transforms to the drive-root `.vro` in place through explicit drive commands:

- **Encrypt / unencrypt:** add or remove the authenticated `.crypt` wrapper around the VCD object.
- **Compress / decompress:** add or remove the `.vip` wrapper, or recompress with a selected profile.
- **Verify / scrub:** validate the root manifest, journal, and content chunks without extracting the drive.

The conceptual state is `drive.vro` → `drive.vro.vip` → `drive.vro.vip.crypt`; on physical media the bootstrap records the active layer chain rather than relying on a host-visible filename. “In place” means the VCD remains the target drive and its logical contents remain intact; it does **not** mean overwriting live bytes unsafely. Each transform writes a complete replacement representation to reserved/free VCD space or safe staging, verifies it, atomically switches the bootstrap pointer/commit generation, and retains the previous committed generation until recovery is no longer needed. Vaero must refuse the operation if capacity, staging, power-safety, or recovery conditions are insufficient.

Encryption and compression therefore act on the whole VCD filesystem object, not independently on each file. This keeps filenames, directory structure, timestamps, allocation metadata, and compression choices inside the encrypted payload. A future format may add multiple logical roots or volumes, but VCD v1 has exactly one drive-root `.vro` filesystem and no user-managed partition table.

### Preparing a VCD

`vaero drive prepare` can turn an existing eligible removable drive into a VCD. This is a provisioning operation, not in-place encryption of arbitrary existing files. It creates a small public bootstrap area and a Vaero device area holding the single drive-root `.vro` filesystem. The bootstrap area may carry only format/version information, a device identifier, active-generation/layer-chain locator, and recovery instructions; file names, file lists, sizes, and policy details remain protected when encryption is enabled.

Preparation normally reformats the selected target and therefore requires a backup-first workflow. Vaero must enumerate the exact physical disk, model, serial/OS identity, capacity, current volumes, and irreversible consequences; require elevated privileges and a typed confirmation that includes the target identity; dismount only after confirmation; and verify the newly written VCD before success. It must refuse system, boot, and ambiguous targets. A future migration workflow may copy ordinary files into a new VCD, verify them, and only then invite the user to erase the source; it must never claim to convert arbitrary filesystem sectors safely in place.

### Integrity and trust rules

Checksums are mandatory for every Vaero object, virtual device, VCD manifest, metadata record, and content chunk. The format uses a versioned collision-resistant hash (for example BLAKE3) for unkeyed content addressing and a keyed or authenticated commitment where secrecy or tamper resistance is needed. Checksums catch accidental damage and enable scrubbing; authenticated encryption and signed/PGP key slots detect malicious modification. Neither a bare checksum nor a PGP signature substitutes for the other.

`vaero verify` must work identically against a `.vro` chain, an unmounted VCD, or a mounted VCD: it first validates bootstrap, active-generation, and root-manifest commitments, then optionally performs a deep file/chunk scan without materializing plaintext. `vaero scrub` should record the last successful verification generation and report exactly which object range failed. Repair data, if introduced, is optional redundancy and never a replacement for a separate backup.

The optional PGP unlock policy applies to the drive-root object. A device-level policy can require an authorized PGP key before opening the VCD filesystem. Users should be warned clearly before creating an unrecoverable `all-of` policy or removing the only phrase/key path.

“Encrypt a drive” therefore has distinct operations in the CLI:

1. **Drive backup:** package readable contents into a Vaero object. This is safest and arrives first.
2. **Virtual device:** create, mount, and manage a `.vro.vip.crypt` device image.
3. **Prepare VCD:** provision a removable physical drive with its single Vaero filesystem object, then manage and transform it through Vaero.
4. **Whole-volume transformation:** overwrite an existing physical volume. This remains deferred until recovery, privilege, crash handling, and independent review are mature.

## 10. CLI design

Proposed command surface:

```powershell
vaero pack <directory> [-o <file>] [--profile balanced] [--words 12]
vaero unpack <file> [-o <directory>]
vaero encrypt <file> [-o <file>] [--words 12] [--pgp-policy <mode>] [--pgp-recipient <fingerprint>...]
vaero decrypt <file> [-o <file>]
vaero archive create <directory> [-o <file>]
vaero archive extract <file> [-o <directory>]
vaero compress <file> [-o <file>] [--profile balanced]
vaero decompress <file> [-o <file>]
vaero verify <file> [--deep]
vaero scrub <file-or-drive> [--deep]
vaero inspect <file>
vaero device create <file> [--size <size>] [--dynamic]
vaero device mount <file> [--read-only]
vaero drive list
vaero drive prepare <physical-drive> [--confirm <target-identity>]
vaero drive encrypt <physical-drive> [--words 12] [--pgp-policy <mode>] [--pgp-recipient <fingerprint>...]
vaero drive decrypt <physical-drive>
vaero drive compress <physical-drive> [--profile balanced]
vaero drive decompress <physical-drive>
vaero benchmark <path>
```

`pack` is the normal user journey. It creates a `.vro`, optionally wraps it in `.vip`, encrypts to `.crypt`, verifies it, and prints the recovery phrase once. `unpack` detects the authenticated layer chain, prompts securely for the phrase and any required PGP key, verifies before exposing data, and restores into a new directory by default.

### CLI behavior

- Interactive phrase entry does not echo.
- `--phrase` must not accept the secret directly on the command line because process listings and shell history may expose it.
- Automation can use a dedicated inherited handle or a carefully permissioned phrase file with an explicit warning; stdin support must avoid collisions with streamed payload input.
- Human output goes to stderr; machine-readable results can use versioned JSON on stdout.
- Exit codes distinguish invalid arguments, wrong phrase/authentication failure, corrupt input, unsafe path, insufficient space, permission failure, and interrupted work.
- Progress is byte-based where possible and disappears automatically when output is redirected.
- Cancellation leaves the original untouched and either removes or clearly labels incomplete output.
- All destructive or overwrite behavior requires an explicit flag and a precise confirmation policy.
- `--pgp-recipient` accepts a full fingerprint only; it must display the resolved certificate/subkey capabilities and never select a key solely by name or email.
- Mounting a device defaults to read-only until integrity and every required unlock policy have passed. Writable mounts use transactional commits and unmount performs a final manifest update.

## 11. Architecture

The project is expected to use Rust, matching the repository's current Cargo-oriented setup.

```text
vaero-cli       command parsing, prompts, progress, JSON output
vaero-core      pipeline orchestration and public high-level API
vaero-crypto    phrase decoding, KDF, key hierarchy, framed AEAD
vaero-archive   archive reader/writer and safe extraction
vaero-compress  Vortex chunker, codec selection, index, deduplication
vaero-format    versioned binary structures and compatibility rules
vaero-device    virtual-device, VCD filesystem object, bootstrap, transactional transforms, journals, scrubber
vaero-openpgp   recipient slots, fingerprint policy evaluation, OpenPGP interoperability
vaero-windows   Windows paths, metadata, privileges, VSS, future mounts
```

Parsers should be streaming state machines with explicit resource limits. Format libraries should not perform UI, prompting, or implicit filesystem writes. The CLI orchestrates policy; the lower-level crates enforce invariants.

Every on-disk format begins with a unique magic value and semantic format version. Compatibility is based on format versions and feature flags, not application version strings. Unknown mandatory features are rejected; optional features can be skipped only when the format defines that behavior safely.

## 12. Threat model

Vaero is intended to protect data at rest when an attacker obtains the encrypted artifact or powered-off storage but not the recovery phrase.

Vaero should defend against:

- Offline guessing of phrases.
- Tampering, truncation, reordering, corruption, stale VCD metadata, and substitution of an older or unrelated VCD generation.
- Metadata disclosure beyond the minimal public header.
- Malicious archives and decompression bombs.
- Path traversal and unsafe Windows filesystem names.
- Accidental interruption, overwrite, and partial output.

Vaero does not claim to protect against:

- A compromised machine, keylogger, screen capture, or malware while data is unlocked.
- An attacker observing the phrase or recovering it from an insecure backup.
- Plaintext copies, filesystem snapshots, page files, hibernation files, or application caches outside Vaero's control.
- A malicious or compromised authorized PGP private key, or the loss of every phrase/key path required by a policy.
- Coercion or compelled disclosure.
- Loss of the only artifact or corruption beyond configured recovery redundancy.

Cryptographic choices, format parsing, secret handling, and drive operations require external review before a “stable” or production-ready release.

## 13. Reliability and testing

- Unit tests for phrase encoding, format parsing, path validation, chunking, and every error boundary.
- Golden vectors for key derivation, headers, frame authentication, and all supported codecs.
- Property tests for round trips and deterministic modes.
- Coverage-guided fuzzing of every parser and decompressor.
- Fault-injection tests for cancellation, full disks, permission changes, truncated writes, and power-loss-like interruption.
- Cross-version compatibility fixtures retained permanently.
- Tests using Unicode, reserved Windows names, long paths, sparse files, ACLs, links, alternate streams, and case collisions.
- Corpus benchmarks with published hardware, settings, datasets, and reproducible scripts.
- Dependency auditing, signed releases, checksums, and a documented vulnerability-reporting process.
- Mandatory checksum/scrub tests covering virtual images, VCD bootstrap records, root manifests, interrupted transforms/commits, and unplug/power-loss simulations.

For every supported pipeline, the defining invariant is: verified extraction reproduces the selected source data and metadata according to the chosen policy, or fails without committing partial results.

## 14. Privacy and operational safety

- No telemetry or network access by default.
- Logs redact paths when requested and never contain phrases or derived keys.
- Crash reporting is opt-in and scrubbed of sensitive buffers and filenames.
- Plaintext output is never written before relevant authentication succeeds.
- Destination space is conservatively estimated, including worst-case format overhead.
- Restore defaults to a new directory and detects conflicts before writing.
- Source removal, if ever offered, is a separate post-verification command with prominent limitations about secure erasure.
- Release binaries should be reproducible where practical and code-signed for Windows.

## 15. Roadmap

### Phase 0 — specification and prototypes

- Freeze terminology, threat model, phrase encoding, and container invariants.
- Prototype streaming archive and encrypted-frame formats.
- Build representative compression and adversarial test corpora.
- Benchmark candidate maintained codec libraries.

### Phase 1 — secure file encryption

- Phrase generation and validation.
- Versioned `.crypt` reader/writer, mandatory checksum commitments, and phrase-only unlock.
- `encrypt`, `decrypt`, `verify`, and `inspect` commands.
- Golden vectors, fuzzing, and fault-injection harnesses.

### Phase 2 — directory archives

- Streaming `.vro` archive creation and safe extraction.
- Windows metadata policies and reparse-point handling.
- End-to-end encrypted directory workflow without plaintext intermediates.

### Phase 3 — Vortex compression

- `.vip` chunk format, index, store mode, and initial mature codecs.
- Adaptive selection, content-defined deduplication, profiles, and benchmarks.
- `pack` and `unpack` as the primary commands.

### Phase 4 — hardening and stable format

- Independent cryptographic and parser review.
- Recovery drills and compatibility testing across Windows versions.
- Stable v1 format declaration, documentation, signed releases, and migration policy.

### Phase 5 — drives and desktop experience

- Encrypted drive-backup workflow.
- Design and audit of mountable `.vro.vip.crypt` virtual devices.
- VCD provisioning, single-object filesystem lifecycle, in-place transform recovery, mandatory scrubbing, and unplug/power-loss recovery drills.
- PGP recipient slots and VCD unlock-policy review.
- GUI using `vaero-core`.
- Evaluate whole-volume encryption only after recovery and audit requirements are met.

## 16. Decisions still requiring design review

- Exact phrase word list, checksum, normalization, and language policy.
- Final AEAD, KDF defaults, frame size, nonce construction, and key hierarchy.
- Binary serialization format and rules for canonical encoding.
- Archive metadata defaults versus optional preservation modes.
- Initial Vortex codec set and the licensing implications of each dependency.
- Deduplication scope and memory/disk index limits for very large archives.
- Whether resilient parity frames belong in v1 or a later feature revision.
- Machine-automation secret input on Windows.
- Minimum supported Windows release and filesystem feature matrix.
- Requirements and architecture for a mountable encrypted virtual drive.
- The canonical `.vro` object taxonomy and which objects may be mounted versus extracted.
- VCD bootstrap layout, single-object filesystem encoding, transform staging/commit protocol, journal/recovery algorithm, supported removable-media matrix, and safe provisioning UX.
- Checksum/hash algorithm, Merkle/manifest commitment layout, scrub scheduling, and any future repair redundancy.
- OpenPGP profile, fingerprint canonicalization, CEK-slot construction, recipient-policy semantics, key rotation, expiry/revocation, and recovery guarantees.

## 17. Definition of a trustworthy v1

Vaero v1 is ready when it can archive, compress, encrypt, verify, decrypt, and safely restore large real-world directory trees through a bounded-memory streaming pipeline; when interrupted operations do not damage source data or commit unverified output; when old test vectors remain readable; when hostile-input fuzzing is routine; and when the cryptographic design and implementation have received independent review.

The goal is not merely a new set of file extensions. It is a durable, transparent format and tool that users can trust with the only copy of data—while strongly encouraging them never to keep only one copy.
