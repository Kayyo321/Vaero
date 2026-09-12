# Phase 3 implementation plan: `.vip` / Vortex compression

> Audience: implementation agent working on `feat/vzip-vip-compression`.
>
> Status: execution plan, not a stabilized format specification. `PROJECT.md`
> explicitly leaves the initial codec set, binary serialization, deduplication
> bounds, and related format decisions open to design review. Do not turn an
> unreviewed suggestion in this plan into a compatibility promise.

## 1. Mission and non-negotiable outcome

Implement the Phase 3 compression system described in `PROJECT.md`: a `.vip`
(Vaero Image Package, “Vaero + zip”) wrapper around an arbitrary input stream,
eventually including content-defined chunking, bounded classification, a
time-bounded codec tournament, per-chunk codec selection, same-artifact
deduplication, seekable indexing, deterministic output, profiles, transactional
file operations, and the `compress`/`decompress` CLI commands. Prepare the
compression layer so later `pack`/`unpack` orchestration can stream
`.vro -> .vip -> .crypt` without plaintext temporary files.

The implementation is correct only when all of the following are true:

1. Decompression reproduces the exact original byte stream or fails without
   committing partial output.
2. Hostile `.vip` input cannot request unbounded allocation, CPU, recursion,
   output expansion, index growth, chunk count, reference depth, or codec
   parameters.
3. Unknown mandatory features and unknown codecs fail cleanly.
4. Incompressible data is stored when compression would exceed the approved
   bounded overhead.
5. A deterministic run over identical input and settings is byte-identical.
6. Output is staged beside the destination, flushed, independently verified,
   and only then committed. The source is never modified or deleted.
7. Every behavior and every defined failure branch is tested, and production
   code retains 100% line and region coverage.
8. `just verify` and `just audit` pass before handoff.

Do not claim that Vortex beats 7z, RAR, ZIP, or any other compressor in all
workloads. `PROJECT.md` permits only workload-and-metric-specific benchmark
claims.

## 2. Required reading and repository baseline

Before editing code, read these files completely in this order:

1. `AGENTS.md` — repository-wide security, testing, and delivery rules.
2. `PROJECT.md` §§1–3, 7–8, 10–17 — naming, Vortex behavior, pipeline, CLI,
   architecture, threat model, test requirements, roadmap, and unresolved
   decisions.
3. `WORKFLOW.md` — branch policy, CI gates, coverage, dependency review, and
   readiness definitions.
4. `docs/development.md` — supported local commands and Windows prerequisites.
5. `docs/dependencies.md` — required dependency documentation style.
6. `docs/formats/crypt-v1.md` — model for a format contract and failure
   taxonomy. Do not copy its magic, frame layout, or cryptographic semantics.
7. `crates/vaero-crypto/src/stream.rs` — existing bounded streaming style.
8. `crates/vaero-core/src/container.rs` — existing transactional staging,
   sync, verification, and commit behavior.
9. `crates/vaero-cli/src/lib.rs` and `crates/vaero-cli/tests/cli.rs` — current
   parser, stderr/stdout policy, stable exit codes, and integration-test style.

Then establish the exact starting state:

```powershell
git status --short --branch
git branch --show-current
git log --oneline --decorate -5
cargo metadata --no-deps --format-version 1
cargo test --workspace --all-features
```

Expected branch: `feat/vzip-vip-compression`. Preserve the untracked `Imgs/`
directory; it is user-owned and outside this work. If the branch is different,
stop and report it rather than silently switching. If baseline tests fail,
record the exact failure before changing anything and distinguish it from new
failures later.

Do not change the workspace version, create tags, publish releases, push to
`main`, or weaken any lint, test, coverage, audit, or branch-protection rule.

## 3. Scope boundaries

### 3.1 In scope

- A new `vaero-compress` crate containing pure format, chunking, codec,
  selection, deduplication, indexing, compression, decompression, inspection,
  and verification logic over `Read`/`Write`/`Seek`-style interfaces as needed.
- A draft `docs/formats/vip-v1.md` that is the exact implementation contract.
- Store mode first, followed by approved mature codecs.
- Content-defined chunking with explicit minimum, target, and maximum sizes.
- Bounded classification and codec trials.
- Profiles: `fast`, `balanced`, `small`, and `archive`.
- Same-artifact deduplication with bounded references and no reference chains.
- A seekable index and integrity checks for header, chunks, and index.
- Deterministic mode.
- Transactional `compress_file`, `decompress_file`, `verify_vip_file`, and
  `inspect_vip_file` orchestration in `vaero-core`.
- CLI `compress` and `decompress`; extend `verify` and `inspect` only after a
  reviewed detection design exists.
- Unit, property-style, integration, golden compatibility, fuzz-smoke,
  corruption, resource-bound, and fault-injection tests.
- Reproducible corpus benchmark tooling and documentation.
- Dependency and development documentation updates.

### 3.2 Not in scope for this branch unless separately approved

- `.vro` directory archive creation or extraction (Phase 2).
- `pack` and `unpack` directory commands. Their final pipeline depends on the
  archive layer, which is not present in the current repository.
- Encryption format changes. `.vip` is input to the existing `.crypt` layer;
  it is not encryption and must not handle phrases or keys.
- Cross-artifact deduplication, network dictionaries, or shared external
  stores.
- VCD/device transformations, mounting, parity/resilience frames, sparse-file
  semantics, delta families, or specialized executable/numeric transforms.
- Novel entropy coders or Vaero-specific codecs.
- Overwrite, source deletion, or “secure erase.”
- A stable v1 declaration. The format remains experimental until the review
  required by `PROJECT.md` §§12 and 17.

Treat “delta families,” “structured transforms,” “restore-first placement,”
and “resilience frames” as reserved follow-on features. The v1 feature-bit
design must permit future addition, but this implementation must not include
half-designed versions of them.

## 4. Mandatory design-review checkpoint

Do not begin production serialization or add codec dependencies until
`docs/formats/vip-v1.md` contains the decisions below and a human reviewer has
approved them. This is a hard gate because `PROJECT.md` §16 explicitly lists
these decisions as unresolved.

Create the draft using the following checklist. Every value must be numeric,
unambiguous, and justified by resource bounds or benchmark evidence:

- Unique 8-byte magic distinct from `VAEROCPT` and all other Vaero formats.
- Format version and rules for version rejection.
- Header length, field offsets, integer endianness, reserved-byte rules, and
  feature-bit semantics.
- Mandatory versus optional feature-bit ranges. Readers must reject an unknown
  mandatory bit; optional bits may be ignored only when the format explicitly
  explains why doing so is safe.
- Hash/checksum algorithm and domain-separated inputs for header, chunks,
  deduplication identifiers, index, and whole-stream commitment.
- Whether checks are corruption detection only. Never imply that an unencrypted
  `.vip` checksum provides authenticity against a malicious editor.
- Content-defined chunker algorithm, rolling window, seed/polynomial or gear
  table generation, minimum size, target size, maximum size, and exact boundary
  predicate.
- Maximum uncompressed chunk size and maximum encoded chunk size.
- Chunk-record layout for literal/store chunks, codec chunks, and duplicate
  references.
- Codec IDs, exact allowed parameter ranges, and the canonical parameter
  encoding for each approved codec.
- An explicit “store fallback” inequality including record overhead. Example
  shape: select compressed form only when its total encoded record is no larger
  than the literal record plus the approved maximum overhead. The approved
  document must replace this description with an exact formula.
- Profile-to-policy mapping for `fast`, `balanced`, `small`, and `archive`:
  candidate codecs, trial sample size, trial byte/time budget, memory ceiling,
  compression objective, and decompression-cost weight.
- Determinism requirements: fixed chunker seed/table, stable candidate order,
  integer scoring or precisely specified tie-breaking, no wall-clock-dependent
  output, stable index order, and canonical reserved bytes.
- Deduplication key, collision resolution, table memory bound, maximum entries,
  maximum reference distance, and the rule that a duplicate points directly to
  a materialized chunk rather than another duplicate.
- Index location and layout, chunk offsets, uncompressed ranges, encoded sizes,
  codec information, and integrity commitment.
- Whether the writer needs a seekable output to backpatch the header. Prefer a
  trailer/footer locator if streaming output is a requirement; explain the
  tradeoff explicitly.
- Maximum total decoded length, maximum chunk count, maximum index bytes,
  maximum allocation per record, maximum compression ratio, and overflow rules.
- Empty-input representation.
- Truncation, trailing-data, bad-checksum, bad-reference, unknown-codec,
  resource-limit, and underlying-I/O failure classifications.
- Inspection schema, including only non-secret metadata. Remember that `.vip`
  metadata is expected to be inside `.crypt` in the normal private pipeline.
- Golden-fixture policy while experimental and after stabilization.

For the initial mature codec set, prepare a short decision table rather than
guessing. At minimum compare:

| Role | Required property | Evaluation questions |
| --- | --- | --- |
| Store | No compression | Is it zero-copy or one bounded copy? What is exact overhead? |
| Fast LZ-family | High throughput | Is the Rust API maintained, memory-bounded, license-compatible, fuzzed, and deterministic? |
| High-ratio mode | Better ratio | Is decompression bounded? Can decoder parameters be attacker-controlled? Is native code introduced? |

For each candidate record maintenance status, audit history, license, source,
Rust-version compatibility, pure-Rust/native build implications on Windows,
streaming/block API suitability, dictionary behavior, maximum decoded-size
handling, and benchmark results. Add only the smallest approved set. Record the
chosen versions through `Cargo.lock`, not by vague prose. Run `cargo deny` and
`cargo audit` immediately after the dependency change.

## 5. Target architecture and dependency direction

Add this workspace member:

```text
crates/vaero-compress/
  Cargo.toml
  src/
    lib.rs          public types and re-exports only
    limits.rs       all reader/writer bounds and checked conversions
    format.rs       magic, version, header/record/index encoding and parsing
    chunker.rs      content-defined boundary state machine
    checksum.rs     approved unkeyed integrity/content identifiers
    codec/
      mod.rs        CodecId and sealed dispatch
      store.rs      mandatory baseline codec
      <approved>.rs one module per reviewed external codec
    classify.rs     bounded sampling and data-family hints
    select.rs       profiles, trials, scoring, and deterministic tie-breaking
    dedupe.rs       bounded writer table and validated reader references
    writer.rs       streaming package writer and index construction
    reader.rs       hostile-input parser, sequential decode, seek/index access
    inspect.rs      public metadata summary without decoding output
  tests/
    golden.rs
    round_trip.rs
    corruption.rs
    limits.rs
    deterministic.rs
    fixtures/
      README.md
      empty-v1.vip
      mixed-v1.vip
```

Keep dependencies one-way:

```text
vaero-cli -> vaero-core -> vaero-compress
                         -> vaero-crypto
```

`vaero-compress` must not depend on `vaero-core`, `vaero-cli`, or
`vaero-crypto`. It must not access the filesystem, prompt, print, inspect the
terminal, read environment variables, spawn processes, or silently create
temporary files. Its public API consumes caller-provided streams and explicit
options/limits.

Do not create a generic `vaero-format` crate merely to satisfy the future
architecture diagram. Create it only if both the `.crypt` and `.vip` formats
have genuinely shared, format-neutral primitives and the refactor is separately
reviewed. Avoid destabilizing the working Phase 1 crypto implementation.

## 6. Public API to design before implementation

Write compile-checked API sketches in `docs/formats/vip-v1.md`, then implement
them with useful rustdoc. Names may change during review, but responsibilities
must remain separate. A suitable shape is:

```rust
pub enum Profile { Fast, Balanced, Small, Archive }
pub struct Limits { /* private or validated fields */ }
pub struct CompressOptions {
    pub profile: Profile,
    pub deterministic: bool,
    pub limits: Limits,
}
pub struct PackageInfo { /* version, features, lengths, chunk/index facts */ }
pub struct StreamSummary { /* input/output bytes, chunks, stored/compressed/ref counts */ }

pub enum FormatError {
    Magic,
    Version(u16),
    UnknownMandatoryFeatures(u64),
    Truncated,
    TrailingData,
    HeaderChecksum,
    RecordKind(u8),
    Codec(u16),
    CodecParameters,
    ChunkLength,
    ChunkChecksum,
    Reference,
    Index,
    Commitment,
    Limit(LimitKind),
}
pub enum Error { Io(std::io::Error), Format(FormatError), Codec(CodecError) }

pub fn compress_stream(...);
pub fn decompress_stream(...);
pub fn verify_stream(...);
pub fn inspect_stream(...);
```

Requirements for the real API:

- `Limits` defaults are documented and validated. Tests can construct smaller
  limits without changing production defaults.
- Public APIs have rustdoc plus `# Errors`; add `# Panics` only where a panic is
  real and intentional. Production input must not trigger panics.
- Error variants carry only safe facts. Do not embed complete data chunks,
  paths, or unbounded external-codec strings.
- Use checked `u64`/`usize` conversions. A 32-bit-host conversion failure must
  be a clean limit/format error even though Windows x86_64 is authoritative.
- Keep writer options separate from reader security limits. A package does not
  get to raise the reader’s safety ceiling merely by declaring large values.
- The reader validates inexpensive fixed-size header facts before allocating,
  reading large buffers, initializing a codec, or following a reference.

## 7. Implementation sequence

Follow the stages exactly. Keep the workspace building and tests green after
each stage. Do not implement several unverified layers in one large edit.

### Stage 0 — baseline and format proposal

1. Capture baseline commands and results in the pull-request notes.
2. Add `docs/formats/vip-v1.md` with the full checklist from §4.
3. Add an explicit experimental/unreviewed warning matching the spirit of
   `docs/formats/crypt-v1.md`.
4. State that filenames are hints; magic/version determine the actual format.
5. State that checksums detect accidental corruption, not malicious tampering.
6. State that decompression may release verified chunks to a streaming caller,
   but file-level orchestration never commits partial output.
7. Obtain human approval for the wire layout, checksum, chunker, exact limits,
   codec set, and dependency choices.

Exit condition: the format document is complete enough that two independent
implementers would emit byte-identical store-only packages.

### Stage 1 — crate skeleton, limits, and errors

1. Add `crates/vaero-compress` to workspace `members`.
2. In its manifest, inherit workspace version, edition, license, repository,
   Rust version, and lints exactly as the existing crates do.
3. Add no external codec yet.
4. Implement `Profile` parsing/display without CLI coupling.
5. Implement `Limits`, defaults, validation, checked addition/multiplication,
   `u64 -> usize` conversion, chunk-count accounting, and decoded-byte budget.
6. Implement exhaustive, stable `Display` and `source()` behavior for errors.
7. Unit-test every valid boundary and the values immediately below/above it.
8. Add fuzz-smoke tests for arbitrary limit values and arithmetic overflow.

Exit condition: the new crate compiles under workspace lints and all production
branches in this stage are covered.

### Stage 2 — canonical format primitives

1. Implement fixed-size header encoding into a zero-initialized byte array.
2. Implement header parsing from an exact-size array.
3. Reject bad magic, version, required feature bits, nonzero reserved bytes,
   invalid declared limits, invalid offsets, and checksum mismatch.
4. Define typed record headers. Never let raw numeric values leak throughout
   reader/writer code.
5. Implement canonical little-endian helpers locally unless an approved small
   dependency is clearly safer.
6. Implement checksum/content-ID helpers with explicit domain tags so the same
   bytes in different structural roles cannot be confused.
7. Implement index entry encoding/parsing and whole-index commitment.
8. Use `checked_add`, `checked_mul`, and bounded range checks before slicing.
9. Test every byte offset, every enum value, reserved bits, truncated prefixes,
   oversized declarations, offset overflow, and trailing bytes.

Exit condition: byte-level unit tests fully specify the canonical encoding and
arbitrary input cannot panic the parser.

### Stage 3 — store-only writer and reader

1. Implement fixed-size chunking temporarily using the approved maximum chunk
   size; do not mix CDC debugging into the first end-to-end format path.
2. Emit only materialized store records.
3. Track input length, encoded length, chunk count, and whole-stream commitment
   with checked arithmetic.
4. Build the index in a bounded structure. Refuse input that would exceed the
   configured chunk/index budget.
5. Finalize the index/footer and any header locator exactly as specified.
6. Implement sequential decompression with one bounded chunk buffer.
7. Verify each chunk checksum before writing its bytes to the caller.
8. Verify final length, index commitment, whole-stream commitment, required
   final marker, and EOF/trailing-data rule.
9. Implement `verify_stream` through the same parser/decoder while discarding
   decoded output. Do not create a second, weaker validation path.
10. Implement `inspect_stream` to validate the fixed public structure and
    report safe metadata without allocating based on untrusted large fields.

Tests must include empty input, one byte, exact boundary, boundary ±1, many
chunks, zero bytes, all byte values, short reads, interrupted writes, malformed
record kinds, chunk checksum corruption, index corruption, commitment mismatch,
truncation at every structural boundary, and trailing data.

Exit condition: store-only round trips and corruption tests pass with bounded
memory and 100% coverage.

### Stage 4 — content-defined chunking

1. Implement the approved rolling fingerprint as a pure state machine.
2. Reset state exactly where the format specifies; do not infer reset behavior.
3. Force a boundary at maximum size, never before minimum size, and use the
   exact target-boundary predicate between them.
4. Emit the final nonempty chunk at EOF; define empty input separately.
5. Never retain the whole input. Keep only rolling state plus one maximum-size
   chunk buffer.
6. Replace the temporary fixed chunker in the writer.

Required tests:

- Golden boundary offsets for fixed byte sequences.
- Minimum/target/maximum boundaries.
- Empty and tiny streams.
- One-byte-at-a-time reads versus large reads produce identical boundaries.
- Inserting bytes near the start preserves most downstream boundaries.
- Determinism across repeated runs.
- Chunk sizes never violate bounds.
- Very long constant and adversarial patterns terminate and remain bounded.

Exit condition: CDC behavior is a compatibility contract with golden boundary
vectors, not an implementation accident.

### Stage 5 — codec abstraction and store fallback

1. Define a closed `CodecId` mapping exactly matching the format document.
2. Define a small internal codec interface operating on one bounded chunk.
3. The decoder receives the declared decoded length and a strict output cap.
4. Add one approved codec dependency at a time.
5. For each dependency, update workspace dependencies, the crate manifest,
   `Cargo.lock`, and `docs/dependencies.md` in the same commit.
6. Wrap external errors into bounded Vaero errors.
7. Reject unsupported parameters before calling external decoder code.
8. Confirm the decoder cannot emit beyond the declared chunk size. If its API
   cannot enforce this directly, decode through a bounded writer that stops at
   the cap and returns an error.
9. Compare total encoded record sizes, including headers and parameters, before
   choosing compression. Apply the exact do-no-harm inequality.
10. Store the original bytes whenever compression loses, ties according to the
    approved tie rule, times out according to deterministic policy, or exceeds
    memory/output bounds.

For every codec add golden decode vectors, random and structured round trips,
invalid parameter tests, truncated/corrupt stream tests, declared-size lies,
decoder output-cap tests, and fuzz-smoke coverage.

Exit condition: each codec is independently safe, bounded, documented, audited,
and never required to decode a store-only package.

### Stage 6 — classification and deterministic codec tournament

1. Read at most the approved sample bytes from the already-buffered chunk.
2. Compute only bounded features: estimated entropy, byte histogram facts,
   UTF-8 validity/printability, simple repetition/run signals, and well-defined
   signatures for already-compressed/encrypted formats if approved.
3. Classification is a hint, never a parser and never a trust decision.
4. Map each profile and class to a fixed ordered list of codec trials.
5. Enforce trial byte, memory, and work budgets. Never allow artifact fields to
   expand these writer-side budgets.
6. Score ratio, compression work, decompression cost, and memory using the
   reviewed formula.
7. Use deterministic integer scores and stable tie-breakers in deterministic
   mode. Wall-clock timing may inform benchmark reports but must not change
   deterministic bytes.
8. For non-deterministic optimized mode, if wall-clock trial limits are used,
   define exactly how cancellation falls back safely to store.
9. Record only the chosen codec/parameters, never classifier-private data unless
   the format explicitly requires it.

Test representative text/source, executable-like bytes, numeric patterns,
photos/video-like incompressible bytes, encrypted/random bytes, tiny chunks,
malformed UTF-8, and adversarial classifier samples. Assert the do-no-harm rule
as an encoded-size property, not merely “store was usually chosen.”

Exit condition: profiles produce valid packages, deterministic mode is exactly
repeatable, and no profile bypasses reader limits.

### Stage 7 — bounded same-artifact deduplication

1. Hash each uncompressed chunk with the approved content-ID domain.
2. Keep a bounded map from content ID to a materialized chunk’s index/offset,
   decoded length, and enough collision-check data to prove equality.
3. Treat a hash match as a candidate, not proof of equality. Perform the exact
   collision-resolution comparison specified in the format design.
4. Emit a duplicate-reference record only after equality is established.
5. Point references directly to materialized data. Never create reference
   chains or cycles.
6. Reject forward references, self-references, out-of-range targets, mismatched
   decoded lengths, excessive reference distance, and references forbidden by
   the configured limits.
7. When the table reaches its memory/entry bound, use the documented eviction
   rule. Eviction affects compression ratio only, never correctness.
8. Preserve deterministic eviction and output ordering in deterministic mode.
9. Decoder memory must remain bounded. If random access is required to replay a
   prior chunk, require a seekable source or use an explicitly bounded cache;
   do not silently retain every decoded chunk.

Test adjacent duplicates, distant duplicates, duplicates after insertion,
forced content-ID collisions through a test-only hasher, table eviction,
forward/self/cyclic references, reference to another reference, length mismatch,
out-of-range offsets, and seek/read failures.

Exit condition: deduplication never changes decoded bytes and hostile references
cannot cause recursion, unbounded seeks, or unbounded storage.

### Stage 8 — index and random access

1. Validate the entire index envelope and commitment before trusting entries.
2. Validate monotonic encoded offsets and decoded ranges with checked math.
3. Ensure every indexed record stays within the data region and no two records
   overlap unless the format explicitly allows it.
4. Ensure index count equals the actual record count.
5. Implement lookup from decoded byte range to chunk entry.
6. Implement bounded random-access decode of one chunk/range.
7. For duplicate targets, apply the same direct-reference and checksum rules as
   sequential decoding.
8. Never treat random access as weaker verification. At minimum validate the
   header, index commitment, selected record, selected decoded checksum, and
   all referenced materialized records.

Test first/last chunk, exact boundaries, cross-chunk range, empty range, range
past EOF, forged offsets, overlapping entries, unsorted entries, duplicate
decoded ranges, count mismatch, and corrupted unselected/selected records under
the documented shallow/deep verification semantics.

Exit condition: index-based access is bounded and agrees byte-for-byte with a
full sequential decode.

### Stage 9 — transactional file orchestration in `vaero-core`

Refactor the existing staging mechanics only if necessary, without weakening
Phase 1 behavior. Prefer a small private reusable transaction helper over copied
commit logic. Preserve these semantics:

1. Refuse an existing destination before creating a temporary.
2. Create a random, clearly named temporary sibling with `create_new`.
3. Open the source read-only and never modify it.
4. Compress/decompress into the temporary.
5. Flush and `sync_all` the temporary.
6. Rewind and independently verify compressed output before committing it.
7. For decompression, do not commit until the complete input, index, chunk
   checks, and commitment validate.
8. Close the temporary before rename.
9. Atomically rename beside the destination where Windows permits.
10. On any read, write, sync, rewind, verify, close/rename, cancellation, or
    codec failure, best-effort remove the temporary and leave the destination
    absent.
11. Never overwrite and never delete the source.

Add public functions resembling:

```rust
pub fn compress_file(source: &Path, destination: &Path,
                     options: &CompressOptions) -> Result<StreamSummary, Error>;
pub fn decompress_file(source: &Path, destination: &Path,
                       limits: &Limits) -> Result<StreamSummary, Error>;
pub fn verify_vip_file(source: &Path, limits: &Limits,
                       deep: bool) -> Result<StreamSummary, Error>;
pub fn inspect_vip_file(source: &Path,
                        limits: &Limits) -> Result<PackageInfo, Error>;
```

Extend `vaero-core::Error` with explicit compression format/codec/limit
classifications. Do not collapse corrupt input into generic I/O. Decide and
document whether a resource limit maps to the existing format code or a new
stable capacity/resource exit code before changing CLI behavior.

Use injectable stage/read/write/rename failures in unit tests, as
`container.rs` already does. Verify cleanup for every failure point.

Exit condition: file operations are transactionally safe and Phase 1 encryption
tests still pass unchanged.

### Stage 10 — CLI commands

Extend the typed parser; do not perform filesystem work during parsing. Add:

```text
vaero compress <input> [-o <file>] [--profile fast|balanced|small|archive]
                       [--deterministic]
vaero decompress <input> [-o <file>]
```

Default behavior:

- `compress` profile is `balanced`.
- `compress` output appends `.vip` unless `-o` is supplied.
- `decompress` strips only a final `.vip`; otherwise it requires `-o`.
- Existing destinations are refused.
- Human status/errors go to stderr.
- Successful `compress`/`decompress` produces no unversioned machine output on
  stdout.
- No filename suffix is trusted for parsing; the reader validates magic.

Parser work checklist:

1. Add typed `CompressArgs` and `DecompressArgs` and new `Command` variants.
2. Add `Opt::Profile` and `Opt::Deterministic` with per-command allowlists.
3. Reject duplicate flags/options and missing/invalid profile values.
4. Reject compression options on every other command.
5. Update `USAGE` completely, including default outputs and profiles.
6. Add default-output helpers with Windows/non-UTF-8-safe `OsString` handling.
7. Map every new core error to a stable documented exit code.
8. Add unit tests for every parser branch and error message.
9. Add executable integration tests for round trip, defaults, explicit output,
   each profile, deterministic equality, incompressible input, wrong magic,
   corruption, truncation, missing source, existing destination, and absence of
   partial files.

Do not add `pack`/`unpack` yet. Update `PROJECT.md` only if the approved CLI
contract intentionally differs from its proposal; never silently diverge.

Exit condition: CLI behavior is documented, stable, tested end to end, and does
not regress phrase secrecy or `.crypt` commands.

### Stage 11 — layer composition preparation

The current Phase 1 stream APIs already accept `Read`/`Write`. Ensure the new
compression APIs do the same so later orchestration can compose them:

```text
.vro reader -> vip compressor -> crypt encryptor -> staged destination
staged crypt reader -> authenticated decryptor -> vip decoder -> archive reader
```

Do not implement an unbounded in-memory `Vec` bridge. If current synchronous
interfaces cannot directly pipe producer to consumer, document and implement a
bounded producer/consumer adapter only after analyzing cancellation, error
propagation, deadlock, thread cleanup, and backpressure. A plaintext `.vip`
temporary is acceptable for the standalone `compress` command because that is
the requested output, but the future `pack` pipeline must not create an
unannounced plaintext `.vro` or `.vip` staging file.

Add an in-memory bounded integration test that composes compression output into
the existing encryption stream and reverses it, without changing `.crypt` v1.
Use only small test data and test KDF settings. Confirm the final bytes match,
and failures at either layer propagate without reporting success.

Exit condition: API design does not block the future safe pipeline.

### Stage 12 — benchmarks and corpus discipline

Add a reproducible benchmark command or example only after correctness is
complete. The benchmark must report, per corpus and profile:

- Original bytes and encoded bytes.
- Compression ratio and bounded overhead.
- Compression and decompression wall time.
- Throughput.
- Peak memory or a clearly documented proxy.
- Chunk counts by store/codec/reference.
- Random-access latency.
- Verification time.
- Behavior when one record and the index are corrupted.

Use corpora representing source code/text, office documents, photos, video,
virtual-machine images, databases, already-compressed/encrypted bytes, repeated
files/chunks, and mixed directories. Do not commit large corpora implicitly.
If a fetch script is added, it must pin each source and cryptographic hash,
verify downloads, place data outside Git, and document licensing. Never depend
on a developer-specific path.

Record CPU, memory, OS, toolchain, dependency versions, corpus version/hashes,
command, and whether caches were warm. Benchmark results must separate metrics;
never reduce them to an unconditional “better compressor” statement.

Exit condition: another Windows developer can reproduce the benchmark setup and
understand every claim.

## 8. Required test matrix

Implement at least the following. Each row needs a positive assertion and, for
failure cases, proof that no committed destination or leaked partial remains.

| Area | Required cases |
| --- | --- |
| Format header | empty/truncated; every bad magic byte; unknown version; unknown required feature; optional-feature rule; reserved bytes; bad checksum; extreme offsets |
| Arithmetic | every limit boundary; `u64` overflow; `usize` conversion; chunk-count/index-size overflow; decoded total overflow |
| Chunker | empty; 1 byte; min/target/max; boundary ±1; short reads; inserted prefix; constant/adversarial/random data; golden offsets |
| Store codec | every byte value; empty policy; max chunk; short writer; declared length mismatch |
| Each external codec | golden vector; levels/params; corrupt/truncated payload; decompression bomb attempt; output cap; external error mapping |
| Selection | every profile/class; store wins; each codec wins; ties; deterministic tie; budget exhaustion; do-no-harm encoded size |
| Deduplication | adjacent/distant repeats; collision; eviction; forward/self/cyclic/chained/bad target; seek failure |
| Index | zero/one/many entries; first/last/range; bad count/order/offset/overlap/commitment; selected-record corruption |
| Streaming | one-byte reads/writes; interrupted reader/writer at every call site; no whole-input buffering; exact EOF and trailing data |
| File transaction | source absent; destination exists; temp collision; sync/rewind/verify/rename failure; cleanup; source preservation |
| CLI | help; every option; duplicates; missing values; invalid UTF-8 option; non-UTF-8 paths; stdout/stderr; exit codes; defaults |
| Composition | vip round trip; vip inside crypt; corrupt vip after valid decrypt; crypto failure before vip; bounded adapter cancellation |
| Compatibility | committed golden empty/mixed fixtures; deterministic byte equality; old fixtures remain readable after later changes |

Property-style tests must assert:

```text
decompress(compress(bytes, options)) == bytes
verify(compress(bytes, options)) succeeds
compress(bytes, deterministic_options) is byte-identical across runs
decoded_length never exceeds configured limits
encoded_store_or_selected_size obeys the do-no-harm formula
mutating structural bytes never causes a panic or silent success
```

Fuzz-smoke test names must contain `fuzz_smoke` so the existing
`just test-fuzz-smoke` target runs them. Full coverage-guided fuzz targets are
required for the header/index parser, record parser, each decompressor, and
reference validator; bounded smoke tests remain part of ordinary CI.

## 9. Documentation updates required with code

Update all affected documentation in the same branch:

- `docs/formats/vip-v1.md`: authoritative experimental format/API contract.
- `PROJECT.md`: only approved clarifications or deliberate command/architecture
  changes; preserve the overall Phase 3 direction.
- `docs/dependencies.md`: every new direct production dependency, version,
  source, license, role, audit evidence, and update procedure.
- `docs/development.md`: focused test commands, fixture regeneration policy,
  benchmark commands, corpus setup, and any approved coverage exclusions.
- `README.md`: only user-visible commands that are actually implemented.
- `docs/release-notes/v0.0.1.md`: concise experimental feature and limitation
  notes if the project intends this work in 0.0.1. Do not change version numbers.
- CLI `USAGE`: must match behavior exactly.

Clearly label `.vip` experimental/unreviewed. State that pre-release artifacts
may become unreadable. State that `.vip` alone is not encrypted and can expose
sizes/compression structure; the normal private chain places it inside
`.crypt`. State that resilience/parity, delta families, archive packing, and
devices are not implemented if they remain absent.

## 10. Commit and review sequence

Use small, reviewable commits. A recommended sequence is:

1. `docs: specify experimental vip v1 format`
2. `feat(compress): add bounded vip format primitives`
3. `feat(compress): implement store-only vip streams`
4. `feat(compress): add content-defined chunking`
5. `build: add reviewed vip codec dependencies`
6. `feat(compress): add adaptive codec selection and profiles`
7. `feat(compress): add bounded same-package deduplication`
8. `feat(compress): validate vip index and random access`
9. `feat(core): add transactional vip file operations`
10. `feat(cli): add compress and decompress commands`
11. `test: add vip compatibility fuzz and fault coverage`
12. `docs: document vip usage dependencies and benchmarks`

Run the narrowest affected test after every edit. Run at least these at the end
of each logical commit:

```powershell
cargo fmt --all -- --check
cargo clippy -p vaero-compress --all-targets --all-features -- -D warnings
cargo test -p vaero-compress --all-features
```

After core integration, add `cargo test -p vaero-core`; after CLI integration,
add `cargo test -p vaero-cli`. Do not commit generated coverage output or build
artifacts.

## 11. Final verification and handoff

Before saying the work is complete:

```powershell
git diff --check
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
just test-fuzz-smoke
just coverage
just verify
just audit
git status --short --branch
```

`just verify` already repeats several commands; run it anyway because it is the
repository’s official pull-request gate. `just audit` is separately mandatory
under `AGENTS.md`. If tools are missing, use the documented bootstrap command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/bootstrap.ps1 -InstallTools
```

Do not weaken a gate to make it pass. Fix the code/test, or report the exact
unavailable tool and reason. Coverage must remain 100% line and region coverage
for production code. Any exclusion requires human review and an exact entry in
`docs/development.md`; there are currently no exclusions.

The final handoff must include:

- Every changed file grouped by crate/documentation purpose.
- The approved format choices and which choices remain experimental.
- Every production dependency added, its license, and audit outcome.
- Commands run and exact pass/fail results.
- Coverage line and region percentages.
- Golden fixtures added and their regeneration rule.
- Benchmark environment and results, without universal claims.
- Security-relevant bounds and failure behavior.
- Confirmation that Phase 1 `.crypt` behavior and fixtures still pass.
- Confirmation that source files are preserved, destinations are not
  overwritten, and partial files are not committed.
- Known limitations and deferred Phase 2/3/5 items.
- Any remaining review risks blocking a stable format declaration.

Open a reviewed pull request from `feat/vzip-vip-compression` to `devel` only
after the local gates pass. Do not merge it directly, do not target `main`, and
do not create a release or tag. A change is ready for `devel` only when it is
reviewed and the same logical checks pass in GitHub Actions, exactly as required
by `WORKFLOW.md`.

## 12. Stop conditions: do not improvise

Stop and request human direction if any of these occurs:

- The wire layout, checksum/hash, CDC algorithm/constants, codec set, or limits
  have not been approved.
- A desired codec cannot enforce bounded decompression or has unacceptable
  licensing/audit/build implications.
- Streaming requires plaintext temporary storage that would contradict the
  disclosure and cleanup rules in `PROJECT.md`.
- Random access and deduplication cannot both be implemented without unbounded
  memory under the approved layout.
- A change would alter `.crypt` v1 bytes, phrase handling, authentication order,
  or plaintext-release semantics.
- A test requires following links/reparse points, overwriting a destination,
  deleting source data, or using a machine-specific path.
- The implementation would need `unsafe`, a global lint relaxation, a coverage
  exclusion, a version bump, or a new release action.
- `PROJECT.md`, `WORKFLOW.md`, the format document, and executable behavior
  disagree in a security- or compatibility-relevant way.

When stopping, report the exact conflicting requirements, the smallest set of
viable choices, and the security/compatibility tradeoff of each. Never conceal
an unresolved decision behind a default or an undocumented constant.
