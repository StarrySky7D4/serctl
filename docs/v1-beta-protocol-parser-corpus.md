# v1 beta protocol parser mutation corpus

The v1 beta local gate runs deterministic, offline mutation corpora for
`serctl-transfer-protocol`, `serctl-remote-protocol`, and `serctl-policy`.
The corpus adds no network dependency and does not read a vault, start a
daemon, use SSH or access a remote helper.

The local-gate steps are:

```text
cargo test --locked -p serctl-transfer-protocol --lib
cargo test --locked -p serctl-remote-protocol --lib
cargo test --locked -p serctl-policy --lib
```

They run in Quick and full modes. The later serial workspace test repeats
them in the full gate.

## Covered rejection properties

The transfer corpus covers every non-empty truncation of one valid data frame,
bad magic, unknown version, unknown frame kind, reserved flags, `u32::MAX`
declared length, an undersized fixed data header, declared body lengths both
shorter and longer than the supplied bytes, an unknown JSON control kind and a
chunk SHA-256 bit flip. A stateful `DataSequenceValidator` separately rejects
transfer-id crossing, offset gaps, replays, invalid hashes and offset overflow
without advancing its accepted prefix.

The remote-helper corpus covers every truncation of one valid frame, bad
magic, unknown version and kind, reserved flags, global and kind-specific
length overflow, short/long declared bodies and trailing data. Its streaming
reader is also given a `u32::MAX` Start length; the test verifies rejection
after consuming only the fixed header. Stateful mutations cover sequence gaps,
sequence replay, stdout offset gaps and stdout replay. Existing receipt tests
verify that a different receipt byte string fails its SHA-256 binding while the
correct bytes can still be authenticated.

The policy corpus covers every truncation of a valid schema-v1 policy, an
invalid-UTF-8 mutation at every byte position, empty/scalar/array/trailing-token
documents, recursion-limit input, wrong scalar types, integer overflow,
top-level and nested unknown fields, and duplicate top-level or nested JSON
fields. Exactly 64 KiB of valid JSON plus trailing whitespace is accepted with
the same canonical digest; 64 KiB plus one byte is rejected before parsing.
All 5,040 permutations of the seven top-level fields compile to the same
ordered IR and SHA-256 digest. All permutations of a representative deny-only
rule set also compile identically, and replaying those rules is explicitly
idempotent. This does not make duplicate JSON object fields valid: serde's
duplicate-field rejection is part of the fail-closed schema boundary.

Policy documents are not a sequenced transport, so "replay" in this corpus
means repeated deny-only rules, while frame sequence replay remains covered by
the transfer and remote protocol validators. Rule ordering cannot grant
authority because schema-v1 rules only remove capabilities/programs or add
denied path prefixes; normalized sets make order and exact rule repetition
irrelevant to the resulting policy digest.

Every malformed mutation must return an error. The remote decoder and every
policy truncation/malformed mutation are run inside `catch_unwind`; any panic
fails the test. Transfer parsing uses finite in-memory async slices, so a panic
fails the async test and every mutation reaches an EOF rather than waiting on a
transport. Declared lengths are checked against `MAX_FRAME_BYTES`,
`MAX_CONTROL_BYTES`, `MAX_CHUNK_BYTES`, `MAX_FRAME_PAYLOAD` and per-kind limits
before payload allocation. Policy bytes are rejected above
`MAX_POLICY_DOCUMENT_BYTES` before `serde_json` is entered; collection and
string limits are then enforced by the canonical compiler/evaluator.

## Coverage-guided fuzzing boundary

`.github/workflows/parser-fuzz.yml` adds a separately bounded weekly/manual
Linux libFuzzer job for `transfer_protocol`, `remote_protocol`, and
`policy_json`. The formal tagged workflow also calls that same pinned workflow
as a reusable exact-tag gate, and both platform-bundle jobs depend on its
success; publication therefore cannot outrun fuzzing of the tagged source. It
pins the nightly toolchain and `cargo-fuzz`, uses an isolated locked fuzz
workspace, limits each run to 180 seconds and 2 GiB RSS, and caps inputs at
each production parser boundary (including one byte beyond the policy limit).
Failure artifacts are uploaded only after a regular-file, count, and per-file
size check. The policy target exercises both arbitrary bytes and a structurally
valid policy assembled from fuzz-derived program names, so mutations reach
beyond the JSON syntax layer.

`scripts/Test-ParserFuzzBoundary.ps1` and its mutation self-test enforce that
workflow envelope under PowerShell 7 and Windows PowerShell 5.1. Local builds
prove that the fuzz targets compile, but do not constitute a completed Linux
fuzz run. Exact-tag acceptance requires retained results from the reusable
tagged run; a scheduled/manual run at another ref, workflow definition,
verifier pass, or Windows build alone does not close the parser-fuzz checkbox.
Every native CI matrix row additionally resolves the independent fuzz
`Cargo.lock` with `cargo metadata --manifest-path fuzz/Cargo.toml --locked` and
runs the portable archive/download verifier self-test, preventing a Linux-only
workflow-source check from hiding Windows or macOS PowerShell/path behavior.

Neither the deterministic corpus nor bounded coverage-guided runs provide
exhaustive input coverage, allocator-failure testing, or a claim that arbitrary
future schemas are panic-free. They do not test a real russh channel, helper
process, filesystem commit, resume journal, receipt MAC implementation outside
the framing crate, daemon IPC or cross-platform process lifecycle.

`serctl-remote-protocol` remains source-only experimental and unshipped. Its
parser corpus is development evidence only; it does not make `serctl-remote`
part of the supported v1 beta runtime. Release acceptance still requires the
remaining exact-tag, cross-platform, real-host, transfer and upgrade/rollback
gates in [the acceptance matrix](v1-beta-acceptance-matrix.md).
