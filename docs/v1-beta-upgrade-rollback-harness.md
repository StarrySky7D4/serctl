# v1 beta whole-bundle upgrade and rollback harness

This harness is a local, fail-closed preparation gate for the
`v0.3.0-beta.2` to `v1.0.0-beta` compatibility window. It does not use a
normal user's vault, recovery medium, daemon descriptor, Grant, SSH profile or
remote host.

Run the framework self-test with:

```powershell
./scripts/Test-WholeBundleUpgradeRollbackHarness.ps1
```

The self-test creates synthetic, non-executable component fixtures under a
new temporary directory. Before exercising those fixtures it invokes two exact
offline Rust tests: `recovery::tests::whole_bundle_storage_direction_fixture`
and `vault::tests::audit_record_format_blocks_beta2_destructive_writer_before_callback`.
A source marker or function-name search is not accepted as evidence. The
harness requires each exact named test to appear once in its own one-test
libtest run; an exit-zero run with zero matching tests fails closed. Together
they verify the four-field predecessor read, current seed/marker preservation,
top-level vault and per-profile record v5 rejection before the beta-2
destructive writer callback, unchanged protected state, future-field rejection
before writeback and rejection of an initialized zero seed. The remaining
structural checks verify:

- CLI, daemon and helper identity plus SHA-256 are treated as one set, and each
  `--version` line must match its complete anchored component grammar rather
  than merely contain the expected version/protocol tokens;
- the predecessor is `v0.3.0-beta.2` / IPC v8 and the candidate is
  `v1.0.0-beta` / IPC v9;
- all six nontrivial mixed predecessor/candidate CLI, daemon and helper
  selections are rejected before activation, as are hash-only substitutions
  whose reported version/commit identity is otherwise unchanged;
- an active-bundle reference can be atomically switched and rolled back on
  the same filesystem;
- active-bundle references require strict UTF-8, a closed JSON schema and
  native JSON field types; duplicate or case-colliding keys, a string-valued
  schema version and invalid UTF-8 are rejected without changing the reference
  or either bundle;
- a cooperative concurrent reference change detected immediately before
  replacement is preserved rather than overwritten even when it selects the
  same semantic bundle with different bytes;
- a failure injected after replacement restores and byte-validates the exact
  previous reference only while the active reference remains the exact bytes
  installed by this writer; a post-replacement concurrent winner is preserved,
  predecessor recovery bytes remain available, and the terminal state is
  reported unknown rather than overwritten by rollback;
- synthetic persistent-state sentinels remain byte-for-byte unchanged; and
- the synthetic run reports `accepted=false` and `BLOCKED` rather than
  impersonating real upgrade evidence.

## Inspecting real candidate directories

Only use dedicated copies of complete, immutable component sets. Do not point
the harness at an installed directory, a shared daemon's directory, the known
mixed `target/release`, or `target/staging-v0.3/release`.

```powershell
./scripts/Invoke-WholeBundleUpgradeRollbackHarness.ps1 `
  -PredecessorDirectory C:\acceptance\v0.3.0-beta.2 `
  -CandidateDirectory C:\acceptance\v1.0.0-beta `
  -CandidateVersion 1.0.0-beta `
  -ReportPath C:\acceptance\reports\bundle-structure.json
```

The inspection first requires a clean source worktree and binds its full
`HEAD` to the common 12-hex embedded candidate commit. It then invokes the
same local offline storage-direction source fixture and each component's
`--version` entry point. Candidate CLI and daemon identities must contain the
exact embedded marker `vault-storage read=v4..=v5 write=v5`; the xfer helper
does not access vault storage and carries no such marker. The inspection
redirects common HOME, application-data, XDG and temporary paths to a new
isolated root, checks that version inspection produces no files there, records
component hashes, clean git identities and a complete flat-file inventory,
requires that inventory to remain byte-for-byte stable across version
inspection, exercises exhaustive mixed-set and hash-only rejection, and
simulates the atomic reference switch, concurrent-change rejection and
post-replacement rollback. It never starts a daemon. Repair candidates may pass a canonical
`1.0.0-beta.N` value to `-CandidateVersion`; the initial default is
`1.0.0-beta`.

The command deliberately exits nonzero after writing its create-new report.
The following gates remain `BLOCKED_NOT_RUN`:

- opening and operating on a byte-for-byte v0.3.0-beta.2 vault v4 fixture;
- an actual v4-to-v5 top-level vault plus per-profile encrypted-record upgrade
  and beta-2 outer-format rejection before any destructive writer mutation;
- actual v8 CLI/v9 daemon and v9 CLI/v8 daemon handshake rejection before a
  business frame;
- matched candidate-bundle activation followed by matched predecessor-bundle
  rollback activation;
- the exact four-field beta-2 KeyPackage schema rejecting current `audit_seed`
  bytes before writer entry, plus the downloaded beta-2 binary rejecting the
  v5 outer storage gates before its mutation-capable `grant-issue` can create
  output or mutate vault/recovery bytes; the probe records whether transient
  runtime activation was observed and separately requires terminal cleanup.
  The current reader likewise rejects future security fields before writer
  entry and before its daemon activation callback;
- actual helper mismatch rejection before transfer;
- descriptor ownership and daemon lifecycle;
- rejection of a predecessor runtime descriptor after candidate activation;
- rejection of every predecessor OperationGrant after candidate activation;
- restoring the exact pre-upgrade vault backup, matching recovery medium and
  preserved ACL/owner metadata as three separately recorded outcomes.

## Formal runtime mode and receipt

Formal mode is Windows x86_64 only and never operates on the supplied fixture
in place. The fixture directory has the fixed layout `home/.serctl/vault.json`
plus `recovery-media.srrec`; the harness rejects reparse points, copies that
tree under its private scratch root, records every file hash and SDDL, and
keeps a second private backup before starting either runtime. The profile name
is an explicit bounded argument and its passphrase is supplied only through
`SERCTL_PROFILE_PASSPHRASE`; it is never placed in argv, a report or receipt.

```powershell
./scripts/Invoke-WholeBundleUpgradeRollbackHarness.ps1 `
  -PredecessorDirectory C:\acceptance\v0.3.0-beta.2 `
  -CandidateDirectory C:\acceptance\v1.0.0-beta `
  -CandidateVersion 1.0.0-beta `
  -RuntimeFixtureDirectory C:\acceptance\disposable-beta2-fixture `
  -RuntimeProfileName FixtureProfile `
  -ReceiptPath C:\acceptance\receipts\whole_bundle_upgrade_rollback.evidence `
  -Tag v1.0.0-beta `
  -TagObject 0123456789abcdef0123456789abcdef01234567 `
  -Commit fedcba9876543210fedcba9876543210fedcba98 `
  -ReleaseManifestSha256 ('A' * 64) `
  -EvidenceOwner StarrySky7D4
```

The fixed in-process sequence opens the beta-2 fixture with the matched
predecessor, proves candidate-CLI/v8-daemon and predecessor-CLI/v9-daemon
rejection without changing the live descriptor, issues a least-scope
`daemon.status` Grant with the candidate to exercise the v4-to-v5 transition,
binds the descriptor PID/build/IPC identity, stops and restarts the candidate,
rejects the predecessor descriptor and pre-restart Grant, proves the beta-2
reader rejects upgraded storage through `grant-issue` while the candidate still
opens it. The harness freezes the upgraded vault and recovery-medium hashes
immediately around that rejection, requires the requested Grant to remain
absent, monitors whether `daemon.json` or `daemon.secret` is observed during
the command, and separately requires both artifacts to be absent after command
exit through a bounded 15-second cleanup wait. An observation value of `false`
means only “not observed”; it is never
treated as proof that the fixed predecessor did not transiently activate. The
harness then restores the exact backup and proves the predecessor can reopen
it. The final
tree hash and every ACL SDDL, including the recovery medium, must equal the
pre-upgrade snapshot. Any command timeout, cleanup uncertainty, descriptor or
Grant ambiguity, hash/ACL drift, or non-PASS gate prevents receipt creation.

The non-privileged self-test also exercises the rollback-set validator with
closed synthetic evidence. It rejects a set missing `recovery-media.srrec`, a
changed pre-upgrade vault hash, and changed SDDL owner/ACL metadata. This proves
that a binary-only or partial-storage rollback cannot satisfy the harness
contract; it does not substitute for the formal disposable-account runtime
run, whose gates remain `BLOCKED_NOT_RUN` until independently executed.
The self-test accepts both boolean values for the synthetic transient-runtime
observation, while rejecting a non-boolean observation or an unclean terminal
runtime state. It starts no serctl daemon.

Only that same process can wrap its in-memory result. There is no runtime
result JSON input. The closed receipt binds the exact predecessor/candidate
three-component hashes, full candidate daemon identity and SHA-256, descriptor
owner PID, tag object, commit and release-manifest hash. It is written with
create-new/no-share/write-through semantics, a protected owner/SYSTEM/
Administrators DACL, and a same-byte SHA-256 post-write check.
The closed details include boolean
`beta2_transient_runtime_activation_observed` and the required-true
`beta2_runtime_state_cleaned_after_rejection`; omitting either, replacing it
with a string, or reporting residual runtime state fails closed.

`Test-WholeBundleRuntimeReceiptContract.ps1` is a non-privileged structural
self-test. It proves parser and closed-schema wiring only; it cannot replace an
external run on a disposable beta-2 fixture with the exact downloaded bundles.

The authenticated-audit KeyPackage transition is a directional storage boundary: `audit_seed directionally incompatible`. The source fixture must prove that the strict predecessor reader rejects the upgraded canonical package before its writer callback and leaves the input bytes/hash unchanged; `unknown fields must not be dropped`. The independently observed beta-2 `grant-issue` failure `unknown field audit_seed` is consistent with that boundary, but the formal harness does not ingest an external log as release evidence. That KeyPackage-only proof is not enough: beta-2 `admin_reset_profile` can replace a profile without decoding KeyPackage. The candidate therefore reads both the top-level vault and per-profile encrypted record at v4 through v5 and writes both at v5. A successful candidate mutation advances the top-level version in the same protected atomic replacement; audit initialization also reseals the affected record as v5. The beta-2 validator must reject top-level v5 before the destructive writer callback is reachable and must independently reject record v5 if only that marker survives with a v4 top level; both synthetic inputs retain identical bytes and SHA-256 after rejection. The downloaded predecessor's mutation-capable runtime probe freezes the upgraded vault/recovery hashes and proves no Grant output, no storage mutation and no runtime state remaining after the command. The bounded monitor records a positive transient activation when it sees either runtime artifact; a negative observation plus final absence still does not prove that a predecessor daemon was never activated during the failed command. Once candidate initialization persists the new record/fields, `binary-only rollback is forbidden`. Formal rollback must restore an `exact pre-upgrade vault backup`, its matching recovery medium, and preserved ACL/owner metadata as one verified set.

The supported reader/writer matrix is deliberately asymmetric:

- the v1 candidate reads the four-field beta-2 KeyPackage, defaults the audit state to uninitialized, and does not change its canonical bytes merely by reading it;
- the v1 candidate reads and preserves the current nonzero `audit_seed` plus `audit_initialized` marker, including through the passphrase and recovery-envelope paths;
- the beta-2 reader must reject that current package. An error such as `unknown field audit_seed` from a matched beta-2 CLI/daemon against a v1-mutated vault is an expected fail-closed result, not permission to downgrade or delete the field;
- the v1 reader also rejects any later unknown KeyPackage field and rejects `audit_initialized=true` with a zero/missing audit seed before encryption or writeback. It must never deserialize a future security extension into a lossy predecessor structure.

Consequently, a runtime switch must select a matched candidate bundle before opening a v1-mutated vault. Replacing only CLI or daemon, or reusing a beta-2 process/descriptor/Grant, is outside the compatibility window and must fail before profile mutation. The harness must not “repair” a vault by projecting its KeyPackage onto the fields understood by an older binary.

The candidate `grant-issue` adds a separate local safety boundary: before reading a runtime descriptor or invoking its daemon launcher, the CLI uses the production strict reader plus the supplied profile passphrase to authenticate the exact stored profile. An incompatible or impossible KeyPackage therefore leaves the launcher callback at zero and creates neither Grant material nor vault output. After that preflight, the daemon independently unlocks the profile and the CLI verifies that its catalog id/generation still match the preflight result. The two KDFs have separate bounded deadlines; decrypted KeyPackage state is not transferred between processes. This candidate behavior does not retroactively change the downloaded beta-2 predecessor, whose runtime probe must still be described only by what its monitor actually observed.

The source fixture is not portable evidence between commits. Inspect mode fails before Cargo when the checkout is dirty or its full `HEAD` does not begin with the common embedded candidate commit. It also rejects a candidate CLI or daemon whose complete `--version` grammar omits or changes the storage marker; checking a source constant alone cannot establish what a downloaded binary implements.

Those gates require a disposable operating-system account with no real serctl
state, a provenance-verified predecessor fixture, and an independently
controlled runtime procedure. A synthetic bundle, a static hash comparison or
an isolated active-reference simulation is never sufficient release evidence.

## Side-effect boundary

The harness does not read file contents from a vault or recovery medium, start
or stop any daemon, create a runtime descriptor, use a Grant, or access a
remote host. It records identity lines, file lengths and SHA-256 only. Reports
use create-new semantics and are not written unless their parent already
exists.

Formal runtime mode proves that a mixed runtime pair fails before a business
frame in its isolated fixture. If a daemon shutdown, descriptor owner, IPC
terminal state or persisted schema is uncertain, it emits no receipt, preserves
the external source fixture untouched and keeps the gate blocked.

The active-reference simulation serializes and byte-rechecks cooperative writers;
it is not an operating-system compare-and-swap primitive and does not prove
resistance to an adversarial process that ignores the writer protocol in the
last instruction window. Its injected post-replacement race proves only that a
change visible before rollback is preserved; it cannot eliminate a later
instruction-window race. Runtime acceptance must therefore record descriptor
owner/PID/instance identity before and after the switch, prove the predecessor
descriptor and Grants cannot be reused, and retain the exact pre-upgrade
bundle, vault and recovery backup until rollback is independently verified.
