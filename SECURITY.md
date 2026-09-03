# Security policy

serctl handles encrypted SSH credentials and mediates remote side effects. Treat suspected credential disclosure, authorization bypass, unsafe overwrite, host-key bypass, IPC authentication failure, and forged completion evidence as security issues.

## Supported release lines

| Release line | Security support |
| --- | --- |
| `v1.0.0-beta.3` | Supported after its tagged acceptance workflow publishes the attested prerelease; fixes are delivered as a new immutable prerelease tag. |
| `v0.3.0-beta.2` | Rollback predecessor during the v1 beta compatibility window; critical fixes only until the v1 beta line is superseded. |
| Older test snapshots | Unsupported. They remain source-history evidence and must not receive moved or replacement tags. |

The v1 beta support window and rollback limits are defined in [the v1 beta release contract](docs/v1-beta-release-contract.md). A source branch, local build, CI run, or unsigned checksum file is not a supported release by itself.

## Reporting a vulnerability

Use the repository's GitHub **Security → Report a vulnerability** flow so details remain private. Include:

- the exact tag, full commit, operating systems and binary `--version` output;
- whether CLI, daemon and helper came from one attested release set;
- a minimal reproduction with secrets, hostnames, paths and personal data removed;
- the expected and observed authorization, overwrite, timeout or cleanup state;
- relevant hashes or attestation verification output, not credential or Grant-file contents.

Do not disclose an exploit, recovery medium, profile passphrase, SSH password, OperationGrant private key, vault ciphertext, runtime activation secret, or live host address in a public issue. If private vulnerability reporting is unavailable, open a public issue containing only a request for a private contact channel and no technical details.

## Response and disclosure

The maintainer will acknowledge a private report when available, reproduce it against a supported immutable tag, classify affected trust boundaries, and coordinate a fixed prerelease tag. No tag or published asset is replaced in place. A security fix receives a new SemVer prerelease identifier, new hashes, new SBOMs and new GitHub build-provenance attestations.

Reports that cross a documented non-goal—such as an already privileged administrator reading ordinary process memory—are still useful when the product or documentation overstates the boundary. They are not silently closed as impossible.

## Verification before use

Download all runtime files from the same GitHub prerelease. Verify the repository, tag and artifact provenance with GitHub's attestation tooling, then verify `SHA256SUMS`. The checksum manifest is meaningful only because it is itself included in the attested subject set.

Windows runtime bundles contain only the matched CLI and daemon. PDB files are separate debug artifacts. The only Linux runtime binary in v1 beta is `serctl-xfer`, with its debug symbols in a separate archive. `serctl-remote` and jobs crates are source-only experimental code: they remain in workspace quality checks but are neither published nor security-supported, and `job.*` is not an Agent/OperationGrant capability. Never combine a CLI, daemon or transfer helper from different releases, and never replace binaries while the daemon owns active sessions, transfers, tunnels or Grants.

## Beta limitations

Beta support does not claim protection from administrator/root debugging, process injection, keylogging, swap or hibernation capture, malicious firmware, or a fully compromised remote host. It also does not convert source-only platform checks into a supported binary distribution. Current supported artifact/platform boundaries are explicit in the release contract and acceptance matrix.

The presence of `serctl-remote`, jobs, or remote-protocol source code in the tagged workspace does not make those components a supported feature. Known security gaps require them to remain unshipped and unreachable from Agent/Grant operation kinds in v1 beta. Reports involving accidental packaging, publication, grant issuance or runtime exposure of `serctl-remote`/`job.*` are security issues.

The candidate authenticated local audit HMAC chain and checkpoint cover **OperationGrant root requests only**, not every CLI/UI/SSH operation. They can detect unkeyed modification, truncation, reordering, and unmatched Grant intents that survive across a daemon restart. `audit status` requires the profile passphrase and an exclusive profile lease, verifies the chain/checkpoint and an optional operator-supplied anchor, and can export only the current checkpoint to a create-new file. `audit resolve-unknown --acknowledge-unknown-outcome` first performs the same verification and then only appends exactly bound `Unknown` outcomes for authenticated pending Intents; it never infers remote success or failure.

Those manually exported external anchor files are not an independent monotonic external trust domain. serctl cannot prove that a file stayed offline or prevent an administrator from rolling back the log, checkpoint, and supplied anchor together to an internally consistent older snapshot. Therefore v1 beta must not claim a tamper-proof audit closure, complete-operation coverage, or cross-snapshot rollback detection. The beta acceptance owner must explicitly sign these limitations; a separately controlled monotonic anchor or remote transparency log remains a blocker for a stable 1.0 security claim. Treat any path that overwrites an anchor, resolves a pending Intent as success/failure, bypasses the exclusive profile lease/passphrase, or expands the ledger beyond its documented Grant-root scope without review as a security issue.
