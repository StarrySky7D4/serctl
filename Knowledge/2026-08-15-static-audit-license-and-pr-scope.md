# Static Audit — License Extraction and Accumulated PR Scope

- Repository: `StarrySky7D4/serctl`
- Original pull request: #1
- Original source: `codex/add-apache-2-license`
- Target: `main`
- Reviewed target base: `9a128c39f4c5f41790dd820711d68bf7ccfad3df`
- License-only commit: `9fa2a3463e6af59454af497610dd397e372ed211`
- Accumulated candidate head: `94fb37118f4b31ab997f40cdba09d105081bde18`
- Review date: 2026-08-15
- Review mode: static commit/source/scope review only; GitHub Actions were not invoked or used as a merge condition.

## Scope finding

PR #1 is titled `License serctl under Apache-2.0` and its body describes four small licensing/documentation edits. Its current branch actually contains six commits and changes 16 files by approximately 21,341 additions and 2,808 deletions.

Only the first commit matches the advertised scope. The five later commits add or alter:

- IPC framing, transfers, deadlines, cancellation, and response semantics;
- SSH/SFTP execution and resource handling;
- daemon lifecycle, locking, and platform behavior;
- vault storage, credentials, file permissions, and security ownership checks;
- terminal/desktop UI state and late-result handling;
- end-to-end tests;
- almost one thousand added lines in `build.rs` for Git provenance and dirty-state inspection;
- dependency features and release-size configuration;
- a large architecture/security HTML report and pre-commit artifact evidence.

The PR body still reports 30 tests, while the accumulated branch documentation reports a later 205/205 baseline and dirty pre-commit binary identities. The title, description, validation statement, and actual risk surface therefore no longer agree.

## License-only review

The isolated first commit:

- adds the canonical Apache License 2.0 text;
- sets Cargo SPDX metadata to `Apache-2.0`;
- records the repository URL;
- links the license from README and the architecture/security guide.

The added `LICENSE` content is byte-equivalent to GitHub's Apache-2.0 template after newline normalization. The SPDX identifier and repository metadata are consistent. No implementation behavior changes in this commit.

## Blocking assessment for the accumulated branch

The remaining five commits are **not approved for merge as one pull request**:

1. The change is too broad for its title and review narrative; security, protocol, persistence, UI, build provenance, and release policy cannot share one license review boundary.
2. The largest files after the change are `src/client.rs` (~5,799 lines), `src/ui.rs` (~3,853), `src/daemon.rs` (~2,857), and `src/ssh.rs` (~2,405). This concentration makes subsystem invariants difficult to review independently.
3. Test/build/audit claims embedded in documentation refer to multiple dirty or historical worktrees and an offline RustSec snapshot. They are useful historical evidence but do not identify one clean, current merge candidate.
4. The branch changes authentication/ownership, credential storage, cancellation, remote process/file operations, and IPC outcomes. A static summary is insufficient to approve those security boundaries without narrowed diffs and explicit per-slice invariants.
5. Release-size optimization and provenance logic should not obscure functional/security changes or reuse their validation statement.

## Required split before further merge

At minimum, restage the remaining work into reviewable changes with current descriptions and clean heads:

1. IPC/client/daemon/SSH transfer semantics plus focused protocol and cancellation tests.
2. Vault, credential, permission, and Windows/Unix ownership hardening.
3. UI/terminal lifecycle and late-result behavior.
4. `build.rs` provenance/dirty detection with its standalone fixtures.
5. Dependency/release-profile optimization and documentation evidence.

Each change must state its exact baseline, files, security invariants, and static evidence. Historical dirty artifact hashes must remain labeled as historical and must not be presented as final release identities.

## Decision

- **Approved:** merge the license-only commit, together with this audit record.
- **Blocked:** do not merge the remaining accumulated branch as currently scoped.

This partial decision grants the public repository an explicit license without treating unrelated high-risk implementation work as reviewed.
