//! serctl shared foundation: the encrypted credential vault, protected-file
//! helpers, 2-of-2 offline recovery, and the russh-backed SSH/SFTP/PTY/tunnel
//! engine. In the split architecture both the daemon and (until Phase 2
//! removes direct connect) the CLI depend on this crate.

pub mod audit;
pub mod daemon_runtime;
pub mod recovery;
pub mod security;
pub mod ssh;
pub mod vault;
