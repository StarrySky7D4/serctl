//! serctl daemon library: the per-profile credential and SSH broker runtime.
//! The `serctl_daemon` binary is a thin entry point over [`daemon::run`]; the
//! CLI's e2e test suite also links this crate to drive the daemon in-process.

pub mod daemon;
