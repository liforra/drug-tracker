//! Shared core for the consumption tracker: pharmacokinetics, event log, crypto.
//!
//! Deliberately platform-free. Every client -- Android, Linux, anything later -- links
//! this same crate so that a level shown on the phone and the same level shown on the
//! laptop come from identical arithmetic, not from two reimplementations that drift.
pub mod crypto;
pub mod levels;
pub mod log;
pub mod pk;
pub mod store;
pub mod sync;
pub mod tracker;
