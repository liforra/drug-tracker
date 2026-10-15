//! Zero-knowledge sync server for the consumption tracker.
//!
//! Exposed as a library so the HTTP surface can be driven directly by tests without
//! binding a socket.

pub mod api;
pub mod audit;
pub mod auth;
pub mod db;
pub mod deks;
pub mod enroll;
pub mod lease;
pub mod maintenance;
pub mod ratelimit;
pub mod tunnel;
