//! Lodeline core domain library.
//!
//! This crate is OS- and notify-independent, and tokio-independent unless the
//! `control-client` feature is on.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod assess;
pub mod audit;
#[cfg(feature = "control-client")]
pub mod control_client;
pub mod control_proto;
pub mod debounce;
pub mod event;
pub mod hashing;
pub mod hook_proto;
pub mod host_id;
pub mod host_meta;
pub mod manifest;
pub mod paths;
pub mod policy;
pub mod ratelimit;
pub mod sink;
pub mod state;
pub mod stats;

pub use event::PolicySignatureInvalidReason;
pub use host_meta::HostMeta;
