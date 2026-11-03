//! Wire types for the `lodeline-server` read API (`/v1/*`).
//!
//! `lodeline-server` and `lodeline-manager` (in `apps/manager`) both depend on
//! this crate, so a change to a response shape fails to compile in the same
//! commit on whichever side disagrees. The crate is empty until the server
//! routes move from `serde_json::json!` to these types.
