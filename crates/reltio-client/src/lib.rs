//! Production-oriented primitives for the `reltio` command-line interface.
//!
//! The crate intentionally keeps tenant-defined API payloads lossless while
//! strongly typing routing, authentication, retries, and safety metadata.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod auth;
pub mod cancellation;
pub mod config;
pub mod entities;
pub mod error;
pub mod fs;
pub mod http;
pub mod redaction;
pub mod registry;
mod release_contract;
pub mod service;
mod streaming_redaction;

pub use error::{ErrorCategory, ReltioError, Result};

#[doc(hidden)]
pub fn release_evidence_bindings_for_validation()
-> &'static [(&'static str, &'static str, &'static str, &'static str)] {
    &release_contract::V0_1_RELEASE_EVIDENCE_BINDINGS
}

/// Stable structured-output schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Maximum body size accepted by any Reltio POST endpoint.
pub const MAX_POST_BODY_BYTES: usize = 50 * 1024 * 1024;

/// Maximum caller-controlled timeout for the currently exposed finite and scan operations.
pub const MAX_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
