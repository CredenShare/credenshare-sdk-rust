//! End-to-end encrypted secret sharing.
//!
//! The crate documentation is the README, included below so that every example in it is
//! compiled as a doctest. Nothing verified those examples before: they lived only in a file
//! rustdoc never read, so a signature could change and the quickstart would go on claiming
//! the old one.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod conformance;
mod crypto;
mod errors;
pub mod webhooks;

#[cfg(feature = "client")]
mod client;

pub use crypto::{
    access_token, custody_keypair, decode_fragment, decrypt_content, encode_fragment,
    encrypt_content, keypair_from_seed, new_content_key, passcode_verifier, unwrap_with_seed,
    validate_fields, wrap_to_public_key, Field, SeedKeypair, FIELD_TYPES,
};
pub use errors::{ApiDetails, Error, Result};

#[cfg(feature = "client")]
pub use client::{
    ClientOptions, CreateParams, CredenShare, Credential, Share, SharePage, ShareSummary,
    DEFAULT_BASE_URL, DEFAULT_LINK_ORIGIN, DEFAULT_MAX_RETRIES, MAX_PAGES,
};

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
