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
mod generate;
pub mod webhooks;

#[cfg(feature = "client")]
mod client;

pub use crypto::{
    access_token, custody_keypair, decode_fragment, decrypt_content, decrypt_submission,
    encode_fragment, encrypt_content, keypair_from_seed, new_content_key, new_seed,
    passcode_verifier, unwrap_with_seed, validate_fields, wrap_to_public_key, Field, SeedKeypair,
    FIELD_TYPES, SEED_LENGTH,
};
pub use errors::{ApiDetails, Error, Result};
pub use generate::{
    generate_passphrase, generate_password, generate_pin, strength_of, Generated,
    PassphraseOptions, PasswordOptions, Separator, PASSWORD_SYMBOLS,
};

#[cfg(feature = "client")]
pub use client::{
    AccessLogEntry, AccessLogPage, AccessLogParams, Capabilities, CapabilityKey, CapabilityLimits,
    CapabilityPlan, ClientOptions, CreateParams, CreateRequestParams, CredenShare, Credential,
    DailyView, ListStatus, RequestDeletion, RequestField, RequestPage, RequestSummary,
    SecureRequest, Share, ShareCounts, ShareOptions, SharePage, ShareSummary, Stats, Submission,
    SubmissionPage, DEFAULT_BASE_URL, DEFAULT_LINK_ORIGIN, DEFAULT_MAX_RETRIES, MAX_PAGES,
    NOTIFY_ON_EVENTS, UNLIMITED,
};

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
