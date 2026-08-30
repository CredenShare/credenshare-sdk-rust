//! # CredenShare
//!
//! End-to-end encrypted secret sharing. **Encryption happens on your machine** — the content
//! key never reaches CredenShare, which is what makes "we cannot read your data" a property of
//! the system rather than a promise.
//!
//! ```no_run
//! use credenshare::{CredenShare, CreateParams, Field};
//!
//! # fn main() -> Result<(), credenshare::Error> {
//! let client = CredenShare::new(&std::env::var("CREDENSHARE_KEY").unwrap())?;
//!
//! let share = client.create_share(CreateParams {
//!     title: "Staging deploy credentials".into(),
//!     fields: vec![
//!         Field::new("Username", "deploy-bot", "text"),
//!         Field::new("Password", "correct horse", "password"),
//!     ],
//!     ..Default::default()
//! })?;
//!
//! println!("{}", share.link);
//! # Ok(())
//! # }
//! ```
//!
//! **That link is the secret.** The key lives in its fragment, which browsers never transmit.
//! Anyone holding the link can read the content; we cannot, and cannot recover it for you.
//!
//! # Features
//!
//! `client` (default) pulls in the HTTP client. Turn it off — `default-features = false` — to
//! compile only the crypto, for a caller that posts with its own client or runs somewhere a
//! TLS stack would be dead weight.

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
    DEFAULT_BASE_URL, DEFAULT_LINK_ORIGIN,
};

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
