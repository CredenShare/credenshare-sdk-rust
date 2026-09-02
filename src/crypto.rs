//! Client-side cryptography for CredenShare.
//!
//! This module implements the published wire specification. The specification is normative —
//! not this file, and not any other implementation. Where they disagree, the specification is
//! right and this is a bug.
//!
//! Nothing here talks to the network, and nothing here writes to disk. Encryption happens on
//! your machine, and the content key never leaves it: that is the entire point of the product,
//! and an SDK that quietly sent a key would be worse than no SDK.
//!
//! # Why this is written from the spec rather than ported
//!
//! The application, this SDK and the three others are independent implementations that share
//! no code. That is a supply-chain decision: a package the production application depended on
//! would mean a compromised publish is a compromised application. The cost is drift, and drift
//! here does not produce a test failure — it produces content that can never be decrypted. The
//! conformance vectors are what hold the implementations together, and they include cases that
//! decrypt material produced by a *different* implementation. Passing them is the only
//! meaningful definition of correct.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use elliptic_curve::sec1::ToEncodedPoint;
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::ops::Reduce;
use p256::{NonZeroScalar, PublicKey, Scalar, SecretKey, U256};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::errors::{Error, Result};

/// Field types the recipient view knows how to render (section 2.2.1).
pub const FIELD_TYPES: [&str; 6] = [
    "text",
    "password",
    "date",
    "multiline",
    "markdown",
    "source_code",
];

/// One labelled value in a share.
///
/// `key` is the VISIBLE LABEL. It is not `label`, `name` or `title` — those are silently
/// ignored by the recipient view, which renders the field with a blank label and no error
/// anywhere. Rust's types stop that spelling at compile time for a struct literal; the
/// deserialising path is where it can still reach you, which is what [`validate_fields`] is
/// for.
// `Default` is derived so that adding `extra` did not break every external struct literal:
// `Field { key, value, field_type, ..Default::default() }` compiles.
//
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub key: String,
    pub value: String,
    #[serde(rename = "type")]
    pub field_type: String,

    /// Members this version does not know about, preserved so a field written by a newer
    /// sender survives being read and written again here.
    ///
    /// Declared LAST and flattened, so the three known members keep their declaration order
    /// on the wire — which is the order the conformance vectors compare against. Without
    /// this the struct is closed: unknown members are dropped on decrypt and gone on
    /// re-encrypt, silently, and only whoever added the member ever finds out.
    #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,
}

// `Eq` is implemented by hand rather than derived, because `serde_json::Value` is only
// `PartialEq` - it can hold an f64, and floats are not reflexive.
//
// Sound here: JSON has no NaN and no infinity. `serde_json::Number` cannot represent either
// (without the `arbitrary_precision` feature, which is not enabled), so every `Value` this
// struct can hold compares equal to itself. Restoring `Eq` keeps `f1 == f2` and any `Eq`
// bound working for consumers.
//
// `Hash` genuinely cannot follow - `Value` does not implement it - so `HashSet<Field>` and
// `HashMap<Field, _>` remain unavailable. Key on `Field::key`, or on a
// `(&str, &str, &str)` tuple of the three known members, and keep the `Field` as the value.
impl Eq for Field {}

impl Field {
    /// A field, with all three members. Ordering matters: the serialised form is compared
    /// byte for byte against the other implementations, and serde preserves declaration order.
    pub fn new(
        key: impl Into<String>,
        value: impl Into<String>,
        field_type: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            field_type: field_type.into(),
            extra: Map::new(),
        }
    }
}

// Lengths are exact, per section 0. Named rather than inlined so a truncated blob is rejected
// by arithmetic that reads like the specification.
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const IV_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;
pub(crate) const KEY_LEN: usize = 32;
pub(crate) const PUBKEY_LEN: usize = 65; // 0x04 || X(32) || Y(32)
pub(crate) const WRAP_VERSION: u8 = 1;

/// HKDF-SHA-256, with `info` encoded as UTF-8.
///
/// An empty salt is passed through as a zero-length byte slice rather than being replaced with
/// a block of zeros. RFC 5869 makes those equivalent for HMAC-SHA-256 — a zero-length HMAC key
/// and a 32-zero-byte one both pad to the same 64-byte block — but the specification calls it
/// out because an implementation that pads to some *other* length silently produces different
/// output and fails conformance.
pub(crate) fn hkdf(
    ikm: &[u8],
    salt: &[u8],
    info: &str,
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    // Zeroizing, because every caller of this is deriving key material. Returning a plain Vec
    // leaves the derived key in freed heap after the cipher is built, where it stays until
    // something happens to reuse the allocation.
    let mut out = Zeroizing::new(vec![0u8; length]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info.as_bytes(), &mut out)
        .map_err(|_| Error::Internal("hkdf: invalid output length"))?;
    Ok(out)
}

/// A nonce from a slice, checked rather than asserted.
///
/// The length is verified here rather than by a panicking helper: a wrong-sized IV reaching
/// this point means a malformed blob, and a client that panics on malformed input hands an
/// attacker a denial of service in exchange for one saved line.
fn nonce(iv: &[u8]) -> Result<aes_gcm::Nonce<aes_gcm::aead::consts::U12>> {
    let fixed: [u8; IV_LEN] = iv
        .try_into()
        .map_err(|_| Error::WireFormat(format!("an iv is {IV_LEN} bytes, got {}", iv.len())))?;
    Ok(fixed.into())
}

fn random_bytes(length: usize) -> Vec<u8> {
    let mut out = vec![0u8; length];
    OsRng.fill_bytes(&mut out);
    out
}

/// A fresh 32-byte content key from the OS CSPRNG.
pub fn new_content_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

/// The length of a secure request's seed, in bytes.
///
/// Exported because a seed read back out of a secrets manager has to be checked before it is
/// handed to [`keypair_from_seed`], and a caller writing `32` at that call site is writing the
/// same figure this crate already knows. The same length as a content key and deliberately not
/// interchangeable with one: seeding a request from a key a recipient holds would make that
/// recipient able to read every submission.
pub const SEED_LENGTH: usize = KEY_LEN;

/// A fresh 32-byte seed from the OS CSPRNG.
///
/// This is the whole private key of a secure request's keypair, in 32 bytes, which is what
/// lets one live in a URL fragment or a single secrets-manager entry rather than a keystore.
/// Minted exactly like a content key and not interchangeable with one: seeding a request from
/// a key you also handed to a recipient would make that recipient able to read every
/// submission.
pub fn new_seed() -> [u8; KEY_LEN] {
    let mut seed = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut seed);
    seed
}

/// Encode a content key as a URL fragment: `"1" + base64url(key)`.
///
/// Bare, with a single leading version character and no `k=` prefix. A key=value appendix reads
/// as optional and invites link-mangling clients to truncate it, and a truncated fragment must
/// fail closed rather than look like a well-formed link missing a part.
pub fn encode_fragment(content_key: &[u8]) -> Result<String> {
    if content_key.len() != KEY_LEN {
        return Err(Error::Internal("a content key is 32 bytes"));
    }
    Ok(format!("1{}", B64URL.encode(content_key)))
}

/// Parse a fragment back into a content key.
///
/// Returns [`Error::MissingKey`] when there is no fragment at all and [`Error::MalformedKey`]
/// when there is one but it is not usable. The distinction is not pedantry: "your link is
/// incomplete" and "this share expired" look identical on screen and have opposite remedies.
pub fn decode_fragment(fragment: &str) -> Result<[u8; KEY_LEN]> {
    let text = fragment.trim_start_matches('#');
    if text.is_empty() {
        return Err(Error::MissingKey);
    }

    let mut chars = text.chars();
    match chars.next() {
        Some('1') => {}
        Some(other) => {
            return Err(Error::MalformedKey(format!(
                "unsupported fragment version '{other}'; this link needs a newer client"
            )))
        }
        None => return Err(Error::MissingKey),
    }

    let raw = B64URL
        .decode(chars.as_str())
        .map_err(|_| Error::MalformedKey("the key fragment is not valid base64url".into()))?;

    raw.try_into().map_err(|raw: Vec<u8>| {
        Error::MalformedKey(format!(
            "a content key is {KEY_LEN} bytes; this fragment decoded to {}, so the link is \
             probably truncated",
            raw.len()
        ))
    })
}

/// Check a field array against section 2.2.1 before it is encrypted.
///
/// A field whose `key` is empty renders with a blank label and no error anywhere — which is
/// what a caller deserialising from JSON with the wrong member name produces. Rust's types stop
/// the struct-literal version of the mistake; this covers the rest.
pub fn validate_fields(fields: &[Field]) -> Result<()> {
    for (index, field) in fields.iter().enumerate() {
        if field.key.is_empty() {
            return Err(Error::Internal_owned(format!(
                "field {index} has no 'key' (its visible label); a blank label renders blank \
                 with no error anywhere"
            )));
        }
        if field.field_type.is_empty() {
            return Err(Error::Internal_owned(format!(
                "field {index} has no 'type'; one of {}",
                FIELD_TYPES.join(", ")
            )));
        }
    }
    Ok(())
}

fn content_cipher(content_key: &[u8], salt: &[u8], passcode: Option<&str>) -> Result<Aes256Gcm> {
    // The passcode goes into `info`, never into the salt. They serve different purposes, and a
    // salt built from the passcode would make the derivation depend on a value that has to
    // stay reproducible from stored data alone.
    let info = match passcode {
        Some(passcode) => format!("content|{passcode}"),
        None => "content".to_string(),
    };
    let derived = hkdf(content_key, salt, &info, KEY_LEN)?;
    Aes256Gcm::new_from_slice(&derived).map_err(|_| Error::Internal("invalid AES key length"))
}

/// Encrypt a field array, returning the base64 blob the API accepts.
///
/// The blob uses standard base64, not base64url: it travels in a JSON body, never in a URL.
pub fn encrypt_content(
    content_key: &[u8],
    fields: &[Field],
    passcode: Option<&str>,
) -> Result<String> {
    encrypt_content_with(content_key, fields, passcode, None, None)
}

/// The conformance vectors fix the salt and IV so the fixture is reproducible.
///
/// `pub(crate)` rather than public, deliberately: an exported "use this IV" knob is one
/// autocomplete away from somebody reusing an IV in production, which destroys AES-GCM's
/// guarantees outright.
pub(crate) fn encrypt_content_with(
    content_key: &[u8],
    fields: &[Field],
    passcode: Option<&str>,
    fixed_salt: Option<&[u8]>,
    fixed_iv: Option<&[u8]>,
) -> Result<String> {
    validate_fields(fields)?;

    let salt = fixed_salt
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| random_bytes(SALT_LEN));
    let iv = fixed_iv
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| random_bytes(IV_LEN));

    let cipher = content_cipher(content_key, &salt, passcode)?;
    // serde_json writes no spaces and preserves declaration order, which is the canonical form
    // the other implementations produce. The vectors compare the blob byte for byte, so any
    // difference fails loudly rather than quietly.
    let plaintext =
        serde_json::to_vec(fields).map_err(|_| Error::Internal("serialising fields"))?;

    let body = cipher
        .encrypt(
            &nonce(&iv)?,
            Payload {
                msg: &plaintext,
                aad: b"",
            },
        )
        .map_err(|_| Error::Internal("encryption failed"))?;

    let mut out = Vec::with_capacity(salt.len() + iv.len() + body.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&body);
    Ok(B64.encode(out))
}

/// Decrypt a blob back into the field array.
///
/// A wrong passcode and a tampered blob are indistinguishable, deliberately: both surface as
/// [`Error::WireFormat`]. Telling them apart would hand an attacker an oracle.
pub fn decrypt_content(
    content_key: &[u8],
    blob: &str,
    passcode: Option<&str>,
) -> Result<Vec<Field>> {
    let raw = B64
        .decode(blob)
        .map_err(|_| Error::WireFormat("the content blob is not valid base64".into()))?;

    let minimum = SALT_LEN + IV_LEN + TAG_LEN;
    if raw.len() < minimum {
        // Checked before anything else, so a truncated blob is reported as truncated rather
        // than as a decryption failure that sends somebody looking for a wrong passcode.
        return Err(Error::WireFormat(format!(
            "the content blob is {} bytes; the smallest possible one is {minimum}",
            raw.len()
        )));
    }

    let salt = &raw[..SALT_LEN];
    let iv = &raw[SALT_LEN..SALT_LEN + IV_LEN];
    let body = &raw[SALT_LEN + IV_LEN..];

    let cipher = content_cipher(content_key, salt, passcode)?;
    let plaintext = cipher
        .decrypt(
            &nonce(iv)?,
            Payload {
                msg: body,
                aad: b"",
            },
        )
        .map_err(|_| {
            Error::WireFormat(
                "could not decrypt: the passcode is wrong, or the content was altered".into(),
            )
        })?;

    serde_json::from_slice(&plaintext)
        .map_err(|_| Error::WireFormat("decrypted content is not a field array".into()))
}

/// The access token the server uses to admit a reader.
///
/// The salt is empty so this is reproducible from the fragment alone, on any device, with
/// nothing stored. The server keeps only a hash of it and learns nothing about the content key,
/// because HKDF's domain separation makes the `access` output independent of the `content` one.
pub fn access_token(content_key: &[u8]) -> Result<String> {
    Ok(B64URL.encode(hkdf(content_key, &[], "access", KEY_LEN)?))
}

/// A one-way verifier that lets the server check a passcode it cannot use.
pub fn passcode_verifier(passcode: &str) -> Result<String> {
    Ok(B64URL.encode(hkdf(passcode.as_bytes(), &[], "verify", KEY_LEN)?))
}

/// A P-256 keypair reconstructed from a 32-byte seed.
///
/// Storing the seed rather than a serialized key is what lets an entire private key live in a
/// URL fragment, and what lets ephemeral automation derive the same key with no local state.
pub struct SeedKeypair {
    // Private. This struct hand-writes a Debug that withholds these two precisely because
    // they are the private key; leaving them as pub fields made that gesture decorative.
    // The accessors below still hand them out, but you have to ask by name.
    pub(crate) seed: [u8; KEY_LEN],
    pub(crate) scalar: [u8; KEY_LEN],
    pub(crate) secret: SecretKey,
    pub public_key_raw: [u8; PUBKEY_LEN],
}

impl Drop for SeedKeypair {
    /// Wipe the private halves.
    ///
    /// `secret` is a p256 `SecretKey`, which zeroizes itself on drop. The two byte arrays are
    /// ours, and without this they stay legible in freed memory after the keypair goes out of
    /// scope - which for a seed is the whole private key.
    fn drop(&mut self) {
        self.seed.zeroize();
        self.scalar.zeroize();
    }
}

impl SeedKeypair {
    pub fn public_key_b64url(&self) -> String {
        B64URL.encode(self.public_key_raw)
    }

    /// The 32-byte seed the whole keypair derives from.
    ///
    /// This is private key material. It exists as a method rather than a field so that
    /// reaching it is a deliberate act that shows up in a review.
    pub fn seed(&self) -> &[u8; KEY_LEN] {
        &self.seed
    }

    /// The private scalar. Private key material — see [`Self::seed`].
    pub fn private_scalar(&self) -> &[u8; KEY_LEN] {
        &self.scalar
    }
}

impl std::fmt::Debug for SeedKeypair {
    /// Never render the private half. A key in a log line is a key that has to be rotated, and
    /// `#[derive(Debug)]` on a struct holding one is how that usually happens.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeedKeypair")
            .field("public_key", &self.public_key_b64url())
            .finish_non_exhaustive()
    }
}

/// Derive a P-256 keypair from a 32-byte seed (section 3).
///
/// 48 bytes of HKDF output rather than 32 is deliberate: the extra 128 bits make the modular
/// bias negligible. Reducing mod `n-1` and adding one yields a scalar in `[1, n-1]`, excluding
/// zero, which is not a valid private key.
pub fn keypair_from_seed(seed: &[u8]) -> Result<SeedKeypair> {
    let seed: [u8; KEY_LEN] = seed
        .try_into()
        .map_err(|_| Error::Internal("a seed is 32 bytes"))?;

    let wide = hkdf(&seed, &[], "crs-ecdh-p256-scalar", 48)?;

    // The reduction is done on a big integer rather than in the field, because the modulus is
    // n-1, not n: `Scalar::reduce` would reduce mod n and give a different answer. The other
    // implementations all compute (wide mod (n-1)) + 1, and the vectors pin it.
    let scalar_bytes = reduce_mod_order_minus_one(&wide);
    let scalar = Scalar::reduce(U256::from_be_slice(&scalar_bytes));
    let nonzero = NonZeroScalar::new(scalar)
        .into_option()
        .ok_or(Error::Internal("the derived scalar was zero"))?;

    let secret = SecretKey::from(nonzero);
    let encoded = secret.public_key().to_encoded_point(false);
    let public_key_raw: [u8; PUBKEY_LEN] = encoded
        .as_bytes()
        .try_into()
        .map_err(|_| Error::Internal("unexpected public key length"))?;

    Ok(SeedKeypair {
        seed,
        scalar: scalar_bytes,
        secret,
        public_key_raw,
    })
}

/// `(wide mod (n - 1)) + 1`, as a 32-byte big-endian scalar.
///
/// Written as long division over bytes rather than pulling in a bignum crate: the operation is
/// one reduction of a 48-byte value, and a dependency for that is a dependency somebody has to
/// audit for no benefit.
fn reduce_mod_order_minus_one(wide: &[u8]) -> [u8; KEY_LEN] {
    // n - 1 for P-256.
    const ORDER_MINUS_ONE: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x50,
    ];

    let mut remainder = [0u8; 33]; // one byte of headroom for the shift
    for &byte in wide {
        // remainder = remainder * 256 + byte
        for i in 0..32 {
            remainder[i] = remainder[i + 1];
        }
        remainder[32] = byte;

        // Subtract the modulus while it fits. At most 255 iterations, and in practice a handful.
        while cmp_be(&remainder[1..], &ORDER_MINUS_ONE) != std::cmp::Ordering::Less
            || remainder[0] != 0
        {
            if remainder[0] == 0
                && cmp_be(&remainder[1..], &ORDER_MINUS_ONE) == std::cmp::Ordering::Less
            {
                break;
            }
            sub_be(&mut remainder, &ORDER_MINUS_ONE);
        }
    }

    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&remainder[1..]);
    add_one_be(&mut out);
    out
}

fn cmp_be(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        match x.cmp(y) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

fn sub_be(value: &mut [u8; 33], modulus: &[u8; 32]) {
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = value[i + 1] as i16 - modulus[i] as i16 - borrow;
        if diff < 0 {
            value[i + 1] = (diff + 256) as u8;
            borrow = 1;
        } else {
            value[i + 1] = diff as u8;
            borrow = 0;
        }
    }
    value[0] = (value[0] as i16 - borrow) as u8;
}

fn add_one_be(value: &mut [u8; KEY_LEN]) {
    for byte in value.iter_mut().rev() {
        let (sum, carry) = byte.overflowing_add(1);
        *byte = sum;
        if !carry {
            return;
        }
    }
}

/// Derive the custody keypair from the third part of an API credential (section 3.1).
///
/// The custody secret is never transmitted. It is a *separate* secret from the auth secret
/// precisely so that the server cannot reconstruct this private key: the auth secret goes over
/// the wire on every request, so deriving custody from it would mean the server *could*
/// decrypt. Not that it would — that it could, which is what zero-knowledge is meant to remove.
///
/// The empty salt is deliberate: the derivation has to be reproducible from the credential
/// alone, on any machine, with nothing stored.
pub fn custody_keypair(custody_secret: &str) -> Result<SeedKeypair> {
    let seed = hkdf(custody_secret.as_bytes(), &[], "custody", KEY_LEN)?;
    keypair_from_seed(&seed)
}

/// Wrap a payload to a published P-256 public key.
///
/// Layout: `base64(0x01 || ephemeralPublic(65) || salt(16) || iv(12) || ciphertext+tag)`.
/// Wrapping a 32-byte payload gives exactly 142 bytes, which is a useful field check.
///
/// The ephemeral keypair is fresh per wrap. Reusing one across wraps leaks the relationship
/// between them.
pub fn wrap_to_public_key(payload: &[u8], recipient_public_key: &[u8]) -> Result<String> {
    wrap_to_public_key_with(payload, recipient_public_key, None, None, None)
}

pub(crate) fn wrap_to_public_key_with(
    payload: &[u8],
    recipient_public_key: &[u8],
    fixed_ephemeral_seed: Option<&[u8]>,
    fixed_salt: Option<&[u8]>,
    fixed_iv: Option<&[u8]>,
) -> Result<String> {
    if recipient_public_key.len() != PUBKEY_LEN || recipient_public_key[0] != 0x04 {
        return Err(Error::Internal(
            "a recipient public key is a 65-byte uncompressed P-256 point starting with 0x04",
        ));
    }

    let ephemeral_seed = fixed_ephemeral_seed
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| random_bytes(KEY_LEN));
    let ephemeral = keypair_from_seed(&ephemeral_seed)?;

    let salt = fixed_salt
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| random_bytes(SALT_LEN));
    let iv = fixed_iv
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| random_bytes(IV_LEN));

    let peer = PublicKey::from_sec1_bytes(recipient_public_key).map_err(|_| {
        Error::WireFormat("the recipient public key is not a valid P-256 point".into())
    })?;
    let shared = diffie_hellman(ephemeral.secret.to_nonzero_scalar(), peer.as_affine());

    let wrapping_key = hkdf(
        shared.raw_secret_bytes(),
        &salt,
        "crs-request-submission",
        KEY_LEN,
    )?;
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|_| Error::Internal("invalid AES key length"))?;
    let body = cipher
        .encrypt(
            &nonce(&iv)?,
            Payload {
                msg: payload,
                aad: b"",
            },
        )
        .map_err(|_| Error::Internal("wrapping failed"))?;

    let mut out = Vec::with_capacity(1 + PUBKEY_LEN + SALT_LEN + IV_LEN + body.len());
    out.push(WRAP_VERSION);
    out.extend_from_slice(&ephemeral.public_key_raw);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&body);
    Ok(B64.encode(out))
}

/// Unwrap a payload with the seed whose public key it was wrapped to.
pub fn unwrap_with_seed(wrapped: &str, seed: &[u8]) -> Result<Vec<u8>> {
    let raw = B64
        .decode(wrapped)
        .map_err(|_| Error::WireFormat("the wrap is not valid base64".into()))?;

    let header = 1 + PUBKEY_LEN + SALT_LEN + IV_LEN;
    if raw.len() < header + TAG_LEN {
        return Err(Error::WireFormat(format!(
            "a wrap is at least {} bytes; this one is {}",
            header + TAG_LEN,
            raw.len()
        )));
    }
    if raw[0] != WRAP_VERSION {
        return Err(Error::WireFormat(format!(
            "unsupported wrap version {}; this needs a newer client",
            raw[0]
        )));
    }

    let ephemeral_public = &raw[1..1 + PUBKEY_LEN];
    let salt = &raw[1 + PUBKEY_LEN..1 + PUBKEY_LEN + SALT_LEN];
    let iv = &raw[1 + PUBKEY_LEN + SALT_LEN..header];
    let body = &raw[header..];

    let recipient = keypair_from_seed(seed)?;
    let peer = PublicKey::from_sec1_bytes(ephemeral_public).map_err(|_| {
        Error::WireFormat("the ephemeral public key is not a valid P-256 point".into())
    })?;
    let shared = diffie_hellman(recipient.secret.to_nonzero_scalar(), peer.as_affine());

    let key = hkdf(
        shared.raw_secret_bytes(),
        salt,
        "crs-request-submission",
        KEY_LEN,
    )?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| Error::Internal("invalid AES key length"))?;

    cipher
        .decrypt(
            &nonce(iv)?,
            Payload {
                msg: body,
                aad: b"",
            },
        )
        .map_err(|_| {
            Error::WireFormat(
                "could not unwrap: wrong recipient key, or the wrap was altered".into(),
            )
        })
}

/// Open a sealed secure-request submission with the seed kept when the request was created.
///
/// A submission is an ECDH wrap ([`unwrap_with_seed`]) whose payload is the same field array a
/// share carries, so this is to submissions what [`decrypt_content`] is to shares: the one
/// call that turns a blob you already hold into fields, with no network in it.
///
/// # The encoding that catches people
///
/// A request's `public_key` goes out as **unpadded base64url** and a submission's `data` comes
/// back as **padded standard base64** — two encodings on the same feature. Pass a
/// submission's `data` verbatim; re-encoding it as base64url first yields a wrap that will
/// not open, and the failure looks like a wrong key rather than a wrong decoder.
///
/// (Deliberately not an intra-doc link to `Submission`: that type lives behind the optional
/// `client` feature, and this module compiles without it.)
///
/// `data` is named for the member it takes, so `decrypt_submission(data, seed)` reads the same
/// here as it does in the Node, Python and Go clients.
pub fn decrypt_submission(data: &str, seed: &[u8]) -> Result<Vec<Field>> {
    let plaintext = unwrap_with_seed(data, seed)?;
    serde_json::from_slice(&plaintext)
        .map_err(|_| Error::WireFormat("a decrypted submission is not a field array".into()))
}
