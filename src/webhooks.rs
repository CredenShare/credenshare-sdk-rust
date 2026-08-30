//! Verifying webhook deliveries.
//!
//! A signature you do not check is decoration. This module exists so that checking one is
//! easier than not checking it — including the parts people usually skip, which are the parts
//! that matter.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// The header carrying the timestamp and signatures.
pub const SIGNATURE_HEADER: &str = "X-CredenShare-Signature";

/// How far a delivery's timestamp may sit from your clock, in either direction, in seconds.
///
/// Symmetric because a receiver's clock can be behind OR ahead, and rejecting only one
/// direction fails for half the machines that are wrong. Five minutes is long enough to survive
/// ordinary drift and short enough that a captured delivery is not replayable for long.
pub const DEFAULT_TOLERANCE_SECONDS: i64 = 300;

/// A delivery did not verify. Treat it as a forgery, not as a transient error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationError(pub String);

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the webhook delivery did not verify: {}", self.0)
    }
}

impl std::error::Error for VerificationError {}

/// Tuning for [`verify`]. `Options::default()` uses the standard tolerance and the real clock.
#[derive(Debug, Clone)]
pub struct Options {
    pub tolerance_seconds: i64,
    /// Unix seconds. `None` means the current clock; set it in tests.
    pub now: Option<i64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            tolerance_seconds: DEFAULT_TOLERANCE_SECONDS,
            now: None,
        }
    }
}

/// Verify a delivery signature.
///
/// `payload` must be the RAW request body, exactly as received. Re-serialising parsed JSON
/// changes the bytes — key order, spacing, escapes — and the signature will not match. It is
/// the single most common reason a correct implementation appears broken.
///
/// `secrets` accepts one secret or several. Pass BOTH during a rotation: for 24 hours after you
/// rotate, deliveries are signed with the old and new secrets together, so a receiver holding
/// either keeps working while you roll your configuration.
///
/// Returns `Ok(())` or an error carrying a reason. There is no `bool` — `Result<bool>` invites
/// a caller to check the `Result` and ignore the value, which produces a receiver that accepts
/// everything and looks like it checks.
pub fn verify(
    payload: &[u8],
    header: &str,
    secrets: &[&str],
    options: &Options,
) -> Result<(), VerificationError> {
    let candidates: Vec<&&str> = secrets.iter().filter(|s| !s.trim().is_empty()).collect();
    if candidates.is_empty() {
        return Err(VerificationError("no signing secret was supplied".into()));
    }

    let (timestamp, signatures) = parse(header)?;

    // The timestamp is checked BEFORE the signatures, and it is inside the signed material, so
    // it cannot be swapped for a fresh one without invalidating the MAC. Verifying the
    // signature but ignoring the timestamp would let anyone who captured one delivery replay it
    // forever.
    let now = options.now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });
    let drift = (now - timestamp).abs();
    if drift > options.tolerance_seconds {
        return Err(VerificationError(format!(
            "the delivery timestamp is {drift}s from this clock, outside the {}s window; it may \
             be a replay, or a clock may be wrong",
            options.tolerance_seconds
        )));
    }

    let mut signed = format!("{timestamp}.").into_bytes();
    signed.extend_from_slice(payload);

    let provided: Vec<Vec<u8>> = signatures.iter().filter_map(|s| unhex(s)).collect();

    for secret in candidates {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).map_err(|_| {
            VerificationError("the signing secret could not be used as a key".into())
        })?;
        mac.update(&signed);
        let expected = mac.finalize().into_bytes();

        for candidate in &provided {
            // Constant time: a byte-by-byte comparison leaks how much of a guess was right,
            // which is enough to forge a signature given enough attempts.
            if expected.len() == candidate.len() && bool::from(expected.ct_eq(candidate)) {
                return Ok(());
            }
        }
    }

    Err(VerificationError(
        "no signature matched. If you are mid-rotation, pass both secrets; otherwise check you \
         are verifying the RAW body rather than re-serialised JSON"
            .into(),
    ))
}

fn parse(header: &str) -> Result<(i64, Vec<String>), VerificationError> {
    if header.trim().is_empty() {
        return Err(VerificationError(format!(
            "the {SIGNATURE_HEADER} header is missing"
        )));
    }

    let mut timestamp: Option<i64> = None;
    let mut signatures = Vec::new();

    for part in header.split(',') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        match key {
            "t" => {
                timestamp = Some(value.parse().map_err(|_| {
                    VerificationError(format!("the timestamp {value:?} is not a unix time"))
                })?);
            }
            // Several v1 entries is normal, not an error: it is how a rotation grace window is
            // expressed, so a receiver holding either secret keeps verifying.
            "v1" => signatures.push(value.to_string()),
            _ => {}
        }
    }

    let timestamp = timestamp
        .ok_or_else(|| VerificationError("the signature header carries no timestamp".into()))?;
    if signatures.is_empty() {
        return Err(VerificationError(
            "the signature header carries no v1 signature".into(),
        ));
    }
    Ok((timestamp, signatures))
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}
