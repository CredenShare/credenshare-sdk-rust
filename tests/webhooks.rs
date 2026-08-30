//! Webhook verification.
//!
//! Most of these assert refusals. A verifier that accepts too much is worse than none, because
//! it produces a system that looks verified and is not.

use credenshare::webhooks::{verify, Options, DEFAULT_TOLERANCE_SECONDS};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const SECRET: &str = "whsec_5NIQiWnzkbjIRSAX0ilnFLBOoIfnDMi16D3F5jrhSbo";
const OTHER: &str = "whsec_someone-elses-secret-entirely-different-value";
const BODY: &[u8] = br#"{"event":"share.created","short_code":"abc123"}"#;
const NOW: i64 = 1_700_000_000;

fn mac(secret: &str, payload: &[u8], at: i64) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{at}.").as_bytes());
    mac.update(payload);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn sign(secret: &str, payload: &[u8], at: i64) -> String {
    format!("t={at},v1={}", mac(secret, payload, at))
}

fn at(now: i64) -> Options {
    Options {
        now: Some(now),
        ..Default::default()
    }
}

#[test]
fn a_genuine_delivery_verifies() {
    assert!(verify(BODY, &sign(SECRET, BODY, NOW), &[SECRET], &at(NOW)).is_ok());
}

#[test]
fn forgeries_are_refused() {
    assert!(verify(BODY, &sign(OTHER, BODY, NOW), &[SECRET], &at(NOW)).is_err());

    let mut tampered = BODY.to_vec();
    tampered.push(b' ');
    assert!(verify(&tampered, &sign(SECRET, BODY, NOW), &[SECRET], &at(NOW)).is_err());
}

#[test]
fn re_serialised_json_does_not_verify() {
    // The most common reason a correct implementation appears broken: re-serialising parsed
    // JSON changes the bytes — key order, spacing, escapes — so the MAC no longer matches.
    let parsed: serde_json::Value = serde_json::from_slice(BODY).unwrap();
    let reserialised = serde_json::to_vec_pretty(&parsed).unwrap();
    assert_ne!(reserialised, BODY);

    let err = verify(&reserialised, &sign(SECRET, BODY, NOW), &[SECRET], &at(NOW)).unwrap_err();
    assert!(err.0.contains("RAW body"), "{err}");
}

#[test]
fn an_old_delivery_is_refused_even_though_its_signature_is_valid() {
    // Without a timestamp check, anyone who captured one delivery could replay it forever.
    let old = NOW - DEFAULT_TOLERANCE_SECONDS - 60;
    let err = verify(BODY, &sign(SECRET, BODY, old), &[SECRET], &at(NOW)).unwrap_err();
    assert!(err.0.contains("outside the"), "{err}");
}

#[test]
fn the_window_is_symmetric() {
    // A receiver's clock can be AHEAD as easily as behind. Rejecting only one direction fails
    // for half the machines that are wrong.
    let future = NOW + DEFAULT_TOLERANCE_SECONDS + 60;
    assert!(verify(BODY, &sign(SECRET, BODY, future), &[SECRET], &at(NOW)).is_err());

    let inside = NOW + DEFAULT_TOLERANCE_SECONDS - 10;
    assert!(verify(BODY, &sign(SECRET, BODY, inside), &[SECRET], &at(NOW)).is_ok());
}

#[test]
fn the_timestamp_cannot_be_swapped_for_a_fresh_one() {
    // It is inside the signed material, so moving it invalidates the MAC.
    let stale = NOW - 10_000;
    let header = sign(SECRET, BODY, stale).replace(&format!("t={stale}"), &format!("t={NOW}"));
    let err = verify(BODY, &header, &[SECRET], &at(NOW)).unwrap_err();
    assert!(err.0.contains("no signature matched"), "{err}");
}

#[test]
fn either_secret_verifies_a_dual_signed_delivery() {
    // For 24 hours after a rotation, deliveries carry both signatures. That is what lets a
    // receiver roll its configuration without dropping anything — without it, the moment of
    // rotation IS an outage.
    let dual = format!("{},v1={}", sign(SECRET, BODY, NOW), mac(OTHER, BODY, NOW));

    assert!(verify(BODY, &dual, &[SECRET], &at(NOW)).is_ok());
    assert!(verify(BODY, &dual, &[OTHER], &at(NOW)).is_ok());
    assert!(verify(BODY, &dual, &[OTHER, SECRET], &at(NOW)).is_ok());

    // Two signatures widen WHO can verify, not WHAT verifies.
    assert!(verify(BODY, &dual, &["whsec_a-third-secret"], &at(NOW)).is_err());
}

#[test]
fn malformed_headers_are_refused_with_a_reason() {
    let zeros = "0".repeat(64);
    let cases: [(String, &str); 6] = [
        (String::new(), "missing"),
        ("   ".into(), "missing"),
        (format!("v1={zeros}"), "no timestamp"),
        (format!("t={NOW}"), "no v1 signature"),
        (format!("t=notanumber,v1={zeros}"), "not a unix time"),
        (format!("t={NOW},v1=zz"), "no signature matched"),
    ];

    for (header, expected) in cases {
        let err = verify(BODY, &header, &[SECRET], &at(NOW)).unwrap_err();
        assert!(err.0.contains(expected), "header {header:?} gave {err}");
    }
}

#[test]
fn no_secret_is_an_error_not_a_pass() {
    for secrets in [vec![], vec![""], vec!["  "]] {
        let err = verify(BODY, &sign(SECRET, BODY, NOW), &secrets, &at(NOW)).unwrap_err();
        assert!(err.0.contains("no signing secret"), "{err}");
    }
}

#[test]
fn the_default_options_use_the_real_clock() {
    // The Default impl has to work: a caller passing it is the common case, and a verifier that
    // rejects every genuine delivery because its default clock is zero is worse than useless.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(verify(
        BODY,
        &sign(SECRET, BODY, now),
        &[SECRET],
        &Options::default()
    )
    .is_ok());
}
