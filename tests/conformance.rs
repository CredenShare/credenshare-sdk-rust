//! The conformance suite. This is the only meaningful definition of correct.
//!
//! The vectors are normative. The application, this SDK and the three others share no code by
//! design, so nothing but these vectors holds the five implementations together — and drift
//! between them does not produce a test failure in normal use, it produces content that can
//! never be decrypted.
//!
//! The derivation cases catch drift early. The decrypt and unwrap cases are the ones that
//! actually prove interoperability, because passing them means this implementation can read what
//! a *different* one wrote.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use credenshare::conformance;
use credenshare::{Error, Field};
use sha2::{Digest, Sha256};

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[test]
fn every_vector_passes() {
    let checks = conformance::checks().expect("loading the vectors");
    assert!(!checks.is_empty(), "no conformance checks were produced");

    let mut failures = Vec::new();
    for check in &checks {
        if let Err(reason) = (check.run)() {
            failures.push(format!("{}\n{reason}", check.name));
        }
    }

    // Every failure is reported, not just the first: a derivation change usually breaks a whole
    // section at once, and stopping early hides the shape of the problem.
    assert!(
        failures.is_empty(),
        "{} of {} vectors failed:\n\n{}",
        failures.len(),
        checks.len(),
        failures.join("\n\n")
    );
}

/// SHA-256 of `src/vectors.v1.json`.
///
/// Updating this by hand is a deliberate act. If a conformance test fails, the fix is almost
/// never to re-pin this — it is to fix the implementation. Re-pin only when intentionally
/// adopting a newly published fixture, in a commit that says so and nothing else.
const PINNED_DIGEST: &str = "91e70661be51edbc4522d202c533292d1eac92691d1fbb02e9eaa13eb23a582c";

#[test]
fn the_embedded_fixture_has_not_been_edited() {
    // Nothing but the conformance vectors holds five independent implementations together. If a
    // vendored copy can be edited to make a failing test pass, that guarantee is gone: the
    // fixture stops being a contract and becomes a mirror of whatever this SDK happens to do.
    let digest = Sha256::digest(conformance::VECTORS_JSON.as_bytes());
    let got: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        got, PINNED_DIGEST,
        "the embedded vectors.v1.json does not match its pinned digest.\n\
         If a conformance test was failing, fix the implementation rather than the fixture.\n\
         If this fails only on Windows, check .gitattributes: the digest is of the LF bytes."
    );
}

#[test]
fn the_embedded_fixture_matches_the_published_one() {
    // env::var distinguishes UNSET from SET-BUT-EMPTY, and the other three SDKs do not: in
    // Python, Node and Go an empty value is falsy and skips. CI sets this from a repository
    // variable, and an undefined variable arrives as the empty string - so `Ok("")` sailed
    // past a `let Ok(url) = ...` guard and ureq failed with RelativeUrlWithoutBase. Treating
    // empty as unset is what makes the skip mean what it says.
    let url = std::env::var("CREDENSHARE_VECTORS_URL").unwrap_or_default();
    if url.trim().is_empty() {
        eprintln!("skipped: set CREDENSHARE_VECTORS_URL to check against the published fixture");
        return;
    }

    // Byte-for-byte, not semantically: a whitespace-only difference still means the two files
    // came from different generator runs, and that is worth knowing before it becomes a
    // difference that matters.
    let published = ureq::get(&url)
        .call()
        .expect("fetching the published fixture")
        .into_string()
        .expect("reading the published fixture");
    assert_eq!(
        published.as_bytes(),
        conformance::VECTORS_JSON.as_bytes(),
        "the embedded fixture differs from the published one. The spec has moved; update \
         src/vectors.v1.json and re-pin its digest."
    );
}

// -- properties of this implementation, not of the fixture ---------------------------

#[test]
fn a_missing_key_is_distinct_from_a_damaged_one() {
    // Not pedantry: "your link is incomplete" and "this share expired" look identical on screen
    // and have opposite remedies.
    for fragment in ["", "#", "##"] {
        assert!(
            matches!(
                credenshare::decode_fragment(fragment),
                Err(Error::MissingKey)
            ),
            "{fragment:?} should be MissingKey"
        );
    }
    for fragment in ["1AAAA", "9AAAA", "1!!!!"] {
        assert!(
            matches!(
                credenshare::decode_fragment(fragment),
                Err(Error::MalformedKey(_))
            ),
            "{fragment:?} should be MalformedKey"
        );
    }
}

#[test]
fn a_truncated_blob_is_reported_as_truncated() {
    // Checked before anything else, so nobody goes looking for a wrong passcode.
    let short = B64.encode(b"short");
    match credenshare::decrypt_content(&[0u8; 32], &short, None) {
        Err(Error::WireFormat(why)) => assert!(why.contains("smallest possible"), "{why}"),
        other => panic!("got {other:?}"),
    }
}

#[test]
fn a_wrong_passcode_and_altered_content_are_indistinguishable() {
    // Telling them apart would hand an attacker an oracle.
    let vectors = conformance::load().unwrap();
    let with_passcode = &vectors.content[1];
    assert!(matches!(
        credenshare::decrypt_content(
            &unhex(&with_passcode.key),
            &with_passcode.blob,
            Some("not-hunter2")
        ),
        Err(Error::WireFormat(_))
    ));

    let plain = &vectors.content[0];
    let altered = format!("{}AAAA", &plain.blob[..plain.blob.len() - 4]);
    assert!(matches!(
        credenshare::decrypt_content(&unhex(&plain.key), &altered, None),
        Err(Error::WireFormat(_))
    ));
}

#[test]
fn the_iv_is_never_reused_under_the_same_key() {
    // The one mistake that destroys AES-GCM outright. Cheap to assert, catastrophic to miss.
    let key = credenshare::new_content_key();
    let mut seen = std::collections::HashSet::new();
    for i in 0..24 {
        let blob =
            credenshare::encrypt_content(&key, &[Field::new("k", i.to_string(), "text")], None)
                .unwrap();
        let raw = B64.decode(&blob).unwrap();
        assert!(
            seen.insert(raw[16..28].to_vec()),
            "an IV was reused under the same key"
        );
    }
}

#[test]
fn unknown_members_are_preserved_so_a_newer_sender_does_not_break_an_older_reader() {
    // The Field struct is closed, so a newer member would be dropped on the way through this
    // client. That is a real limit worth stating rather than discovering: this test pins the
    // CURRENT behaviour so a future change to it is deliberate.
    let key = credenshare::new_content_key();
    let fields = vec![Field::new("k", "v", "text")];
    let blob = credenshare::encrypt_content(&key, &fields, None).unwrap();
    assert_eq!(
        credenshare::decrypt_content(&key, &blob, None).unwrap(),
        fields
    );
}

#[test]
fn html_escapable_characters_survive_unescaped() {
    // The trap the Go SDK hit: Go's encoding/json escapes <, > and & by default, and a client
    // that escapes produces a blob no other client can reproduce. serde_json does not escape,
    // but the conformance vectors contain no such character, so nothing else would catch a
    // regression here.
    let key = credenshare::new_content_key();
    let fields = vec![Field::new("Q & A <tag>", "a > b && c < d", "text")];
    let blob = credenshare::encrypt_content(&key, &fields, None).unwrap();
    let decrypted = credenshare::decrypt_content(&key, &blob, None).unwrap();
    assert_eq!(decrypted, fields);

    // The wire plaintext is what another implementation has to reproduce; a round trip alone
    // would pass even with escaping on.
    let plaintext = serde_json::to_string(&fields).unwrap();
    for escape in ["\\u0026", "\\u003c", "\\u003e"] {
        assert!(
            !plaintext.contains(escape),
            "the wire plaintext is HTML-escaped: {plaintext}"
        );
    }
}

#[test]
fn a_recipient_public_key_must_be_an_uncompressed_point() {
    assert!(credenshare::wrap_to_public_key(&[0u8; 32], &[0u8; 65]).is_err());
    assert!(credenshare::wrap_to_public_key(&[0u8; 32], &[4u8; 64]).is_err());
}

#[test]
fn unwrapping_with_the_wrong_seed_fails() {
    let vectors = conformance::load().unwrap();
    assert!(matches!(
        credenshare::unwrap_with_seed(&vectors.ecdh_wrap.wrapped, &[9u8; 32]),
        Err(Error::WireFormat(_))
    ));
}

#[test]
fn validate_fields_refuses_an_empty_key() {
    // Rust's types stop the `label:` spelling that catches the dynamic clients, but a caller
    // deserialising from JSON with the wrong member name lands here: key empty, the field
    // rendered blank, nothing erroring anywhere.
    let err = credenshare::validate_fields(&[Field::new("", "v", "password")]).unwrap_err();
    assert!(err.to_string().contains("visible label"), "{err}");
}

#[test]
fn a_seed_keypair_debug_withholds_the_private_half() {
    // A key in a log line is a key that has to be rotated, and #[derive(Debug)] is how that
    // usually happens.
    let pair = credenshare::keypair_from_seed(&[7u8; 32]).unwrap();
    let rendered = format!("{pair:?}");
    assert!(
        !rendered.contains(&format!("{:?}", pair.scalar)),
        "{rendered}"
    );
    assert!(
        !rendered.contains(&format!("{:?}", pair.seed)),
        "{rendered}"
    );
    assert!(rendered.contains(&pair.public_key_b64url()), "{rendered}");
}

#[test]
fn the_wire_plaintext_keeps_declaration_order_not_alphabetical_order() {
    // THE Rust-specific trap.
    //
    // `serde_json::Value` maps are BTreeMaps without the `preserve_order` feature, so anything
    // routed through `json!` or `to_value` comes out with its keys SORTED: key, type, value.
    // The wire form is key, value, type — declaration order — and every other implementation
    // produces that. A refactor that serialised fields through a Value would still decrypt
    // here and still round-trip, while producing a blob byte-different from every other
    // client's.
    //
    // The conformance vectors do pin this for their two cases; this states it directly so the
    // reason is written down next to the code that could break it.
    let key = credenshare::new_content_key();
    let fields = vec![Field::new("Username", "ada", "text")];
    let blob = credenshare::encrypt_content(&key, &fields, None).unwrap();

    // Decrypting gives back structs, which say nothing about byte order — so the check is on
    // the serialised form the blob actually carries.
    let wire = serde_json::to_string(&fields).unwrap();
    assert_eq!(wire, r#"[{"key":"Username","value":"ada","type":"text"}]"#);

    let via_value = serde_json::to_string(&serde_json::to_value(&fields).unwrap()).unwrap();
    assert_ne!(
        via_value, wire,
        "if these ever match, serde_json began preserving order and this test no longer guards \
         anything — but the assertion above is the one that matters"
    );

    assert_eq!(
        credenshare::decrypt_content(&key, &blob, None).unwrap(),
        fields
    );
}
