//! The normative wire-specification vectors, and a self-check that runs this crate against them.
//!
//! ```bash
//! cargo run --bin credenshare-conformance -- -v
//! ```
//!
//! The vectors are embedded with `include_str!`, so they compile into the binary and cannot go
//! missing in a container that shipped only the executable.
//!
//! That the fixture is normative matters more here than in most libraries. The application and
//! the four SDKs share no code by design — a package the production application depended on
//! would mean a compromised publish is a compromised application — so nothing but these vectors
//! holds the five implementations together. Drift between them does not surface as a test
//! failure in normal use. It surfaces as content that can never be decrypted.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;

use crate::crypto::{self, Field};
use crate::errors::{Error, Result};

/// The raw fixture bytes, so a caller can hash them.
pub const VECTORS_JSON: &str = include_str!("vectors.v1.json");

/// The fixture version this code was written against. A silent bump would mean every check
/// asserts against a contract nobody wrote it for, which is worse than failing.
pub const SUPPORTED_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
pub struct Vectors {
    pub version: u32,
    pub hkdf: Vec<HkdfCase>,
    pub fragment: FragmentCase,
    pub access_token: AccessTokenCase,
    pub passcode_verifier: Vec<PasscodeCase>,
    pub content: Vec<ContentCase>,
    pub seed_keypair: Vec<SeedCase>,
    pub custody_keypair: CustodyCase,
    pub ecdh_wrap: WrapCase,
}

#[derive(Debug, Deserialize)]
pub struct HkdfCase {
    pub name: String,
    pub ikm: String,
    pub salt: String,
    pub info: String,
    pub length: usize,
    pub out: String,
}

#[derive(Debug, Deserialize)]
pub struct FragmentCase {
    pub key: String,
    pub encoded: String,
    pub rejects: Vec<RejectCase>,
}

#[derive(Debug, Deserialize)]
pub struct RejectCase {
    pub input: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct AccessTokenCase {
    pub key: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct PasscodeCase {
    pub passcode: String,
    pub verifier: String,
}

#[derive(Debug, Deserialize)]
pub struct ContentCase {
    pub name: String,
    pub key: String,
    pub salt: String,
    pub iv: String,
    #[serde(default)]
    pub passcode: Option<String>,
    pub plaintext: String,
    pub blob: String,
}

#[derive(Debug, Deserialize)]
pub struct SeedCase {
    pub name: String,
    pub seed: String,
    pub scalar: String,
    pub public_key: String,
    pub public_key_b64url: String,
}

#[derive(Debug, Deserialize)]
pub struct CustodyCase {
    pub custody_secret: String,
    pub seed: String,
    pub public_key: String,
    pub public_key_b64url: String,
}

#[derive(Debug, Deserialize)]
pub struct WrapCase {
    pub wrap_version: u8,
    pub recipient_seed: String,
    pub recipient_public_key: String,
    pub ephemeral_seed: String,
    pub salt: String,
    pub iv: String,
    pub payload: String,
    pub wrapped: String,
}

/// Parse the embedded fixture.
pub fn load() -> Result<Vectors> {
    let vectors: Vectors = serde_json::from_str(VECTORS_JSON)
        .map_err(|_| Error::Internal("the embedded fixture could not be parsed"))?;
    if vectors.version != SUPPORTED_VERSION {
        return Err(Error::Internal_owned(format!(
            "the embedded fixture is version {}, but this SDK implements version {}",
            vectors.version, SUPPORTED_VERSION
        )));
    }
    Ok(vectors)
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn expect<T: PartialEq + std::fmt::Debug>(
    what: &str,
    got: T,
    want: T,
) -> std::result::Result<(), String> {
    if got == want {
        Ok(())
    } else {
        Err(format!("{what}\n  expected: {want:?}\n  actual:   {got:?}"))
    }
}

/// One named vector.
pub struct Check {
    pub name: String,
    #[allow(clippy::type_complexity)]
    pub run: Box<dyn Fn() -> std::result::Result<(), String>>,
}

impl std::fmt::Debug for Check {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Check")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Every vector, as an individually named check.
///
/// Returned as a list rather than run, so a caller — the binary, or `cargo test` — can report
/// them one by one instead of stopping at the first, which matters when a derivation change
/// breaks a whole section at once.
pub fn checks() -> Result<Vec<Check>> {
    let v = load()?;
    let mut out: Vec<Check> = Vec::new();

    for case in v.hkdf {
        out.push(Check {
            name: format!("hkdf/{}", case.name),
            run: Box::new(move || {
                let got = crypto::hkdf(
                    &unhex(&case.ikm),
                    &unhex(&case.salt),
                    &case.info,
                    case.length,
                )
                .map_err(|e| e.to_string())?;
                expect("HKDF output", hex(&got), case.out.clone())
            }),
        });
    }

    let fragment_key = v.fragment.key.clone();
    let fragment_encoded = v.fragment.encoded.clone();
    out.push(Check {
        name: "fragment/encode".into(),
        run: Box::new(move || {
            let got = crypto::encode_fragment(&unhex(&fragment_key)).map_err(|e| e.to_string())?;
            expect("encoded fragment", got, fragment_encoded.clone())
        }),
    });

    let fragment_key = v.fragment.key.clone();
    let fragment_encoded = v.fragment.encoded.clone();
    out.push(Check {
        name: "fragment/decode".into(),
        run: Box::new(move || {
            let got = crypto::decode_fragment(&fragment_encoded).map_err(|e| e.to_string())?;
            expect("decoded content key", hex(&got), fragment_key.clone())
        }),
    });

    for (index, reject) in v.fragment.rejects.into_iter().enumerate() {
        // Refusals are part of the contract, not extra credit: a client that accepts a
        // truncated fragment produces a key that decrypts nothing, and reports it as a content
        // error somewhere far away from the mangled link that caused it.
        out.push(Check {
            name: format!("fragment/rejects/{index}/{}", reject.reason),
            run: Box::new(move || match crypto::decode_fragment(&reject.input) {
                Ok(_) => Err(format!(
                    "{:?} was accepted; the fixture requires a refusal",
                    reject.input
                )),
                Err(Error::MissingKey) if reject.reason == "missing-key" => Ok(()),
                Err(Error::MalformedKey(_)) if reject.reason == "malformed-key" => Ok(()),
                // The distinction is not pedantry. "Your link is incomplete" and "this link is
                // damaged" have different remedies, and both look identical on screen.
                Err(other) => Err(format!(
                    "expected a {} error for {:?}, got {other}",
                    reject.reason, reject.input
                )),
            }),
        });
    }

    let token_case = v.access_token;
    out.push(Check {
        name: "access_token".into(),
        run: Box::new(move || {
            let got = crypto::access_token(&unhex(&token_case.key)).map_err(|e| e.to_string())?;
            expect("access token", got, token_case.token.clone())
        }),
    });

    for (index, case) in v.passcode_verifier.into_iter().enumerate() {
        // Numbered rather than named after the passcode: one of these cases is deliberately
        // non-ASCII, and a legacy console code page would turn printing its name into a crash
        // in the tool meant to be diagnosing crashes.
        out.push(Check {
            name: format!("passcode_verifier/{index}"),
            run: Box::new(move || {
                let got = crypto::passcode_verifier(&case.passcode).map_err(|e| e.to_string())?;
                expect("passcode verifier", got, case.verifier.clone())
            }),
        });
    }

    for case in v.content {
        let encrypt_case = ContentCase {
            ..clone_content(&case)
        };
        out.push(Check {
            name: format!("content/{}/encrypt", case.name),
            run: Box::new(move || {
                let fields: Vec<Field> =
                    serde_json::from_str(&encrypt_case.plaintext).map_err(|e| e.to_string())?;
                let blob = crypto::encrypt_content_with(
                    &unhex(&encrypt_case.key),
                    &fields,
                    encrypt_case.passcode.as_deref(),
                    Some(&unhex(&encrypt_case.salt)),
                    Some(&unhex(&encrypt_case.iv)),
                )
                .map_err(|e| e.to_string())?;
                // Byte-identical, not merely decryptable. A blob that differs while still
                // decrypting here would hide a JSON-serialisation difference — key order,
                // separators — that another implementation may not tolerate.
                expect("content blob", blob, encrypt_case.blob.clone())
            }),
        });

        out.push(Check {
            name: format!("content/{}/decrypt", case.name),
            run: Box::new(move || {
                // The decrypt direction is the one that proves interoperability: the blob in
                // the fixture was produced by a different implementation, so reading it means
                // this client can read what that one wrote.
                let want: Vec<Field> =
                    serde_json::from_str(&case.plaintext).map_err(|e| e.to_string())?;
                let got = crypto::decrypt_content(
                    &unhex(&case.key),
                    &case.blob,
                    case.passcode.as_deref(),
                )
                .map_err(|e| e.to_string())?;
                expect("decrypted fields", got, want)
            }),
        });
    }

    for case in v.seed_keypair {
        out.push(Check {
            name: format!("seed_keypair/{}", case.name),
            run: Box::new(move || {
                let pair =
                    crypto::keypair_from_seed(&unhex(&case.seed)).map_err(|e| e.to_string())?;
                // The scalar is checked as well as the public key. Both would have to be wrong
                // together for a bias in the reduction to slip through unnoticed.
                expect("scalar", hex(&pair.scalar), case.scalar.clone())?;
                expect(
                    "public key",
                    hex(&pair.public_key_raw),
                    case.public_key.clone(),
                )?;
                expect(
                    "public key (base64url)",
                    pair.public_key_b64url(),
                    case.public_key_b64url.clone(),
                )
            }),
        });
    }

    let custody = v.custody_keypair;
    out.push(Check {
        name: "custody_keypair".into(),
        run: Box::new(move || {
            let pair =
                crypto::custody_keypair(&custody.custody_secret).map_err(|e| e.to_string())?;
            // The seed is checked too: it is the value a different implementation has to arrive
            // at independently, and a mismatch here explains a public-key mismatch below it.
            expect("custody seed", hex(&pair.seed), custody.seed.clone())?;
            expect(
                "custody public key",
                hex(&pair.public_key_raw),
                custody.public_key.clone(),
            )?;
            expect(
                "custody public key (base64url)",
                pair.public_key_b64url(),
                custody.public_key_b64url.clone(),
            )
        }),
    });

    let wrap = v.ecdh_wrap;
    let wrap_for_wrap = clone_wrap(&wrap);
    out.push(Check {
        name: "ecdh_wrap/wrap".into(),
        run: Box::new(move || {
            let wrapped = crypto::wrap_to_public_key_with(
                &unhex(&wrap_for_wrap.payload),
                &unhex(&wrap_for_wrap.recipient_public_key),
                Some(&unhex(&wrap_for_wrap.ephemeral_seed)),
                Some(&unhex(&wrap_for_wrap.salt)),
                Some(&unhex(&wrap_for_wrap.iv)),
            )
            .map_err(|e| e.to_string())?;
            expect("wrapped blob", wrapped, wrap_for_wrap.wrapped.clone())
        }),
    });

    let wrap_for_unwrap = clone_wrap(&wrap);
    out.push(Check {
        name: "ecdh_wrap/unwrap".into(),
        run: Box::new(move || {
            let payload = crypto::unwrap_with_seed(
                &wrap_for_unwrap.wrapped,
                &unhex(&wrap_for_unwrap.recipient_seed),
            )
            .map_err(|e| e.to_string())?;
            expect(
                "unwrapped payload",
                hex(&payload),
                wrap_for_unwrap.payload.clone(),
            )
        }),
    });

    out.push(Check {
        name: "ecdh_wrap/roundtrip".into(),
        run: Box::new(move || {
            let recipient = crypto::keypair_from_seed(&unhex(&wrap.recipient_seed))
                .map_err(|e| e.to_string())?;
            let payload = unhex(&wrap.payload);
            let wrapped = crypto::wrap_to_public_key(&payload, &recipient.public_key_raw)
                .map_err(|e| e.to_string())?;

            let raw = B64.decode(&wrapped).map_err(|e| e.to_string())?;
            // 1 version + 65 public + 16 salt + 12 iv + payload + 16 tag. A 32-byte payload
            // wraps to exactly 142 bytes, which is a useful field check when something
            // downstream rejects a wrap without saying why.
            expect(
                "wrap length",
                raw.len(),
                1 + 65 + 16 + 12 + payload.len() + 16,
            )?;
            expect("version byte", raw[0], wrap.wrap_version)?;

            let got = crypto::unwrap_with_seed(&wrapped, &unhex(&wrap.recipient_seed))
                .map_err(|e| e.to_string())?;
            expect("unwrapped payload", hex(&got), wrap.payload.clone())
        }),
    });

    Ok(out)
}

fn clone_content(case: &ContentCase) -> ContentCase {
    ContentCase {
        name: case.name.clone(),
        key: case.key.clone(),
        salt: case.salt.clone(),
        iv: case.iv.clone(),
        passcode: case.passcode.clone(),
        plaintext: case.plaintext.clone(),
        blob: case.blob.clone(),
    }
}

fn clone_wrap(case: &WrapCase) -> WrapCase {
    WrapCase {
        wrap_version: case.wrap_version,
        recipient_seed: case.recipient_seed.clone(),
        recipient_public_key: case.recipient_public_key.clone(),
        ephemeral_seed: case.ephemeral_seed.clone(),
        salt: case.salt.clone(),
        iv: case.iv.clone(),
        payload: case.payload.clone(),
        wrapped: case.wrapped.clone(),
    }
}

/// One check that did not pass.
#[derive(Debug, Clone)]
pub struct Failure {
    pub name: String,
    pub reason: String,
}

/// Run every check, collecting failures rather than stopping at the first.
pub fn run(verbose: bool, log: &mut dyn FnMut(&str)) -> Result<(usize, Vec<Failure>)> {
    let mut passed = 0usize;
    let mut failures = Vec::new();

    for check in checks()? {
        match (check.run)() {
            Ok(()) => {
                passed += 1;
                if verbose {
                    log(&format!("ok   {}", check.name));
                }
            }
            Err(reason) => {
                if verbose {
                    log(&format!("FAIL {}\n{reason}", check.name));
                }
                failures.push(Failure {
                    name: check.name,
                    reason,
                });
            }
        }
    }

    Ok((passed, failures))
}
