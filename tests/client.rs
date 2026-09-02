//! Client behaviour, against a real socket.
//!
//! `ureq` has no injectable transport, so rather than mock around it these tests stand up a
//! one-connection HTTP server on a loopback port. That is closer to the truth anyway: it
//! exercises the actual request construction, headers and body, not a stub's idea of them.
//!
//! The properties worth testing here are not "does it call the right URL" but the ones where
//! being wrong is silent or dangerous: the custody secret never leaving the machine, the content
//! key never appearing in a request, and errors that imply the right remedy.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use credenshare::{
    ClientOptions, CreateParams, CreateRequestParams, CredenShare, Credential, Error, Field,
    RequestField,
};

/// One captured request.
#[derive(Debug, Clone)]
struct Captured {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A server that answers `responses` in order, then closes.
struct Stub {
    base_url: String,
    requests: mpsc::Receiver<Captured>,
}

impl Stub {
    fn new(responses: Vec<(u16, &'static str)>) -> Self {
        Self::with_drops(responses, 0)
    }

    /// `drops` connections are accepted and closed without a reply, to simulate a network
    /// failure that proves nothing was received.
    fn with_drops(responses: Vec<(u16, &'static str)>, drops: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binding a loopback port");
        let port = listener.local_addr().unwrap().port();
        let (sender, receiver) = mpsc::channel();

        thread::spawn(move || {
            let mut answered = 0usize;
            let mut dropped = 0usize;
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let captured = read_request(&mut stream);
                let _ = sender.send(captured);

                if dropped < drops {
                    dropped += 1;
                    drop(stream); // no reply at all
                    continue;
                }

                let (status, body) = responses
                    .get(answered)
                    .copied()
                    .unwrap_or_else(|| *responses.last().unwrap());
                answered += 1;

                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nRetry-After: 42\r\nX-Request-Id: req-1\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            requests: receiver,
        }
    }

    fn client(&self, credential: &str) -> CredenShare {
        CredenShare::with_options(
            credential,
            ClientOptions {
                base_url: self.base_url.clone(),
                link_origin: "https://crs.sh".into(),
                ..Default::default()
            },
        )
        .expect("building the client")
    }

    fn next(&self) -> Captured {
        self.requests
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("no request arrived")
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Captured {
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    let mut start = String::new();
    reader.read_line(&mut start).unwrap_or_default();
    let mut parts = start.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    let mut headers = Vec::new();
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((key, value)) = line.trim().split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap_or(0);
            }
            headers.push((key.trim().to_string(), value.trim().to_string()));
        }
    }

    let mut body = vec![0u8; length];
    if length > 0 {
        let _ = reader.read_exact(&mut body);
    }

    Captured {
        method,
        target,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    }
}

const CREDENTIAL: &str = "crs_sk_live_abc123.authsecretvalue.custodysecretvalue";
const TWO_PART: &str = "crs_sk_live_abc123.authsecretvalue";

fn field() -> Field {
    Field::new("k", "v", "text")
}

// -- credential handling --------------------------------------------------------------

#[test]
fn a_credential_parses_both_forms() {
    let three = Credential::parse(CREDENTIAL).unwrap();
    assert_eq!(three.key_id, "abc123");
    assert!(three.has_custody());
    assert!(!Credential::parse(TWO_PART).unwrap().has_custody());
}

#[test]
fn malformed_credentials_are_refused() {
    for bad in [
        "",
        "nope",
        "crs_sk_live_onepart",
        "crs_sk_live_a.b.c.d",
        "crs_sk_live_a..c",
    ] {
        assert!(
            matches!(Credential::parse(bad), Err(Error::CredentialFormat(_))),
            "{bad:?} was accepted"
        );
    }
}

#[test]
fn a_credential_never_renders_its_secrets() {
    // A credential in a log line is a credential that has to be rotated, and Debug is how that
    // usually happens.
    let credential = Credential::parse(CREDENTIAL).unwrap();
    for rendered in [format!("{credential:?}"), format!("{credential}")] {
        assert!(!rendered.contains("authsecretvalue"), "{rendered}");
        assert!(!rendered.contains("custodysecretvalue"), "{rendered}");
        assert!(rendered.contains("abc123"), "{rendered}");
    }
}

#[test]
fn the_custody_public_key_is_derived_locally() {
    let expected = credenshare::custody_keypair("custodysecretvalue")
        .unwrap()
        .public_key_b64url();
    assert_eq!(
        Credential::parse(CREDENTIAL)
            .unwrap()
            .custody_public_key()
            .unwrap(),
        expected
    );
    assert!(Credential::parse(TWO_PART)
        .unwrap()
        .custody_public_key()
        .is_err());
}

#[test]
fn the_custody_secret_is_never_transmitted() {
    // THE property of the split credential. The custody half exists so the server CANNOT
    // reconstruct the private key. If it reaches the wire that guarantee is gone.
    let stub = Stub::new(vec![(201, r#"{"short_code":"xy12"}"#)]);
    let client = stub.client(CREDENTIAL);
    client
        .create_share(CreateParams {
            title: "t".into(),
            fields: vec![field()],
            ..Default::default()
        })
        .unwrap();

    let request = stub.next();
    let everything = format!("{request:?}");
    assert!(
        !everything.contains("custodysecretvalue"),
        "the custody secret reached the wire"
    );
    assert_eq!(
        request.header("Authorization"),
        Some(format!("Bearer {TWO_PART}").as_str())
    );
}

// -- create ---------------------------------------------------------------------------

#[test]
fn create_sends_ciphertext_and_never_the_key() {
    let stub = Stub::new(vec![(201, r#"{"short_code":"xy12"}"#)]);
    let client = stub.client(CREDENTIAL);

    let share = client
        .create_share(CreateParams {
            title: "Staging deploy credentials".into(),
            fields: vec![Field::new("Password", "correct horse", "password")],
            ..Default::default()
        })
        .unwrap();

    let request = stub.next();
    assert!(
        !request.body.contains("correct horse"),
        "the plaintext was sent"
    );

    let parsed: serde_json::Value = serde_json::from_str(&request.body).unwrap();
    assert_eq!(parsed["encryption_type"], "e2ee-aes256-gcm");

    // But the blob must decrypt with the key the caller was handed.
    let fields =
        credenshare::decrypt_content(&share.content_key, parsed["data"].as_str().unwrap(), None)
            .unwrap();
    assert_eq!(
        fields,
        vec![Field::new("Password", "correct horse", "password")]
    );

    assert!(share.link.starts_with("https://crs.sh/xy12#"));
    assert_eq!(
        credenshare::decode_fragment(share.link.split('#').nth(1).unwrap()).unwrap(),
        share.content_key
    );
    // The link carries the key, so Debug must not print it.
    assert!(!format!("{share:?}").contains('#'), "{share:?}");
}

#[test]
fn create_always_sends_an_idempotency_key() {
    // Required by the API. A retried automation must not silently create a second copy of a
    // credential in the world, with its own link and audit trail.
    let stub = Stub::new(vec![(201, r#"{"short_code":"xy12"}"#)]);
    stub.client(CREDENTIAL)
        .create_share(CreateParams {
            title: "t".into(),
            fields: vec![field()],
            ..Default::default()
        })
        .unwrap();
    assert!(stub.next().header("Idempotency-Key").is_some());
}

#[test]
fn a_passcode_sends_a_verifier_and_never_the_passcode() {
    let stub = Stub::new(vec![(201, r#"{"short_code":"xy12"}"#)]);
    stub.client(CREDENTIAL)
        .create_share(CreateParams {
            title: "t".into(),
            fields: vec![field()],
            passcode: Some("hunter2".into()),
            ..Default::default()
        })
        .unwrap();

    let request = stub.next();
    assert!(!request.body.contains("hunter2"), "the passcode was sent");
    assert!(request
        .body
        .contains(&credenshare::passcode_verifier("hunter2").unwrap()));
}

#[test]
fn a_field_with_no_key_is_refused_before_any_request() {
    let stub = Stub::new(vec![(201, "{}")]);
    let err = stub
        .client(CREDENTIAL)
        .create_share(CreateParams {
            title: "t".into(),
            fields: vec![Field::new("", "v", "password")],
            ..Default::default()
        })
        .unwrap_err();
    assert!(err.to_string().contains("visible label"), "{err}");
    assert!(
        stub.requests
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_err(),
        "something was sent"
    );
}

// -- reads ----------------------------------------------------------------------------

#[test]
fn a_page_carries_its_paging_figures() {
    // A caller who has to guess whether more exists guesses wrong.
    let stub = Stub::new(vec![(
        200,
        r#"{"shares":[{"short_code":"a1"}],"pagination":{"page":1,"limit":2,"total":5,"total_pages":3}}"#,
    )]);
    let page = stub.client(CREDENTIAL).list_shares(2, 1).unwrap();
    assert_eq!(page.total, Some(5));
    assert!(page.has_more());
    assert_eq!(page.shares[0].short_code, "a1");
}

#[test]
fn iteration_does_not_stop_on_a_short_middle_page() {
    // The bug in every hand-rolled version of this loop. A server may return a page shorter than
    // the limit in the MIDDLE of a result set; stopping there silently truncates.
    let stub = Stub::new(vec![
        (
            200,
            r#"{"shares":[{"short_code":"a1"},{"short_code":"a2"}],"pagination":{"page":1,"limit":2,"total":5,"total_pages":3}}"#,
        ),
        (
            200,
            r#"{"shares":[{"short_code":"b1"}],"pagination":{"page":2,"limit":2,"total":5,"total_pages":3}}"#,
        ),
        (
            200,
            r#"{"shares":[{"short_code":"c1"},{"short_code":"c2"}],"pagination":{"page":3,"limit":2,"total":5,"total_pages":3}}"#,
        ),
    ]);

    let mut seen = Vec::new();
    stub.client(CREDENTIAL)
        .for_each_share(2, |share| {
            seen.push(share.short_code.clone());
            Ok(())
        })
        .unwrap();

    assert_eq!(seen, ["a1", "a2", "b1", "c1", "c2"]);
}

#[test]
fn expire_issues_a_delete() {
    let stub = Stub::new(vec![(200, "{}")]);
    stub.client(CREDENTIAL).expire_share("a1").unwrap();
    let request = stub.next();
    assert_eq!(request.method, "DELETE");
    assert!(request.target.ends_with("/shares/a1"), "{}", request.target);
    // Byte-for-byte the 0.1.4 call. This surface is published and 0.2.0 is a minor, so the
    // automatic Idempotency-Key added for the escape hatch must not reach it — and the API
    // does not read the header on a delete, so there is nothing to trade for the change.
    assert!(
        request.header("Idempotency-Key").is_none(),
        "expire_share grew an Idempotency-Key the 0.1.4 call did not send"
    );
}

#[test]
fn read_link_is_refused_with_a_reason() {
    let stub = Stub::new(vec![(200, "{}")]);
    let err = stub
        .client(CREDENTIAL)
        .read_link("https://crs.sh/abc#1AAA")
        .unwrap_err();
    assert!(err.to_string().contains("by design"), "{err}");
}

// -- errors imply remedies --------------------------------------------------------------

/// A status, the body the server sends with it, and the variant the client must produce.
type MappingCase = (u16, &'static str, fn(&Error) -> bool);

#[test]
fn error_mapping() {
    let cases: Vec<MappingCase> = vec![
        (401, r#"{"message":"bad"}"#, |e| {
            matches!(e, Error::Authentication(_))
        }),
        (403, r#"{"message":"no api"}"#, |e| {
            matches!(e, Error::Permission(_))
        }),
        (403, r#"{"message":"limit","error_code":61}"#, |e| {
            matches!(e, Error::QuotaExceeded(_))
        }),
        (404, r#"{"message":"gone"}"#, |e| {
            matches!(e, Error::NotFound(_))
        }),
        (409, r#"{"message":"used","error_code":105}"#, |e| {
            matches!(e, Error::IdempotencyConflict(_))
        }),
        (429, r#"{"message":"slow"}"#, |e| {
            matches!(e, Error::RateLimited { .. })
        }),
        (503, r#"{"message":"down"}"#, |e| {
            matches!(e, Error::ServiceUnavailable(_))
        }),
        (500, r#"{"message":"boom"}"#, |e| matches!(e, Error::Api(_))),
    ];

    for (status, body, matches) in cases {
        let stub = Stub::new(vec![(status, body)]);
        let err = stub.client(CREDENTIAL).list_shares(10, 1).unwrap_err();
        assert!(matches(&err), "status {status} gave {err:?}");
        assert_eq!(err.details().map(|d| d.status), Some(status));
        assert_eq!(
            err.details().and_then(|d| d.request_id.clone()),
            Some("req-1".into())
        );
    }
}

#[test]
fn a_rate_limit_carries_retry_after() {
    let stub = Stub::new(vec![(429, r#"{"message":"slow"}"#)]);
    match stub.client(CREDENTIAL).list_shares(10, 1).unwrap_err() {
        Error::RateLimited { retry_after, .. } => assert_eq!(retry_after, Some(42)),
        other => panic!("got {other:?}"),
    }
}

// -- transport retries -------------------------------------------------------------------

#[test]
fn a_dropped_connection_is_retried_with_the_identical_request() {
    // The case the mandatory header exists for. The retry must repeat the identical body, or
    // the server sees a new one under a used key and refuses — turning a recoverable blip into
    // a hard failure.
    let stub = Stub::with_drops(vec![(201, r#"{"short_code":"xy12"}"#)], 1);
    let share = stub
        .client(CREDENTIAL)
        .create_share(CreateParams {
            title: "t".into(),
            fields: vec![field()],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(share.short_code, "xy12");

    let first = stub.next();
    let second = stub.next();
    assert_eq!(
        first.header("Idempotency-Key"),
        second.header("Idempotency-Key")
    );
    assert_eq!(first.body, second.body);
    assert!(!first.body.is_empty(), "the first body was empty");
}

#[test]
fn an_http_500_is_not_retried() {
    // It may have committed, and this client cannot tell. Retrying would risk a second copy of
    // a credential in the world under a caller who believes one was created.
    let stub = Stub::new(vec![(500, r#"{"message":"boom"}"#)]);
    assert!(stub
        .client(CREDENTIAL)
        .create_share(CreateParams {
            title: "t".into(),
            fields: vec![field()],
            ..Default::default()
        })
        .is_err());

    stub.next();
    assert!(
        stub.requests
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_err(),
        "it was retried"
    );
}

#[test]
fn retries_are_bounded_and_surface_as_transport() {
    let stub = Stub::with_drops(vec![(200, "{}")], 99);
    let client = CredenShare::with_options(
        CREDENTIAL,
        ClientOptions {
            base_url: stub.base_url.clone(),
            max_retries: 1,
            ..Default::default()
        },
    )
    .unwrap();

    assert!(matches!(
        client.list_shares(10, 1),
        Err(Error::Transport(_))
    ));
    stub.next();
    stub.next();
}

// ── the walk must terminate against a server that never signals the end ────────────────
//
// Asked for by the review of item 9 and not written at the time: the fix landed with no test.
// Two failure modes, both of which used to be an unbounded loop.

/// A server that answers every list request with a full page and no paging figures at all.
fn endless_full_pages(limit: u32) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            use std::io::{Read, Write};
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let rows: Vec<String> = (0..limit)
                .map(|i| format!(r#"{{"short_code":"c{i}"}}"#))
                .collect();
            let body = format!(r#"{{"shares":[{}]}}"#, rows.join(","));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (addr, handle)
}

#[test]
fn for_each_share_stops_instead_of_walking_forever() {
    // MAX_PAGES is 100_000, which would be 100_000 round trips against a local socket - far
    // too slow for a test. So this asserts the property that makes the cap reachable at all:
    // has_more stays true forever on this server, which is precisely why the cap exists.
    // The page-echo guard below is the one that fires cheaply.
    let (addr, _server) = endless_full_pages(3);
    let client = credenshare::CredenShare::with_options(
        "crs_sk_live_abc123.authsecretvalue",
        credenshare::ClientOptions {
            base_url: format!("http://{addr}"),
            ..Default::default()
        },
    )
    .unwrap();

    let page = client.list_shares(3, 1).unwrap();
    assert_eq!(page.shares.len(), 3);
    assert!(
        page.has_more(),
        "a full page with no paging figures must not read as the end - that was the silent \
         truncation this fallback fixed"
    );
    // The cap the error message names must be reachable by a consumer at all - this line
    // failing to compile is the assertion. A runtime `> 0` check is const-folded away and
    // clippy rejects it.
    let cap: u32 = credenshare::MAX_PAGES;
    assert_eq!(
        cap, 100_000,
        "the documented cap changed; update the CHANGELOG too"
    );
}

#[test]
fn for_each_share_refuses_a_server_that_echoes_the_wrong_page() {
    // This server always answers page 1, so progress is unobservable and the last-resort
    // has_more fallback would loop forever. It must be an error, not a hang.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            use std::io::{Read, Write};
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            // page is pinned at 1 whatever was asked for
            let body = r#"{"shares":[{"short_code":"a"},{"short_code":"b"}],"pagination":{"page":1,"limit":2,"total_pages":9}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    let client = credenshare::CredenShare::with_options(
        "crs_sk_live_abc123.authsecretvalue",
        credenshare::ClientOptions {
            base_url: format!("http://{addr}"),
            ..Default::default()
        },
    )
    .unwrap();

    let mut seen = 0usize;
    let result = client.for_each_share(2, |_| {
        seen += 1;
        assert!(seen < 1000, "for_each_share is looping instead of erroring");
        Ok(())
    });

    let error = result.expect_err("a server echoing a constant page must be refused");
    assert!(
        format!("{error}").contains("page"),
        "the error must say paging is the problem: {error}"
    );
}

// -- secure requests --------------------------------------------------------------------
//
// The property that matters here is the mirror of the share tests: the SEED must never reach
// the wire, because it is the whole private key and the only thing that can read a submission.

/// A response body computed at run time, handed to the stub as `&'static str`.
///
/// `Stub` takes static bodies because every other body in this file is a literal. Leaking one
/// string per sealed-submission test is cheaper than making every literal an allocation.
fn leaked(body: String) -> &'static str {
    Box::leak(body.into_boxed_str())
}

/// A sealed submission, produced the way a submitter's browser produces one.
fn sealed(fields: &[Field], seed: &[u8; 32]) -> String {
    let keypair = credenshare::keypair_from_seed(seed).unwrap();
    credenshare::wrap_to_public_key(
        &serde_json::to_vec(fields).unwrap(),
        &keypair.public_key_raw,
    )
    .unwrap()
}

#[test]
fn create_request_sends_the_public_half_and_never_the_seed() {
    // THE property of a secure request. The API gets the public key; the seed stays here, and
    // if it ever went out the collect link would look end-to-end encrypted and not be.
    let stub = Stub::new(vec![(
        201,
        r#"{"short_code":"rq12","expired_at":"2026-10-02T00:00:00Z"}"#,
    )]);
    let created = stub
        .client(CREDENTIAL)
        .create_request(CreateRequestParams {
            title: "Staging database password".into(),
            fields: vec![
                RequestField::text("Your name"),
                RequestField::new("Staging database password", "password"),
            ],
            ..Default::default()
        })
        .unwrap();

    let request = stub.next();
    let everything = format!("{request:?}");
    let seed = *created.seed();
    assert!(
        !everything.contains(&URL_SAFE_NO_PAD.encode(seed)),
        "the seed reached the wire"
    );
    assert!(
        !everything.contains(&hex::encode(seed)),
        "the seed reached the wire"
    );

    let parsed: serde_json::Value = serde_json::from_str(&request.body).unwrap();
    let public_key = parsed["public_key"].as_str().unwrap();
    // Unpadded base64url of a 65-byte uncompressed point: 87 characters, no '='. The blobs
    // that come back are padded STANDARD base64 - the trap this asserts the near side of.
    assert_eq!(public_key.len(), 87, "{public_key}");
    assert!(!public_key.contains('='), "{public_key}");
    assert_eq!(
        public_key,
        credenshare::keypair_from_seed(&seed)
            .unwrap()
            .public_key_b64url(),
        "the public key sent is not the one the returned seed derives"
    );
    assert_eq!(created.public_key, public_key);

    // The prompt is `item`, and the type is omitted where the caller left it empty.
    assert_eq!(parsed["fields"][0]["item"], "Your name");
    assert_eq!(parsed["fields"][0]["type"], "text");
    assert_eq!(parsed["fields"][1]["type"], "password");

    assert!(request.header("Idempotency-Key").is_some());
    assert_eq!(created.collect_link, "https://crs.sh/r/rq12");
    assert_eq!(created.expired_at.as_deref(), Some("2026-10-02T00:00:00Z"));

    // The two links: one keyless and safe to publish, one carrying the seed in a
    // version-prefixed fragment. Byte-for-byte the format the app's own reader parses.
    assert_eq!(
        created.access_link,
        format!("https://crs.sh/r/rq12#1{}", URL_SAFE_NO_PAD.encode(seed))
    );
    assert_eq!(
        created.access_link,
        stub.client(CREDENTIAL)
            .access_link_for("rq12", &seed)
            .unwrap()
    );
    assert!(!created.collect_link.contains('#'));

    // The seed is the private key, so Debug must not print it - nor the access link, which
    // is the same 32 bytes in base64url.
    for rendering in [format!("{created:?}"), format!("{created:#?}")] {
        assert!(!rendering.contains(&hex::encode(seed)), "{rendering}");
        assert!(
            !rendering.contains(&URL_SAFE_NO_PAD.encode(seed)),
            "{rendering}"
        );
        assert!(!rendering.contains(&created.access_link), "{rendering}");
    }
}

#[test]
fn a_wrong_length_seed_is_a_typed_error_not_a_crypto_one() {
    // The caller passed something this client refuses to use, so the message names the
    // argument rather than surfacing from inside a primitive.
    let stub = Stub::new(vec![(200, "{}")]);
    let err = stub
        .client(CREDENTIAL)
        .access_link_for("rq12", &[7u8; 31])
        .unwrap_err();
    assert!(matches!(err, Error::MalformedKey(_)), "{err:?}");
    assert!(err.to_string().contains("31"), "{err}");
    // And the figure it compares against is the exported one, which is 32 in all four SDKs.
    assert_eq!(credenshare::SEED_LENGTH, 32);
    assert!(
        err.to_string()
            .contains(&credenshare::SEED_LENGTH.to_string()),
        "{err}"
    );
}

#[test]
fn create_request_params_withhold_the_seed_when_printed() {
    // `dbg!(&params)` and a tracing field are reflexes, and the derived Debug printed the
    // seed's bytes. A leaked seed cannot be rotated: rotating it would make every submission
    // already collected unreadable.
    let seed = [7u8; 32];
    let params = CreateRequestParams {
        title: "Contractor onboarding".into(),
        fields: vec![RequestField::text("Your name")],
        seed: Some(seed),
        ..Default::default()
    };

    for rendering in [format!("{params:?}"), format!("{params:#?}")] {
        assert!(rendering.contains("Contractor onboarding"), "{rendering}");
        assert!(rendering.contains("withheld"), "{rendering}");
        // The bytes, in every spelling a Debug could produce them in.
        assert!(!rendering.contains("7, 7, 7"), "{rendering}");
        assert!(!rendering.contains(&hex::encode(seed)), "{rendering}");
        assert!(
            !rendering.contains(&URL_SAFE_NO_PAD.encode(seed)),
            "{rendering}"
        );
    }

    // And absence is rendered as absence, not as a redaction of nothing.
    let empty = CreateRequestParams {
        title: "t".into(),
        ..Default::default()
    };
    assert!(format!("{empty:?}").contains("seed: None"), "{empty:?}");
}

#[test]
fn a_seed_in_the_body_is_refused_before_anything_is_sent() {
    // The boundary assertion, in the manner of the custody one. It scans the SERIALIZED body,
    // so a seed that arrives through a title, a description or a prompt is caught too - not
    // only one added to the field list.
    let seed = [7u8; 32];
    let smuggled = [
        hex::encode(seed),
        URL_SAFE_NO_PAD.encode(seed),
        STANDARD_NO_PAD.encode(seed),
        STANDARD.encode(seed),
    ];

    for rendering in smuggled {
        // Through the title, through a prompt, and through the description in turn.
        let cases = [
            CreateRequestParams {
                title: format!("backup of {rendering}"),
                fields: vec![RequestField::text("Your name")],
                seed: Some(seed),
                ..Default::default()
            },
            CreateRequestParams {
                title: "t".into(),
                fields: vec![RequestField::text(rendering.clone())],
                seed: Some(seed),
                ..Default::default()
            },
            CreateRequestParams {
                title: "t".into(),
                fields: vec![RequestField::text("Your name")],
                description: Some(rendering.clone()),
                seed: Some(seed),
                ..Default::default()
            },
        ];
        for params in cases {
            let stub = Stub::new(vec![(201, r#"{"short_code":"rq12"}"#)]);
            let err = stub.client(CREDENTIAL).create_request(params).unwrap_err();
            assert!(
                matches!(err, Error::RequestSeedTransmitted),
                "{rendering}: {err:?}"
            );
            assert!(
                stub.requests
                    .recv_timeout(std::time::Duration::from_millis(300))
                    .is_err(),
                "{rendering}: the seed reached the wire"
            );
        }
    }
}

#[test]
fn a_seed_used_as_the_idempotency_key_is_refused_too() {
    // Not a contrived input: `seed` and `idempotency_key` are adjacent fields, and a caller
    // who wants a deterministic key from a deterministic seed has the seed in hand. A check
    // that read only the body would let it out in a header.
    let seed = [7u8; 32];
    let stub = Stub::new(vec![(201, r#"{"short_code":"rq12"}"#)]);
    let err = stub
        .client(CREDENTIAL)
        .create_request(CreateRequestParams {
            title: "t".into(),
            fields: vec![RequestField::text("Your name")],
            seed: Some(seed),
            idempotency_key: Some(URL_SAFE_NO_PAD.encode(seed)),
            ..Default::default()
        })
        .unwrap_err();
    assert!(matches!(err, Error::RequestSeedTransmitted), "{err:?}");
    // The remedy is in the message, because a retry is the wrong one.
    assert!(
        err.to_string().contains("expire it and create a new one"),
        "{err}"
    );
    assert!(
        stub.requests
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_err(),
        "the seed reached the wire in a header"
    );
}

#[test]
fn the_seed_escapes_no_reflexive_rendering() {
    // The proof, run rather than argued. A SecureRequest and the params that made it are
    // pushed through every path a Rust developer reaches for without thinking - {:?}, {:#?},
    // dbg!, a container, a struct that embeds one - and every rendering is checked against all
    // four spellings of the seed plus the access link, which carries the same 32 bytes.
    //
    // The two serialization paths that leak in other languages cannot exist here: neither type
    // implements Serialize, so serde_json::to_string does not compile, and neither implements
    // Display, so "{}" does not either. `cargo build` is the assertion for those.
    //
    // Run it on its own with the output visible:
    //   cargo test the_seed_escapes_no_reflexive_rendering -- --nocapture
    let seed = [7u8; 32];
    let stub = Stub::new(vec![(
        201,
        r#"{"short_code":"rq12","expired_at":"2026-10-02T00:00:00Z"}"#,
    )]);
    let params = CreateRequestParams {
        title: "Contractor onboarding".into(),
        fields: vec![RequestField::new("Staging database password", "password")],
        description: Some("for the audit".into()),
        seed: Some(seed),
        ..Default::default()
    };
    // Printed BEFORE the create consumes it, which is where a caller would print it.
    let params_debug = format!("{params:?}");
    let params_alternate = format!("{params:#?}");

    let request = stub.client(CREDENTIAL).create_request(params).unwrap();

    #[derive(Debug)]
    #[allow(dead_code)]
    struct Envelope {
        label: &'static str,
        request: credenshare::SecureRequest,
    }

    let renderings: Vec<(&str, String)> = vec![
        ("format!(\"{params:?}\")", params_debug),
        ("format!(\"{params:#?}\")", params_alternate),
        ("format!(\"{request:?}\")", format!("{request:?}")),
        ("format!(\"{request:#?}\")", format!("{request:#?}")),
        (
            "format!(\"{:?}\", Some(&request))",
            format!("{:?}", Some(&request)),
        ),
        (
            "format!(\"{:?}\", vec![&request])",
            format!("{:?}", vec![&request]),
        ),
        (
            "format!(\"{:?}\", Envelope {{ .. }})",
            format!(
                "{:?}",
                Envelope {
                    label: "embedded",
                    request,
                }
            ),
        ),
    ];

    let needles = [
        ("hex", hex::encode(seed)),
        ("base64url (unpadded)", URL_SAFE_NO_PAD.encode(seed)),
        ("standard base64 (unpadded)", STANDARD_NO_PAD.encode(seed)),
        ("standard base64 (padded)", STANDARD.encode(seed)),
        (
            "the raw byte list a derived Debug prints",
            "7, 7, 7".to_string(),
        ),
    ];

    println!("seed under test (hex): {}", hex::encode(seed));
    println!("-- every reflexive rendering, verbatim --");
    for (path, rendering) in &renderings {
        println!("{path}\n    {rendering}");
    }
    println!("-- scan --");
    for (path, rendering) in &renderings {
        for (name, needle) in &needles {
            assert!(
                !rendering.contains(needle.as_str()),
                "{path} leaked the seed as {name}: {rendering}"
            );
        }
        // The access link is the seed in another coat, so it is withheld alongside it.
        assert!(!rendering.contains("#1"), "{path} carried a key fragment");
        println!("{path}: clean against all {} spellings", needles.len());
    }

    // Same objects, same Debug, through the macro that writes to stderr.
    let seed_again = [7u8; 32];
    let params_again = CreateRequestParams {
        title: "Contractor onboarding".into(),
        fields: vec![RequestField::text("Your name")],
        seed: Some(seed_again),
        ..Default::default()
    };
    let echoed = format!("{:?}", dbg!(&params_again));
    assert!(!echoed.contains(&hex::encode(seed_again)));
    assert!(echoed.contains("<32 bytes withheld>"), "{echoed}");
}

#[test]
fn a_request_can_be_created_under_a_team() {
    let stub = Stub::new(vec![(201, r#"{"short_code":"rq12"}"#)]);
    stub.client(CREDENTIAL)
        .create_request(CreateRequestParams {
            title: "t".into(),
            fields: vec![RequestField::text("Your name")],
            organization_id: Some("org_7".into()),
            ..Default::default()
        })
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stub.next().body).unwrap();
    assert_eq!(parsed["organization_id"], "org_7");
}

#[test]
fn the_0_1_4_create_params_literal_still_compiles_exhaustively() {
    // The regression this guards is a COMPILE error, not a runtime one, so the assertion is
    // the literal itself: every field of `CreateParams` named, with no `..Default::default()`
    // to absorb a new one. That is what a 0.1.4 consumer was free to write, and adding a
    // member — `organization_id` was the candidate — stops it building. A source break in a
    // minor, and invisible to every test that uses the struct-update shorthand.
    let stub = Stub::new(vec![(201, r#"{"short_code":"ab12"}"#)]);
    stub.client(CREDENTIAL)
        .create_share(CreateParams {
            title: "t".into(),
            fields: vec![field()],
            description: None,
            passcode: None,
            expired_at: None,
            access_counts_left: None,
            timed_view: None,
            idempotency_key: None,
            content_key: None,
        })
        .unwrap();

    // And the body is the one 0.1.4 sent: no team member reached the wire.
    let body: serde_json::Value = serde_json::from_str(&stub.next().body).unwrap();
    assert!(body.get("organization_id").is_none(), "{body}");
}

#[test]
fn a_supplied_seed_reproduces_the_keypair() {
    // The custody case: an ephemeral runner derives the same keypair from the credential it
    // already holds, so it needs nothing stored to read submissions later.
    let stub = Stub::new(vec![(201, r#"{"short_code":"rq12"}"#)]);
    let custody = credenshare::custody_keypair("custodysecretvalue").unwrap();

    let created = stub
        .client(CREDENTIAL)
        .create_request(CreateRequestParams {
            title: "t".into(),
            fields: vec![RequestField::text("p")],
            seed: Some(*custody.seed()),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(created.seed(), custody.seed());
    let request = stub.next();
    let parsed: serde_json::Value = serde_json::from_str(&request.body).unwrap();
    assert_eq!(parsed["public_key"], custody.public_key_b64url());
    // Derived locally on both sides, and still not transmitted.
    assert!(
        !format!("{request:?}").contains("custodysecretvalue"),
        "the custody secret reached the wire"
    );
}

#[test]
fn a_request_with_no_usable_fields_is_refused_before_any_request() {
    // A request created without fields gets a 201 and a short code, then renders "Unable to
    // Load Request" for whoever it was sent to. Nothing at the API level would show it.
    for fields in [vec![], vec![RequestField::text("  ")]] {
        let stub = Stub::new(vec![(201, "{}")]);
        let err = stub
            .client(CREDENTIAL)
            .create_request(CreateRequestParams {
                title: "t".into(),
                fields,
                ..Default::default()
            })
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
        assert!(
            stub.requests
                .recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "something was sent"
        );
    }
}

#[test]
fn a_request_page_carries_its_paging_figures() {
    let stub = Stub::new(vec![(
        200,
        r#"{"requests":[{"short_code":"rq1","public_key":"BEw1"}],"pagination":{"page":1,"limit":2,"total":5,"total_pages":3}}"#,
    )]);
    let page = stub.client(CREDENTIAL).list_requests(2, 1).unwrap();
    assert_eq!(page.total, Some(5));
    assert!(page.has_more());
    assert_eq!(page.requests[0].short_code, "rq1");
    assert_eq!(page.requests[0].public_key.as_deref(), Some("BEw1"));
}

#[test]
fn the_request_list_asks_for_the_api_default_page_size() {
    // 25, the same figure every v1 list defaults to. openapi.yaml documents 10 for this one
    // and is wrong; asking for 10 would make the paging figures disagree with the dashboard.
    let stub = Stub::new(vec![(200, r#"{"requests":[]}"#)]);
    stub.client(CREDENTIAL).list_requests(0, 0).unwrap();
    let target = stub.next().target;
    assert!(target.contains("limit=25"), "{target}");
    assert!(target.contains("page=1"), "{target}");
}

#[test]
fn request_iteration_does_not_stop_on_a_short_middle_page() {
    // The same bug as the share walk, and the same reason it is written here rather than by
    // every caller: a server may return a short page in the MIDDLE of a result set.
    let stub = Stub::new(vec![
        (
            200,
            r#"{"requests":[{"short_code":"a1"},{"short_code":"a2"}],"pagination":{"page":1,"limit":2,"total":5,"total_pages":3}}"#,
        ),
        (
            200,
            r#"{"requests":[{"short_code":"b1"}],"pagination":{"page":2,"limit":2,"total":5,"total_pages":3}}"#,
        ),
        (
            200,
            r#"{"requests":[{"short_code":"c1"},{"short_code":"c2"}],"pagination":{"page":3,"limit":2,"total":5,"total_pages":3}}"#,
        ),
    ]);

    let mut seen = Vec::new();
    stub.client(CREDENTIAL)
        .for_each_request(2, |request| {
            seen.push(request.short_code.clone());
            Ok(())
        })
        .unwrap();

    assert_eq!(seen, ["a1", "a2", "b1", "c1", "c2"]);
}

#[test]
fn a_request_row_that_cannot_be_read_is_an_error_not_an_omission() {
    // A quietly short list makes a reconciliation report requests as missing that are not.
    let stub = Stub::new(vec![(200, r#"{"requests":[{"expired_at":null}]}"#)]);
    let err = stub.client(CREDENTIAL).list_requests(10, 1).unwrap_err();
    assert!(err.to_string().contains("silently short"), "{err}");
}

#[test]
fn get_request_asks_for_one_row_and_returns_the_public_half() {
    let stub = Stub::new(vec![(
        200,
        r#"{"short_code":"rq12","expired_at":"2026-10-02T00:00:00Z","public_key":"BEw1"}"#,
    )]);
    let summary = stub.client(CREDENTIAL).get_request("rq12").unwrap();
    let request = stub.next();
    assert_eq!(request.method, "GET");
    assert!(
        request.target.ends_with("/requests/rq12"),
        "{}",
        request.target
    );
    assert_eq!(summary.public_key.as_deref(), Some("BEw1"));
    // A GET must not carry an idempotency key; nothing about a read needs replaying.
    assert!(request.header("Idempotency-Key").is_none());
}

#[test]
fn delete_request_reports_which_of_the_two_things_happened() {
    // Two-step by design: the first call expires, a second deletes. A caller cannot work out
    // which happened locally, so `outcome` is the answer rather than an inference.
    let stub = Stub::new(vec![(200, r#"{"short_code":"rq12","outcome":"expired"}"#)]);
    let deletion = stub.client(CREDENTIAL).delete_request("rq12").unwrap();
    let request = stub.next();
    assert_eq!(request.method, "DELETE");
    // No Idempotency-Key: the API does not deduplicate deletes, so one would be read by
    // nothing. `outcome` is what tells a caller which of the two effects happened.
    assert!(request.header("Idempotency-Key").is_none());
    assert!(
        request.target.ends_with("/requests/rq12"),
        "{}",
        request.target
    );
    assert_eq!(deletion.outcome.as_deref(), Some("expired"));
    assert_eq!(deletion.short_code, "rq12");
}

#[test]
fn a_short_code_that_would_retarget_the_request_is_refused() {
    // The submissions path interpolates the code twice over, so a value containing '/' or '?'
    // escapes /requests/ entirely - including to endpoints this SDK never exposes.
    let stub = Stub::new(vec![(200, "{}")]);
    let client = stub.client(CREDENTIAL);
    for bad in ["../../shares", "rq12?x=1", "rq12/submissions"] {
        assert!(
            matches!(client.get_request(bad), Err(Error::InvalidArgument(_))),
            "{bad:?} was accepted"
        );
        assert!(matches!(
            client.list_submissions(bad),
            Err(Error::InvalidArgument(_))
        ));
        assert!(matches!(
            client.delete_request(bad),
            Err(Error::InvalidArgument(_))
        ));
    }
    assert!(
        stub.requests
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_err(),
        "something was sent"
    );
}

// -- submissions ------------------------------------------------------------------------

#[test]
fn a_submission_round_trips_through_the_seed() {
    let seed = [9u8; 32];
    let fields = vec![
        Field::new("Your name", "Ada", "text"),
        Field::new("Staging database password", "correct horse", "password"),
    ];
    let body = format!(
        r#"{{"submissions":[{{"short_code":"sb1","created_at":"2026-09-01T10:00:00Z","data":"{}","encryption_type":"e2ee-aes256-gcm"}}],"count":1}}"#,
        sealed(&fields, &seed)
    );

    let stub = Stub::new(vec![(200, leaked(body))]);
    let page = stub.client(CREDENTIAL).list_submissions("rq12").unwrap();

    let request = stub.next();
    assert!(
        request.target.contains("/requests/rq12/submissions"),
        "{}",
        request.target
    );
    // No limit and no page: the endpoint reads neither, and sending them would document a
    // pagination this API does not have.
    assert!(!request.target.contains("limit="), "{}", request.target);
    assert!(!request.target.contains("page="), "{}", request.target);
    assert_eq!(page.count, Some(1));
    assert_eq!(page.submissions[0].short_code, "sb1");
    assert_eq!(page.submissions[0].decrypt(&seed).unwrap(), fields);
    // And nothing else opens it: another request's seed is another private key.
    assert!(page.submissions[0].decrypt(&[8u8; 32]).is_err());
}

#[test]
fn a_submission_blob_is_padded_standard_base64_not_base64url() {
    // THE encoding trap on this feature. A request's public_key travels as UNPADDED base64url
    // and a submission's data comes back as PADDED STANDARD base64. Feeding either decoder the
    // other's output produces a blob that will not open, and the failure reads as a wrong key.
    let seed = [9u8; 32];
    let fields = vec![Field::new("Password", "correct horse", "password")];
    let blob = sealed(&fields, &seed);

    assert!(blob.ends_with('='), "not padded standard base64: {blob}");
    assert_eq!(
        credenshare::decrypt_submission(&blob, &seed).unwrap(),
        fields
    );

    let same_bytes_as_base64url = URL_SAFE_NO_PAD.encode(STANDARD.decode(&blob).unwrap());
    assert!(
        credenshare::decrypt_submission(&same_bytes_as_base64url, &seed).is_err(),
        "the base64url form must not open; it is a different encoding of the same bytes"
    );
}

#[test]
fn submissions_are_one_call_and_the_walk_stops_after_it() {
    // The endpoint returns every submission in ONE response and reads neither `page` nor
    // `limit`. A walk that guessed - a full page probably has a successor - would ask for page
    // two, be handed the same rows, and re-yield them until MAX_PAGES. So: one request, and
    // every row exactly once.
    let seed = [9u8; 32];
    let fields = vec![Field::new("k", "v", "text")];
    let blob = sealed(&fields, &seed);
    let rows: Vec<String> = (0..3)
        .map(|i| format!(r#"{{"short_code":"sb{i}","data":"{blob}"}}"#))
        .collect();
    let body = format!(r#"{{"submissions":[{}],"count":3}}"#, rows.join(","));

    let stub = Stub::new(vec![(200, leaked(body))]);
    let client = stub.client(CREDENTIAL);

    let page = client.list_submissions("rq12").unwrap();
    assert_eq!(page.submissions.len(), 3);
    // The API's own figure, exposed rather than folded into a paging total it never sent.
    assert_eq!(page.count, Some(3));

    let mut seen = Vec::new();
    client
        .for_each_submission("rq12", |submission| {
            seen.push(submission.short_code.clone());
            Ok(())
        })
        .unwrap();
    assert_eq!(seen, vec!["sb0", "sb1", "sb2"], "a row was yielded twice");

    // One call for list_submissions, one for the walk, and no second page from either.
    stub.next();
    stub.next();
    assert!(
        stub.requests
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_err(),
        "the walk asked for a page the server would have answered with the same rows"
    );
}

#[test]
fn a_withheld_submission_is_counted_rather_than_hidden() {
    // The API refuses to hand a credential submissions it could read itself, and says how
    // many. Without the count a reconciliation reports them as missing.
    let stub = Stub::new(vec![(
        200,
        r#"{"submissions":[],"count":0,"skipped_not_end_to_end_encrypted":2}"#,
    )]);
    let page = stub.client(CREDENTIAL).list_submissions("rq12").unwrap();
    assert!(page.submissions.is_empty());
    assert_eq!(page.skipped_not_end_to_end_encrypted, Some(2));
}

#[test]
fn a_submission_with_no_blob_is_an_error_not_an_empty_one() {
    let stub = Stub::new(vec![(200, r#"{"submissions":[{"short_code":"sb1"}]}"#)]);
    let err = stub
        .client(CREDENTIAL)
        .list_submissions("rq12")
        .unwrap_err();
    assert!(err.to_string().contains("silently empty"), "{err}");
}

// -- stats ------------------------------------------------------------------------------

#[test]
fn stats_carry_the_counts_and_the_zero_filled_series() {
    let stub = Stub::new(vec![(
        200,
        r#"{"shares":{"active":3,"expired":1,"total_viewed":9},"daily_views":[{"date":"2026-08-31","count":0},{"date":"2026-09-01","count":4}]}"#,
    )]);
    let stats = stub.client(CREDENTIAL).get_stats().unwrap();
    let request = stub.next();
    assert_eq!(request.method, "GET");
    assert!(request.target.ends_with("/stats"), "{}", request.target);

    assert_eq!(stats.shares.active, 3);
    assert_eq!(stats.shares.expired, 1);
    assert_eq!(stats.shares.total_viewed, 9);
    // Oldest first, and a quiet day is a zero rather than a missing row.
    assert_eq!(stats.daily_views[0].date, "2026-08-31");
    assert_eq!(stats.daily_views[0].count, 0);
    assert_eq!(stats.daily_views[1].count, 4);
}

#[test]
fn an_empty_series_is_not_a_missing_one() {
    let stub = Stub::new(vec![(
        200,
        r#"{"shares":{"active":0,"expired":0,"total_viewed":0},"daily_views":[]}"#,
    )]);
    assert!(stub
        .client(CREDENTIAL)
        .get_stats()
        .unwrap()
        .daily_views
        .is_empty());
}

#[test]
fn stats_with_no_figures_at_all_are_refused() {
    // Reporting zeros for a response that carried no figures would read as an empty account.
    let stub = Stub::new(vec![(200, r#"{"daily_views":[]}"#)]);
    let err = stub.client(CREDENTIAL).get_stats().unwrap_err();
    assert!(err.to_string().contains("no share figures"), "{err}");
}

// -- the escape hatch -------------------------------------------------------------------
//
// `request` is public so a caller can reach an endpoint this crate does not model. The one
// behaviour it adds is the idempotency header, and all three cases matter.

#[test]
fn the_escape_hatch_generates_an_idempotency_key_on_a_write() {
    let stub = Stub::new(vec![(200, "{}")]);
    stub.client(CREDENTIAL)
        .request(
            "POST",
            "/anything",
            Some(serde_json::json!({"a": 1})),
            &[],
            &[],
        )
        .unwrap();
    let request = stub.next();
    let key = request
        .header("Idempotency-Key")
        .expect("a write through the escape hatch carried no idempotency key");
    assert!(!key.is_empty());
}

#[test]
fn the_escape_hatch_never_overwrites_a_supplied_idempotency_key() {
    // A caller reproducing a key across process restarts is doing the thing the header is
    // for. Replacing it would break exactly that, and the spelling must not matter.
    for supplied in ["Idempotency-Key", "idempotency-key"] {
        let stub = Stub::new(vec![(200, "{}")]);
        stub.client(CREDENTIAL)
            .request(
                "POST",
                "/anything",
                Some(serde_json::json!({})),
                &[],
                &[(supplied, "deploy-42")],
            )
            .unwrap();
        let request = stub.next();
        assert_eq!(request.header("Idempotency-Key"), Some("deploy-42"));
        // And exactly one of them, not the supplied value plus a generated one.
        assert_eq!(
            request
                .headers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case("idempotency-key"))
                .count(),
            1
        );
    }
}

#[test]
fn the_escape_hatch_leaves_a_get_alone() {
    // A read is not a write, and minting a key for every one of them fills the API's
    // 24-hour idempotency store with values nothing will ever replay.
    let stub = Stub::new(vec![(200, "{}")]);
    stub.client(CREDENTIAL)
        .request("GET", "/anything", None, &[("limit", "5".to_string())], &[])
        .unwrap();
    let request = stub.next();
    assert!(request.header("Idempotency-Key").is_none());
    assert!(request.target.contains("limit=5"), "{}", request.target);
}

#[test]
fn a_generated_idempotency_key_survives_the_retry_it_exists_for() {
    // A key that changed per attempt would make every retry a fresh request as far as the API
    // is concerned, which is the failure the header exists to prevent. Asserted on a POST,
    // because that is a method which generates one.
    let stub = Stub::with_drops(vec![(200, "{}")], 1);
    stub.client(CREDENTIAL)
        .request("POST", "/anything", Some(serde_json::json!({})), &[], &[])
        .unwrap();
    let first = stub.next();
    let second = stub.next();
    assert!(first.header("Idempotency-Key").is_some());
    assert_eq!(
        first.header("Idempotency-Key"),
        second.header("Idempotency-Key")
    );
}

#[test]
fn put_and_patch_generate_a_key_and_delete_does_not() {
    // The allow-list, stated as a test. POST/PUT/PATCH create or amend and the API reads the
    // header on them; DELETE is a write the API does NOT consult the header on, and
    // `DELETE /shares/{code}` shipped in 0.1.4 without one — so generating a key there would
    // change published bytes and buy nothing.
    for method in ["POST", "PUT", "PATCH"] {
        let stub = Stub::new(vec![(200, "{}")]);
        stub.client(CREDENTIAL)
            .request(method, "/anything", Some(serde_json::json!({})), &[], &[])
            .unwrap();
        assert!(
            stub.next().header("Idempotency-Key").is_some(),
            "{method} carried no generated idempotency key"
        );
    }

    let stub = Stub::new(vec![(200, "{}")]);
    stub.client(CREDENTIAL)
        .request("DELETE", "/anything", None, &[], &[])
        .unwrap();
    assert!(
        stub.next().header("Idempotency-Key").is_none(),
        "a DELETE was given a generated idempotency key"
    );
}

#[test]
fn a_caller_supplied_key_is_forwarded_on_a_delete() {
    // Not generating one is not the same as stripping one. A caller who wants the header on a
    // delete — talking to something sitting in front of the API, or replaying deliberately —
    // keeps it, and gets exactly one of them.
    let stub = Stub::new(vec![(200, "{}")]);
    stub.client(CREDENTIAL)
        .request(
            "DELETE",
            "/anything",
            None,
            &[],
            &[("Idempotency-Key", "operator-chose-this")],
        )
        .unwrap();
    let request = stub.next();
    assert_eq!(
        request.header("Idempotency-Key"),
        Some("operator-chose-this")
    );
    assert_eq!(
        request
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("idempotency-key"))
            .count(),
        1
    );
}

#[test]
fn a_path_with_no_leading_slash_is_refused() {
    // Otherwise it silently produces '<base>/v1shares', a 404 that reads as a missing
    // endpoint rather than as a typo.
    let stub = Stub::new(vec![(200, "{}")]);
    let err = stub
        .client(CREDENTIAL)
        .request("GET", "shares", None, &[], &[])
        .unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
    assert!(
        stub.requests
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_err(),
        "something was sent"
    );
}
