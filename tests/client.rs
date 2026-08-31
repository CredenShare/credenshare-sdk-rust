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

use credenshare::{ClientOptions, CreateParams, CredenShare, Credential, Error, Field};

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
    assert!(
        credenshare::MAX_PAGES > 0,
        "the cap the error message names must be reachable by a consumer"
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
