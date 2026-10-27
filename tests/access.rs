//! The /v1 additions of Gitea #404 (the access log, capabilities, the expired lists and
//! activity emails) and #412 (links on a team's custom domain), against a loopback server as in
//! `client.rs`. This one can also send an `ETag` and a body-less 304, which the conditional
//! reads need.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use credenshare::{
    AccessLogParams, ClientOptions, CreateParams, CreateRequestParams, CredenShare, Error, Field,
    ListStatus, RequestField, ShareOptions, DEFAULT_LINK_ORIGIN, FIELD_TYPES, NOTIFY_ON_EVENTS,
    UNLIMITED,
};

const CREDENTIAL: &str = "crs_sk_live_abc123.authsecretvalue.custodysecretvalue";

#[derive(Debug, Clone)]
struct Captured {
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

    fn query(&self, name: &str) -> Option<String> {
        let (_, query) = self.target.split_once('?')?;
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| value.replace("%3A", ":").replace("%2F", "/"))
        })
    }
}

/// One canned reply: status, body (empty for none), and an `ETag` to send.
type Reply = (u16, String, Option<&'static str>);

struct Stub {
    base_url: String,
    requests: mpsc::Receiver<Captured>,
}

impl Stub {
    fn new(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binding a loopback port");
        let port = listener.local_addr().unwrap().port();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            for (answered, stream) in listener.incoming().enumerate() {
                let Ok(mut stream) = stream else { break };
                let _ = sender.send(read_request(&mut stream));
                let (status, body, etag) = replies
                    .get(answered)
                    .cloned()
                    .unwrap_or_else(|| replies.last().cloned().unwrap());
                let etag = etag.map(|t| format!("ETag: {t}\r\n")).unwrap_or_default();
                let response = if status == 304 {
                    format!("HTTP/1.1 304 X\r\n{etag}Connection: close\r\n\r\n")
                } else {
                    format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{etag}\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            requests: receiver,
        }
    }

    fn client(&self) -> CredenShare {
        CredenShare::with_options(
            CREDENTIAL,
            ClientOptions {
                base_url: self.base_url.clone(),
                link_origin: "https://crs.sh".into(),
                ..Default::default()
            },
        )
        .expect("building the client")
    }

    /// A client with no link origin configured, so it asks the API (Gitea #412).
    fn unconfigured(&self) -> CredenShare {
        CredenShare::with_options(
            CREDENTIAL,
            ClientOptions {
                base_url: self.base_url.clone(),
                max_retries: 0,
                ..Default::default()
            },
        )
        .expect("building the client")
    }

    /// Every request the server has received so far.
    fn drain(&self) -> Vec<Captured> {
        let mut seen = Vec::new();
        while let Ok(request) = self
            .requests
            .recv_timeout(std::time::Duration::from_millis(200))
        {
            seen.push(request);
        }
        seen
    }

    fn next(&self) -> Captured {
        self.requests
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("no request arrived")
    }

    fn sent_nothing(&self) -> bool {
        self.requests
            .recv_timeout(std::time::Duration::from_millis(200))
            .is_err()
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Captured {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut start = String::new();
    reader.read_line(&mut start).unwrap_or_default();
    let target = start
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
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
        target,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    }
}

fn access_log_body(next: Option<&str>) -> String {
    let next = next.map_or("null".to_string(), |n| format!("\"{n}\""));
    format!(
        r#"{{"short_code":"AbC123","entries":[
            {{"accessed_at":"2026-10-25T18:00:00Z","accessed_ip":"203.0.113.7","platform":"macOS","user_agent":"Mozilla/5.0","failed_passcode":false,"signed_in":true}},
            {{"accessed_at":"2026-10-25T17:00:00Z","accessed_ip":"198.51.100.2","platform":"Linux","user_agent":null,"failed_passcode":true,"signed_in":false}}],
            "next_cursor":{next},"retention_days":90,
            "effective_from":"2026-07-27T18:00:00Z","effective_to":"2026-10-25T18:00:00Z"}}"#
    )
}

#[test]
fn the_access_log_reads_a_page_its_window_and_its_etag() {
    let stub = Stub::new(vec![(200, access_log_body(Some("c1")), Some("W/\"abc\""))]);
    let page = stub
        .client()
        .get_access_log(
            "AbC123",
            &AccessLogParams {
                limit: Some(10),
                cursor: Some("prev".into()),
                from: Some("2026-10-01T00:00:00Z".into()),
                to: Some("2026-10-31T23:59:59Z".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(page.short_code, "AbC123");
    assert_eq!(page.entries.len(), 2);
    let (first, second) = (&page.entries[0], &page.entries[1]);
    assert_eq!(first.accessed_ip, "203.0.113.7");
    assert_eq!(first.user_agent.as_deref(), Some("Mozilla/5.0"));
    assert!(first.signed_in && !first.failed_passcode);
    // A null user agent stays None rather than becoming a string a caller would match on.
    assert!(second.user_agent.is_none() && second.failed_passcode && !second.signed_in);
    assert_eq!(page.next_cursor.as_deref(), Some("c1"));
    assert!(page.has_more());
    assert_eq!(page.retention_days, 90);
    assert_eq!(page.effective_from.as_deref(), Some("2026-07-27T18:00:00Z"));
    assert_eq!(page.etag.as_deref(), Some("W/\"abc\""));
    assert!(!page.not_modified);

    let sent = stub.next();
    assert!(
        sent.target.starts_with("/shares/AbC123/access-log?"),
        "{}",
        sent.target
    );
    assert_eq!(sent.query("limit").as_deref(), Some("10"));
    assert_eq!(sent.query("cursor").as_deref(), Some("prev"));
    assert_eq!(sent.query("from").as_deref(), Some("2026-10-01T00:00:00Z"));
    assert_eq!(sent.query("to").as_deref(), Some("2026-10-31T23:59:59Z"));
    assert!(sent.header("if-none-match").is_none());
    assert!(sent.header("idempotency-key").is_none());
}

#[test]
fn an_unchanged_page_is_not_modified_rather_than_an_error() {
    let stub = Stub::new(vec![(304, String::new(), Some("W/\"abc\""))]);
    let page = stub
        .client()
        .get_access_log(
            "AbC123",
            &AccessLogParams {
                if_none_match: Some("W/\"abc\"".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(page.not_modified);
    assert_eq!(page.etag.as_deref(), Some("W/\"abc\""));
    assert!(page.entries.is_empty());
    assert_eq!(page.short_code, "AbC123");
    assert_eq!(stub.next().header("if-none-match"), Some("W/\"abc\""));
}

#[test]
fn access_log_refusals_map_to_their_errors() {
    for (status, check) in [
        (
            403u16,
            (|e: &Error| matches!(e, Error::Permission(_))) as fn(&Error) -> bool,
        ),
        (404, |e| matches!(e, Error::NotFound(_))),
        (400, |e| matches!(e, Error::Api(_))),
    ] {
        let stub = Stub::new(vec![(
            status,
            r#"{"message":"no","error_code":1}"#.into(),
            None,
        )]);
        let err = stub
            .client()
            .get_access_log("AbC123", &AccessLogParams::default())
            .unwrap_err();
        assert!(check(&err), "{status} gave {err:?}");
    }
}

#[test]
fn access_log_options_are_checked_before_any_request() {
    for (code, limit) in [("AbC123", Some(101)), ("AbC123", Some(0)), ("a/b", None)] {
        let stub = Stub::new(vec![(200, access_log_body(None), None)]);
        let err = stub
            .client()
            .get_access_log(
                code,
                &AccessLogParams {
                    limit,
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{err:?}");
        assert!(stub.sent_nothing());
    }
}

#[test]
fn the_walk_follows_every_cursor_and_never_revalidates() {
    let stub = Stub::new(vec![
        (200, access_log_body(Some("c1")), None),
        (200, access_log_body(Some("c2")), None),
        (200, access_log_body(None), None),
    ]);
    let mut seen = 0;
    stub.client()
        .for_each_access_log_entry(
            "AbC123",
            &AccessLogParams {
                limit: Some(2),
                if_none_match: Some("W/\"x\"".into()),
                ..Default::default()
            },
            |_| {
                seen += 1;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(seen, 6);
    let sent: Vec<Captured> = (0..3).map(|_| stub.next()).collect();
    assert_eq!(sent[1].query("cursor").as_deref(), Some("c1"));
    assert_eq!(sent[2].query("cursor").as_deref(), Some("c2"));
    for request in &sent {
        // A walk never revalidates: a 304 on page one would end it having read nothing.
        assert!(request.header("if-none-match").is_none());
        assert_eq!(request.query("limit").as_deref(), Some("2"));
    }
}

#[test]
fn the_walk_refuses_a_cursor_that_does_not_move() {
    let stub = Stub::new(vec![(200, access_log_body(Some("same")), None)]);
    let err = stub
        .client()
        .for_each_access_log_entry("AbC123", &AccessLogParams::default(), |_| Ok(()))
        .unwrap_err();
    assert!(matches!(err, Error::Internal(_)), "{err:?}");
}

const PAGE: &str = r#"{"shares":[{"short_code":"old1","expired_at":"2026-10-20T00:00:00Z"}],
    "requests":[{"short_code":"req1","expired_at":"2026-10-20T00:00:00Z"}],
    "pagination":{"page":1,"limit":25,"total":1,"total_pages":1}}"#;

#[test]
fn the_old_lists_send_what_they_always_have() {
    let stub = Stub::new(vec![(200, PAGE.into(), None)]);
    let client = stub.client();
    client.list_shares(25, 1).unwrap();
    client.list_requests(25, 1).unwrap();
    for _ in 0..2 {
        assert!(stub.next().query("status").is_none());
    }
}

#[test]
fn the_expired_half_is_asked_for_in_lists_and_walks() {
    let stub = Stub::new(vec![(200, PAGE.into(), None)]);
    let client = stub.client();
    let shares = client
        .list_shares_by_status(ListStatus::Expired, 25, 1)
        .unwrap();
    assert_eq!(shares.shares[0].short_code, "old1");
    client
        .list_requests_by_status(ListStatus::Expired, 25, 1)
        .unwrap();
    client
        .for_each_share_by_status(ListStatus::Expired, 25, |_| Ok(()))
        .unwrap();
    client
        .for_each_request_by_status(ListStatus::Active, 25, |_| Ok(()))
        .unwrap();
    let statuses: Vec<Option<String>> = (0..4).map(|_| stub.next().query("status")).collect();
    assert_eq!(
        statuses,
        ["expired", "expired", "expired", "active"].map(|s| Some(s.to_string()))
    );
}

fn capabilities_body(org: &str, policy: &str) -> String {
    format!(
        r#"{{"api_version":"1",
        "key":{{"key_id":"abc123","scopes":["shares:write","audit:read"],"custody_level":1,"organization_id":{org},"rate_limit_rpm":100}},
        "plan":{{"code":"business","name":"Business"}},
        "limits":{{"max_shares":-1,"remaining_shares":-1,"max_fields":20,"max_days_access_logs":90,"max_api_keys":10,"max_webhooks":5}},
        "features":{{"secure_requests":true,"zero_knowledge":false}},
        "sharing_policy":{policy},
        "field_types":["text","password","date","multiline","markdown","source_code","url","qr"],
        "notify_on_events":["viewed","denied","expired","deleted"]}}"#
    )
}

#[test]
fn capabilities_for_a_personal_key() {
    let stub = Stub::new(vec![(
        200,
        capabilities_body("null", "null"),
        Some("W/\"cap\""),
    )]);
    let caps = stub.client().get_capabilities(None).unwrap();
    assert_eq!(caps.api_version, "1");
    assert_eq!(caps.key.key_id, "abc123");
    assert_eq!(caps.key.scopes, ["shares:write", "audit:read"]);
    assert_eq!(caps.key.custody_level, 1);
    assert!(caps.key.organization_id.is_none());
    assert_eq!(caps.key.rate_limit_rpm, 100);
    assert_eq!(
        (caps.plan.code.as_str(), caps.plan.name.as_str()),
        ("business", "Business")
    );
    assert_eq!(caps.limits.max_shares, UNLIMITED);
    assert_eq!(caps.limits.max_days_access_logs, 90);
    assert_eq!(caps.features.get("secure_requests"), Some(&true));
    assert_eq!(caps.features.get("zero_knowledge"), Some(&false));
    assert!(caps.sharing_policy.is_none());
    // The API publishes the lists this crate carries; they must agree.
    assert_eq!(caps.field_types, FIELD_TYPES);
    assert_eq!(caps.notify_on_events, NOTIFY_ON_EVENTS);
    assert_eq!(caps.etag.as_deref(), Some("W/\"cap\""));
    assert!(!caps.not_modified);
    assert_eq!(stub.next().target, "/capabilities");
}

#[test]
fn capabilities_for_a_team_key_carry_its_policy() {
    let stub = Stub::new(vec![(
        200,
        capabilities_body("\"org-1\"", r#"{"require_passcode":true}"#),
        None,
    )]);
    let caps = stub.client().get_capabilities(None).unwrap();
    assert_eq!(caps.key.organization_id.as_deref(), Some("org-1"));
    assert_eq!(
        caps.sharing_policy.unwrap().get("require_passcode"),
        Some(&serde_json::Value::Bool(true))
    );
}

#[test]
fn unchanged_capabilities_are_not_modified() {
    let stub = Stub::new(vec![(304, String::new(), Some("W/\"cap\""))]);
    let caps = stub.client().get_capabilities(Some("W/\"cap\"")).unwrap();
    assert!(caps.not_modified);
    assert_eq!(caps.etag.as_deref(), Some("W/\"cap\""));
    assert_eq!(stub.next().header("if-none-match"), Some("W/\"cap\""));
}

fn field() -> Field {
    Field::new("k", "v", "text")
}

#[test]
fn notify_on_is_sent_when_set_and_absent_otherwise() {
    let stub = Stub::new(vec![(201, r#"{"short_code":"abc"}"#.into(), None)]);
    let client = stub.client();
    let params = || CreateParams {
        title: "t".into(),
        fields: vec![field()],
        ..Default::default()
    };
    client
        .create_share_with(
            params(),
            ShareOptions::default().notify_on(["viewed", "denied"]),
        )
        .unwrap();
    client.create_share(params()).unwrap();
    client
        .create_share_with(params(), ShareOptions::default())
        .unwrap();
    let bodies: Vec<serde_json::Value> = (0..3)
        .map(|_| serde_json::from_str(&stub.next().body).unwrap())
        .collect();
    assert_eq!(
        bodies[0]["notify_on"],
        serde_json::json!(["viewed", "denied"])
    );
    assert!(bodies[1].get("notify_on").is_none());
    assert!(bodies[2].get("notify_on").is_none());
}

#[test]
fn notify_on_is_checked_as_the_api_checks_it() {
    for events in [
        vec!["opened"],
        vec!["viewed", "viewed"],
        vec!["Viewed"],
        vec!["viewed", "denied", "expired", "deleted", "viewed"],
    ] {
        let stub = Stub::new(vec![(201, r#"{"short_code":"abc"}"#.into(), None)]);
        let err = stub
            .client()
            .create_share_with(
                CreateParams {
                    title: "t".into(),
                    fields: vec![field()],
                    ..Default::default()
                },
                ShareOptions::default().notify_on(events.clone()),
            )
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "{events:?} gave {err:?}"
        );
        assert!(stub.sent_nothing(), "{events:?} reached the API");
    }
}

// -- links on a team's own domain (Gitea #412) ------------------------------------------------

fn created(code: &str) -> Reply {
    (201, format!(r#"{{"short_code":"{code}"}}"#), None)
}

fn capabilities_with_origin(origin: &str) -> Reply {
    (
        200,
        format!(r#"{{"api_version":"1","key":{{"key_id":"abc123"}},"link_origin":{origin}}}"#),
        None,
    )
}

fn capability_calls(requests: &[Captured]) -> usize {
    requests
        .iter()
        .filter(|r| r.target == "/capabilities")
        .count()
}

fn share_params() -> CreateParams {
    CreateParams {
        title: "t".into(),
        fields: vec![field()],
        ..Default::default()
    }
}

#[test]
fn a_team_keys_links_are_on_its_custom_domain_asked_once() {
    let stub = Stub::new(vec![
        created("abc123"),
        capabilities_with_origin(r#""https://cd-test.credenshare.io""#),
        created("def456"),
    ]);
    let client = stub.unconfigured();
    let first = client.create_share(share_params()).unwrap();
    let second = client.create_share(share_params()).unwrap();
    for share in [&first, &second] {
        let prefix = format!("https://cd-test.credenshare.io/{}#1", share.short_code);
        assert!(share.link.starts_with(&prefix), "{}", share.link);
    }
    // The link helpers agree with what the creates returned.
    assert_eq!(
        client
            .link_for(&first.short_code, &first.content_key)
            .unwrap(),
        first.link
    );
    assert_eq!(client.link_origin(), "https://cd-test.credenshare.io");
    assert_eq!(capability_calls(&stub.drain()), 1);
}

#[test]
fn a_configured_origin_wins_and_nothing_is_asked() {
    let stub = Stub::new(vec![created("abc123")]);
    let client = CredenShare::with_options(
        CREDENTIAL,
        ClientOptions {
            base_url: stub.base_url.clone(),
            link_origin: "https://links.example.com/".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let share = client.create_share(share_params()).unwrap();
    assert!(
        share.link.starts_with("https://links.example.com/abc123#"),
        "{}",
        share.link
    );
    let seen = stub.drain();
    assert_eq!((seen.len(), capability_calls(&seen)), (1, 0));
}

#[test]
fn no_team_origin_or_a_failed_answer_gives_the_default() {
    let answers: Vec<(&str, Reply)> = vec![
        ("a null origin", capabilities_with_origin("null")),
        (
            "no member at all",
            (200, r#"{"api_version":"1"}"#.into(), None),
        ),
        (
            "a refusal",
            (403, r#"{"message":"no","error_code":78}"#.into(), None),
        ),
        (
            "a server error",
            (500, r#"{"message":"boom"}"#.into(), None),
        ),
        (
            "a path",
            capabilities_with_origin(r#""https://cd.example.com/evil""#),
        ),
        (
            "plain http",
            capabilities_with_origin(r#""http://cd.example.com""#),
        ),
        (
            "credentials",
            capabilities_with_origin(r#""https://user@cd.example.com""#),
        ),
        (
            "a query",
            capabilities_with_origin(r#""https://cd.example.com?x=1""#),
        ),
        ("not a string", capabilities_with_origin("42")),
    ];
    for (name, answer) in answers {
        let stub = Stub::new(vec![created("abc123"), answer, created("def456")]);
        let client = stub.unconfigured();
        for _ in 0..2 {
            let share = client
                .create_share(share_params())
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(
                share.link.starts_with(&format!("{DEFAULT_LINK_ORIGIN}/")),
                "{name}: {}",
                share.link
            );
        }
        // The answer is kept, a "none" or a failure included: one question per client.
        assert_eq!(capability_calls(&stub.drain()), 1, "{name}");
    }
}

#[test]
fn a_secure_requests_links_are_on_the_team_domain_too() {
    let stub = Stub::new(vec![
        created("rq01"),
        capabilities_with_origin(r#""https://cd-test.credenshare.io""#),
    ]);
    let request = stub
        .unconfigured()
        .create_request(CreateRequestParams {
            title: "t".into(),
            fields: vec![RequestField::new("Password", "password")],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        request.collect_link,
        "https://cd-test.credenshare.io/r/rq01"
    );
    assert!(request
        .access_link
        .starts_with("https://cd-test.credenshare.io/r/rq01#1"));
}

#[test]
fn the_capabilities_type_carries_the_origin() {
    let team = Stub::new(vec![capabilities_with_origin(
        r#""https://cd-test.credenshare.io""#,
    )]);
    assert_eq!(
        team.unconfigured()
            .get_capabilities(None)
            .unwrap()
            .link_origin
            .as_deref(),
        Some("https://cd-test.credenshare.io")
    );
    let personal = Stub::new(vec![capabilities_with_origin("null")]);
    assert!(personal
        .unconfigured()
        .get_capabilities(None)
        .unwrap()
        .link_origin
        .is_none());
}
