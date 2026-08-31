//! The CredenShare API client.
//!
//! Everything sensitive happens before a request is built. By the time anything reaches the
//! network it is ciphertext plus metadata, and the content key exists only in the link this
//! client hands back to you.

use std::fmt;
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};

use crate::crypto::{self, Field};
use crate::errors::{ApiDetails, Error, Result};

/// The production API.
pub const DEFAULT_BASE_URL: &str = "https://api.credenshare.io/v1";
/// Where recipient links live.
pub const DEFAULT_LINK_ORIGIN: &str = "https://crs.sh";

/// The only accepted encryption type. Plaintext creates are refused by the server, and this
/// client has no way to express one.
const ENCRYPTION_TYPE: &str = "e2ee-aes256-gcm";

/// The API's numeric code for an exhausted plan allowance. Distinguished from other 403s
/// because waiting does not help and the remedy is a plan change, not a retry.
const QUOTA_EXCEEDED_CODE: i64 = 61;

/// The API's numeric code for an Idempotency-Key replayed with a different body.
const IDEMPOTENCY_CONFLICT_CODE: i64 = 105;

/// Retries for network failures. Only transport errors are retried, never an HTTP status: a
/// 5xx may have committed, and this client cannot tell. A create is safe to retry because the
/// Idempotency-Key and the body are both identical on the second attempt — which is the entire
/// reason the header is mandatory.
pub const DEFAULT_MAX_RETRIES: u32 = 2;

const CREDENTIAL_PREFIX: &str = "crs_sk_live_";

/// A parsed API credential: `crs_sk_live_<keyId>.<authSecret>[.<custodySecret>]`.
///
/// The custody secret is held here but is NEVER placed in a request. It is a separate secret
/// precisely so the server cannot reconstruct the custody private key — deriving it from the
/// auth secret, which is transmitted on every call, would mean the server *could* decrypt. Not
/// that it would; that it could.
#[derive(Clone)]
pub struct Credential {
    pub key_id: String,
    auth_secret: String,
    custody_secret: Option<String>,
}

impl Credential {
    pub fn parse(raw: &str) -> Result<Self> {
        let text = raw.trim();
        if !text.starts_with(CREDENTIAL_PREFIX) {
            return Err(Error::CredentialFormat(format!(
                "a credential starts with '{CREDENTIAL_PREFIX}'; this does not look like one"
            )));
        }
        let parts: Vec<&str> = text.split('.').collect();
        if !(2..=3).contains(&parts.len()) || parts.iter().any(|p| p.is_empty()) {
            return Err(Error::CredentialFormat(format!(
                "a credential is '{CREDENTIAL_PREFIX}<keyId>.<authSecret>' with an optional \
                 '.<custodySecret>'; this has {} part(s)",
                parts.len()
            )));
        }

        // parts[0] being non-empty only proves the PREFIX is there: "crs_sk_live_.secret"
        // splits into two non-empty parts and yields an empty key id, which then goes out in
        // an Authorization header that cannot identify anything.
        let key_id = parts[0][CREDENTIAL_PREFIX.len()..].to_string();
        if key_id.is_empty() {
            return Err(Error::CredentialFormat(
                "the credential has no key id between the prefix and the first '.'".to_string(),
            ));
        }

        Ok(Self {
            key_id,
            auth_secret: parts[1].to_string(),
            custody_secret: parts.get(2).map(|s| s.to_string()),
        })
    }

    pub fn has_custody(&self) -> bool {
        self.custody_secret.is_some()
    }

    /// The two-part value sent in the Authorization header.
    ///
    /// Assembled from the parts rather than by trimming the original string, so a third part
    /// cannot survive a formatting mistake and reach the wire.
    fn bearer(&self) -> String {
        format!("{CREDENTIAL_PREFIX}{}.{}", self.key_id, self.auth_secret)
    }

    /// The base64url custody public key to register for account custody.
    ///
    /// Only the public half leaves this machine. Any machine holding the credential derives the
    /// same keypair, so ephemeral runners need no local state.
    pub fn custody_public_key(&self) -> Result<String> {
        let secret = self.custody_secret.as_deref().ok_or_else(|| {
            Error::CredentialFormat(
                "this credential has no custody secret, so no custody keypair exists".into(),
            )
        })?;
        Ok(crypto::custody_keypair(secret)?.public_key_b64url())
    }
}

impl fmt::Debug for Credential {
    /// Never render the secrets. A credential in a log line is a credential that has to be
    /// rotated, and `#[derive(Debug)]` is how that usually happens.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<Credential {} ({})>",
            self.key_id,
            if self.has_custody() {
                "with custody"
            } else {
                "no custody"
            }
        )
    }
}

impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// A created share, and the only place its link exists.
pub struct Share {
    pub short_code: String,
    /// The full recipient link, INCLUDING the key fragment. Treat this as the secret itself:
    /// anyone holding it can read the content, and CredenShare cannot.
    pub link: String,
    /// The content key, if you need to build your own link or decrypt later.
    pub content_key: [u8; 32],
    pub expired_at: Option<String>,
    pub custody: Option<String>,
}

impl fmt::Debug for Share {
    /// The link carries the key, so it is not printed by default.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<Share {} (link withheld)>", self.short_code)
    }
}

/// Metadata for a share. Never content, and never a key.
///
/// Deliberately thin, because the API is: `/v1` returns the short code and the expiry and
/// nothing else. There is no title here even though you supply one on create — the server does
/// not return it, and a field that is always `None` reads as broken rather than absent.
#[derive(Debug, Clone)]
pub struct ShareSummary {
    pub short_code: String,
    pub expired_at: Option<String>,
}

/// One page of shares, with the paging figures attached.
///
/// A bare `Vec` would leave a caller guessing whether more exists, and a caller who has to
/// guess guesses wrong — usually by stopping at the first short page.
#[derive(Debug, Clone)]
pub struct SharePage {
    pub shares: Vec<ShareSummary>,
    pub page: u32,
    pub limit: u32,
    pub total: Option<u32>,
    pub total_pages: Option<u32>,
}

impl SharePage {
    /// Whether another page exists.
    ///
    /// Falls back deliberately rather than answering `false` when the server omits the paging
    /// figures: reporting "no more" on a full page is what makes [`Client::for_each_share`]
    /// stop after page one and return a fraction of the account as though it were all of it.
    pub fn has_more(&self) -> bool {
        if let Some(total_pages) = self.total_pages {
            return self.page < total_pages;
        }
        if let Some(total) = self.total {
            return u64::from(self.page) * u64::from(self.limit) < u64::from(total);
        }
        // Nothing to go on but the page itself: a full page probably has a successor, and a
        // short one ends the walk.
        !self.shares.is_empty() && self.shares.len() as u32 >= self.limit
    }
}

/// A share to create.
#[derive(Debug, Default)]
pub struct CreateParams {
    pub title: String,
    pub fields: Vec<Field>,
    pub description: Option<String>,
    pub passcode: Option<String>,
    pub expired_at: Option<String>,
    pub access_counts_left: Option<u32>,
    pub timed_view: Option<u32>,

    /// Generated per call unless you set it. Setting your own does NOT make a second call a
    /// no-op: encryption is randomised per call, so the body differs and the API refuses with
    /// [`Error::IdempotencyConflict`]. That is the header working, not failing. What it
    /// protects is a network retry, which this client performs itself.
    pub idempotency_key: Option<String>,

    /// Create a share under a key you already hold — a link you handed out before the create,
    /// or a fixed key in a test. It does not make the request body reproducible.
    pub content_key: Option<[u8; 32]>,
}

/// Client configuration. `ClientOptions::default()` targets production.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub base_url: String,
    pub link_origin: String,
    pub timeout: Duration,
    pub max_retries: u32,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            link_origin: DEFAULT_LINK_ORIGIN.to_string(),
            timeout: Duration::from_secs(30),
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }
}

/// The API client.
#[derive(Debug)]
pub struct CredenShare {
    pub credential: Credential,
    options: ClientOptions,
    agent: ureq::Agent,
}

impl CredenShare {
    /// Build a client from a credential, against production.
    pub fn new(credential: &str) -> Result<Self> {
        Self::with_options(credential, ClientOptions::default())
    }

    pub fn with_options(credential: &str, mut options: ClientOptions) -> Result<Self> {
        options.base_url = options.base_url.trim_end_matches('/').to_string();
        options.link_origin = options.link_origin.trim_end_matches('/').to_string();

        let agent = ureq::AgentBuilder::new()
            .timeout(options.timeout)
            .user_agent(&format!("credenshare-rust/{}", crate::VERSION))
            .build();

        Ok(Self {
            credential: Credential::parse(credential)?,
            options,
            agent,
        })
    }

    /// Assemble a recipient link.
    ///
    /// The key lives in the fragment, which browsers never send to a server. That is what makes
    /// the link readable by its holder and opaque to us.
    pub fn link_for(&self, short_code: &str, content_key: &[u8]) -> Result<String> {
        Ok(format!(
            "{}/{short_code}#{}",
            self.options.link_origin,
            crypto::encode_fragment(content_key)?
        ))
    }

    /// Not implemented, on purpose.
    ///
    /// The recipient path is deliberately absent from the API, because bearer auth skips the
    /// proof-of-work and captcha gates that protect it, and exposing it to a credential would
    /// be an enumeration bypass. Open the link in a browser, or use
    /// [`crate::decrypt_content`] on a blob you already hold.
    pub fn read_link(&self, _link: &str) -> Result<Vec<Field>> {
        Err(Error::Internal(
            "the recipient read path is not exposed over the API by design; open the link in a \
             browser, or use decrypt_content on a blob you already have",
        ))
    }

    /// Encrypt `fields` locally and create a share.
    pub fn create_share(&self, params: CreateParams) -> Result<Share> {
        let content_key = params.content_key.unwrap_or_else(crypto::new_content_key);
        let blob =
            crypto::encrypt_content(&content_key, &params.fields, params.passcode.as_deref())?;

        let mut body = Map::new();
        body.insert("title".into(), json!(params.title));
        body.insert("encryption_type".into(), json!(ENCRYPTION_TYPE));
        body.insert("data".into(), json!(blob));
        body.insert(
            "access_token".into(),
            json!(crypto::access_token(&content_key)?),
        );

        if let Some(description) = &params.description {
            body.insert("description".into(), json!(description));
        }
        if let Some(passcode) = &params.passcode {
            body.insert(
                "passcode_verifier".into(),
                json!(crypto::passcode_verifier(passcode)?),
            );
        }
        if let Some(expired_at) = &params.expired_at {
            body.insert("expired_at".into(), json!(expired_at));
        }
        if let Some(count) = params.access_counts_left {
            body.insert("access_counts_left".into(), json!(count));
        }
        if let Some(seconds) = params.timed_view {
            body.insert("timed_view".into(), json!(seconds));
        }

        // Required by the API, not optional. A retried automation must not create a second copy
        // of a credential in the world, with its own link and audit trail, that the caller does
        // not know exists.
        let idempotency_key = params.idempotency_key.unwrap_or_else(random_token);

        let data = self.request(
            "POST",
            "/shares",
            Some(Value::Object(body)),
            &[],
            &[("Idempotency-Key", idempotency_key.as_str())],
        )?;

        let short_code = data
            .get("short_code")
            .and_then(Value::as_str)
            .ok_or(Error::Internal("the API returned no short_code"))?
            .to_string();

        Ok(Share {
            link: self.link_for(&short_code, &content_key)?,
            short_code,
            content_key,
            expired_at: data
                .get("expired_at")
                .and_then(Value::as_str)
                .map(str::to_string),
            custody: data
                .get("custody")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    /// One page of the account's shares, newest first. Metadata only.
    pub fn list_shares(&self, limit: u32, page: u32) -> Result<SharePage> {
        let limit = if limit == 0 { 25 } else { limit };
        let page = if page == 0 { 1 } else { page };
        let data = self.request(
            "GET",
            "/shares",
            None,
            &[("limit", limit.to_string()), ("page", page.to_string())],
            &[],
        )?;

        // A row this client cannot read is an error, not an omission. Dropping it silently
        // while `total` still reports the true count produces a list that is quietly short,
        // and a reconciliation against it reports shares as missing that are not.
        let shares: Vec<ShareSummary> = match data.get("shares").and_then(Value::as_array) {
            None => Vec::new(),
            Some(rows) => rows
                .iter()
                .map(|row| {
                    let short_code =
                        row.get("short_code")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                Error::InternalOwned(
                                    "a share row carried no string short_code; refusing to \
                                     return a list that is silently short"
                                        .to_string(),
                                )
                            })?;
                    Ok(ShareSummary {
                        short_code: short_code.to_string(),
                        expired_at: row
                            .get("expired_at")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        };

        let pagination = data.get("pagination");
        let read = |name: &str| {
            pagination
                .and_then(|p| p.get(name))
                .and_then(Value::as_u64)
                .map(|v| v as u32)
        };

        Ok(SharePage {
            shares,
            page: read("page").unwrap_or(page),
            limit: read("limit").unwrap_or(limit),
            total: read("total"),
            total_pages: read("total_pages"),
        })
    }

    /// Every share, page by page, handed to `visit`.
    ///
    /// Written here because the hand-rolled version is usually wrong in the same way: it stops
    /// on the first page shorter than `limit`, which is a page the server is entitled to return
    /// in the middle of a result set.
    pub fn for_each_share<F>(&self, limit: u32, mut visit: F) -> Result<()>
    where
        F: FnMut(&ShareSummary) -> Result<()>,
    {
        let limit = if limit == 0 { 100 } else { limit };
        let mut page = 1u32;
        loop {
            let batch = self.list_shares(limit, page)?;
            for share in &batch.shares {
                visit(share)?;
            }
            if !batch.has_more() {
                return Ok(());
            }
            page += 1;
        }
    }

    /// One share's metadata.
    ///
    /// Does not consume a view, evaluate a passcode, or return content. A share belonging to
    /// another account reports exactly as one that does not exist.
    pub fn get_share(&self, short_code: &str) -> Result<ShareSummary> {
        check_short_code(short_code)?;
        let data = self.request("GET", &format!("/shares/{short_code}"), None, &[], &[])?;
        Ok(ShareSummary {
            short_code: data
                .get("short_code")
                .and_then(Value::as_str)
                .unwrap_or(short_code)
                .to_string(),
            expired_at: data
                .get("expired_at")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    /// Expire a share immediately.
    ///
    /// Irreversible: afterwards the content is unrecoverable by anyone, including CredenShare —
    /// the key was never ours, and now the ciphertext is gone too.
    ///
    /// The share is REMOVED, not flagged. A later [`Self::get_share`] returns
    /// [`Error::NotFound`] rather than a row with an expiry set, and it drops out of
    /// [`Self::list_shares`]. Worth knowing if you reconcile against your own records: a share
    /// you expired and one that never existed look identical afterwards.
    pub fn expire_share(&self, short_code: &str) -> Result<()> {
        check_short_code(short_code)?;
        self.request("DELETE", &format!("/shares/{short_code}"), None, &[], &[])?;
        Ok(())
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        query: &[(&str, String)],
        headers: &[(&str, &str)],
    ) -> Result<Value> {
        let authorization = format!("Bearer {}", self.credential.bearer());
        // Belt and braces. `bearer` is assembled from parts so a custody secret cannot reach
        // the header, but this asserts the property at the boundary rather than trusting a
        // constructor elsewhere in the file.
        if let Some(custody) = &self.credential.custody_secret {
            if authorization.contains(custody.as_str()) {
                return Err(Error::CustodySecretTransmitted);
            }
        }

        let url = format!("{}{path}", self.options.base_url);
        let mut attempt = 0u32;

        loop {
            let mut request = self
                .agent
                .request(method, &url)
                .set("Authorization", &authorization);
            for (key, value) in query {
                request = request.query(key, value);
            }
            for (key, value) in headers {
                request = request.set(key, value);
            }

            let outcome = match &body {
                Some(value) => request.send_json(value.clone()),
                None => request.call(),
            };

            match outcome {
                Ok(response) => return parse_success(response),
                Err(ureq::Error::Status(status, response)) => {
                    return Err(error_for(status, response))
                }
                Err(transport) => {
                    // Retry only the failures that prove nothing was received. A 5xx might have
                    // committed and this client cannot tell, so it is surfaced above rather
                    // than repeated.
                    if attempt >= self.options.max_retries {
                        return Err(Error::Transport(format!(
                            "could not reach the API after {} attempt(s): {transport}",
                            attempt + 1
                        )));
                    }
                    // Plain exponential backoff, no jitter: the retry count is 2 by default, so
                    // a thundering herd is not the failure mode worth complicating this for.
                    std::thread::sleep(Duration::from_millis(500 * (1 << attempt)));
                    attempt += 1;
                }
            }
        }
    }
}

/// Reject a short code that could change which endpoint the request reaches.
///
/// The code is interpolated into the request path. Without this, a value containing `/`, `?`
/// or `#` escapes `/shares/` entirely and retargets an authenticated request — including at
/// endpoints this SDK never exposes.
fn check_short_code(code: &str) -> Result<()> {
    if code.is_empty() || code.len() > 64 {
        return Err(Error::InvalidArgument(format!(
            "a short code is 1-64 characters; this one is {}",
            code.len()
        )));
    }
    if !code
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::InvalidArgument(
            "a short code is alphanumeric with - and _; this one would change the request path"
                .to_string(),
        ));
    }
    Ok(())
}

fn parse_success(response: ureq::Response) -> Result<Value> {
    let text = response
        .into_string()
        .map_err(|e| Error::Transport(format!("reading the response: {e}")))?;
    if text.is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    // Swallowing the parse failure turned a successful create into an empty object, so the
    // caller got Error::Internal from the missing short_code and lost the content key for a
    // share that exists. Say what actually arrived instead.
    serde_json::from_str(&text).map_err(|e| {
        Error::InternalOwned(format!(
            "the API returned a success whose body is not JSON ({e}): {}",
            text.chars().take(200).collect::<String>()
        ))
    })
}

fn error_for(status: u16, response: ureq::Response) -> Error {
    let request_id = response
        .header("x-request-id")
        .or_else(|| response.header("x-amzn-requestid"))
        .map(str::to_string);
    let retry_after = response
        .header("retry-after")
        .and_then(|v| v.parse::<u64>().ok());

    let text = response.into_string().unwrap_or_default();
    let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);

    let message = parsed
        .get("message")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            if text.is_empty() {
                format!("HTTP {status}")
            } else {
                text.chars().take(200).collect()
            }
        });
    let code = parsed.get("error_code").and_then(Value::as_i64);
    let details = ApiDetails {
        message,
        status,
        code,
        request_id,
    };

    match status {
        401 => Error::Authentication(details),
        // A spent allowance is a 403 like a missing scope, but the remedies are opposite: one
        // needs a plan change, the other a different key. The numeric code separates them.
        403 if code == Some(QUOTA_EXCEEDED_CODE) => Error::QuotaExceeded(details),
        403 => Error::Permission(details),
        404 => Error::NotFound(details),
        409 if code == Some(IDEMPOTENCY_CONFLICT_CODE) => Error::IdempotencyConflict(details),
        429 => Error::RateLimited {
            details,
            retry_after,
        },
        503 => Error::ServiceUnavailable(details),
        _ => Error::Api(details),
    }
}

fn random_token() -> String {
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
