//! Errors whose variants imply remedies.
//!
//! Several of these look identical on screen and have opposite fixes — a link that arrived
//! without its key versus a link that arrived damaged; a spent plan allowance versus a rate
//! limit. Matching on the variant is the difference between a caller who knows what to do and
//! one who retries forever.

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A link arrived with no key at all.
    ///
    /// Usually something stripped the fragment: a chat client that "cleaned" the URL, a
    /// redirect, a copy that stopped at the `#`. The remedy is to ask for the link again — not
    /// to ask for the share to be recreated.
    MissingKey,

    /// A key is present but unusable — truncated, or from a newer format.
    MalformedKey(String),

    /// Content could not be read: a wrong passcode, or altered ciphertext.
    ///
    /// The two are indistinguishable on purpose. Telling them apart would hand an attacker an
    /// oracle for guessing passcodes.
    WireFormat(String),

    /// A credential is not in the `crs_sk_live_<keyId>.<authSecret>[.<custodySecret>]` shape.
    CredentialFormat(String),

    /// The custody secret was about to be transmitted.
    ///
    /// Raised at the request boundary rather than trusted to a constructor elsewhere. If this
    /// ever fires, rotate the credential: the guarantee it exists to provide — that the server
    /// *cannot* reconstruct the custody private key — is gone the moment it reaches the wire.
    CustodySecretTransmitted,

    /// The credential is unknown, revoked or expired. Mint a new one.
    Authentication(ApiDetails),

    /// Valid credential, not allowed to do this: a missing scope, or a plan without API access.
    Permission(ApiDetails),

    /// No such share on this account.
    ///
    /// A share belonging to another account reports identically, on purpose, so a credential
    /// cannot be used to discover what other accounts hold.
    NotFound(ApiDetails),

    /// Too many requests. `retry_after` is seconds, from the header.
    RateLimited {
        details: ApiDetails,
        retry_after: Option<u64>,
    },

    /// The plan's share allowance is spent.
    ///
    /// Distinct from [`Error::RateLimited`]: waiting does not help, and the fix is a plan
    /// change or expiring old shares.
    QuotaExceeded(ApiDetails),

    /// An Idempotency-Key was reused with a different request body.
    ///
    /// Almost always this means a caller passed the same key to two separate creates expecting
    /// the second to be a no-op. It cannot be, and no argument makes it one: encryption is
    /// randomised per call — a fresh salt and IV every time, which AES-GCM requires — so two
    /// calls with identical arguments, and even with the same content key, still produce
    /// different ciphertext. The API is right to refuse.
    ///
    /// What the header actually protects is a NETWORK retry, where the body is byte-identical
    /// because it is the same already-encrypted request being sent again. This client performs
    /// those retries itself.
    IdempotencyConflict(ApiDetails),

    /// Entitlements could not be resolved, so nothing was created.
    ///
    /// Transient and safe to retry. The API returns this rather than guessing, because guessing
    /// "unlimited" would let an account exceed its plan and guessing "exhausted" would break a
    /// healthy one during a billing hiccup.
    ServiceUnavailable(ApiDetails),

    /// Any other refusal from the API.
    Api(ApiDetails),

    /// The request never reached the API.
    Transport(String),

    /// The caller passed something this client refuses to send.
    ///
    /// Distinct from [`Error::Internal`], which means a bug in this crate. Reporting bad
    /// caller input as an internal error sends the reader looking for a fault in the SDK.
    InvalidArgument(String),

    /// A webhook delivery did not verify.
    ///
    /// Present so `?` can carry a [`crate::webhooks::VerificationError`] across a function
    /// that returns [`Result`] - a handler usually verifies and then does API work, and
    /// without this the two error types cannot share a signature.
    WebhookVerification(String),

    /// A programming error in this crate or its caller, not a wire condition.
    Internal(&'static str),

    /// The owned form of [`Error::Internal`], for messages that carry a field index.
    InternalOwned(String),
}

impl Error {
    #[allow(non_snake_case)]
    pub(crate) fn Internal_owned(message: String) -> Self {
        Error::InternalOwned(message)
    }

    /// The API details, where the variant carries them.
    pub fn details(&self) -> Option<&ApiDetails> {
        match self {
            Error::Authentication(d)
            | Error::Permission(d)
            | Error::NotFound(d)
            | Error::QuotaExceeded(d)
            | Error::IdempotencyConflict(d)
            | Error::ServiceUnavailable(d)
            | Error::Api(d) => Some(d),
            Error::RateLimited { details, .. } => Some(details),
            _ => None,
        }
    }
}

/// What the API said about a refusal.
#[derive(Debug, Clone)]
pub struct ApiDetails {
    pub message: String,
    pub status: u16,
    /// The API's numeric error code, where it sends one.
    pub code: Option<i64>,
    /// Quote this when reporting a problem; it identifies the exact request in our logs.
    pub request_id: Option<String>,
}

impl fmt::Display for ApiDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (HTTP {}", self.message, self.status)?;
        if let Some(code) = self.code {
            write!(f, ", code {code}")?;
        }
        if let Some(request_id) = &self.request_id {
            write!(f, ", request {request_id}")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingKey => write!(
                f,
                "no key fragment was supplied; the link is incomplete, so ask for it again"
            ),
            Error::MalformedKey(why) => write!(f, "the key in the link is unusable: {why}"),
            Error::WireFormat(why) => write!(f, "the content could not be read: {why}"),
            Error::CredentialFormat(why) => write!(f, "the credential is malformed: {why}"),
            Error::CustodySecretTransmitted => write!(
                f,
                "the custody secret was about to be transmitted; rotate this credential"
            ),
            Error::Authentication(d) => write!(f, "the credential was not accepted: {d}"),
            Error::Permission(d) => write!(f, "this credential may not do that: {d}"),
            Error::NotFound(d) => write!(f, "no such share on this account: {d}"),
            Error::RateLimited {
                details,
                retry_after,
            } => match retry_after {
                Some(seconds) => write!(f, "too many requests, retry after {seconds}s: {details}"),
                None => write!(f, "too many requests: {details}"),
            },
            Error::QuotaExceeded(d) => write!(
                f,
                "the plan's share allowance is spent; waiting will not help: {d}"
            ),
            Error::IdempotencyConflict(d) => write!(
                f,
                "this Idempotency-Key was used with a different body; encryption is randomised \
                 per call, so a replayed key cannot be a no-op: {d}"
            ),
            Error::ServiceUnavailable(d) => {
                write!(
                    f,
                    "the service could not resolve entitlements; nothing was created: {d}"
                )
            }
            Error::Api(d) => write!(f, "{d}"),
            Error::Transport(why) => write!(f, "the request never reached the API: {why}"),
            Error::InvalidArgument(why) => write!(f, "{why}"),
            Error::WebhookVerification(why) => {
                write!(f, "the webhook delivery did not verify: {why}")
            }
            Error::Internal(why) => write!(f, "{why}"),
            Error::InternalOwned(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for Error {}
