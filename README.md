# CredenShare for Rust

End-to-end encrypted secret sharing. **Encryption happens on your machine** — the content key
never reaches CredenShare, which is what makes "we cannot read your data" a property of the
system rather than a promise.

```toml
[dependencies]
credenshare = "0.1"
```



```rust,no_run
use credenshare::{CredenShare, CreateParams, Field};

fn main() -> Result<(), credenshare::Error> {
    let client = CredenShare::new(&std::env::var("CREDENSHARE_KEY").unwrap())?;

    let share = client.create_share(CreateParams {
        title: "Staging deploy credentials".into(),
        fields: vec![
            Field::new("Username", "deploy-bot", "text"),
            Field::new("Password", "correct horse", "password"),
        ],
        ..Default::default()
    })?;

    println!("{}", share.link);
    // https://crs.sh/aB3dEf12#1xK9...
    Ok(())
}
```

**That link is the secret.** The key lives in its fragment, which browsers never transmit.
Anyone holding the link can read the content; we cannot, and cannot recover it for you.

## What this crate is made of

`#![forbid(unsafe_code)]`, and the primitives come from RustCrypto — `aes-gcm`, `hkdf`, `p256`,
`subtle` — rather than from anything hand-rolled here. A crate whose entire claim is that it
encrypts correctly is the wrong place to be clever.

The `client` feature is on by default. Turn it off to compile only the crypto:

```toml
credenshare = { version = "0.1", default-features = false }
```

A caller that posts with its own HTTP client, or runs somewhere a TLS stack would be dead
weight, should not have to carry one.

---

## The field object

`Field::key` is the **visible label**, not an identifier. Rust's types stop the `label:`
spelling that catches the dynamic clients at compile time; a caller deserialising from JSON
with the wrong member name still lands in the same place — an empty `key`, a field rendered
blank, nothing erroring anywhere — which is what `validate_fields` refuses.

`Field::field_type` is one of `text`, `password`, `date`, `multiline`, `markdown`,
`source_code`, and decides how the recipient sees it.

## A passcode

```rust,no_run
use credenshare::{CredenShare, CreateParams, Field};
fn main() -> Result<(), credenshare::Error> {
    let client = CredenShare::new("crs_sk_live_a.b")?;
    client.create_share(CreateParams {
        title: "Production database".into(),
        fields: vec![Field::new("Password", "s3cr3t", "password")],
        passcode: Some("hunter2".into()),
        ..Default::default()
    })?;
    Ok(())
}
```

The passcode is mixed into the key derivation and never sent. The server receives only a
one-way verifier, so it can check an attempt without gaining the ability to decrypt. Share the
link and the passcode over different channels — that is the point of having both.

## Listing and expiring

```rust,no_run
use credenshare::CredenShare;
fn main() -> Result<(), credenshare::Error> {
    let client = CredenShare::new("crs_sk_live_a.b")?;
    let page = client.list_shares(50, 1)?;
    println!("{:?} {}", page.total, page.has_more());

    client.for_each_share(100, |share| {
        println!("{} {:?}", share.short_code, share.expired_at);
        Ok(())
    })?;

    client.expire_share("aB3dEf12")?;
    Ok(())
}
```

`list_shares` and `get_share` return **metadata only** — never content, never a key. A short
code belonging to another account reports exactly as one that does not exist, so a credential
cannot be used to discover what other accounts hold.

`expire_share` **removes** the share rather than flagging it: a later `get_share` returns
`Error::NotFound` rather than a row with an expiry set. Worth knowing if you reconcile against
your own records — a share you expired and one that never existed look identical afterwards.

There is deliberately **no method to read a share over the API**. The recipient path is
protected by proof-of-work and captcha gates that bearer auth skips, so exposing it to a
credential would be an enumeration bypass. Open the link in a browser.

## Secure requests

A collect link somebody fills in, whose submissions are sealed to a key you hold. **You
generate the keypair** — this crate mints it locally, sends the public half, and hands you the
32-byte seed.

```rust,no_run
use credenshare::{CredenShare, CreateRequestParams, RequestField};

fn main() -> Result<(), credenshare::Error> {
    let client = CredenShare::new("crs_sk_live_a.b")?;

    let request = client.create_request(CreateRequestParams {
        title: "Contractor onboarding".into(),
        fields: vec![
            RequestField::text("Your name"),
            RequestField::new("Staging database password", "password"),
        ],
        ..Default::default()
    })?;

    println!("{}", request.collect_link);
    // https://crs.sh/r/aB3dEf12  — no key in it. Safe to publish.

    // STORE THIS. It is the only thing that can read the submissions - as are the same 32
    // bytes in `request.access_link`, which is a link rather than a byte array and so the
    // easier of the two to put in a secrets manager. Treat either as the secret itself.
    let seed = *request.seed();

    for submission in client.list_submissions(&request.short_code)?.submissions {
        for field in submission.decrypt(&seed)? {
            println!("{}: {}", field.key, field.value);
        }
    }
    Ok(())
}
```

**The seed never leaves your machine**, which is what makes a submission unreadable to
CredenShare — and, because every submission uses its own ephemeral key, unreadable to the other
submitters too. There is no recovery path: a request whose seed is lost goes on collecting
submissions that nobody can ever open. Store it as you would a private key.

That guarantee is enforced rather than promised. Before the create is sent, the serialized body
and the outgoing `Idempotency-Key` are scanned for the seed in base64url, standard base64 and
hex; finding it is `Error::RequestSeedTransmitted` and nothing is sent. So a seed that reaches
the body through a title, a description or a prompt fails here rather than in production. For
the same reason `CreateRequestParams` and `SecureRequest` have hand-written `Debug`
implementations that withhold the seed — `dbg!(&params)` prints `seed: Some(<32 bytes
withheld>)` — and `SecureRequest` withholds `access_link` alongside it, because that string
carries the same 32 bytes. `SEED_LENGTH` is exported for checking a seed read back out of a
secrets manager.

The two links are opposites. `collect_link` has no key in it and is safe to publish; holding it
lets somebody submit and never read. `access_link` carries the seed in a version-prefixed
fragment (`"1" + base64url(seed)`), so it is the ability to read every submission, on any
device, with nothing stored. `CredenShare::access_link_for` turns a stored seed back into one,
which is the call to reach for rather than assembling the fragment by hand.

`SecureRequest` zeroizes its own copy of the seed when it drops. That is its copy, not every
copy: `[u8; 32]` is `Copy`, so whatever you took out with `*request.seed()` — and the access
link string — is yours to look after.

Pass `CreateRequestParams::seed` to derive the keypair from a seed you already hold. That is the
custody case: `custody_keypair(secret).seed()` is reproducible on any machine holding the
credential, so an ephemeral runner can create a request today and its replacement can read the
submissions next week with nothing stored anywhere.

Submissions come back **sealed**, and `decrypt` is a separate call for the same reason
`decrypt_content` is: the seed is yours, and a list that decrypted silently would demand it on
every read — including the reads that only want to know how many arrived.

`list_submissions` takes no `limit` and no `page` because the endpoint has neither: it answers
with the whole set, and `count` is the API's own figure for what it sent.
`for_each_submission` is therefore one call and then a stop, not a walk — the share and request
lists are the paginated ones, and both default to the API's own page size of 25.

One encoding trap, which is worth knowing before you debug it: a request's `public_key` travels
as **unpadded base64url**, and a submission's `data` comes back as **padded standard base64**.
Two encodings, same feature. Pass `data` verbatim to `Submission::decrypt` or
`decrypt_submission`; re-encoding it first produces a blob that will not open, and the failure
reads as a wrong key rather than a wrong decoder.

Pass `CreateRequestParams::organization_id` to create the request under a team you belong to.
The API accepts it only where it matches the organization the credential already acts in, so it
selects among what that credential can already reach rather than widening it. There is no
counterpart on the share side: `CreateParams` shipped in 0.1.4 without one, and adding a member
would stop an exhaustive struct literal from compiling — a source break a minor release does
not get to make. Until the next major, create a share under a team through `client.request`.

`delete_request` is two-step by design: the first call expires an active request, stopping new
submissions while preserving those already received, and a second call on an expired one removes
it. `RequestDeletion::outcome` says which happened rather than leaving you to infer it.

## Usage figures

```rust,no_run
use credenshare::CredenShare;
fn main() -> Result<(), credenshare::Error> {
    let client = CredenShare::new("crs_sk_live_a.b")?;
    let stats = client.get_stats()?;
    println!("{} active, {} viewed", stats.shares.active, stats.shares.total_viewed);
    for day in stats.daily_views {
        println!("{} {}", day.date, day.count);
    }
    Ok(())
}
```

Scoped to the team when the credential acts in one. `daily_views` is oldest-first and
zero-filled, so a quiet day is a zero rather than a missing row. The per-member breakdown the
dashboard shows is deliberately absent: a key scoped to read statistics should not become a way
to enumerate colleagues.

## Idempotency and retries

Every create carries an `Idempotency-Key`. It exists so a **network** retry cannot leave a
second copy of a credential in the world, with its own link and audit trail, that you do not
know about. This client performs those retries itself, repeating the byte-identical request.

Setting your own `idempotency_key` does **not** make a second `create_share` a no-op, and no
field makes it one: encryption is randomised per call — a fresh salt and IV every time, which
AES-GCM requires — so the body differs and the API refuses with `Error::IdempotencyConflict`.
That is the header working, not failing.

Only transport failures are retried. A 5xx is surfaced, because it may have committed and this
client cannot tell.

`request` is the escape hatch, for an endpoint this crate does not model:

```rust,no_run
use credenshare::CredenShare;
fn main() -> Result<(), credenshare::Error> {
    let client = CredenShare::new("crs_sk_live_a.b")?;
    let body = client.request("GET", "/stats", None, &[], &[])?;
    println!("{body}");
    Ok(())
}
```

It adds an `Idempotency-Key` to every `POST`, `PUT` and `PATCH` that does not already carry
one, and never overwrites a supplied one — a caller reproducing a key across process restarts
is doing exactly what the header is for. The generated key is computed once and reused across
that call's own retries, because a key that changed per attempt would make every retry a fresh
request as far as the API is concerned.

Every other method gets none, `DELETE` included. The API consults the header on creates and
does not read it on a delete, so a generated key there would be inert — and `expire_share`
shipped in 0.1.4 sending none, which is a wire detail a minor release does not get to change.
Supply your own on a `DELETE` and it is forwarded untouched.

---

## Verifying webhooks

```rust,no_run
use credenshare::webhooks::{verify, Options, SIGNATURE_HEADER};

fn handle(raw_body: &[u8], signature: &str, secret: &str) -> bool {
        verify(raw_body, signature, &[secret], &Options::default()).is_ok()
}
```

Two things people get wrong, both of which this module tries to make hard:

**Verify the raw body.** Re-serialising decoded JSON changes the bytes — key order, spacing,
escapes — and the signature will not match. It is the most common reason a correct integration
appears broken.

**Pass both secrets while rotating.** For 24 hours after you rotate, deliveries carry both
signatures so you can roll your configuration without dropping anything:

```rust,no_run
use credenshare::webhooks::{verify, Options};
fn f(body: &[u8], header: &str, new_secret: &str, old_secret: &str) {
    verify(body, header, &[new_secret, old_secret], &Options::default()).unwrap();
}
```

`verify` returns `Result<(), VerificationError>` — no `bool`. `Result<bool>` invites a caller to
check the `Result` and ignore the value, which produces a receiver that accepts everything and
looks like it checks.

---

## API credentials

```text
crs_sk_live_<keyId>.<authSecret>.<custodySecret>
                                  └ never transmitted
```

The third part is optional and, when present, **stays on your machine**. It is a separate
secret precisely so the server cannot reconstruct your custody private key: the auth secret
goes over the wire on every request, so deriving custody from it would mean the server *could*
decrypt. Not that it would — that it could, which is what zero-knowledge removes.

The bearer value is assembled from the parsed parts rather than by trimming the string, so a
third part cannot survive a formatting mistake and reach the wire, and there is a second
assertion at the request boundary. `Debug` is written by hand on `Credential` and
`SeedKeypair`, because a derive would print the private half and a key in a log line is a key
that has to be rotated.

---

## The wire specification

This crate implements the CredenShare wire and crypto specification, which ships in this
repository as [`CRYPTO_WIRE_SPEC.md`](CRYPTO_WIRE_SPEC.md). **The specification is
normative — not this code**, and not any other implementation. Where they disagree, this
is the bug.

Versioning, and how a release is cut, is in [`VERSIONING.md`](VERSIONING.md). Worth reading
before the first one: this SDK is not on a registry yet, and the release path needs
per-repository settings that do not exist yet.


The application and the four SDKs share no code, deliberately: a package the production
application depended on would mean a compromised publish is a compromised application. The cost
is drift, and drift here does not produce a test failure — it produces content that can never
be decrypted.

The vectors are embedded with `include_str!`, so they compile into the binary:

```bash
cargo run --bin credenshare-conformance -- -v
```

Non-zero exit on failure, so it works as a deployment gate. The vectors include cases that
**decrypt and unwrap material produced by a different implementation** — passing them means
this client can read what another one wrote, which is interoperability rather than
self-consistency.

## Errors

Match on the variant; the variant is the remedy.

| Variant | Means | What helps |
| ------- | ----- | ---------- |
| `MissingKey` | a link arrived with no key | ask for the link again — something stripped it |
| `MalformedKey` | the key is present but unusable | the link is truncated; ask for it again |
| `WireFormat` | wrong passcode, or altered content | check the passcode. The two are indistinguishable by design |
| `Authentication` | credential unknown or revoked | mint a new one |
| `Permission` | missing scope, or a plan without API access | check scopes, or upgrade |
| `QuotaExceeded` | the plan's share allowance is spent | waiting does not help — expire old shares or change plan |
| `IdempotencyConflict` | a key was replayed with a different body | expected on a caller-level replay; see above |
| `RateLimited` | too many requests | wait `retry_after` seconds |
| `ServiceUnavailable` | entitlements could not be resolved | nothing was created; retry |
| `Transport` | the request never reached the API | already retried; check the network |
| `InvalidArgument` | this client refused to send what it was given | fix the argument — nothing was sent |
| `RequestSeedTransmitted` | a request seed was about to go out | nothing was sent; take the seed out of the body |

## Licence

MIT OR Apache-2.0, the Rust convention. Open source is a requirement here, not a preference: if
the client performing the encryption is closed, the claim that we cannot read your data is
unverifiable.
