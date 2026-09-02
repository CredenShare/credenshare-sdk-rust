# Changelog

## 0.2.0 — 2026-09-02

Secure requests: a collect link somebody fills in, whose submissions are sealed to a keypair
this crate mints locally and never transmits. Plus the account's usage figures. Additive —
nothing on the shares surface changed, and the conformance fixture is byte-identical.

The version is a minor bump because 0.1.4 is on crates.io and this adds public API. The four
CredenShare SDKs ship this surface together and under one set of names, so a reader who knows
one of them can read the others: `SecureRequest`, `RequestDeletion { short_code, outcome }`,
`Stats { shares, daily_views }`, `decrypt_submission(data, seed)`, `SEED_LENGTH`, and the two
link helpers.

### Added

- **`CredenShare::create_request`**, which mints a P-256 keypair from a 32-byte seed, registers
  the PUBLIC half, and hands back a `SecureRequest` holding the seed. The seed is the only thing
  that can read the request's submissions, and it is never sent — see *Security* below for what
  enforces that rather than promising it.
- **`CredenShare::list_requests` / `for_each_request` / `get_request` / `delete_request`.**
  `delete_request` returns a `RequestDeletion` whose `outcome` says which of the endpoint's two
  effects happened: `"expired"` for an active request, `"deleted"` for one already expired.
  `outcome` is `Option<String>` and stays `None` when the server did not say, rather than being
  coerced to a guess.
- **`CredenShare::list_submissions` and `for_each_submission`**, which hand back submissions
  still sealed. `Submission::decrypt` and the module-level `decrypt_submission(data, seed)` open
  one with the seed. Neither takes a `limit` or a `page`: the endpoint is not paginated, and it
  reads neither parameter (see *The submissions endpoint* below).
- **`CredenShare::get_stats`** — `Stats { shares: ShareCounts, daily_views: Vec<DailyView> }`,
  scoped to the team where the credential acts in one.
- **`collect_link_for` and `access_link_for`** on the client, and `collect_link` and
  `access_link` on a created request. The collect link carries no key and is safe to publish;
  the access link carries the seed in a version-prefixed fragment (`"1" + base64url(seed)`) and
  is the secret itself. `access_link_for` exists so that turning a stored seed back into a link
  is not a hand-assembled fragment with the version prefix left off.
- **`CreateRequestParams::organization_id`**, to create a request under a team the credential
  already acts in. Omitted from the body entirely when unset, so a caller who does not use
  teams sends what it always did. Request-side ONLY: the matching member was drafted for the
  shares `CreateParams` too and then withdrawn, because that struct shipped in 0.1.4 and adding
  a field to it stops an exhaustive struct literal from compiling — a source break, which this
  release does not make. Creating a share under a team goes through `CredenShare::request`
  until the next major.
- **`SEED_LENGTH`**, for checking a seed read back out of a secrets manager before handing it to
  `keypair_from_seed`. `access_link_for` uses it to report a wrong-length seed as
  `Error::MalformedKey`, naming the argument, rather than surfacing an error from inside a
  primitive.
- **`new_seed`**, the OS-CSPRNG mint used when `CreateRequestParams::seed` is left unset.

### Security

- **The seed is asserted at the request boundary, in the manner of the custody-secret
  assertion.** Before a create is sent, the SERIALIZED body and the outgoing `Idempotency-Key`
  are scanned for the seed rendered as unpadded base64url, unpadded standard base64 and hex —
  four spellings, since the unpadded base64 needle also matches the padded form. A hit is the
  new `Error::RequestSeedTransmitted` and nothing is sent. Scanning the serialized form rather
  than the field list is what catches a seed that arrived through a title, a description or a
  prompt; scanning the header is what catches a caller deriving a deterministic idempotency key
  from a deterministic seed.
- **`CreateRequestParams` has a hand-written `Debug` that withholds the seed.** The derived one
  printed its bytes, so `dbg!(&params)` or a `tracing` field wrote the private key of every
  submission that request will ever collect into a log — and a leaked seed cannot be rotated,
  because rotating it makes the submissions already collected unreadable. It now renders
  `seed: Some(<32 bytes withheld>)`. `SecureRequest`'s `Debug` withholds the seed and the
  access link, which carries the same 32 bytes.

### Changed

- **The automatic `Idempotency-Key` covers `POST`, `PUT` and `PATCH`, and nothing else.**
  `CredenShare::request` is public in this release, and it generates the header the typed
  creates were already sending so that a write through the escape hatch cannot leave a second
  object behind on a retry. The allow-list is deliberate rather than "every method but `GET`":
  the API consults the header on creates and does not read it on a `DELETE`, so a generated key
  there is inert — and `DELETE /shares/{code}` shipped in 0.1.4 sending none, so generating one
  would alter the bytes of an already-published call for no gain. **No request this crate makes
  on the 0.1.4 surface changes.** A key you supply yourself is forwarded untouched on any
  method, `DELETE` included.
- **`SecureRequest` no longer implements `Drop`.** The seed is a `Zeroizing<[u8; 32]>` instead,
  which wipes on drop exactly as before while restoring the moves a manual `Drop` forbade:
  `let code = request.short_code;` was `error[E0509]`, so every example a caller wrote carried
  `.clone()` noise. The doc no longer claims more than the wipe delivers — `[u8; 32]` is `Copy`,
  so a seed copied out with `*request.seed()` is the caller's to look after.
- **`list_requests` defaults to 25 rather than 10** when passed `limit: 0`. 25 is the API's
  default for every v1 list — the handler reads one constant for all of them — and asking for a
  different page size than the server's makes every paging figure in the response disagree with
  the dashboard's. The share list's 25 is unchanged.

### The submissions endpoint

`GET /requests/{code}/submissions` answers with `{submissions, count}` and reads neither `page`
nor `limit`. `SubmissionPage` therefore carries `submissions`, `count` and
`skipped_not_end_to_end_encrypted` and no paging figures at all, and there is no `has_more`: a
member that is always absent reads as a broken field rather than an absent one, and a
`has_more` computed from figures the server never sends is how a walk asks for a page two that
does not exist and is handed page one again. `openapi.yaml` documents no `pagination` block
here either — an earlier revision did, and it has since been corrected to match the handler, so
spec and deployed API now agree with this crate.

`Submission` carries the four members the handler emits — `short_code`, `created_at`, `data`
and `encryption_type` — and no `expired_at`. A submission has no expiry of its own; the request
expires, and expiring it stops new submissions rather than dating the ones already collected.
The Node, Python and Go clients hold the same four.

### Tests

- The seed's absence is asserted rather than assumed: a seed smuggled into a title, a prompt or
  a description in any of four encodings is refused before a byte is sent, as is a seed passed
  as the `idempotency_key`; `{:?}` and `{:#?}` of both `CreateRequestParams` and `SecureRequest`
  are asserted to contain neither the bytes, nor the hex, nor the base64url, nor the access
  link.
- One submissions call yields every row exactly once and issues exactly one HTTP request, and
  the request carries no `limit` or `page` in its query.
- `list_requests(0, 0)` is asserted to ask the API for `limit=25`.
- `expire_share` is asserted to send NO `Idempotency-Key`, byte-for-byte the 0.1.4 call, while
  a key the caller supplies on a `DELETE` is asserted to be forwarded unchanged.


## 0.1.4 — released 2026-08-30

The first version whose install instructions are the registry ones, because 0.1.3 is on the
registries. Also fixes a version string that had drifted.

### Fixed

- **The in-code version constant was stale.** It read `0.1.0` while `0.1.3` was published: the
  release guard compared the TAG to the manifest and never to this second copy. Rust was already correct - `Cargo.toml` is the single source.

### Documentation

- The install line is the registry command rather than a git URL.


## 0.1.3 — released 2026-08-30

No code change from 0.1.2. Cut to exercise the publish path with no stored credential: the npm
`NPM_TOKEN` bootstrap secret is deleted and publication now runs on OIDC trusted publishing, so
nothing long-lived exists in any repository that could publish this package.


## 0.1.2 — released 2026-08-30

The first version published to a package registry. No code change from 0.1.1: the conformance
fixture is byte-identical and every client still reports 24/24. Cut so that the published
version's own release workflow carries the npm OIDC version floor, which is what allows npm
publishing to move off a token immediately afterwards.


## 0.1.1 — released 2026-08-30

`v0.1.0` was tagged before the release-facing files were corrected, so the artifact resolved at
that tag told consumers to install unpinned and its changelog denied its own release. This
version contains those corrections. Nothing about the cryptography or the wire format changed
between the two; the conformance fixture is byte-identical.

### Changed

- **`Eq` is restored on `Field`.** 0.1.0 dropped it, and the reason given was wrong:
  `serde_json::Value` is only `PartialEq` because it can hold a float, but JSON has no NaN or
  infinity, so every value this struct can hold is reflexive. A hand-written `impl Eq` is
  sound, and `f1 == f2` works again. `Hash` still cannot follow, so `HashSet<Field>` remains
  unavailable — key on a `(&str, &str, &str)` tuple of the three known members.
- **`MAX_PAGES` is exported**, so the constant its own error message names can be read.

### Fixed

- **The release build can check fixture drift again.** The doctest step added in 0.1.0 was
  inserted directly above an `env:` block, which in YAML bound to the new step; the drift
  comparison is an integration test that `--all-targets` runs and `--doc` never does.
- `DEFAULT_MAX_RETRIES` has its documentation back. `MAX_PAGES`'s doc comment had swallowed it.
- `for_each_share`'s rustdoc documents both ways the walk can now fail.

### Tests

- The page bound landed in 0.1.0 untested. Two tests now cover it, and the page-echo one fails
  with "looping instead of erroring" when the guard is removed.

## 0.1.0 — released 2026-08-30

First release.

### Breaking, before v0.1.0

These landed before `v0.1.0` was tagged, so no released version ever had the old shape.
Recorded because the repository is public and someone may have pinned to a commit from the
window before the tag existed.

- **`Field` gained a fourth public member.** `extra: Map<String, Value>` preserves members
  this version does not know about, so a field written by a newer sender survives a
  decrypt/re-encrypt round trip instead of being silently deleted. An exhaustive struct
  literal therefore no longer compiles — use
  `Field { key, value, field_type, ..Default::default() }`, which `Default` is now derived for.

  **`Eq` is retained.** It is implemented by hand rather than derived, because
  `serde_json::Value` is only `PartialEq`. That is sound here: JSON has no NaN or infinity, so
  every value this struct can hold is reflexive. `f1 == f2` and any `Eq` bound keep working.

  **`Hash` is not available**, because `Value` does not implement it, so `HashSet<Field>` and
  `HashMap<Field, _>` do not compile. Key on `Field::key`, or on a `(&str, &str, &str)` tuple
  of the three known members, and keep the `Field` as the value.
- **`SeedKeypair::seed` and `::scalar` are no longer public fields.** They are the private
  key, on a struct whose hand-written `Debug` deliberately withholds them — leaving them
  public made that gesture decorative. Use `seed()` and `private_scalar()`.

### Fixed

- **`for_each_share` terminates.** Against a server that omits both `total_pages` and `total`
  and returns full pages, the walk was unbounded: the caller's process hung and the visitor
  was re-fed the same rows forever. It is bounded by `MAX_PAGES` now, refuses a mismatched
  page echo, and fails with a message naming the cause rather than hanging.
- `get_share` and `expire_share` reject a short code that could change the request path.
- `list_shares` treats an unreadable row as an error rather than dropping it while `total`
  still reports the true count.
- A successful create whose body is not JSON reports what arrived, instead of an
  `Error::Internal` about a missing `short_code` — which lost the content key for a share
  that exists.
- `Credential::parse` rejects an empty key id.
- Key material is zeroized: `hkdf` returns `Zeroizing`, and `SeedKeypair` wipes its seed and
  scalar on drop.

### CI

- **Doctests actually run.** `cargo test --all-targets` excludes them, and `lib.rs` includes
  the README specifically so its examples are compiled — so nothing compiled them, which is
  the exact gap that arrangement exists to close. `cargo test --doc` runs in both workflows.
- The drift job's anti-rename guard is unconditional. It was wrapped in a check on the
  vectors URL, so in the shipped state — the variable unset — a renamed or deleted fixture
  test turned the job green while checking nothing.

- End-to-end encrypted share creation, listing and expiry against the `/v1` API. Encryption
  happens locally; the content key never reaches CredenShare.
- `#![forbid(unsafe_code)]`, and the crypto comes from RustCrypto — the ecosystem's audited
  implementations of exactly these primitives — rather than from anything hand-rolled.
- The `client` feature is on by default and can be turned off, so a caller embedding only the
  crypto does not compile a TLS stack it never calls.
- Split API credentials. The custody part never leaves the machine: the bearer value is
  assembled from parsed parts, with a second assertion at the request boundary, and `Debug` is
  implemented by hand on both `Credential` and `SeedKeypair` so a derive cannot leak a secret.
- Webhook signature verification, including the dual-signature rotation grace window, a
  symmetric replay-tolerance check, and constant-time comparison via `subtle`.
- `cargo run --bin credenshare-conformance` verifies a built copy against the wire
  specification's vectors, embedded with `include_str!`.
- Client tests run against a real loopback socket rather than a mocked transport, so request
  construction, headers and body are exercised as they actually go out.
