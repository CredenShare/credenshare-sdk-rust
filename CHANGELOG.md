# Changelog

## 0.1.0 — unreleased

First release.

### Breaking, before the first release

Nothing is published, so nothing is pinned to a version — but this repository is public with
no tags, so pinning to a **commit** is the only thing a consumer can do, and both of these
stop such a consumer's code from compiling.

- **`Field` gained a fourth public member and lost `Eq`.** `extra: Map<String, Value>`
  preserves members this version does not know about, so a field written by a newer sender
  survives a decrypt/re-encrypt round trip instead of being silently deleted. Consequences:
  an exhaustive struct literal no longer compiles — use
  `Field { key, value, field_type, ..Default::default() }`, which `Default` is now derived
  for — and `Eq` is gone, because `serde_json::Value` is only `PartialEq` (it can carry
  floats). Anything with an `Eq` bound or a `HashSet<Field>` needs `PartialEq` instead.
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
