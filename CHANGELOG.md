# Changelog

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
