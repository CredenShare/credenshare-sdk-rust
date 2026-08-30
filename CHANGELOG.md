# Changelog

## 0.1.0 — unreleased

First release.

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
