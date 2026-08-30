# CredenShare wire and crypto specification

**Version 1 · normative**

This document defines the cryptographic constructions and wire formats a CredenShare client
must implement. It is the normative reference for the application in this repository and for
every SDK (Python, Go, Rust, Node), which are independent implementations in separate
repositories.

**The spec is normative, not any implementation.** Rev 3 of `API_PLATFORM_PLAN.md` decided
that public and private code stay completely separate — no shared crypto package, because a
module the production app depends on is a supply-chain surface, and for a product whose whole
claim is that we cannot read customer data, that is the wrong surface to open. The cost of
that decision is five independent implementations that can drift; the mitigation is this
document plus `conformance/vectors.v1.json`, which every implementation must reproduce.

Conformance vectors are **data**. They are vendored and compared, never imported. Data crosses
the boundary between public and private code; code does not.

---

## 0. Conventions

| term | meaning |
|---|---|
| `base64` | standard base64 with padding (RFC 4648 §4) |
| `base64url` | URL-safe base64, **no padding** (RFC 4648 §5) |
| `‖` | byte concatenation |
| `utf8(s)` | UTF-8 encoding of string `s`, no BOM |

Byte lengths are exact. A field described as 16 bytes is always 16 bytes.

Key words follow RFC 2119.

---

## 1. Primitives

| primitive | parameters |
|---|---|
| Hash | SHA-256 |
| KDF | HKDF-SHA-256 (RFC 5869), extract-and-expand |
| AEAD | AES-256-GCM, 96-bit IV, 128-bit tag |
| Curve | NIST P-256 (secp256r1), ECDH |
| Password KDF | PBKDF2-HMAC-SHA-256, 600,000 iterations |

**`hkdf(ikm, salt, info, len)`** denotes HKDF-SHA-256 with `info = utf8(info)`. An empty salt
is a zero-length byte string, **not** a block of zero bytes — implementations that pad an
absent salt will produce different output and fail conformance.

AES-GCM output is `ciphertext ‖ tag` in a single buffer, matching WebCrypto. Implementations
whose AEAD returns tag and ciphertext separately MUST concatenate in that order.

P-256 public keys are the **uncompressed** point encoding: `0x04 ‖ X(32) ‖ Y(32)`, 65 bytes.

### 1.1 Domain separation

Every derivation from the same input keying material uses a distinct `info` string. This is
what allows the access token to be handed to the server while the content key is not.

| `info` | purpose |
|---|---|
| `content` | content encryption key, no passcode |
| `content\|<passcode>` | content encryption key with a passcode |
| `access` | access token |
| `verify` | passcode verifier |
| `crs-ecdh-p256-scalar` | seed → private scalar |
| `crs-request-submission` | ECDH shared secret → wrapping key |
| `custody` | API credential custody secret → keypair seed (§3.1) |

Implementations MUST NOT add, rename or reuse these strings. A collision silently makes two
different secrets equal.

---

## 2. Content encryption

Used for shares, pastes and secure-request submissions.

### 2.1 The content key and the fragment

A content key is **32 random bytes** from a cryptographically secure source.

It is transported in the URL fragment, which browsers never send to a server:

```
fragment = "1" ‖ base64url(contentKey)
```

The fragment is **bare** — a single leading version character, no `k=` prefix. A key=value
appendix reads as optional and invites truncation by link-mangling clients, and a truncated
fragment must fail closed rather than appear to be a well-formed link missing a part.

Parsing MUST reject, distinguishably:

| condition | reason |
|---|---|
| empty or absent | `missing-key` |
| leading character is not `1` | `malformed-key` |
| body is not valid base64url | `malformed-key` |
| decoded length ≠ 32 | `malformed-key` |

The distinction matters to users: "your link is incomplete" and "this expired" look identical
on screen and have opposite remedies.

### 2.2 Encryption

```
salt  = 16 random bytes
iv    = 12 random bytes
key   = hkdf(contentKey, salt, passcode ? "content|" + passcode : "content", 32)
body  = AES-256-GCM(key, iv, utf8(JSON.stringify(fields)))
blob  = base64(salt ‖ iv ‖ body)
```

`blob` uses **standard** base64, not base64url: it travels in a JSON body, never in a URL.

The passcode is mixed into `info`, **never into the salt**. Salt and info serve different
purposes, and putting the passcode in the salt would make the derivation depend on a value
that must stay reproducible from stored data alone.

The plaintext is the JSON serialization of the field array. Unknown members MUST be preserved
on decrypt and re-emitted unchanged.

#### 2.2.1 The field object

This was missing from rev 1, and its absence is the kind of gap that costs an afternoon: a
share built with the wrong member names still encrypts, still posts, still decrypts, and
still renders — with every field label blank. Nothing errors. Caught by opening an
API-created share in a real browser and noticing the values had no names against them.

```json
[
  { "key": "Database password", "value": "s3cr3t", "type": "password" },
  { "key": "Host", "value": "db.internal.example", "type": "text" }
]
```

| Member | Required | Notes |
|---|---|---|
| `key` | yes | The field's visible **label**. Not an identifier — it is what the recipient reads. Blank renders as an unlabelled row. |
| `value` | yes | The field's content. |
| `type` | yes | One of `text`, `password`, `date`, `multiline`, `markdown`, `source_code`. Decides rendering: `password` is masked behind a reveal, `source_code` is syntax-highlighted, `markdown` is rendered. |
| `selectedProgrammingLanguage` | no | Language hint for `source_code`. |
| `filename` | no | For `source_code`/`markdown`, offers the recipient a Download button using this name. |

`key` is the member name for the label because that is what the field array has always used
and the recipient view reads it directly. It is **not** `label`, `name` or `title`; those are
silently ignored, which is precisely the failure described above.

An unrecognised `type` MUST be treated as `text` rather than rejected — a newer sender must
not be able to make an older reader fail on content it can otherwise display perfectly.

Decryption MUST reject a blob shorter than `16 + 12 + 16` bytes before attempting anything
else, and MUST treat AEAD authentication failure as an ordinary decryption failure — a wrong
passcode and a tampered blob are indistinguishable by design.

### 2.3 Access token

```
accessToken = base64url(hkdf(contentKey, "", "access", 32))
```

The **salt is empty** so the token is reproducible from the fragment alone, on any device,
with no stored state. The server stores only a hash of it and learns nothing about the
content key, because HKDF's domain separation makes the `access` output independent of the
`content` output.

### 2.4 Passcode verifier

```
verifier = base64url(hkdf(utf8(passcode), "", "verify", 32))
```

One-way on purpose: the server can check an attempt without gaining the ability to decrypt.

---

## 3. Seed-derived P-256 keypairs

Secure-request keys, zero-knowledge account keys and team keys are all stored as a **32-byte
seed** rather than a serialized keypair. The seed reconstructs the keypair anywhere, which is
what lets an entire private key live in a URL fragment.

```
wide   = hkdf(seed, "", "crs-ecdh-p256-scalar", 48)
scalar = (bigEndianInt(wide) mod (n - 1)) + 1        // n = P-256 group order
```

48 bytes rather than 32 is deliberate: the extra 128 bits make the modular bias negligible.
This is the standard hash-to-field construction. Adding 1 after reducing mod `n-1` yields a
scalar in `[1, n-1]`, excluding zero, which is not a valid private key.

`scalar` is encoded big-endian in exactly 32 bytes. The public key is `scalar · G` in
uncompressed form.

> P-256 rather than X25519 because WebCrypto support for X25519 is still uneven across
> browsers, and the property required here — that the private key cannot be recovered from
> the published public key — holds equally.

---

## 3.1 API credential custody

An API credential is:

```
crs_sk_live_<keyId>.<authSecret>.<custodySecret>
             │        │            └ NEVER transmitted
             │        └ the bearer credential; only its SHA-256 is stored
             └ opaque public id
```

Clients MUST send only the first two parts. A server receiving all three MUST refuse the
request: the custody half has been disclosed, and that credential should be rotated.

The custody keypair is derived locally:

```
seed      = hkdf(utf8(custodySecret), "", "custody", 32)
publicKey = scalar · G   (uncompressed, per §3)
```

Only `publicKey` is uploaded.

**Why a second secret rather than deriving custody from the auth secret.** The auth secret
is transmitted on every request, so deriving custody from it would mean the server *could*
reconstruct the private key and decrypt. Not that it would — that it could, which is
precisely what zero-knowledge is meant to eliminate. Splitting the credential removes the
capability instead of promising restraint. It is the same reasoning as the URL fragment,
applied to a credential.

Two consequences follow, and both are load-bearing rather than incidental:

- Any machine holding the credential derives the same keypair, so multi-runner and
  ephemeral-container automation need no local state.
- Revoking the key revokes custody in the same motion. The wraps remain and nothing can
  open them.

The empty salt is deliberate and matches §2.3: the derivation must be reproducible from
the credential alone, anywhere, with nothing stored.

---

## 4. ECDH wrapping

Used to wrap a key to a published public key: request submissions, and zero-knowledge wraps
to an account key, a team key or an API key.

```
ephemeral       = fresh random P-256 keypair          // per operation, never reused
sharedSecret    = ECDH(ephemeral.private, recipientPublic)   // 32-byte X coordinate
salt            = 16 random bytes
iv              = 12 random bytes
wrappingKey     = hkdf(sharedSecret, salt, "crs-request-submission", 32)
body            = AES-256-GCM(wrappingKey, iv, payload)
wrapped         = base64(0x01 ‖ ephemeral.public(65) ‖ salt(16) ‖ iv(12) ‖ body)
```

The leading byte is the wrap format version, currently `1`. A reader MUST reject any other
value rather than guessing.

Wrapping a 32-byte payload therefore produces **142 bytes**, or 192 base64 characters:
`1 + 65 + 16 + 12 + 32 + 16`. That arithmetic is a useful field check.

**The ephemeral keypair MUST be freshly generated per wrap.** The conformance vector derives
it from a seed only so the fixture is reproducible; reusing an ephemeral key across wraps
leaks the relationship between them.

Unwrapping reverses this using the recipient's seed-derived private key. It MUST reject a
blob shorter than `1 + 65 + 16 + 12 + 16` bytes.

---

## 5. Passphrase envelope (zero-knowledge account keys)

The account key seed is wrapped under a key derived from a **generated** passphrase.

```
alphabet   = "23456789ABCDEFGHJKMNPQRSTVWXYZ"     // 30 symbols
length     = 24 characters                        // ≈ 117.8 bits
```

Crockford-style: no `I`, `L`, `O`, `U`, `1` or `0`, because the user transcribes this off a
screen exactly once and `l` versus `1` is where that goes wrong. Generation MUST use rejection
sampling, not `random % 30`, which would bias toward the first symbols and quietly cost
entropy in the one secret with no server-side rate limit in front of it.

The passphrase is **generated, never user-chosen**: a chosen secret is a dictionary target
handed to an attacker alongside the ciphertext.

Normalization before use: strip spaces and hyphens, uppercase.

```
wrappingKey = PBKDF2-HMAC-SHA-256(utf8(normalize(passphrase)), salt, 600000) → 32 bytes
wrapped     = base64(iv(12) ‖ AES-256-GCM(wrappingKey, iv, seed))
kdfSalt     = base64url(salt(16))
```

Wrapping a 32-byte seed yields 60 bytes, or 80 base64 characters: `12 + 32 + 16`.

The salt is stored beside the wrapped blob, not inside it.

---

## 6. Versioning

Two independent version numbers, deliberately:

- **Fragment version** — the leading character of the fragment. Currently `1`.
- **Wrap version** — the leading byte of an ECDH-wrapped blob. Currently `1`.

A bump to either is a **breaking change**. The rollout order is fixed and MUST be observed:

1. The spec and conformance vectors publish the new version.
2. Every SDK ships support for reading it.
3. Only then may any implementation begin emitting it.

Emitting before readers exist strands content that cannot be opened. Treating a version bump
as a one-line change is the failure this ordering exists to prevent.

Readers MUST reject unknown versions rather than attempting a best-effort parse.

---

## 7. Conformance

`conformance/vectors.v1.json` is normative. An implementation conforms when it reproduces
every vector exactly.

The vectors cover derivations, encodings, and — more importantly — **decrypting and unwrapping
material produced by a different implementation**. The derivation cases catch drift early; the
decrypt and unwrap cases are what actually prove interoperability, because passing them means
the implementation can read what another one wrote.

The vectors are generated by `scripts/gen-conformance-vectors.mjs`, which implements this
document from scratch against `node:crypto` and imports nothing from the application. That
independence is the point: if the generator used the app's crypto, the vectors would merely
restate whatever the app does, and an app bug would become the standard every SDK is held to.

All vector inputs are synthetic and key nothing real. Salts, IVs and ephemeral scalars are
fixed so the fixture is reproducible; production code MUST use fresh random values.

**Every implementation gates on these vectors**: a CI check in this repository asserts the
vendored copy has not diverged from the published fixture and that the application satisfies
it, and each SDK gates its releases the same way.
