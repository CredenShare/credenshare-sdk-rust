# Versioning and releases

Four SDKs implement one specification. This is how the version numbers relate, and how a
release is cut.

## Three version axes, deliberately independent

| Axis | Where it lives | What a change means |
| ---- | -------------- | ------------------- |
| **Fragment version** | the `"1"` prefix inside a link fragment | The link format changed. Old clients cannot open new links |
| **Vectors version** | `conformance/vectors.v1.json`, `version: 1` | The contract's shape changed. Additive cases keep the version and move only the digest |
| **SDK version** | each SDK's own semver | That one library changed |

An SDK's version tells you nothing about which spec it implements. Its conformance self-check
does, and that is the honest answer — `python -m credenshare.conformance` and friends.

## The SDKs version independently

Lockstep was considered and rejected. Bumping four libraries because one of them fixed a typo
teaches consumers that a version bump means nothing, and the day it *does* mean something they
will not read the changelog. So: each SDK moves on its own, at its own pace, and a shared
release is a coincidence rather than a rule.

Semver, with one clarification specific to a crypto client:

- **patch** — a fix that does not change the bytes on the wire.
- **minor** — new surface, or a fix to something that was *never* interoperable. The Python
  0.1.x non-ASCII escaping fix was this: it changed the bytes, but the old bytes were wrong
  and no other client could reproduce them.
- **major** — a change that breaks a caller's code, or changes bytes that *were* correct.

## A fragment-version bump is a five-repo problem

This is the one that will hurt if it is treated as a one-liner. The order is not negotiable:

1. **This repository moves first.** Spec and vectors describe the new version.
2. **Every SDK ships support for reading it**, and releases.
3. **Consumers upgrade.** There is no way to know when this finishes, which is why step 4 waits.
4. **Only then** may the application start *emitting* the new version.

Reverse any two of those and you produce links that clients in the wild cannot open — content
that is not lost, but is unreadable by the person you sent it to, which is the same thing to
them.

## Tagging is safe before the registries are configured

A tag always does the verifiable half: it checks the tag against the manifest, runs the full
test and conformance suite, and creates a **GitHub Release**. That half needs no credentials
and works today.

Uploading to a registry is gated on the repository variable **`PUBLISH_TO_REGISTRY`**. Until
it is `true`, the publish step is skipped with a notice saying so, and the run is green rather
than red — because a release path that fails by default is one everybody learns to ignore.

Switching publication on is therefore two steps, in this order:

1. Configure the registry credential for that repo (below).
2. Set `PUBLISH_TO_REGISTRY=true` on the repository.

The next tag publishes. Nothing else changes.

## Before the FIRST registry upload: what must exist

Nothing has been uploaded to a registry yet. All three names were free as of 2026-08-30:
`credenshare` on PyPI, `@credenshare/sdk` on npm, `credenshare` on crates.io.

**The GitHub side is already done** (2026-08-30): the `pypi`, `npm` and `crates-io`
environments exist on their repositories, and each carries `PUBLISH_TO_REGISTRY=false`. What
remains is a registry account per ecosystem, and one secret for two of the three.

Two different mechanisms are in play, and the distinction matters:

- **OIDC trusted publishing** (PyPI, npm) — no long-lived credential. The registry trusts
  *this workflow, on this repository, in this environment*, and mints a token per run. Nothing
  to leak, nothing to rotate.
- **A long-lived API token** (crates.io) — no OIDC equivalent exists there yet.

### PyPI — trusted publishing, and it works before the name exists

PyPI supports a *pending* publisher, which is exactly this case: the project does not exist and
the first publish claims it.

1. Create an account at **pypi.org** and enable 2FA. Publishing requires it.
2. Go to **Account settings → Publishing → Add a new pending publisher**, choose GitHub, and
   fill in **exactly** these values:

   | Field | Value |
   | ----- | ----- |
   | PyPI Project Name | `credenshare` |
   | Owner | `CredenShare` |
   | Repository name | `credenshare-sdk-python` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

   The environment name is the usual thing to get wrong: it must match the `environment:` in
   `release.yml`, which is `pypi`. A mismatch fails the OIDC exchange with a message that does
   not obviously say so.
3. No secret is added to GitHub. That is the point of this mechanism.

### npm — an org, then Trusted Publishing

`@credenshare/sdk` is a *scoped* package, so the scope has to exist and be yours.

1. Create an account at **npmjs.com** and enable 2FA.
2. Create the organisation **`credenshare`** (npmjs.com → your avatar → *Add an
   Organization*). Free for public packages. This is what makes the `@credenshare` scope yours.
3. **Configure Trusted Publishing**, which is what npm itself recommends. On the package's npm
   settings page, point it at this repository, workflow `release.yml`, environment `npm`. No
   secret is stored anywhere, and provenance is attested by the registry.

**Do not tick "Bypass two-factor authentication (2FA)" on a token.** npm's own warning next to
that checkbox says to use Trusted Publishing for CI instead, and it is right: a token that
bypasses 2FA is a long-lived credential with publish rights and no second factor.

**One version requirement, and it fails confusingly if missed.** npm's OIDC exchange needs
**npm ≥ 11.5.1**. Node 22 bundles npm 10.9.8, so a workflow pinned to Node 22 cannot do trusted
publishing at all — and the failure reads as a credentials problem rather than a version one.
The publish job therefore runs `npm install -g npm@^11.5.1` before publishing, and prints
`npm --version` so the log says which CLI actually did it. The test matrix deliberately stays
on what Node ships, because that is what consumers run.

**`NPM_TOKEN` remains supported as a bootstrap only.** If npm will not attach a publisher to a
package that does not exist yet, a granular token (Access Tokens → *Granular Access Token*,
*Read and write* on **Packages and scopes → `@credenshare/*`**) gets the first version out.
Add it to the `npm` environment, publish once, configure the publisher, then **delete the
secret** — the workflow falls back to OIDC with no other change.

### crates.io — a token, because there is no alternative

1. Sign in at **crates.io** with GitHub.
2. **Account Settings → API Tokens → New Token**. Scopes: **`publish-new`** and
   **`publish-update`**. Leave the crate scope empty for the first publish — a token cannot be
   scoped to a crate that does not exist yet. After `credenshare` exists, replace it with a
   token scoped to that crate alone.
3. Add it to the repository as the secret **`CARGO_REGISTRY_TOKEN`**, inside the `crates-io`
   environment.

### Go — nothing

The tag *is* the release; the module proxy serves it straight from the repository. This is also
why Go was the only one releasable before any of the above existed.

### Then, per repository

Add the secret to the **environment**, not just the repository, so it is scoped to the job that
needs it: *Settings → Environments → (`npm` | `crates-io`) → Add environment secret*.

Finally flip the switch: *Settings → Secrets and variables → Actions → Variables* and set
**`PUBLISH_TO_REGISTRY`** to `true`. The next tag publishes. Nothing else changes.

### Verifying before you tag

```bash
gh api repos/CredenShare/credenshare-sdk-node/environments --jq '.environments[].name'
gh api repos/CredenShare/credenshare-sdk-node/actions/variables --jq '.variables[]|"\(.name)=\(.value)"'
```

A tag with the switch off is still useful — it verifies the tag against the manifest, runs the
full suite and creates a GitHub Release. Only the upload is skipped, with a notice saying so.

### One thing that cannot be undone

**Deleting and recreating a repository destroys its environments, secrets and variables**, and
PyPI's trusted publisher is bound to the repository *name*, so it survives — but the GitHub
half does not. That happened on 2026-08-30 and is why this section exists.

## Cutting a release

Every SDK releases the same way: **tag, and CI does the rest**. Nothing is published from a
laptop.

```bash
# 1. Bump the version in the manifest, and add a CHANGELOG entry that says why.
#    Python: pyproject.toml    Node: package.json
#    Rust:   Cargo.toml        Go:   the Version constant in client.go
# 2. Commit that on its own.
# 3. Tag it.
git tag v0.2.0 && git push origin v0.2.0
```

Each release workflow refuses to publish unless the tag matches the version declared in the
manifest, because a release that says one thing on GitHub and another in the registry makes
"which version were you running" unanswerable — and that is the first question on every bug
report.

### What differs per language

Setup is above; this is what each mechanism means once it is running.

**Python** publishes through **OIDC trusted publishing** — no stored credential at all.

**Node** can do either, and the workflow accepts both: it uses `NPM_TOKEN` when that secret
exists and falls back to OIDC when it does not. The token path is what gets the first version
out, because npm generally wants a package to exist before a trusted publisher can be attached
to it. Delete the secret once a publisher is configured.

**Rust** needs a `CARGO_REGISTRY_TOKEN` secret: crates.io has no trusted-publishing equivalent
yet. It is the only unavoidable long-lived registry credential of the four, and after the first
publish it should be replaced with one scoped to the `credenshare` crate alone.

**Go has no publish step at all** — the tag *is* the release, resolved straight from the
repository by the module proxy. Two consequences worth internalising:

- A mistagged commit is public the instant it is pushed, and the proxy caches it **forever**.
  There is no yank. The only remedy is a new version.
- From **v2 onward the module path must carry the major version** (`.../credenshare-sdk-go/v2`).
  Tagging `v2.0.0` without moving the path yields a version the proxy will happily serve and
  `go get` cannot resolve — a broken release that looks published. CI checks for this, but
  decide it before v1 rather than after.

## Yanking

Yank a release if it produces bytes another implementation cannot read. That is the one
failure mode that is silent and permanent for the person on the other end, and it outranks the
inconvenience of a yank.

Yanking does not delete: existing lockfiles keep resolving. Follow it with a fixed version and
a changelog entry naming what was wrong, so somebody pinned to the bad one can tell whether it
affects them.
