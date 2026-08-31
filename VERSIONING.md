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

## Before the FIRST release: what must exist

Nothing has been released yet — all four sit at `0.1.0` with **zero tags**. Tagging before the
items below exist produces a red release run, and for Go a tag that cannot be withdrawn.

**These are per-repository settings, and deleting and recreating a repository destroys every
one of them.** That happened on 2026-08-30, so anything configured before that date is gone
and must be redone.

| Repo | Needs | Notes |
| ---- | ----- | ----- |
| Python | A PyPI **trusted publisher** for `CredenShare/credenshare-sdk-python`, workflow `release.yml`, environment `pypi`; plus a `pypi` environment on the repo | No stored token. Configure at pypi.org before the tag, or the OIDC exchange is refused |
| Node | An `npm` environment on the repo, and npm publishing rights for `@credenshare/sdk` | `--provenance` needs `id-token: write`, which the workflow has |
| Rust | A `crates-io` environment holding `CARGO_REGISTRY_TOKEN` | The only long-lived registry credential of the four. Scope it to publish-update on `credenshare` alone |
| Go | **Nothing.** | The tag *is* the release. This is also why Go is the only one that can be released today |

Verify before tagging, not after:

```bash
gh api repos/CredenShare/credenshare-sdk-node/environments   # expect the environment to exist
```

The package names are unclaimed on PyPI, npm and crates.io as of 2026-08-30. Until they are
published, every README installs from source — which works, and whose conformance self-check
behaves identically, so an install is verifiable either way.

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

**Python** and **Node** publish through **OIDC trusted publishing**, so there is no long-lived
registry token in either repository.

**Rust** still needs a `CARGO_REGISTRY_TOKEN` secret: crates.io has no trusted-publishing
equivalent yet. It is the only long-lived registry credential in the four, and it should be
scoped to publish-update on the `credenshare` crate alone.

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
