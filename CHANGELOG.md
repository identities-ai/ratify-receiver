# Changelog

This project follows [semantic versioning](https://semver.org/). While the
version is below 1.0, minor releases may contain breaking changes.

## 0.1.3 (2026-09-16)

Corrected the published package metadata and switched npm publishing to GitHub
OIDC Trusted Publishing.

## 0.1.0 (deprecated)

First release: a TypeScript helper that guards a protected handler with Ratify
Verify, extracted from the Ratify service repository and published standalone.

This version is deprecated because it declared the protocol as a direct
dependency. Use 0.1.3 or later.

### The design worth knowing about

- **The handler is passed to `guard`, not called by the integrator.** A receiver
  that verifies and then forgets to branch is indistinguishable from one that
  never verified, and it passes every test that only inspects decisions.
- **The payload is snapshotted before it is hashed.** `guard` takes an owned,
  deeply frozen copy, reading every value once. The digest comes from that copy
  and the handler receives that same copy, so a payload cannot change between
  being authorized and being acted on, and distinctions that no verifier can see
  cannot reach the handler.
- **A replayed allow does not run the handler.** Ratify answers a known
  `invocationId` from its record and cannot say whether the handler ran, so
  re-running it would risk acting twice on one authorization. `onReplay: "run"`
  opts out.
- **`GuardResult` has no `allowed` boolean.** A replayed allow is authorized and
  did not run; one boolean cannot say both. Branch on `status`.
- **Non-JSON payloads are refused, never coerced.** A serializer that turns what
  it does not understand into `{}` lets two different actions share one digest.

### Requirements

- Node.js 22 or newer.
- `@identities-ai/ratify-protocol` is a **peer dependency**, so exactly one copy
  exists in your tree. Two copies at different versions would compute different
  request hashes and disagree silently.
