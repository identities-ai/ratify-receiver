# Security policy

## Reporting a vulnerability

Email **security@identities.ai**. Please do not open a public issue for a
suspected vulnerability.

Include what you have: affected version, a description of the behaviour, and a
reproduction if you have one. You will get an acknowledgement, and we will tell
you what we find and when a fix ships.

## What belongs here

This package decides whether a consequential action runs. A defect that lets an
action execute without a matching authorization is in scope, and so is anything
that weakens the binding between a decision and the action it authorized.
Concretely, report:

- a way for `guard` to invoke a protected handler without an explicit `allow`;
- two different payloads or actions that produce the same request hash;
- a payload or action that can change between being hashed and being acted on;
- a malformed or hostile Verify response that reaches the handler, or that turns
  replay protection off;
- anything a handler can read or modify that the signature does not cover.

## What belongs elsewhere

- **The Ratify protocol itself.** Specification, canonicalization, signature or
  certificate-chain behaviour goes to
  [ratify-protocol](https://github.com/identities-ai/ratify-protocol).
- **The hosted Ratify Verify service.** Availability, the API, or anything
  server-side goes to security@identities.ai with the service name in the
  subject. It is handled separately from this package.

If you are unsure which applies, send it to security@identities.ai and say so.

## Supported versions

This package is pre-1.0. Fixes land on the latest released version; there are no
maintained release branches yet.
