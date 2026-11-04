# A cross-signing upload is verified against the accompanying or held master key

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`POST /keys/device_signing/upload` stored a self-signing or user-signing key without checking its signature, although
the spec says it "Must be signed by the accompanying master signing key, or by the user's most recently uploaded master
signing key if no master signing key is included in the request" and lists `M_INVALID_SIGNATURE`. Test fixtures used
invented key and signature text, so the check looked costly to add.

## Decision Outcome

`cross_signing_upload_refusal` verifies the signature before any write. The verifying key is the master key in the
request, else the master row held for the user (an upload replaces the row, so it is the most recently uploaded one).
A key is accepted only as `ed25519:<k>` whose value is `<k>` and decodes to 32 bytes: another algorithm cannot be
verified here, so it is refused rather than stored unchecked. The signature is over the canonical JSON without
`signatures` and `unsigned`; other signatures on the key are ignored; a master key's own signatures are not checked.

Rejected: leaving the check out because fixtures were fake. The fixtures are the thing to fix:
`tests/support/cross_signing_fixture.hpp` generates real keys and signatures, and a test that uploads cross-signing keys
uses it. Do not loosen the check (padded base64, a value that differs from the key name, a missing signature) to let an
invented fixture through.

### Consequences

* A client that uploads a self-signing key with no master key at all gets `M_MISSING_PARAM`, as the spec lists.
* Verification runs under `runtime.mutex` and costs one Ed25519 verification per signed key (at most two) plus one
  scan of the user's at most three stored rows.
