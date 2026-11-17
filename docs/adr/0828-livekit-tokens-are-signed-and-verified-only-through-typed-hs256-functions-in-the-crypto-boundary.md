# LiveKit tokens are signed and verified only through typed HS256 functions in the crypto boundary

* Status: accepted
* Date: 2026-11-17

## Context and Problem Statement

The built-in MatrixRTC token service (MSC4195) hands clients LiveKit access tokens and calls LiveKit's room service,
and LiveKit signs the webhooks it sends. All three are JSON Web Tokens signed with HS256 (HMAC-SHA256) under the
LiveKit API secret. The project has HMAC-SHA1 for coturn only (ADR-0480) and no HMAC-SHA256, and a general
"sign these bytes" function would let any later code mint tokens with any rights, under the one secret that controls
the SFU.

## Decision Drivers

* A token never grants `roomCreate` to a participant, `roomAdmin`, `hidden`, or any right this server did not decide on.
* No new dependency, and no hand-written primitive.
* A webhook is accepted only under a MAC check that cannot be steered by the token itself.

## Considered Options

* A general `hmac_sha256(key, message)` and a JWT builder outside the crypto boundary.
* OpenSSL's `HMAC` with `EVP_sha256()`, as `hmac_sha1` uses.
* Typed signers and one verifier in `src/crypto/LiveKitToken.cpp`, over libsodium's `crypto_auth_hmacsha256`.

## Decision Outcome

Chosen option: typed signers and one verifier over libsodium, because no caller can widen what a token says, and
libsodium's HMAC-SHA256 is already in the build.

* `crypto/LiveKitToken.hpp` declares exactly three operations:
  * `sign_livekit_participant_token(api_key, api_secret, LiveKitParticipantGrant)`. The grant type holds the MSC4195
    identity and room name, one `can_publish` flag (which sets `canPublish` and `canPublishData` together), and
    `nbf`/`exp`. It has no field for `roomCreate`, `roomAdmin`, `roomList`, `roomRecord`, `ingressAdmin`, `hidden`,
    `canUpdateOwnMetadata`, a name, metadata or attributes, so no participant token can carry them. `roomJoin` and
    `canSubscribe` are always true.
  * `sign_livekit_room_create_token(api_key, api_secret, nbf, exp)`: `video` is `{"roomCreate":true}` and nothing else,
    with no `sub` and no `room`. It is used for `CreateRoom` only.
  * `verify_hs256_token(token, secret)`, for LiveKit's webhook requests. It bounds the token at 4,096 bytes, requires
    exactly three non-empty unpadded URL-safe base64 segments, computes HMAC-SHA256 over the first two segments as
    received, and compares it with the third in constant time (`constant_time_equal`, 32 bytes). It decodes the header
    and payload only after the MAC matches, returns them undecided, and never reads the header's `alg`: an
    `alg: none` or any other algorithm claim cannot change what is checked. The caller judges every claim.
* The HMAC is libsodium's `crypto_auth_hmacsha256_init`/`update`/`final`, which takes a key of any length, as RFC 7518
  section 3.2 requires. It stays in an anonymous namespace; the state is wiped after use. It is not exported.
* Every value placed in a token is checked before it is written, so the JSON needs no escaping:
  * the API key is 1 to 128 ASCII letters, digits, `_`, `-` and `.`;
  * the identity and room are 43 characters of the standard base64 alphabet;
  * `nbf` is not negative and `exp` is after it.
* The payload's keys are in lexical order. Its characters cannot form a base64 group of 62 or 63, so the encoded
  payload has no `-` or `_`. Element Call reads it with `atob`, which knows only the standard alphabet, so the signer
  refuses (rather than emits) a payload that would contain either.
* The secret must be at least 32 bytes, for signing and verifying alike. The caller reads it per use from its file into
  a `core::SecretBuffer`. This file holds no secret.
* HMAC-SHA1 stays for coturn alone (ADR-0480). Nothing here uses it.

### Positive Consequences

* A participant token's rights are fixed by a type, and the tests pin the exact bytes of every token kind against
  vectors computed apart from this code (Python's `hmac`). The verifier is checked against RFC 7515 Appendix A.1.
* A future LiveKit call that needs a different grant must add a typed signer here, under review, and record the
  call in an ADR.

### Negative Consequences

* A new LiveKit grant (for example a participant lookup with `roomAdmin`) cannot be added from the homeserver module
  alone. That is the point.

## Pros and Cons of the Options

### A general HMAC-SHA256 and a JWT builder outside the boundary

* Good, because it is flexible.
* Bad, because any caller could sign a token with `roomAdmin` or `hidden` under the SFU's secret.

### OpenSSL `HMAC` with SHA-256

* Good, because it matches `hmac_sha1`.
* Bad, because libsodium already offers HMAC-SHA256 with an arbitrary-length key, and the boundary prefers libsodium
  where it has the primitive (ADR-0014); OpenSSL was admitted for SHA-1 only because libsodium has none.

## Links

* Refines [ADR-0480](0480-turn-credentials-come-from-a-coturn-shared-secret-file-through-an-openssl-hmac-sha1.md) and [ADR-0014](0014-confine-cryptographic-primitives-behind-providers.md)
* [MSC4195](https://github.com/matrix-org/matrix-spec-proposals/blob/6d49798949e1b31023565d4ff1c7fe10f4cacf83/proposals/4195-matrixrtc-livekit.md)
* [RFC 7515 Appendix A.1](https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1),
  [RFC 7518 section 3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2)
