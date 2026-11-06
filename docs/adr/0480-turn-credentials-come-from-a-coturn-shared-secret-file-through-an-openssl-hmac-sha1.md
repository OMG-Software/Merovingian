# TURN credentials come from a coturn shared-secret file, through an OpenSSL HMAC-SHA1

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`GET /voip/turnServer` issued the same static credentials to every user, which a coturn `use-auth-secret`
deployment cannot use. That mode (the coturn REST API) expects username `<expiry>:<user_id>` and password
`base64(HMAC-SHA1(secret, username))`. libsodium, the only cryptographic library the `src/crypto/` boundary wraps,
has no SHA-1.

## Decision Outcome

* `server.turn.shared_secret_file` names an owner-only secret file. Each request reads it with
  `platform::read_secure_secret_file` into a `core::SecretBuffer` (trailing line ends dropped), builds the
  credentials and lets the buffer wipe itself. The secret is not kept in the runtime, copied into a `std::string`,
  logged or compared. Reading per request lets an operator rotate the secret by replacing the file, as the SMTP
  password does. An unreadable or empty file is a `500` and an error log naming no secret.
* The file and `server.turn.username`/`password` are mutually exclusive: a configuration with both is refused, so it
  is never unclear which credentials clients get. The static option keeps working unchanged.
* `crypto::hmac_sha1` (`src/crypto/hmac_sha1.cpp`) calls OpenSSL's `HMAC` with `EVP_sha1()`. OpenSSL is already a
  required dependency (TLS), so no new dependency enters the build; only `merovingian-crypto` now links it. Writing
  SHA-1 or HMAC by hand would be a custom primitive, which the boundary forbids. SHA-1 is allowed here for this one
  protocol: HMAC-SHA1 is not weakened by SHA-1 collisions, and coturn fixes the format. Nothing else may add SHA-1
  uses.
  SonarQube's weak-hash rule (`cpp:S4790`) is silenced with `NOSONAR` at that one call for this reason, so the finding
  cannot fail the quality gate; a second SHA-1 use would still be reported.
* No constant-time comparison applies: this server only creates the MAC. The TURN server verifies it.
* The credential ends at `now + ttl_seconds` (`server.turn.ttl_seconds`, default 24 hours); the response `ttl` is the
  same number.

Rejected: reading the secret once at startup (a rotation would need a restart, and the secret would sit in the
runtime for its life); a hand-written SHA-1; HMAC-SHA256 (coturn's REST API is defined with SHA-1 for the default
`use-auth-secret`).
