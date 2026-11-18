# src/crypto/ — Cryptography Module

All cryptographic operations flow through the interfaces defined here.
**Never call libsodium functions directly from outside `src/crypto/`, `src/events/`, `src/auth/`
or `src/core/SecretBuffer.cpp`.** `scripts/reject-unsafe.sh` enforces this for both calls and
`<sodium.h>` includes (ADR-0014).

## What lives here

| File | Purpose |
|---|---|
| `Ed25519.cpp` | Key/signature shape validation; key ID format validation; keypair generation into `SecretBuffer` |
| `RuntimeEd25519Provider.cpp` | `RuntimeEd25519Provider` — the production libsodium `Ed25519Provider` |
| `RuntimeMultiKeyEd25519Provider.cpp` | `RuntimeMultiKeyEd25519Provider` — production provider holding several signing keys |
| `RefusingEd25519Provider.cpp` | `RefusingEd25519Provider` — the federation worker's provider: refuses every `sign` and `verify` (ADR-0078) |
| `SigningService.cpp` | Server signing-key selection and delegation to the Ed25519 provider |
| `HmacSha1.cpp` | `hmac_sha1`: OpenSSL's `HMAC` with SHA-1, for the coturn REST API's TURN password only (ADR-0480). Not for any new use of SHA-1 |
| `LiveKitToken.cpp` | LiveKit HS256 tokens (ADR-0828): `sign_livekit_participant_token` (grant type cannot express create, admin or hidden), `sign_livekit_room_create_token` (`roomCreate` only), `sign_livekit_room_admin_token` (`roomAdmin` for one named room, for `GetParticipant`) and `verify_hs256_token` (webhooks; never reads `alg`). libsodium HMAC-SHA256 stays internal: there is no general HMAC-SHA256 or "sign these bytes" function |
| `ConstantTime.cpp` | Constant-time byte comparison (wraps `sodium_memcmp`) |
| `Random.cpp` | Bounded random byte generation (wraps `randombytes_buf`) |
| `GenericHash.cpp` | Domain-separated BLAKE2b hashing helpers |
| `Sha256.cpp` | `sha256`: SHA-256 for protocols that name it (PKCE `S256`, the page policy's style hash); a hash of the project's own choosing uses `GenericHash` |
| `Encoding.cpp` | Hex and base64 (URL-safe and original) encoding wrappers |
| `MasterKey.cpp` | Loads and validates the operator master key into locked memory; fails closed if it cannot be locked |
| `SecretBox.cpp` | `SecretBoxKey` — encrypts server signing secrets at rest (`secretbox:v1:` format) |
| `TokenKey.cpp` | `TokenHmacKey` — master-key-derived keys for `v3`/`v4` access-token hashing, cached together (`cached_token_hmac_keys`), and the OAuth client ID key (own label, ADR-0779), derived per registration by `derive_oauth_client_id_key_from_file` and never cached: every cached key is a locked page held for the life of the process, from a per-process budget (`RLIMIT_MEMLOCK`, 64 KiB by default on FreeBSD) the other secrets need too, so `TokenHmacKeys` holds the two access-token keys only (ADR-0779, amended) |
| `OAuthClientId.cpp` | `oauth_client_id`: keyed BLAKE2b of canonical OAuth client metadata, 43 URL-safe base64 characters (ADR-0779) |
| `IpcAuthKey.cpp` | `IpcAuthKey` — master-key-derived key that authenticates the federation-worker IPC handshake |
| `IpcStreamCipher.cpp` | `crypto_kx` session keys and `secretstream` AEAD framing for the IPC channel |

## Security rules — non-negotiable

1. **Never log key material.** No private key bytes, signatures, or access tokens in log output.
   Wrap sensitive data in `SecretBuffer` from `core/SecretBuffer.hpp`.

2. **Always use constant-time comparison for secrets.** Call `constant_time_equal()` from
   `ConstantTime.hpp`. Never use `==`, `memcmp`, or `std::equal` on secret bytes.

3. **Fail closed.** If the signing key is unavailable, signing must fail — never fall back to
   an unsigned output or a weaker operation.

4. **Validate external key material before use.** Call `ed25519_public_key_shape_is_valid()` and
   `ed25519_signature_shape_is_valid()` on any key or signature received from a remote server.

5. **Validate key IDs.** Call `ed25519_key_id_is_valid()` — key IDs must start with `ed25519:`
   and contain only printable non-space ASCII.

6. **A derived-key cache takes the master key's identity and its bytes from one open.** Use
   `open_master_key_file()` and `load_master_key_material(opened)`; never call
   `master_key_file_identity(path)` and then `load_master_key_material(path)`. Two opens let a
   file swapped in between leave a key from one file cached under another's identity (ISO-7).

## Provider interface pattern

`Ed25519Provider` (in `Ed25519.hpp`) decouples signing from the libsodium implementation.
Production code uses the libsodium provider. Tests inject a deterministic double.
Do **not** bypass this interface by calling libsodium functions directly.

## What is deliberately NOT here

- Password hashing — uses `crypto_pwhash` in `src/auth/` (one-way, no key management needed)
- Access-token hashing — the `crypto_generichash` call over the token stays in `src/auth/Token.cpp`;
  only the `v3`/`v4` HMAC key it uses is derived here, in `TokenKey.cpp`
- SHA-256 content/reference hashes — used directly in `src/events/` via the canonical JSON pipeline
  (every other SHA-256 goes through `crypto::sha256`)

## Key spec sections

- [Signing JSON](../../docs/matrix-v1.19-spec/appendices.md#signing-json)
- [Cryptographic key representation](../../docs/matrix-v1.19-spec/appendices.md#cryptographic-key-representation)
- [Event signing](../../docs/matrix-v1.19-spec/server-server-api.md#signing-events)
