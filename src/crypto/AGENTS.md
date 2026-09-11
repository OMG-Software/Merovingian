# src/crypto/ — Cryptography Module

All cryptographic operations flow through the interfaces defined here.
**Never call libsodium functions directly from outside `src/crypto/`, `src/events/`, `src/auth/`
or `src/core/secret_buffer.cpp`.** `scripts/reject-unsafe.sh` enforces this for both calls and
`<sodium.h>` includes (ADR-0014).

## What lives here

| File | Purpose |
|---|---|
| `ed25519.cpp` | Key/signature shape validation; key ID format validation; keypair generation into `SecretBuffer` |
| `runtime_ed25519_provider.cpp` | `RuntimeEd25519Provider` — the production libsodium `Ed25519Provider` |
| `runtime_multikey_ed25519_provider.cpp` | `RuntimeMultiKeyEd25519Provider` — production provider holding several signing keys |
| `signing_service.cpp` | Server signing-key selection and delegation to the Ed25519 provider |
| `constant_time.cpp` | Constant-time byte comparison (wraps `sodium_memcmp`) |
| `random.cpp` | Bounded random byte generation (wraps `randombytes_buf`) |
| `generic_hash.cpp` | Domain-separated BLAKE2b hashing helpers |
| `encoding.cpp` | Hex and base64 (URL-safe and original) encoding wrappers |
| `master_key.cpp` | Loads and validates the operator master key into locked memory; fails closed if it cannot be locked |
| `secret_box.cpp` | `SecretBoxKey` — encrypts server signing secrets at rest (`secretbox:v1:` format) |
| `token_key.cpp` | `TokenHmacKey` — master-key-derived key for `v3`/`v4` access-token hashing |
| `ipc_auth_key.cpp` | `IpcAuthKey` — master-key-derived key that authenticates the federation-worker IPC handshake |
| `ipc_stream_cipher.cpp` | `crypto_kx` session keys and `secretstream` AEAD framing for the IPC channel |

## Security rules — non-negotiable

1. **Never log key material.** No private key bytes, signatures, or access tokens in log output.
   Wrap sensitive data in `SecretBuffer` from `core/secret_buffer.hpp`.

2. **Always use constant-time comparison for secrets.** Call `constant_time_equal()` from
   `constant_time.hpp`. Never use `==`, `memcmp`, or `std::equal` on secret bytes.

3. **Fail closed.** If the signing key is unavailable, signing must fail — never fall back to
   an unsigned output or a weaker operation.

4. **Validate external key material before use.** Call `ed25519_public_key_shape_is_valid()` and
   `ed25519_signature_shape_is_valid()` on any key or signature received from a remote server.

5. **Validate key IDs.** Call `ed25519_key_id_is_valid()` — key IDs must start with `ed25519:`
   and contain only printable non-space ASCII.

## Provider interface pattern

`Ed25519Provider` (in `ed25519.hpp`) decouples signing from the libsodium implementation.
Production code uses the libsodium provider. Tests inject a deterministic double.
Do **not** bypass this interface by calling libsodium functions directly.

## What is deliberately NOT here

- Password hashing — uses `crypto_pwhash` in `src/auth/` (one-way, no key management needed)
- Access-token hashing — the `crypto_generichash` call over the token stays in `src/auth/token.cpp`;
  only the `v3`/`v4` HMAC key it uses is derived here, in `token_key.cpp`
- SHA-256 content/reference hashes — used directly in `src/events/` via the canonical JSON pipeline

## Key spec sections

- [Signing JSON](../../docs/matrix-v1.19-spec/appendices.md#signing-json)
- [Cryptographic key representation](../../docs/matrix-v1.19-spec/appendices.md#cryptographic-key-representation)
- [Event signing](../../docs/matrix-v1.19-spec/server-server-api.md#signing-events)
