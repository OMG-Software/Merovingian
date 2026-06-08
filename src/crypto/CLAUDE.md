# src/crypto/ — Cryptography Module

All cryptographic operations flow through the interfaces defined here.
**Never call libsodium functions directly from outside `src/crypto/` or `src/events/`.**

## What lives here

| File | Purpose |
|---|---|
| `ed25519.cpp` | Key/signature shape validation; key ID format validation |
| `signing_service.cpp` | Server signing-key selection and delegation to the Ed25519 provider |
| `constant_time.cpp` | Constant-time byte comparison (wraps `sodium_memcmp`) |
| `random.cpp` | Bounded random byte generation (wraps `randombytes_buf`) |

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
- Access-token hashing — uses `crypto_generichash` in `src/auth/`
- SHA-256 content/reference hashes — used directly in `src/events/` via the canonical JSON pipeline

## Key spec sections

- [Signing JSON](https://spec.matrix.org/v1.18/appendices/#signing-json)
- [Cryptographic key representation](https://spec.matrix.org/v1.18/appendices/#cryptographic-key-representation)
- [Event signing](https://spec.matrix.org/v1.18/server-server-api/#signing-events)
