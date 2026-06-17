# Cryptography boundary and signing service scaffold

This capability note describes project-owned cryptography interfaces without
implementing custom cryptographic primitives.

## Included now

- Constant-time comparison boundary (fixed and variable-length inputs).
- Variable-length comparison uses domain-separated hashing so it does not leak
  input length through a premature length check.
- Runtime signing secret material is held in `core::SecretBuffer` (mlocked,
  zeroised-on-destruction) while in process memory.
- Random-source interface for future reviewed RNG integration.
- Ed25519 provider interface for reviewed signing and verification integration.
- Server signing-key store interface.
- Server signing service that selects the active server key and delegates
  signing to a provider.
- Runtime server signing-key persistence for the current local Ed25519 key.
- Explicit server signing-key rotation (`rotate_server_signing_key`) that retires
  the active key into `old_verify_keys` and activates a freshly generated key.
- Validation for Ed25519 public-key shape, signature shape, and key IDs.
- Bounded random request-size validation.
- Event-signing integration tests using deterministic provider doubles.
- Cryptographically random Ed25519 keypair generation for runtime signing
  (replacing the previous deterministic derivation from public values).
- `secret_box` authenticated encryption for at-rest signing-secret storage,
  using a domain-separated XSalsa20-Poly1305 key derived from a configured
  master key (`security.secrets.master_key_file`).

## Security posture

Local homeserver password hashing, access-token generation, access-token
hashing, media deduplication hashes, and Matrix event hashes use LibSodium.
Event signing and verification now flow through the Ed25519 provider interface.
Runtime-created local room events use the persisted server signing-key record
and fail closed if the signing key cannot be materialized.
Access-token and refresh-token hashes now use a keyed BLAKE2b (`token-hash:v3`)
construction seeded from runtime secret material; the previous unkeyed
`token-hash:v2` form remains accepted only for lookup compatibility with older
persisted rows.
- Variable-length secret comparison does not branch on input length before
  computing a fixed-size digest, removing a timing side-channel on secret size.
- Signing secret material is held in a `core::SecretBuffer` while in process memory
  and is zeroised when the buffer is destroyed or moved-from.

The runtime signing key is generated using `crypto_sign_keypair`, which produces
a cryptographically random keypair. When `security.secrets.master_key_file` is
configured, the secret seed is encrypted at rest with `secret_box` and a
random nonce, stored as `secretbox:v1:<base64(nonce || mac || ciphertext)>`, and
transparently decrypted on restart. If no master key is configured the secret is
stored as a legacy plaintext base64 value and a one-time diagnostic warns the
operator; this fallback preserves backward compatibility with existing
deployments and test configurations. An explicit rotation is available via
`rotate_server_signing_key`: it retires the active key (setting its
`valid_until_ts` to now so it publishes under `old_verify_keys` with a past
`expired_ts`) and activates a freshly generated key. `ensure_runtime_server_signing_key`
selects the key with the greatest `valid_until_ts`, so the rotated-in key becomes
active while peers can still verify events signed under the retired key. A single
key is active at a time.
Comma-delimited PDUs without JSON are rejected when a signing key is available,
closing the legacy-verification bypass.

The boundary provides these guarantees:

- Application code depends on project-owned interfaces, not dependency-specific types.
- Signing fails closed when no active usable key exists.
- Providers returning invalid signature shapes are rejected.
- Key IDs must be Ed25519-shaped before use.
- Matrix event signatures are encoded as unpadded Base64 and verified against
  the redacted canonical payload.
- Runtime event signatures are stored with event rows and the corresponding
  public signing key is persisted for local verification/key publication work.
- Random byte requests are bounded at the interface edge.
- Runtime signing keys are generated from system entropy, not derived from
  public server identity values.
- Newly issued bearer-token digests are keyed, so a database leak no longer
  exposes reusable unkeyed token hashes for offline correlation.
- The server signing secret is encrypted at rest when a master key is configured;
  deployments without a master key fall back to plaintext with a diagnostic so the
  operator can rotate to encrypted storage.
- Commma-delimited PDUs without JSON body are rejected rather than bypassing
  Ed25519 cryptographic verification.

## Deliberately not included

These remain deferred:

- Simultaneously-active multiple signing keys (one key is active at a time).
- Audit-log persistence for signing-key lifecycle changes.
- Hardware-backed key support.
- Encrypted key storage without operator-supplied master-key material (the master
  key file must be provisioned and protected by the administrator).

## Next starting points

1. Add dependency review documentation for the selected crypto provider.
2. Add a concrete production provider behind the Ed25519 and RNG interfaces.
3. Add audit events for signing-key lifecycle changes.
4. Investigate hardware-backed key storage (HSM or key vault) for operator-managed
   deployments that cannot rely on a filesystem master key.
