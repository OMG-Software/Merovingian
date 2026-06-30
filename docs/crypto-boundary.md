# Cryptography boundary and signing service scaffold

This capability note describes project-owned cryptography interfaces without
implementing custom cryptographic primitives.

## Included now

- Constant-time comparison boundary (fixed and variable-length inputs).
- Variable-length comparison uses domain-separated hashing so it does not leak
  input length through a premature length check.
- Runtime signing secret material is held in `core::SecretBuffer` (mlocked,
  zeroised-on-destruction) while in process memory. The destructor and custom
  move operations use `sodium_munlock`/`sodium_memzero`, which are optimisation
  barriers the compiler cannot elide, and the `mlock`/`munlock` pair stays
  aligned across moves so a move over a mlocked buffer neither leaks the lock
  nor leaves the source bytes unwiped.
- Random-source interface for future reviewed RNG integration.
- Ed25519 provider interface for reviewed signing and verification integration.
- Server signing-key store interface.
- Server signing service that selects the active server key and delegates
  signing to a provider.
- Runtime server signing-key persistence for the current local Ed25519 key.
- Explicit server signing-key rotation (`rotate_server_signing_key`) that retires
  the active key into `old_verify_keys` and activates a freshly generated key.
- Centralised runtime signing provider (`HomeserverRuntime::crypto_provider`)
  so every server signing path uses one provider instance.
- Sign-back IPC channel for the out-of-process federation worker: the worker
  delegates Ed25519 signing to the main process over the encrypted IPC channel
  via `IpcEd25519Provider`; the private key never enters the worker address space.
- Master-key-authenticated IPC key exchange (#318): both the main process and the
  worker derive the same 32-byte IPC auth key from the operator master-key file
  (the same material used for at-rest signing-secret encryption and v4
  access-token keys) via a domain-separated label `merovingian:ipc-channel-auth:1`
  (distinct from the v3/v4 access-token HMAC labels). Each side MACs the other's
  ephemeral `crypto_kx` public key (and its role) with `crypto_auth` before
  deriving session keys, so a local process that reaches the inherited `AF_UNIX`
  fd without the master key cannot complete the handshake or inject AEAD frames.
  The auth key is wiped with `sodium_memzero` after the handshake.
- Verified-identity IPC forwarding (#323): the main process verifies the inbound
  peer X-Matrix signature and forwards only the verified identity
  (`origin`/`key_id`/`sig_verified`) to the worker; the raw peer `access_token`
  and `Authorization`/`X-Matrix` headers are stripped from the `fed_request` frame
  and never cross IPC, so a compromised worker cannot harvest or replay peer
  homeserver credentials. The outbound `Authorization` header that does cross IPC
  is our own request-bound X-Matrix signature (not a reusable peer credential);
  the signing secret itself never enters the worker (#317).
- The outbound signing path keeps the server signing secret in a `core::SecretBuffer`
  or a borrowing `std::span<std::uint8_t const>`, never a `std::string`. `make_federation_signature`,
  `OutboundCall::secret_key`, `DispatchWorkerConfig::secret_key`, and `perform_sync_outbound_call`
  accept a span; production call sites pass `signing_secret_key.bytes()` directly, and
  `DispatchWorkerConfig::secret_key` owns an mlocked `SecretBuffer` copy constructed from
  that span. This removes the `std::string{reinterpret_cast<…>(…bytes().data()…)}` copies that
  left the key unpinned and unzeroised on the heap.
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
  and is zeroised when the buffer is destroyed or moved-from. The wipe is non-elidable
  (`sodium_munlock`/`sodium_memzero`), and custom move-ctor/move-assign transfer the
  mlock to the destination while wiping the source, so the secret is never duplicated
  in memory and never left pinned in a moved-from object. The outbound federation
  signing path (`make_federation_signature`, `OutboundCall`, `DispatchWorkerConfig`,
  `perform_sync_outbound_call`) consumes the key as a borrowing span off the
  `SecretBuffer` (or an owned `SecretBuffer` copy in the dispatch worker), so the key
  is never copied into an unpinned, unzeroised `std::string` to sign a request.

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

## IPC channel key exchange

The encrypted channel between `merovingian-server` and `merovingian-fed-worker`
(`src/ipc/channel.cpp`) uses libsodium key exchange and authenticated encryption:

- **Ephemeral key pair**: each side generates a fresh `crypto_kx_keypair` on
  every connection. Neither party persists the IPC key material; compromise of
  the IPC key does not affect the server's Matrix signing key.
- **Key exchange**: `crypto_kx_server_session_keys` / `crypto_kx_client_session_keys`
  derive two one-directional session keys (tx and rx) from the ephemeral pair.
  The exchange is authenticated — both sides must contribute valid key material
  or the session fails.
- **Authenticated encryption**: all subsequent frames use
  `crypto_secretstream_xchacha20poly1305` (XChaCha20-Poly1305 AEAD). Each
  frame is independently authenticated; a truncated or tampered frame is
  rejected before the plaintext is consumed.
- **Framing**: `[4-byte big-endian ciphertext_length][ciphertext]`. The
  ciphertext includes the AEAD MAC overhead so the receiver can verify integrity
  before decrypting.
- **Isolation**: client access tokens are stripped from every forwarded request.
  The Matrix signing key is never transmitted over the IPC channel. The worker
  does not load the signing secret from the database; instead it sends
  `sign_request` frames and the main process signs with the in-memory production
  provider, returning only the unpadded base64 signature.

The IPC channel is tested by `tests/unit/test_ipc_framing.cpp` covering:
concurrent key exchange, request/response pairing, notification delivery,
timeout behaviour when no reply arrives, and the `IpcEd25519Provider` sign-back
round-trip.

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
