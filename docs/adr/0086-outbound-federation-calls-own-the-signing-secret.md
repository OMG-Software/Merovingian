# Outbound federation calls own the signing secret

* Status: accepted
* Date: 2026-10-01

## Context and Problem Statement

The homeserver keeps its Ed25519 signing secret in `runtime.database.signing_secret_key`, a `core::SecretBuffer` that is mlocked in process memory. Outbound federation calls were passed a `std::span` borrowed from that buffer, and then released `runtime.mutex` before the network round trip and the X-Matrix signature. Because `ensure_runtime_server_signing_key()` can move-assign a new `SecretBuffer` into the runtime slot while another thread is signing with the old span, the span could dangle and produce a heap-use-after-free inside `crypto::ed25519_sign_detached`. How do we keep the key material mlocked while ensuring no outbound call can sign with a freed span?

## Decision Drivers

* The secret must stay in `core::SecretBuffer` (mlocked, zeroised) and never in an unpinned `std::string` or raw pointer.
* Outbound calls release `runtime.mutex` around blocking network I/O, so they cannot borrow runtime state that might be mutated underneath them.
* A signing-key rotation or reload must not invalidate in-flight signatures.

## Considered Options

1. **Keep the span and hold runtime.mutex while signing.** Rejected: signing happens after host discovery and TLS negotiation, which can block for seconds; holding the recursive runtime mutex across federation I/O serialises every other request.
2. **Copy the secret into a plain `std::vector`/`std::string` for the call.** Rejected: it removes the mlock guarantee and expands the window in which the key material is in ordinary pageable memory.
3. **Copy the secret into an owned `core::SecretBuffer` while the caller still holds runtime.mutex, then move it into the outbound call.** Accepted: it keeps the mlock/pinning property, gives the call independent ownership, and lets the network path release the mutex safely.

## Decision Outcome

Chosen option: "copy into an owned `core::SecretBuffer`".

`federation::OutboundCall::secret_key` is now a `core::SecretBuffer` instead of a `std::span`. Every caller that prepares an outbound call copies the runtime signing secret into a local `core::SecretBuffer` while holding `runtime.mutex` and moves that owned buffer into the call. The copy is small (64 bytes for Ed25519), so the cost is negligible compared with the network round trip.

### Consequences

* Positive: no outbound call can sign with freed key material, even if the runtime key is rotated or reloaded during the network round trip.
* Positive: the secret remains mlocked for the entire lifetime of the call object.
* Negative: a 64-byte mlocked allocation is made per outbound call; acceptable given the security gain and the bounded number of concurrent calls.

## Compliance

* `core::SecretBuffer` is move-only; `OutboundCall` is therefore also move-only. Code that copied `OutboundCall` objects will fail to compile, which is desirable because a copied call would duplicate the transaction state and signing material.

## Related

* `docs/adr/0015-keep-the-signing-secret-out-of-the-federation-worker.md`
* `docs/adr/0044-wipe-secrets-with-an-optimisation-barrier.md`
