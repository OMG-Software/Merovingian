# Refuse an unlocked master key

* Status: accepted
* Date: 2026-10-18

## Context and Problem Statement

ADR-0018 records the former warn-and-continue policy for failed master-key
memory locking. The 0.12.5 security repair changed `load_master_key_material`
to reject an unlocked root secret, but the old ADR and crypto guide still
prescribed continuing. This record documents that existing implementation;
it introduces no runtime change.

The master key derives the signing-secret encryption key, token-hash keys and
IPC authentication key. Continuing with pageable root material would silently
weaken their shared storage boundary.

## Considered Options

* Refuse to use master-key material whose memory lock failed.
* Warn once and continue with zeroisation but potentially pageable memory.

## Decision Outcome

Chosen option: **refuse to use an unlocked master key**. The secure-file
reader returns no material if its `SecretBuffer` is unlocked; the loader also
checks lock success defensively. The secure-reader failure is currently
reported through the generic `master_key.load_failed` diagnostic in the `crypto` module;
the later `master_key.not_mlocked` branch is not the ordinary reader-failure
path. Operators must correct file admission or the service's locked-memory
allowance rather than rely on an availability fallback.

This supersedes [ADR-0018](0018-warn-rather-than-abort-when-memory-locking-fails.md).
It applies to master-key admission, not to every general `SecretBuffer`:
signing-secret allocations do not all enforce lock success. Derived
`SecureKeyBytes` allocations have their own fail-closed locking requirement
([ADR-0128](0128-lock-derived-key-storage-without-changing-persisted-derivations.md)).

### Positive Consequences

* Root-key admission cannot silently fall back to pageable storage.
* Documentation and the accepted ADR register match the implemented policy.

### Negative Consequences

* An insufficient `RLIMIT_MEMLOCK` can prevent startup or key-dependent work.
  Raise the service limit or provision `CAP_IPC_LOCK` where appropriate;
  do not restore the old warn-and-continue branch.

## Links

* [Master-key implementation](../../src/crypto/master_key.cpp)
* [Cryptographic boundary](../crypto-boundary.md)

<!-- Recorded in 0.12.29; the implementation predates this record (0.12.5). -->
