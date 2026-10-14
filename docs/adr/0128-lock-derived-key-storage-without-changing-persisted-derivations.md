# Lock derived-key storage without changing persisted derivations

* Status: accepted
* Date: 2026-10-11

## Context and Problem Statement

CRY-3 and CRY-4 of the 29 September audit require a valid random root and
reliable locked storage. The audit also proposes replacing the existing
BLAKE2b derivation with `crypto_kdf_derive_from_key`. That is not a storage-only
change: the existing derivations protect persisted signing-key ciphertext and
access/refresh-token digests. A silent replacement would strand those records.

## Decision Drivers

* Keep live roots, derived keys and cached-key copies in independently locked,
  wiped allocations.
* Refuse invalid root files and failed key allocation without weakening issuance.
* Preserve encrypted data and existing digest validation formats.
* Do not mistake a length/all-zero check for an entropy test.

## Considered Options

* Harden storage and root admission while preserving existing derivations.
* Replace derivations in place with the audit's suggested KDF.
* Introduce a separately versioned derivation with an explicit data migration.

## Decision Outcome

Chosen option: "Harden storage and root admission while preserving existing
derivations". `SecretBuffer` uses isolated sodium allocations; derived-key
value types use independently locked `SecureKeyBytes`, including copies.
Optional derivation and cache interfaces fail closed when locking/allocation
fails. New token issuance requires v4 and returns HTTP 503 when that key is
unavailable; legacy validation is not an issuance fallback.

The root file requires 32–4096 bytes and rejects all-zero material. Operators
must still supply cryptographically random bytes. Existing BLAKE2b
message/key orientation and all domain-separation labels remain unchanged;
compatibility is covered by a regression against the historical algorithm.

### Positive Consequences

* No silent loss of signing-key decryptability or token validation compatibility.
* Destroying one small secret allocation cannot unlock a neighbouring key.
* Memory-lock exhaustion refuses credential issuance instead of downgrading it.

### Negative Consequences

* Small-key copies consume isolated pages and locked-memory budget; deployments
  may need to raise their memory-lock allowance.
* A new KDF is deliberately not introduced in this fix. A future derivation
  change must use a new persisted format, migration and compatibility tests.

## Pros and Cons of the Options

### Replace derivations in place

* Bad, because an apparently stronger primitive does not migrate existing
  ciphertext or digests and cannot recover a low-entropy operator root.

### Introduce a versioned derivation and migration

* Good, because it permits a reviewed format transition.
* Bad for this pass, because it adds a separate migration/key-rotation problem
  rather than repairing the demonstrated storage and admission defects.
