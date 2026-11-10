# Fallback keys are capped per device by algorithm count, not by an algorithm allow-list

* Status: accepted
* Date: 2026-11-10

Technical Story: GHSA-3p9g-gpvx-2cx9 (internal adversarial audit run-1, `F-business-logic.key-upload.unbounded-fallback-keys`)

## Context and Problem Statement

`POST /keys/upload` keeps one fallback key per algorithm for each device, as the specification requires: a new key replaces
the held key whose ID has the same algorithm prefix (the key ID up to and including its first `:`). Nothing bounded how
many algorithms a device could name, so a client choosing a fresh prefix per key added a row each time. Every row is
persisted, kept in the main process for its lifetime, loaded at start-up, and scanned by `/sync` and `/keys/claim`. How
should the fallback keys one device holds be bounded?

## Decision Drivers

* Bounded storage per authenticated account, under `runtime.mutex` and across restarts.
* The CSAZ-10 policy for end-to-end key material: an over-cap upload is refused with `400 M_TOO_LARGE`, nothing from it is
  stored, nothing is evicted, and the caps are operator-configurable.
* A device at its cap must still be able to replace its fallback keys: clients rotate them after one is used.
* The specification does not name the algorithms a fallback key may use.

## Considered Options

* A per-device cap on distinct fallback-key algorithms, `server.client_api.max_fallback_keys_per_device` (default 16).
* Persist fallback keys only for an algorithm allow-list (today `signed_curve25519`).
* Evict the oldest algorithm when a device passes a cap.

## Decision Outcome

Chosen option: a per-device cap on distinct algorithms, because it bounds the rows without the server deciding which
algorithms exist, and it keeps the CSAZ-10 policy of refusing whole requests rather than evicting.

The cap counts `database::fallback_key_algorithm(key_id)` over the device's held keys and the request's keys together, so
an algorithm already held, or named twice in one request, is a replacement and adds nothing. `store_fallback_key`
replaces by the same function, so the cap and the replacement rule cannot disagree about what one algorithm is. The check
sits beside the one-time-key cap, before anything in the request (device keys, one-time keys, fallback keys) is written.

### Positive Consequences

* A device holds at most `max_fallback_keys_per_device` fallback keys, whatever the client sends.
* A device at the cap can always rotate the keys of algorithms it holds.
* A future algorithm needs no server change.

### Negative Consequences

* A client that really used more than 16 fallback-key algorithms on one device would be refused until an operator raised
  the cap (range 1..1024). No client does: Olm uses `signed_curve25519` alone.
* `store_fallback_key` now replaces only keys of exactly the same algorithm. Before, a key ID with no `:` (its whole ID is
  its algorithm) also replaced any held key whose ID began with that text, so `curve25519` replaced `curve25519extra`.
  Neither is a well-formed key ID; the old rule was an accident of `starts_with`.

## Pros and Cons of the Options

### A per-device cap on distinct algorithms

* Good, because storage is bounded and operator-tunable, like the other CSAZ-10 caps.
* Good, because it needs no list of algorithms.
* Bad, because one more configuration key.

### An algorithm allow-list

* Good, because it bounds a device to one or two rows with no configuration.
* Bad, because the specification does not restrict fallback-key algorithms, so a new algorithm would be silently dropped
  or refused until the server was changed.
* Bad, because the server would be judging cryptography it does not use, where the client is the authority.

### Evict the oldest algorithm past a cap

* Good, because an upload is never refused.
* Bad, because a client can push out a key another user is about to claim, and CSAZ-10 chose never to evict end-to-end
  key material.

## Links

* Follows the CSAZ-10 cap policy recorded in `tests/integration/test_otk_cap_flow.cpp` and `docs/user-manual.md`
  (operational budgets).
