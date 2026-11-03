# Bound the shape and size of uploaded keys

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2 F-37, key rows were capped by count and never by size

## Context and Problem Statement

ADR-0118 caps one-time keys per device (1000) and key signatures per user (10000) so the stored keys stay bounded in
memory. It counts rows. `POST /keys/upload` accepted any non-null JSON value for an unsigned one-time or fallback
key and any extra members on `device_keys`; cross-signing keys and signature uploads were stored as sent. A row could
be as large as the body (1 MiB), so a device held about a gigabyte of keys.

## Considered Options

* Check the value's shape and size where it is validated, before anything is stored
* Add a byte check to `key_payload_is_valid`
* A per-user byte budget for all end-to-end key material

## Decision Outcome

Chosen option: "Check the shape and size where it is validated", with named constants, no configuration:

* A one-time or fallback key ID is at most 255 bytes. Its value is a string of 1 to 256 bytes, or a key object
  (`{key, signatures, fallback?}`, client-server API, "POST /keys/upload"): `key` a string of 1 to 256 bytes,
  `signatures` an object if present, `fallback` a boolean if present, and the whole object at most 4096 bytes. Any
  other value is refused with `400 M_BAD_JSON` before any key (device keys included) is stored. A curve25519 key is
  43 characters, a signed key object about 200, so Element's uploads, signed or unsigned, are unaffected.
* `device_keys` (as normalised for storage), each cross-signing key of `device_signing/upload`, and each signed key
  of `signatures/upload` are at most 16384 bytes when serialised, or the request is refused with
  `400 M_TOO_LARGE` before it stores anything.

A byte check inside `key_payload_is_valid` was rejected: that function also guards key-backup rows, which are
legitimately large, and its failure is a `500`. A per-user byte budget was not added: with each key bounded the
stored bytes per device are at most 1000 keys of 4 KiB, and the number of devices a user can create is a separate
limit (device creation is rate limited at login).

### Negative Consequences

* A client that signs a key with more than 4 KiB of extra members is refused. No client does.
