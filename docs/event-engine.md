# Event engine

This capability note describes the Matrix event-engine foundation on top of
canonical JSON.

## Current scope

Implemented now:

- deterministic event ID scaffold over canonical JSON
- event envelope parsing and validation for core Matrix fields
- event signing payload construction that excludes `unsigned` and `signatures`
- signature attachment and presence-verification scaffolding
- room-version policy registry for modern stable room versions
- room-version policy shape for event format, redaction rules, auth rules, state resolution, and event ID format
- redaction scaffold with room-version-dependent key retention
- unit coverage for event IDs, event envelope parsing, signing payloads, signature presence, redaction, and room-version lookup

Not implemented yet:

- Ed25519 cryptographic signing and verification
- server signing-key storage and rotation
- event authorization rules
- auth event selection
- state resolution
- event DAG persistence
- room membership behavior
- full Matrix room-version fixture suite

## Signing boundary

The event signing payload is produced from canonical JSON after removing fields that Matrix signing excludes from the signed payload:

- `unsigned`
- `signatures`

The current implementation does not implement Ed25519. `attach_event_signature`
records a caller-supplied signature under a server name and key ID so later
crypto integration has a stable event-shape boundary.

## Event IDs

`make_content_hash_id` is currently a deterministic scaffold over canonical
JSON. It is not the final Matrix room-version-specific event ID algorithm.
Later crypto/event work must replace the placeholder hash with the correct
Matrix reference-hash behavior for each room version.

## Redaction

The redaction engine currently retains a conservative key allowlist and switches
`unsigned` retention based on room-version redaction policy. Later work must
expand this with full Matrix room-version fixtures.
