# The mutual rooms token carries its offset

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, low findings, `F-resource-exhaustion.mutual-rooms.token-decode-brute-forces-offsets-under-mutex`.

## Context and Problem Statement

The `next_batch` of `GET /mutual_rooms` was a keyed hash of caller, target and offset with the offset left out. Verifying a
`from` token meant hashing every offset up to the room count plus 1000, under `runtime.mutex`, and a junk token paid for
the whole loop.

## Considered Options

* `<offset>.<keyed hash of caller, target and offset>`, verified with one hash and a constant-time comparison.
* Keep the search and cap it.
* Encrypt the offset into an opaque blob.

## Decision Outcome

Chosen option: the first (`MutualRoomsToken.cpp`). The offset is not a secret, since the client learns it by paging; the
keyed hash is what stops a client forging a token for another pair or offset. Verification costs one hash whatever the
token is, and the comparison is `crypto::constant_time_equal_variable_length`. A capped search still scales with its cap,
and encryption adds a second primitive for no property the check needs. Tokens issued before this change fail with
`M_INVALID_PARAM`, as any altered token does.

The other opaque tokens in the client-server runtime do not search: sync and `/messages` tokens are plain stream positions
parsed in one step, and the space hierarchy token is unkeyed base64 JSON, read in one parse, so there is nothing to search for.
