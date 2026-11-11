# An identifier over 255 bytes never reaches a namespace regex

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, `F-resource-exhaustion.appservice-namespace-regex.unbounded-input-recursion`.

## Context and Problem Statement

`std::regex_match` in the standard libraries this server builds with recurses on its input. `GET /directory/room/{alias}`
and `GET /profile/{userId}` passed a request's path segment to an application service's namespace regex at whatever length
the request carried, without authentication, so a long enough identifier exhausted a thread's stack and took the process
down.

What bounds the input?

## Decision Drivers

* The spec limits a user ID and a room alias to 255 bytes (`docs/matrix-v1.19-spec/appendices.md`, "Identifier Grammar").
* A namespace can also be matched against a room ID and against any identifier a remote server names.
* A registration's pattern comes from the operator, but what it is matched against comes from anyone.

## Considered Options

* Check the length in the two GET handlers only.
* Check the length inside the matcher only.
* Check in the matcher, and answer 400 in the GET handlers as well.
* Replace `std::regex` with a linear-time engine.

## Decision Outcome

Chosen option: "Check in the matcher, and answer 400 in the GET handlers as well".

* `namespace_matches` and `compiled_namespace_matches` are the only callers of `std::regex_match`. Each answers false for
  an identifier over `max_namespace_match_input_bytes` (255) before matching, so every caller is covered, including ones
  added later.
* An identifier that long is not a valid identifier, so it matches nothing.
* The two GET handlers answer `400 M_INVALID_PARAM` before any lookup: a request naming such an identifier is malformed,
  and the client should be told rather than get a `404`.
* A linear-time engine would be a dependency for a problem a length check closes; 255 bytes of recursion fits a thread's
  stack.

### Positive Consequences

* Stack use in a namespace match no longer depends on the request.

### Negative Consequences

* A registration cannot match an identifier longer than the spec allows. None is valid.
