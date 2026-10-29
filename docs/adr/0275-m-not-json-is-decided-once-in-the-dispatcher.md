# M_NOT_JSON is decided once in the dispatcher

* Status: accepted
* Date: 2026-10-29

Technical Story: Complement run 10 (`TestRequestEncodingFails`)

## Context and Problem Statement

A client body that was not JSON (invalid UTF-8 inside it, for instance) answered `M_BAD_JSON`,
from whichever of about 111 handlers parsed it. The spec says `M_NOT_JSON` "Request did not contain
valid JSON", and `M_BAD_JSON` for JSON that is malformed for the endpoint.

## Considered Options

* Fix each handler's parse error.
* Decide it once, in the dispatcher, before any handler runs.

## Decision Outcome

Chosen option: once, in the dispatcher, for every `/_matrix/client/` request with a body, after the
rate limit. Media uploads and the `/_merovingian/admin` routes are exempt (their bodies are not
JSON). A syntax error, invalid UTF-8 included, is 400 `M_NOT_JSON`. Valid JSON the endpoint refuses
(floats, integers out of range, duplicate keys, size caps, the wrong shape) stays the endpoint's
`M_BAD_JSON`. The check uses `parse_json`, because `parse_lossless` also refuses fractions, which
are valid JSON. A handler added later needs nothing of its own for `M_NOT_JSON`.
