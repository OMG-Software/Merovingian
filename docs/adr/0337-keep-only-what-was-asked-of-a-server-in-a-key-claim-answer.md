# Keep only what was asked of a server in a key claim answer

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2 F-36, `POST /keys/claim` copied every user a remote server named into the response

## Context and Problem Statement

For remote users `handle_key_claim` sent one federation claim per server and pushed every user entry of the answer's
`one_time_keys` into the client response. A hostile server asked about its own user could name any other user, among
them a local user whose one-time key had just been claimed. `canonicaljson::Object` is a member vector, so the user
appeared twice, the serialiser refuses a duplicate member and `json_serialize` returned its empty output, which the
handler sent as `200` with no body after the local keys were spent. `src/federation/AGENTS.md` rule 6 already says a
remote answer about users is never relayed unfiltered; `/keys/query` did that and `/keys/claim` did not.

## Considered Options

* `federation::accept_remote_key_claim_response(origin, body, requested)`, as for `/keys/query`
* Check only for duplicate users when merging

## Decision Outcome

Chosen option: "`accept_remote_key_claim_response`". It keeps a user only if it was requested of that server (a
user's first entry wins), a device only if it was requested for that user, and a device's value only if it is a
non-empty object whose members are a string or a key object (`string|KeyObject`, client-server API, "POST
/keys/claim"). Anything else is dropped and logged. A body that is not a JSON object with a `one_time_keys` object is
`std::nullopt`, and the handler records it as `failures.<server>` rather than as an empty answer. The handler also
skips a user the response already holds, so a local answer is never overwritten.

Serialisation on this response path now checks the serialiser's error: `handle_key_claim` answers `500 M_UNKNOWN` if
it cannot serialise, never a `200` with an empty body. Other `json_serialize` callers are not changed here; the
function keeps ignoring the error, and a response path that can hold remote-chosen members should not use it without
a check.

### Negative Consequences

* A server that returns a key for a device not asked for loses it, even if the device exists: only what was asked is
  relayed.
