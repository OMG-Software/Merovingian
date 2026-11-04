# A top-level event_id is signed, and refused on a reference-hash PDU

* Status: accepted
* Date: 2026-11-04

Technical Story: security audit run 2, finding F-57. Commit aa824cbc (0.4.26) stripped `event_id` from the
signing payload for room version 3 and later, while the reference hash that names the event kept it. A relay
could add `event_id` to a genuine event: the signature still verified, and the hash, so the event's ID, changed.

## Context and Problem Statement

The spec's signing pseudocode (`server-server-api.md`, "Signing events") strips what redaction removes, then
`signatures` and `unsigned`. Redaction keeps `event_id` in every room version. rooms/v3.md says: "the
`event_id` field is no longer included", and "A server receiving an event should compute the relevant event
ID for itself."

The spec's own event signing test vector settles what is signed. Its second event carries `"event_id":
"$0:domain"`, and its published signature verifies only with that key in the signed bytes (`[spec-vector]`).

The 0.4.26 commit said other servers add `event_id` as a hint outside their signatures. That claim is not in
the spec, and the tests it added cited "Spec MUST" text the spec does not contain. The spec is the authority
here, not what any other server is said to do.

The result was that one signed event could have many event IDs, each passing every check, and a server that
had stored one copy could be handed another as a different event with the same signature.

## Considered Options

* **Sign `event_id` like any other kept key, and refuse a v3+ PDU that carries one (chosen).**
* Keep stripping it from the signing payload and also strip it before hashing. Rejected: this tolerates a peer
  that adds the field, but it is not the algorithm the spec gives, so an event whose author signed with
  the field present would fail here though it is valid by the spec's procedure.
* Sign it and accept the field, relying on the signature to fail. Rejected: the author's own server could still
  write one, and rooms/v3.md's format has no such field.

## Decision Outcome

`make_event_signing_payload` is the spec's pseudocode with nothing added. `pdu_format_violation` (ADR-0399)
refuses a reference-hash PDU that has a top-level `event_id`, on every path that takes events from another
server. This server never writes the field: `claim_membership_event_template` removes it from a template.

### Negative Consequences

* A peer that does add `event_id` to its v3+ PDUs has them refused, with a per-PDU error naming the reason.
  If real peers are found doing this, the answer has to be decided against the spec again, not by restoring
  the strip: the strip is what made one signature cover many event IDs.

## Links

* Refined by [ADR-0399](0399-one-check-holds-every-received-event-to-its-room-versions-format.md)
