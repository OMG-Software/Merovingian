# The authorising-signature helper decides by room version itself

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-38. Refines [ADR-0171](0171-every-pdu-ingestion-path-verifies-the-authorising-servers-signature.md).

## Context and Problem Statement

ADR-0171 made `federation::verify_join_authorising_server_signature` the one check of a restricted
join's authorising-server signature, called by every path that puts a remote PDU into the event
graph (`/send`, `send_join`, worker relay, backfill, the `send_join` state this server stores).
The helper applied the rule to every `m.room.member` event whose content named
`join_authorised_via_users_server`, in every room version.

The rule only exists from room version 8 (rooms/v8.md, authorisation rule 4.2, "New in this
version"). Room versions 3 to 7 never mention the property, so there it is ordinary content. A
member of a version 3 to 7 room could send a member event naming a third server in that field;
other servers accept it and build on it, this server refused it on every path, and every descendant
then lacked a `prev_event`.

Where should the room-version condition live?

## Considered Options

* The helper returns "accepted" when the room version's policy has no `restricted_join_rule`.
* Each of the five callers tests the policy before calling the helper.
* Strip `join_authorised_via_users_server` from events of versions 3 to 7 on receipt.

## Decision Outcome

Chosen option: "the helper decides itself". The helper already takes the policy, so the condition
sits beside the rule it scopes and `RoomVersionPolicy::restricted_join_rule` is the same flag the
auth rules (`events::authorize_event_against_auth_events`, rule 4.3.5) already use. The ADR-0171 rule
for future code stands unchanged: a new ingestion path calls the helper and refuses unless it
accepts. Because the helper owns the version test, a new path cannot forget it, and the five
existing paths cannot drift apart.

Rejected: gating at each call site. That is the shape ADR-0171 was written to avoid; one caller
omitting the test refuses valid events (as this finding did) or, if it gated the wrong way round,
accepts a forged signature in a version that requires one. Rejected: stripping the property.
Event hashes and signatures cover it, so changing the event breaks both.

The key prefetch (`filter_verified_send_join_events`'s parallel pass, the inbound prefetch) skips the
authorising server for versions without the rule, since it would fetch keys nothing then checks.

### Negative Consequences

* `join_authorising_signature_key` alone no longer says that the rule applies; a caller that needs
  to know (a prefetch) asks the policy too. The two prefetch sites do.
