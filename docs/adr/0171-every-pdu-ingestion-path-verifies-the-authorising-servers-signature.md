# Every PDU ingestion path verifies a restricted join's authorising-server signature

* Status: accepted
* Date: 2026-10-21

## Context and Problem Statement

The room version auth rules say that an `m.room.member` event whose content carries
`join_authorised_via_users_server` must be rejected unless it is validly signed by the homeserver
of that user (rooms/v8.md and v10.md rule 4.2.1; v12.md rule 5.2.1). Checking a signature needs
that server's key, and `events::authorize_event_against_auth_events` is a pure function with no
key resolver, so it can only see that a signature entry is present.

The 2026-09-29 fix (EVT-1) added the cryptographic check to the resolver overload of
`federation::authorize_federation_pdu`, which only the `/send` and `send_join` paths call.
Security audit run-1 (2026-10-20) found two more paths that put PDUs into the event graph and
called only the sender-signature check: main's re-verification of PDUs relayed by the federation
worker (`worker_pool.cpp`, ADR-0071) and backfill / missing-history ingestion
(`verify_and_store_backfilled_event` in `local_http_router.cpp`). In a restricted room this was
latent only because those paths' auth maps (`build_auth_event_map_from_entries`) never carry the
authorising user's membership, so the restricted branch refuses every non-invited join first.
That is a separate bug, and fixing it without this check would let a compromised worker on the
first path, or any remote server answering a history fetch on the second, get a forged
restricted join stored. In rooms with other join rules, a forged authorising signature was
already accepted, against the rule.

Where should the check live so that a new ingestion path cannot miss it?

## Considered Options

* Move the check into `events::authorize_event_against_auth_events`, passing it a key resolver.
* One shared federation helper, `federation::verify_join_authorising_server_signature`, called
  by every ingestion path right after the sender-signature check.
* Add the check separately at each call site.

## Decision Outcome

Chosen option: "one shared federation helper", because the auth rules stay a pure function (they
also run inside state resolution and on stored events, where no network fetch may happen), while
the key lookup stays with each caller. Each caller passes its own admitted lookup
(`resolve_verification_key`, or the `/send` path's adapter over its resolver), so each keeps its
FED-10 admission and its overload handling. A local admission denial comes back as a retryable
503, never as a verdict on the signature: the relay answers `main_overloaded`, and backfill sets
its budget's `key_resolution_locally_denied`.

The rule for future code: **a new path that puts a remote PDU into the event graph calls
`verify_join_authorising_server_signature` after the sender-signature check, and refuses the
event unless it accepts.** The `/send` path does this through the resolver overload of
`authorize_federation_pdu`; relay, backfill and the `send_join` state this server stores when
it joins a remote room (`filter_verified_send_join_events`) call it directly. The last of these
was added in review: it is the one path where this server is the joiner, and its state and auth
chain enter the event graph like any other received event.

Any one valid signature from the authorising server satisfies the rule, and the signatures
object is not itself signed, so a relaying server can add key IDs ahead of the genuine one. The
helper therefore tries each listed key in order until one verifies, but no more than
`max_authorising_signature_keys` (4): every candidate may cost a key fetch, and an unbounded list
would let one event amplify key fetches. A local overload on any candidate, with none verified,
is a retryable 503. A caller with a wall-clock budget passes its deadline, and no candidate
lookup starts after it (a 504, again no verdict); backfill does, so several uncached candidates
cannot hold recovery past its deadline by more than the one lookup already in progress.

The rule is triggered by the key being present, so a value that is not a user ID (a number, an
object, a string without a server name) is refused: it denotes no homeserver that could have
signed the event. It is never treated as an absent key.

The helper checks only `m.room.member` events, as the rule says. The earlier `/send`-only code
also checked other event types that carried the field; that was stricter than the spec and is
dropped.

### Positive Consequences

* One implementation of the rule, with one set of tests, shared by every ingestion path.
* The structural check in the auth rules remains as a second line: an event with no signature
  entry at all is rejected there too.

### Negative Consequences

* The auth rules alone are not enough for a remote event. Anything that admits a remote event
  without going through one of the three paths would reopen the gap. This ADR and
  `src/federation/AGENTS.md` rule 2 say so.
