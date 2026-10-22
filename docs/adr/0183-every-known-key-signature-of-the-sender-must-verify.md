# A server's signature is checked against every listed key ID, within a bound

* Status: accepted
* Date: 2026-10-21

Technical Story: conformance audit 2026-10-17, finding R05

## Context and Problem Statement

Every received PDU must be validly signed by its sender's server. Before 0.12.34 the request
layer, the worker relay, backfill and the `send_join` state this server stores when it joins all
took the first key ID listed under the sender's server in `signatures`, resolved that one key and
verified with it. ADR-0171 had already made the restricted-join authorising-server check try
several key IDs; the sender check had not.

The spec does not limit the check to one key. server-server-api.md, "Validating hashes and
signatures on received events": "If a signature is from an unknown or expired key, it is
skipped." appendices.md, "Checking for a Signature", step 2: "Removes any signing key
identifiers from the entry with algorithms it doesn't understand", and step 3 looks up keys "for
the remaining signing key identifiers". The `signatures` object is not covered by any signature,
so a relaying server can list extra key IDs, and a server that has rotated its key may sign with
a key ID that is not the first. A first-key-only check rejected genuine events in both cases,
and a relay could make this server reject any event by listing a junk key ID first.

Each candidate key may cost a fetch, and the list is chosen by whoever sent the event.

## Considered Options

* Keep checking the first listed key ID only.
* Check every listed key ID; accept when any one verifies; bound the candidates per server.
* Require every listed signature from a known, unexpired key to verify ("If all signatures from
  known unexpired keys from the originating server(s) are found to be valid").

## Decision Outcome

Chosen option: "any one verifies, within a bound". One helper,
`federation::authorize_federation_pdu_sender`, runs the sender check on every path that admits a
remote PDU: `/send`, `send_join` / `send_leave` / `send_knock`, `/invite`, the worker relay
(`verify_relayed_event_signature`) and backfill. `filter_verified_send_join_events` uses the same
loop through `verify_server_signature_with_any_listed_key`. ADR-0171's authorising-server check
keeps its own loop with the same rule, bound and algorithm filter.

The candidate list is `signature_key_ids_for_server`: the key IDs listed for the server, in the
event's own order, without repeats, keeping only the `ed25519:` algorithm, and at most
`max_signature_keys_per_server` (4). Unsupported algorithms are removed before the bound, so they
cannot use up the candidates. The request's X-Matrix key, when it is the sender's, is tried first
and costs no lookup. Every other candidate goes through the caller's admitted lookup (FED-10:
per-source rate, the in-flight cap and the (server, key ID) failure cache), so the bound per
event and those budgets together bound the fetches an attacker-written list can cause. The
`/send` pre-pass still fetches only the first candidate ahead of time; further candidates are
looked up only when it does not verify. `filter_verified_send_join_events` pre-fetches every
candidate in its parallel pass, because it must not do serial fetches afterwards.

A local admission denial on any candidate, with nothing verified, is a retryable 503, never a
verdict; running out of a caller's deadline is a 504.

The reading "every known key must verify" was rejected. It is fail-closed but it hands a relay a
lever: add an invalid signature under another known key of the sender and the genuine event is
refused. The sender's server cannot sign the `signatures` object, so its genuine signature is the
evidence and a relay's additions are not. "Checking for a Signature" asks whether the entity has
signed the object, which one valid signature answers. The orchestrating brief for wave 2 asked for
the same reading ("fail closed only if none verifies"), matching ADR-0171.

### Positive Consequences

* An event signed with any of its server's current keys is accepted whatever the relay listed
  ahead of it.
* The sender and authorising-server checks follow one rule and one bound.

### Negative Consequences

* An event can now cost up to four admitted lookups for its sender's server and four for a
  restricted join's authorising server, instead of one and four.
* A direct request whose event is signed with a key other than its X-Matrix key now triggers a
  lookup of that key, where it used to be refused outright.

## Links

* Refines [ADR-0171](0171-every-pdu-ingestion-path-verifies-the-authorising-servers-signature.md)
