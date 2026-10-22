# Every known, unexpired key's signature of the sender's server must verify

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit 2026-10-17, finding R05

## Context and Problem Statement

Every received PDU must pass the signature check for its sender's server. Before 0.12.36 the
request layer, the worker relay, backfill and the `send_join` state this server stores when it
joins all took the first key ID listed under the sender's server in `signatures`, resolved that
one key and verified with it. A server that signs with more than one key, or a relay that lists
another key ID first, made a genuine event fail.

server-server-api.md, "Validating hashes and signatures on received events":

* "If a signature is from an unknown or expired key, it is skipped."
* "any keys that are known to have expired prior to the event's `origin_server_ts` are ignored."
* "If all signatures from known unexpired keys from the originating server(s) are found to be
  valid, the expected content hash is calculated".

appendices.md, "Checking for a Signature": identifiers "with algorithms it doesn't understand"
are removed (step 2), and with no verification key "the check fails" (step 3). "Checks performed
on receipt of a PDU", step 2: an event that fails the signature checks "is dropped".

The `signatures` object is covered by no signature, so whoever relays the event chooses the list,
and each candidate may cost a key fetch.

## Considered Options

* Keep checking the first listed key ID only.
* Check every listed key ID and accept when any one verifies (the wave-2 draft, and the reading
  an earlier orchestration brief asked for).
* Check every listed key ID: skip unknown and expired keys, require every other signature to
  verify and at least one to exist.

## Decision Outcome

Chosen option: the third, because it is what the spec says. "If all signatures from known
unexpired keys ... are found to be valid" is the condition for going on to the hash check; an
event that does not meet it has failed the signature checks and is dropped. "Any one verifies"
accepts an event the spec drops: one carrying an invalid signature by a key the sender's server
publishes.

The draft rejected this reading because a relay could add an invalid signature under another
known key and get the genuine event dropped. That gives a relay nothing it does not already have:
it can drop the event, or corrupt the genuine signature, with the same effect. A dropped event is
not recorded as rejected, so the genuine copy arriving by another path is still accepted.

One helper, `federation::verify_server_signatures_on_event`, runs the check, and
`authorize_federation_pdu_sender` applies it to a PDU's sender. Every path that admits a remote
PDU uses one of them: `/send`, `send_join` / `send_leave` / `send_knock`, `/invite`, the worker
relay (`verify_relayed_event_signature`), backfill and `filter_verified_send_join_events`.

* The candidates are `signature_key_ids_for_server`: the `ed25519:` key IDs listed for the
  server, in the event's order, without repeats. Unsupported algorithms are removed first, so they
  cannot use up the bound.
* More than `max_signature_keys_per_server` (4) candidates is refused (403) before any lookup.
  Checking only the first four would accept an event whose fifth signature was never looked at,
  and no server signs with more than two keys at once.
* A key that does not resolve, or whose `valid_until_ts` is before the event's
  `origin_server_ts` (from room v5, ADR-0075), is skipped. A known, unexpired key whose signature
  does not verify refuses the event at once (403). No verified signature at the end is a 403.
* The request's X-Matrix key, when it is one of the sender's listed keys, is used without a
  lookup. Every other candidate goes through the caller's admitted lookup (FED-10). The `/send`
  pre-pass still fetches only the first candidate ahead of time.
* A local admission denial on any candidate makes the outcome a retryable 503, even when another
  candidate verified, because the denied key may be known and its signature invalid. Running out
  of a caller's deadline is a 504. Neither is a verdict.

The restricted-join authorising-server check (ADR-0171) is a different rule and keeps its "any
one valid signature" loop: the auth rule asks whether the event "is validly signed by the
homeserver of the user ID denoted by the key", not whether it passes the receipt-time signature
checks. It shares the bound and the algorithm filter.

### Positive Consequences

* The sender check is the spec's, on every ingestion path, with one implementation.
* An event signed with any of its server's current keys is accepted whatever unknown key IDs a
  relay listed ahead of it.

### Negative Consequences

* An event costs one admitted lookup per listed candidate for its sender's server (up to four),
  where it used to cost one, because the check cannot stop at the first key that verifies.
* An event listing more than four `ed25519` key IDs for its sender's server is dropped, even if
  every signature is valid.

## Links

* Related to [ADR-0171](0171-every-pdu-ingestion-path-verifies-the-authorising-servers-signature.md)
* Related to [ADR-0075](0075-event-signing-key-validity-is-judged-at-origin-server-ts.md)
