# A retired server key verifies events sent before it expired and never authenticates a request

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`GET /_matrix/key/v2/server` lists the keys a server has stopped using under `old_verify_keys`, each with the
`expired_ts` at which it stopped. The spec says they are "only valid for signing events". The key cache read only
`verify_keys`, so an event signed before a rotation and received later (send_join state, `/backfill`,
`/get_missing_events`) found no key and was dropped.

## Considered Options

* Treat an old key as an ordinary cached key with `valid_until_ts = expired_ts`.
* Carry it as a distinct, flagged record (`FederationKeyRecord::retired`, `expired_ts`) that only the event checks accept.

## Decision Outcome

Chosen option: the flagged record. With the first option the same record would also verify an `X-Matrix` request signed
before `expired_ts`, and a leaked retired key is exactly what an attacker holds. `verify_signed_federation_request`
refuses a retired key, and the two places that install a resolved key as a remote's request key skip one.
`check_signing_key_valid_for_event` accepts a retired key only when `origin_server_ts < expired_ts` (strictly), and
fails closed on a missing `expired_ts`; room versions 1 to 4 ignore key validity for every key as before.

Each `old_verify_keys` entry is read on its own: a malformed one (no object, no `key`, an `expired_ts` that is not an
integer above zero, key material that is not 32 bytes, an ID that is also a current key) is skipped and never costs the
response its `verify_keys`. The response signature already covers the member. The expiry is capped at the moment of
the fetch, as a current key's validity is capped at seven days.

### Negative Consequences

* Old keys are not persisted: `server_signing_keys` has no column for `expired_ts` or for "retired", and writing a
  retired key as a row would make it indistinguishable from a live one. A retired key id therefore resolves from a
  fresh fetch each time (subject to the existing key-resolution budgets). Persisting them needs a schema change.
