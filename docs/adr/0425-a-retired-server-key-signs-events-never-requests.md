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

### Retired keys are stored durably (follow-up)

A fresh fetch per event does not work: backfilling thousands of events signed by one old key would spend the capped
key-resolution budget once per event and refuse them, and a remote that has gone offline could never have its old
events verified. `server_signing_keys` therefore gains `expired_ts TEXT NOT NULL DEFAULT ''` (edited in the v1 step
in place, ADR-0224) and `cache_remote_server_keys` writes each `old_verify_keys` entry as a retired row, `expired_ts`
capped at the fetch time and `valid_until_ts` equal to it.

Retirement is one way and the earliest expiry wins, enforced in `store_server_signing_key` and in the SQL upsert:

* a later listing with a smaller `expired_ts` lowers the stored value; a larger one never raises it;
* a later listing under `verify_keys` does not turn the row back into a current key, and does not replace its public
  key;
* a key cached as current that a response lists under `old_verify_keys` is retired at once, rather than running out
  its seven-day cache window;
* a row that holds a secret (this server's own key) never takes an expiry.

`remote_key_needs_refresh` is true for every retired row (its `valid_until_ts` is in the past), so the resolver, the
worker mirror refresh and the PDU key lookup judge a cached key with `cached_remote_key_usable`: a retired row is a
cache hit with no fetch. `find_any_cached_remote_key` skips retired rows, and the X-Matrix paths refuse them.

Rejected alternatives:

* An in-memory cache of retired keys. It would not survive a restart, a federation worker would not see main's, and a
  remote that went offline could not be re-fetched.
* Letting a re-listing under `verify_keys` revive a retired key. A remote (or anyone able to alter a response) could
  then make a key it already retired authenticate requests again.

### Negative Consequences

* A schema column, so databases created before it must be recreated (no upgrade shim before 1.0.0, ADR-0224).
