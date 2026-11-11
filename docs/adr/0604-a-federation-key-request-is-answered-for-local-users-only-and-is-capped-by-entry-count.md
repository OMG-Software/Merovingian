# A federation key request is answered for local users only and is capped by entry count

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, `resource-exhaustion.federation-user-keys.linear-scan-per-attacker-key-under-runtime-mutex`

## Context and Problem Statement

`POST /_matrix/federation/v1/user/keys/query` and `/user/keys/claim` accept any signed federated server. The builders
scanned `one_time_keys`, `fallback_keys`, `device_keys`, `devices` and `cross_signing_keys` once per user and device the
body named (about 20000 entries fit in 1 MiB), under the runtime lock; they also looked up users that are not ours at
all. The same shape existed in the code that checks a remote server's answer to our queries
(`accept_remote_key_query_response`, `accept_remote_cross_signing_keys`, `accept_remote_key_claim_response`), which
searched a vector per key of an answer whose size the remote server chooses. What should a request cost, and what
should happen to one that is too big?

## Decision Drivers

* The Server-Server API defines no limit and no error for either endpoint.
* A real server batches by room: it queries the users it shares rooms with.
* The claim hands out one-time keys, so refusing a request must not consume any.

## Considered Options

1. Index the tables only.
2. Index, answer for this server's own users only, and refuse a request naming more than a fixed number of entries.
3. Truncate an over-large request and answer the first entries.

## Decision Outcome

Chosen option 2.

* The builders take `local_server_name`; a user of another server is skipped before any table is read (a server has
  nothing to publish for them). The tables are read through the indexes of ADR-0603, so an entry costs the rows it
  names.
* A request naming more than `max_key_request_entries` (25000, counting every user and every device or algorithm entry
  under it) is refused whole with 413 `M_TOO_LARGE`, by the HTTP handler before the provider runs, and by the builder
  itself (an empty body), because the worker relay reaches the builder directly. The limit is fixed in code: the 1 MiB
  body limit already stops a request near it, so it is a backstop for a body that packs entries, not a tuning knob.
* The answer checks use `std::set` lookups for requested users, devices and answered keys.

### Why not truncate

Answering the first N entries would return a partial answer that looks complete, and a claim would consume keys for
the entries it did answer; a requester cannot tell what was dropped. A refusal is unambiguous and consumes nothing.

### Why 413 and not 400

400 is this handler's "malformed body" (an empty builder result). A body that parses and is too big is the case
`M_TOO_LARGE` names; the existing status-to-errcode map already pairs 413 with it.

## Residual

A claim that hits still deletes each claimed key with one synchronous statement. That is bounded by the cap and by the
keys that exist, and it is a design property of one-time keys, not a scan.
