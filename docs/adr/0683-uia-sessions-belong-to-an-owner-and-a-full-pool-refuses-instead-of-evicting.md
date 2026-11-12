# UIA sessions belong to an owner, and a full pool refuses instead of evicting

* Status: accepted
* Date: 2026-11-12

Technical Story: security audit run-3, finding C45.

## Context and Problem Statement

All User-Interactive Authentication sessions share one in-memory pool (`max_uia_sessions`, 2048). When it was full the
oldest session went, whoever held it, and every 401 on `/delete_devices`, `/devices/{id}`, `/login/get_token` and
`/register` minted one. One account (or a few addresses) could therefore keep evicting a victim's session, so a client
that echoes its `session` never finished.

## Considered Options

* Record an owner in each session (the authenticated user ID, or the client address key for unauthenticated
  registration), cap each owner (16) by replacing the owner's own oldest, and refuse a new challenge when the pool is full.
* Evict from the owner that holds the most sessions when the pool is full.
* Keep global oldest-first eviction and raise the cap.

## Decision Outcome

Chosen option: owner, per-owner cap, refuse when full. Refusal is `429 M_LIMIT_EXCEEDED` with a `retry_after_ms` of
5 seconds; sessions live ten minutes, so the pool drains by itself and no live session is touched. A session is also
valid only for its owner, so a stolen or leaked session id is useless to another account.

Evicting from the largest holder was rejected: with many owners holding one session each, "the largest" is arbitrary and
the victim can still be chosen, so the guarantee depends on how many accounts the attacker has. A larger cap only moves
the flood threshold.

A challenge is minted only when it is sent: a request that carries a valid session no longer mints a spare one first, so a
full pool does not stop a client that already holds a session from finishing.

Residual: an attacker with enough accounts or addresses (16 sessions each, bounded by the rate limits) can fill the pool and
make others' first challenge a 429 until sessions expire. Their sessions are no longer able to void a challenge already
issued.

## Links

* Refines [ADR-0057](0057-uiaa-sessions-are-in-memory-and-single-stage.md)
