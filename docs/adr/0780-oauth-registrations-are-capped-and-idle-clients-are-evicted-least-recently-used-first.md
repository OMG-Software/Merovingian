# OAuth registrations are capped, and idle clients are evicted least recently used first

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 4 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

Client registration is unauthenticated. The `auth_sensitive` rate limit bounds one address, but many addresses can
still register distinct metadata, each a row of up to 16 KiB held in memory and in the database. The spec says "The
server MUST NOT delete client registrations that have an active session". How is the number of clients bounded?

## Decision Drivers

* Memory and database rows must stay bounded whatever unauthenticated callers send.
* A client with a session, or one in the middle of an authorisation, must never be deleted.
* Work under `runtime.mutex` per registration must be bounded.

## Considered Options

* A cap (`ClientApiLimits::max_oauth_clients`, 10000) at which a registration evicts least-recently-used clients with
  no session and no pending authorisation, at most `max_oauth_client_evictions_per_registration` (8), and otherwise
  answers `503 temporarily_unavailable` and stores nothing.
* A cap that refuses every new registration once reached.
* No cap, relying on the 30-day retention sweep.

## Decision Outcome

Chosen option: cap with bounded eviction. `make_room_for_a_client` (`OAuthClientRegistration.cpp`) counts the rows,
and at the cap asks `oauth_clients_without_sessions` for the oldest sessionless clients, skipping those
`oauth_client_has_pending_authorisation` names, and deletes them in one transaction. A client with a session is not a
candidate and `delete_oauth_clients` refuses one. A repeat registration of a held client is answered without eviction.
The cap is a field so tests can lower it; it is not configurable.

### Positive Consequences

* At most 10000 clients are held, whatever is sent.
* An attacker filling the table evicts only other idle registrations, which register again for free (ADR-0779).

### Negative Consequences

* A flood can evict a legitimate client between registration and authorisation start. The client registers again.
* With every held client protected, new clients get 503 until sessions end or the sweep runs. Accepted: the
  alternative breaks the spec's MUST NOT.

## Pros and Cons of the Options

### Refuse at the cap

* Good, because nothing is ever evicted.
* Bad, because one flood shuts registration for 30 days, until the sweep.

### No cap

* Good, because nothing is refused.
* Bad, because memory grows without bound for 30 days at the rate limit times the number of addresses.
