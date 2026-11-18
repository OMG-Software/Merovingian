# Pending authorisations and authorization codes are in memory, hashed, bounded and never evicted

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 5a of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md) (P5)

## Context and Problem Statement

An authorization request (RFC 6749 section 4.1.1) lives across several page round trips before the user is sent back
with a code, and the code (section 4.1.2) lives until the client redeems it. Both are bearer secrets: whoever holds a
pending authorisation's identifier and the browser's token, or a code and the PKCE verifier, completes the grant. Where
are they kept, how are they found, and what happens when there are too many?

## Decision Drivers

* A leaked store (a core dump, a database backup) must not hand out live grants.
* Lookup must not leak by timing which identifiers exist, and must not cost a scan under `runtime.mutex`.
* An unauthenticated client starts a pending authorisation; it must not be able to push a real user's out.
* The retention sweep must know that a client is in use without a scan (ADR-0777, ADR-0780).

## Considered Options

* In memory on `HomeserverRuntime`, keyed by the BLAKE2b hash of a 32-byte random secret, bounded, refusing when full
* Persisted in the database next to the OAuth sessions
* In memory, evicting the oldest entry when full

## Decision Outcome

Chosen option: in memory, hashed, bounded, refusing when full.

* `PendingAuthorisationStore` and `AuthorizationCodeStore` (`src/homeserver/`) live on `HomeserverRuntime`, guarded by
  `runtime.mutex`. Each secret is 32 random bytes (64 hex digits, `make_oauth_secret`); only `oauth_secret_hash` of it
  is kept. Lookup goes through `HashedSecretTable`: an index of digests of the hash, every candidate confirmed with
  `crypto::constant_time_equal`, never a fall-back scan (the ADR-0488 shape).
* A pending authorisation lives 10 minutes and is bound to a browser token, compared in constant time; a wrong token
  answers exactly as an unknown identifier. A code lives 60 seconds; a redeemed code is kept, marked, until its own
  expiry, so a replay is told apart (RFC 6749 section 4.1.2: revoke what the code issued) and names the user and
  device it went to.
* Every operation takes the current time; an entry is expired when `expires_at <= now` and is removed on the next
  operation. Caps: 8192 pending authorisations, 16 per client address, 8192 codes. At a cap, expired entries are
  purged first; if the store is still full the request is refused. A live entry is never evicted.
* `oauth_client_has_pending_authorisation(runtime, client_id, now_ms)` is the O(1) answer the retention sweep and the
  registration cap's eviction ask: a per-client multiset of expiries, whose latest is compared with `now`. The test
  seam `test_oauth_pending_authorisation` is gone; tests hold real entries.
* `OAuthTables::idle_clients` examines at most `max_idle_client_rows_examined` (8192 + 8192 + 512) rows: the clients
  the stores can name plus one retention batch. Nothing idle within the bound means nothing can go this round.

### Positive Consequences

* Nothing a backup or a dump holds can be redeemed; a restart ends every pending grant, which a user retries.
* An unauthenticated caller fills at most its own 16 places and then the shared cap; it never removes another user's.

### Negative Consequences

* A restart loses every pending authorisation and unredeemed code.
* At the total cap new authorisations are refused for up to 10 minutes; the per-address cap bounds one address's part.

## Pros and Cons of the Options

### Persisted in the database

* Good, because a restart keeps grants.
* Bad, because every page round trip writes a row, and the rows outlive their 60 seconds in backups.

### Evicting the oldest when full

* Good, because a new request always gets a place.
* Bad, because an attacker who fills the store pushes out every real user's authorisation in progress.

## Links

* Refines [ADR-0777](0777-an-oauth-client-s-last-use-is-written-at-most-once-a-day.md) and
  [ADR-0780](0780-oauth-registrations-are-capped-and-idle-clients-are-evicted-least-recently-used-first.md)
* Model: [ADR-0548](0548-login-tokens-are-opt-in-single-use-and-held-in-memory.md),
  [ADR-0488](0488-sessions-are-found-through-a-digest-index-and-unusable-credentials-are-deleted.md)
