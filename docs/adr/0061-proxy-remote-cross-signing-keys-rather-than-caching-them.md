# Proxy remote cross-signing keys rather than caching them

* Status: accepted
* Date: 2026-09-11

Technical Story: 0.12.10, "devices of users on other servers always show as
unverified".

## Context and Problem Statement

Clients need a remote user's master and self-signing keys to decide whether that
user's devices, and the user, are verified. Merovingian learns them two ways:
the `/keys/query` federation proxy asks the user's server
(`/user/keys/query`), and the user's server pushes `m.signing_key_update` EDUs
when they change. Before 0.12.10 the proxy discarded the cross-signing keys and
the EDU was dropped as an unknown type.

When fixing both, the EDU could either be stored, as a cache the proxy reads,
or treated purely as a signal.

## Decision Drivers

* The device-key half of the same flow is already proxied live and never cached,
  and an inbound `m.device_list_update` only marks the user changed.
* A cached copy can be served stale or duplicated next to a freshly proxied one.
  JSON objects in the `/keys/query` response must not repeat a user ID.
* An EDU arrives unrequested. Storing its keys means trusting the push path as
  much as the pull path, and `store.cross_signing_keys` currently holds local
  users only. Other code assumes that.

## Considered Options

* Store the keys from `m.signing_key_update` in `cross_signing_keys` and serve
  remote users from the store.
* Keep proxying; treat `m.signing_key_update` exactly like
  `m.device_list_update` — put the user in local users' `device_lists.changed`
  so clients re-query.

## Decision Outcome

Chosen option: **keep proxying, and treat the EDU as a change signal only.**
The shared inbound handler in `local_http_router.cpp` handles both EDU types.
`handle_key_query` collects cross-signing keys from the store for local users
only, and takes remote users' keys from their server's response after
`federation::accept_remote_key_query_response()` has filtered it.

**The rule this sets for future code: `cross_signing_keys` holds local users'
keys only. If remote caching is ever added, it needs its own storage and must
replace — not add to — the proxied entry for that user in the response.**

### Positive Consequences

* One source of truth for remote keys: the remote server, at query time.
* No cache invalidation, no duplicate-key hazard in the response.

### Negative Consequences

* Every `/keys/query` for a remote user costs a federation round trip, as it
  already did for device keys. An unreachable server shows up in `failures`
  instead of being served from cache.

## Links

* Related: [ADR-0060](0060-show-an-uploaded-key-signature-only-to-its-owner-audience.md)
