# Cap pusher registration and break the circuit to failing gateways

* Status: accepted
* Date: 2026-10-15

Technical Story: 29 September 2026 security audit, finding OUT-3 (one user's stalled push gateways
consume the global push-delivery cap). Supersedes the "registration stays unbounded" part of
[ADR-0029](0029-bound-pusher-delivery-rather-than-registration.md).

## Context and Problem Statement

A pusher's gateway URL is chosen by the client. Each delivery calls a recipient's pushers in sequence,
each with a 30 s timeout. ADR-0029 bounded the pushers contacted per event and left registration
unbounded; the per-recipient in-flight cap (at most eight of a recipient's batches) keeps one user from
holding every delivery slot. What remained: a user could register any number of pushers, and a gateway
host that stalls or fails was contacted again for every event, holding a slot for the full timeout each
time.

## Considered Options

* **Cap distinct pushers per user, and skip a gateway host for a cooldown after consecutive failures
  (chosen).**
* Keep registration unbounded (ADR-0029). Rejected: the delivery cap already skips pushers silently, so
  an unbounded list only costs memory and hides which pushers are skipped; refusing at registration
  tells the client.
* Retry with backoff per delivery instead of a breaker. Rejected: the spec makes retry a SHOULD, and
  retries of a stalled host make the slot problem worse, not better.

## Decision Outcome

Chosen option: both caps, as configuration with these defaults.

* `server.push.max_pushers_per_user` (20): `POST /pushers/set` refuses a new `(app_id, pushkey)` beyond
  it with 400 `M_INVALID_PARAM` (the endpoint's documented 400, "pusher values were invalid";
  `M_LIMIT_EXCEEDED` means rate limiting and `M_RESOURCE_LIMIT_EXCEEDED` needs an `admin_contact`).
  Updating or deleting an existing pusher is always allowed.
* `push::GatewayCircuitBreaker`, keyed by the gateway URL's host: after
  `server.push.gateway_failure_threshold` (3) consecutive transport failures, timeouts or 5xx responses
  the host is skipped for `server.push.gateway_cooldown_seconds` (300); then one delivery per cooldown is
  let through as a probe until one succeeds. A 4xx counts as reaching the gateway. At most 4096 hosts are
  tracked, the least recently failing forgotten first, because the hosts are client-supplied.

### Negative Consequences

* A user with more than 20 devices that each register a pusher cannot add more without removing one.
* Deliveries to a host whose circuit is open are dropped, not queued; a gateway that recovers within the
  cooldown misses those notifications.
