# Identity validation sessions are capped per rate-limit client key

* Status: accepted
* Date: 2026-11-12

Technical Story: security audit run-3, finding C10.

## Context and Problem Statement

The cap on open identity validation sessions (`max_registration_validation_sessions_per_remote`, 16) counted sessions by
`req.remote_addr`, the TCP peer. Behind a reverse proxy, which the shipped example configuration assumes
(`server.trusted_proxies=127.0.0.1`), every client has the proxy's address, so the per-client cap was one cap for the
whole server: one client could open 16 sessions and make every other user's requestToken fail with 429.

## Decision Outcome

Chosen option: key the cap on `rate_limit_client_key(req, server_config)`, the identity the rate limiter uses: the client
address after trusted proxies, with IPv6 clients grouped by prefix. All five call sites of
`record_identity_validation_session` pass it.

A rule for new code: a per-client limit never uses `LocalHttpRequest::remote_addr` directly. Rejected: adding a second
resolution of the client address next to the rate limiter's, which would drift from it.

## Links

* Follows [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md)
