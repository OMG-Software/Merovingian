# The client address is the rightmost untrusted X-Forwarded-For entry

* Status: accepted
* Deciders: James Chapman
* Date: 2026-09-27

Technical Story: 0.12.13 audit, found while doing remaining-work item 4 in
`docs/todos/audit-0.12.13-handover.md`; the user chose the fix in writing on
2026-09-27. The Matrix spec does not define X-Forwarded-For handling.

## Context and Problem Statement

Behind a trusted reverse proxy, `effective_client_ip` took the leftmost
`X-Forwarded-For` entry as the client. A proxy that appends to the header
(nginx `$proxy_add_x_forwarded_for`, the common default) leaves whatever the
client sent on the left, so a client could prefix a different valid address
to each request and get a fresh rate-limit bucket every time. The shipped
example config told operators to make the proxy overwrite the header instead,
which a misconfiguration silently undoes.

Which entry identifies the client?

## Considered Options

* **Rightmost entry that is not a trusted proxy (chosen).** Each proxy
  appends the address it received the request from, so the entries written
  by trusted proxies are the only ones that can be believed; walking from the
  right past them reaches the first address a trusted proxy vouched for.
* **Leftmost entry, and require proxies to overwrite.** Rejected: safe only
  while every operator configures their proxy exactly right.

## Decision Outcome

Chosen option: "Rightmost entry that is not a trusted proxy".

* Every `X-Forwarded-For` line is read, in order, as one list (RFC 9110
  §5.3).
* The list is walked from the right; entries listed in
  `server.trusted_proxies` are skipped. The first other entry is the client
  if it is a valid IP literal; if it is malformed, the direct peer is used.
* If every entry is a trusted proxy, the leftmost is used.
* `rate_limit_client_key` groups the result by
  `server.http.ipv6_client_prefix_length`; the client-server rate limiter and
  the federation key-resolution budget both key on it.

### Positive Consequences

* A proxy that appends and a proxy that overwrites give the same key.

### Negative Consequences

* A chain of proxies must list every hop the operator controls in
  `server.trusted_proxies`, or the inner hop's address becomes the key.

## Links

* Tests: `tests/unit/test_client_server.cpp` (`[rate_limit_keys]`)
* `docs/http-transport.md`, "Trusted-proxy client IP resolution"
* [ADR-0072](0072-per-ip-connection-cap-at-accept-time.md) (shared
  `client_address_key`)
