# Check outbound socket peers against each request's approved pins

* Status: accepted
* Date: 2026-10-04

## Context and Problem Statement

OUT-1 and OUT-2 found divergent authority parsers in discovery, redirect
handling and transport. DNS override strings alone did not establish that
libcurl connected to the authority the policy approved.

## Considered Options

* Use libcurl's URL API and check the actual peer before opening a socket.
* Strengthen handwritten parsers and rely on DNS overrides.
* Check only the connected peer after establishing a connection.

## Decision Outcome

Transport and redirects use one strict libcurl URL parser. Reject userinfo,
fragments, backslashes, controls, authority escapes and IPv6 zones. Preserve
path/query semantics with normalization disabled. Attach the same parsed URL
handle to the transfer. Matrix server names follow v1.19 grammar before
discovery, including single-label DNS names and real IPv6 syntax.

A single DNS override entry retains all approved numeric addresses. An
open-socket callback also compares the destination's binary address and port
with that request's pins before creating a socket. Invalid pins fail closed.
Checking after connection would send traffic before discovering a violation.

Disable environment proxies, force fresh connections and forbid socket reuse.
Proxy peers are not origin peers; pooled sockets bypass the open-socket callback
and current pins. Check all security-option results. RAII resets borrowed
request pointers before their owning values are destroyed.

### Positive Consequences

* Parser/resolver disagreement cannot connect to an unapproved numeric peer.
* Redirects transfer the canonical URL that discovery checked.

### Negative Consequences

* Direct outbound access is required; environment proxies are ignored.
* Fresh sockets add connection/handshake overhead; TLS session caching remains.
* Fragment-bearing URLs are refused as a project security policy.

## Links

* [libcurl URL API](https://curl.se/libcurl/c/libcurl-url.html)
* [Open-socket callback](https://curl.se/libcurl/c/CURLOPT_OPENSOCKETFUNCTION.html)
* [Matrix server names](../matrix-v1.19-spec/appendices.md#server-name)
