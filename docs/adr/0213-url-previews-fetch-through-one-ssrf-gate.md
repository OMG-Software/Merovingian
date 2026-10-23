# URL previews are off by default and fetch only through one SSRF gate

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit endpoint gaps (2026-10-17): `GET /_matrix/client/v1/media/preview_url`

## Context and Problem Statement

`GET /_matrix/client/v1/media/preview_url?url=...` makes this server fetch a URL any
authenticated user names, parse it, and fetch and store the image it points at. That is the
largest server-side request forgery surface the server has: a client could aim it at loopback
services, the cloud metadata address, RFC 1918 hosts or IPv6 ULA and link-local hosts, through
a literal address, a DNS name that resolves to one, a redirect, or a DNS answer that changes
between check and connect. The response is also hostile content. How does the server offer the
endpoint without becoming a proxy into its own network?

## Decision Drivers

* Every hop of every fetch must be checked, not only the URL the client typed.
* The check and the connection must use the same addresses (no DNS rebinding).
* A client must not be able to tell, from the answer, why a URL failed.
* Fetching must never hold a main-pool thread or `runtime.mutex`.
* Parsing must be bounded and must run nothing.

## Considered Options

* Let libcurl follow redirects and fetch with its own resolver
* A dedicated gate: resolve, check, pin and fetch each hop ourselves, with redirects followed
  by the gate
* Do not implement previews

## Decision Outcome

Chosen option: "a dedicated gate", behind `security.media.url_preview_enabled` (default
`false`; while off the endpoint answers `404 M_UNRECOGNIZED`, as if unimplemented).
`homeserver::preview_url` (`src/homeserver/url_preview_service.cpp`) fetches only through
`gated_fetch`, which for every hop:

1. parses the URL with `http::parse_outbound_url` (http or https; userinfo, fragments, encoded
   authority bytes and malformed literals refused) and refuses any other scheme;
2. resolves the host with `federation::resolve_federation_destination`, which refuses a
   literal or resolved address in the private, loopback, link-local, CGNAT, NAT64, multicast or
   reserved ranges, IPv4 and IPv6 (including IPv4-mapped forms), or in
   `security.federation.deny_ip_ranges`; one bad address in the answer refuses the host;
3. pins the connection to exactly the checked addresses (`CURLOPT_RESOLVE`), with the
   client's per-socket peer check, so a second DNS answer cannot redirect it;
4. lets the HTTP client refuse redirects, and follows a `Location` itself only by going round
   the loop again, at most `url_preview_max_redirects` (default 3, at most 5) times.

All hops and the image share one deadline (`url_preview_timeout_seconds`, default 10, at most
30) and byte caps (`url_preview_max_page_size`, default 1 MiB; `url_preview_max_image_size`,
default 5 MiB, never above `max_upload_size`). Only `text/html` and `application/xhtml+xml` are
parsed, by `media::extract_open_graph`: one forward pass, no DOM, no scripts, comments and
`<script>`/`<style>` skipped, at most 32 `og:*` properties of 1000 bytes and 8 KiB in all,
entity-decoded and returned only if valid UTF-8 with no control characters. Anything else
previews as `{}` ("which may be empty"). An `og:image` is fetched through the same gate and
stored with `store_fetched_media_for_user`, i.e. the normal upload pipeline as the requesting
user's media (sniffing, scanner, MIME policy, quarantine, size limit, quotas); quarantined or
refused images are left out of the response.

The gate refuses with one answer, `502 M_UNKNOWN "URL preview unavailable"`, whatever the
reason (refused address, unknown name, timeout, size, HTTP error), so the endpoint is not an
oracle for which internal names resolve or which ports answer. Malformed parameters are `400`
before anything is resolved.

A preview never fetches on a main-pool thread: it defers through `RemoteMediaFetchScope` to the
media fetch pool after the checks that need no network, like a remote media fetch (ADR-0121);
run inline (no pool) it takes an ADR-0079 client-outbound slot first. DNS, every request and the
HTML parse release `runtime.mutex`. Concurrent previews of one URL are coalesced on the remote media fetch
coalescer under a `preview:` key. Requests are rate limited per user in the `media` tier.

`http` is allowed (`OutboundRequest::allow_cleartext_http`), the one client-named destination
that may be: the request carries no credential, the response is treated as hostile in any case,
and the pin and peer check apply to cleartext exactly as to TLS. Refusing `http` would leave
much of the web unpreviewable without reducing the SSRF surface.

### Positive Consequences

* The same check guards the first hop, every redirect and the image; nothing reaches the
  network around it.
* Previews cannot tie up request threads or the runtime lock.

### Negative Consequences

* A server that enables previews still makes outbound requests on clients' behalf to the
  public internet (its address is revealed to the target site); operators decide.
* Sites that need JavaScript or relative-path image references get thinner previews.

## Pros and Cons of the Options

### libcurl follows redirects

* Good, because it is less code.
* Bad, because libcurl would resolve and connect to redirect targets without our address
  check, which is exactly the SSRF hole.

### Do not implement previews

* Good, because there is no surface.
* Bad, because clients then fall back to fetching previews themselves, revealing every reader's
  address to every linked site.

## Links

* Builds on [ADR-0121](0121-remote-media-fetches-run-on-their-own-pool.md) and
  [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md)
* Refined by [ADR-0214](0214-url-preview-cache-is-keyed-by-url-and-caches-failures.md)
