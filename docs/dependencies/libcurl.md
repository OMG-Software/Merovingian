# libcurl dependency review

This note records the dependency review for libcurl.

## Decision

libcurl is accepted as the selected HTTP transport for the federation
outbound HTTP client. It is wrapped behind `merovingian::http::OutboundClient`
and must not leak `CURL*`, `CURLcode`, or `curl_slist*` types into routing,
federation logic, room logic, or any caller above the HTTP transport
boundary.

## Why it is needed

Federation outbound traffic requires an HTTPS client with peer and hostname
certificate verification, redirect refusal, pinned-address resolution to
enforce the SSRF policy, bounded response capture, and a stable error
contract that supports retries and circuit breaker decisions. Rolling these
from scratch is high-risk; libcurl is widely audited, packaged across the
supported Linux and BSD targets, and ships in mainline distributions.

## Security boundary

- `CURL*`, `curl_slist*`, and `CURLcode` ownership is RAII-managed inside
  `src/http/outbound_client.cpp`.
- `curl_global_init` runs once through a function-local static guard so the
  call is serialized before any easy-handle initialization on other threads.
- Every request runs with `CURLOPT_SSL_VERIFYPEER=1`, `CURLOPT_SSL_VERIFYHOST=2`,
  `CURLOPT_FOLLOWLOCATION=0`, `CURLOPT_PROTOCOLS_STR="https"`, and
  `CURLOPT_NOSIGNAL=1`. Each security option is checked and the request
  fails closed if libcurl refuses to apply it.
- Hostnames are pinned to caller-supplied addresses through
  `CURLOPT_RESOLVE` so the connection cannot drift to a different address
  after the federation security policy validates the destination.
- Response bodies are captured behind a per-request byte cap; oversized
  bodies abort the transfer and surface as `OutboundError::response_too_large`.
- 3xx responses are not followed; they surface as
  `OutboundError::redirect_rejected` with the status and headers preserved
  on the result for audit.

## Maintenance and platform posture

libcurl is pinned through `subprojects/curl.wrap`, currently targeting the
8.20.0 source release. The TLS backend still follows the host OpenSSL selection
underneath that wrap, and the OutboundClient integration suite remains
responsible for catching backend behavior drift across supported platforms.
The fallback packagefile exposes curl's installed include root, not the nested
`curl` include directory, so `<curl/curl.h>` resolves the same way on Linux and
BSD.

The fallback also disables optional zlib and zstd content-encoding support.
Merovingian does not require compressed federation responses at this boundary,
and disabling those backends keeps the static fallback link closed without
pulling undeclared compression libraries into every binary.

## Current limitations

- The libcurl-backed `perform()` is synchronous. Async/multi-handle support
  is intentionally deferred.
- Connection pooling and keep-alive across requests is deferred until the
  federation outbound transaction flow demands it.
- Per-platform integration tests against a local TLS test server land with
  the federation wiring slice.
