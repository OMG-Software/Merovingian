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

libcurl is a **system-provided dependency on every platform** — the meson
dependency uses `allow_fallback: false`, so the build always links the operating
system's libcurl and never vendors it. The build host must provide the libcurl
development files (`libcurl4-openssl-dev`, `libcurl-devel`, or the `curl`
package depending on platform), and the OS packages declare libcurl as a runtime
dependency so deployments receive distro security updates. The TLS backend
follows the host libcurl's OpenSSL/LibreSSL selection; the OutboundClient
integration suite catches backend behavior drift across supported platforms.

The portable static (musl) build is the one exception. Alpine's `libcurl.a`
pulls in libpsl, libidn2 and libunistring, whose static archives Alpine does
not ship, so `scripts/build-static-linux.sh` passes `-Dstatic_curl_wrap=true`
and builds curl from `subprojects/curl.wrap` (curl 8.23.0) instead.
`subprojects/packagefiles/curl/meson.build` runs curl's own `configure` as a
Meson external project, static only, against the host OpenSSL, with every
optional backend it does not need turned off (`--without-libpsl`,
`--without-libidn2`, compression, HTTP/2 and HTTP/3, SSH, GSS-API). Check its
`configure` options against each new curl release: autoconf only warns about an
option it no longer knows, so a removed one fails silently (RTMP support, and
with it `--without-librtmp`, was removed in curl 8.20.0). `<curl/curl.h>`
resolves from the installed include root the same way on Linux and BSD.

## License

libcurl is released under the curl license, an MIT-style license (`SPDX:
curl`). It is compatible with Merovingian's GPL-3.0-or-later distribution
and is resolved from the operating-system package.

## Current limitations

- The libcurl-backed `perform()` is synchronous. Async/multi-handle support
  is intentionally deferred.
- Connection pooling and keep-alive across requests is deferred until the
  federation outbound transaction flow demands it.
- Per-platform integration tests against a local TLS test server land with
  the federation wiring slice.
