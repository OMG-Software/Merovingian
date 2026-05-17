# JSON output and HTTP client hardening

This plan covers two pieces of work that should land together: removing
hand-rolled JSON string construction from response paths, and replacing the
not-yet-built outbound federation HTTP client with a library-backed
implementation.

The motivation in both cases is the same: hand-written parsers, serializers,
and protocol formatters are where security defects accumulate. Where a vetted
library already exists in the project's dependency surface, use it.

## Background

The project already depends on `yyjson` (pinned to v0.12.0 in
`subprojects/yyjson.wrap`) and `OpenSSL` (pinned via wrap, used for TLS
termination on inbound listeners). The canonical JSON layer uses `yyjson` for
strict parsing and project-owned deterministic serialization for signing
inputs.

Despite this, several response paths build JSON shapes by string concatenation
through a bespoke `json_escape` helper, and the federation outbound path is a
57-line stub with no socket, TLS, signing, or retry implementation.

## Problem statement

### JSON output

`src/homeserver/client_server.cpp` constructs response JSON by string
concatenation in at least the following places:

- `devices_json`
- `joined_rooms_json`
- `sync_json` (the most complex shape — nested rooms and timelines)
- the generic single-field response helper at the room-event GET path
- the device-keys response paths
- `matrix_error` — used by every error response
- the register, login, and whoami responses

The local `json_escape` helper handles `"`, `\`, `\b`, `\f`, `\n`, `\r`, and
`\t`, but does not emit `\u00XX` for other U+0000..U+001F control characters.
Matrix canonical JSON requires these to be escaped. While none of the current
response paths obviously emit canonical JSON to the wire, this asymmetry is a
latent defect because:

- Error response bodies pass user-derived strings (errcode, error message)
  through the same incomplete escaper.
- Any string carrying a control byte (e.g. an `\r` injected through a
  database-stored field) would break the on-wire JSON.
- The codebase already has a correct canonical-JSON serializer; maintaining a
  second, weaker escaper increases audit surface.

### Outbound HTTP

`src/federation/outbound_transaction.cpp` declares the federation outbound
transaction shape but does not implement:

- TCP connect or DNS resolution under the documented SSRF policy
- TLS handshake or remote certificate validation (no `SSL_VERIFY_PEER`, no
  hostname check)
- `X-Matrix` request signing
- canonical JSON body construction for signing
- redirect handling (federation must reject 3xx)
- chunked transfer or `Content-Length` handling on responses
- per-request timeouts
- keep-alive or connection reuse
- retry against the existing `compute_backoff` policy
- circuit-breaker state transitions

Because this code is not yet written, the cost of choosing a library is at its
lowest right now.

## Goals

- Remove every hand-built JSON shape from response paths and replace them with
  `yyjson` mutable-document construction.
- Adopt `libcurl` for outbound federation HTTP, wrapped behind a
  `merovingian::http::OutboundClient` abstraction so the rest of the codebase
  never touches `CURL*` handles.
- Keep the existing inbound HTTP server (parser, slowloris caps, fuzz target,
  OpenSSL TLS termination) in place.
- Keep the existing canonical JSON serializer in place for signing inputs.
- Preserve the project's existing failure modes: fail-closed startup, bounded
  inputs, no dependency-defined signing semantics.

## Non-goals

- Replacing the inbound HTTP/1.1 parser. It is documented in
  `docs/http-transport.md`, has bounded inputs and a fuzz target, and works.
- Replacing the canonical JSON serializer. It is signing-critical and is
  intentionally project-owned per `docs/canonical-json.md`. `yyjson_mut_write`
  is not a substitute for it.
- Adopting HTTP/2 anywhere. Matrix federation works over HTTP/1.1 and HTTP/2
  is non-trivial to add safely; deferred.
- Adopting libcurl for inbound serving. libcurl is a client.
- Building a generic HTTP client framework. The outbound client surface should
  expose only what federation needs.

## Phase A — JSON output refactor (v0.1.49, completed)

Every hand-rolled JSON response in `src/homeserver/client_server.cpp` now
flows through `canonicaljson::Value` + `serialize_canonical`. Sites covered:
`matrix_error`, `devices_json`, `joined_rooms_json`, `sync_json`,
`safety_reports_json`, `wrap`, the device key and one-time key responses,
and the register/login/whoami responses. The local `json_escape` helper is
gone; control-character escaping (`\u00XX` for U+0000..U+001F) and UTF-8
validation now ride on the audit-friendly serializer.

A thin anonymous-namespace builder facade (`json_str`, `json_int`,
`json_bool`, `json_arr`, `json_obj`, `json_member`, `json_serialize`,
`json_embed_raw`) keeps the response sites readable. Stored device key
payloads are embedded through `json_embed_raw`, which parses the blob
through the canonical parser so malformed stored data surfaces as a
well-formed `null` on the wire rather than corrupting the response.

Response key ordering moved from insertion order to canonical
lexicographic order as a side effect; existing tests use substring
matchers and remain green.



### A.1 Scope

Replace string-concatenated JSON construction in `client_server.cpp` with
`yyjson_mut_doc`. Delete the local `json_escape` helper once no caller remains.

The canonical JSON layer is untouched. Only response-path JSON moves to
`yyjson`.

### A.2 Approach

- Introduce a thin response-builder facade in `src/homeserver/` so call sites
  build values via a small set of helpers (`make_string`, `make_array`,
  `add_member`) and serialize once at the boundary. This keeps `yyjson.h` from
  spreading through transport code and mirrors the existing yyjson adapter
  pattern in `src/canonicaljson/`.
- Serialize with the unicode-escape write flag set so control characters are
  emitted as `\u00XX`.
- Replace each call site in this order to limit churn:
  1. `matrix_error` — highest blast radius, smallest shape.
  2. Single-field response helpers (whoami, register, login token returns).
  3. `devices_json`, `joined_rooms_json`, device-keys responses.
  4. `sync_json` last — most nested shape; refactor benefits most from the
     builder pattern.
- Remove `json_escape` once no caller remains. Confirm with a grep gate in CI.

### A.3 Testing

Per project rules, write the behavior test before changing the code.

- GIVEN an error path produces an `errcode` containing a control byte WHEN the
  response is serialized THEN the body parses as JSON and the control byte
  appears as `\u00XX`.
- GIVEN a device with a display name containing `"` and `\` WHEN
  `devices_json` is serialized THEN the body parses as JSON and round-trips to
  the original value.
- GIVEN a `sync_json` shape with nested rooms WHEN serialized THEN it parses
  as JSON and contains the expected `next_batch`, `rooms.join`, and timeline
  members.
- Existing client-server endpoint tests must continue to pass without
  modification — the shape on the wire is unchanged for well-formed inputs.

A fuzz target should be added that drives the new response builder with
arbitrary string inputs and asserts the output parses back via `yyjson`.

## Phase B — Outbound HTTP via libcurl

### B.1 Scope

Author a `subprojects/curl.wrap` (system pkg-config fallback first, wrapped
build second), introduce `merovingian::http::OutboundClient`, and wire it into
the federation outbound transaction path.

### B.2 Approach

- Add a wrap file that prefers a system libcurl via pkg-config, falling back
  to the upstream curl release. Required curl features: HTTP/1.1 only, no
  SCP/SFTP, no LDAP, no RTSP, no telnet, no dict, no smtp, no pop3, no imap,
  no gopher, no file protocol. The narrower the build, the smaller the audit
  surface. The TLS backend is whatever the system curl was built against
  (OpenSSL on Linux, LibreSSL on OpenBSD, etc.) — this keeps packaging simple
  on BSD targets at the cost of a less-uniform TLS surface; the
  `OutboundClient` test suite must run on each supported platform to confirm
  verification behavior is consistent.
- Wrap libcurl behind `merovingian::http::OutboundClient`. The interface
  exposes:
  - a request type carrying method, target URL, headers, optional body, and a
    timeout
  - a response type carrying status, headers, and body
  - a synchronous `perform` entry point at first; async/multi can come later
- Configure each request with:
  - `CURLOPT_SSL_VERIFYPEER = 1`
  - `CURLOPT_SSL_VERIFYHOST = 2`
  - `CURLOPT_FOLLOWLOCATION = 0` (federation must not follow redirects)
  - `CURLOPT_PROTOCOLS_STR = "https"` (no cleartext outbound)
  - explicit connect and total timeouts from `RuntimeFederationConfig`
  - the SSRF address-binding rules already documented in
    `src/federation/security.cpp` — resolve, validate the address set against
    loopback/link-local/private/ULA, then pin via `CURLOPT_RESOLVE` so curl
    cannot drift to a different address after validation
- Build the request body via the canonical JSON serializer (not `yyjson_mut`)
  because the body is the signing input.
- Construct the `X-Matrix` Authorization header using
  `make_federation_signature` shared with the inbound verifier so signing
  semantics stay symmetric.
- Drive retries through the existing `compute_backoff` and circuit-breaker
  primitives in `security.cpp`.

### B.3 Testing

- GIVEN a federation peer that presents an invalid certificate WHEN the
  outbound client attempts a request THEN the request fails closed with a
  TLS verification error.
- GIVEN a peer that returns 302 WHEN the outbound client receives the
  response THEN the request fails closed with a redirect-rejection error.
- GIVEN a peer that resolves to a loopback or private address WHEN the
  outbound client attempts a connect THEN the request fails closed before any
  bytes are sent.
- GIVEN a peer that returns 200 with a canonical JSON body WHEN the outbound
  client receives the response THEN the response body parses and verifies
  under the peer's signing key.
- GIVEN three consecutive failures against a peer WHEN a fourth request is
  attempted THEN the circuit breaker rejects it without a network call.

Integration tests should run against a local TLS test server stood up in the
test harness, not against real homeservers.

### B.4 Wrap and build

- Add `subprojects/curl.wrap` with version, source URL, source hash, and
  `provide` mapping for `libcurl`.
- Add `curl_dep = dependency('libcurl', version: '>= 8.0.0', required: true,
  fallback: ['curl', 'libcurl_dep'])` at the top-level `meson.build`.
- Gate federation outbound build on `curl_dep.found()` so the project still
  builds for non-federation-enabled deployments if that becomes a goal.
- CI Linux and BSD jobs must install libcurl development headers before
  configuring Meson, matching the existing OpenSSL/LibSodium pattern.

## Out of scope / deferred

- Inbound HTTP parser replacement.
- Canonical JSON serializer replacement.
- HTTP/2 outbound or inbound.
- Async/event-loop outbound client. The first cut is synchronous; an event
  loop can layer on top once the shape is stable.
- Connection pooling / keep-alive across federation requests. Curl supports
  this but it is out of scope for the first cut.
- Replacing the inbound TLS termination layer.

## Risks

- libcurl is large. Mitigation: build a narrowed feature set (HTTPS only)
  and pin the version through a wrap; review the curl CVE feed at each
  version bump.
- TLS backend is not pinned at wrap time. Mitigation: the OutboundClient
  integration suite runs on each supported platform (Linux, FreeBSD,
  OpenBSD) and asserts identical verification behavior — invalid cert
  rejection, hostname mismatch rejection, expired cert rejection — so a
  backend drift surfaces in CI rather than at runtime.
- The `yyjson` mutable doc API allocates. Mitigation: response paths already
  allocate (they build `std::string`); benchmark `sync_json` before and after
  to confirm no regression at p99.
- Two JSON serializers (`yyjson` for responses, project-owned for canonical)
  is a maintenance cost. Mitigation: document the boundary in
  `docs/canonical-json.md` so future contributors do not blur the two.
- Outbound TLS verification disagreements with peers (e.g. self-signed test
  servers) will surface during integration. This is correct behavior, not a
  regression.

## Sequencing

Phase B lands first. Outbound federation is the larger correctness gap and
the JSON refactor can ride on the response-builder pattern Phase B
establishes for its own request bodies.

Phase A follows on its own branch and version bump.

### Phase B progress

Phase B is split into three slices. Each slice ships on its own version bump
and CHANGELOG entry so each merge is reviewable in isolation.

- **Slice 1 — foundation (v0.1.45, completed).** Public surface of
  `merovingian::http::OutboundClient` plus `OutboundRequest`,
  `OutboundResponse`, `OutboundResult`, `OutboundError`, the pure
  `validate_outbound_request` helper, and a fail-closed stub `perform()`
  that returns `OutboundError::not_implemented`. `libcurl` (>= 7.85.0) is
  wired into `http_lib` as a build dependency. BDD test coverage exists
  for method, scheme, host-segment, empty-URL, and pinned-address
  validation, for stub fail-closed behavior, and for stable error names.
- **Slice 2 — libcurl-backed `perform()` (v0.1.46, completed).** The real
  request loop runs with `CURLOPT_SSL_VERIFYPEER=1`,
  `CURLOPT_SSL_VERIFYHOST=2`, `CURLOPT_FOLLOWLOCATION=0`,
  `CURLOPT_PROTOCOLS_STR="https"`, `CURLOPT_NOSIGNAL=1`, explicit connect
  and total timeouts, and a bounded response body cap that surfaces
  oversized responses as `response_too_large`. The slice also includes
  the SSRF pin: `CURLOPT_RESOLVE` is populated from the caller-supplied
  `pinned_addresses` so the connection cannot drift to a different
  address. libcurl failure modes map onto a stable
  `OutboundError` set: `tls_verification_failed`, `connection_failed`,
  `timeout`, `response_too_large`, `redirect_rejected`, and the
  catch-all `network_error`. The `not_implemented` placeholder is gone.
- **Slice 3 — federation wiring (v0.1.47, completed).** Composed
  `OutboundCall` from a transaction shape, validated destination
  resolution, and signing identity. Added a pure
  `build_outbound_request` (URL = `https://<resolved_host>:<resolved_port><target>`,
  X-Matrix Authorization built through `make_federation_signature`,
  pinned addresses passed through verbatim), `apply_outbound_result`
  (resets the destination on 2xx and applies `compute_backoff` on any
  other outcome), and `perform_outbound_transaction` (single-attempt
  wrapper that short-circuits to `circuit_open` when
  `destination_should_retry` rejects the attempt). BDD coverage for the
  builder, the retry-state transitions, and the circuit-breaker early
  return are in place.
- **Slice 3b — local TLS integration tests (v0.1.48, completed).**
  Stood up a one-shot TLS test server in
  `tests/integration/test_federation_outbound_flow.cpp` backed by
  `merovingian::homeserver::TlsServerContext`. `OutboundRequest`
  gained an optional `trusted_ca_pem` field that maps onto
  `CURLOPT_CAINFO_BLOB` so the test cert can be trusted in-process
  without changing the system trust store. Four scenarios assert the
  expected behavior: a valid cert with matching hostname and trusted
  CA round-trips a 200 response; a hostname mismatch fails with
  `tls_verification_failed`; an empty trust bundle against a
  self-signed cert fails with `tls_verification_failed`; and a 302
  response surfaces as `redirect_rejected` with the redirect status
  preserved on the result. The suite runs on each supported platform
  in CI so TLS backend drift surfaces there rather than at runtime.

## Versioning and changelog

Each phase increments the project version and records its changes in
`CHANGELOG.md` per the project's versioning rule. Phase A and Phase B each
land as their own version bump on a dedicated branch.

## Open questions

- Should `OutboundClient` expose a streaming response body, or buffer the
  full body before returning? Federation transactions are bounded, so
  buffering is acceptable for the first cut. Streaming can come with media.

## Resolved questions

- TLS backend: system curl decides. The wrap does not pin OpenSSL. CI runs
  the OutboundClient suite on each supported platform to catch backend
  drift.
- BSD runtime dependency on libcurl: acceptable for the packaging targets
  in `docs/01-progress-tracker.md`.
- Sequencing: Phase B before Phase A.
