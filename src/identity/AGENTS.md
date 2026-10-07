# src/identity/ — Identity Service API Client

The homeserver is a **client** of operator-configured identity servers (IS). This
module is the outbound Identity Service API surface — it never serves IS
endpoints, only calls them.

## Key files

| File | Responsibility |
|---|---|
| `identity_client.cpp` | `IdentityServerClient`: `store-invite`, `lookup`, `bind`, `unbind`, `request_email_token`, `request_msisdn_token`, `get_validated_3pid`; pure URL/body/response helpers |

## Security rules (non-negotiable)

- **No ad-hoc DNS.** Every IS host is resolved to SSRF-safe pinned addresses via
  `federation::CachedServerDiscovery::lookup_addresses_filtered(host, port)`,
  which rejects private, loopback, link-local, CGNAT, NAT64, multicast, and
  reserved addresses before returning pinned addresses. The client never
  resolves DNS itself and never accepts a client-supplied IP. Fail closed
  (`ok == false`) when resolution yields no usable address.
- **Test-only discovery seam.** `IdentityServerClient` accepts an optional
  `std::map<std::string, TestForcedIdentityResolution> const* forced_resolution`
  (struct defined in this header, stored on
  `HomeserverRuntime::test_forced_identity_resolution`, keyed by IS host). When
  an entry exists for the target host, `perform()` uses the entry's
  `pinned_addresses` + `trusted_ca_pem` and **skips** `CachedServerDiscovery`,
  letting the conformance/integration suites reach a self-signed local mock IS
  on `127.0.0.1` over real TLS. The map is empty in production and has no
  production construction path. Unlike the federation seam there is no
  `resolved_port`: the URL carries the port and `OutboundClient` builds
  `CURLOPT_RESOLVE` `host:port:address`, so the mock IS port must match the URL.
  The struct lives in the identity header (not `runtime.hpp`) to keep the
  `homeserver → identity` dependency direction correct.
- **TLS on, always.** IS base URLs must be `https://` (enforced by config
  validation and `parse_identity_server_url`). `http::OutboundClient` verifies
  peer + hostname certificates; redirects are refused.
- **Bearer auth, not X-Matrix.** The IS API uses the client's `id_access_token`
  (from `/_matrix/client/v3/user/{userId}/openid/request_token`) as a bearer
  token for authenticated endpoints (`store-invite`, `bind`, `requestToken`,
  `getValidated3pid`).
  `lookup` is unauthenticated. Never send the homeserver's signing key or
  `Authorization: X-Matrix` to an IS. **Exception — `unbind` auth mode 2:** when
  the HS replays a stored `client_secret` + `sid` (no bearer), `unbind` sends an
  unauthenticated body via `build_unbind_body` (no `Authorization` header); an
  empty `id_access_token` selects mode 2. The `client_secret`/`sid` are
  persisted (migration `007`) only for IS-bound 3PIDs so the HS can remotely
  unbind after the user's original `id_access_token` is long gone.
- **The IS owns the store-invite token + ephemeral key, not the HS.** Per
  v1.19, `POST /store-invite` returns `{token, display_name, public_keys}` —
  the HS embeds the IS-provided `public_key`/`key_validity_url` in the
  `m.room.third_party_invite` event so joining servers can verify the invite
  signature against the IS. The HS must not mint its own token/key for a remote
  3PID invite.
- **The identity server is the only proof of 3PID ownership (AUTH-5).** The
  homeserver cannot send email or SMS, so it never validates an address itself.
  A `requestToken` without a trusted `id_server` is refused
  (`M_THREEPID_MEDIUM_NOT_SUPPORTED`); a delegated session starts unvalidated;
  and a 3PID is added or bound only after `get_validated_3pid` returns a 200
  that `parse_validated_3pid_response` accepts for the same medium and address
  as the session. `parse_validated_3pid_response` must keep failing closed
  (missing or mistyped field, empty value, non-positive `validated_at`): a
  response that does not positively say "validated" must never be read as
  validated. The call site (`confirm_validation_session` in
  `src/homeserver/client_server.cpp`) releases `runtime.mutex` for the call and
  re-checks the session after re-taking it. `build_get_validated_3pid_path`
  percent-encodes both query values: the sid is chosen by the identity server.
- **Trusted-server allowlist.** Call sites must confirm `base_url` is in
  `config.server().identity_server.trusted_servers` before calling. An
  untrusted IS URL is a configuration/programming error, not a fallback path.

## Conventions

- Pure helpers (`parse_identity_server_url`, `build_*_body`, `parse_*_response`)
  are free functions — unit-testable with no network. The body builders use
  canonicaljson so request bodies are byte-identical to signed federation
  traffic and stay ordered/encoded consistently.
- `IdentityServerResult.ok` reflects **transport** success only. Callers branch
  on `status` for IS-level outcomes (e.g. a 404 on `lookup` = "no binding", not
  a transport failure) and fail closed on `ok == false`.
- The client borrows `http::OutboundClient&`, `federation::CachedServerDiscovery&`,
  and `config::IdentityServerConfig const&` by reference — all owned by the
  `HomeserverRuntime`. Construct once at startup (restart-required reload
  policy); do not construct per-request.

## Spec reference

- `docs/matrix-v1.19-spec/identity-service-api.md` — store-invite, lookup,
  bind/unbind, requestToken, key validity.