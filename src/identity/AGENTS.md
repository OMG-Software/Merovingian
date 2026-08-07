# src/identity/ — Identity Service API Client

The homeserver is a **client** of operator-configured identity servers (IS). This
module is the outbound Identity Service API surface — it never serves IS
endpoints, only calls them.

## Key files

| File | Responsibility |
|---|---|
| `identity_client.cpp` | `IdentityServerClient`: `store-invite`, `lookup`, `bind`, `unbind`, `requestToken`; pure URL/body/response helpers |

## Security rules (non-negotiable)

- **No ad-hoc DNS.** Every IS host is resolved to SSRF-safe pinned addresses via
  `federation::CachedServerDiscovery::upstream().lookup_addresses(host, port)`,
  which applies the operator `deny_ip_ranges` (private/loopback/link-local)
  before returning addresses. The client never resolves DNS itself and never
  accepts a client-supplied IP. Fail closed (`ok == false`) when resolution
  yields no usable address.
- **TLS on, always.** IS base URLs must be `https://` (enforced by config
  validation and `parse_identity_server_url`). `http::OutboundClient` verifies
  peer + hostname certificates; redirects are refused.
- **Bearer auth, not X-Matrix.** The IS API uses the client's `id_access_token`
  (from `/_matrix/client/v3/user/{userId}/openid/request_token`) as a bearer
  token for authenticated endpoints (`store-invite`, `bind`, `unbind`,
  `requestToken`). `lookup` is unauthenticated. Never send the homeserver's
  signing key or `Authorization: X-Matrix` to an IS.
- **The IS owns the store-invite token + ephemeral key, not the HS.** Per
  v1.19, `POST /store-invite` returns `{token, display_name, public_keys}` —
  the HS embeds the IS-provided `public_key`/`key_validity_url` in the
  `m.room.third_party_invite` event so joining servers can verify the invite
  signature against the IS. The HS must not mint its own token/key for a remote
  3PID invite.
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