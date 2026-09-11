# src/federation/ — Federation Module

Implements the Matrix Server-Server API v1.19.
Spec authority: ../../docs/matrix-v1.19-spec/server-server-api.md

Federation is the highest-risk surface: **all input comes from untrusted remote servers.**

## Security rules — non-negotiable

1. **Authenticate every inbound request with X-Matrix auth** before touching any body data.
   Reject with `401 Unauthorized` if the header is absent, malformed, or the signature is invalid.
   See `inbound_request.hpp` and `security.hpp`.

2. **Verify every inbound PDU's signature** against the sending server's published key before
   allowing it to enter the event graph. Unverified events must be silently dropped (not persisted).

3. **Fetch remote server keys via `remote_key_cache.hpp`** — never trust a key the remote server
   supplies inline. The key cache fetches from `/_matrix/key/v2/server` and enforces TTL.

4. **Run authorization rules** (`events/authorization.hpp`) before persisting any inbound PDU.

5. **Reject soft-failed events** — do not forward or act on events that fail auth but are kept for
   state resolution purposes. **Not implemented yet:** there is no soft-fail check (auth against
   the room's current state) anywhere in `src/`; see `docs/todos/capability-gaps.md`.

6. **Never relay a remote server's answer about users unfiltered.** Keep only the users that
   server was asked about, and only records that describe the user they are filed under. For
   E2EE keys use `accept_remote_key_query_response()` (`key_query.hpp`). Merge uploaded key
   signatures only through `key_signatures.hpp`, passing `std::nullopt` as the viewer for
   anything sent to another server (ADR-0060).

## Key files

| File | Responsibility |
|---|---|
| `inbound_request.cpp` | Parses and authenticates inbound federation HTTP requests |
| `inbound_ingestion.cpp` | Validates, verifies, and ingests inbound PDUs |
| `outbound_transaction.cpp` | Batches local events and delivers them to remote servers |
| `server_discovery.cpp` | Resolves `server_name` → host:port per SS API §Resolving Server Names |
| `remote_key_cache.cpp` | Caches remote server signing keys with validity TTL |
| `membership_endpoints.cpp` | /make_join, /send_join, /make_leave, /send_leave |
| `key_query.cpp` | E2EE key responses served over federation, key EDU contents, filtering remote key-query responses |
| `key_signatures.cpp` | The one place uploaded key signatures are merged into published keys (visibility per ADR-0060) |
| `security.cpp` | Federation-layer security checks (rate limits, origin validation, SSRF address policy) |
| `transactions.cpp` | Transaction batching and deduplication |
| `server_acl.cpp` | Parses and evaluates `m.room.server_acl` allow/deny lists |
| `dispatch_worker.cpp` | Background outbound PDU/EDU delivery with per-destination retry and back-off |
| `event_query.cpp` | Serves `GET /_matrix/federation/v1/event/{eventId}` |
| `outbound_membership.cpp` | Outbound `make_join` / `make_leave` / `make_knock` calls |
| `cached_server_discovery.cpp` | TTL-bounded in-memory cache in front of server discovery |
| `runtime_federation.cpp` | Federation route registration and per-origin request caps |

## Adding a new federation endpoint

1. Declare handler in the relevant `.hpp`
2. Implement in the matching `.cpp`
3. Register route in `runtime_federation.cpp`
4. Add a conformance test in `tests/conformance/` citing the spec section
5. Add an integration test in `tests/integration/test_federation_*_flow.cpp`

## Key spec sections

- [Request authentication (X-Matrix)](../../docs/matrix-v1.19-spec/server-server-api.md#request-authentication)
- [PDUs](../../docs/matrix-v1.19-spec/server-server-api.md#pdus)
- [Authorisation rules](../../docs/matrix-v1.19-spec/server-server-api.md#authorisation-rules)
- [Resolving server names](../../docs/matrix-v1.19-spec/server-server-api.md#resolving-server-names)
- [Transactions](../../docs/matrix-v1.19-spec/server-server-api.md#transactions)
- [Joining rooms](../../docs/matrix-v1.19-spec/server-server-api.md#joining-rooms)
- [Key publication](../../docs/matrix-v1.19-spec/server-server-api.md#publishing-keys)
