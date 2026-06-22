# src/federation/ — Federation Module

Implements the Matrix Server-Server API v1.18.
Spec authority: ../../docs/matrix-v1.18-spec/server-server-api.md

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
   state resolution purposes.

## Key files

| File | Responsibility |
|---|---|
| `inbound_request.cpp` | Parses and authenticates inbound federation HTTP requests |
| `inbound_ingestion.cpp` | Validates, verifies, and ingests inbound PDUs |
| `outbound_transaction.cpp` | Batches local events and delivers them to remote servers |
| `server_discovery.cpp` | Resolves `server_name` → host:port per SS API §Resolving Server Names |
| `remote_key_cache.cpp` | Caches remote server signing keys with validity TTL |
| `membership_endpoints.cpp` | /make_join, /send_join, /make_leave, /send_leave |
| `security.cpp` | Federation-layer security checks (rate limits, origin validation) |
| `transactions.cpp` | Transaction batching and deduplication |

## Adding a new federation endpoint

1. Declare handler in the relevant `.hpp`
2. Implement in the matching `.cpp`
3. Register route in `runtime_federation.cpp`
4. Add a conformance test in `tests/conformance/` citing the spec section
5. Add an integration test in `tests/integration/test_federation_*_flow.cpp`

## Key spec sections

- [Request authentication (X-Matrix)](../../docs/matrix-v1.18-spec/server-server-api.md#request-authentication)
- [PDUs](../../docs/matrix-v1.18-spec/server-server-api.md#pdus)
- [Authorization rules](../../docs/matrix-v1.18-spec/server-server-api.md#authorization-rules)
- [Resolving server names](../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names)
- [Transactions](../../docs/matrix-v1.18-spec/server-server-api.md#transactions)
- [Joining rooms](../../docs/matrix-v1.18-spec/server-server-api.md#joining-rooms)
- [Key publication](../../docs/matrix-v1.18-spec/server-server-api.md#get_matrixkeyv2server)
