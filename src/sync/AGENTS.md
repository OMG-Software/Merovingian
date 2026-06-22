# src/sync/ — Sync Module

Implements `/sync` (CS API v3), MSC4186 Simplified Sliding Sync (`/sync/v3` unstable),
sync filtering, stream tokens, and the sync notifier.

Spec authority:
- `/sync`: ../../docs/matrix-v1.18-spec/client-server-api.md#syncing
- Sliding sync: MSC4186 (unstable, `/_matrix/client/unstable/org.matrix.simplified_msc3575/sync`)

## Key files

| File | Responsibility |
|---|---|
| `stream_token.cpp` | Encode/decode stream ordering tokens; used for `since=` / `next_batch` / `from=` parameters |
| `sync_filter.cpp` | Parse and apply sync filter arguments (event type filters, room filters, timeline limits) |
| `sync_notifier.cpp` | Broadcasts new events to waiting long-poll sync requests; handles the `timeout=` wait |
| `sliding_sync_parser.cpp` | Parses MSC4186 request body (list operators, range, required_state, etc.) |
| `sliding_sync_room_list.cpp` | Builds the ordered room list for a sliding sync response |
| `sliding_sync_room_builder.cpp` | Constructs per-room response data (timeline, state, heroes) |
| `sliding_sync_extensions.cpp` | MSC4186 extensions (to_device, e2ee, account_data, typing, receipts) |

## Stream token format

`next_batch` and `since` for `/sync` are opaque encoded triplets:
`<rooms_ordering>|<to_device_ordering>|<account_data_ordering>`

For `/messages` and timeline `prev_batch`, the token is a plain stream-ordering integer.
Use `stream_token.hpp` — never parse or construct tokens manually.

## Sliding sync connection state

MSC4186 tracks per-connection state keyed by `conn_id`. On a no-`pos` poll, the server
uses `conn.last_event_ordering` as the since-baseline so repeated `timeout=0` polls return
a delta (empty rooms, same pos) rather than re-sending the full initial sync.

## Long-poll behaviour

`sync_notifier` holds requests until an event arrives or `timeout` expires.
- The timeout is capped at the configured maximum and polled in 5-second slices
- The sync thread pool (`sync_pool`) is separate from the main thread pool to prevent
  long-polling clients from starving federation and other short-lived requests

## Key spec sections

- [Syncing](../../docs/matrix-v1.18-spec/client-server-api.md#syncing)
- [Filtering](../../docs/matrix-v1.18-spec/client-server-api.md#filtering)
- [MSC4186 Simplified Sliding Sync](../../docs/matrix-v1.18-spec/client-server-api.md)
