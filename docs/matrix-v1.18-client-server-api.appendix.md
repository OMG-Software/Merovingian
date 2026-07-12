---

## Unstable Extensions

The following endpoints are **not part of the stable v1.18 spec**. They are served under
`/_matrix/client/unstable/` and are advertised via `unstable_features` in
`/_matrix/client/versions`. They may change or be removed when finalised by the spec process.

### MSC4186 — Simplified Sliding Sync

- **Proposal**: <https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md>
- **Latest raw proposal** (authoritative for stable endpoint and request shape): <https://raw.githubusercontent.com/matrix-org/matrix-spec-proposals/refs/heads/main/proposals/4186-simplified-sliding-sync.md>
- **Advertised via**: `unstable_features["org.matrix.msc4186"] = true` and
  `unstable_features["org.matrix.simplified_msc3575"] = true` in `/_matrix/client/versions`
- **Implementation files**:
  - `include/merovingian/sync/sliding_sync.hpp` — request/response types
  - `include/merovingian/sync/sliding_sync_parser.hpp` + `src/sync/sliding_sync_parser.cpp` — request parser
  - `include/merovingian/sync/sliding_sync_room_list.hpp` + `src/sync/sliding_sync_room_list.cpp` — room-list windowing and ops
  - `include/merovingian/sync/sliding_sync_room_builder.hpp` + `src/sync/sliding_sync_room_builder.cpp` — per-room response builder
  - `include/merovingian/sync/sliding_sync_extensions.hpp` + `src/sync/sliding_sync_extensions.cpp` — five extensions
  - `src/homeserver/client_server.cpp` — HTTP handler (`sliding_sync_json`)

| Method | Path | Auth | Request body | Responses |
| --- | --- | --- | --- | --- |
| `POST` | `/_matrix/client/v4/sync` | access token | optional `application/json` | 200, 400 |
| `POST` | `/_matrix/client/unstable/org.matrix.msc4186/sync` | access token | optional `application/json` | 200, 400 |
| `POST` | `/_matrix/client/unstable/org.matrix.simplified_msc3575/sync` | access token | optional `application/json` | 200, 400 |

#### Request parameters

The `pos` and `timeout` parameters may be supplied either as query parameters or as top-level
fields in the JSON body. The server prefers query parameters when both are present.

| Parameter | Type | Description |
| --- | --- | --- |
| `pos` | string | Opaque position token from the previous response. Absent on first request (initial sync). |
| `timeout` | integer | Long-poll wait time in milliseconds. Absent or 0 = respond immediately. |

#### Request body fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `conn_id` | string | optional | Identifies a logical connection so the server can maintain separate state per client tab. |
| `pos` | string | optional | Body-level alternative to the `pos` query parameter. |
| `timeout` | integer | optional | Body-level alternative to the `timeout` query parameter. |
| `lists` | object | optional | Named room lists. Keys are arbitrary list IDs chosen by the client. |
| `lists.*.ranges` | array of [start, end] pairs | required if list present | Windowed view into the sorted room list. Ranges MUST NOT overlap; start MUST be ≤ end. |
| `lists.*.range` | [start, end] | alternative to `ranges` | A single sliding window. Accepted for clients that send one window as a 2-tuple rather than a nested array. |
| `lists.*.sort` | array of strings | optional | Sort criteria applied left-to-right: `by_recency`, `by_notification_count`, `by_name`. |
| `lists.*.required_state` | array of [type, state_key] pairs | optional | State events to include in each room. `"*"` is a wildcard in either position. |
| `lists.*.timeline_limit` | integer | optional | Maximum number of timeline events to return per room. |
| `room_subscriptions` | object | optional | Explicit per-room subscriptions keyed by room ID. |
| `extensions` | object | optional | Extension requests. Each extension has an `enabled` boolean. |
| `extensions.to_device` | object | optional | Fetch pending to-device messages. Fields: `enabled`, `limit`, `since`. |
| `extensions.e2ee` | object | optional | Fetch device list changes and OTK counts. Fields: `enabled`. |
| `extensions.account_data` | object | optional | Fetch global and per-room account data. Fields: `enabled`. |
| `extensions.receipts` | object | optional | Fetch read receipts. Fields: `enabled`, `rooms`. |
| `extensions.typing` | object | optional | Fetch typing notifications. Fields: `enabled`, `rooms`. |

#### Response body fields

| Field | Type | Description |
| --- | --- | --- |
| `pos` | string | New opaque position token. MUST be returned on every successful response. |
| `lists` | object | One entry per list. Contains `count` (total rooms matching the filter) and `ops` (list operations). |
| `rooms` | object | One entry per room included in the response. Keyed by room ID. |
| `extensions` | object | Extension responses. Only present for enabled extensions. |

#### Room object fields (`rooms[roomId]`)

| Field | Type | Description |
| --- | --- | --- |
| `name` | string \| null | Room display name. |
| `avatar` | string \| null | Room avatar MXC URL. |
| `initial` | boolean | `true` the first time this room appears on this connection. |
| `is_dm` | boolean | Whether the room is a direct message. |
| `joined_count` | integer | Number of joined members. |
| `invited_count` | integer | Number of invited members. |
| `notification_count` | integer | Unread message/encrypted event count. |
| `highlight_count` | integer | Unread highlight count. |
| `num_live` | integer | Number of timeline events that occurred since the previous request. |
| `timestamp` | integer | `origin_server_ts` of the most recent event in the room. |
| `heroes` | array | Hero members for computing a fallback room name. |
| `required_state` | array | State events matching the subscription's `required_state`. |
| `timeline` | array | **MSC4186: a plain `[Event]` array**, not the `/v3/sync` `{events, limited, prev_batch}` object. |
| `invite_state` | array | For invited rooms, the stripped state events. |

#### List operations (`ops` array)

| Op | Description |
| --- | --- |
| `SYNC` | Replace the room list window with the supplied room IDs. |
| `INSERT` | Insert a room ID at the supplied index. |
| `DELETE` | Remove the room ID at the supplied index. |
| `UPDATE` | Move a room ID from one index to another. |
