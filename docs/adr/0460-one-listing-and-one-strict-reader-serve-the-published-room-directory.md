# One listing and one strict request reader serve every published room directory endpoint

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`GET` and `POST /_matrix/federation/v1/publicRooms` ("Published Room Directory", Server-Server API) were not served: a
remote server asking for this server's directory got 404. The client-server `publicRooms` had its own listing inside
`client_server.cpp`. That listing omitted `room_type`, ignored the filter's `room_types` and never sent `prev_batch`, and it
found each room's name and topic in a state index built per request. A remote server now reaches the listing, choosing
`limit`, `since` and the filter, while `runtime.mutex` is held.

## Considered Options

* One listing (`homeserver/public_rooms.cpp`) and one reader for the request (`federation/public_rooms.cpp`), used by all
  four endpoints
* A second listing for federation, leaving the client one as it was
* Excluding rooms created with `m.federate: false` from the federation answer
* Answering an unusable `since` or `limit` as if it had not been sent, as the client `GET` does for `since`

## Decision Outcome

Chosen option: one listing and one reader, because the two answers have the same type in the spec, and two copies would
drift on exactly the fields that had already been missed. The client endpoints gain `room_type`, `room_types` and
`prev_batch` from this.

The rest of this decision is what a later reader might otherwise undo:

* **A federation request is read strictly.** A wrong type is 400 `M_BAD_JSON`, and a `since` or `limit` that is not decimal
  digits is 400 `M_INVALID_PARAM`. Answering an unusable `since` from the first page would loop a paginating server for ever,
  and hide its bug. The client `since` stays lenient, because `?server=` forwards a token a remote server issued, which need
  not be a number here.
* **`limit=0` is the spec's "no limit", and the server still pages.** The page is capped at
  `server.client_api.max_public_rooms_page_size`, with `next_batch` reaching the rest, which the spec's paging fields allow.
* **An empty `room_types` lists nothing.** The spec calls it "An optional list of room types to search for", and says "When
  not specified, all applicable rooms (regardless of type) are returned." An empty list is specified, and names no type.
* **A page is at most 8 MiB, and always holds one room** (`max_public_rooms_page_bytes`). `limit` alone does not bound it: a
  room's name, topic, alias and avatar can each be an event's 64 KiB. The answer has to fit an IPC frame once escaped and
  base64-encoded (ADR-0461). At least one room per page means paging always advances.
* **Room state is read by index, once per room in the page** (`find_current_state_event_id`, ADR-0344), and past the end of
  the page an unfiltered room costs a count. Building a state index per request made every listing cost the whole store's
  state. A listing is still linear in the published rooms, under `runtime.mutex`.
* **An empty name, alias or avatar URL is left out.** The types do not allow an empty alias or URI, and the field is optional.
  An empty topic is kept, because it is a string the room really holds.
* **`m.federate: false` rooms are listed.** The spec says the endpoint "Lists the server's published room directory" and makes
  no exception, and the client `GET` already serves the same list to anyone without authentication, so nothing would be kept
  from a remote server by leaving them out.

### Negative Consequences

* A remote server can make main walk the published rooms, up to the per-origin request cap. The spec marks the endpoint
  "Rate-limited: No", which tells a requester not to expect 429; the project keeps its per-origin cap on every non-`/send`
  endpoint regardless (`check_federation_origin_request_rate`).
* `total_room_count_estimate` is exact and costs the same walk as a page. It could be cached if directories grow large.
