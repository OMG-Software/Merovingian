// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/event_table.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_outbound_proxy.hpp"
#include "merovingian/homeserver/runtime_mutex.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// Asking other servers for `GET /_matrix/client/v1/rooms/{roomId}/timestamp_to_event` (ADR-0299).
//
// Client-Server API: "If the server does not have all of the room history and does not have an event
// suitably close to the requested timestamp, it can use the corresponding federation endpoint to ask
// other servers for a suitable event." Server-Server API: "The heuristics for deciding when to ask
// another homeserver for a closer event ... are left up to the homeserver implementation"; "A good
// heuristic for which servers to try first is to sort by servers that have been in the room the
// longest"; the answer is used only if its `origin_server_ts` is closer than the local one, and the
// event is then fetched with `/event/{event_id}` so it is available to the client.

// The most servers one request asks.
inline constexpr std::size_t max_timestamp_to_event_servers{3U};

struct RemoteTimestampEvent final
{
    std::string event_id{};
    std::int64_t origin_server_ts{0};
};

// The servers to ask, best first: servers other than `our_server` with a joined member in `room_id`
// (the memberships table is the room's current joins), ordered by the stream ordering of the
// earliest join membership any of their users currently holds, then by name; at most
// `max_timestamp_to_event_servers`. The stream ordering of a current join is the approximation of
// "in the room the longest" (ADR-0299). Reads the store only.
[[nodiscard]] auto timestamp_to_event_candidate_servers(database::PersistentStore const& store,
                                                        std::string_view room_id, std::string_view our_server)
    -> std::vector<std::string>;

// The `event_id` and `origin_server_ts` of a federation `timestamp_to_event` answer, or nullopt when
// `body` is not a JSON object with a `$`-prefixed string `event_id` of at most 255 bytes and an
// integer `origin_server_ts`. A remote answer is untrusted: nothing else is read.
[[nodiscard]] auto parse_timestamp_to_event_answer(std::string_view body) -> std::optional<RemoteTimestampEvent>;

// Whether an event stamped `candidate` is a better answer for (`ts`, `direction`) than `current`, the
// local answer's timestamp (nullopt: there is none). It must lie on the requested side of `ts`,
// inclusively (forwards `candidate >= ts`, backwards `candidate <= ts`), and be strictly nearer to
// `ts` than `current`.
[[nodiscard]] auto timestamp_is_closer(std::int64_t candidate, std::optional<std::int64_t> current, std::int64_t ts,
                                       database::TimeDirection direction) noexcept -> bool;

// Asks `servers` in order, one at a time, for the event nearest `ts` in `direction` in `room_id`,
// until one names an event closer than `local_ts` (`timestamp_is_closer`) that this server then
// fetches with `GET /event/{eventId}` and stores through the verified backfill path (signature
// checked, never stored unverified). Returns the ID of that event, or nullopt when no server did.
//
// Call with `runtime.mutex` held through `guard`: it is released around each network exchange
// (RuntimeLockRelease) and held again on return. Every exchange draws from `deadline`. The caller
// holds an ADR-0079 slot (`admit_client_outbound_proxy`). Each stored event is offered to `usable`, with
// the lock held, before it is returned: the caller judges there what the remote server cannot vouch for
// (its status, whether the user may see it, its own stored timestamp). One it refuses does not end the
// search: the next server is asked.
[[nodiscard]] auto acquire_closer_timestamp_event(HomeserverRuntime& runtime, std::unique_lock<RuntimeMutex>& guard,
                                                  std::string_view room_id, std::vector<std::string> const& servers,
                                                  std::int64_t ts, database::TimeDirection direction,
                                                  std::optional<std::int64_t> local_ts,
                                                  OutboundDeadline const& deadline,
                                                  std::function<bool(std::string_view event_id)> const& usable)
    -> std::optional<std::string>;

} // namespace merovingian::homeserver
