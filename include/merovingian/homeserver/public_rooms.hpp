// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/appservice/registration.hpp"
#include "merovingian/federation/public_rooms.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalDatabase.hpp"
#include "merovingian/homeserver/PublicRoomsScope.hpp" // split-shim

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

// The published room directory listing, the one implementation behind GET and POST
// /_matrix/client/v3/publicRooms and GET and POST /_matrix/federation/v1/publicRooms (ADR-0460).
namespace merovingian::homeserver
{

// One page of a listing never exceeds this many bytes, whatever `limit` says: a room's name, topic, alias
// and avatar can each reach an event's 64 KiB, and a worker must fit the answer in an IPC frame, escaped
// (at most twice the size) and again base64-encoded (kIpcMaxFrameBytes is 24 MiB). A page always holds at
// least one room, so paging always advances.
inline constexpr auto max_public_rooms_page_bytes = std::size_t{8U * 1024U * 1024U};

// The prefix of every `instance_id` minted for one protocol of one appservice (ADR-0192):
// `<registration id>:<protocol>:`, both parts percent-encoded so the colons between them are the only
// colons and a registration id or protocol containing one cannot make two pairs collide.
[[nodiscard]] auto thirdparty_instance_id_prefix(std::string_view registration_id, std::string_view protocol)
    -> std::string;

// The scope a request's network parameters name. An id that names no network of any registered
// appservice lists nothing, rather than falling back to the homeserver's own directory the requester did
// not ask for.
[[nodiscard]] auto public_rooms_scope(appservice::AppserviceRegistry const& registry, bool include_all_networks,
                                      std::string_view third_party_instance_id) -> PublicRoomsScope;

// One page of the listing, as the 200 response body of any of the four endpoints. `limit` is the most
// rooms to return and the caller has already capped it; 0 is treated as 1. The caller holds runtime.mutex.
// Offsets count the rooms the filter and scope select, in the order of `database.rooms`.
[[nodiscard]] auto public_rooms_response_json(LocalDatabase const& database,
                                              federation::PublicRoomsFilter const& filter, std::size_t limit,
                                              std::size_t since_offset, PublicRoomsScope const& scope = {},
                                              std::size_t max_page_bytes = max_public_rooms_page_bytes) -> std::string;

// The federation endpoint's answer for an authenticated request: caps `limit` at the operator's
// server.client_api.max_public_rooms_page_size, resolves the scope and lists. Takes runtime.mutex itself
// and makes no network call. Runs in main; a worker relays here (ADR-0461).
[[nodiscard]] auto serve_federation_public_rooms(HomeserverRuntime& runtime,
                                                 federation::PublicRoomsRequest const& request) -> std::string;

} // namespace merovingian::homeserver
