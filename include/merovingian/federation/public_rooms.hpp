// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/canonicaljson/value.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

// Spec: GET and POST /_matrix/federation/v1/publicRooms (Server-Server API, "Published Room Directory"),
// and the same `filter` on POST /_matrix/client/v3/publicRooms.
// ../../../docs/matrix-v1.19-spec/server-server-api.md#published-room-directory
//
// What a request for a directory listing asks for, read from what another server sent. Everything here
// refuses: a wrong type or an unusable paging value is a 400, never answered as if it had not been sent
// (ADR-0460). The listing itself is homeserver/public_rooms.hpp.
namespace merovingian::federation
{

struct PublicRoomsFilter final
{
    std::string generic_search_term{};
    // Not specified: every room, whatever its type. Specified: only rooms of a listed type, with an entry
    // holding no value standing for the spec's `null`, "rooms without a room type". An empty list searches
    // for no type, so it lists nothing.
    std::optional<std::vector<std::optional<std::string>>> room_types{};
};

struct PublicRoomsRequest final
{
    PublicRoomsFilter filter{};
    // Absent: the request set no limit (or `limit=0`, the spec's "no limit"). The server still pages.
    std::optional<std::size_t> limit{};
    std::size_t since_offset{0U};
    bool include_all_networks{false};
    std::string third_party_instance_id{};
};

// A refused request: always 400, with this standard error.
struct PublicRoomsRefusal final
{
    std::string errcode{};
    std::string message{};
};

// What was read, or why not. Not std::expected, which this project's toolchain does not build.
using PublicRoomsFilterResult = std::variant<PublicRoomsFilter, PublicRoomsRefusal>;
using PublicRoomsRequestResult = std::variant<PublicRoomsRequest, PublicRoomsRefusal>;

// Reads a request's `filter` member. Shared with the client-server POST /publicRooms.
[[nodiscard]] auto parse_public_rooms_filter(canonicaljson::Value const& filter) -> PublicRoomsFilterResult;

// The `filter` as a request body holds it. Shared with the client-server `?server=` proxy.
[[nodiscard]] auto public_rooms_filter_value(PublicRoomsFilter const& filter) -> canonicaljson::Value;

// A POST body. An empty body is a request with no fields set, because no field is required.
[[nodiscard]] auto parse_public_rooms_body(std::string_view body) -> PublicRoomsRequestResult;

// A GET's percent-decoded query parameters. An empty value means the parameter was not sent.
[[nodiscard]] auto parse_public_rooms_query(std::string_view limit, std::string_view since,
                                            std::string_view include_all_networks,
                                            std::string_view third_party_instance_id) -> PublicRoomsRequestResult;

// The request as a POST body that parse_public_rooms_body reads back to an equal request. A worker relays
// it to main in this form, so main applies the same checks to a frame it does not trust (ADR-0071).
[[nodiscard]] auto serialize_public_rooms_request(PublicRoomsRequest const& request) -> std::string;

} // namespace merovingian::federation
