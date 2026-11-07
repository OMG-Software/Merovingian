// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/federation/PublicRoomsFilter.hpp"
#include "merovingian/federation/PublicRoomsRefusal.hpp"
#include "merovingian/federation/PublicRoomsRequest.hpp"

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
