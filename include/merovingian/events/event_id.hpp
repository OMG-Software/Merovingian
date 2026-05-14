// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::events
{

struct EventIdResult final
{
    std::string event_id{};
    std::string error{};
};

struct EventHashResult final
{
    std::string sha256{};
    std::string error{};
};

[[nodiscard]] auto event_id_is_valid(std::string_view event_id) noexcept -> bool;
[[nodiscard]] auto make_content_hash(canonicaljson::Value const& event) -> EventHashResult;
[[nodiscard]] auto make_reference_hash(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy)
    -> EventHashResult;
[[nodiscard]] auto make_reference_hash_event_id(canonicaljson::Value const& event,
                                                rooms::RoomVersionPolicy const& policy) -> EventIdResult;
[[nodiscard]] auto make_content_hash_id(canonicaljson::Value const& event) -> EventIdResult;

} // namespace merovingian::events
