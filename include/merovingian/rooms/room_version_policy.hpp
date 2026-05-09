// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>
#include <vector>

namespace merovingian::rooms
{

enum class EventFormat : unsigned char
{
    room_v1_v2,
    room_v3_plus,
};

enum class RedactionRules : unsigned char
{
    room_v1_v10,
    room_v11_plus,
};

enum class AuthRules : unsigned char
{
    room_v1,
    room_v6_plus,
};

enum class StateResolutionAlgorithm : unsigned char
{
    v1,
    v2,
};

enum class EventIdFormat : unsigned char
{
    reference_hash,
};

struct RoomVersionPolicy final
{
    std::string_view id{};
    EventFormat event_format{EventFormat::room_v3_plus};
    RedactionRules redaction_rules{RedactionRules::room_v11_plus};
    AuthRules auth_rules{AuthRules::room_v6_plus};
    StateResolutionAlgorithm state_resolution{StateResolutionAlgorithm::v2};
    EventIdFormat event_id_format{EventIdFormat::reference_hash};
    bool stable{false};
};

[[nodiscard]] auto known_room_versions() -> std::vector<RoomVersionPolicy>;
[[nodiscard]] auto find_room_version_policy(std::string_view id) noexcept -> RoomVersionPolicy const*;
[[nodiscard]] auto room_version_is_supported(std::string_view id) noexcept -> bool;

} // namespace merovingian::rooms
