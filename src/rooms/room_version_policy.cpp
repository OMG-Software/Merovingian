// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/rooms/room_version_policy.hpp>

#include <array>
#include <vector>

namespace merovingian::rooms
{
namespace
{

constexpr auto policies = std::array{
    RoomVersionPolicy{"10", EventFormat::room_v3_plus, RedactionRules::room_v1_v10, AuthRules::room_v6_plus, StateResolutionAlgorithm::v2, EventIdFormat::reference_hash, true},
    RoomVersionPolicy{"11", EventFormat::room_v3_plus, RedactionRules::room_v11_plus, AuthRules::room_v6_plus, StateResolutionAlgorithm::v2, EventIdFormat::reference_hash, true},
    RoomVersionPolicy{"12", EventFormat::room_v3_plus, RedactionRules::room_v11_plus, AuthRules::room_v6_plus, StateResolutionAlgorithm::v2, EventIdFormat::reference_hash, true},
};

} // namespace

auto known_room_versions() -> std::vector<RoomVersionPolicy>
{
    return {policies.begin(), policies.end()};
}

auto find_room_version_policy(std::string_view id) noexcept -> RoomVersionPolicy const*
{
    for (auto const& policy : policies)
    {
        if (policy.id == id)
        {
            return &policy;
        }
    }

    return nullptr;
}

auto room_version_is_supported(std::string_view id) noexcept -> bool
{
    return find_room_version_policy(id) != nullptr;
}

} // namespace merovingian::rooms
