// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/rooms/room_version_policy.hpp"

#include <array>
#include <vector>

namespace merovingian::rooms
{
namespace
{

    // Designated initializers (declaration order); an omitted flag takes its
    // default, which is false for all but event_id_url_safe_base64.
    //   create_event_is_room_id, privilege_room_creators: v12 (MSC4291, MSC4289).
    //   power_levels_require_integers: v10+ (rooms/v10.md, "Values in
    //     m.room.power_levels events must be integers").
    //   Join rules: knock v7+, restricted v8+, knock_restricted v10+.
    //   redaction_keeps_aliases: v1-v5 (rooms/v6.md removed m.room.aliases
    //     from the redaction algorithm).
    //   redaction_keeps_join_authorisation: v9+ (rooms/v9.md).
    //   event_id_url_safe_base64: v4+ (rooms/v3.md uses standard Unpadded Base64).
    //   ignores_key_validity: v3-v4 (server-server-api.md, valid_until_ts "MUST be
    //     ignored in room versions 1, 2, 3, and 4"; rooms/v5.md enforces it).
    //
    // Room versions 1 and 2 are deliberately absent: they are not supported
    // (ADR-0076). Their event ID is carried in the event ($localpart:domain)
    // and needs a signature from the event ID's domain, v1 has its own state
    // resolution algorithm, and none of that was ever implemented. An absent
    // version is refused on every path (createRoom, joins, invites, PDUs).
    constexpr auto policies = std::array{
        RoomVersionPolicy{.id = "3",
                          .redaction_rules = RedactionRules::room_v1_v7,
                          .auth_rules = AuthRules::room_v1,
                          .stable = true,
                          .redaction_keeps_aliases = true,
                          .ignores_key_validity = true,
                          .event_id_url_safe_base64 = false},
        RoomVersionPolicy{.id = "4",
                          .redaction_rules = RedactionRules::room_v1_v7,
                          .auth_rules = AuthRules::room_v1,
                          .stable = true,
                          .redaction_keeps_aliases = true,
                          .ignores_key_validity = true},
        RoomVersionPolicy{.id = "5",
                          .redaction_rules = RedactionRules::room_v1_v7,
                          .auth_rules = AuthRules::room_v1,
                          .stable = true,
                          .redaction_keeps_aliases = true},
        RoomVersionPolicy{.id = "6", .redaction_rules = RedactionRules::room_v1_v7, .stable = true},
        RoomVersionPolicy{
                          .id = "7", .redaction_rules = RedactionRules::room_v1_v7, .stable = true, .knock_join_rule = true},
        // Room v8 introduced restricted joins (MSC3083): the allow field in
        // m.room.join_rules content is now preserved through redaction.
        RoomVersionPolicy{.id = "8",
                          .redaction_rules = RedactionRules::room_v8_v10,
                          .stable = true,
                          .knock_join_rule = true,
                          .restricted_join_rule = true},
        RoomVersionPolicy{.id = "9",
                          .redaction_rules = RedactionRules::room_v8_v10,
                          .stable = true,
                          .knock_join_rule = true,
                          .restricted_join_rule = true,
                          .redaction_keeps_join_authorisation = true},
        RoomVersionPolicy{.id = "10",
                          .redaction_rules = RedactionRules::room_v8_v10,
                          .stable = true,
                          .power_levels_require_integers = true,
                          .knock_join_rule = true,
                          .restricted_join_rule = true,
                          .knock_restricted_join_rule = true,
                          .redaction_keeps_join_authorisation = true},
        RoomVersionPolicy{.id = "11",
                          .redaction_rules = RedactionRules::room_v11_plus,
                          .stable = true,
                          .power_levels_require_integers = true,
                          .knock_join_rule = true,
                          .restricted_join_rule = true,
                          .knock_restricted_join_rule = true,
                          .redaction_keeps_join_authorisation = true},
        RoomVersionPolicy{.id = "12",
                          .redaction_rules = RedactionRules::room_v11_plus,
                          .auth_rules = AuthRules::room_v12,
                          .state_resolution = StateResolutionAlgorithm::v2_1,
                          .stable = true,
                          .create_event_is_room_id = true,
                          .privilege_room_creators = true,
                          .power_levels_require_integers = true,
                          .knock_join_rule = true,
                          .restricted_join_rule = true,
                          .knock_restricted_join_rule = true,
                          .redaction_keeps_join_authorisation = true},
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
