// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/events/MemberJoinSender.hpp"

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/events/Authorization.hpp"

#include <string>
#include <string_view>
#include <variant>

namespace merovingian::events
{

namespace
{

    [[nodiscard]] auto string_member(canonicaljson::Object const& event, std::string_view key) -> std::string const*
    {
        for (auto const& member : event)
        {
            if (member.key == key)
            {
                return std::get_if<std::string>(&member.value->storage());
            }
        }
        return nullptr;
    }

} // namespace

auto join_names_another_user(canonicaljson::Value const& event) -> bool
{
    auto const* object = std::get_if<canonicaljson::Object>(&event.storage());
    if (object == nullptr)
    {
        return false;
    }
    auto const* type = string_member(*object, "type");
    auto const* sender = string_member(*object, "sender");
    auto const* state_key = string_member(*object, "state_key");
    return type != nullptr && sender != nullptr && state_key != nullptr && *type == "m.room.member" &&
           *sender != *state_key && extract_content_membership(event) == "join";
}

} // namespace merovingian::events
