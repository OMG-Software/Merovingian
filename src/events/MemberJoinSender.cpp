// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/events/MemberJoinSender.hpp"

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/events/Authorization.hpp"

#include <string>
#include <variant>

namespace merovingian::events
{

auto join_names_another_user(canonicaljson::Value const& event) -> bool
{
    auto const* object = std::get_if<canonicaljson::Object>(&event.storage());
    if (object == nullptr)
    {
        return false;
    }
    std::string const* type = nullptr;
    std::string const* sender = nullptr;
    std::string const* state_key = nullptr;
    for (auto const& member : *object)
    {
        auto const* text = std::get_if<std::string>(&member.value->storage());
        if (member.key == "type")
        {
            type = text;
        }
        else if (member.key == "sender")
        {
            sender = text;
        }
        else if (member.key == "state_key")
        {
            state_key = text;
        }
    }
    return type != nullptr && sender != nullptr && state_key != nullptr && *type == "m.room.member" &&
           *sender != *state_key && extract_content_membership(event) == "join";
}

} // namespace merovingian::events
