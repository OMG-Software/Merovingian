// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/InvitePermission.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"

#include <string>
#include <variant>

namespace merovingian::homeserver
{

auto invite_permission_blocks(database::PersistentStore const& store, std::string_view user_id) -> bool
{
    auto const content =
        database::find_account_data_content(store, user_id, std::string_view{}, "m.invite_permission_config");
    if (!content.has_value())
    {
        return false;
    }
    auto const parsed = canonicaljson::parse_lossless(*content);
    auto const* object = parsed.error == canonicaljson::ParseError::none
                             ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                             : nullptr;
    if (object == nullptr)
    {
        return false;
    }
    for (auto const& member : *object)
    {
        if (member.key == "default_action")
        {
            auto const* action = member.value == nullptr ? nullptr : std::get_if<std::string>(&member.value->storage());
            return action != nullptr && *action == "block";
        }
    }
    return false;
}

} // namespace merovingian::homeserver
