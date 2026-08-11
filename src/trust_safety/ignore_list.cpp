// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/trust_safety/ignore_list.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"

#include <algorithm>
#include <variant>

namespace merovingian::trust_safety
{
namespace
{

    [[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

} // namespace

auto parse_ignored_user_list(std::string_view content_json) -> std::unordered_set<std::string>
{
    auto ignored = std::unordered_set<std::string>{};
    if (content_json.empty())
    {
        return ignored;
    }
    // Account data is not signed/canonical JSON — parse_json (not
    // parse_lossless) is the parser this codebase designates for it.
    auto const parsed = canonicaljson::parse_json(content_json);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return ignored;
    }
    auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (root == nullptr)
    {
        return ignored;
    }
    auto const* ignored_users = object_member(*root, "ignored_users");
    if (ignored_users == nullptr)
    {
        return ignored;
    }
    auto const* ignored_users_object = std::get_if<canonicaljson::Object>(&ignored_users->storage());
    if (ignored_users_object == nullptr)
    {
        return ignored;
    }
    for (auto const& member : *ignored_users_object)
    {
        if (!member.key.empty())
        {
            ignored.insert(member.key);
        }
    }
    return ignored;
}

auto resolve_ignored_users(database::PersistentStore const& store, std::string_view user_id)
    -> std::unordered_set<std::string>
{
    auto const row = std::ranges::find_if(store.account_data, [&](database::PersistentAccountData const& data) {
        return data.user_id == user_id && data.room_id.empty() && data.event_type == "m.ignored_user_list";
    });
    if (row == store.account_data.end())
    {
        return {};
    }
    return parse_ignored_user_list(row->content_json);
}

auto is_delivery_suppressed(std::unordered_set<std::string> const& ignored_senders, std::string_view sender,
                            bool is_state_event, bool is_new_room_invite) noexcept -> bool
{
    if (!ignored_senders.contains(std::string{sender}))
    {
        return false;
    }
    // Spec: "Servers must not send room invites from ignored users to
    // clients." — this overrides the state-event exemption below even though
    // an invite is itself an m.room.member state event.
    if (is_new_room_invite)
    {
        return true;
    }
    // Spec: "Servers must still send state events sent by ignored users to
    // clients." — never suppressed, so room state (names, topics, membership
    // of third parties, etc.) never looks different just because the viewer
    // ignored the sender.
    if (is_state_event)
    {
        return false;
    }
    return true;
}

auto event_json_is_state_event(std::string_view event_json) -> bool
{
    auto const parsed = canonicaljson::parse_lossless(event_json);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return false;
    }
    auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (root == nullptr)
    {
        return false;
    }
    return object_member(*root, "state_key") != nullptr;
}

} // namespace merovingian::trust_safety
