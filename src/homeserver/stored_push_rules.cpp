// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/stored_push_rules.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/homeserver/default_push_ruleset.hpp"

#include <algorithm>
#include <utility>

namespace merovingian::homeserver
{
namespace
{

    // The `global` object of the user's stored m.push_rules, or an empty object.
    [[nodiscard]] auto stored_global_ruleset(database::PersistentStore const& store, std::string_view user_id)
        -> canonicaljson::Object
    {
        auto const row = std::ranges::find_if(store.account_data, [user_id](database::PersistentAccountData const& d) {
            return d.user_id == user_id && d.room_id.empty() && d.event_type == push_rules_account_data_type;
        });
        if (row == store.account_data.end())
        {
            return {};
        }
        auto parsed = canonicaljson::parse_lossless(row->content_json);
        auto const* content = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (parsed.error != canonicaljson::ParseError::none || content == nullptr)
        {
            return {};
        }
        auto const global = std::ranges::find_if(*content, [](canonicaljson::ObjectMember const& member) {
            return member.key == "global";
        });
        if (global == content->end())
        {
            return {};
        }
        auto const* object = std::get_if<canonicaljson::Object>(&global->value->storage());
        return object == nullptr ? canonicaljson::Object{} : *object;
    }

} // namespace

auto load_user_push_rules(database::PersistentStore const& store, std::string_view user_id, std::size_t max_user_rules)
    -> push::UserPushRules
{
    return push::UserPushRules{default_push_ruleset(user_id), stored_global_ruleset(store, user_id), max_user_rules};
}

auto load_push_ruleset(database::PersistentStore const& store, std::string_view user_id, std::size_t max_user_rules)
    -> push::PushRuleset
{
    return push::parse_push_ruleset(load_user_push_rules(store, user_id, max_user_rules).ruleset());
}

auto push_rules_account_data_content(push::UserPushRules const& rules) -> std::optional<std::string>
{
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("global", canonicaljson::Value{rules.ruleset()}));
    auto serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(content)});
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return std::nullopt;
    }
    return std::move(serialized.output);
}

} // namespace merovingian::homeserver
