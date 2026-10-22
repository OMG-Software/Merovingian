// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/push_rule_unread_classifier.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/stored_push_rules.hpp"
#include "merovingian/sync/read_markers.hpp"
#include "merovingian/sync/sliding_sync_room_builder.hpp"

#include <algorithm>
#include <limits>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto string_field(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const found = std::ranges::find_if(object, [key](canonicaljson::ObjectMember const& member) {
            return member.key == key;
        });
        return found == object.end() ? nullptr : std::get_if<std::string>(&found->value->storage());
    }

    [[nodiscard]] auto object_field(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const found = std::ranges::find_if(object, [key](canonicaljson::ObjectMember const& member) {
            return member.key == key;
        });
        return found == object.end() ? nullptr : std::get_if<canonicaljson::Object>(&found->value->storage());
    }

} // namespace

auto current_join_start(database::PersistentStore const& store, std::string_view room_id, std::string_view user)
    -> std::optional<std::uint64_t>
{
    // (stream ordering, is a join) for each of the user's own m.room.member events.
    auto transitions = std::vector<std::pair<std::uint64_t, bool>>{};
    for (auto const& event : store.events)
    {
        // Only accepted membership changes moved the user: a rejected or soft-failed leave did not.
        if (event.room_id != room_id || event.status != "accepted" ||
            event.json.find("m.room.member") == std::string::npos || event.json.find(user) == std::string::npos)
        {
            continue;
        }
        auto const parsed = canonicaljson::parse_lossless(event.json);
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        auto const* type = root == nullptr ? nullptr : string_field(*root, "type");
        auto const* state_key = root == nullptr ? nullptr : string_field(*root, "state_key");
        if (parsed.error != canonicaljson::ParseError::none || type == nullptr || *type != "m.room.member" ||
            state_key == nullptr || *state_key != user)
        {
            continue;
        }
        auto const* content = object_field(*root, "content");
        auto const* membership = content == nullptr ? nullptr : string_field(*content, "membership");
        transitions.emplace_back(event.stream_ordering, membership != nullptr && *membership == "join");
    }
    std::ranges::sort(transitions);
    auto start = std::optional<std::uint64_t>{};
    for (auto const& [stream_ordering, is_join] : transitions)
    {
        if (!is_join)
        {
            start.reset();
        }
        else if (!start.has_value())
        {
            start = stream_ordering;
        }
    }
    return start;
}

PushRuleUnreadClassifier::PushRuleUnreadClassifier(database::PersistentStore const& store, std::string_view user,
                                                   std::size_t max_user_rules)
    : store_{store}
    , user_{user}
    , ruleset_{load_push_ruleset(store, user, max_user_rules)}
{
}

PushRuleUnreadClassifier::PushRuleUnreadClassifier(database::PersistentStore const& store, std::string_view user,
                                                   push::PushRuleset ruleset)
    : store_{store}
    , user_{user}
    , ruleset_{std::move(ruleset)}
{
}

auto push_badge_unread_count(HomeserverRuntime const& runtime, std::string_view user_id,
                             push::PushRuleset const& ruleset) -> std::uint32_t
{
    auto const& store = runtime.database.persistent_store;
    auto const unread = PushRuleUnreadClassifier{store, user_id, ruleset};
    auto budget = sync::UnreadScanBudget{push_badge_unread_cap, push_badge_unread_examined_cap};
    auto total = std::uint64_t{0U};
    for (auto const& membership : store.memberships)
    {
        if (membership.user_id != user_id || membership.membership != "join")
        {
            continue;
        }
        auto const read_markers = sync::read_receipt_markers(runtime, store, membership.room_id, user_id);
        total += sync::count_notifications_within(store, membership.room_id, user_id, read_markers, unread, budget);
    }
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(total, std::numeric_limits<std::uint32_t>::max()));
}

auto PushRuleUnreadClassifier::counted_after(std::string_view room_id) const -> std::optional<std::uint64_t>
{
    return room(room_id).joined_after;
}

auto PushRuleUnreadClassifier::classify(std::string_view room_id, canonicaljson::Value const& event) const
    -> sync::UnreadEventOutcome
{
    auto const* root = std::get_if<canonicaljson::Object>(&event.storage());
    auto const* sender = root == nullptr ? nullptr : string_field(*root, "sender");
    if (sender == nullptr)
    {
        return {};
    }
    auto const& facts = room(room_id);
    auto const result = push::evaluate_push_rules(
        ruleset_, event, push_evaluation_context(facts.push, user_, facts.display_name, *sender));
    return {result.notify, result.notify && result.tweak_highlight};
}

auto PushRuleUnreadClassifier::room(std::string_view room_id) const -> RoomFacts const&
{
    if (auto const cached = rooms_.find(room_id); cached != rooms_.end())
    {
        return cached->second;
    }
    auto const& store = store_.get();
    auto const members = static_cast<std::uint64_t>(
        std::ranges::count_if(store.memberships, [room_id](database::PersistentMembership const& membership) {
            return membership.room_id == room_id && membership.membership == "join";
        }));
    auto facts = RoomFacts{push_room_facts(store, room_id, members), room_member_display_name(store, room_id, user_),
                           current_join_start(store, room_id, user_)};
    return rooms_.emplace(std::string{room_id}, std::move(facts)).first->second;
}

} // namespace merovingian::homeserver
