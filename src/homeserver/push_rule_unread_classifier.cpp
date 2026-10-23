// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/push_rule_unread_classifier.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/homeserver/stored_push_rules.hpp"
#include "merovingian/homeserver/stored_room_version.hpp"

#include <algorithm>
#include <unordered_map>
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

auto member_transition(database::PersistentEvent const& event, std::string_view room_id, std::string_view user)
    -> std::optional<std::pair<std::uint64_t, bool>>
{
    // Only accepted membership changes moved the user: a rejected or soft-failed leave did not.
    if (event.room_id != room_id || event.status != "accepted" ||
        event.json.find("m.room.member") == std::string::npos || event.json.find(user) == std::string::npos)
    {
        return std::nullopt;
    }
    auto const parsed = canonicaljson::parse_lossless(event.json);
    auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    auto const* type = root == nullptr ? nullptr : string_field(*root, "type");
    auto const* state_key = root == nullptr ? nullptr : string_field(*root, "state_key");
    if (parsed.error != canonicaljson::ParseError::none || type == nullptr || *type != "m.room.member" ||
        state_key == nullptr || *state_key != user)
    {
        return std::nullopt;
    }
    auto const* content = object_field(*root, "content");
    auto const* membership = content == nullptr ? nullptr : string_field(*content, "membership");
    return std::pair{event.stream_ordering, membership != nullptr && *membership == "join"};
}

auto current_join_start(database::PersistentStore const& store, std::string_view room_id, std::string_view user)
    -> std::optional<std::uint64_t>
{
    auto transitions = std::vector<std::pair<std::uint64_t, bool>>{};
    for (auto const& event : store.events)
    {
        if (auto transition = member_transition(event, room_id, user); transition.has_value())
        {
            transitions.push_back(*transition);
        }
    }
    return join_start_from(std::move(transitions));
}

auto join_start_from(std::vector<std::pair<std::uint64_t, bool>> transitions) -> std::optional<std::uint64_t>
{
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
    , owned_visibility_{std::in_place, store, user}
    , visibility_{*owned_visibility_}
{
}

PushRuleUnreadClassifier::PushRuleUnreadClassifier(database::PersistentStore const& store, std::string_view user,
                                                   std::size_t max_user_rules, sync::HistoryVisibility& visibility)
    : store_{store}
    , user_{user}
    , ruleset_{load_push_ruleset(store, user, max_user_rules)}
    , owned_visibility_{}
    , visibility_{visibility}
{
}

auto PushRuleUnreadClassifier::visible(database::PersistentEvent const& event) const -> bool
{
    return visibility_.get().can_see(event);
}

PushRuleUnreadClassifier::PushRuleUnreadClassifier(database::PersistentStore const& store, std::string_view user,
                                                   push::PushRuleset ruleset)
    : store_{store}
    , user_{user}
    , ruleset_{std::move(ruleset)}
    , owned_visibility_{std::in_place, store, user}
    , visibility_{*owned_visibility_}
{
}

auto PushRuleUnreadClassifier::counted_after(std::string_view room_id) const -> std::optional<std::uint64_t>
{
    if (auto const cached = join_starts_.find(room_id); cached != join_starts_.end())
    {
        return cached->second;
    }
    ensure_join_transitions();
    auto const transitions = join_transitions_.find(room_id);
    auto start = transitions == join_transitions_.end() ? std::nullopt : join_start_from(transitions->second);
    join_starts_.emplace(std::string{room_id}, start);
    return start;
}

auto PushRuleUnreadClassifier::table_walks() const noexcept -> std::uint64_t
{
    return table_walks_;
}

auto PushRuleUnreadClassifier::ensure_join_transitions() const -> void
{
    if (join_transitions_built_)
    {
        return;
    }
    join_transitions_built_ = true;
    // current_join_start's transitions, for every room at once.
    for (auto const& event : store_.get().events)
    {
        if (auto transition = member_transition(event, event.room_id, user_); transition.has_value())
        {
            join_transitions_[event.room_id].push_back(*transition);
        }
    }
    ++table_walks_;
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
    ensure_room_sources();
    auto const& store = store_.get();
    auto const sources = room_sources_.find(room_id);
    if (sources == room_sources_.end())
    {
        // Not one of the user's rooms, so never counted: computed on its own, as before.
        ++table_walks_;
        auto const members = static_cast<std::uint64_t>(
            std::ranges::count_if(store.memberships, [room_id](database::PersistentMembership const& membership) {
                return membership.room_id == room_id && membership.membership == "join";
            }));
        auto facts =
            RoomFacts{push_room_facts(store, room_id, members), room_member_display_name(store, room_id, user_)};
        return rooms_.emplace(std::string{room_id}, std::move(facts)).first->second;
    }
    // The same reads push_room_facts and room_member_display_name make, through the event index.
    auto& visibility = visibility_.get();
    auto const event_value = [&visibility](std::optional<std::string> const& event_id) -> canonicaljson::Value {
        auto const* event = event_id.has_value() ? visibility.find_event(*event_id) : nullptr;
        if (event == nullptr)
        {
            return canonicaljson::Value{};
        }
        auto parsed = canonicaljson::parse_lossless(event->json);
        return parsed.error == canonicaljson::ParseError::none ? std::move(parsed.value) : canonicaljson::Value{};
    };
    auto version = std::optional<std::string>{};
    if (sources->second.create_event_id.has_value())
    {
        auto const* create = visibility.find_event(*sources->second.create_event_id);
        version = create == nullptr ? std::string{"1"} : stored_create_room_version(create->json);
    }
    auto facts =
        RoomFacts{push_room_facts_from(event_value(sources->second.power_levels_event_id), version,
                                       sources->second.joined_members),
                  member_display_name_from(event_value(sources->second.member_event_id), profile_display_name_)};
    return rooms_.emplace(std::string{room_id}, std::move(facts)).first->second;
}

auto PushRuleUnreadClassifier::ensure_room_sources() const -> void
{
    if (room_sources_built_)
    {
        return;
    }
    room_sources_built_ = true;
    auto const& store = store_.get();

    // The user's rooms, and every room's joined members.
    auto joined = std::unordered_map<std::string_view, std::uint64_t>{};
    for (auto const& membership : store.memberships)
    {
        if (membership.user_id == user_)
        {
            room_sources_.try_emplace(membership.room_id);
        }
        if (membership.membership == "join")
        {
            ++joined[membership.room_id];
        }
    }
    ++table_walks_;
    for (auto& [room_id, sources] : room_sources_)
    {
        if (auto const count = joined.find(room_id); count != joined.end())
        {
            sources.joined_members = count->second;
        }
    }

    // Each of those rooms' current power levels, create and the user's member event. The first row
    // of each wins, as current_state_event and stored_room_version take it.
    for (auto const& state : store.state)
    {
        auto const room = room_sources_.find(state.room_id);
        if (room == room_sources_.end())
        {
            continue;
        }
        auto const record = [&state](std::optional<std::string>& event_id) {
            if (!event_id.has_value())
            {
                event_id = state.event_id;
            }
        };
        if (state.state_key.empty() && state.event_type == "m.room.power_levels")
        {
            record(room->second.power_levels_event_id);
        }
        else if (state.state_key.empty() && state.event_type == "m.room.create")
        {
            record(room->second.create_event_id);
        }
        else if (state.state_key == user_ && state.event_type == "m.room.member")
        {
            record(room->second.member_event_id);
        }
    }
    ++table_walks_;

    auto const profile = database::find_profile(store, user_);
    profile_display_name_ = profile.has_value() ? profile->displayname : std::string{};
    ++table_walks_;
}

} // namespace merovingian::homeserver
