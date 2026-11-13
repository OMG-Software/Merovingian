// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/PushRuleUnreadClassifier.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/homeserver/StoredPushRules.hpp"
#include "merovingian/homeserver/StoredRoomVersion.hpp"
#include "merovingian/push/PushRules.hpp"
#include "merovingian/sync/ReadMarkers.hpp"
#include "merovingian/trust_safety/IgnoreList.hpp"

#include <algorithm>
#include <cstddef>
#include <functional>
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

    // current_join_start's answer without a walk of the events (ADR-0617): the user's member events, from the current
    // one back through their recorded predecessors, to the last that is not a join. At most the unread budget of
    // events are read: a join older than that is older than any row a count reads.
    //
    // A room with no current member row for the user (a row store written without state) is read from its newest
    // rows instead, with the same budget.
    [[nodiscard]] auto join_start_of_member_chain(database::PersistentStore const& store, std::string_view room_id,
                                                  std::string_view user) -> std::optional<std::uint64_t>
    {
        auto current = database::find_current_state_event_id(store, room_id, "m.room.member", user);
        if (!current.has_value())
        {
            auto transitions = std::vector<std::pair<std::uint64_t, bool>>{};
            auto const rows = store.events.room_in_stream_order(room_id);
            auto examined = std::size_t{0U};
            for (auto row = rows.end(); row != rows.begin() && examined < sync::max_unread_rows_examined;)
            {
                --row;
                ++examined;
                if (auto const transition = member_transition(*row, room_id, user); transition.has_value())
                {
                    transitions.push_back(*transition);
                }
            }
            return join_start_from(std::move(transitions));
        }
        auto start = std::optional<std::uint64_t>{};
        for (auto steps = std::size_t{0U}; current.has_value() && steps < sync::max_unread_rows_examined; ++steps)
        {
            auto const event = store.events.find(*current);
            if (event == store.events.end())
            {
                break;
            }
            if (auto const transition = member_transition(*event, room_id, user); transition.has_value())
            {
                if (!transition->second)
                {
                    break;
                }
                start = transition->first;
            }
            auto const* const step = database::find_state_transition(store, room_id, "m.room.member", user, *current);
            current = step == nullptr || step->previous_event_id.empty()
                          ? std::nullopt
                          : std::optional<std::string>{step->previous_event_id};
        }
        return start;
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
    , ignored_{trust_safety::resolve_ignored_users(store, user)}
    , ruleset_{load_push_ruleset(store, user, max_user_rules)}
    , owned_visibility_{std::in_place, store, user}
    , visibility_{*owned_visibility_}
{
}

PushRuleUnreadClassifier::PushRuleUnreadClassifier(database::PersistentStore const& store, std::string_view user,
                                                   std::size_t max_user_rules, sync::HistoryVisibility& visibility)
    : store_{store}
    , user_{user}
    , ignored_{trust_safety::resolve_ignored_users(store, user)}
    , ruleset_{load_push_ruleset(store, user, max_user_rules)}
    , owned_visibility_{}
    , visibility_{visibility}
{
}

auto PushRuleUnreadClassifier::visible(database::PersistentEvent const& event) -> bool
{
    // Ignoring Users: "the client will no longer receive events sent by that user", with the
    // exception of state events. The sender is looked up first so the event JSON is parsed only
    // for an ignored sender's event, and no event costs a store scan.
    if (ignored_.contains(event.sender_user_id) &&
        trust_safety::is_delivery_suppressed(ignored_, event.sender_user_id,
                                             trust_safety::event_json_is_state_event(event.json)))
    {
        return false;
    }
    return visibility_.get().can_see(event);
}

PushRuleUnreadClassifier::PushRuleUnreadClassifier(database::PersistentStore const& store, std::string_view user,
                                                   push::PushRuleset ruleset)
    : store_{store}
    , user_{user}
    , ignored_{trust_safety::resolve_ignored_users(store, user)}
    , ruleset_{std::move(ruleset)}
    , owned_visibility_{std::in_place, store, user}
    , visibility_{*owned_visibility_}
{
}

auto PushRuleUnreadClassifier::counted_after(std::string_view room_id) -> std::optional<std::uint64_t>
{
    if (auto const cached = join_starts_.find(room_id); cached != join_starts_.end())
    {
        return cached->second;
    }
    auto start = join_start_of_member_chain(store_.get(), room_id, user_);
    join_starts_.emplace(std::string{room_id}, start);
    return start;
}

auto PushRuleUnreadClassifier::table_walks() const noexcept -> std::uint64_t
{
    return table_walks_;
}

auto PushRuleUnreadClassifier::classify(std::string_view room_id, canonicaljson::Value const& event)
    -> sync::UnreadEventOutcome
{
    auto const* root = std::get_if<canonicaljson::Object>(&event.storage());
    auto const* sender = root == nullptr ? nullptr : string_field(*root, "sender");
    if (sender == nullptr)
    {
        return {};
    }
    auto const& facts = room(room_id);
    auto const context = push_evaluation_context(facts.push, user_, facts.display_name, *sender);
    auto const result = evaluation_budget_.has_value()
                            ? push::evaluate_push_rules(ruleset_, event, context, evaluation_budget_->get())
                            : push::evaluate_push_rules(ruleset_, event, context);
    return {result.notify, result.notify && result.tweak_highlight};
}

auto PushRuleUnreadClassifier::use_evaluation_budget(push::PushEvaluationBudget& budget) noexcept -> void
{
    evaluation_budget_ = std::ref(budget);
}

auto PushRuleUnreadClassifier::evaluation_budget_exhausted() const noexcept -> bool
{
    return evaluation_budget_.has_value() && evaluation_budget_->get().exhausted;
}

auto PushRuleUnreadClassifier::room(std::string_view room_id) -> RoomFacts const&
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

auto PushRuleUnreadClassifier::ensure_room_sources() -> void
{
    if (room_sources_built_)
    {
        return;
    }
    room_sources_built_ = true;
    auto const& store = store_.get();

    // The user's rooms, from the user's own membership rows; then each of those rooms' joined members from the
    // room's own rows, and its current power levels, create and the user's member event from the state index
    // (ADR-0659). Nothing here reads a server-wide table.
    database::for_each_user_membership_row(store, user_, [this](database::PersistentMembership const& membership) {
        room_sources_.try_emplace(membership.room_id);
    });
    ++table_walks_;
    for (auto& [room_id, sources] : room_sources_)
    {
        auto joined = std::uint64_t{0U};
        database::for_each_room_membership_row(store, room_id, [&joined](database::PersistentMembership const& row) {
            if (row.membership == "join")
            {
                ++joined;
            }
        });
        sources.joined_members = joined;
        // The current event of each key: the state index holds one row per (room, type, state key), the row the old
        // scan found first.
        sources.power_levels_event_id =
            database::find_current_state_event_id(store, room_id, "m.room.power_levels", "");
        sources.create_event_id = database::find_current_state_event_id(store, room_id, "m.room.create", "");
        sources.member_event_id = database::find_current_state_event_id(store, room_id, "m.room.member", user_);
    }
    ++table_walks_;

    auto const profile = database::find_profile(store, user_);
    profile_display_name_ = profile.has_value() ? profile->displayname : std::string{};
    ++table_walks_;
}

} // namespace merovingian::homeserver
