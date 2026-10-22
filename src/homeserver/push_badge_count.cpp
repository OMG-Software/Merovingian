// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/push_badge_count.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/homeserver/push_rule_unread_classifier.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/read_markers.hpp"

#include <algorithm>
#include <cstddef>
#include <map>
#include <optional>
#include <ranges>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    // A visited event the user's rules notify for, waiting for its room's markers and join start.
    struct Candidate final
    {
        std::uint64_t stream_ordering{0U};
        std::string thread_id{};
    };

    // What the pass learnt about one joined room.
    struct BadgeRoom final
    {
        sync::ReadMarkers markers{};
        std::vector<std::pair<std::uint64_t, bool>> transitions{};
        std::vector<Candidate> candidates{};
        // An own event whose thread could not be determined within the budget: it may cover any
        // thread, so the room counts nothing.
        bool own_thread_unknown{false};
    };

    [[nodiscard]] auto has_member(canonicaljson::Object const& object, std::string_view key) noexcept -> bool
    {
        return std::ranges::any_of(object, [key](canonicaljson::ObjectMember const& member) {
            return member.key == key;
        });
    }

} // namespace

auto count_push_badge(HomeserverRuntime const& runtime, std::string_view user_id, push::PushRuleset const& ruleset,
                      std::uint64_t row_budget) -> PushBadgeCount
{
    auto const& store = runtime.database.persistent_store;
    auto result = PushBadgeCount{};

    // Loaded once, before the pass: the joined rooms, and the read receipts read_markers_for uses
    // (m.read and m.read.private), keyed by the event each names.
    auto rooms = std::map<std::string, BadgeRoom, std::less<>>{};
    for (auto const& membership : store.memberships)
    {
        if (membership.user_id == user_id && membership.membership == "join")
        {
            rooms.try_emplace(membership.room_id);
        }
    }
    auto const& receipts = runtime.database.persistent_store.receipts;
    auto receipt_targets = std::unordered_map<std::string, std::vector<std::size_t>>{};
    for (auto index = std::size_t{0U}; index < receipts.size(); ++index)
    {
        auto const& receipt = receipts[index];
        if (receipt.user_id == user_id && rooms.contains(receipt.room_id) &&
            (receipt.receipt_type == "m.read" || receipt.receipt_type == "m.read.private"))
        {
            receipt_targets[receipt.event_id].push_back(index);
        }
    }
    auto receipt_found = std::set<std::size_t>{};

    auto const classifier = PushRuleUnreadClassifier{store, user_id, ruleset};
    auto rows_left = row_budget;
    auto all_rows_visited = true;
    // Newest row first, so a capped pass is more likely to reach recent events; nothing below
    // depends on the order (store.events is not stream-ordered, ADR-0207).
    for (auto const& row : std::views::reverse(store.events))
    {
        if (rows_left == 0U)
        {
            all_rows_visited = false;
            break;
        }
        --rows_left;
        auto const room = rooms.find(row.room_id);
        if (room == rooms.end())
        {
            continue;
        }
        auto& facts = room->second;

        // read_markers_for: a receipt's position is the stream ordering of the event it names.
        if (auto const targets = receipt_targets.find(row.event_id); targets != receipt_targets.end())
        {
            for (auto const index : targets->second)
            {
                auto const& receipt = receipts[index];
                if (receipt.room_id != row.room_id)
                {
                    continue;
                }
                receipt_found.insert(index);
                auto& position =
                    receipt.thread_id.empty() ? facts.markers.unthreaded : facts.markers.threads[receipt.thread_id];
                position = std::max(position, row.stream_ordering);
            }
        }
        // current_join_start's transitions.
        if (auto transition = member_transition(row, row.room_id, user_id); transition.has_value())
        {
            facts.transitions.push_back(*transition);
        }

        if (row.sender_user_id == user_id)
        {
            // read_markers_for: a non-state event the user sent reads its own thread (ADR-0170).
            auto thread_id = std::optional<std::string>{std::string{sync::main_thread_id}};
            if (row.json.find("\"state_key\"") != std::string::npos ||
                row.json.find("\"m.relates_to\"") != std::string::npos)
            {
                auto const parsed = canonicaljson::parse_lossless(row.json);
                auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                if (parsed.error != canonicaljson::ParseError::none || object == nullptr ||
                    has_member(*object, "state_key"))
                {
                    continue;
                }
                thread_id = sync::event_thread_id_within(store, *object, rows_left);
            }
            if (!thread_id.has_value())
            {
                facts.own_thread_unknown = true;
                all_rows_visited = false;
                continue;
            }
            auto& position = facts.markers.threads[*thread_id];
            position = std::max(position, row.stream_ordering);
            continue;
        }

        // sync::count_unread_by_thread's filters, in its order after the position checks, which
        // wait until the pass has the markers and the join start.
        if (row.status != "accepted" || !classifier.visible(row))
        {
            continue;
        }
        auto const parsed = canonicaljson::parse_lossless(row.json);
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (parsed.error != canonicaljson::ParseError::none || object == nullptr)
        {
            continue;
        }
        if (!classifier.classify(row.room_id, parsed.value).notify)
        {
            continue;
        }
        auto thread_id = sync::event_thread_id_within(store, *object, rows_left);
        if (!thread_id.has_value())
        {
            all_rows_visited = false;
            continue;
        }
        facts.candidates.push_back({row.stream_ordering, std::move(*thread_id)});
    }
    result.rows_visited = row_budget - rows_left;
    result.capped = !all_rows_visited;

    auto total = std::uint64_t{0U};
    for (auto& [room_id, facts] : rooms)
    {
        if (facts.own_thread_unknown)
        {
            continue;
        }
        // A capped pass may not have reached a receipt's event, whose position is then unknown:
        // count nothing it could cover.
        auto unreadable_room = false;
        auto unreadable_threads = std::set<std::string, std::less<>>{};
        if (result.capped)
        {
            for (auto const& [event_id, indexes] : receipt_targets)
            {
                for (auto const index : indexes)
                {
                    if (receipts[index].room_id != room_id || receipt_found.contains(index))
                    {
                        continue;
                    }
                    if (receipts[index].thread_id.empty())
                    {
                        unreadable_room = true;
                    }
                    else
                    {
                        unreadable_threads.insert(receipts[index].thread_id);
                    }
                }
            }
        }
        auto const start = join_start_from(std::move(facts.transitions));
        if (unreadable_room || !start.has_value())
        {
            continue;
        }
        for (auto const& candidate : facts.candidates)
        {
            if (candidate.stream_ordering <= facts.markers.unthreaded || candidate.stream_ordering <= *start ||
                unreadable_threads.contains(candidate.thread_id) ||
                facts.markers.covers(candidate.stream_ordering, candidate.thread_id))
            {
                continue;
            }
            ++total;
        }
    }
    result.unread = static_cast<std::uint32_t>(std::min<std::uint64_t>(total, push_badge_unread_cap));
    return result;
}

auto push_badge_unread_count(HomeserverRuntime const& runtime, std::string_view user_id,
                             push::PushRuleset const& ruleset) -> std::uint32_t
{
    return count_push_badge(runtime, user_id, ruleset).unread;
}

} // namespace merovingian::homeserver
