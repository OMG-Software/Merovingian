// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/send_join_answer_authorization.hpp"

#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event_id.hpp"

#include <algorithm>
#include <cstddef>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto member_of(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        auto const member = std::ranges::find_if(object, [key](canonicaljson::ObjectMember const& candidate) {
            return candidate.key == key;
        });
        return member != object.end() ? member->value.get() : nullptr;
    }

    [[nodiscard]] auto string_of(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = member_of(object, key);
        return value != nullptr ? std::get_if<std::string>(&value->storage()) : nullptr;
    }

    // One distinct event of the answer. Both arrays may carry it; two copies have one ID, and an event ID covers
    // everything the auth rules read (the redacted form).
    struct AnswerEvent final
    {
        std::reference_wrapper<canonicaljson::Value const> event;
        std::string event_id{};
        std::string type{};
        std::string sender{};
        std::optional<std::string> state_key{};
        std::vector<std::string> auth_event_ids{};
        // The events that wait for this one's verdict.
        std::vector<std::size_t> dependents{};
        std::size_t unjudged_dependencies{0U};
        bool names_failed_event{false};
        bool accepted{false};
    };

    [[nodiscard]] auto answer_event_of(canonicaljson::Value const& entry, rooms::RoomVersionPolicy const& policy)
        -> std::optional<AnswerEvent>
    {
        auto const* object = std::get_if<canonicaljson::Object>(&entry.storage());
        auto const* type = object != nullptr ? string_of(*object, "type") : nullptr;
        auto const* sender = object != nullptr ? string_of(*object, "sender") : nullptr;
        if (type == nullptr || sender == nullptr)
        {
            return std::nullopt;
        }
        auto const id = events::make_reference_hash_event_id(entry, policy);
        if (!id.error.empty() || id.event_id.empty())
        {
            return std::nullopt;
        }
        auto answer_event = AnswerEvent{std::cref(entry), id.event_id, *type, *sender};
        if (auto const* state_key = string_of(*object, "state_key"); state_key != nullptr)
        {
            answer_event.state_key = *state_key;
        }
        auto const* named = member_of(*object, "auth_events");
        auto const* named_array = named != nullptr ? std::get_if<canonicaljson::Array>(&named->storage()) : nullptr;
        if (named_array == nullptr)
        {
            return std::nullopt;
        }
        for (auto const& name : *named_array)
        {
            auto const* name_string = std::get_if<std::string>(&name.storage());
            if (name_string == nullptr)
            {
                return std::nullopt;
            }
            answer_event.auth_event_ids.push_back(*name_string);
        }
        return answer_event;
    }

    // The graph of the answer's events, judged in dependency order.
    class AnswerGraph final
    {
    public:
        AnswerGraph(rooms::RoomVersionPolicy const& policy, std::string_view room_id)
            : policy_{policy}
            , room_id_{room_id}
        {
        }

        auto add(canonicaljson::Value const& entry) -> void
        {
            auto answer_event = answer_event_of(entry, policy_);
            if (answer_event.has_value() && !positions_.contains(answer_event->event_id))
            {
                positions_.emplace(answer_event->event_id, nodes_.size());
                nodes_.push_back(std::move(*answer_event));
            }
        }

        // Every event is judged after the events it names: an iterative walk, because the depth of the graph is
        // the resident's to choose. An event that names itself through others never reaches zero and stays
        // unaccepted.
        auto judge_all() -> void
        {
            create_position_ = implicit_create_position();
            auto ready = std::vector<std::size_t>{};
            for (auto position = std::size_t{0U}; position < nodes_.size(); ++position)
            {
                wire_dependencies(position);
                if (nodes_[position].unjudged_dependencies == 0U)
                {
                    ready.push_back(position);
                }
            }
            while (!ready.empty())
            {
                auto const position = ready.back();
                ready.pop_back();
                auto& node = nodes_[position];
                node.accepted = !node.names_failed_event && is_authorized(node.event.get(), node);
                for (auto const dependent_position : node.dependents)
                {
                    auto& dependent = nodes_[dependent_position];
                    dependent.names_failed_event = dependent.names_failed_event || !node.accepted;
                    --dependent.unjudged_dependencies;
                    if (dependent.unjudged_dependencies == 0U)
                    {
                        ready.push_back(dependent_position);
                    }
                }
            }
        }

        [[nodiscard]] auto accepted(std::string_view event_id) const -> bool
        {
            auto const position = positions_.find(event_id);
            return position != positions_.end() && nodes_[position->second].accepted;
        }

        [[nodiscard]] auto accepted_create_ids() const -> std::vector<std::string>
        {
            auto ids = std::vector<std::string>{};
            for (auto const& node : nodes_)
            {
                if (node.accepted && node.type == "m.room.create" && node.state_key == std::string{})
                {
                    ids.push_back(node.event_id);
                }
            }
            return ids;
        }

        // Whether the kept events allow `join_event`, which the answer need not carry.
        [[nodiscard]] auto allows(canonicaljson::Value const& join_event) const -> bool
        {
            auto const candidate = answer_event_of(join_event, policy_);
            if (!candidate.has_value())
            {
                return false;
            }
            return std::ranges::all_of(candidate->auth_event_ids,
                                       [this](std::string const& event_id) {
                                           return accepted(event_id);
                                       }) &&
                   is_authorized(join_event, *candidate);
        }

    private:
        // Room version 12 onwards: the create event is implicit in the room ID (rooms/v12.md), so every other event
        // depends on it without naming it. Its ID is the room ID with the sigil changed.
        [[nodiscard]] auto implicit_create_position() const -> std::optional<std::size_t>
        {
            if (!policy_.create_event_is_room_id || room_id_.empty())
            {
                return std::nullopt;
            }
            auto const position = positions_.find("$" + std::string{room_id_.substr(1U)});
            return position != positions_.end() ? std::optional{position->second} : std::nullopt;
        }

        auto wire_dependencies(std::size_t const position) -> void
        {
            auto& node = nodes_[position];
            for (auto const& event_id : node.auth_event_ids)
            {
                auto const named = positions_.find(event_id);
                if (named == positions_.end())
                {
                    node.names_failed_event = true;
                    continue;
                }
                nodes_[named->second].dependents.push_back(position);
                ++node.unjudged_dependencies;
            }
            if (!policy_.create_event_is_room_id || node.type == "m.room.create")
            {
                return;
            }
            if (!create_position_.has_value())
            {
                node.names_failed_event = true;
                return;
            }
            nodes_[*create_position_].dependents.push_back(position);
            ++node.unjudged_dependencies;
        }

        [[nodiscard]] auto is_authorized(canonicaljson::Value const& event, AnswerEvent const& judged) const -> bool
        {
            auto const token = events::third_party_invite_token(event);
            auto const permitted =
                events::permitted_auth_event_keys(event, policy_, judged.type, judged.sender, judged.state_key, token);
            auto const authorising_user = events::join_authorising_user(event);
            auto const target = judged.state_key.value_or(std::string{});
            auto const slots = events::AuthEventSlots{judged.sender, target, judged.type, token, authorising_user};
            auto map = events::AuthEventMap{};
            auto const load = [this](std::string_view event_id) -> canonicaljson::Value {
                return nodes_[positions_.find(event_id)->second].event.get();
            };
            auto seen = std::vector<std::pair<std::string, std::string>>{};
            for (auto const& event_id : judged.auth_event_ids)
            {
                auto const named = positions_.find(event_id);
                if (named == positions_.end())
                {
                    return false;
                }
                auto const& auth_event = nodes_[named->second];
                if (!auth_event.state_key.has_value())
                {
                    return false; // an event with no state_key is not room state
                }
                auto key = std::pair{auth_event.type, *auth_event.state_key};
                if (std::ranges::find(seen, key) != seen.end() || std::ranges::find(permitted, key) == permitted.end())
                {
                    return false;
                }
                seen.push_back(std::move(key));
                events::fill_auth_event_slot(map, slots, auth_event.type, *auth_event.state_key, event_id, load);
            }
            if (create_position_.has_value() && judged.type != "m.room.create")
            {
                map.create = nodes_[*create_position_].event.get();
                map.create_event_id = nodes_[*create_position_].event_id;
            }
            return events::authorize_event_against_auth_events(event, policy_, map).allowed;
        }

        rooms::RoomVersionPolicy const& policy_;
        std::string_view room_id_;
        std::vector<AnswerEvent> nodes_{};
        std::map<std::string, std::size_t, std::less<>> positions_{};
        std::optional<std::size_t> create_position_{};
    };

    [[nodiscard]] auto kept_entries(canonicaljson::Array const& entries, AnswerGraph const& graph,
                                    rooms::RoomVersionPolicy const& policy) -> canonicaljson::Array
    {
        auto kept = canonicaljson::Array{};
        kept.reserve(entries.size());
        for (auto const& entry : entries)
        {
            auto const id = events::make_reference_hash_event_id(entry, policy);
            if (id.error.empty() && graph.accepted(id.event_id))
            {
                kept.push_back(entry);
            }
        }
        return kept;
    }

} // namespace

auto authorize_send_join_answer(canonicaljson::Array const& state, canonicaljson::Array const& auth_chain,
                                canonicaljson::Value const& join_event, rooms::RoomVersionPolicy const& policy,
                                std::string_view room_id) -> AuthorizedSendJoinAnswer
{
    auto graph = AnswerGraph{policy, room_id};
    for (auto const& entry : state)
    {
        graph.add(entry);
    }
    for (auto const& entry : auth_chain)
    {
        graph.add(entry);
    }
    graph.judge_all();

    auto answer = AuthorizedSendJoinAnswer{};
    answer.state = kept_entries(state, graph, policy);
    answer.auth_chain = kept_entries(auth_chain, graph, policy);
    answer.dropped = state.size() - answer.state.size() + auth_chain.size() - answer.auth_chain.size();

    // A room has one create event. Two that each pass the rules on their own would give later events a choice of
    // room rules, and `state` must hold the one there is: it is the room's state, and the create is part of that.
    auto const creates = graph.accepted_create_ids();
    auto const in_state = std::ranges::any_of(answer.state, [&](canonicaljson::Value const& entry) {
        auto const id = events::make_reference_hash_event_id(entry, policy);
        return id.error.empty() && !creates.empty() && id.event_id == creates.front();
    });
    if (creates.size() != 1U || !in_state)
    {
        answer.refusal = "the answer does not hold exactly one valid m.room.create in its state";
        return answer;
    }
    if (!graph.allows(join_event))
    {
        answer.refusal = "the events in the answer do not authorise the join";
    }
    return answer;
}

} // namespace merovingian::homeserver
