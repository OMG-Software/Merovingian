// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/viewer_event_unsigned.hpp"

#include "merovingian/canonicaljson/parser.hpp"

#include <algorithm>
#include <optional>
#include <string_view>
#include <utility>
#include <variant>

namespace merovingian::sync
{

namespace
{

    constexpr auto unsigned_key = std::string_view{"unsigned"};

    [[nodiscard]] auto string_field(canonicaljson::Object const& object, std::string_view key) -> std::string const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return std::get_if<std::string>(&member.value->storage());
            }
        }
        return nullptr;
    }

} // namespace

ViewerEventUnsigned::ViewerEventUnsigned(database::PersistentStore const& store, HistoryVisibility& visibility,
                                         std::string_view user_id, std::string_view device_id)
    : store_{store}
    , visibility_{visibility}
    , user_id_{user_id}
    , device_id_{device_id}
{
}

auto ViewerEventUnsigned::transaction_id_of(database::PersistentEvent const& event) const -> std::optional<std::string>
{
    if (device_id_.empty())
    {
        return std::nullopt;
    }
    auto const* record = database::find_client_txn_by_event_id(store_, event.event_id);
    if (record == nullptr || record->user_id != user_id_ || record->device_id != device_id_)
    {
        return std::nullopt;
    }
    return record->txn_id;
}

auto ViewerEventUnsigned::previous_content_of(database::PersistentEvent const& event,
                                              canonicaljson::Object const& client_event)
    -> std::optional<canonicaljson::Value>
{
    auto const* event_type = string_field(client_event, "type");
    auto const* state_key = string_field(client_event, "state_key");
    if (event_type == nullptr || state_key == nullptr)
    {
        return std::nullopt;
    }
    auto const* transition =
        database::find_state_transition(store_, event.room_id, *event_type, *state_key, event.event_id);
    if (transition == nullptr || transition->previous_event_id.empty())
    {
        return std::nullopt;
    }
    auto const previous = store_.events.find(transition->previous_event_id);
    if (previous == store_.events.end() || !visibility_.can_see(*previous))
    {
        return std::nullopt;
    }
    auto const parsed = canonicaljson::parse_lossless(previous->json);
    auto const* previous_object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (parsed.error != canonicaljson::ParseError::none || previous_object == nullptr)
    {
        return std::nullopt;
    }
    for (auto const& member : *previous_object)
    {
        if (member.key == "content" && std::holds_alternative<canonicaljson::Object>(member.value->storage()))
        {
            return *member.value;
        }
    }
    return std::nullopt;
}

auto ViewerEventUnsigned::apply(database::PersistentEvent const& event, canonicaljson::Value client_event)
    -> canonicaljson::Value
{
    auto const* object = std::get_if<canonicaljson::Object>(&client_event.storage());
    if (object == nullptr)
    {
        return client_event;
    }
    auto added = canonicaljson::Object{};
    if (auto transaction = transaction_id_of(event); transaction.has_value())
    {
        added.push_back(canonicaljson::make_member("transaction_id", canonicaljson::Value{std::move(*transaction)}));
    }
    if (auto membership = visibility_.membership_at(event); membership.has_value())
    {
        added.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::move(*membership)}));
    }
    // Client-Server API, ClientEvent `unsigned.prev_content`: "The `content` of the previous state event
    // that was replaced by this event ... only returned if the event is a state event, and the client has
    // permission to see the previous event."
    if (auto previous = previous_content_of(event, *object); previous.has_value())
    {
        added.push_back(canonicaljson::make_member("prev_content", std::move(*previous)));
    }
    if (added.empty())
    {
        return client_event;
    }

    auto result = canonicaljson::Object{};
    auto merged = canonicaljson::Object{};
    for (auto const& member : *object)
    {
        if (member.key != unsigned_key)
        {
            result.push_back(member);
            continue;
        }
        if (auto const* existing = std::get_if<canonicaljson::Object>(&member.value->storage()); existing != nullptr)
        {
            for (auto const& entry : *existing)
            {
                auto const replaced = std::ranges::any_of(added, [&entry](canonicaljson::ObjectMember const& fresh) {
                    return fresh.key == entry.key;
                });
                if (!replaced)
                {
                    merged.push_back(entry);
                }
            }
        }
    }
    for (auto& member : added)
    {
        merged.push_back(std::move(member));
    }
    result.push_back(canonicaljson::make_member(std::string{unsigned_key}, canonicaljson::Value{std::move(merged)}));
    return canonicaljson::Value{std::move(result)};
}

} // namespace merovingian::sync
