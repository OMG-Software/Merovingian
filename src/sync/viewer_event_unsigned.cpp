// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/viewer_event_unsigned.hpp"

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
