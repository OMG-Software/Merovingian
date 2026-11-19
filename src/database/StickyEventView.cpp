// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/StickyEventView.hpp"

#include "merovingian/database/PersistentStickyEvent.hpp"
#include "merovingian/events/StickyEvent.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <variant>

namespace merovingian::database
{

auto sticky_clock_now_ms(PersistentStore const& store) -> std::int64_t
{
    if (store.test_sticky_clock_ms.has_value())
    {
        return *store.test_sticky_clock_ms;
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

auto attach_sticky_remaining(PersistentStore const& store, std::string_view event_id,
                             canonicaljson::Object& client_event) -> void
{
    if (store.sticky_events.size() == 0U)
    {
        return;
    }
    auto const now_ms = sticky_clock_now_ms(store);
    auto const* row = store.sticky_events.find(event_id, now_ms);
    if (row == nullptr)
    {
        return;
    }
    auto const remaining = events::sticky_remaining_ms(row->expires_at_ms, now_ms);
    if (!remaining.has_value())
    {
        return;
    }
    auto unsigned_object = canonicaljson::Object{};
    auto* unsigned_member = static_cast<canonicaljson::ObjectMember*>(nullptr);
    for (auto& member : client_event)
    {
        if (member.key == "unsigned")
        {
            unsigned_member = &member;
            break;
        }
    }
    if (unsigned_member != nullptr)
    {
        if (auto const* current = std::get_if<canonicaljson::Object>(&unsigned_member->value->storage());
            current != nullptr)
        {
            for (auto const& member : *current)
            {
                if (member.key != events::sticky_remaining_field && member.key != events::unstable_sticky_remaining_field)
                {
                    unsigned_object.push_back(member);
                }
            }
        }
    }
    unsigned_object.push_back(
        canonicaljson::make_member(std::string{events::sticky_remaining_field}, canonicaljson::Value{*remaining}));
    unsigned_object.push_back(canonicaljson::make_member(std::string{events::unstable_sticky_remaining_field},
                                                         canonicaljson::Value{*remaining}));
    if (unsigned_member != nullptr)
    {
        unsigned_member->value = std::make_unique<canonicaljson::Value>(std::move(unsigned_object));
        return;
    }
    client_event.push_back(canonicaljson::make_member("unsigned", canonicaljson::Value{std::move(unsigned_object)}));
}

} // namespace merovingian::database
