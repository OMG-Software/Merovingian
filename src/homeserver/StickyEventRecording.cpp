// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/StickyEventRecording.hpp"

#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/database/PersistentStickyEvent.hpp"
#include "merovingian/database/StickyEventRecordOutcome.hpp"
#include "merovingian/database/StickyEventStore.hpp"
#include "merovingian/events/StickyEvent.hpp"

#include <string>
#include <utility>
#include <variant>

namespace merovingian::homeserver
{

namespace
{

    [[nodiscard]] auto member_of(canonicaljson::Object const& object, std::string_view key)
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

auto record_sticky_event_of_pdu(database::PersistentStore& store, std::string_view pdu_json, std::string_view event_id,
                                std::int64_t received_at_ms, database::StickyEventCaps caps, std::int64_t now_ms)
    -> database::StickyEventRecordOutcome
{
    auto const parsed = canonicaljson::parse_lossless(pdu_json);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return database::StickyEventRecordOutcome{true, {}};
    }
    auto const duration = events::sticky_duration_of(parsed.value);
    if (!duration.has_value())
    {
        return database::StickyEventRecordOutcome{true, {}};
    }
    auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (object == nullptr)
    {
        return database::StickyEventRecordOutcome{true, {}};
    }
    auto const* room_id = member_of(*object, "room_id");
    auto const* sender = member_of(*object, "sender");
    auto const* ts = member_of(*object, "origin_server_ts");
    if (room_id == nullptr || sender == nullptr || ts == nullptr)
    {
        return database::StickyEventRecordOutcome{true, {}};
    }
    auto const* room_text = std::get_if<std::string>(&room_id->storage());
    auto const* sender_text = std::get_if<std::string>(&sender->storage());
    auto const* origin_ts = std::get_if<std::int64_t>(&ts->storage());
    if (room_text == nullptr || sender_text == nullptr || origin_ts == nullptr)
    {
        return database::StickyEventRecordOutcome{true, {}};
    }
    auto row = database::PersistentStickyEvent{};
    row.event_id = std::string{event_id};
    row.room_id = *room_text;
    row.sender = *sender_text;
    row.received_at_ms = received_at_ms;
    row.expires_at_ms = events::sticky_expiry_ms(*origin_ts, received_at_ms, *duration);
    return database::record_sticky_event(store, std::move(row), caps, now_ms);
}

} // namespace merovingian::homeserver
