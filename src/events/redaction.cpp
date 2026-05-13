// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/redaction.hpp"

#include <string_view>
#include <variant>

namespace merovingian::events
{
namespace
{

[[nodiscard]] auto base_key_is_allowed(std::string_view key) noexcept -> bool
{
    return key == "event_id" || key == "type" || key == "room_id" || key == "sender" || key == "state_key"
        || key == "content" || key == "hashes" || key == "signatures" || key == "depth" || key == "prev_events"
        || key == "auth_events" || key == "origin_server_ts";
}

[[nodiscard]] auto key_is_allowed(std::string_view key, rooms::RoomVersionPolicy const& policy) noexcept -> bool
{
    if (policy.redaction_rules == rooms::RedactionRules::room_v1_v10)
    {
        return base_key_is_allowed(key) || key == "origin" || key == "prev_state" || key == "membership";
    }

    return base_key_is_allowed(key) || key == "unsigned";
}

} // namespace

auto redact_event(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy) -> RedactionResult
{
    auto const* object = std::get_if<canonicaljson::Object>(&event.storage());
    if (object == nullptr)
    {
        return {{}, "event must be an object"};
    }

    auto redacted = canonicaljson::Object{};
    redacted.reserve(object->size());
    for (auto const& member : *object)
    {
        if (key_is_allowed(member.key, policy))
        {
            redacted.push_back(canonicaljson::make_member(member.key, *member.value));
        }
    }

    return {canonicaljson::Value{std::move(redacted)}, {}};
}

} // namespace merovingian::events
