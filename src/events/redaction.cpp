// SPDX-FileCopyrightText: 2026 James Chapman
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
        return key == "event_id" || key == "type" || key == "room_id" || key == "sender" || key == "state_key" ||
               key == "content" || key == "hashes" || key == "signatures" || key == "depth" || key == "prev_events" ||
               key == "auth_events" || key == "origin_server_ts";
    }

    [[nodiscard]] auto key_is_allowed(std::string_view key, rooms::RoomVersionPolicy const& policy) noexcept -> bool
    {
        // v1–v10 (both the v1_v7 and v8_v10 buckets) preserve origin, prev_state,
        // and membership as top-level fields; v11+ removed them from the survivor set.
        if (policy.redaction_rules == rooms::RedactionRules::room_v1_v7 ||
            policy.redaction_rules == rooms::RedactionRules::room_v8_v10)
        {
            return base_key_is_allowed(key) || key == "origin" || key == "prev_state" || key == "membership";
        }

        return base_key_is_allowed(key);
    }

    [[nodiscard]] auto object_member_value(canonicaljson::Object const& object,
                                           std::string_view key) noexcept -> canonicaljson::Value const*
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

    [[nodiscard]] auto string_member(canonicaljson::Object const& object,
                                     std::string_view key) noexcept -> std::string const*
    {
        auto const* value = object_member_value(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto content_key_allowed(std::string_view event_type, std::string_view key,
                                           rooms::RoomVersionPolicy const& policy) noexcept -> bool
    {
        if (event_type == "m.room.member")
        {
            return key == "membership" || key == "join_authorised_via_users_server" ||
                   (policy.redaction_rules == rooms::RedactionRules::room_v11_plus && key == "third_party_invite");
        }
        if (event_type == "m.room.create")
        {
            return policy.redaction_rules == rooms::RedactionRules::room_v11_plus || key == "creator";
        }
        if (event_type == "m.room.join_rules")
        {
            // Spec: "join_rule" preserved in all versions.
            //       "allow" was introduced by restricted joins (MSC3083) in room v8
            //       and is preserved from v8 onwards (v8-v10 and v11+).
            // URL:  ../../docs/matrix-v1.18-spec/rooms/v10.md#redactions
            auto const allow_preserved =
                policy.redaction_rules == rooms::RedactionRules::room_v8_v10 ||
                policy.redaction_rules == rooms::RedactionRules::room_v11_plus;
            return key == "join_rule" || (allow_preserved && key == "allow");
        }
        if (event_type == "m.room.power_levels")
        {
            return key == "ban" || key == "events" || key == "events_default" || key == "kick" || key == "redact" ||
                   key == "state_default" || key == "users" || key == "users_default" ||
                   (policy.redaction_rules == rooms::RedactionRules::room_v11_plus && key == "invite");
        }
        if (event_type == "m.room.history_visibility")
        {
            return key == "history_visibility";
        }
        if (event_type == "m.room.aliases")
        {
            // Spec v1-v10: "aliases" key preserved. v11+: entire content stripped (no keys kept).
            // ../../docs/matrix-v1.18-spec/rooms/v11.md#redactions
            return policy.redaction_rules != rooms::RedactionRules::room_v11_plus && key == "aliases";
        }
        if (event_type == "m.room.third_party_invite")
        {
            // Spec (all versions): m.room.third_party_invite preserves "signed" from content.
            // URL: ../../docs/matrix-v1.18-spec/rooms/v10.md#redactions
            return key == "signed";
        }
        if (event_type == "m.room.redaction")
        {
            return policy.redaction_rules == rooms::RedactionRules::room_v11_plus && key == "redacts";
        }

        return false;
    }

    [[nodiscard]] auto redact_third_party_invite(canonicaljson::Value const& value) -> canonicaljson::Value
    {
        auto const* object = std::get_if<canonicaljson::Object>(&value.storage());
        if (object == nullptr)
        {
            return canonicaljson::Value{canonicaljson::Object{}};
        }

        auto redacted = canonicaljson::Object{};
        if (auto const* signed_value = object_member_value(*object, "signed"); signed_value != nullptr)
        {
            redacted.push_back(canonicaljson::make_member("signed", *signed_value));
        }
        return canonicaljson::Value{std::move(redacted)};
    }

    [[nodiscard]] auto redact_content(canonicaljson::Value const& content, std::string_view event_type,
                                      rooms::RoomVersionPolicy const& policy) -> canonicaljson::Value
    {
        auto const* object = std::get_if<canonicaljson::Object>(&content.storage());
        if (object == nullptr)
        {
            return canonicaljson::Value{canonicaljson::Object{}};
        }

        auto redacted = canonicaljson::Object{};
        redacted.reserve(object->size());
        for (auto const& member : *object)
        {
            if (content_key_allowed(event_type, member.key, policy))
            {
                if (member.key == "third_party_invite")
                {
                    redacted.push_back(
                        canonicaljson::make_member(member.key, redact_third_party_invite(*member.value)));
                }
                else
                {
                    redacted.push_back(canonicaljson::make_member(member.key, *member.value));
                }
            }
        }

        return canonicaljson::Value{std::move(redacted)};
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
    auto const* event_type = string_member(*object, "type");
    // MSC4291 (room v12): the m.room.create event carries no room_id — the room ID
    // is derived from the create event's reference hash. Drop a spurious room_id so
    // our reference hash and signing payload match a conformant peer's, which never
    // includes room_id in the create event's redacted form.
    auto const create_event_omits_room_id =
        policy.create_event_is_room_id && event_type != nullptr && *event_type == "m.room.create";
    for (auto const& member : *object)
    {
        if (member.key == "room_id" && create_event_omits_room_id)
        {
            continue;
        }
        if (key_is_allowed(member.key, policy))
        {
            if (member.key == "content" && event_type != nullptr)
            {
                redacted.push_back(
                    canonicaljson::make_member(member.key, redact_content(*member.value, *event_type, policy)));
            }
            else
            {
                redacted.push_back(canonicaljson::make_member(member.key, *member.value));
            }
        }
    }

    return {canonicaljson::Value{std::move(redacted)}, {}};
}

} // namespace merovingian::events
