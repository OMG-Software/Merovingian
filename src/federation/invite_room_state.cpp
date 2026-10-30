// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/invite_room_state.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/event.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/limits.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::federation
{
namespace
{

    [[nodiscard]] auto refuse(std::string reason) -> FederationDecision
    {
        return {false, 400U, std::move(reason)};
    }

    [[nodiscard]] auto find_member(canonicaljson::Object const& object, std::string_view key) noexcept
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

    template <typename T>
    [[nodiscard]] auto member_as(canonicaljson::Object const& object, std::string_view key) noexcept -> T const*
    {
        auto const* value = find_member(object, key);
        return value == nullptr ? nullptr : std::get_if<T>(&value->storage());
    }

    // A PDU of a version whose events carry no event_id: every field the version
    // requires is present with the right JSON type. A stripped event (type,
    // state_key, content, sender only) is not one.
    [[nodiscard]] auto formatted_as_pdu(canonicaljson::Object const& event, bool create_event_is_room_id) -> bool
    {
        auto const* type = member_as<std::string>(event, "type");
        if (type == nullptr || member_as<std::string>(event, "sender") == nullptr ||
            member_as<std::string>(event, "state_key") == nullptr ||
            member_as<canonicaljson::Object>(event, "content") == nullptr ||
            member_as<std::int64_t>(event, "origin_server_ts") == nullptr ||
            member_as<std::int64_t>(event, "depth") == nullptr ||
            member_as<canonicaljson::Array>(event, "prev_events") == nullptr ||
            member_as<canonicaljson::Array>(event, "auth_events") == nullptr)
        {
            return false;
        }
        auto const* hashes = member_as<canonicaljson::Object>(event, "hashes");
        auto const* signatures = member_as<canonicaljson::Object>(event, "signatures");
        if (hashes == nullptr || member_as<std::string>(*hashes, "sha256") == nullptr || signatures == nullptr ||
            signatures->empty())
        {
            return false;
        }
        // Room versions 3 and later identify an event by its reference hash, so
        // the event itself never carries an event_id.
        if (find_member(event, "event_id") != nullptr)
        {
            return false;
        }
        auto const has_room_id = find_member(event, "room_id") != nullptr;
        if (create_event_is_room_id && *type == "m.room.create")
        {
            // rooms/v12.md: the create event "does not have a room_id".
            return !has_room_id;
        }
        return member_as<std::string>(event, "room_id") != nullptr;
    }

} // namespace

auto validate_invite_room_state(std::string_view room_id, std::string_view room_version,
                                std::vector<std::string> const& invite_room_state_json,
                                std::optional<FederationKeyRecord> const& known_key,
                                SignatureKeyResolver const& resolve_key) -> FederationDecision
{
    auto const* policy = rooms::find_room_version_policy(room_version);
    if (policy == nullptr)
    {
        return {false, 500U, "room version policy is unavailable"};
    }
    // Versions 1 through 11: the spec says servers MAY validate, and servers
    // still migrating send stripped entries. Accept what arrives.
    if (!policy->create_event_is_room_id)
    {
        return {true, 200U, {}};
    }
    if (invite_room_state_json.size() > max_invite_room_state_entries)
    {
        return refuse("invite_room_state has more entries than a room's stripped state can");
    }

    auto create_seen = false;
    for (auto const& entry_json : invite_room_state_json)
    {
        if (entry_json.size() > events::max_event_size_bytes)
        {
            return refuse("invite_room_state entry exceeds the event size limit");
        }
        auto const parsed = canonicaljson::parse_lossless(entry_json);
        auto const* event = parsed.error == canonicaljson::ParseError::none
                                ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                                : nullptr;
        if (event == nullptr || !formatted_as_pdu(*event, policy->create_event_is_room_id))
        {
            return refuse("invite_room_state entry is not formatted according to the room version");
        }
        auto const envelope = events::parse_event_envelope(parsed.value);
        if (!envelope.error.empty())
        {
            return refuse("invite_room_state entry is not formatted according to the room version");
        }
        auto const event_id = events::make_reference_hash_event_id(parsed.value, *policy);
        if (event_id.event_id.empty())
        {
            return refuse("invite_room_state entry is not formatted according to the room version");
        }
        auto const is_create = envelope.event.event_type == "m.room.create";
        // The create event has no room_id: its room is the one its reference
        // hash names (MSC4291).
        auto const entry_room_id = is_create ? "!" + event_id.event_id.substr(1U) : envelope.event.room_id;
        if (entry_room_id != room_id)
        {
            return refuse("invite_room_state entry is not in the room of the invite");
        }

        auto pdu = FederationPdu{};
        pdu.event_id = event_id.event_id;
        pdu.room_id = entry_room_id;
        pdu.event_type = envelope.event.event_type;
        pdu.sender = envelope.event.sender;
        pdu.signatures = envelope.event.signatures;
        pdu.json = entry_json;
        pdu.room_version = std::string{room_version};
        auto const decision = authorize_federation_pdu_sender(pdu, known_key, resolve_key);
        if (!decision.accepted)
        {
            if (decision.status == 503U)
            {
                return decision;
            }
            return refuse("invite_room_state entry failed signature verification: " + decision.reason);
        }
        if (is_create && envelope.event.state_key.empty())
        {
            create_seen = true;
        }
    }
    if (!create_seen)
    {
        return refuse("invite_room_state does not contain the m.room.create event");
    }
    return {true, 200U, {}};
}

} // namespace merovingian::federation
