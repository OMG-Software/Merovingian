// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/push/push_rules.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::homeserver
{

// What push-rule evaluation needs to know about a room, from its current state: the
// m.room.power_levels event (for `sender_notification_permission`), how the room's version
// encodes power levels, its `notifications` levels, and its member count (for
// `room_member_count`). Push delivery and unread counting (R15, ADR-0205) build their
// push::PushEvaluationContext from these, so both decide "does this notify" the same way.
struct PushRoomFacts final
{
    canonicaljson::Value power_levels{};
    events::PowerLevelEncoding level_encoding{events::PowerLevelEncoding::integers_or_strings};
    std::unordered_map<std::string, std::int64_t> notification_levels{};
    std::uint64_t member_count{0U};
};

// The facts for `room_id`. `member_count` is the caller's: delivery uses its in-memory roster,
// counting uses the joined memberships.
[[nodiscard]] auto push_room_facts(database::PersistentStore const& store, std::string_view room_id,
                                   std::uint64_t member_count) -> PushRoomFacts;

// The same facts from what push_room_facts reads from the store: the room's current
// m.room.power_levels event (a null Value when it has none or it cannot be read) and its stored
// version (stored_room_version: nullopt for a room with no create event). For a caller that has
// already found those events, so it does not walk the store once per room.
[[nodiscard]] auto push_room_facts_from(canonicaljson::Value power_levels,
                                        std::optional<std::string> const& room_version, std::uint64_t member_count)
    -> PushRoomFacts;

// `member`'s display name in `room_id`: the `displayname` of their current m.room.member event,
// else their profile's, else empty. Spec (contains_display_name): "the owner's display name in
// that room".
[[nodiscard]] auto room_member_display_name(database::PersistentStore const& store, std::string_view room_id,
                                            std::string_view member) -> std::string;

// room_member_display_name from what it reads: the member's current m.room.member event in the room
// (a null Value when there is none) and their profile's display name.
[[nodiscard]] auto member_display_name_from(canonicaljson::Value const& member_event,
                                            std::string_view profile_display_name) -> std::string;

// The evaluation context for `recipient` judging an event `sender` sent in the room `facts` describe.
[[nodiscard]] auto push_evaluation_context(PushRoomFacts const& facts, std::string_view recipient,
                                           std::string recipient_display_name, std::string_view sender)
    -> push::PushEvaluationContext;

} // namespace merovingian::homeserver
