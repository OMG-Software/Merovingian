// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// The LiveKit names MSC4195 derives, so the SFU never sees a Matrix ID or room ID (ADR-0829). Each is the unpadded
// standard base64 of the SHA-256 of the canonical JSON array of two strings: 43 characters of `A-Za-z0-9+/`.

// The slot ID released Element Call versions send on the unstable path, and the one MSC4195 names. lk-jwt-service
// hashes the first as the second, so a call between old and new clients lands in one LiveKit room; this server does
// the same, for that one value only.
inline constexpr auto legacy_call_slot_id = std::string_view{"m.call#ROOM"};
inline constexpr auto call_slot_id = std::string_view{"m.call#room"};

// The LiveKit room for `slot_id` in `room_id`: hash of `[room_id, slot_id]`, with `legacy_call_slot_id` read as
// `call_slot_id`. nullopt when either string is not valid for JSON or hashing fails.
[[nodiscard]] auto livekit_room_name(std::string_view room_id, std::string_view slot_id) -> std::optional<std::string>;

// The LiveKit participant identity of member `member_id` of `user_id`: hash of `[user_id, member_id]`. nullopt as
// above.
[[nodiscard]] auto livekit_participant_identity(std::string_view user_id, std::string_view member_id)
    -> std::optional<std::string>;

} // namespace merovingian::homeserver
