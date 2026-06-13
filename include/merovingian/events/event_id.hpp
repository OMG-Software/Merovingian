// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::events
{

struct EventIdResult final
{
    std::string event_id{};
    std::string error{};
};

struct EventHashResult final
{
    std::string sha256{};
    std::string error{};
};

[[nodiscard]] auto event_id_is_valid(std::string_view event_id) noexcept -> bool;
[[nodiscard]] auto make_content_hash(canonicaljson::Value const& event) -> EventHashResult;
[[nodiscard]] auto make_reference_hash(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy)
    -> EventHashResult;
[[nodiscard]] auto make_reference_hash_event_id(canonicaljson::Value const& event,
                                                rooms::RoomVersionPolicy const& policy) -> EventIdResult;
[[nodiscard]] auto make_content_hash_id(canonicaljson::Value const& event) -> EventIdResult;

// Spec: Matrix Server-Server API v1.18 — Calculating the Content Hash for an Event
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#calculating-the-content-hash-for-an-event
//
// Returns true when the event's hashes.sha256 field matches the computed
// SHA-256 content hash. Returns false when the field is absent or incorrect.
[[nodiscard]] auto verify_pdu_content_hash(canonicaljson::Value const& event) -> bool;

} // namespace merovingian::events
