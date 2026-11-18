// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/homeserver/OperationResult.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

struct LiveKitTokenRequest;

// Module-internal helpers shared by the MSC4195 request handlers (`LiveKitTokenService.cpp`, `LiveKitDelegations.cpp`).
// Not a public API.

// A failed OperationResult with `status`, `errcode` and `reason`.
[[nodiscard]] auto livekit_refusal(std::uint16_t status, std::string errcode, std::string reason) -> OperationResult;

// The value of `object`'s member `key`, or nullptr.
[[nodiscard]] auto livekit_member_of(canonicaljson::Object const& object, std::string_view key)
    -> canonicaljson::Value const*;

// A required string member of at most `max_bytes` bytes, at least one, valid for JSON, copied into `out`. A missing
// member is 400 `M_MISSING_PARAM`, anything else wrong 400 `M_INVALID_PARAM`; neither echoes the value.
[[nodiscard]] auto read_livekit_string(canonicaljson::Object const& object, std::string_view key, std::size_t max_bytes,
                                       std::string& out) -> std::optional<OperationResult>;

// The members every MSC4195 call request carries: `url`, `room_id` (held to the shape of a room ID; it is only ever
// looked up exactly), `slot_id` and `member_id`, each within its `max_livekit_*_bytes`. The first refusal, or nullopt.
[[nodiscard]] auto read_livekit_call_members(canonicaljson::Object const& object, LiveKitTokenRequest& request)
    -> std::optional<OperationResult>;

} // namespace merovingian::homeserver
