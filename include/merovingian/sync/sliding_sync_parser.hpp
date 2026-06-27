// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/sliding_sync.hpp"
#include "merovingian/sync/stream_token.hpp"

#include <cstdint>
#include <optional>
#include <string_view>

namespace merovingian::sync
{

// Parse the JSON POST body of a sliding sync request.
// Returns nullopt when the body is malformed JSON or not a JSON object.
// Returns nullopt when any list contains overlapping ranges.
// Unknown top-level keys are silently ignored per MSC4186 extensibility rules.
[[nodiscard]] auto parse_sliding_sync_request(std::string_view body) -> std::optional<SlidingSyncRequest>;

// Extract and decode the ?pos= query parameter from a request target.
// Returns nullopt when pos is absent or cannot be decoded as a StreamToken.
[[nodiscard]] auto parse_sliding_sync_pos(std::string_view target) -> std::optional<StreamToken>;

// Extract ?timeout= from a request target. Returns nullopt when absent or
// not a non-negative integer.
[[nodiscard]] auto parse_sliding_sync_timeout(std::string_view target) -> std::optional<std::uint64_t>;

// True when the ranges in a single list are non-overlapping and in ascending
// order (i.e. ranges[i].end < ranges[i+1].start for all i).
[[nodiscard]] auto sliding_sync_ranges_valid(std::vector<SlidingSyncRange> const& ranges) noexcept -> bool;

} // namespace merovingian::sync
