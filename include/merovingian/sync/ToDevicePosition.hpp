// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::sync
{

// The sliding sync to_device extension's `since` / `next_batch` (MSC4186): the sync stream id of the last
// to-device message delivered, which acknowledges every message at or below it, and the stream token epoch it
// was issued in (ADR-0592). Clients keep it apart from `pos`, across an `M_UNKNOWN_POS`, so it carries the epoch
// itself. Encoded as the decimal stream id, then `_` and the decimal epoch when the epoch is not zero.
struct ToDevicePosition final
{
    std::uint64_t stream_id{0U};
    std::uint64_t epoch{0U};
};

[[nodiscard]] auto encode_to_device_position(ToDevicePosition position) -> std::string;

// nullopt for anything encode_to_device_position does not produce: an empty or over-long stream id, a character
// that is not a decimal digit, a value past 2^64-1, an empty, zero or malformed epoch, or anything after it.
[[nodiscard]] auto decode_to_device_position(std::string_view encoded) -> std::optional<ToDevicePosition>;

} // namespace merovingian::sync
