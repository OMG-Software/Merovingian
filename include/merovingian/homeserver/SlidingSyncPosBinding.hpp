// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// MSC4186: "Servers MUST reject a `pos` that was not issued to the requesting user and device". A `pos` names stream
// positions only, so two devices can be issued the same text; the server therefore sends `<pos>-<mac>`, where the MAC
// is a keyed hash over a fixed label, the user ID, the device ID and the `pos` text (ADR-0866). Checking one costs a
// single hash and a constant-time comparison, holds no state, and survives a restart. `nullopt` when `key` is empty.
[[nodiscard]] auto bind_sliding_sync_pos(std::string_view pos, std::string_view user_id, std::string_view device_id,
                                         std::span<std::uint8_t const> key) -> std::optional<std::string>;

// The `pos` text `bound` carries when it was issued to this user and device, or `nullopt` for one that has no MAC, was
// issued to another user or device, or was altered. The text returned is not yet read as a position.
[[nodiscard]] auto unbind_sliding_sync_pos(std::string_view bound, std::string_view user_id, std::string_view device_id,
                                           std::span<std::uint8_t const> key) -> std::optional<std::string_view>;

} // namespace merovingian::homeserver
