// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::sync
{

struct StreamToken final
{
    std::uint64_t event_ordering{0U};
    std::uint64_t membership_ordering{0U};
    // Stream id covering the to_device, device_lists, and presence
    // surfaces. Encoded as a third underscore-separated hex component
    // appended to the token; tokens without this component decode with
    // `sync_stream_id == 0`.
    std::uint64_t sync_stream_id{0U};
    // The stream token epoch of the database that issued the token (ADR-0592): a random value drawn when a
    // database is created and again by `merovingian-server --after-restore`. The positions above mean something
    // only in that epoch. Encoded as a fourth hex component, and only when it is not zero; a token without it
    // decodes with `epoch == 0`, so an explicit zero component does not decode.
    std::uint64_t epoch{0U};
};

[[nodiscard]] auto encode_stream_token(StreamToken token) -> std::string;

[[nodiscard]] auto decode_stream_token(std::string_view encoded) -> std::optional<StreamToken>;

[[nodiscard]] auto is_valid_stream_token(std::string_view encoded) noexcept -> bool;

} // namespace merovingian::sync
