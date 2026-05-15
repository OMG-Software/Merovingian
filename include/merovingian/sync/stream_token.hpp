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
};

[[nodiscard]] auto encode_stream_token(StreamToken token) -> std::string;

[[nodiscard]] auto decode_stream_token(std::string_view encoded) -> std::optional<StreamToken>;

[[nodiscard]] auto is_valid_stream_token(std::string_view encoded) noexcept -> bool;

} // namespace merovingian::sync