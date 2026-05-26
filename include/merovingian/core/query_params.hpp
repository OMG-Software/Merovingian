// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::core
{

struct SyncRequest final
{
    std::optional<std::string> since{};
    std::optional<std::uint64_t> timeout{};
    std::optional<bool> full_state{};
    std::optional<std::string> filter{};
};

[[nodiscard]] auto parse_query_params(std::string_view target) -> SyncRequest;

[[nodiscard]] auto percent_decode(std::string_view encoded) -> std::string;

[[nodiscard]] auto percent_decode_path_component(std::string_view encoded) -> std::string;

[[nodiscard]] auto percent_encode_path_component(std::string_view decoded) -> std::string;

} // namespace merovingian::core
