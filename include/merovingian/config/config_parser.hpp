// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::config
{

inline constexpr auto max_config_bytes = std::size_t{1024U} * std::size_t{1024U};
inline constexpr auto max_config_line_bytes = std::size_t{4096U};

struct ConfigParseResult final
{
    Config config{};
    std::vector<ConfigValidationFinding> findings{};
};

[[nodiscard]] auto trim_ascii(std::string_view value) noexcept -> std::string_view;
[[nodiscard]] auto parse_bool_value(std::string_view value, bool& output) noexcept -> bool;
[[nodiscard]] auto parse_u32_value(std::string_view value, std::uint32_t& output) noexcept -> bool;
[[nodiscard]] auto parse_string_list(std::string_view value) -> std::vector<std::string>;
[[nodiscard]] auto parse_key_value_config(std::string_view input) -> ConfigParseResult;

} // namespace merovingian::config
