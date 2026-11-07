// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/Header.hpp"             // split-shim
#include "merovingian/http/HttpVersion.hpp"        // split-shim
#include "merovingian/http/RequestErrorCode.hpp"   // split-shim
#include "merovingian/http/RequestHead.hpp"        // split-shim
#include "merovingian/http/RequestParseResult.hpp" // split-shim
#include "merovingian/http/request_limits.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::http
{

[[nodiscard]] auto request_error_name(RequestErrorCode code) noexcept -> char const*;
[[nodiscard]] auto request_error_status(RequestErrorCode code) noexcept -> std::uint16_t;
[[nodiscard]] auto header_name_is_valid(std::string_view name) noexcept -> bool;
[[nodiscard]] auto header_value_is_valid(std::string_view value) noexcept -> bool;
[[nodiscard]] auto parse_request_head(std::string_view input, RequestLimits const& limits = {}) -> RequestParseResult;

} // namespace merovingian::http
