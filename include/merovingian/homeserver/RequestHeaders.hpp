// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LocalHttpRequest.hpp"

#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

// The value of the first header of `req` named `name`, matched case-insensitively (RFC 9110 section 5.1: field names
// are case-insensitive, and the wire spelling varies by client), or an empty view when it is missing. The view lives
// as long as `req`.
[[nodiscard]] auto request_header(LocalHttpRequest const& req, std::string_view name) noexcept -> std::string_view;

// Every value of the headers of `req` named `name`, matched as request_header matches, in request order: for a caller
// that must tell an absent header from an empty one, or refuses a header sent twice (the OAuth 2.0 pages' `Origin`,
// `Sec-Fetch-Site` and `Cookie`). The views live as long as `req`.
[[nodiscard]] auto request_header_values(LocalHttpRequest const& req, std::string_view name)
    -> std::vector<std::string_view>;

} // namespace merovingian::homeserver
