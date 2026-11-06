// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::http
{

// Canonical, strictly parsed URL fields for callers that must resolve or
// authorize a destination before passing it to OutboundClient. IPv6 literals
// are returned without square brackets; `url` retains those brackets and the
// original path/query after libcurl canonicalization with path normalization
// disabled.
struct ParsedOutboundUrl final
{
    std::string scheme{};
    std::string host{};
    std::uint16_t port{0U};
    std::string path{};
    std::string query{};
    std::string url{};
    bool ipv6_literal{false};
};

} // namespace merovingian::http
