// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::identity
{

// Parsed identity-server base URL. The IS is configured by absolute HTTPS URL
// (e.g. "https://is.example.org" or "https://is.example.org:8448/path"); the
// host and port drive SSRF-safe address resolution and the optional `path`
// prefixes every IS API path.
struct IdentityServerUrl final
{
    std::string host{};
    std::uint16_t port{443U};
    std::string path{};
};

} // namespace merovingian::identity
