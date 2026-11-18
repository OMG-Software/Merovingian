// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string_view>

namespace merovingian::homeserver
{

// How a route answers a use of the legacy authentication API while `server.oauth.legacy_api_enabled` is false
// (`legacy_auth_refusal`, ADR-0801). Fixed text: every field names a literal.
struct LegacyAuthRefusal final
{
    std::uint16_t status{404U};
    std::string_view errcode{"M_UNRECOGNIZED"};
    std::string_view reason{"route not found"};
};

} // namespace merovingian::homeserver
