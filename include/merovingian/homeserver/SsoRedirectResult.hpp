// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

// Outcome of resolving `GET /login/sso/redirect[/{idpId}]` to a concrete
// redirect target. `location` is only meaningful when `ok` is true.
struct SsoRedirectResult final
{
    bool ok{false};
    std::uint16_t status{400U};
    std::string location{};
    std::string errcode{};
    std::string reason{};
};

} // namespace merovingian::homeserver
