// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::federation
{

// How a server's exchange of a third-party invite ended.
struct ThirdPartyInviteExchangeResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string reason{};
};

} // namespace merovingian::federation
