// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/ThirdPartyInviteExchange.hpp"

#include <optional>
#include <string>

namespace merovingian::federation
{

struct ThirdPartyInviteExchangeParse final
{
    std::optional<ThirdPartyInviteExchange> exchange{};
    std::string reason{};
};

} // namespace merovingian::federation
