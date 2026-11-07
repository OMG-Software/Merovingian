// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/ThirdPartyUser.hpp"
#include "merovingian/http/OutboundError.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::appservice
{

// Outcome of a `GET /_matrix/app/v1/thirdparty/user[/{protocol}]` call.
struct AppserviceThirdPartyUsersResult final
{
    bool ok{false};
    bool disabled{false};
    std::uint16_t status{0U};
    bool found{false};
    std::vector<ThirdPartyUser> users{};
    http::OutboundError error{http::OutboundError::none};
    std::string error_detail{};
};

} // namespace merovingian::appservice
