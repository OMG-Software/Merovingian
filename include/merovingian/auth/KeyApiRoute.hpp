// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/auth/KeyApiEndpoint.hpp"
#include "merovingian/http/RateLimitPolicy.hpp"

#include <string>

namespace merovingian::auth
{

struct KeyApiRoute final
{
    std::string method{};
    std::string path_template{};
    KeyApiEndpoint endpoint{KeyApiEndpoint::upload_keys};
    bool requires_access_token{true};
    bool stores_server_blind_payload{true};
    http::RateLimitPolicy rate_limit{};
};

} // namespace merovingian::auth
