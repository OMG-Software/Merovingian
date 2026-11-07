// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/OperationResult.hpp"

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

// Result of minting an OpenID token via `POST
// /_matrix/client/v3/user/{userId}/openid/request_token` (Matrix v1.19 CS
// API §OpenID). Kept separate from OperationResult because the spec's 200
// response has three required fields beyond the token itself.
struct OpenidTokenIssueResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string access_token{};
    std::string matrix_server_name{};
    std::uint64_t expires_in_seconds{0U};
    std::string reason{};
};

} // namespace merovingian::homeserver
