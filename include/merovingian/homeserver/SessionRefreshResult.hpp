// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

struct SessionRefreshResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string access_token{};
    std::string refresh_token{};
    std::string user_id{};
    std::string device_id{};
    std::string reason{};
    // Matrix error code the dispatcher must render for a refusal, when the
    // generic status-to-errcode mapping would be wrong. A locked account is a
    // spec MUST of M_USER_LOCKED + soft_logout (§Account locking), which is
    // neither M_UNKNOWN_TOKEN nor M_UNKNOWN. Empty means "use the default
    // mapping".
    std::string errcode{};
    bool soft_logout{false};
};

} // namespace merovingian::homeserver
