// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// Migration 002 (ADR-0776): the device (`user_id`, `device_id`) is an OAuth 2.0 session of `client_id`, granted
// `scope` (`oauth_sessions`). The device's tokens are ordinary `access_tokens` and `refresh_tokens` rows; this row
// is what makes it an OAuth device. It is deleted with the device, in the same transaction.
struct PersistentOAuthSession final
{
    std::string user_id{};
    std::string device_id{};
    std::string client_id{};
    std::string scope{};
    std::uint64_t created_at_ms{0U};
};

} // namespace merovingian::database
