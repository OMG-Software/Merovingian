// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

// One signed-in session of the account pages (`AccountSessionStore`, ADR-0796): whose it is and when it ends. The
// session's secret is not here: the store keeps only its hash.
struct AccountSession final
{
    // The user whose password was verified when the session began.
    std::string user_id{};
    std::uint64_t created_at_ms{0U};
    // `created_at_ms` plus the fixed lifetime; never extended.
    std::uint64_t expires_at_ms{0U};
};

} // namespace merovingian::homeserver
