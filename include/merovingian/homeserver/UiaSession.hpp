// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

// One outstanding User-Interactive Authentication challenge (spec §User-
// Interactive Authentication API). Issued when the server answers 401 with a
// flow the client must complete, and consumed when the client comes back with
// a matching `auth.session`.
//
// L-01/L-02 (security audit 2026-09): the session id used to be a compile-time
// constant shared by every client and every attempt (`merovingian-ui-auth`,
// `delete_device`, `delete_devices`). The spec treats the session id as the
// server's handle on one in-flight attempt; a constant is not a handle, and it
// tells an attacker exactly what to echo.
struct UiaSession final
{
    std::string session_id{};
    // The endpoint the challenge was issued for: a session minted for a device
    // deletion must not satisfy a registration challenge.
    std::string purpose{};
    std::uint64_t created_at_ms{0U};
};

} // namespace merovingian::homeserver
