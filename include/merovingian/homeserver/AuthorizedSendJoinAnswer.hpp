// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"

#include <cstddef>
#include <string>

namespace merovingian::homeserver
{

// What is left of a resident's send_join answer once the auth rules have judged it (F-45, ADR-0369).
struct AuthorizedSendJoinAnswer final
{
    canonicaljson::Array state{};
    canonicaljson::Array auth_chain{};
    // Entries of `state` and `auth_chain` that failed, counted once per array entry.
    std::size_t dropped{0U};
    // Why the join cannot go ahead on this answer, or empty when it can.
    std::string refusal{};
};

} // namespace merovingian::homeserver
