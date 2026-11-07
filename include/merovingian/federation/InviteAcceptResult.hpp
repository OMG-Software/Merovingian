// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::federation
{

struct InviteAcceptResult final
{
    bool accepted{false};
    std::uint16_t status{500U};
    std::string reason{};
    // The signed invite event to return to the inviter. Production
    // implementations sign the event with the local server's signing key;
    // tests can echo the input.
    std::string signed_event_json{};
};

} // namespace merovingian::federation
