// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// How one request round on a connection ended (ADR-0077).
enum class RoundOutcome : std::uint8_t
{
    // One request round finished and the connection must close.
    close_connection,
    // One request round finished with Connection: keep-alive; the
    // connection goes back to the dispatcher for its next request.
    continue_keep_alive,
    // The request was a long-poll handed off to the sync pool, which now
    // owns the connection (and hands it back to the dispatcher itself).
    transferred,
};

} // namespace merovingian::homeserver
