// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// What storing a locally composed event came to. The event commits in one transaction; what follows it (the
// live roster and the device-list rows of a member event) is bookkeeping that can fail after the event is
// durable. A durably stored event must still be federated and announced, so the two failures are told apart
// (analysis finding C13).
enum class PersistOutcome : std::uint8_t
{
    // The event is stored and its bookkeeping is done.
    stored,
    // The event is durable but the bookkeeping after it failed (logged with the event ID). Callers carry on as
    // for `stored`: federate, notify, answer success.
    stored_bookkeeping_failed,
    // Nothing was stored; the caller answers an error.
    not_stored,
};

} // namespace merovingian::homeserver
