// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// What main can check an outbound federation answer against (F-43, ADR-0349). It decides the route:
// the federation worker is the process most exposed to hostile traffic, so what it relays is input,
// not a fact. An answer main uses without a signature check must be fetched over main's own
// OutboundClient, or a compromised worker could speak as any remote server.
enum class OutboundAnswerTrust : std::uint8_t
{
    // Main acts on the answer as given: its status, its fields or its choice of content. Direct
    // route only. This includes an answer whose body is signed but whose status, or whose choice of
    // which signed objects to send, main also acts on. A caller that cannot say it is
    // signature_verified is this.
    unverified,
    // Every use main makes of a success body is a signature check on the whole of it (backfilled
    // PDUs are verified one by one before they are stored), and a failure only means "no data".
    // The worker may carry the call: the most it can do is withhold or replay what servers signed.
    signature_verified,
};

} // namespace merovingian::homeserver
