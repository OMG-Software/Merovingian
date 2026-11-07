// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::push
{

// How the attempt at an email taken by take_due ended.
enum class EmailDigestOutcome : std::uint8_t
{
    sent,
    // Nothing was unread when it was due, so nothing was sent.
    nothing_unread,
    // It could not be sent; try again after a backoff.
    failed,
    // It must never be sent: the pusher, or the address it sends to, has gone.
    abandoned,
};

} // namespace merovingian::push
