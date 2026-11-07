// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/OutboundDeadline.hpp"

#include <chrono>

namespace merovingian::homeserver
{

// The limits of a bounded call: one wall-clock deadline for discovery plus the
// request, and the margin the federation-worker round trip may add to it.
struct BoundedOutboundLimits final
{
    OutboundDeadline deadline;
    std::chrono::seconds worker_margin;
};

} // namespace merovingian::homeserver
