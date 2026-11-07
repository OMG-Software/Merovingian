// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>

namespace merovingian::push
{

// When notification emails go out (ADR-0219). A notification for an email pusher schedules one
// email `delay` later, but never sooner than `throttle` after the last email to that pusher; more
// notifications before then fold into the same email. The email reports how much is unread when
// it is sent, so one that finds nothing unread (the user read it elsewhere) is not sent at all.
struct EmailDigestPolicy final
{
    std::chrono::seconds delay{600};
    std::chrono::seconds throttle{3600};
};

} // namespace merovingian::push
