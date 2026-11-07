// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::sync
{

// What one unread event counts as. Spec (client-server-api.md, "Receiving notifications"):
// "Notifications are determined by the push rules which apply to an event", and
// `highlight_count` is "The number of unread notifications for this room with the highlight flag
// set", so `highlight` implies `notify`.
struct UnreadEventOutcome final
{
    bool notify{false};
    bool highlight{false};
};

} // namespace merovingian::sync
