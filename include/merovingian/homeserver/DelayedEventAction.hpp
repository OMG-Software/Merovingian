// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::homeserver
{

// What an owner asks of a delayed event they scheduled (MSC4140): send it now, cancel it, or restart its timer.
enum class DelayedEventAction
{
    send,
    cancel,
    restart,
};

} // namespace merovingian::homeserver
