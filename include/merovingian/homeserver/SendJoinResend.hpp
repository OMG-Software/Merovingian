// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::homeserver
{

// A send_join for a join already stored (ADR-0372), as the answer's plan needs it.
struct SendJoinResend final
{
    std::string join_event_id{};
    // The joiner's membership in the state before the join; empty when there was none.
    std::string before_event_id{};
};

} // namespace merovingian::homeserver
