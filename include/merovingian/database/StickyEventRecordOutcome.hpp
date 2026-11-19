// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::database
{

// What `record_sticky_event` did. `recorded` is true when the row is recorded or there was
// nothing to write, false when the store refused the row (memory unchanged). `other_rooms` are the rooms, other than
// the new row's own, that lost an unexpired row to the sender cap (a sender's oldest row can be in any room). Each is
// listed once, in the order first evicted; empty when nothing outside the row's room changed or nothing was written.
// The caller tells the federation worker each of them changed, as it does the new row's room (ADR-0862).
struct StickyEventRecordOutcome final
{
    bool recorded{false};
    std::vector<std::string> other_rooms{};
};

} // namespace merovingian::database
