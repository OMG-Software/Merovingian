// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace merovingian::homeserver
{

// What one decision read, for a test that the cost follows the room and not the server (F-19).
struct RestrictedJoinWork final
{
    // Rows of `state` the decision looked at, all of them rows of rooms the join rule names.
    std::size_t state_rows_visited{0U};
    // Stored events parsed.
    std::size_t events_parsed{0U};
};

} // namespace merovingian::homeserver
