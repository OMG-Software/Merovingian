// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::sync
{

// Where a user stands in the notifier's history (ADR-0437): their generation and the broadcast generation, taken
// together under the notifier's mutex by `SyncNotifier::observe`.
struct WaitCursor final
{
    std::string user{};
    std::uint64_t user_generation{0U};
    std::uint64_t broadcast_generation{0U};
};

} // namespace merovingian::sync
