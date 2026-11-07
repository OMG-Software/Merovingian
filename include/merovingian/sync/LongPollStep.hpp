// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::sync
{

// What a rerun of the sync decided: `complete` means respond now; otherwise the position it ended with.
struct LongPollStep final
{
    bool complete{false};
    std::uint64_t since_stream_ordering{0U};
    std::uint64_t since_sync_stream_id{0U};
};

} // namespace merovingian::sync
