// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

struct FetchThreadsRequest final
{
    std::string room_id{};
    // "all" (default) or "participated". Any other value is rejected with 400
    // rather than silently treated as "all".
    std::optional<std::string> include{};
    std::optional<std::string> from{};
    std::optional<std::uint64_t> limit{};
    // The most of the room's events the request may examine; `max_thread_events_examined` when
    // unset. For a test to reach the bound without storing thousands of events.
    std::optional<std::size_t> max_events_examined{};
};

} // namespace merovingian::homeserver
