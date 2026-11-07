// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

// Parameters that the /sync handler returns when it needs to wait outside
// the runtime state mutex before building the response.
struct SyncWaitParams final
{
    std::uint64_t since_stream_ordering{0U};
    std::uint64_t since_sync_stream_id{0U};
    std::chrono::milliseconds timeout{0U};
    // Authenticated identities, supplied by the handler while holding the runtime lock.
    std::string user_id{};
    std::string device_id{};
};

} // namespace merovingian::homeserver
