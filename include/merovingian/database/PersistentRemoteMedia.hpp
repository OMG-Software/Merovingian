// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// A remote (server_name, media_id) and the local record holding its stored
// copy: the durable form of the remote media cache (ADR-0119, migration 020).
struct PersistentRemoteMedia final
{
    std::string server_name{};
    std::string media_id{};
    std::string content_type{};
    std::uint64_t size_bytes{0U};
    bool quarantined{false};
    std::string local_media_id{};
    // Milliseconds since the Unix epoch.
    std::uint64_t fetched_at_ms{0U};
};

} // namespace merovingian::database
