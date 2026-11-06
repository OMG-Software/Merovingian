// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

// A stored remote copy the remote media cache no longer holds: its local
// media row and cache row are deleted (ADR-0119).
struct PersistentRemoteMediaRelease final
{
    std::string local_media_id{};
    std::string server_name{};
    std::string media_id{};
};

} // namespace merovingian::database
