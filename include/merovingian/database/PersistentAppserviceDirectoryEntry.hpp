// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

// A room an appservice has published to the directory of one of its networks (protocols) with PUT
// /_matrix/client/v3/directory/list/appservice/{networkId}/{roomId} (ADR-0192). Independent of
// `LocalRoom::directory_public`, the homeserver's own published room directory. Primary key
// (appservice_id, network_id, room_id).
struct PersistentAppserviceDirectoryEntry final
{
    std::string appservice_id{};
    std::string network_id{};
    std::string room_id{};
};

} // namespace merovingian::database
