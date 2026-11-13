// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentServerSigningKey.hpp"
#include "merovingian/database/RoomReloadSnapshot.hpp"

#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

// Where WorkerSnapshotService gets what it sends a federation worker (ADR-0733, ADR-0735). WorkerPool reads the
// database through a store of its own that holds only the backend and its location (never main's live store and never
// runtime.mutex), and the keys from main's memory; a unit test passes functions that count their calls.
struct WorkerSnapshotSources final
{
    // Every room ID, sorted, from one read; nullopt when the read failed.
    std::function<std::optional<std::vector<std::string>>()> list_rooms{};
    // One room's rows from one read transaction, closed when it returns; nullopt when the read failed.
    std::function<std::optional<database::RoomReloadSnapshot>(std::string_view room_id)> read_room{};
    // A server's public signing keys from memory, at most the given number of rows.
    std::function<std::vector<database::PersistentServerSigningKey>(std::string_view server_name, std::size_t max_rows)>
        server_keys{};
    std::function<std::chrono::steady_clock::time_point()> now{};
};

} // namespace merovingian::homeserver
