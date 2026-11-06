// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/MembershipProjection.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/persistent_event.hpp"
#include "merovingian/database/statement.hpp"

#include <optional>
#include <string>
#include <vector>

namespace merovingian::database
{

// Split version of store_event_with_state for callers that need to release locks
// around the backend commit. `prepare` validates in-memory pre-conditions and
// builds the prepared statements. `commit` writes them to the backend. `apply`
// mirrors the committed rows into the in-memory vectors. The three phases must be
// called in order on the same PreparedStateUpdate; prepare/apply are typically run
// under a per-room lock while commit runs without it so independent rooms can overlap.
struct PreparedStateUpdate final
{
    PersistentEvent event{};
    std::optional<PersistentStateEvent> state{};
    std::optional<MembershipProjection> membership{};
    std::vector<PreparedStatement> statements{};
    bool state_already_existed{false};
    std::string previous_event_id{};
};

} // namespace merovingian::database
