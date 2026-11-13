// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PreparedStateUpdate.hpp"
#include "merovingian/database/PreparedStatement.hpp"

#include <vector>

namespace merovingian::database
{

// Outlier events prepared for one backend transaction (`prepare_outlier_events_batch`): the updates to apply in memory
// once the statements have committed. Preparing and applying need the store's owner to hold its lock; committing does
// not.
struct PreparedOutlierBatch final
{
    std::vector<PreparedStateUpdate> updates{};
    std::vector<PreparedStatement> statements{};
};

} // namespace merovingian::database
