// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::database
{

// The event IDs a PDU names that this store cannot yet use: every `auth_events` ID with no stored event,
// and every `prev_events` ID that is not stored or has no recorded state group (so no state can be
// computed before the PDU). The one definition ingestion backfills by and retained PDUs are indexed by.
struct MissingEventReferences final
{
    std::vector<std::string> auth{};
    std::vector<std::string> prev{};
};

} // namespace merovingian::database
