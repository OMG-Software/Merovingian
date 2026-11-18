// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::database
{

// What `record_delayed_event_outcome` did (ADR-0825). `recorded`: the row is finalised in the database and in memory.
// `refused`: nothing changed, because the row is absent or not scheduled or the arguments were not storable.
// `commit_failed`: the row IS finalised in memory but the database still holds it as scheduled, so the caller logs
// it and the next start-up sends the event again (at least once, ADR-0825).
enum class DelayedEventOutcomeResult
{
    recorded,
    refused,
    commit_failed,
};

} // namespace merovingian::database
