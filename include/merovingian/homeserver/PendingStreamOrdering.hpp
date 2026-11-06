// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

struct LocalDatabase;

// ADR-0247: marks `ordering` as reserved for an event not yet applied to the
// store, for as long as it lives. Construct it right after allocating the
// ordering, and destroy it once the event is applied (or abandoned), both with
// runtime.mutex held: a path that commits with the mutex released must hold one
// across the commit, or a sync in that window hands out a position past an
// event the client then never receives.
class PendingStreamOrdering final
{
public:
    PendingStreamOrdering(LocalDatabase& database, std::uint64_t ordering);
    ~PendingStreamOrdering();

    PendingStreamOrdering(PendingStreamOrdering const&) = delete;
    auto operator=(PendingStreamOrdering const&) -> PendingStreamOrdering& = delete;
    PendingStreamOrdering(PendingStreamOrdering&&) = delete;
    auto operator=(PendingStreamOrdering&&) -> PendingStreamOrdering& = delete;

private:
    LocalDatabase& m_database;
    std::uint64_t m_ordering;
};

} // namespace merovingian::homeserver
