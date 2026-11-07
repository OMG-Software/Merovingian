// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/PendingStreamOrdering.hpp"

#include "merovingian/homeserver/LocalDatabase.hpp"

#include <cstdint>

namespace merovingian::homeserver
{

PendingStreamOrdering::PendingStreamOrdering(LocalDatabase& database, std::uint64_t ordering)
    : m_database{database}
    , m_ordering{ordering}
{
    m_database.pending_stream_orderings.insert(m_ordering);
}

PendingStreamOrdering::~PendingStreamOrdering()
{
    if (auto const entry = m_database.pending_stream_orderings.find(m_ordering);
        entry != m_database.pending_stream_orderings.end())
    {
        m_database.pending_stream_orderings.erase(entry);
    }
}

} // namespace merovingian::homeserver
