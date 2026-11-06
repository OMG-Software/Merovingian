// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// One event queued for delivery to one appservice (audit R01). The
// transaction queue the Application Service API requires: a row is written
// when the event is dispatched (under the runtime lock, interest decided at
// that moment) and deleted in the same backend transaction that records its
// delivery on the cursor above.
//
// The primary key is (appservice_id, stream_ordering) and is the ONLY dedupe.
// There is deliberately no "already delivered" threshold: stream orderings are
// allocated before an event commits and events in different rooms commit out
// of order, so a lower ordering can legitimately arrive after a higher one was
// delivered. The in-memory vector is kept sorted by (appservice_id,
// stream_ordering) numerically; the column is TEXT like every other numeric
// column, so the backend's own ordering is not relied on.
struct PersistentAppserviceOutboxEntry final
{
    std::string appservice_id{};
    std::uint64_t stream_ordering{0U};
    std::string event_id{};
};

} // namespace merovingian::database
