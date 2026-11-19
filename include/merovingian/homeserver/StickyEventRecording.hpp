// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/StickyEventCaps.hpp"

#include <cstdint>
#include <string_view>

namespace merovingian::homeserver
{

// Records an accepted, persisted PDU as a sticky event (MSC4354, ADR-0854) when it is one. `pdu_json` is the PDU as
// stored, `event_id` its ID and `received_at_ms` the time this server first saw it (for a locally composed event, the
// event clock's reading when it was composed; for a federated one, the time the main process accepted it; never a time
// the sender supplied). Whether the PDU is sticky is decided by `events::sticky_duration_of`; the row's room, sender
// and `origin_server_ts` are read from the PDU, its expiry is `events::sticky_expiry_ms`, and the row is held to
// `caps` (`database::record_sticky_event`: the oldest is expired, never the new event refused; ADR-0857). `now_ms` is
// the clock reading the expiry is judged against. Independent of any client request. The caller holds
// `runtime.mutex`.
//
// True when the event is recorded and also when there is nothing to record (the PDU is not sticky, is unparseable, or
// has already expired). False only when the store refused the row. Nothing is logged here; the caller logs a false
// result without event content.
[[nodiscard]] auto record_sticky_event_of_pdu(database::PersistentStore& store, std::string_view pdu_json,
                                              std::string_view event_id, std::int64_t received_at_ms,
                                              database::StickyEventCaps caps, std::int64_t now_ms) -> bool;

} // namespace merovingian::homeserver
