// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

namespace merovingian::database
{

// Which retained PDUs wait for which events (F-18, ADR-0326). In memory only, derived from
// `PersistentStore::deferred_pdus` and never persisted: upsert_deferred_pdu and remove_deferred_pdu keep
// it current, rebuild_deferred_pdu_awaits re-derives it after hydration. A PDU is indexed under the
// event IDs it is missing (see find_missing_event_references), so waking the PDUs that wait for an event
// is a lookup, not a search of every retained row's JSON.
struct DeferredPduAwaits final
{
    // Awaited event ID -> (retained event ID -> its room ID).
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> rows_by_awaited{};
    // Retained event ID -> the event IDs it is indexed under.
    std::unordered_map<std::string, std::vector<std::string>> awaited_by_row{};
    // `deferred_pdus.size()` when the index was last made to match the rows. A caller that pushed rows
    // directly leaves it behind, and take_deferred_pdus_awaiting rebuilds first.
    std::size_t indexed_rows{0U};
};

} // namespace merovingian::database
