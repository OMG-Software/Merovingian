// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::database
{

// What upsert_deferred_pdu did.
enum class DeferredPduUpsert : std::uint8_t
{
    inserted,
    // The event was already retained: its attempts (and origin) were replaced,
    // its received_at_ms and PDU JSON were kept.
    updated,
    // A new row would exceed a bound (max_deferred_pdus_per_room,
    // max_deferred_pdus_total or max_deferred_pdu_json_bytes). Nothing was
    // written. An update of a row already held never hits a bound.
    refused_full,
    persistence_failed,
};

} // namespace merovingian::database
