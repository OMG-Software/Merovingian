// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// F-54 (ADR-0381): every PUT /sendToDevice/{eventType}/{txnId} leaves a `client_txn_ids` row, so the
// to-device ones (room_id empty) are aged out. How long the "client-txn-prune" job sleeps between sweeps.
inline constexpr auto client_txn_prune_interval = std::chrono::hours{1};

// One sweep: deletes the to-device transaction records older than
// database::to_device_client_txn_retention_ms before `now`, from the database and the in-memory mirror
// (database::prune_to_device_client_txns). Room-send and redact records are never touched. Takes
// HomeserverRuntime::mutex for the one linear pass the store makes; the interval keeps that to once an hour,
// and a sweep with nothing to remove costs only the comparison pass. Returns how long to wait before the
// next sweep.
[[nodiscard]] auto prune_client_transactions(HomeserverRuntime& runtime, std::chrono::system_clock::time_point now)
    -> std::chrono::milliseconds;

} // namespace merovingian::homeserver
