// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/StopFlag.hpp"

#include <chrono>
#include <cstddef>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// G7 (ADR-0488, ADR-0489): rows that nothing will ever read again are deleted, in bounded batches, by the
// "retention-sweep" `PeriodicJob`.
inline constexpr auto retention_sweep_interval = std::chrono::hours{1};
// When a sweep stopped before it was done, how soon the next one starts.
inline constexpr auto retention_sweep_continue_interval = std::chrono::seconds{5};
// The most rows one transaction, and so one hold of HomeserverRuntime::mutex, deletes.
inline constexpr auto retention_batch_rows = std::size_t{500U};
// The most batches one sweep runs, per kind of row.
inline constexpr auto retention_max_batches = std::size_t{20U};
// An access token stays on record this long after it expired, so a request that presents it is still answered
// "token expired" in the audit log rather than "session not found". A revoked one goes at once.
inline constexpr auto expired_access_token_grace = std::chrono::hours{24 * 7};

// One sweep at `now`:
//  - deletes the sessions and tokens that can no longer authenticate (revoked or long-expired access tokens,
//    expired refresh tokens), from the database in batches of `retention_batch_rows`, then once from memory;
//  - when `security.audit_log_retention_days` is not 0, deletes the audit rows older than that, in batches,
//    and writes one `audit.retention.purged` audit row saying up to when and in how many batches.
// Locks: HomeserverRuntime::mutex is taken for one scan of the in-memory tokens, once per batch (one
// transaction of at most `retention_batch_rows` rows) and once for the final in-memory erase; it is released
// between batches. The audit existence probe reads on a connection of its own with no lock held. A failed
// write ends that kind's work for this sweep and is logged; the next sweep starts again.
// Returns how long to wait before the next sweep.
[[nodiscard]] auto run_retention_sweep(HomeserverRuntime& runtime, std::chrono::system_clock::time_point now,
                                       StopFlag const& stop) -> std::chrono::milliseconds;

} // namespace merovingian::homeserver
