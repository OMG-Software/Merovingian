// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace merovingian::sync
{

// Spec: GET /sync timeout is a non-negative number of milliseconds supplied by
// the client. The server is free to impose a cap; without one a client can pin
// a worker indefinitely or exhaust connection bookkeeping. This constant is the
// maximum long-poll timeout used on every sync endpoint (HTTP-4).
inline constexpr std::uint64_t k_max_sync_timeout_ms = 120'000U;

// Long-polling primitive for /sync. The runtime increments the global
// stream counters every time a new event, to-device message, device-list
// change, account-data row, or presence update becomes visible. Sync
// handlers call `wait_for_change` with the caller's since-token; the
// helper returns immediately when either counter has already advanced
// past the caller's since-value, and otherwise blocks up to the supplied
// timeout.
//
// The notifier tracks two independent counters:
//   - stream_ordering: timeline events (messages, state events)
//   - sync_stream_id:  sync-stream surfaces (to_device, presence,
//                      device_lists, account_data)
//
// Either counter advancing wakes all waiters.
//
// The notifier is intentionally process-local. A distributed deployment
// would replace this with a shared stream broker; the API stays the
// same for the sync handler.
class SyncNotifier final
{
public:
    SyncNotifier() = default;
    SyncNotifier(SyncNotifier const&) = delete;
    auto operator=(SyncNotifier const&) -> SyncNotifier& = delete;
    SyncNotifier(SyncNotifier&&) = delete;
    auto operator=(SyncNotifier&&) -> SyncNotifier& = delete;
    ~SyncNotifier() = default;

    // Record that one or both stream counters have advanced. Values
    // equal to or less than the current counter are ignored for that
    // counter. Wakes all parked waiters if either counter advanced.
    auto publish(std::uint64_t new_stream_ordering, std::uint64_t new_sync_stream_id) -> void;

    // Block up to `timeout` for either counter to advance past the
    // caller's since-values. Returns true when a change was observed
    // (i.e. current > since at either entry or wake-up), false on
    // timeout. `timeout == 0` returns immediately with the current
    // state.
    [[nodiscard]] auto wait_for_change(std::uint64_t since_stream_ordering, std::uint64_t since_sync_stream_id,
                                       std::chrono::milliseconds timeout) -> bool;

    // Read the current sync_stream_id without blocking. Mostly useful
    // for tests that want to drive the notifier deterministically.
    [[nodiscard]] auto current_sync_stream_id() const -> std::uint64_t;

    // Callers currently blocked in wait_for_change (diagnostics and tests:
    // it tells a test when a long-poll has started waiting).
    [[nodiscard]] auto waiting() const -> std::size_t;

private:
    mutable std::mutex mutex_{};
    std::condition_variable cv_{};
    std::uint64_t stream_ordering_{0U};
    std::uint64_t sync_stream_id_{0U};
    std::size_t waiting_{0U};
};

} // namespace merovingian::sync
