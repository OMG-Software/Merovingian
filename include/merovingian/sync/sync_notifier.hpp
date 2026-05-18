// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>

namespace merovingian::sync
{

// Long-polling primitive for /sync. The runtime increments the global
// stream id (via `bump`) every time a new event, to-device message,
// device-list change, account-data row, or presence update becomes
// visible. Sync handlers call `wait_for_change` with the caller's
// since-token; the helper returns immediately when the current id has
// already advanced past `since` (i.e. there's data to return), and
// otherwise blocks up to the supplied timeout.
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

    // Record that the global stream id has advanced. The new id MUST be
    // strictly greater than every previously published id.
    auto publish(std::uint64_t new_stream_id) -> void;

    // Block up to `timeout` for the stream id to advance past `since`.
    // Returns true when a change was observed (i.e. current > since at
    // either entry or wake-up), false on timeout. `timeout == 0` returns
    // immediately with the current state.
    [[nodiscard]] auto wait_for_change(std::uint64_t since, std::chrono::milliseconds timeout) -> bool;

    // Read the current stream id without blocking. Mostly useful for
    // tests that want to drive the notifier deterministically.
    [[nodiscard]] auto current_stream_id() const -> std::uint64_t;

private:
    mutable std::mutex mutex_{};
    std::condition_variable cv_{};
    std::uint64_t stream_id_{0U};
};

} // namespace merovingian::sync
