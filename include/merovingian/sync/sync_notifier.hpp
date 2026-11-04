// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::sync
{

// Spec: GET /sync timeout is a non-negative number of milliseconds supplied by
// the client. The server is free to impose a cap; without one a client can pin
// a worker indefinitely or exhaust connection bookkeeping. This constant is the
// maximum long-poll timeout used on every sync endpoint (HTTP-4).
inline constexpr std::uint64_t k_max_sync_timeout_ms = 120'000U;

// The users a publish can have changed anything for (ADR-0437). A publish with no scope is a broadcast.
using AffectedUsers = std::span<std::string const>;

// Where a user stands in the notifier's history (ADR-0437): their generation and the broadcast generation, taken
// together under the notifier's mutex by `SyncNotifier::observe`.
struct WaitCursor final
{
    std::string user{};
    std::uint64_t user_generation{0U};
    std::uint64_t broadcast_generation{0U};
};

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
// Who a publish wakes (ADR-0437). A publish names the users it affected, or names nobody
// and is a broadcast. A long-poll for a user takes a cursor (`observe`) and waits on it
// (`wait_for_change(cursor, timeout)`): the wait returns true when a publish scoped to that
// user, or any broadcast, has happened since the cursor was taken, however long ago and
// whether or not anyone was waiting then; a publish scoped to other users leaves it asleep
// and the positions do not matter. A waiter that names no user (the position overload) wakes
// on every publish, as every waiter once did. The counters, each user's generation and the
// waiters are guarded by one mutex, and a cursor is taken under it, so a publish is either
// before the cursor or seen by it: never neither. Only a publish whose affected set is
// certain is scoped; a caller that cannot name the set broadcasts.
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
    // counter. When either advanced: with no `scope` every parked waiter
    // is woken; with a `scope` the waiters of the named users, and any
    // waiter that named no user, are.
    auto publish(std::uint64_t new_stream_ordering, std::uint64_t new_sync_stream_id,
                 std::optional<AffectedUsers> scope = std::nullopt) -> void;

    // Block up to `timeout` for either counter to advance past the
    // caller's since-values. Returns true when a change was observed
    // (i.e. current > since at entry or at wake-up), false on
    // timeout. `timeout == 0` returns immediately with the current
    // state. Wakes on every publish: for a waiter that names no user.
    [[nodiscard]] auto wait_for_change(std::uint64_t since_stream_ordering, std::uint64_t since_sync_stream_id,
                                       std::chrono::milliseconds timeout) -> bool;

    // The cursor for `user`'s next wait. A user's generation is kept for as long as the notifier lives, not just
    // while someone waits, so a publish that lands between two waits moves it: the map holds one small entry per
    // user that has ever long-polled on this server, which is bounded by its local users.
    [[nodiscard]] auto observe(std::string_view user) -> WaitCursor;

    // Block up to `timeout` until `cursor`'s user's generation or the broadcast generation has moved past the
    // cursor. A generation that moved before the call returns true at once, with no position check.
    [[nodiscard]] auto wait_for_change(WaitCursor const& cursor, std::chrono::milliseconds timeout) -> bool;

    // Read the current sync_stream_id without blocking. Mostly useful
    // for tests that want to drive the notifier deterministically.
    [[nodiscard]] auto current_sync_stream_id() const -> std::uint64_t;

    // Callers currently blocked in wait_for_change (diagnostics and tests:
    // it tells a test when a long-poll has started waiting).
    [[nodiscard]] auto waiting() const -> std::size_t;

    // How many waiters publish() has signalled since the notifier was made, counting one per
    // waiting user (and one for all the waiters that named none) per publish. A publish
    // scoped to users nobody waits for signals none. For tests that count wake-ups.
    [[nodiscard]] auto signals_sent() const -> std::uint64_t;

private:
    // One user's waiters and generation. Held in a map whose nodes do not move, and never erased.
    struct UserWaiters final
    {
        std::condition_variable wake{};
        std::size_t waiters{0U};
        // Moves each time a publish scoped to this user happens.
        std::uint64_t generation{0U};
    };
    struct UserHash final
    {
        using is_transparent = void;
        [[nodiscard]] auto operator()(std::string_view user) const noexcept -> std::size_t
        {
            return std::hash<std::string_view>{}(user);
        }
    };

    mutable std::mutex mutex_{};
    // Waiters that named no user.
    std::condition_variable anyone_{};
    std::unordered_map<std::string, UserWaiters, UserHash, std::equal_to<>> by_user_{};
    std::uint64_t stream_ordering_{0U};
    std::uint64_t sync_stream_id_{0U};
    // Moves each time a broadcast publish happens.
    std::uint64_t broadcast_generation_{0U};
    std::uint64_t signals_sent_{0U};
    std::size_t waiting_{0U};
    std::size_t waiting_anyone_{0U};
};

// What a rerun of the sync decided: `complete` means respond now; otherwise the position it ended with.
struct LongPollStep final
{
    bool complete{false};
    std::uint64_t since_stream_ordering{0U};
    std::uint64_t since_sync_stream_id{0U};
};

struct LongPollOutcome final
{
    // A rerun completed.
    bool dispatched{false};
    // `idle` reported the client gone.
    bool client_gone{false};
};

// The long-poll sequence all three transports share (ADR-0437). With a user: take a cursor; if the positions are
// already past `since`, rerun once (the rerun's snapshot is taken after the cursor, so nothing is missed); then
// loop: wait on the cursor for at most `slice`; on a change take a new cursor and THEN rerun, in that order; on a
// quiet slice call `idle`, which returns false to stop because the client is gone. A publish for other users never
// reruns it, however far the positions move. With no user the wait is on the positions, as it always was. The
// loop ends when `running` is false, at `deadline`, on a completed rerun or when the client is gone.
[[nodiscard]] auto long_poll_wait(SyncNotifier& notifier, std::string_view user, std::uint64_t since_stream_ordering,
                                  std::uint64_t since_sync_stream_id, std::chrono::steady_clock::time_point deadline,
                                  std::chrono::milliseconds slice, std::function<bool()> const& running,
                                  std::function<LongPollStep()> const& rerun, std::function<bool()> const& idle)
    -> LongPollOutcome;

} // namespace merovingian::sync
