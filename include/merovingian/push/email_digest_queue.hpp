// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace merovingian::push
{

// When notification emails go out (ADR-0219). A notification for an email pusher schedules one
// email `delay` later, but never sooner than `throttle` after the last email to that pusher; more
// notifications before then fold into the same email. The email reports how much is unread when
// it is sent, so one that finds nothing unread (the user read it elsewhere) is not sent at all.
struct EmailDigestPolicy final
{
    std::chrono::seconds delay{600};
    std::chrono::seconds throttle{3600};
};

// A failed send is tried again after 1 minute, doubling to at most 30 minutes, and given up after
// 6 failed attempts: about an hour and a half after the first.
inline constexpr auto email_digest_initial_backoff = std::chrono::minutes{1};
inline constexpr auto email_digest_max_backoff = std::chrono::minutes{30};
inline constexpr auto email_digest_max_attempts = std::uint32_t{6U};
// Pushers tracked at once. Each pusher is capped per user at registration
// (server.push.max_pushers_per_user), so this bounds memory against many users, not one.
inline constexpr auto email_digest_queue_capacity = std::size_t{4096U};

// The wait before the attempt that follows `failed_attempts` failed attempts (at least 1).
[[nodiscard]] auto email_digest_backoff(std::uint32_t failed_attempts) noexcept -> std::chrono::milliseconds;

// One email pusher: the user and the pusher's pushkey (the address as the client registered it).
struct EmailDigestKey final
{
    std::string user_id{};
    std::string pushkey{};

    auto operator<=>(EmailDigestKey const&) const = default;
};

enum class EmailDigestAdmission : std::uint8_t
{
    // An email is now due; it was not before.
    scheduled,
    // An email was already due or being sent; this notification will be in it, or in the one that
    // follows it.
    folded,
    // email_digest_queue_capacity pushers are tracked and none could be released.
    queue_full,
};

// How the attempt at an email taken by take_due ended.
enum class EmailDigestOutcome : std::uint8_t
{
    sent,
    // Nothing was unread when it was due, so nothing was sent.
    nothing_unread,
    // It could not be sent; try again after a backoff.
    failed,
    // It must never be sent: the pusher, or the address it sends to, has gone.
    abandoned,
};

// The email pushers with a notification email due, and when each last sent one. Thread-safe:
// request threads note notifications (under runtime.mutex) and the email job takes and completes
// due emails, each under this queue's own mutex, which is never held while taking another. Holds
// no network state; the caller sends. In memory only: a restart forgets due emails, as the push
// retry queue forgets due retries (ADR-0206).
class EmailDigestQueue final
{
public:
    EmailDigestQueue() = default;
    ~EmailDigestQueue() = default;
    EmailDigestQueue(EmailDigestQueue const&) = delete;
    EmailDigestQueue(EmailDigestQueue&&) = delete;
    auto operator=(EmailDigestQueue const&) -> EmailDigestQueue& = delete;
    auto operator=(EmailDigestQueue&&) -> EmailDigestQueue& = delete;

    // A notification for `key` at `now`. Schedules an email at the later of now + policy.delay and
    // the last email + policy.throttle, unless one is already due or being sent. Calls the wake
    // hook when it schedules.
    [[nodiscard]] auto note_notification(EmailDigestKey const& key, std::chrono::steady_clock::time_point now,
                                         EmailDigestPolicy const& policy) -> EmailDigestAdmission;

    // Removes up to `max` emails due at `now`, earliest first, and marks each as being sent until
    // complete() is called for it.
    [[nodiscard]] auto take_due(std::chrono::steady_clock::time_point now, std::size_t max)
        -> std::vector<EmailDigestKey>;

    // Records how the attempt at `key`'s email ended at `now`. A notification noted while it was
    // being sent schedules the next email under `policy`. Returns true when `failed` scheduled
    // another attempt, false when it gave up (and for every other outcome).
    auto complete(EmailDigestKey const& key, EmailDigestOutcome outcome, std::chrono::steady_clock::time_point now,
                  EmailDigestPolicy const& policy) -> bool;

    // Forgets `key` entirely: its pusher was removed.
    auto forget(EmailDigestKey const& key) -> void;

    // When the earliest email is due, or nullopt when none is.
    [[nodiscard]] auto next_due() const -> std::optional<std::chrono::steady_clock::time_point>;

    // Pushers tracked: due, being sent, or remembered for their throttle.
    [[nodiscard]] auto size() const -> std::size_t;

    // Called, under this queue's mutex, whenever an email is scheduled; the email job installs its
    // PeriodicJob::wake here and clears it (an empty function) before it stops.
    auto set_wake(std::function<void()> wake) -> void;

private:
    struct Entry final
    {
        std::optional<std::chrono::steady_clock::time_point> due{};
        bool sending{false};
        // A notification arrived while sending.
        bool renotified{false};
        std::uint32_t failed_attempts{0U};
        std::optional<std::chrono::steady_clock::time_point> last_sent{};
        // The throttle in force when last_sent was recorded, for releasing the entry.
        std::chrono::seconds throttle{0};
    };

    auto schedule(Entry& entry, std::chrono::steady_clock::time_point now, EmailDigestPolicy const& policy) -> void;
    auto release_idle(std::chrono::steady_clock::time_point now) -> void;

    mutable std::mutex mutex_{};
    std::map<EmailDigestKey, Entry> entries_{};
    std::function<void()> wake_{};
};

} // namespace merovingian::push
