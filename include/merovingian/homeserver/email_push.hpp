// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/periodic_job.hpp"
#include "merovingian/homeserver/stop_flag.hpp"

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::database
{
struct PersistentStore;
}

namespace merovingian::config
{
class Config;
}

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// Kind "email" pushers (ADR-0219, ADR-0220). Spec (client-server-api.md, POST /pushers/set):
// "email" makes a pusher that emails the user with unread notifications, and its pushkey "is the
// email address to send notifications to". A request never sends email: push delivery notes the
// notification in HomeserverRuntime::email_digest_queue_ and one PeriodicJob thread sends what is
// due, as the push retry job does (ADR-0206).

// At most this many emails are sent by one call of send_due_email_notifications, so one call cannot
// hold the job (or a stop request) behind a backlog.
inline constexpr auto email_push_batch = std::size_t{16U};
// How long the email job sleeps when nothing is due sooner. Scheduling an email wakes it.
inline constexpr auto email_push_idle_delay = std::chrono::minutes{5};

// Whether this server sends email at all: server.email.smtp_url is set. Without it POST
// /pushers/set refuses kind "email".
[[nodiscard]] auto email_push_configured(config::Config const& config) -> bool;

// The address an email pusher with `pushkey` may send to for `user_id`: the user's own email 3PID
// that `pushkey` names (compared case-insensitively, as 3PID addresses are stored lower-case), and
// only when that address passes email::is_safe_mailbox_address. nullopt otherwise. Read under
// runtime.mutex.
[[nodiscard]] auto owned_email_pusher_address(database::PersistentStore const& store, std::string_view user_id,
                                              std::string_view pushkey) -> std::optional<std::string>;

// Deletes `user_id`'s email pushers whose pushkey names `address` (a lower-case email address the
// user no longer holds as a 3PID), and forgets any email due to them. Returns false when a pusher
// could not be deleted (it stays, still matching, so a retry finishes the job). Call under
// runtime.mutex.
[[nodiscard]] auto remove_email_pushers_for_address(HomeserverRuntime& runtime, std::string_view user_id,
                                                    std::string_view address) -> bool;

// The email job's body: sends the emails due at `now` (at most email_push_batch), checking `stop`
// between them. For each it re-reads, under runtime.mutex, that the pusher is still registered and
// its address is still the user's own 3PID (if not, the email is abandoned, and a pusher whose
// address has gone is deleted), and counts the user's unread notifications as the Push Gateway
// badge counts them; nothing unread means nothing is sent. The email is then sent with the mutex
// released. Returns how long to wait before the next call: until the earliest due email, between
// one second and email_push_idle_delay.
[[nodiscard]] auto send_due_email_notifications(HomeserverRuntime& runtime, StopFlag const& stop,
                                                std::chrono::steady_clock::time_point now) -> std::chrono::milliseconds;

// Runs send_due_email_notifications on its own thread and points the email queue's wake hook at
// it. The thread starts only in start(), after process hardening (ADR-0082). stop() (and the
// destructor) clear the hook before stopping the thread; call it before the runtime is torn down.
class EmailPushJob final
{
public:
    explicit EmailPushJob(HomeserverRuntime& runtime);
    ~EmailPushJob();

    EmailPushJob(EmailPushJob const&) = delete;
    EmailPushJob(EmailPushJob&&) = delete;
    auto operator=(EmailPushJob const&) -> EmailPushJob& = delete;
    auto operator=(EmailPushJob&&) -> EmailPushJob& = delete;

    // Starts the thread and installs the wake hook. False if the thread could not be started (the
    // hook is then left unset).
    [[nodiscard]] auto start() -> bool;
    // Clears the wake hook, then stops and joins the thread. Idempotent.
    auto stop() noexcept -> void;

private:
    HomeserverRuntime& runtime_;
    PeriodicJob job_;
};

} // namespace merovingian::homeserver
