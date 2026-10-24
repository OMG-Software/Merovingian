// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/email_push.hpp"

#include "merovingian/config/config.hpp"
#include "merovingian/crypto/random.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/email/mailbox_address.hpp"
#include "merovingian/email/notification_email.hpp"
#include "merovingian/email/smtp_client.hpp"
#include "merovingian/email/smtp_endpoint.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/push_badge_count.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/stored_push_rules.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/push/email_digest_queue.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    // Push delivery has always logged under the rooms logger (room_service.cpp, push_retry.cpp).
    // Fields name the user, never the address: an email address is personal data the logs need
    // not hold.
    auto log_email_push(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("rooms", event, fields, severity);
    }

    [[nodiscard]] auto to_lower_ascii(std::string_view text) -> std::string
    {
        auto lowered = std::string{text};
        std::ranges::transform(lowered, lowered.begin(), [](char byte) {
            return (byte >= 'A' && byte <= 'Z') ? static_cast<char>(byte - 'A' + 'a') : byte;
        });
        return lowered;
    }

    // The 128 random bits that make a Message-ID unique, as 32 lower-case hex characters.
    constexpr auto message_id_random_bytes = std::size_t{16U};

    // What the job does with one due email, decided under runtime.mutex.
    struct PreparedEmail final
    {
        push::EmailDigestOutcome skip_outcome{push::EmailDigestOutcome::abandoned};
        // Set when the email is to be sent.
        std::optional<std::string> recipient{};
        std::uint32_t unread{0U};
    };

    [[nodiscard]] auto email_pusher_registered(database::PersistentStore const& store, push::EmailDigestKey const& key)
        -> bool
    {
        auto const pushers = database::list_pushers_for_user(store, key.user_id);
        return std::ranges::any_of(pushers, [&key](database::PersistentPusher const& pusher) {
            return pusher.kind == "email" && pusher.pushkey == key.pushkey;
        });
    }

    // Re-reads everything the email depends on, since any of it may have changed after the
    // notification: the pusher, the user's hold on the address, and what is unread now.
    [[nodiscard]] auto prepare_email(HomeserverRuntime& runtime, push::EmailDigestKey const& key) -> PreparedEmail
    {
        auto const guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
        auto& store = runtime.database.persistent_store;
        // A deactivated account keeps its pushers and 3PIDs, but nobody can sign in to it to turn
        // the emails off, so it is never mailed.
        if (!email_pusher_registered(store, key) || !asserted_user_is_active(runtime, key.user_id))
        {
            return PreparedEmail{};
        }
        auto address = owned_email_pusher_address(store, key.user_id, key.pushkey);
        if (!address.has_value())
        {
            // The address is no longer the user's own 3PID (removed, or the account deactivated by
            // a path that does not remove pushers). The pusher must not send anywhere again.
            // A pusher that could not be deleted is still abandoned here, and the same check
            // finds and deletes it again before any later email.
            std::ignore = remove_email_pushers_for_address(runtime, key.user_id, to_lower_ascii(key.pushkey));
            log_email_push("push.email.pusher_removed",
                           {
                               {"recipient", key.user_id,                       false},
                               {"reason",    "address is no longer the user's", false}
            },
                           observability::LogEventSeverity::info);
            return PreparedEmail{};
        }
        auto const ruleset = load_push_ruleset(
            store, key.user_id, static_cast<std::size_t>(runtime.config.server().client_api.max_push_rules_per_user));
        auto const unread = push_badge_unread_count(runtime, key.user_id, ruleset);
        if (unread == 0U)
        {
            return PreparedEmail{push::EmailDigestOutcome::nothing_unread, std::nullopt, 0U};
        }
        return PreparedEmail{push::EmailDigestOutcome::sent, std::move(address), unread};
    }

    [[nodiscard]] auto smtp_settings(HomeserverRuntime const& runtime) -> std::optional<email::SmtpSettings>
    {
        auto const& configured = runtime.config.server().email;
        auto endpoint = email::parse_smtp_url(configured.smtp_url);
        if (!endpoint.has_value())
        {
            return std::nullopt;
        }
        auto settings = email::SmtpSettings{};
        settings.endpoint = std::move(*endpoint);
        settings.require_tls = configured.require_tls;
        settings.from = configured.from;
        settings.username = configured.username;
        settings.password_file = configured.password_file;
        auto const& server_name = runtime.config.server().server_name;
        settings.helo_domain = server_name.substr(0U, server_name.find(':'));
        settings.connect_timeout_seconds = configured.connect_timeout_seconds;
        settings.total_timeout_seconds = configured.total_timeout_seconds;
        settings.test_resolution = runtime.test_forced_smtp_resolution;
        return settings;
    }

    [[nodiscard]] auto digest_policy(HomeserverRuntime const& runtime) -> push::EmailDigestPolicy
    {
        auto const& configured = runtime.config.server().email;
        return push::EmailDigestPolicy{std::chrono::seconds{configured.notification_delay_seconds},
                                       std::chrono::seconds{configured.notification_throttle_seconds}};
    }

    [[nodiscard]] auto send_result_name(email::SmtpSendResult result) -> std::string_view
    {
        switch (result)
        {
        case email::SmtpSendResult::sent:
            return "sent";
        case email::SmtpSendResult::refused_locally:
            return "refused_locally";
        case email::SmtpSendResult::protocol_unavailable:
            return "protocol_unavailable";
        case email::SmtpSendResult::credentials_unavailable:
            return "credentials_unavailable";
        case email::SmtpSendResult::failed:
            return "failed";
        }
        return "failed";
    }

    // Builds and sends one email, with no lock held. Returns how the attempt ended for the queue.
    [[nodiscard]] auto send_email(email::SmtpSettings const& settings, std::string const& server_name,
                                  push::EmailDigestKey const& key, PreparedEmail const& prepared)
        -> push::EmailDigestOutcome
    {
        auto token = crypto::secure_random_hex(message_id_random_bytes);
        if (!token.has_value())
        {
            log_email_push("push.email.failed",
                           {
                               {"recipient", key.user_id,                    false},
                               {"result",    "no randomness for Message-ID", false}
            },
                           observability::LogEventSeverity::warning);
            return push::EmailDigestOutcome::failed;
        }
        auto content = email::UnreadNotificationEmail{};
        content.from = settings.from;
        content.to = *prepared.recipient;
        content.server_name = server_name;
        content.unread_count = prepared.unread;
        content.sent_at = std::chrono::system_clock::now();
        content.message_id_token = std::move(*token);
        auto const message = email::build_unread_notification_email(content);
        if (!message.has_value())
        {
            log_email_push(
                "push.email.failed",
                {
                    {"recipient", key.user_id,                         false},
                    {"result",    "message could not be built safely", false}
            },
                observability::LogEventSeverity::warning);
            return push::EmailDigestOutcome::abandoned;
        }
        auto const outcome = email::send_smtp_message(settings, *prepared.recipient, *message);
        if (outcome.result == email::SmtpSendResult::sent)
        {
            log_email_push("push.email.sent",
                           {
                               {"recipient", key.user_id,                     false},
                               {"unread",    std::to_string(prepared.unread), false}
            });
            return push::EmailDigestOutcome::sent;
        }
        log_email_push("push.email.failed",
                       {
                           {"recipient", key.user_id,                                   false},
                           {"result",    std::string{send_result_name(outcome.result)}, false},
                           {"detail",    outcome.detail,                                false}
        },
                       observability::LogEventSeverity::warning);
        // A message refused before it left this server would be refused again; anything else may
        // succeed later (a relay that comes back, a password file the operator fixes).
        return outcome.result == email::SmtpSendResult::refused_locally ? push::EmailDigestOutcome::abandoned
                                                                        : push::EmailDigestOutcome::failed;
    }

} // namespace

auto email_push_configured(config::Config const& config) -> bool
{
    return !config.server().email.smtp_url.empty();
}

auto owned_email_pusher_address(database::PersistentStore const& store, std::string_view user_id,
                                std::string_view pushkey) -> std::optional<std::string>
{
    auto address = to_lower_ascii(pushkey);
    if (!email::is_safe_mailbox_address(address))
    {
        return std::nullopt;
    }
    auto const owned =
        std::ranges::any_of(store.account_threepids, [&](database::PersistentThreePidBinding const& row) {
            return row.user_id == user_id && row.medium == "email" && row.address == address;
        });
    if (!owned)
    {
        return std::nullopt;
    }
    return address;
}

auto remove_email_pushers_for_address(HomeserverRuntime& runtime, std::string_view user_id, std::string_view address)
    -> bool
{
    auto& store = runtime.database.persistent_store;
    auto all_deleted = true;
    // A copy: delete_pusher erases from the store's mirror.
    auto const pushers = database::list_pushers_for_user(store, user_id);
    for (auto const& pusher : pushers)
    {
        if (pusher.kind != "email" || to_lower_ascii(pusher.pushkey) != address)
        {
            continue;
        }
        if (!database::delete_pusher(store, user_id, pusher.app_id, pusher.pushkey))
        {
            all_deleted = false;
            continue;
        }
        if (runtime.email_digest_queue_ != nullptr)
        {
            runtime.email_digest_queue_->forget(push::EmailDigestKey{std::string{user_id}, pusher.pushkey});
        }
    }
    return all_deleted;
}

auto send_due_email_notifications(HomeserverRuntime& runtime, StopFlag const& stop,
                                  std::chrono::steady_clock::time_point now) -> std::chrono::milliseconds
{
    auto const idle = std::chrono::milliseconds{email_push_idle_delay};
    if (runtime.email_digest_queue_ == nullptr || !email_push_configured(runtime.config))
    {
        return idle;
    }
    auto& queue = *runtime.email_digest_queue_;
    auto const policy = digest_policy(runtime);
    auto const settings = smtp_settings(runtime);
    auto const server_name = runtime.config.server().server_name;
    // A batch can take up to its size times the SMTP timeout. Time spent in it is added to `now`, so
    // an outcome late in the batch is recorded when it happened.
    auto const batch_started = std::chrono::steady_clock::now();
    auto const current = [&now, batch_started]() {
        return now + (std::chrono::steady_clock::now() - batch_started);
    };
    auto due = queue.take_due(now, email_push_batch);
    for (auto index = std::size_t{0U}; index < due.size(); ++index)
    {
        auto const& key = due[index];
        if (stop.stop_requested())
        {
            // Put the rest back as failed attempts rather than lose them: they are due again after
            // the first backoff, by which time the process has stopped or the job runs again.
            for (auto const& remaining : std::span{due}.subspan(index))
            {
                std::ignore = queue.complete(remaining, push::EmailDigestOutcome::failed, current(), policy);
            }
            break;
        }
        auto const prepared = prepare_email(runtime, key);
        if (!prepared.recipient.has_value())
        {
            std::ignore = queue.complete(key, prepared.skip_outcome, current(), policy);
            continue;
        }
        auto const outcome = settings.has_value() ? send_email(*settings, server_name, key, prepared)
                                                  : push::EmailDigestOutcome::abandoned;
        auto const retried = queue.complete(key, outcome, current(), policy);
        if (outcome == push::EmailDigestOutcome::failed && !retried)
        {
            log_email_push("push.email.abandoned",
                           {
                               {"recipient", key.user_id,                                     false},
                               {"attempts",  std::to_string(push::email_digest_max_attempts), false}
            },
                           observability::LogEventSeverity::warning);
        }
    }
    auto const next = queue.next_due();
    if (!next.has_value())
    {
        return idle;
    }
    auto const wait = std::chrono::duration_cast<std::chrono::milliseconds>(*next - current());
    return std::clamp(wait, std::chrono::milliseconds{std::chrono::seconds{1}}, idle);
}

EmailPushJob::EmailPushJob(HomeserverRuntime& runtime)
    : runtime_{runtime}
    , job_{"email-push", [&runtime](StopFlag const& stop) {
               return send_due_email_notifications(runtime, stop, std::chrono::steady_clock::now());
           }}
{
}

EmailPushJob::~EmailPushJob()
{
    stop();
}

auto EmailPushJob::start() -> bool
{
    if (!job_.start())
    {
        return false;
    }
    if (runtime_.email_digest_queue_ != nullptr)
    {
        runtime_.email_digest_queue_->set_wake([this]() {
            job_.wake();
        });
    }
    return true;
}

auto EmailPushJob::stop() noexcept -> void
{
    if (runtime_.email_digest_queue_ != nullptr)
    {
        try
        {
            runtime_.email_digest_queue_->set_wake({});
        }
        catch (...)
        {
            // Clearing a std::function does not throw; set_wake's mutex could, in principle.
        }
    }
    job_.stop();
}

} // namespace merovingian::homeserver
