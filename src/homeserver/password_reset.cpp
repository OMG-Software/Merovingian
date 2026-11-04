// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/password_reset.hpp"

#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/random.hpp"
#include "merovingian/email/notification_email.hpp"
#include "merovingian/email/smtp_client.hpp"
#include "merovingian/homeserver/email_push.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/observability/logger.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <exception>
#include <future>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    auto log_reset(std::string_view event, std::string_view detail, observability::LogEventSeverity severity) -> void
    {
        observability::log_diagnostic("auth", event,
                                      {
                                          {"detail", std::string{detail}, false}
        },
                                      severity);
    }

} // namespace

auto make_password_reset_token() -> std::optional<std::string>
{
    auto bytes = crypto::secure_random_bytes(password_reset_token_length);
    if (!bytes.has_value() || bytes->size() != password_reset_token_length)
    {
        return std::nullopt;
    }
    auto token = std::string{};
    token.reserve(password_reset_token_length);
    for (auto const byte : *bytes)
    {
        // 32 symbols: the low five bits of a uniform byte are uniform.
        token.push_back(password_reset_token_alphabet[byte & 0x1FU]);
    }
    return token;
}

auto normalize_password_reset_token(std::string_view typed) -> std::string
{
    auto normalized = std::string{typed};
    std::ranges::transform(normalized, normalized.begin(), [](char const c) {
        return static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    });
    return normalized;
}

auto send_password_reset_email(HomeserverRuntime& runtime, std::string recipient, std::string token) -> bool
{
    auto settings = email_smtp_settings(runtime);
    if (!settings.has_value())
    {
        return false;
    }
    auto id = crypto::secure_random_hex(16U);
    if (!id.has_value())
    {
        return false;
    }
    auto content = email::PasswordResetEmail{};
    content.from = settings->from;
    content.to = recipient;
    content.server_name = runtime.config.server().server_name;
    content.token = std::move(token);
    content.sent_at = std::chrono::system_clock::now();
    content.message_id_token = std::move(*id);
    auto message = email::build_password_reset_email(content);
    // The code is in the message now, and nowhere else the task can reach.
    core::secure_zero(std::as_writable_bytes(std::span{content.token.data(), content.token.size()}));
    if (!message.has_value())
    {
        log_reset("password_reset.mail_unbuildable", "message could not be built safely",
                  observability::LogEventSeverity::warning);
        return false;
    }
    try
    {
        auto const orphan_lock = std::lock_guard{runtime.orphan_futures_mutex_};
        reap_completed_futures(runtime.orphan_futures_);
        if (at_background_task_capacity(runtime.orphan_futures_.size(), password_reset_max_sends_in_flight))
        {
            log_reset("password_reset.mail_dropped", "too many sends in flight",
                      observability::LogEventSeverity::warning);
            return false;
        }
        // Reserve before launching, as dispatch_push_deliveries does: a failed allocation after the launch
        // would wait on the running task while this request owns runtime.mutex.
        runtime.orphan_futures_.reserve(runtime.orphan_futures_.size() + 1U);
        auto send = std::async(std::launch::async, [settings = std::move(*settings), recipient = std::move(recipient),
                                                    message = std::move(*message)]() {
            auto const outcome = email::send_smtp_message(settings, recipient, message);
            if (outcome.result != email::SmtpSendResult::sent)
            {
                log_reset("password_reset.mail_failed", outcome.detail, observability::LogEventSeverity::warning);
            }
        });
        runtime.orphan_futures_.push_back(std::move(send));
    }
    catch (std::exception const&)
    {
        log_reset("password_reset.mail_dropped", "could not start the send", observability::LogEventSeverity::warning);
        return false;
    }
    return true;
}

} // namespace merovingian::homeserver
