// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/email/notification_email.hpp"

#include "merovingian/email/mailbox_address.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <ctime>
#include <optional>
#include <string>
#include <string_view>

#include <time.h>

namespace merovingian::email
{

namespace
{

    constexpr auto min_message_id_token_bytes = std::size_t{16U};
    constexpr auto max_message_id_token_bytes = std::size_t{64U};
    constexpr auto max_server_name_bytes = std::size_t{255U};

    [[nodiscard]] auto is_lower_hex(std::string_view token) noexcept -> bool
    {
        return token.size() >= min_message_id_token_bytes && token.size() <= max_message_id_token_bytes &&
               std::ranges::all_of(token, [](char byte) {
                   return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
               });
    }

    // A Matrix server name as written into a header: letters, digits, '-', '.', ':' and, for an IPv6
    // literal, brackets. The grammar is enforced where the server name is configured; here only the
    // bytes matter, and none of these can end a header or a Message-ID.
    [[nodiscard]] auto is_header_safe_server_name(std::string_view server_name) noexcept -> bool
    {
        return !server_name.empty() && server_name.size() <= max_server_name_bytes &&
               std::ranges::all_of(server_name, [](char byte) {
                   return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                          (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' || byte == ':' || byte == '[' ||
                          byte == ']';
               });
    }

    // The server name without a port: up to and including ']' for an IPv6 literal, else up to the
    // first ':'.
    [[nodiscard]] auto host_of(std::string_view server_name) -> std::string_view
    {
        if (server_name.front() == '[')
        {
            auto const close = server_name.find(']');
            return close == std::string_view::npos ? server_name : server_name.substr(0U, close + 1U);
        }
        return server_name.substr(0U, server_name.find(':'));
    }

    [[nodiscard]] auto two_digits(int value) -> std::string
    {
        return value < 10 ? "0" + std::to_string(value) : std::to_string(value);
    }

    // RFC 5322 section 3.3 date-time in UTC, e.g. "Sat, 24 Oct 2026 09:05:07 +0000". Day and month
    // names are the RFC's fixed English tokens, never the locale's.
    [[nodiscard]] auto rfc5322_date(std::chrono::system_clock::time_point when) -> std::string
    {
        constexpr auto days = std::array<std::string_view, 7U>{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
        constexpr auto months = std::array<std::string_view, 12U>{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
        auto const epoch_seconds = std::chrono::system_clock::to_time_t(std::chrono::floor<std::chrono::seconds>(when));
        auto fields = std::tm{};
        if (::gmtime_r(&epoch_seconds, &fields) == nullptr || fields.tm_wday < 0 || fields.tm_wday > 6 ||
            fields.tm_mon < 0 || fields.tm_mon > 11)
        {
            return {};
        }
        constexpr auto tm_year_base = 1900;
        return std::string{days.at(static_cast<std::size_t>(fields.tm_wday))} + ", " + two_digits(fields.tm_mday) +
               " " + std::string{months.at(static_cast<std::size_t>(fields.tm_mon))} + " " +
               std::to_string(fields.tm_year + tm_year_base) + " " + two_digits(fields.tm_hour) + ":" +
               two_digits(fields.tm_min) + ":" + two_digits(fields.tm_sec) + " +0000";
    }

} // namespace

auto build_unread_notification_email(UnreadNotificationEmail const& email) -> std::optional<std::string>
{
    if (email.unread_count == 0U || !is_safe_mailbox_address(email.from) || !is_safe_mailbox_address(email.to) ||
        !is_header_safe_server_name(email.server_name) || !is_lower_hex(email.message_id_token))
    {
        return std::nullopt;
    }
    auto const host = host_of(email.server_name);
    auto const date = rfc5322_date(email.sent_at);
    if (host.empty() || date.empty())
    {
        return std::nullopt;
    }

    auto const noun = email.unread_count == 1U ? std::string_view{"notification"} : std::string_view{"notifications"};
    auto const summary =
        std::to_string(email.unread_count) + " unread " + std::string{noun} + " on " + email.server_name;

    auto message = std::string{};
    message += "From: " + email.from + "\r\n";
    message += "To: " + email.to + "\r\n";
    message += "Subject: " + summary + "\r\n";
    message += "Date: " + date + "\r\n";
    message += "Message-ID: <" + email.message_id_token + "@" + std::string{host} + ">\r\n";
    message += "MIME-Version: 1.0\r\n";
    message += "Content-Type: text/plain; charset=us-ascii\r\n";
    message += "Content-Transfer-Encoding: 7bit\r\n";
    message += "Auto-Submitted: auto-generated\r\n";
    message += "\r\n";
    message += "You have " + summary + ".\r\n";
    message += "\r\n";
    message += "Open your Matrix client to read them. To stop these emails, turn off email\r\n";
    message += "notifications in your Matrix client's settings.\r\n";
    return message;
}

} // namespace merovingian::email
