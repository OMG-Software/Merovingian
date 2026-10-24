// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The pure parts of the email module (ADR-0219, ADR-0220): which addresses may be written into an
// SMTP command or header, which relay URLs are accepted, and what a notification email says.
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md, POST /_matrix/client/v3/pushers/set —
// kind "email" "makes a pusher that emails the user with unread notifications".

#include "merovingian/email/mailbox_address.hpp"
#include "merovingian/email/notification_email.hpp"
#include "merovingian/email/smtp_endpoint.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace
{

using merovingian::email::build_unread_notification_email;
using merovingian::email::is_safe_mailbox_address;
using merovingian::email::parse_smtp_url;
using merovingian::email::UnreadNotificationEmail;

[[nodiscard]] auto sample_email(std::uint32_t unread = 3U) -> UnreadNotificationEmail
{
    auto email = UnreadNotificationEmail{};
    email.from = "matrix@example.org";
    email.to = "alice@example.net";
    email.server_name = "example.org";
    email.unread_count = unread;
    // 2026-10-24T09:05:07Z.
    email.sent_at = std::chrono::system_clock::time_point{std::chrono::seconds{1792832707}};
    email.message_id_token = "0123456789abcdef0123456789abcdef";
    return email;
}

// The header section, each header with its own CRLF (the blank line that ends the section is not
// included).
[[nodiscard]] auto header_block(std::string const& message) -> std::string
{
    auto const end = message.find("\r\n\r\n");
    return end == std::string::npos ? message : message.substr(0U, end + 2U);
}

[[nodiscard]] auto body_of(std::string const& message) -> std::string
{
    auto const end = message.find("\r\n\r\n");
    return end == std::string::npos ? std::string{} : message.substr(end + 4U);
}

} // namespace

SCENARIO("Only plain addresses may be written into an SMTP command or header", "[email][email-address]")
{
    GIVEN("addresses an email pusher could name")
    {
        WHEN("each plain local@domain address is checked")
        {
            THEN("it is accepted")
            {
                REQUIRE(is_safe_mailbox_address("alice@example.org"));
                REQUIRE(is_safe_mailbox_address("first.last+tag@mail.example.co.uk"));
                REQUIRE(is_safe_mailbox_address("a_b-c=d!e#f$g%h&i'j*k/l?m^n`o{p|q}r~s@x-y.example"));
            }
        }

        WHEN("an address could end the command or header early")
        {
            THEN("it is refused")
            {
                REQUIRE_FALSE(is_safe_mailbox_address("alice@example.org\r\nRCPT TO:<mallory@example.org>"));
                REQUIRE_FALSE(is_safe_mailbox_address("alice@example.org>"));
                REQUIRE_FALSE(is_safe_mailbox_address("<alice@example.org"));
                REQUIRE_FALSE(is_safe_mailbox_address(std::string_view{"alice@example.org\0x", 19U}));
                REQUIRE_FALSE(is_safe_mailbox_address("alice@example.org\n"));
            }
        }

        WHEN("an address is malformed or needs quoting")
        {
            THEN("it is refused")
            {
                REQUIRE_FALSE(is_safe_mailbox_address(""));
                REQUIRE_FALSE(is_safe_mailbox_address("alice"));
                REQUIRE_FALSE(is_safe_mailbox_address("@example.org"));
                REQUIRE_FALSE(is_safe_mailbox_address("alice@"));
                REQUIRE_FALSE(is_safe_mailbox_address("alice@bob@example.org"));
                REQUIRE_FALSE(is_safe_mailbox_address("al ice@example.org"));
                REQUIRE_FALSE(is_safe_mailbox_address("\"alice\"@example.org"));
                REQUIRE_FALSE(is_safe_mailbox_address(".alice@example.org"));
                REQUIRE_FALSE(is_safe_mailbox_address("alice.@example.org"));
                REQUIRE_FALSE(is_safe_mailbox_address("al..ice@example.org"));
                REQUIRE_FALSE(is_safe_mailbox_address("alice@[127.0.0.1]"));
                REQUIRE_FALSE(is_safe_mailbox_address("alice@exa_mple.org"));
                REQUIRE_FALSE(is_safe_mailbox_address("alice@.example.org"));
                REQUIRE_FALSE(is_safe_mailbox_address("alice@example..org"));
                REQUIRE_FALSE(is_safe_mailbox_address("alice@-example.org"));
                REQUIRE_FALSE(is_safe_mailbox_address("alice@example-.org"));
                REQUIRE_FALSE(is_safe_mailbox_address("alice@example.org."));
                REQUIRE_FALSE(is_safe_mailbox_address("al(ice)@example.org"));
                REQUIRE_FALSE(is_safe_mailbox_address("alicé@example.org"));
            }
        }

        WHEN("an address is longer than SMTP allows")
        {
            auto const long_local = std::string(65U, 'a') + "@example.org";
            auto const long_overall = std::string(64U, 'a') + "@" + std::string(63U, 'b') + "." +
                                      std::string(63U, 'c') + "." + std::string(63U, 'd') + ".org";

            THEN("it is refused")
            {
                REQUIRE_FALSE(is_safe_mailbox_address(long_local));
                REQUIRE(long_overall.size() > merovingian::email::max_mailbox_address_bytes);
                REQUIRE_FALSE(is_safe_mailbox_address(long_overall));
                REQUIRE(is_safe_mailbox_address(std::string(64U, 'a') + "@example.org"));
            }
        }
    }
}

SCENARIO("An SMTP relay URL names a scheme, a host and at most a port", "[email][smtp-url]")
{
    GIVEN("relay URLs an operator might configure")
    {
        WHEN("an implicit-TLS relay is given without a port")
        {
            auto const endpoint = parse_smtp_url("smtps://Mail.Example.org");

            THEN("it is TLS from the first byte on port 465, with the host lower-cased")
            {
                REQUIRE(endpoint.has_value());
                REQUIRE(endpoint->implicit_tls);
                REQUIRE(endpoint->host == "mail.example.org");
                REQUIRE(endpoint->port == 465U);
                REQUIRE_FALSE(endpoint->loopback_literal);
            }
        }

        WHEN("a submission relay is given with a port and a trailing slash")
        {
            auto const endpoint = parse_smtp_url("SMTP://mail.example.org:2525/");

            THEN("it uses STARTTLS-capable smtp on that port")
            {
                REQUIRE(endpoint.has_value());
                REQUIRE_FALSE(endpoint->implicit_tls);
                REQUIRE(endpoint->port == 2525U);
            }
        }

        WHEN("a submission relay is given without a port")
        {
            auto const endpoint = parse_smtp_url("smtp://mail.example.org");

            THEN("it uses port 587")
            {
                REQUIRE(endpoint.has_value());
                REQUIRE(endpoint->port == 587U);
            }
        }

        WHEN("the relay is a loopback IP literal")
        {
            auto const v4 = parse_smtp_url("smtp://127.0.0.1:25");
            auto const v4_other = parse_smtp_url("smtp://127.10.20.30:25");
            auto const v6 = parse_smtp_url("smtp://[::1]:25");

            THEN("it is recognised as loopback")
            {
                REQUIRE(v4.has_value());
                REQUIRE(v4->loopback_literal);
                REQUIRE(v4_other.has_value());
                REQUIRE(v4_other->loopback_literal);
                REQUIRE(v6.has_value());
                REQUIRE(v6->loopback_literal);
                REQUIRE(v6->host == "[::1]");
            }
        }

        WHEN("the relay is a name that usually resolves to loopback, or a non-loopback literal")
        {
            auto const name = parse_smtp_url("smtp://localhost:25");
            auto const other = parse_smtp_url("smtp://10.0.0.1:25");

            THEN("it is not treated as loopback")
            {
                REQUIRE(name.has_value());
                REQUIRE_FALSE(name->loopback_literal);
                REQUIRE(other.has_value());
                REQUIRE_FALSE(other->loopback_literal);
            }
        }

        WHEN("the URL carries anything beyond scheme, host and port")
        {
            THEN("it is refused")
            {
                REQUIRE_FALSE(parse_smtp_url("").has_value());
                REQUIRE_FALSE(parse_smtp_url("https://mail.example.org").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://user:pass@mail.example.org").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://mail.example.org/helo.example").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://mail.example.org?x=1").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://mail.example.org#x").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://mail.example.org:0").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://mail.example.org:65536").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://mail.example.org:").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://mail.example.org:25x").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://mail%2eexample.org").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://mail.example.org\r\n").has_value());
                REQUIRE_FALSE(parse_smtp_url(" smtp://mail.example.org").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://mail example.org").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://[::1").has_value());
                REQUIRE_FALSE(parse_smtp_url("smtp://[not-an-ip]").has_value());
            }
        }
    }
}

SCENARIO("A notification email reports an unread count and nothing a user was sent", "[email][notification-email]")
{
    GIVEN("three unread notifications for an address on example.org")
    {
        auto const email = sample_email(3U);

        WHEN("the email is built")
        {
            auto const message = build_unread_notification_email(email);

            THEN("it is a US-ASCII message whose every line ends in CRLF")
            {
                REQUIRE(message.has_value());
                for (auto const byte : *message)
                {
                    REQUIRE(static_cast<unsigned char>(byte) < 0x80U);
                }
                for (auto index = std::size_t{0U}; index < message->size(); ++index)
                {
                    if ((*message)[index] == '\n')
                    {
                        REQUIRE(index > 0U);
                        REQUIRE((*message)[index - 1U] == '\r');
                    }
                }
            }

            THEN("its headers address it from the server to the user")
            {
                REQUIRE(message.has_value());
                auto const headers = header_block(*message);
                REQUIRE(headers.find("From: matrix@example.org\r\n") != std::string::npos);
                REQUIRE(headers.find("To: alice@example.net\r\n") != std::string::npos);
                REQUIRE(headers.find("Date: Sat, 24 Oct 2026 09:05:07 +0000\r\n") != std::string::npos);
                REQUIRE(headers.find("Message-ID: <0123456789abcdef0123456789abcdef@example.org>\r\n") !=
                        std::string::npos);
                REQUIRE(headers.find("Auto-Submitted: auto-generated\r\n") != std::string::npos);
                REQUIRE(headers.find("Content-Type: text/plain; charset=us-ascii\r\n") != std::string::npos);
            }

            THEN("its subject and body give the count and the server")
            {
                REQUIRE(message.has_value());
                REQUIRE(header_block(*message).find("Subject: 3 unread notifications on example.org") !=
                        std::string::npos);
                auto const body = body_of(*message);
                REQUIRE(body.find('3') != std::string::npos);
                REQUIRE(body.find("example.org") != std::string::npos);
            }
        }
    }

    GIVEN("exactly one unread notification")
    {
        auto const message = build_unread_notification_email(sample_email(1U));

        WHEN("the subject is read")
        {
            auto const headers = message.has_value() ? header_block(*message) : std::string{};

            THEN("it is singular")
            {
                REQUIRE(headers.find("Subject: 1 unread notification on example.org\r\n") != std::string::npos);
            }
        }
    }

    GIVEN("a server name with a port")
    {
        auto email = sample_email();
        email.server_name = "example.org:8448";

        WHEN("the email is built")
        {
            auto const message = build_unread_notification_email(email);

            THEN("the Message-ID names the host without the port")
            {
                REQUIRE(message.has_value());
                REQUIRE(message->find("@example.org>\r\n") != std::string::npos);
                REQUIRE(message->find("@example.org:8448>") == std::string::npos);
            }
        }
    }

    GIVEN("inputs that cannot be written safely")
    {
        WHEN("the recipient carries a header injection")
        {
            auto email = sample_email();
            email.to = "alice@example.net\r\nBcc: mallory@example.org";

            THEN("no message is built")
            {
                REQUIRE_FALSE(build_unread_notification_email(email).has_value());
            }
        }

        WHEN("the sender is not a plain address")
        {
            auto email = sample_email();
            email.from = "Matrix <matrix@example.org>";

            THEN("no message is built")
            {
                REQUIRE_FALSE(build_unread_notification_email(email).has_value());
            }
        }

        WHEN("the server name carries a line break")
        {
            auto email = sample_email();
            email.server_name = "example.org\r\nBcc: mallory@example.org";

            THEN("no message is built")
            {
                REQUIRE_FALSE(build_unread_notification_email(email).has_value());
            }
        }

        WHEN("the Message-ID token is not lower-case hex of the documented length")
        {
            auto short_token = sample_email();
            short_token.message_id_token = "abc";
            auto upper = sample_email();
            upper.message_id_token = "0123456789ABCDEF";
            auto injected = sample_email();
            injected.message_id_token = "0123456789abcdef>\r\nX: y";

            THEN("no message is built")
            {
                REQUIRE_FALSE(build_unread_notification_email(short_token).has_value());
                REQUIRE_FALSE(build_unread_notification_email(upper).has_value());
                REQUIRE_FALSE(build_unread_notification_email(injected).has_value());
            }
        }

        WHEN("nothing is unread")
        {
            THEN("no message is built")
            {
                REQUIRE_FALSE(build_unread_notification_email(sample_email(0U)).has_value());
            }
        }
    }
}
