// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              EMAIL PUSHERS — END-TO-END INTEGRATION TESTS               |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19, POST /pushers/set — kind "email" |
// |  "makes a pusher that emails the user with unread notifications".       |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3pushersset |
// |                                                                         |
// |  Drives a real message send through push rule evaluation, the email     |
// |  digest queue and the email job's SMTP session against a mock relay on  |
// |  a loopback socket (ADR-0219, ADR-0220). The job is called directly     |
// |  with a clock past the delay, as the push retry tests call theirs.      |
// +-------------------------------------------------------------------------+

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/email/smtp_client.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/email_push.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/stop_flag.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <poll.h>
#include <sys/socket.h>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

constexpr auto smtp_host = std::string_view{"smtp.localhost.test"};
constexpr auto alice_address = std::string_view{"alice@example.net"};
constexpr auto relay_from = std::string_view{"matrix@example.org"};

enum class RelayMode : std::uint8_t
{
    // smtps://: TLS from the first byte.
    implicit_tls,
    // smtp://, advertising and accepting STARTTLS.
    starttls,
    // smtp://, never offering STARTTLS: a relay that would take mail in cleartext.
    cleartext,
};

// What one SMTP session sent the relay.
struct SmtpSession final
{
    std::vector<std::string> commands{};
    std::string data{};
    bool tls{false};
    bool message_accepted{false};
};

// A relay on a real loopback socket. It serves sessions until destroyed and records each one;
// the serving thread makes no assertions (Catch2 is not thread-safe), tests read sessions() from
// the main thread. Each session ends after QUIT, a closed connection, or five quiet seconds.
class MockSmtpRelay final
{
public:
    explicit MockSmtpRelay(RelayMode mode)
        : mode_{mode}
        , certificate_{tls_mock::write_test_tls_certificate(std::string{smtp_host})}
        , tls_{merovingian::homeserver::make_tls_server_context(certificate_.certificate_file,
                                                                certificate_.private_key_file)}
    {
        REQUIRE(tls_.ok());
        REQUIRE(acceptor_.bind("127.0.0.1", 0U).ok);
        REQUIRE(acceptor_.bound_port() > 0U);
        thread_ = std::thread{[this] {
            serve();
        }};
    }

    ~MockSmtpRelay()
    {
        stop_.store(true);
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    MockSmtpRelay(MockSmtpRelay const&) = delete;
    auto operator=(MockSmtpRelay const&) -> MockSmtpRelay& = delete;
    MockSmtpRelay(MockSmtpRelay&&) = delete;
    auto operator=(MockSmtpRelay&&) -> MockSmtpRelay& = delete;

    // Points `runtime` at this relay. A TLS relay is named by its certificate's host and pinned to
    // loopback with the self-signed certificate trusted; the cleartext relay is named by its
    // loopback literal, which is the only cleartext relay config validation allows.
    auto install(ClientServerRuntime& runtime, bool with_credentials = false) const -> void
    {
        auto& email_config = runtime.homeserver.config.server().email;
        auto const port = std::to_string(acceptor_.bound_port());
        switch (mode_)
        {
        case RelayMode::implicit_tls:
            email_config.smtp_url = "smtps://" + std::string{smtp_host} + ":" + port;
            email_config.require_tls = true;
            break;
        case RelayMode::starttls:
            email_config.smtp_url = "smtp://" + std::string{smtp_host} + ":" + port;
            email_config.require_tls = true;
            break;
        case RelayMode::cleartext:
            email_config.smtp_url = "smtp://127.0.0.1:" + port;
            email_config.require_tls = false;
            break;
        }
        email_config.from = std::string{relay_from};
        email_config.connect_timeout_seconds = 5U;
        email_config.total_timeout_seconds = 10U;
        if (with_credentials)
        {
            email_config.username = "mailer";
            email_config.password_file = password_file();
        }
        runtime.homeserver.test_forced_smtp_resolution =
            merovingian::email::SmtpTestResolution{{"127.0.0.1"}, certificate_.certificate_pem};
    }

    [[nodiscard]] auto sessions() const -> std::vector<SmtpSession>
    {
        auto const lock = std::lock_guard<std::mutex>{mutex_};
        return sessions_;
    }

    // Sessions in which a message was accepted (DATA ended with 250).
    [[nodiscard]] auto delivered() const -> std::vector<SmtpSession>
    {
        auto delivered = std::vector<SmtpSession>{};
        for (auto const& session : sessions())
        {
            if (session.message_accepted)
            {
                delivered.push_back(session);
            }
        }
        return delivered;
    }

private:
    // The SMTP AUTH password, in an owner-read-only file as the server requires of a secret file.
    [[nodiscard]] auto password_file() const -> std::string
    {
        auto const path = certificate_.directory / "smtp-password";
        if (!std::filesystem::exists(path))
        {
            auto stream = std::ofstream{path, std::ios::binary};
            stream << "hunter2-smtp\n";
            stream.close();
            std::filesystem::permissions(path, std::filesystem::perms::owner_read);
        }
        return path.string();
    }

    // Line I/O over the accepted socket, in cleartext until STARTTLS (or from the start for
    // implicit TLS) and through TLS after.
    class Channel final
    {
    public:
        explicit Channel(int fd) noexcept
            : fd_{fd}
        {
        }

        auto start_tls(merovingian::homeserver::TlsServerContext& context) -> bool
        {
            auto result = merovingian::homeserver::accept_tls_connection(context, fd_, 5000);
            if (!result.connection.has_value())
            {
                return false;
            }
            tls_.emplace(std::move(*result.connection));
            buffer_.clear();
            return true;
        }

        [[nodiscard]] auto tls() const noexcept -> bool
        {
            return tls_.has_value();
        }

        auto write(std::string_view text) -> void
        {
            if (tls_.has_value())
            {
                std::ignore = tls_->write(text);
                return;
            }
            std::ignore = ::send(fd_, text.data(), text.size(), MSG_NOSIGNAL);
        }

        // The next line without its CRLF, or nullopt when the peer closed or went quiet.
        [[nodiscard]] auto read_line() -> std::optional<std::string>
        {
            while (true)
            {
                auto const end = buffer_.find("\r\n");
                if (end != std::string::npos)
                {
                    auto line = buffer_.substr(0U, end);
                    buffer_.erase(0U, end + 2U);
                    return line;
                }
                auto chunk = std::array<char, 4096>{};
                auto received = std::ptrdiff_t{0};
                if (tls_.has_value())
                {
                    received = tls_->read(chunk.data(), chunk.size());
                }
                else
                {
                    auto entry = ::pollfd{fd_, POLLIN, 0};
                    if (::poll(&entry, 1U, 5000) <= 0)
                    {
                        return std::nullopt;
                    }
                    received = ::recv(fd_, chunk.data(), chunk.size(), 0);
                }
                if (received <= 0)
                {
                    return std::nullopt;
                }
                buffer_.append(chunk.data(), static_cast<std::size_t>(received));
            }
        }

    private:
        int fd_;
        std::optional<merovingian::homeserver::TlsConnection> tls_{};
        std::string buffer_{};
    };

    auto serve() noexcept -> void
    {
        while (!stop_.load())
        {
            auto const client_fd = tls_mock::accept_loopback(acceptor_, 50);
            if (client_fd < 0)
            {
                continue;
            }
            auto const owned = merovingian::core::SocketHandle{client_fd};
            try
            {
                serve_session(client_fd);
            }
            catch (...)
            {
                // A session that could not be recorded is simply not recorded.
            }
        }
    }

    auto serve_session(int client_fd) -> void
    {
        auto session = SmtpSession{};
        auto channel = Channel{client_fd};
        auto const record = [this, &session]() {
            auto const lock = std::lock_guard<std::mutex>{mutex_};
            sessions_.push_back(session);
        };
        if (mode_ == RelayMode::implicit_tls && !channel.start_tls(*tls_.context))
        {
            record();
            return;
        }
        channel.write("220 " + std::string{smtp_host} + " ESMTP mock\r\n");
        while (auto line = channel.read_line())
        {
            session.commands.push_back(*line);
            auto const verb = line->substr(0U, line->find(' '));
            if (verb == "EHLO" || verb == "HELO")
            {
                if (mode_ == RelayMode::starttls && !channel.tls())
                {
                    channel.write("250-" + std::string{smtp_host} + "\r\n250 STARTTLS\r\n");
                }
                else if (channel.tls())
                {
                    channel.write("250-" + std::string{smtp_host} + "\r\n250 AUTH PLAIN\r\n");
                }
                else
                {
                    channel.write("250 " + std::string{smtp_host} + "\r\n");
                }
            }
            else if (verb == "STARTTLS")
            {
                if (mode_ != RelayMode::starttls || channel.tls())
                {
                    channel.write("454 TLS not available\r\n");
                    continue;
                }
                channel.write("220 ready to start TLS\r\n");
                if (!channel.start_tls(*tls_.context))
                {
                    break;
                }
            }
            else if (verb == "AUTH")
            {
                if (*line == "AUTH PLAIN")
                {
                    channel.write("334 \r\n");
                    auto credentials = channel.read_line();
                    if (!credentials.has_value())
                    {
                        break;
                    }
                    session.commands.push_back(*credentials);
                }
                channel.write("235 authenticated\r\n");
            }
            else if (verb == "DATA")
            {
                channel.write("354 end with <CRLF>.<CRLF>\r\n");
                while (auto data_line = channel.read_line())
                {
                    if (*data_line == ".")
                    {
                        session.message_accepted = true;
                        break;
                    }
                    session.data += *data_line + "\r\n";
                }
                channel.write("250 queued\r\n");
            }
            else if (verb == "QUIT")
            {
                channel.write("221 bye\r\n");
                break;
            }
            else
            {
                channel.write("250 ok\r\n");
            }
            session.tls = channel.tls();
        }
        session.tls = session.tls || channel.tls();
        record();
    }

    RelayMode mode_;
    tls_mock::TlsTestCertificate certificate_;
    merovingian::homeserver::TlsServerContextResult tls_;
    merovingian::net::TcpAcceptor acceptor_{};
    std::atomic<bool> stop_{false};
    mutable std::mutex mutex_{};
    std::vector<SmtpSession> sessions_{};
    std::thread thread_{};
};

[[nodiscard]] auto email_test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest (0.12.5 audit,
    // finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto register_and_login(ClientServerRuntime& runtime, std::string const& localpart) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                      R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart + R"(_DEV"})"});
    REQUIRE(login.response.status == 200U);
    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// Alice and Bob in a two-member room; Alice holds alice@example.net as a 3PID and has an email
// pusher for it.
struct EmailFixture final
{
    std::string alice{};
    std::string bob{};
    std::string room_id{};
};

[[nodiscard]] auto alice_with_email_pusher(ClientServerRuntime& runtime) -> EmailFixture
{
    auto fixture = EmailFixture{};
    fixture.alice = register_and_login(runtime, "alice");
    fixture.bob = register_and_login(runtime, "bob");
    auto const create = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", fixture.alice,
                  R"({"preset":"private_chat","invite":["@bob:example.org"]})"});
    REQUIRE(create.response.status == 200U);
    auto const create_body = parse_object(create.response.body);
    auto const* room_id = string_member(create_body, "room_id");
    REQUIRE(room_id != nullptr);
    fixture.room_id = *room_id;
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + fixture.room_id + "/join", fixture.bob, "{}"})
                .response.status == 200U);

    auto binding = merovingian::database::PersistentThreePidBinding{};
    binding.user_id = "@alice:example.org";
    binding.medium = "email";
    binding.address = std::string{alice_address};
    binding.added_at_ms = 1700000000000U;
    binding.validated_at_ms = 1700000000000U;
    REQUIRE(merovingian::database::store_account_threepid(runtime.homeserver.database.persistent_store, binding));

    auto const pusher = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/pushers/set", fixture.alice,
                  R"({"app_display_name":"Mail","app_id":"m.email","data":{},"device_display_name":"Inbox",)"
                  R"("kind":"email","lang":"en","pushkey":")" +
                      std::string{alice_address} + R"("})"});
    REQUIRE(pusher.response.status == 200U);
    return fixture;
}

// Bob sends a message to the room. Returns its event ID.
auto bob_says(ClientServerRuntime& runtime, EmailFixture const& fixture, std::string const& txn_id,
              std::string const& text) -> std::string
{
    auto const sent = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + fixture.room_id + "/send/m.room.message/" + txn_id, fixture.bob,
                  R"({"msgtype":"m.text","body":")" + text + R"("})"});
    REQUIRE(sent.response.status == 200U);
    auto const body = parse_object(sent.response.body);
    auto const* event_id = string_member(body, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

// Runs the email job once with a clock past every delay and throttle the default policy sets.
auto run_email_job(ClientServerRuntime& runtime) -> void
{
    auto const stop = merovingian::homeserver::StopFlag{};
    std::ignore = merovingian::homeserver::send_due_email_notifications(
        runtime.homeserver, stop, std::chrono::steady_clock::now() + std::chrono::hours{2});
}

[[nodiscard]] auto contains(std::vector<std::string> const& lines, std::string_view needle) -> bool
{
    return std::ranges::any_of(lines, [needle](std::string const& line) {
        return line.find(needle) != std::string::npos;
    });
}

} // namespace

SCENARIO("A notification for an email pusher is mailed, as an unread count only, after the delay",
         "[integration][push][email]")
{
    GIVEN("an implicit-TLS relay with SMTP AUTH and Alice's email pusher")
    {
        auto const relay = MockSmtpRelay{RelayMode::implicit_tls};
        auto started = merovingian::homeserver::start_client_server(email_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        relay.install(runtime, true);
        auto const fixture = alice_with_email_pusher(runtime);

        WHEN("Bob sends a message and the email job runs once the delay has passed")
        {
            std::ignore = bob_says(runtime, fixture, "txn1", "secret lunch plans");
            REQUIRE(relay.sessions().empty());
            run_email_job(runtime);
            auto const delivered = relay.delivered();

            THEN("one email went to Alice's address from the configured sender, over TLS, after AUTH")
            {
                REQUIRE(delivered.size() == 1U);
                auto const& session = delivered.front();
                REQUIRE(session.tls);
                REQUIRE(contains(session.commands, "MAIL FROM:<matrix@example.org>"));
                REQUIRE(contains(session.commands, "RCPT TO:<alice@example.net>"));
                REQUIRE(contains(session.commands, "AG1haWxlcgBodW50ZXIyLXNtdHA="));
            }

            THEN("it gives the unread count and none of the message")
            {
                REQUIRE(delivered.size() == 1U);
                auto const& data = delivered.front().data;
                REQUIRE(data.find("Subject: 1 unread notification on example.org") != std::string::npos);
                REQUIRE(data.find("To: alice@example.net") != std::string::npos);
                REQUIRE(data.find("lunch") == std::string::npos);
                REQUIRE(data.find("@bob:example.org") == std::string::npos);
                REQUIRE(data.find(fixture.room_id) == std::string::npos);
            }

            THEN("nothing more is due")
            {
                REQUIRE_FALSE(runtime.homeserver.email_digest_queue_->next_due().has_value());
            }
        }

        WHEN("Bob sends two messages before the email is due")
        {
            std::ignore = bob_says(runtime, fixture, "txn1", "one");
            std::ignore = bob_says(runtime, fixture, "txn2", "two");
            run_email_job(runtime);

            THEN("one email reports both")
            {
                auto const delivered = relay.delivered();
                REQUIRE(delivered.size() == 1U);
                REQUIRE(delivered.front().data.find("Subject: 2 unread notifications") != std::string::npos);
            }
        }
    }
}

SCENARIO("No email is sent when the user has read everything before it is due", "[integration][push][email]")
{
    GIVEN("a relay and Alice's email pusher")
    {
        auto const relay = MockSmtpRelay{RelayMode::implicit_tls};
        auto started = merovingian::homeserver::start_client_server(email_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        relay.install(runtime);
        auto const fixture = alice_with_email_pusher(runtime);

        WHEN("Bob sends a message, Alice reads it on another device, and the email job runs")
        {
            auto const event_id = bob_says(runtime, fixture, "txn1", "hello");
            auto const receipt = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + fixture.room_id + "/receipt/m.read/" + event_id,
                          fixture.alice, "{}"});
            REQUIRE(receipt.response.status == 200U);
            run_email_job(runtime);

            THEN("the relay is never contacted and nothing is left due")
            {
                REQUIRE(relay.sessions().empty());
                REQUIRE_FALSE(runtime.homeserver.email_digest_queue_->next_due().has_value());
            }
        }
    }
}

SCENARIO("An email pusher whose address has left the account sends nothing and is removed",
         "[integration][push][email][security]")
{
    GIVEN("a relay and Alice's email pusher with a notification due")
    {
        auto const relay = MockSmtpRelay{RelayMode::implicit_tls};
        auto started = merovingian::homeserver::start_client_server(email_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        relay.install(runtime);
        auto const fixture = alice_with_email_pusher(runtime);
        std::ignore = bob_says(runtime, fixture, "txn1", "hello");

        WHEN("the address stops being Alice's 3PID by a path that leaves the pusher, and the job runs")
        {
            // Directly in the store: the client API's 3PID delete removes the pusher itself, which
            // test_client_server_conformance.cpp covers. This is the job's own re-check.
            REQUIRE(merovingian::database::delete_account_threepid(runtime.homeserver.database.persistent_store,
                                                                   "@alice:example.org", "email", alice_address));
            run_email_job(runtime);

            THEN("no email is sent and the pusher is gone")
            {
                REQUIRE(relay.sessions().empty());
                REQUIRE(merovingian::database::list_pushers_for_user(runtime.homeserver.database.persistent_store,
                                                                     "@alice:example.org")
                            .empty());
            }
        }
    }
}

SCENARIO("Deleting an email pusher drops the email due to it", "[integration][push][email]")
{
    GIVEN("a relay and Alice's email pusher with a notification due")
    {
        auto const relay = MockSmtpRelay{RelayMode::implicit_tls};
        auto started = merovingian::homeserver::start_client_server(email_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        relay.install(runtime);
        auto const fixture = alice_with_email_pusher(runtime);
        std::ignore = bob_says(runtime, fixture, "txn1", "hello");
        auto const due_before_delete = runtime.homeserver.email_digest_queue_->next_due().has_value();

        WHEN("Alice deletes the pusher with kind null and the email job runs")
        {
            auto const deleted = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/pushers/set", fixture.alice,
                          R"({"app_id":"m.email","kind":null,"pushkey":")" + std::string{alice_address} + R"("})"});
            auto const due_after_delete = runtime.homeserver.email_digest_queue_->next_due().has_value();
            run_email_job(runtime);

            THEN("the email that was due is dropped and the relay is never contacted")
            {
                REQUIRE(due_before_delete);
                REQUIRE(deleted.response.status == 200U);
                REQUIRE_FALSE(due_after_delete);
                REQUIRE(relay.sessions().empty());
            }
        }
    }
}

SCENARIO("A submission relay must start TLS before mail is sent to it", "[integration][push][email][security]")
{
    GIVEN("a relay that offers STARTTLS")
    {
        auto const relay = MockSmtpRelay{RelayMode::starttls};
        auto started = merovingian::homeserver::start_client_server(email_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        relay.install(runtime);
        auto const fixture = alice_with_email_pusher(runtime);

        WHEN("an email is due")
        {
            std::ignore = bob_says(runtime, fixture, "txn1", "hello");
            run_email_job(runtime);

            THEN("it is delivered after STARTTLS")
            {
                auto const delivered = relay.delivered();
                REQUIRE(delivered.size() == 1U);
                REQUIRE(delivered.front().tls);
                REQUIRE(contains(delivered.front().commands, "STARTTLS"));
            }
        }
    }

    GIVEN("a relay that never offers STARTTLS, configured with TLS required")
    {
        auto const relay = MockSmtpRelay{RelayMode::cleartext};
        auto started = merovingian::homeserver::start_client_server(email_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        relay.install(runtime);
        auto& email_config = runtime.homeserver.config.server().email;
        email_config.smtp_url = "smtp://" + std::string{smtp_host} + ":" +
                                email_config.smtp_url.substr(email_config.smtp_url.rfind(':') + 1U);
        email_config.require_tls = true;
        auto const fixture = alice_with_email_pusher(runtime);

        WHEN("an email is due")
        {
            std::ignore = bob_says(runtime, fixture, "txn1", "hello");
            run_email_job(runtime);

            THEN("no envelope or message is sent in cleartext, and the email is due again later")
            {
                REQUIRE_FALSE(relay.sessions().empty());
                for (auto const& session : relay.sessions())
                {
                    REQUIRE_FALSE(session.message_accepted);
                    REQUIRE_FALSE(contains(session.commands, "MAIL FROM"));
                    REQUIRE_FALSE(contains(session.commands, "RCPT TO"));
                }
                REQUIRE(runtime.homeserver.email_digest_queue_->next_due().has_value());
            }
        }
    }
}

SCENARIO("A cleartext relay at a loopback literal is used when TLS is explicitly not required",
         "[integration][push][email]")
{
    GIVEN("a local cleartext relay with require_tls=false")
    {
        auto const relay = MockSmtpRelay{RelayMode::cleartext};
        auto started = merovingian::homeserver::start_client_server(email_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        relay.install(runtime);
        auto const fixture = alice_with_email_pusher(runtime);

        WHEN("an email is due")
        {
            std::ignore = bob_says(runtime, fixture, "txn1", "hello");
            run_email_job(runtime);

            THEN("it is delivered")
            {
                auto const delivered = relay.delivered();
                REQUIRE(delivered.size() == 1U);
                REQUIRE_FALSE(delivered.front().tls);
            }
        }
    }
}
