// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |        APPLICATION SERVICE TRANSACTION QUEUE (AUDIT R01)                |
// |                                                                         |
// |  Spec: Matrix Application Service API v1.19, "Pushing events".          |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// |                                                                         |
// |  "The homeserver MUST maintain a queue of transactions to send to the   |
// |  application service. If the application service cannot be reached,     |
// |  the homeserver SHOULD backoff exponentially ... Homeservers MUST NOT   |
// |  alter (e.g. add more) events they were going to send within that       |
// |  transaction ID on retries."                                            |
// |                                                                         |
// |  These drive a real mock appservice on loopback and assert on the       |
// |  transactions it actually received: which events, in which order, under |
// |  which transaction IDs. The drainer is called directly with a stepped   |
// |  clock, so no test sleeps and no PeriodicJob thread runs.               |
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/appservice_delivery.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

#include <poll.h>
#include <unistd.h>

namespace
{

using namespace std::chrono_literals;
using merovingian::homeserver::ClientServerRuntime;

struct CapturedRequest final
{
    std::string target{};
    std::string body{};
    std::uint16_t status{0U};
};

// A loopback appservice that answers every request with 200 while "up" and 503
// while "down", and records each request it saw. It runs on its own thread, so
// the request log is read through a copy taken under its mutex, and every
// assertion stays on the test thread.
class MockAppservice final
{
public:
    MockAppservice()
    {
        REQUIRE(acceptor_.bind("127.0.0.1", 0U).ok);
        port_ = acceptor_.bound_port();
        REQUIRE(port_ > 0U);
        thread_ = std::thread{[this] {
            serve();
        }};
    }

    MockAppservice(MockAppservice const&) = delete;
    MockAppservice(MockAppservice&&) = delete;
    auto operator=(MockAppservice const&) -> MockAppservice& = delete;
    auto operator=(MockAppservice&&) -> MockAppservice& = delete;

    ~MockAppservice()
    {
        stop_.store(true);
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    [[nodiscard]] auto port() const noexcept -> std::uint16_t
    {
        return port_;
    }

    auto set_up(bool up) noexcept -> void
    {
        up_.store(up);
    }

    [[nodiscard]] auto requests() const -> std::vector<CapturedRequest>
    {
        auto const lock = std::lock_guard{mutex_};
        return requests_;
    }

private:
    [[nodiscard]] static auto content_length_of(std::string const& head) -> std::size_t
    {
        auto lowered = head;
        std::ranges::transform(lowered, lowered.begin(), [](char c) {
            return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        });
        auto const key = std::string{"content-length:"};
        auto const at = lowered.find(key);
        if (at == std::string::npos)
        {
            return 0U;
        }
        return static_cast<std::size_t>(std::stoull(lowered.substr(at + key.size())));
    }

    auto serve() noexcept -> void
    {
        while (!stop_.load())
        {
            auto const client_fd = merovingian::tests::tls_mock::accept_loopback(acceptor_, 25);
            if (client_fd < 0)
            {
                continue;
            }
            handle(client_fd);
            ::close(client_fd);
        }
    }

    auto handle(int client_fd) -> void
    {
        auto buffer = std::array<char, 8192>{};
        auto received = std::string{};
        auto const read_some = [&]() {
            auto pollfd_entry = ::pollfd{client_fd, POLLIN, 0};
            if (::poll(&pollfd_entry, 1U, 2000) <= 0)
            {
                return false;
            }
            auto const bytes_read = ::read(client_fd, buffer.data(), buffer.size());
            if (bytes_read <= 0)
            {
                return false;
            }
            received.append(buffer.data(), static_cast<std::size_t>(bytes_read));
            return true;
        };
        while (received.find("\r\n\r\n") == std::string::npos)
        {
            if (!read_some())
            {
                return;
            }
        }
        auto const head_end = received.find("\r\n\r\n") + 4U;
        auto const expected = content_length_of(received.substr(0U, head_end));
        while (received.size() - head_end < expected)
        {
            if (!read_some())
            {
                return;
            }
        }

        auto const request_line_end = received.find("\r\n");
        auto const request_line = received.substr(0U, request_line_end);
        auto const target_begin = request_line.find(' ') + 1U;
        auto const target_end = request_line.find(' ', target_begin);
        auto const up = up_.load();
        auto captured = CapturedRequest{};
        captured.target = request_line.substr(target_begin, target_end - target_begin);
        captured.body = received.substr(head_end, expected);
        captured.status = up ? 200U : 503U;
        {
            auto const lock = std::lock_guard{mutex_};
            requests_.push_back(std::move(captured));
        }
        auto const response = merovingian::tests::tls_mock::json_http_response(up ? "200 OK" : "503 Service Unavailable",
                                                                               up ? "{}" : R"({"error":"down"})");
        std::ignore = ::write(client_fd, response.data(), response.size());
    }

    merovingian::net::TcpAcceptor acceptor_{};
    std::uint16_t port_{0U};
    std::atomic<bool> stop_{false};
    std::atomic<bool> up_{true};
    mutable std::mutex mutex_{};
    std::vector<CapturedRequest> requests_{};
    std::thread thread_{};
};

[[nodiscard]] auto unique_path(std::string_view stem, std::string_view extension) -> std::filesystem::path
{
    static auto counter = std::atomic<std::uint64_t>{0U};
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           (std::string{stem} + "-" + std::to_string(now) + "-" + std::to_string(counter.fetch_add(1U)) +
            std::string{extension});
}

// An appservice that claims every room, so every event in every room is
// interesting to it. `url` is empty for `url: null` (a disabled appservice).
[[nodiscard]] auto write_registration(std::string_view id, std::string_view url, std::string_view namespaces_json)
    -> std::filesystem::path
{
    auto const path = unique_path("merovingian-as-delivery-" + std::string{id}, ".json");
    auto out = std::ofstream{path, std::ios::binary};
    out << R"({"id": ")" << id << R"(", "url": )";
    if (url.empty())
    {
        out << "null";
    }
    else
    {
        out << '"' << url << '"';
    }
    out << R"(, "as_token": "as-token-)" << id << R"(", "hs_token": "hs-token-)" << id
        << R"(", "sender_localpart": "_)" << id << R"(_bot", "namespaces": )" << namespaces_json
        << R"(, "protocols": []})";
    return path;
}

constexpr auto every_room_namespaces = std::string_view{
    R"({"users": [], "aliases": [], "rooms": [{"exclusive": false, "regex": ".*"}]})"};
constexpr auto no_room_namespaces = std::string_view{
    R"({"users": [{"exclusive": true, "regex": "@_never_.*"}], "aliases": [], "rooms": []})"};

[[nodiscard]] auto config_for(std::vector<std::filesystem::path> const& registrations,
                              std::optional<std::filesystem::path> const& sqlite_path = std::nullopt)
    -> merovingian::config::Config
{
    auto database = merovingian::tests::in_memory_database_config();
    if (sqlite_path.has_value())
    {
        database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        database.sqlite_path = sqlite_path->string();
    }
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        database,
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
    for (auto const& registration : registrations)
    {
        config.appservice().registration_files.push_back(registration.string());
    }
    return config;
}

[[nodiscard]] auto json_string_member(std::string const& body, std::string const& key) -> std::string
{
    auto const needle = "\"" + key + "\":\"";
    auto const begin = body.find(needle);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + needle.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto register_alice(ClientServerRuntime& runtime) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/register", {},
                  merovingian::tests::registration_json("alice", "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    return json_string_member(reg.response.body, "access_token");
}

[[nodiscard]] auto create_room(ClientServerRuntime& runtime, std::string const& token) -> std::string
{
    auto const created = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
    REQUIRE(created.response.status == 200U);
    return json_string_member(created.response.body, "room_id");
}

auto send_message(ClientServerRuntime& runtime, std::string const& token, std::string const& room_id,
                  std::string const& text) -> void
{
    auto const sent = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn-" + text, token,
                  R"({"msgtype":"m.text","body":")" + text + R"("})"});
    REQUIRE(sent.response.status == 200U);
}

// Steps a synthetic steady clock so the drainer's backoff never makes a test
// sleep: every advance is longer than the backoff cap.
struct SteppedClock final
{
    std::chrono::steady_clock::time_point now{std::chrono::steady_clock::now()};

    [[nodiscard]] auto advance() -> std::chrono::steady_clock::time_point
    {
        now += 10min;
        return now;
    }
};

[[nodiscard]] auto drain_once(ClientServerRuntime& runtime, std::chrono::steady_clock::time_point now)
    -> std::chrono::milliseconds
{
    auto const stop = std::stop_source{};
    return merovingian::homeserver::drain_appservice_queues(runtime.homeserver, stop.get_token(), now);
}

[[nodiscard]] auto queues_are_idle(ClientServerRuntime& runtime) -> bool
{
    auto const& store = runtime.homeserver.database.persistent_store;
    return store.appservice_outbox.empty() &&
           std::ranges::all_of(store.appservice_txn_cursors, [](auto const& cursor) {
               return cursor.pending_txn_id == 0U;
           });
}

// Drains with the appservice reachable until nothing is queued or in flight.
auto drain_until_idle(ClientServerRuntime& runtime, SteppedClock& clock) -> void
{
    for (auto attempt = 0U; attempt < 50U && !queues_are_idle(runtime); ++attempt)
    {
        std::ignore = drain_once(runtime, clock.advance());
    }
    REQUIRE(queues_are_idle(runtime));
}

[[nodiscard]] auto txn_id_of(CapturedRequest const& request) -> std::uint64_t
{
    auto const path = request.target.substr(0U, request.target.find('?'));
    return std::stoull(path.substr(path.rfind('/') + 1U));
}

[[nodiscard]] auto occurrences(std::string const& haystack, std::string_view needle) -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto at = haystack.find(needle); at != std::string::npos; at = haystack.find(needle, at + needle.size()))
    {
        ++count;
    }
    return count;
}

// The requests that arrived after the first `skip`, optionally only the ones the appservice accepted.
[[nodiscard]] auto requests_after(MockAppservice const& mock, std::size_t skip, bool accepted_only)
    -> std::vector<CapturedRequest>
{
    auto all = mock.requests();
    auto out = std::vector<CapturedRequest>{};
    for (auto index = skip; index < all.size(); ++index)
    {
        if (!accepted_only || all[index].status == 200U)
        {
            out.push_back(all[index]);
        }
    }
    return out;
}

// Which of the named message bodies a transaction carries, in the order given.
[[nodiscard]] auto messages_in(CapturedRequest const& request, std::vector<std::string> const& texts)
    -> std::vector<std::string>
{
    auto out = std::vector<std::string>{};
    for (auto const& text : texts)
    {
        if (request.body.find("\"body\":\"" + text + "\"") != std::string::npos)
        {
            out.push_back(text);
        }
    }
    return out;
}

} // namespace

SCENARIO("events queued while an appservice is down reach it in order, each in its own transaction, once it recovers",
         "[appservice][r01][integration]")
{
    GIVEN("an appservice that claims every room, a room, and the appservice currently down")
    {
        auto mock = MockAppservice{};
        auto const registration =
            write_registration("bridge", "http://127.0.0.1:" + std::to_string(mock.port()), every_room_namespaces);
        auto started = merovingian::homeserver::start_client_server(config_for({registration}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = SteppedClock{};
        auto const token = register_alice(runtime);
        auto const room_id = create_room(runtime, token);
        drain_until_idle(runtime, clock);
        auto const baseline = mock.requests().size();

        mock.set_up(false);
        send_message(runtime, token, room_id, "msg-A");
        send_message(runtime, token, room_id, "msg-B");

        WHEN("a drain fails, the appservice recovers, a third event is sent and the queue drains")
        {
            std::ignore = drain_once(runtime, clock.advance());
            auto const failed_attempts = requests_after(mock, baseline, false);
            mock.set_up(true);
            send_message(runtime, token, room_id, "msg-C");
            drain_until_idle(runtime, clock);
            auto const accepted = requests_after(mock, baseline, true);

            THEN("it received A, B and C in that order, one event per transaction")
            {
                auto delivered = std::vector<std::string>{};
                for (auto const& request : accepted)
                {
                    REQUIRE(occurrences(request.body, "\"event_id\"") == 1U);
                    for (auto const& text : messages_in(request, {"msg-A", "msg-B", "msg-C"}))
                    {
                        delivered.push_back(text);
                    }
                }
                REQUIRE(delivered == std::vector<std::string>{"msg-A", "msg-B", "msg-C"});
            }

            THEN("transaction IDs strictly increase and are never reused for different contents")
            {
                REQUIRE_FALSE(accepted.empty());
                for (auto index = std::size_t{1U}; index < accepted.size(); ++index)
                {
                    REQUIRE(txn_id_of(accepted[index]) > txn_id_of(accepted[index - 1U]));
                }
            }

            THEN("the failed attempt and its successful retry used the same transaction ID and identical body")
            {
                REQUIRE(failed_attempts.size() == 1U);
                REQUIRE_FALSE(accepted.empty());
                REQUIRE(accepted.front().target == failed_attempts.front().target);
                REQUIRE(accepted.front().body == failed_attempts.front().body);
                REQUIRE(messages_in(accepted.front(), {"msg-A", "msg-B", "msg-C"}) ==
                        std::vector<std::string>{"msg-A"});
            }
        }
    }
}

SCENARIO("a queued event is delivered after the appservice recovers even if no further room traffic arrives",
         "[appservice][r01][integration]")
{
    GIVEN("an appservice that is down while an event is sent, and a failed first attempt")
    {
        auto mock = MockAppservice{};
        auto const registration =
            write_registration("bridge", "http://127.0.0.1:" + std::to_string(mock.port()), every_room_namespaces);
        auto started = merovingian::homeserver::start_client_server(config_for({registration}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = SteppedClock{};
        auto const token = register_alice(runtime);
        auto const room_id = create_room(runtime, token);
        drain_until_idle(runtime, clock);
        auto const baseline = mock.requests().size();

        mock.set_up(false);
        send_message(runtime, token, room_id, "msg-A");
        std::ignore = drain_once(runtime, clock.advance());

        WHEN("the appservice recovers and nothing else happens in any room")
        {
            mock.set_up(true);
            drain_until_idle(runtime, clock);
            auto const accepted = requests_after(mock, baseline, true);

            THEN("the event is delivered")
            {
                auto delivered = std::vector<std::string>{};
                for (auto const& request : accepted)
                {
                    for (auto const& text : messages_in(request, {"msg-A"}))
                    {
                        delivered.push_back(text);
                    }
                }
                REQUIRE(delivered == std::vector<std::string>{"msg-A"});
            }
        }
    }
}

SCENARIO("an event queued while the appservice is down survives a restart and is delivered afterwards",
         "[appservice][r01][integration][restart]")
{
    GIVEN("a SQLite-backed runtime holding an undelivered event for an unreachable appservice")
    {
        auto mock = MockAppservice{};
        auto const registration =
            write_registration("bridge", "http://127.0.0.1:" + std::to_string(mock.port()), every_room_namespaces);
        auto const sqlite_path = unique_path("merovingian-as-delivery-restart", ".sqlite3");
        auto const config = config_for({registration}, sqlite_path);
        auto clock = SteppedClock{};
        auto baseline = std::size_t{0U};
        {
            auto first = merovingian::homeserver::start_client_server(config);
            REQUIRE(first.started);
            auto const token = register_alice(first.runtime);
            auto const room_id = create_room(first.runtime, token);
            drain_until_idle(first.runtime, clock);
            baseline = mock.requests().size();
            mock.set_up(false);
            send_message(first.runtime, token, room_id, "msg-A");
            std::ignore = drain_once(first.runtime, clock.advance());
        }

        WHEN("the server restarts, the appservice is reachable again and the queue drains")
        {
            mock.set_up(true);
            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            drain_until_idle(restarted.runtime, clock);
            auto const accepted = requests_after(mock, baseline, true);

            THEN("the event is delivered, the outbox is empty and no transaction is left pending")
            {
                auto delivered = std::vector<std::string>{};
                for (auto const& request : accepted)
                {
                    for (auto const& text : messages_in(request, {"msg-A"}))
                    {
                        delivered.push_back(text);
                    }
                }
                REQUIRE(delivered == std::vector<std::string>{"msg-A"});
                auto const& store = restarted.runtime.homeserver.database.persistent_store;
                REQUIRE(store.appservice_outbox.empty());
                REQUIRE(merovingian::database::find_appservice_txn_cursor(store, "bridge").pending_txn_id == 0U);
            }
        }
        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("a failed delivery backs the appservice off instead of being retried at once",
         "[appservice][r01][integration][backoff]")
{
    GIVEN("an unreachable appservice and an event queued for it")
    {
        auto mock = MockAppservice{};
        auto const registration =
            write_registration("bridge", "http://127.0.0.1:" + std::to_string(mock.port()), every_room_namespaces);
        auto started = merovingian::homeserver::start_client_server(config_for({registration}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = SteppedClock{};
        auto const token = register_alice(runtime);
        auto const room_id = create_room(runtime, token);
        drain_until_idle(runtime, clock);
        mock.set_up(false);
        send_message(runtime, token, room_id, "msg-A");
        auto const before = mock.requests().size();
        auto const failed_at = clock.advance();
        std::ignore = drain_once(runtime, failed_at);
        auto const after_first = mock.requests().size();

        WHEN("the queue is drained again at the same instant")
        {
            auto const delay = drain_once(runtime, failed_at);

            THEN("the appservice is not called and the caller is told to come back later")
            {
                REQUIRE(after_first == before + 1U);
                REQUIRE(mock.requests().size() == after_first);
                REQUIRE(delay > 0ms);
                REQUIRE(delay <= 5min);
            }
        }

        WHEN("the queue is drained after the backoff has passed and the appservice fails again")
        {
            std::ignore = drain_once(runtime, failed_at + 1h);

            THEN("the appservice is called again with the same transaction")
            {
                auto const all = mock.requests();
                REQUIRE(all.size() == after_first + 1U);
                REQUIRE(all.back().target == all[after_first - 1U].target);
                REQUIRE(all.back().body == all[after_first - 1U].body);
            }
        }
    }
}

SCENARIO("only appservices interested in an event are queued for it, and a disabled appservice drains without network",
         "[appservice][r01][integration]")
{
    GIVEN("one appservice claiming every room, one claiming none, and one with url null claiming every room")
    {
        auto interested = MockAppservice{};
        auto uninterested = MockAppservice{};
        auto const interested_registration = write_registration(
            "bridge", "http://127.0.0.1:" + std::to_string(interested.port()), every_room_namespaces);
        auto const uninterested_registration = write_registration(
            "other", "http://127.0.0.1:" + std::to_string(uninterested.port()), no_room_namespaces);
        auto const disabled_registration = write_registration("quiet", "", every_room_namespaces);
        auto started = merovingian::homeserver::start_client_server(
            config_for({interested_registration, uninterested_registration, disabled_registration}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = SteppedClock{};
        auto const token = register_alice(runtime);
        auto const room_id = create_room(runtime, token);
        send_message(runtime, token, room_id, "msg-A");

        WHEN("the queues are drained")
        {
            drain_until_idle(runtime, clock);

            THEN("the uninterested appservice received nothing and has nothing queued")
            {
                REQUIRE(uninterested.requests().empty());
                auto const& store = runtime.homeserver.database.persistent_store;
                REQUIRE(std::ranges::none_of(store.appservice_outbox, [](auto const& row) {
                    return row.appservice_id == "other";
                }));
            }

            THEN("the interested appservice received the event")
            {
                auto delivered = false;
                for (auto const& request : interested.requests())
                {
                    delivered = delivered || !messages_in(request, {"msg-A"}).empty();
                }
                REQUIRE(delivered);
            }

            THEN("the disabled appservice's queue is emptied and its cursor advanced")
            {
                auto const& store = runtime.homeserver.database.persistent_store;
                REQUIRE(std::ranges::none_of(store.appservice_outbox, [](auto const& row) {
                    return row.appservice_id == "quiet";
                }));
                auto const cursor = merovingian::database::find_appservice_txn_cursor(store, "quiet");
                REQUIRE(cursor.pending_txn_id == 0U);
                REQUIRE(cursor.delivered_stream_ordering > 0U);
            }
        }
    }
}

SCENARIO("an outbox row whose event is missing is dropped so the queue cannot wedge",
         "[appservice][r01][integration]")
{
    GIVEN("an outbox row naming an event the store does not hold, ahead of a real event")
    {
        auto mock = MockAppservice{};
        auto const registration =
            write_registration("bridge", "http://127.0.0.1:" + std::to_string(mock.port()), every_room_namespaces);
        auto started = merovingian::homeserver::start_client_server(config_for({registration}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = SteppedClock{};
        auto const token = register_alice(runtime);
        auto const room_id = create_room(runtime, token);
        drain_until_idle(runtime, clock);
        auto const baseline = mock.requests().size();
        auto& store = runtime.homeserver.database.persistent_store;
        REQUIRE(merovingian::database::enqueue_appservice_event(store, {"bridge", 1U, "$vanished:example.org"}));
        send_message(runtime, token, room_id, "msg-A");

        WHEN("the queue is drained")
        {
            drain_until_idle(runtime, clock);

            THEN("the unreadable row is gone and the real event was still delivered")
            {
                REQUIRE(queues_are_idle(runtime));
                auto delivered = false;
                for (auto const& request : requests_after(mock, baseline, true))
                {
                    delivered = delivered || !messages_in(request, {"msg-A"}).empty();
                }
                REQUIRE(delivered);
            }
        }
    }
}

SCENARIO("a transaction left pending by the previous delivery design is retried under its own ID",
         "[appservice][r01][integration][upgrade]")
{
    GIVEN("a cursor with a pending transaction for a stored event and an empty outbox")
    {
        auto mock = MockAppservice{};
        auto const registration =
            write_registration("bridge", "http://127.0.0.1:" + std::to_string(mock.port()), every_room_namespaces);
        auto started = merovingian::homeserver::start_client_server(config_for({registration}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = SteppedClock{};
        auto const token = register_alice(runtime);
        std::ignore = create_room(runtime, token);
        drain_until_idle(runtime, clock);
        auto& store = runtime.homeserver.database.persistent_store;
        REQUIRE_FALSE(store.events.empty());
        auto const& pending_event = store.events.back();
        auto cursor = merovingian::database::find_appservice_txn_cursor(store, "bridge");
        cursor.pending_txn_id = 900U;
        cursor.next_txn_id = 901U;
        cursor.pending_stream_ordering = pending_event.stream_ordering;
        REQUIRE(merovingian::database::store_appservice_txn_cursor(store, cursor));
        auto const baseline = mock.requests().size();

        WHEN("the queue is drained")
        {
            drain_until_idle(runtime, clock);

            THEN("transaction 900 carries that event and the cursor is clear afterwards")
            {
                auto const accepted = requests_after(mock, baseline, true);
                REQUIRE(accepted.size() == 1U);
                REQUIRE(txn_id_of(accepted.front()) == 900U);
                REQUIRE(accepted.front().body.find(pending_event.event_id) != std::string::npos);
                REQUIRE(merovingian::database::find_appservice_txn_cursor(store, "bridge").pending_txn_id == 0U);
            }
        }
    }
}

SCENARIO("a drain asked to stop makes no call", "[appservice][r01][integration]")
{
    GIVEN("a queued event and a stop already requested")
    {
        auto mock = MockAppservice{};
        auto const registration =
            write_registration("bridge", "http://127.0.0.1:" + std::to_string(mock.port()), every_room_namespaces);
        auto started = merovingian::homeserver::start_client_server(config_for({registration}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_alice(runtime);
        std::ignore = create_room(runtime, token);
        auto stop = std::stop_source{};
        stop.request_stop();

        WHEN("the queue is drained")
        {
            std::ignore = merovingian::homeserver::drain_appservice_queues(runtime.homeserver, stop.get_token(),
                                                                           std::chrono::steady_clock::now());

            THEN("the appservice is not called and the events stay queued")
            {
                REQUIRE(mock.requests().empty());
                REQUIRE_FALSE(runtime.homeserver.database.persistent_store.appservice_outbox.empty());
            }
        }
    }
}

SCENARIO("the outbox accepts a late event with a lower stream ordering than one already delivered",
         "[appservice][r01][database]")
{
    GIVEN("an outbox whose stream ordering 10 has been delivered")
    {
        auto store = merovingian::database::PersistentStore{};
        REQUIRE(merovingian::database::enqueue_appservice_event(store, {"bridge", 10U, "$ten:example.org"}));
        auto const first = merovingian::database::find_first_appservice_outbox_entry(store, "bridge");
        REQUIRE(first.has_value());
        REQUIRE(merovingian::database::complete_appservice_delivery(store, "bridge", first->stream_ordering));

        WHEN("an event with stream ordering 5 (committed late by another room) is enqueued")
        {
            REQUIRE(merovingian::database::enqueue_appservice_event(store, {"bridge", 5U, "$five:example.org"}));

            THEN("it is queued, not dropped for being behind the delivered high-water mark")
            {
                auto const next = merovingian::database::find_first_appservice_outbox_entry(store, "bridge");
                REQUIRE(next.has_value());
                REQUIRE(next->event_id == "$five:example.org");
            }

            THEN("completing it leaves the high-water mark at 10")
            {
                REQUIRE(merovingian::database::complete_appservice_delivery(store, "bridge", 5U));
                auto const cursor = merovingian::database::find_appservice_txn_cursor(store, "bridge");
                REQUIRE(cursor.delivered_stream_ordering == 10U);
                REQUIRE(store.appservice_outbox.empty());
            }
        }
    }
}

SCENARIO("enqueueing the same event twice leaves one row, and the oldest row is served first",
         "[appservice][r01][database]")
{
    GIVEN("rows enqueued out of order, one of them twice")
    {
        auto store = merovingian::database::PersistentStore{};
        REQUIRE(merovingian::database::enqueue_appservice_event(store, {"bridge", 30U, "$c:example.org"}));
        REQUIRE(merovingian::database::enqueue_appservice_event(store, {"bridge", 20U, "$b:example.org"}));
        REQUIRE(merovingian::database::enqueue_appservice_event(store, {"bridge", 20U, "$b:example.org"}));
        REQUIRE(merovingian::database::enqueue_appservice_event(store, {"other", 10U, "$a:example.org"}));

        WHEN("the first row for the appservice is read")
        {
            auto const first = merovingian::database::find_first_appservice_outbox_entry(store, "bridge");

            THEN("it is the lowest stream ordering for that appservice only, and no row was duplicated")
            {
                REQUIRE(first.has_value());
                REQUIRE(first->stream_ordering == 20U);
                REQUIRE(store.appservice_outbox.size() == 3U);
                REQUIRE_FALSE(merovingian::database::find_first_appservice_outbox_entry(store, "nobody").has_value());
            }
        }
    }
}
