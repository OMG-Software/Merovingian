// SPDX-License-Identifier: GPL-3.0-or-later
// OUT-3: docs/security-audit-report-2026-09-29.md:1836-1851.
// This covers cross-user delivery isolation only, not registration limits,
// gateway circuits, retries, or fairness within a mixed-recipient event.

#include "../support/joining_threads.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/push/push_gateway_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;
using namespace std::chrono_literals;
namespace canonicaljson = merovingian::canonicaljson;
namespace homeserver = merovingian::homeserver;
namespace tls_mock = merovingian::tests::tls_mock;

class PushSqliteDirectory final
{
public:
    PushSqliteDirectory()
    {
        static auto sequence = std::atomic<unsigned>{0U};
        auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
        directory_ = temporary_directory() / ("merovingian-push-isolation-" + std::to_string(now) + "-" +
                                              std::to_string(sequence.fetch_add(1U)));
        std::filesystem::create_directories(directory_);
    }

    ~PushSqliteDirectory()
    {
        auto ignored = std::error_code{};
        std::filesystem::remove_all(directory_, ignored);
    }

    PushSqliteDirectory(PushSqliteDirectory const&) = delete;
    auto operator=(PushSqliteDirectory const&) -> PushSqliteDirectory& = delete;

    [[nodiscard]] auto database_path() const -> std::filesystem::path
    {
        return directory_ / "push.sqlite3";
    }

private:
    std::filesystem::path directory_{};
};

[[nodiscard]] auto isolation_config(std::filesystem::path const& database_path) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = shared_master_key_file();
    enable_token_registration(security);
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = database_path.string();
    auto server = merovingian::config::ServerConfig{};
    server.push.enabled = true;
    // Two genuine attacker events exhaust the current global-only budget.
    // A repaired per-user budget must leave room for a different recipient.
    // Deliberately do not prescribe a new configuration member here.
    server.push.max_in_flight_deliveries = 2U;
    return {server,   merovingian::config::ListenersConfig{},        database,
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
}

[[nodiscard]] auto serialize_object(canonicaljson::Object object) -> std::string
{
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(object)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

[[nodiscard]] auto register_and_login(homeserver::ClientServerRuntime& runtime, std::string const& localpart)
    -> std::string
{
    auto const password = localpart + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                          std::string{'A', 'a', '7', '!'};
    auto const registration = homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/register", {}, registration_json(localpart, password)});
    REQUIRE(registration.response.status == 200U);

    auto identifier = canonicaljson::Object{};
    identifier.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.id.user"}}));
    identifier.push_back(canonicaljson::make_member("user", canonicaljson::Value{localpart}));
    auto body = canonicaljson::Object{};
    body.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.login.password"}}));
    body.push_back(canonicaljson::make_member("identifier", canonicaljson::Value{std::move(identifier)}));
    body.push_back(canonicaljson::make_member("password", canonicaljson::Value{password}));
    body.push_back(canonicaljson::make_member("device_id", canonicaljson::Value{localpart + "_DEV"}));
    auto const login = homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, serialize_object(std::move(body))});
    REQUIRE(login.response.status == 200U);
    auto const response = parse_object(login.response.body);
    auto const* token = string_member(response, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto private_room(homeserver::ClientServerRuntime& runtime, std::string const& sender,
                                std::string const& recipient, std::string const& recipient_localpart) -> std::string
{
    auto const create = homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", sender,
                  R"({"preset":"private_chat","invite":["@)" + recipient_localpart + R"(:example.org"]})"});
    REQUIRE(create.response.status == 200U);
    auto const body = parse_object(create.response.body);
    auto const* room_id = string_member(body, "room_id");
    REQUIRE(room_id != nullptr);
    auto const join = homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/rooms/" + *room_id + "/join", recipient, "{}"});
    REQUIRE(join.response.status == 200U);
    return *room_id;
}

auto register_http_pusher(homeserver::ClientServerRuntime& runtime, std::string const& token, std::string const& url,
                          std::size_t ordinal) -> void
{
    // Unique runtime-only values; no credentials, gateway URLs, or raw notify
    // bodies are attached to Catch diagnostics.
    auto const pushkey =
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "-" + std::to_string(ordinal);
    auto const body = std::string{R"({"app_id":"org.example.isolation","pushkey":")"} + pushkey +
                      R"(","kind":"http","app_display_name":"Isolation App",)" +
                      R"("device_display_name":"Isolation Device","lang":"en","data":{"url":")" + url + R"("}})";
    auto const registered =
        homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/pushers/set", token, body});
    REQUIRE(registered.response.status == 200U);
}

[[nodiscard]] auto pusher_count(homeserver::ClientServerRuntime& runtime, std::string const& token) -> std::size_t
{
    auto const response =
        homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/pushers", token, {}});
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* pushers = object_member_as_array(body, "pushers");
    REQUIRE(pushers != nullptr);
    return pushers->size();
}

[[nodiscard]] auto send_message(homeserver::ClientServerRuntime& runtime, std::string const& sender,
                                std::string const& room_id, std::string const& transaction) -> std::string
{
    auto const response = homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + transaction, sender,
                  R"({"msgtype":"m.text","body":"isolation notification"})"});
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* event_id = string_member(body, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

// Move futures while briefly holding the leaf mutex; never wait under it or
// runtime.mutex. Call only when no public request is concurrently dispatching.
auto drain_background_tasks(homeserver::HomeserverRuntime& runtime) -> void
{
    for (;;)
    {
        auto pending = std::vector<std::future<void>>{};
        {
            auto const lock = std::lock_guard{runtime.orphan_futures_mutex_};
            pending.swap(runtime.orphan_futures_);
        }
        if (pending.empty())
        {
            return;
        }
        for (auto& future : pending)
        {
            if (future.valid())
            {
                future.wait();
            }
        }
    }
}

template <typename Predicate>
[[nodiscard]] auto wait_until(Predicate&& predicate, std::chrono::milliseconds timeout) -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + timeout;
    while (!predicate() && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(5ms);
    }
    return predicate();
}

struct NotifyReceipt final
{
    std::string event_id{};
    std::string room_id{};
};

// Local real TLS peer, patterned on tls_mock::run_stalling_tls_server, with
// two essential differences: it reads the whole HTTP notify before recording
// success, and keeps accepting connections for both control and test traffic.
// StallingTlsServerState::request_received alone is not evidence of receipt:
// the shared one-shot helper also sets it on accept/handshake failure.
class PushGatewayPeer final
{
public:
    PushGatewayPeer(homeserver::HomeserverRuntime& runtime, std::string host, bool stall)
        : certificate_{tls_mock::write_test_tls_certificate(host)}
        , tls_{homeserver::make_tls_server_context(certificate_.certificate_file, certificate_.private_key_file)}
        , stall_{stall}
    {
        REQUIRE(tls_.ok());
        REQUIRE(acceptor_.bind("127.0.0.1", 0U).ok);
        REQUIRE(acceptor_.bound_port() > 0U);
        url_ = "https://" + host + ":" + std::to_string(acceptor_.bound_port()) + "/_matrix/push/v1/notify";
        runtime.test_forced_push_gateway_resolution[host] =
            merovingian::push::TestForcedPushGatewayResolution{{"127.0.0.1"}, certificate_.certificate_pem};
        listener_.emplace_back([this] {
            serve();
        });
    }

    ~PushGatewayPeer()
    {
        release();
        stop_.store(true);
        listener_.join();
    }

    PushGatewayPeer(PushGatewayPeer const&) = delete;
    auto operator=(PushGatewayPeer const&) -> PushGatewayPeer& = delete;

    [[nodiscard]] auto url() const -> std::string const&
    {
        return url_;
    }

    auto release() noexcept -> void
    {
        state_.released.store(true);
    }

    [[nodiscard]] auto holds_notify() const noexcept -> bool
    {
        return held_requests_.load() > 0U && !state_.released.load();
    }

    [[nodiscard]] auto received(std::string const& event_id, std::string const& room_id) const -> bool
    {
        auto const lock = std::lock_guard{receipts_mutex_};
        return std::ranges::any_of(receipts_, [&](auto const& receipt) {
            return receipt.event_id == event_id && receipt.room_id == room_id;
        });
    }

private:
    [[nodiscard]] static auto read_notify(homeserver::TlsConnection& connection) -> std::optional<NotifyReceipt>
    {
        auto request = std::string{};
        auto buffer = std::array<char, 8192>{};
        auto body_offset = std::string::npos;
        auto body_size = std::size_t{0U};
        constexpr auto max_request_bytes = std::size_t{65536U};
        for (;;)
        {
            if (body_offset != std::string::npos && request.size() >= body_offset + body_size)
            {
                break;
            }
            auto const bytes_read = connection.read(buffer.data(), buffer.size());
            if (bytes_read <= 0)
            {
                return std::nullopt;
            }
            request.append(buffer.data(), static_cast<std::size_t>(bytes_read));
            if (request.size() > max_request_bytes)
            {
                return std::nullopt;
            }
            auto const headers_end = request.find("\r\n\r\n");
            if (body_offset == std::string::npos && headers_end != std::string::npos)
            {
                if (!request.starts_with("POST /_matrix/push/v1/notify "))
                {
                    return std::nullopt;
                }
                auto headers = request.substr(0U, headers_end);
                std::ranges::transform(headers, headers.begin(), [](unsigned char character) {
                    return static_cast<char>(character >= 'A' && character <= 'Z' ? character + ('a' - 'A')
                                                                                  : character);
                });
                auto const length_header = headers.find("\r\ncontent-length:");
                if (length_header == std::string::npos)
                {
                    return std::nullopt;
                }
                auto length =
                    std::string_view{headers}.substr(length_header + std::string_view{"\r\ncontent-length:"}.size());
                length = length.substr(0U, length.find("\r\n"));
                auto const first_digit = length.find_first_not_of(" \t");
                if (first_digit == std::string_view::npos)
                {
                    return std::nullopt;
                }
                length.remove_prefix(first_digit);
                auto const converted = std::from_chars(length.data(), length.data() + length.size(), body_size);
                body_offset = headers_end + 4U;
                if (converted.ec != std::errc{} || converted.ptr != length.data() + length.size() ||
                    body_size > max_request_bytes - body_offset)
                {
                    return std::nullopt;
                }
            }
        }
        auto const parsed = canonicaljson::parse_lossless(std::string_view{request}.substr(body_offset, body_size));
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        auto const* notification = object == nullptr ? nullptr : object_member_as_object(*object, "notification");
        if (notification == nullptr)
        {
            return std::nullopt;
        }
        auto const* event_id = string_member(*notification, "event_id");
        auto const* room_id = string_member(*notification, "room_id");
        if (event_id == nullptr || room_id == nullptr)
        {
            return std::nullopt;
        }
        return NotifyReceipt{*event_id, *room_id};
    }

    auto serve_connection(int client_fd) -> void
    {
        auto accepted = homeserver::accept_tls_connection(*tls_.context, client_fd, 2000);
        if (!accepted.connection.has_value())
        {
            return;
        }
        auto& connection = *accepted.connection;
        auto receipt = read_notify(connection);
        if (!receipt.has_value())
        {
            return;
        }
        if (stall_)
        {
            ++held_requests_;
        }
        {
            auto const lock = std::lock_guard{receipts_mutex_};
            receipts_.push_back(std::move(*receipt));
        }
        state_.request_received.store(true);
        if (stall_)
        {
            auto const deadline = std::chrono::steady_clock::now() + 20s;
            while (!state_.released.load() && !stop_.load() && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(5ms);
            }
            --held_requests_;
        }
        std::ignore = connection.write(tls_mock::json_http_response("200 OK", R"({"rejected":[]})"));
    }

    auto serve() -> void
    {
        auto connections = JoiningThreads{};
        while (!stop_.load())
        {
            auto const client_fd = tls_mock::accept_loopback(acceptor_, 50);
            if (client_fd >= 0)
            {
                // Both attacker events may reach the same first gateway. A
                // held connection must not make this listener one-shot.
                connections.emplace_back([this, client = merovingian::core::SocketHandle{client_fd}] {
                    serve_connection(client.native_handle());
                });
            }
        }
    }

    tls_mock::TlsTestCertificate certificate_{};
    homeserver::TlsServerContextResult tls_{};
    merovingian::net::TcpAcceptor acceptor_{};
    bool const stall_;
    std::string url_{};
    tls_mock::StallingTlsServerState state_{};
    std::atomic<bool> stop_{false};
    std::atomic<std::size_t> held_requests_{0U};
    mutable std::mutex receipts_mutex_{};
    std::vector<NotifyReceipt> receipts_{};
    JoiningThreads listener_{};
};

// Declared after the runtime: on every exit, including a failed REQUIRE,
// release ALL peers first, drain actual outbound tasks while listeners, TLS
// contexts and runtime are still alive, then destroy/join the peer threads.
class PushGatewayFleet final
{
public:
    explicit PushGatewayFleet(homeserver::HomeserverRuntime& runtime)
        : runtime_{runtime}
    {
    }

    ~PushGatewayFleet()
    {
        release_and_drain();
    }

    PushGatewayFleet(PushGatewayFleet const&) = delete;
    auto operator=(PushGatewayFleet const&) -> PushGatewayFleet& = delete;

    auto add(std::string host, bool stall) -> PushGatewayPeer&
    {
        peers_.push_back(std::make_unique<PushGatewayPeer>(runtime_, std::move(host), stall));
        return *peers_.back();
    }

    [[nodiscard]] auto holds_notify() const -> bool
    {
        return std::ranges::any_of(peers_, [](auto const& peer) {
            return peer->holds_notify();
        });
    }

    [[nodiscard]] auto received(std::string const& event_id, std::string const& room_id) const -> bool
    {
        return std::ranges::any_of(peers_, [&](auto const& peer) {
            return peer->received(event_id, room_id);
        });
    }

    auto release_and_drain() -> void
    {
        for (auto& peer : peers_)
        {
            peer->release();
        }
        drain_background_tasks(runtime_);
    }

private:
    homeserver::HomeserverRuntime& runtime_;
    std::vector<std::unique_ptr<PushGatewayPeer>> peers_{};
};

} // namespace

SCENARIO("one user's stalled push gateways do not prevent another user's notification",
         "[integration][push][out-3-isolation]")
{
    GIVEN("real SQLite, two separate recipient rooms, and a successfully delivering healthy TLS gateway")
    {
        auto directory = PushSqliteDirectory{};
        auto started = homeserver::start_client_server(isolation_config(directory.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& server = runtime.homeserver;
        REQUIRE(server.database.persistent_store.backend == merovingian::database::PersistentStoreBackend::sqlite);
        REQUIRE(std::filesystem::exists(directory.database_path()));
        REQUIRE(server.outbound_client != nullptr);
        REQUIRE(server.cached_discovery != nullptr);
        auto gateways = PushGatewayFleet{server};

        auto const sender = register_and_login(runtime, "sender");
        auto const healthy = register_and_login(runtime, "healthy");
        auto const attacker = register_and_login(runtime, "attacker");
        // No attacker membership in the healthy room or healthy membership in
        // the attacker room: the healthy event cannot ride in the same vector.
        auto const healthy_room = private_room(runtime, sender, healthy, "healthy");
        auto const attacker_room = private_room(runtime, sender, attacker, "attacker");
        REQUIRE(healthy_room != attacker_room);
        auto& healthy_gateway = gateways.add("push-healthy.localhost.test", false);
        register_http_pusher(runtime, healthy, healthy_gateway.url(), 0U);

        auto const control_event = send_message(runtime, sender, healthy_room, "healthy-control");
        auto const control_delivered = wait_until(
            [&] {
                return healthy_gateway.received(control_event, healthy_room);
            },
            5s);
        REQUIRE(control_delivered);
        // Drain only the completed healthy control; no stalled work exists yet.
        drain_background_tasks(server);
        REQUIRE(server.push_delivery_in_flight_.load() == 0U);
        {
            auto const lock = std::lock_guard{server.orphan_futures_mutex_};
            REQUIRE(server.orphan_futures_.empty());
        }

        for (auto index = std::size_t{0U}; index < 10U; ++index)
        {
            auto& gateway = gateways.add("push-stalled-" + std::to_string(index) + ".localhost.test", true);
            register_http_pusher(runtime, attacker, gateway.url(), index + 1U);
        }
        REQUIRE(pusher_count(runtime, attacker) == 10U);

        WHEN("two distinct attacker events are sent while its first real notify remains held")
        {
            auto const first_attack = send_message(runtime, sender, attacker_room, "attacker-first");
            auto const real_attack_notify = wait_until(
                [&] {
                    return gateways.received(first_attack, attacker_room) && gateways.holds_notify();
                },
                5s);
            REQUIRE(real_attack_notify);
            REQUIRE(server.push_delivery_in_flight_.load() > 0U);
            auto const second_attack = send_message(runtime, sender, attacker_room, "attacker-second");
            REQUIRE(first_attack != second_attack);
            // Do not require two admitted attacker tasks: the GREEN fix may
            // reject/queue the second, retaining one slot for the healthy user.
            REQUIRE(gateways.holds_notify());

            auto const healthy_event = send_message(runtime, sender, healthy_room, "healthy-under-attack");
            auto const healthy_notify_arrived = wait_until(
                [&] {
                    return healthy_gateway.received(healthy_event, healthy_room);
                },
                5s);
            auto const attack_still_held = gateways.holds_notify();

            THEN("the healthy user's actual notify arrives before any stalled gateway is released")
            {
                CHECK(attack_still_held);
                CHECK(healthy_notify_arrived);
                // Nonfatal RED above must still execute ordered cleanup.
                gateways.release_and_drain();
                CHECK(server.push_delivery_in_flight_.load() == 0U);
            }
        }
    }
}
