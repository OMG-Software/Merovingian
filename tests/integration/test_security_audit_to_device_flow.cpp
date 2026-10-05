// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace
{

class ToDeviceSqliteFixture final
{
public:
    ToDeviceSqliteFixture()
    {
        static auto counter = std::uint64_t{0U};
        auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
        directory_ = merovingian::tests::temporary_directory() /
                     ("merovingian-security-audit-to-device-" + std::to_string(now) + "-" + std::to_string(counter++));
        std::filesystem::create_directories(directory_);
    }

    ~ToDeviceSqliteFixture()
    {
        auto ignored = std::error_code{};
        std::filesystem::remove_all(directory_, ignored);
    }

    ToDeviceSqliteFixture(ToDeviceSqliteFixture const&) = delete;
    auto operator=(ToDeviceSqliteFixture const&) -> ToDeviceSqliteFixture& = delete;

    [[nodiscard]] auto database_path() const -> std::filesystem::path
    {
        return directory_ / "to-device.sqlite3";
    }

private:
    std::filesystem::path directory_{};
};

[[nodiscard]] auto to_device_config(std::filesystem::path const& sqlite_path) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);

    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = sqlite_path.string();

    return {merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            std::move(database),
            std::move(security),
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{}};
}

struct DeviceSession final
{
    std::string user_id{};
    std::string access_token{};
    std::string device_id{};
};

[[nodiscard]] auto response_string(merovingian::canonicaljson::Object const& response, std::string_view key)
    -> std::string
{
    auto const* value = merovingian::tests::string_member(response, key);
    REQUIRE(value != nullptr);
    REQUIRE_FALSE(value->empty());
    return *value;
}

[[nodiscard]] auto register_device(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view localpart,
                                   std::string_view password) -> DeviceSession
{
    auto const registration = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json(localpart, password)});
    REQUIRE(registration.response.status == 200U);
    auto const body = merovingian::tests::parse_object(registration.response.body);
    return {"@" + std::string{localpart} + ":example.org", response_string(body, "access_token"),
            response_string(body, "device_id")};
}

[[nodiscard]] auto login_device(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view localpart,
                                std::string_view password, std::string_view device_id) -> DeviceSession
{
    auto const user_id = "@" + std::string{localpart} + ":example.org";
    auto const body = std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")"} + user_id +
                      R"("},"password":")" + std::string{password} + R"(","device_id":")" + std::string{device_id} +
                      R"("})";
    auto const response =
        merovingian::homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/login", {}, body});
    REQUIRE(response.response.status == 200U);
    auto const parsed = merovingian::tests::parse_object(response.response.body);
    return {user_id, response_string(parsed, "access_token"), response_string(parsed, "device_id")};
}

[[nodiscard]] auto send_to_device(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view sender_token,
                                  std::string_view txn_id, std::string body)
    -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {"PUT", "/_matrix/client/v3/sendToDevice/m.test.message/" + std::string{txn_id},
                         std::string{sender_token}, std::move(body)})
        .response;
}

[[nodiscard]] auto sync_to_device_count(merovingian::homeserver::ClientServerRuntime& runtime,
                                        std::string_view access_token) -> std::size_t
{
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v3/sync?timeout=0", std::string{access_token}, {}});
    REQUIRE(response.response.status == 200U);
    auto const body = merovingian::tests::parse_object(response.response.body);
    auto const* to_device = merovingian::tests::object_member_as_object(body, "to_device");
    REQUIRE(to_device != nullptr);
    auto const* events = merovingian::tests::object_member_as_array(*to_device, "events");
    REQUIRE(events != nullptr);
    return events->size();
}

} // namespace

// Matrix Client-Server API v1.19, §Send-to-Device messaging and PUT
// /_matrix/client/v3/sendToDevice/{eventType}/{txnId}:
// docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3sendtodeviceeventtypetxnid
// Local unknown-recipient handling is a server privacy policy: silently discard
// rather than disclose which local users or devices exist.
SCENARIO("sendToDevice silently discards unknown local recipients without allocating queue state",
         "[security_audit_to_device][integration][sqlite]")
{
    GIVEN("a SQLite-backed homeserver and a registered sender")
    {
        auto const sqlite = ToDeviceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(to_device_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_device(runtime, "alice", "CorrectHorse7!");

        WHEN("Alice sends to an unknown local user")
        {
            auto const stream_before = runtime.homeserver.database.persistent_store.next_sync_stream_id;
            auto const response =
                send_to_device(runtime, alice.access_token, "unknown-user",
                               R"({"messages":{"@nobody:example.org":{"NOBODY_DEVICE":{"value":"secret"}}}})");

            THEN("the request succeeds without revealing recipient existence or creating durable queue state")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(runtime.homeserver.database.persistent_store.to_device_messages.empty());
                REQUIRE(runtime.homeserver.database.persistent_store.next_sync_stream_id == stream_before);
            }
        }
    }
}

SCENARIO("sendToDevice silently discards a named device that does not belong to a local user",
         "[security_audit_to_device][integration][sqlite]")
{
    GIVEN("a SQLite-backed homeserver with sender Alice and recipient Bob on real registered devices")
    {
        auto const sqlite = ToDeviceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(to_device_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_device(runtime, "alice", "CorrectHorse7!");
        auto const bob = register_device(runtime, "bob", "CorrectHorse8!");

        WHEN("Alice sends to a device ID that Bob has not registered")
        {
            auto const stream_before = runtime.homeserver.database.persistent_store.next_sync_stream_id;
            auto const response =
                send_to_device(runtime, alice.access_token, "unknown-device",
                               R"({"messages":{"@bob:example.org":{"NOT_BOBS_DEVICE":{"value":"secret"}}}})");

            THEN("the request succeeds without allocating queue state for the invented device")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(runtime.homeserver.database.persistent_store.to_device_messages.empty());
                REQUIRE(runtime.homeserver.database.persistent_store.next_sync_stream_id == stream_before);
                REQUIRE(sync_to_device_count(runtime, bob.access_token) == 0U);
            }
        }
    }
}

SCENARIO("sendToDevice keeps valid deliveries when the same request names an unknown local device",
         "[security_audit_to_device][integration][sqlite]")
{
    GIVEN("Alice and Bob have registered SQLite-backed client sessions")
    {
        auto const sqlite = ToDeviceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(to_device_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_device(runtime, "alice", "CorrectHorse7!");
        auto const bob = register_device(runtime, "bob", "CorrectHorse8!");

        WHEN("Alice sends one request addressed to Bob's real device and a nonexistent device")
        {
            auto const body = std::string{R"({"messages":{"@bob:example.org":{")"} + bob.device_id +
                              R"(":{"value":"delivered"},"NOT_BOBS_DEVICE":{"value":"discarded"}}}})";
            auto const response = send_to_device(runtime, alice.access_token, "mixed-targets", body);

            THEN("the request succeeds and only the registered device receives a queued message")
            {
                REQUIRE(response.status == 200U);
                auto const& queue = runtime.homeserver.database.persistent_store.to_device_messages;
                REQUIRE(queue.size() == 1U);
                REQUIRE(queue.front().target_user_id == bob.user_id);
                REQUIRE(queue.front().target_device_id == bob.device_id);
                REQUIRE(sync_to_device_count(runtime, bob.access_token) == 1U);
            }
        }
    }
}

SCENARIO("sendToDevice wildcard fans out only to the recipient's registered devices",
         "[security_audit_to_device][integration][sqlite]")
{
    GIVEN("Bob has two real registered devices on a SQLite-backed homeserver")
    {
        auto const sqlite = ToDeviceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(to_device_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_device(runtime, "alice", "CorrectHorse7!");
        auto const bob_first = register_device(runtime, "bob", "CorrectHorse8!");
        auto const bob_second = login_device(runtime, "bob", "CorrectHorse8!", "BOB_SECOND_DEVICE");

        WHEN("Alice sends a wildcard message to Bob")
        {
            auto const response =
                send_to_device(runtime, alice.access_token, "wildcard",
                               R"({"messages":{"@bob:example.org":{"*":{"value":"to every known device"}}}})");

            THEN("each registered device gets one message and no wildcard queue row is retained")
            {
                REQUIRE(response.status == 200U);
                auto const& queue = runtime.homeserver.database.persistent_store.to_device_messages;
                REQUIRE(queue.size() == 2U);
                REQUIRE(std::ranges::all_of(queue, [&](auto const& message) {
                    return message.target_user_id == bob_first.user_id && message.target_device_id != "*";
                }));
                REQUIRE(std::ranges::count_if(queue, [&](auto const& message) {
                            return message.target_device_id == bob_first.device_id;
                        }) == 1);
                REQUIRE(std::ranges::count_if(queue, [&](auto const& message) {
                            return message.target_device_id == bob_second.device_id;
                        }) == 1);
                REQUIRE(sync_to_device_count(runtime, bob_first.access_token) == 1U);
                REQUIRE(sync_to_device_count(runtime, bob_second.access_token) == 1U);
            }
        }
    }
}
