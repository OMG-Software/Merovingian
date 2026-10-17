// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../federation_signing_test_support.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#include <sqlite3.h>

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

struct SqliteCloser final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        if (connection != nullptr)
        {
            std::ignore = sqlite3_close(connection);
        }
    }
};

// R02: makes every INSERT into one table of the server's database file fail
// from a second connection, so the server's own transaction aborts and rolls
// back exactly as a failed commit would. clear() lifts the fault so a client
// retry can succeed; the destructor lifts it too.
class SqliteInsertFault final
{
public:
    SqliteInsertFault(std::filesystem::path const& path, std::string_view table, std::string_view name)
        : drop_sql_{"DROP TRIGGER IF EXISTS " + std::string{name}}
    {
        auto* raw_connection = static_cast<sqlite3*>(nullptr);
        auto const status = sqlite3_open(path.string().c_str(), &raw_connection);
        connection_.reset(raw_connection);
        REQUIRE(status == SQLITE_OK);
        REQUIRE(connection_ != nullptr);
        REQUIRE(execute("CREATE TRIGGER " + std::string{name} + " BEFORE INSERT ON " + std::string{table} +
                        " BEGIN SELECT RAISE(ABORT, 'injected r02 write failure'); END"));
        active_ = true;
    }

    SqliteInsertFault(SqliteInsertFault const&) = delete;
    auto operator=(SqliteInsertFault const&) -> SqliteInsertFault& = delete;
    SqliteInsertFault(SqliteInsertFault&&) = delete;
    auto operator=(SqliteInsertFault&&) -> SqliteInsertFault& = delete;

    ~SqliteInsertFault()
    {
        if (active_)
        {
            std::ignore = execute(drop_sql_);
        }
    }

    auto clear() -> void
    {
        REQUIRE(execute(drop_sql_));
        active_ = false;
    }

private:
    [[nodiscard]] auto execute(std::string const& sql) const -> bool
    {
        return sqlite3_exec(connection_.get(), sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
    }

    std::unique_ptr<sqlite3, SqliteCloser> connection_{};
    std::string drop_sql_{};
    bool active_{false};
};

[[nodiscard]] auto queued_for(merovingian::homeserver::ClientServerRuntime const& runtime, std::string_view user_id,
                              std::string_view device_id) -> std::ptrdiff_t
{
    return std::ranges::count_if(runtime.homeserver.database.persistent_store.to_device_messages,
                                 [&](auto const& message) {
                                     return message.target_user_id == user_id && message.target_device_id == device_id;
                                 });
}

[[nodiscard]] auto txn_recorded(merovingian::homeserver::ClientServerRuntime const& runtime,
                                std::string_view sender_user_id, std::string_view txn_id) -> bool
{
    return merovingian::database::find_client_txn_event_id(runtime.homeserver.database.persistent_store, sender_user_id,
                                                           "", "m.test.message", txn_id)
        .has_value();
}

[[nodiscard]] auto error_code_of(merovingian::homeserver::LocalHttpResponse const& response) -> std::string
{
    auto const body = merovingian::tests::parse_object(response.body);
    auto const* errcode = merovingian::tests::string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

// What a restart would read back: the database file through a fresh store.
struct DurableToDeviceState final
{
    std::size_t to_device_rows{0U};
    bool txn_recorded{false};
};

[[nodiscard]] auto durable_to_device_state(std::filesystem::path const& path, std::string_view sender_user_id,
                                           std::string_view txn_id) -> DurableToDeviceState
{
    auto opened = merovingian::database::open_sqlite_persistent_store(path.string());
    REQUIRE(opened.ok);
    return {opened.store.to_device_messages.size(),
            merovingian::database::find_client_txn_event_id(opened.store, sender_user_id, "", "m.test.message", txn_id)
                .has_value()};
}

// A dispatch worker that is never started: enqueue() persists the transaction
// and queues it, which is all these scenarios observe.
[[nodiscard]] auto make_idle_dispatch_worker(merovingian::http::OutboundClient& client,
                                             merovingian::database::PersistentStore& store)
    -> std::unique_ptr<merovingian::federation::DispatchWorker>
{
    auto config = merovingian::federation::DispatchWorkerConfig{};
    config.origin = "example.org";
    config.key_id = "ed25519:auto";
    config.secret_key = merovingian::federation::test::secret_key_buffer(
        merovingian::federation::test::keypair_from_seed("r02-to-device-test"));
    config.max_queue_depth = 64U;
    config.max_retries = 2U;
    auto resolver = merovingian::federation::DispatchResolver{[](std::string_view server_name) {
        auto result = merovingian::federation::ServerDiscoveryResult{};
        result.server_name = std::string{server_name};
        result.resolved_host = std::string{server_name};
        result.resolved_port = 8448U;
        result.discovery_allowed = true;
        return std::optional<merovingian::federation::ServerDiscoveryResult>{result};
    }};
    auto clock = []() -> std::uint64_t {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
    };
    auto sleep_fn = [](std::chrono::milliseconds) {
    };
    return std::make_unique<merovingian::federation::DispatchWorker>(std::move(config), client, std::move(resolver),
                                                                     std::move(clock), std::move(sleep_fn), &store);
}

[[nodiscard]] auto direct_to_device_edus_carrying(merovingian::database::PersistentStore const& store,
                                                  std::string_view message_id) -> std::ptrdiff_t
{
    auto const needle = R"("message_id":")" + std::string{message_id} + R"(")";
    return std::ranges::count_if(store.federation_transactions, [&needle](auto const& transaction) {
        return transaction.body.find(R"("edu_type":"m.direct_to_device")") != std::string::npos &&
               transaction.body.find(needle) != std::string::npos;
    });
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

// R02 (audit): PUT /sendToDevice answers 200 only once the messages are
// durably queued and the transaction ID is recorded, both in one commit.
// Matrix v1.19 CS API: 200 means "The message was successfully sent"; the
// transaction ID makes a retried request idempotent, so a retry after a failed
// request must be processed, not replayed.
// docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3sendtodeviceeventtypetxnid
SCENARIO("sendToDevice reports a failed enqueue and delivers once on retry",
         "[security_audit_to_device][to_device][r02][integration][sqlite]")
{
    GIVEN("Bob's queue table refuses inserts on a SQLite-backed homeserver")
    {
        auto const sqlite = ToDeviceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(to_device_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_device(runtime, "alice", "CorrectHorse7!");
        auto const bob = register_device(runtime, "bob", "CorrectHorse8!");
        auto fault = SqliteInsertFault{sqlite.database_path(), "to_device_messages", "r02_named_device"};
        auto const body =
            std::string{R"({"messages":{"@bob:example.org":{")"} + bob.device_id + R"(":{"value":"keep me"}}}})";

        WHEN("Alice sends to Bob's device")
        {
            auto const response = send_to_device(runtime, alice.access_token, "r02-named", body);

            THEN("the request fails instead of reporting success, and no message or transaction record remains")
            {
                REQUIRE(response.status != 200U);
                REQUIRE(error_code_of(response) == "M_UNKNOWN");
                REQUIRE(queued_for(runtime, bob.user_id, bob.device_id) == 0);
                REQUIRE(sync_to_device_count(runtime, bob.access_token) == 0U);
                REQUIRE_FALSE(txn_recorded(runtime, alice.user_id, "r02-named"));
                auto const durable = durable_to_device_state(sqlite.database_path(), alice.user_id, "r02-named");
                REQUIRE(durable.to_device_rows == 0U);
                REQUIRE_FALSE(durable.txn_recorded);
            }

            AND_WHEN("the fault clears and Alice retries with the same transaction ID")
            {
                fault.clear();
                auto const retried = send_to_device(runtime, alice.access_token, "r02-named", body);

                THEN("the retry is processed rather than replayed, and Bob receives exactly one message")
                {
                    REQUIRE(retried.status == 200U);
                    REQUIRE(queued_for(runtime, bob.user_id, bob.device_id) == 1);
                    REQUIRE(sync_to_device_count(runtime, bob.access_token) == 1U);
                    REQUIRE(txn_recorded(runtime, alice.user_id, "r02-named"));
                }
            }
        }
    }
}

SCENARIO("sendToDevice wildcard delivers to every device or to none when the enqueue fails",
         "[security_audit_to_device][to_device][r02][integration][sqlite]")
{
    GIVEN("Bob has two devices and the queue table refuses inserts")
    {
        auto const sqlite = ToDeviceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(to_device_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_device(runtime, "alice", "CorrectHorse7!");
        auto const bob_first = register_device(runtime, "bob", "CorrectHorse8!");
        auto const bob_second = login_device(runtime, "bob", "CorrectHorse8!", "BOB_SECOND_DEVICE");
        auto fault = SqliteInsertFault{sqlite.database_path(), "to_device_messages", "r02_wildcard"};
        auto const body = std::string{R"({"messages":{"@bob:example.org":{"*":{"value":"to all"}}}})"};

        WHEN("Alice sends a wildcard message to Bob")
        {
            auto const response = send_to_device(runtime, alice.access_token, "r02-wildcard", body);

            THEN("the request fails and neither device has a message")
            {
                REQUIRE(response.status != 200U);
                REQUIRE(queued_for(runtime, bob_first.user_id, bob_first.device_id) == 0);
                REQUIRE(queued_for(runtime, bob_second.user_id, bob_second.device_id) == 0);
                REQUIRE(sync_to_device_count(runtime, bob_first.access_token) == 0U);
                REQUIRE(sync_to_device_count(runtime, bob_second.access_token) == 0U);
                REQUIRE_FALSE(txn_recorded(runtime, alice.user_id, "r02-wildcard"));
            }

            AND_WHEN("the fault clears and Alice retries with the same transaction ID")
            {
                fault.clear();
                auto const retried = send_to_device(runtime, alice.access_token, "r02-wildcard", body);

                THEN("each device has exactly one message")
                {
                    REQUIRE(retried.status == 200U);
                    REQUIRE(queued_for(runtime, bob_first.user_id, bob_first.device_id) == 1);
                    REQUIRE(queued_for(runtime, bob_second.user_id, bob_second.device_id) == 1);
                    REQUIRE(sync_to_device_count(runtime, bob_first.access_token) == 1U);
                    REQUIRE(sync_to_device_count(runtime, bob_second.access_token) == 1U);
                }
            }
        }
    }
}

SCENARIO("sendToDevice commits its messages and its transaction record together",
         "[security_audit_to_device][to_device][r02][integration][sqlite]")
{
    GIVEN("Bob has two devices and the transaction-ID table refuses inserts")
    {
        auto const sqlite = ToDeviceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(to_device_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_device(runtime, "alice", "CorrectHorse7!");
        auto const bob_first = register_device(runtime, "bob", "CorrectHorse8!");
        auto const bob_second = login_device(runtime, "bob", "CorrectHorse8!", "BOB_SECOND_DEVICE");
        auto fault = SqliteInsertFault{sqlite.database_path(), "client_txn_ids", "r02_txn_record"};
        auto const body = std::string{R"({"messages":{"@bob:example.org":{"*":{"value":"to all"}}}})"};

        WHEN("Alice sends a wildcard message and only the transaction record cannot be written")
        {
            auto const response = send_to_device(runtime, alice.access_token, "r02-atomic", body);

            THEN("the request fails and no message was committed in memory or on disk")
            {
                REQUIRE(response.status != 200U);
                REQUIRE(runtime.homeserver.database.persistent_store.to_device_messages.empty());
                REQUIRE(sync_to_device_count(runtime, bob_first.access_token) == 0U);
                auto const durable = durable_to_device_state(sqlite.database_path(), alice.user_id, "r02-atomic");
                REQUIRE(durable.to_device_rows == 0U);
                REQUIRE_FALSE(durable.txn_recorded);
            }

            AND_WHEN("the fault clears and Alice retries")
            {
                fault.clear();
                auto const retried = send_to_device(runtime, alice.access_token, "r02-atomic", body);

                THEN("each device has exactly one message")
                {
                    REQUIRE(retried.status == 200U);
                    REQUIRE(queued_for(runtime, bob_first.user_id, bob_first.device_id) == 1);
                    REQUIRE(queued_for(runtime, bob_second.user_id, bob_second.device_id) == 1);
                }
            }
        }
    }
}

SCENARIO("sendToDevice to local and remote recipients is not recorded when the local enqueue fails",
         "[security_audit_to_device][to_device][r02][integration][sqlite]")
{
    GIVEN("a dispatch worker, a remote recipient, and a local queue table that refuses inserts")
    {
        auto client = merovingian::http::OutboundClient{};
        auto const sqlite = ToDeviceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(to_device_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_device(runtime, "alice", "CorrectHorse7!");
        auto const bob = register_device(runtime, "bob", "CorrectHorse8!");
        runtime.homeserver.dispatch_worker =
            make_idle_dispatch_worker(client, runtime.homeserver.database.persistent_store);
        auto fault = SqliteInsertFault{sqlite.database_path(), "to_device_messages", "r02_mixed"};
        auto const body = std::string{R"({"messages":{"@bob:example.org":{")"} + bob.device_id +
                          R"(":{"value":"local"}},"@carol:remote.example.org":{"CAROL1":{"value":"remote"}}}})";

        WHEN("Alice sends to both and the local enqueue fails")
        {
            auto const response = send_to_device(runtime, alice.access_token, "r02-mixed", body);

            THEN("the request fails, nothing local is queued, and the transaction is not recorded")
            {
                REQUIRE(response.status != 200U);
                REQUIRE(queued_for(runtime, bob.user_id, bob.device_id) == 0);
                REQUIRE_FALSE(txn_recorded(runtime, alice.user_id, "r02-mixed"));
            }

            AND_WHEN("the fault clears and Alice retries with the same transaction ID")
            {
                fault.clear();
                auto const retried = send_to_device(runtime, alice.access_token, "r02-mixed", body);

                THEN("the retry is processed: Bob has one message and the remote EDU carries the same message_id")
                {
                    REQUIRE(retried.status == 200U);
                    REQUIRE(queued_for(runtime, bob.user_id, bob.device_id) == 1);
                    REQUIRE(txn_recorded(runtime, alice.user_id, "r02-mixed"));
                    REQUIRE(direct_to_device_edus_carrying(runtime.homeserver.database.persistent_store, "r02-mixed") >=
                            1);
                }
            }
        }
    }
}

SCENARIO("sendToDevice commits nothing locally when a remote EDU cannot be queued",
         "[security_audit_to_device][to_device][r02][integration][sqlite]")
{
    GIVEN("a local recipient, a remote recipient and an outbound queue that cannot persist a transaction")
    {
        auto client = merovingian::http::OutboundClient{};
        auto const sqlite = ToDeviceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(to_device_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_device(runtime, "alice", "CorrectHorse7!");
        auto const bob = register_device(runtime, "bob", "CorrectHorse8!");
        runtime.homeserver.dispatch_worker =
            make_idle_dispatch_worker(client, runtime.homeserver.database.persistent_store);
        auto fault = SqliteInsertFault{sqlite.database_path(), "federation_transactions", "r02_remote_queue"};
        auto const body = std::string{R"({"messages":{"@bob:example.org":{")"} + bob.device_id +
                          R"(":{"value":"local"}},"@carol:remote.example.org":{"CAROL1":{"value":"remote"}}}})";

        WHEN("Alice sends to both")
        {
            auto const response = send_to_device(runtime, alice.access_token, "r02-remote", body);

            THEN("the request fails, Bob has nothing, and the transaction is not recorded")
            {
                REQUIRE(response.status != 200U);
                REQUIRE(error_code_of(response) == "M_UNKNOWN");
                REQUIRE(queued_for(runtime, bob.user_id, bob.device_id) == 0);
                REQUIRE_FALSE(txn_recorded(runtime, alice.user_id, "r02-remote"));
            }

            AND_WHEN("the fault clears and Alice retries with the same transaction ID")
            {
                fault.clear();
                auto const retried = send_to_device(runtime, alice.access_token, "r02-remote", body);

                THEN("the retry is processed and delivers both the local message and the remote EDU")
                {
                    REQUIRE(retried.status == 200U);
                    REQUIRE(queued_for(runtime, bob.user_id, bob.device_id) == 1);
                    REQUIRE(direct_to_device_edus_carrying(runtime.homeserver.database.persistent_store,
                                                           "r02-remote") == 1);
                }
            }
        }
    }
}

SCENARIO("sendToDevice replays a recorded transaction without delivering again",
         "[security_audit_to_device][to_device][r02][integration][sqlite]")
{
    GIVEN("Alice has successfully sent a message to Bob's device")
    {
        auto const sqlite = ToDeviceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(to_device_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_device(runtime, "alice", "CorrectHorse7!");
        auto const bob = register_device(runtime, "bob", "CorrectHorse8!");
        auto const body =
            std::string{R"({"messages":{"@bob:example.org":{")"} + bob.device_id + R"(":{"value":"once"}}}})";
        REQUIRE(send_to_device(runtime, alice.access_token, "r02-replay", body).status == 200U);
        auto const stream_before = runtime.homeserver.database.persistent_store.next_sync_stream_id;

        WHEN("Alice repeats the request with the same transaction ID")
        {
            auto const replayed = send_to_device(runtime, alice.access_token, "r02-replay", body);

            THEN("the response is 200 and nothing further is queued")
            {
                REQUIRE(replayed.status == 200U);
                REQUIRE(queued_for(runtime, bob.user_id, bob.device_id) == 1);
                REQUIRE(runtime.homeserver.database.persistent_store.next_sync_stream_id == stream_before);
            }
        }

        WHEN("the database file is read back by a fresh store")
        {
            auto const durable = durable_to_device_state(sqlite.database_path(), alice.user_id, "r02-replay");

            THEN("both the message and the transaction record are present")
            {
                REQUIRE(durable.to_device_rows == 1U);
                REQUIRE(durable.txn_recorded);
            }
        }
    }
}

SCENARIO("sendToDevice with no local recipient still records its transaction",
         "[security_audit_to_device][to_device][r02][integration][sqlite]")
{
    GIVEN("a sender whose request names only an unknown local user")
    {
        auto const sqlite = ToDeviceSqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(to_device_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_device(runtime, "alice", "CorrectHorse7!");

        WHEN("Alice sends the request")
        {
            auto const response =
                send_to_device(runtime, alice.access_token, "r02-empty",
                               R"({"messages":{"@nobody:example.org":{"NOBODY_DEVICE":{"value":"x"}}}})");

            THEN("it succeeds and the transaction is recorded in memory and on disk")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(runtime.homeserver.database.persistent_store.to_device_messages.empty());
                REQUIRE(txn_recorded(runtime, alice.user_id, "r02-empty"));
                REQUIRE(durable_to_device_state(sqlite.database_path(), alice.user_id, "r02-empty").txn_recorded);
            }
        }
    }
}
