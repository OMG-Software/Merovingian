// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../federation_signing_test_support.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

class TemporarySqliteDirectory final
{
public:
    TemporarySqliteDirectory()
    {
        auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = merovingian::tests::temporary_directory() / ("merovingian-federated-to-device-" + std::to_string(now));
        std::filesystem::create_directories(path_);
    }

    ~TemporarySqliteDirectory()
    {
        auto ignored = std::error_code{};
        std::filesystem::remove_all(path_, ignored);
    }

    TemporarySqliteDirectory(TemporarySqliteDirectory const&) = delete;
    auto operator=(TemporarySqliteDirectory const&) -> TemporarySqliteDirectory& = delete;

    [[nodiscard]] auto database_path() const -> std::filesystem::path
    {
        return path_ / "federated-to-device.sqlite3";
    }

private:
    std::filesystem::path path_{};
};

[[nodiscard]] auto to_device_config(std::filesystem::path const& sqlite_path) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.federation.enabled = true;
    security.federation.default_policy = "allow";
    security.federation.max_transaction_size = "1MiB";
    security.federation.remote_timeout = "30s";

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

[[nodiscard]] auto response_string(merovingian::canonicaljson::Object const& response, std::string_view key)
    -> std::string
{
    auto const* value = merovingian::tests::string_member(response, key);
    REQUIRE(value != nullptr);
    REQUIRE_FALSE(value->empty());
    return *value;
}

struct DeviceSession final
{
    std::string user_id{};
    std::string access_token{};
    std::string device_id{};
};

[[nodiscard]] auto register_bob(merovingian::homeserver::ClientServerRuntime& runtime) -> DeviceSession
{
    auto const registration = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("bob", "CorrectHorse7!")});
    REQUIRE(registration.response.status == 200U);
    auto const parsed = merovingian::tests::parse_object(registration.response.body);
    return {"@bob:example.org", response_string(parsed, "access_token"), response_string(parsed, "device_id")};
}

[[nodiscard]] auto login_bob_device(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view device_id)
    -> DeviceSession
{
    auto const user_id = std::string{"@bob:example.org"};
    auto const body = std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")"} + user_id +
                      R"("},"password":"CorrectHorse7!","device_id":")" + std::string{device_id} + R"("})";
    auto const response =
        merovingian::homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/login", {}, body});
    REQUIRE(response.response.status == 200U);
    auto const parsed = merovingian::tests::parse_object(response.response.body);
    return {user_id, response_string(parsed, "access_token"), response_string(parsed, "device_id")};
}

[[nodiscard]] auto remote_for(std::string_view origin, std::string_view key_id,
                              merovingian::federation::test::SigningKeypair const& keypair)
    -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = origin;
    remote.signing_key = {std::string{origin}, std::string{key_id}, std::numeric_limits<std::uint64_t>::max(),
                          keypair.public_key};
    remote.discovery.server_name = origin;
    remote.discovery.well_known_host = origin;
    remote.discovery.resolved_host = origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto signed_authorization(std::string_view origin, std::string_view destination, std::string_view key_id,
                                        std::string_view method, std::string_view target, std::string_view body,
                                        std::string_view secret_key) -> std::string
{
    auto const signature =
        merovingian::federation::make_federation_signature(origin, destination, method, target, body, secret_key);
    return std::string{"X-Matrix origin=\""} + std::string{origin} + "\",destination=\"" + std::string{destination} +
           "\",key=\"" + std::string{key_id} + "\",sig=\"" + signature + "\"";
}

} // namespace

// Matrix Server-Server API v1.19, "Send-to-device messaging" and "EDUs".
// The sender is authenticated by the sending server, while local target
// admission requires an existing active account and device.
SCENARIO("a verified federation to-device EDU queues only known active local devices",
         "[integration][sqlite][security_audit_federated_to_device_flow]")
{
    GIVEN("a SQLite-backed homeserver with Bob logged in on a real target device and a remote signing key")
    {
        auto const sqlite = TemporarySqliteDirectory{};
        auto started = merovingian::homeserver::start_client_server(to_device_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const bob = register_bob(runtime);
        auto const bob_device = login_bob_device(runtime, "BOB_DEVICE");
        REQUIRE(bob_device.device_id == "BOB_DEVICE");
        auto const origin = std::string{"matrix.ping.me.uk"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const keypair = merovingian::federation::test::keypair_from_seed("federated-to-device-seed");
        merovingian::federation::upsert_remote(runtime.homeserver.federation, remote_for(origin, key_id, keypair));

        auto const remote_sender = std::string{"@james:"} + origin;
        auto const transaction_target = std::string{"/_matrix/federation/v1/send/txn-known-and-invented-device"};
        auto const transaction_body =
            std::string{"{\"origin\":\""} + origin +
            R"(","origin_server_ts":1000,"pdus":[],"edus":[{"edu_type":"m.direct_to_device","content":{"sender":")" +
            remote_sender +
            R"(","type":"m.room.encrypted","message_id":"known-and-invented-device","messages":{"@bob:example.org":{"BOB_DEVICE":{"value":"deliver"},"NOT_BOBS_DEVICE":{"value":"discard"}}}}}]})";
        auto const authorization = signed_authorization(origin, "example.org", key_id, "PUT", transaction_target,
                                                        transaction_body, keypair.secret_key);
        auto const sync_stream_before = runtime.homeserver.database.persistent_store.next_sync_stream_id;

        WHEN("the signed federation transaction names Bob's device and an unregistered device")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{};
            request.method = "PUT";
            request.target = transaction_target;
            request.access_token = authorization;
            request.body = transaction_body;
            // Leave sig_verified false: this exercises Ed25519 verification of
            // the X-Matrix header against the remote key configured above.
            auto const response = merovingian::homeserver::handle_federation_http_request(runtime.homeserver, request);

            THEN("the EDU is accepted, only the real device is queued, and the invented target allocates no stream row")
            {
                REQUIRE(response.status == 200U);
                auto const& store = runtime.homeserver.database.persistent_store;
                REQUIRE(std::ranges::none_of(store.users, [&](merovingian::database::PersistentUser const& user) {
                    return user.user_id == remote_sender;
                }));
                REQUIRE(store.to_device_messages.size() == 1U);
                REQUIRE(store.to_device_messages.front().sender_user_id == remote_sender);
                REQUIRE(store.to_device_messages.front().target_user_id == bob.user_id);
                REQUIRE(store.to_device_messages.front().target_device_id == bob_device.device_id);
                REQUIRE(store.to_device_messages.front().content_json == R"({"value":"deliver"})");
                REQUIRE(store.next_sync_stream_id == sync_stream_before + 1U);
            }
        }
    }
}

// Matrix Server-Server API v1.19, "Send-to-device messaging": in
// m.direct_to_device "The device ID may also be `*`, meaning all known devices
// for the user."
SCENARIO("a verified federation to-device EDU addressed to device '*' reaches every device of the local user",
         "[integration][sqlite][security_audit_federated_to_device_flow]")
{
    GIVEN("Bob with several registered devices, Carol with her own device, and a trusted remote signing key")
    {
        auto const sqlite = TemporarySqliteDirectory{};
        auto started = merovingian::homeserver::start_client_server(to_device_config(sqlite.database_path()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const bob = register_bob(runtime);
        std::ignore = login_bob_device(runtime, "BOB_PHONE");
        std::ignore = login_bob_device(runtime, "BOB_LAPTOP");
        auto const carol = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("carol", "CorrectHorse7!")});
        REQUIRE(carol.response.status == 200U);

        auto const& store = runtime.homeserver.database.persistent_store;
        auto bob_devices = std::vector<std::string>{};
        for (auto const& device : store.devices)
        {
            if (device.user_id == bob.user_id)
            {
                bob_devices.push_back(device.device_id);
            }
        }
        std::ranges::sort(bob_devices);
        REQUIRE(bob_devices.size() == 3U);

        auto const origin = std::string{"matrix.ping.me.uk"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const keypair = merovingian::federation::test::keypair_from_seed("federated-to-device-wildcard-seed");
        merovingian::federation::upsert_remote(runtime.homeserver.federation, remote_for(origin, key_id, keypair));

        auto const remote_sender = std::string{"@james:"} + origin;
        auto const transaction_target = std::string{"/_matrix/federation/v1/send/txn-wildcard-device"};
        auto const transaction_body =
            std::string{"{\"origin\":\""} + origin +
            R"(","origin_server_ts":1000,"pdus":[],"edus":[{"edu_type":"m.direct_to_device","content":{"sender":")" +
            remote_sender +
            R"(","type":"m.room_key_request","message_id":"wildcard-device","messages":{"@bob:example.org":{"*":{"action":"request_cancellation"}}}}}]})";
        auto const authorization = signed_authorization(origin, "example.org", key_id, "PUT", transaction_target,
                                                        transaction_body, keypair.secret_key);
        auto const sync_stream_before = store.next_sync_stream_id;

        WHEN("the signed federation transaction addresses Bob's wildcard device")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{};
            request.method = "PUT";
            request.target = transaction_target;
            request.access_token = authorization;
            request.body = transaction_body;
            auto const response = merovingian::homeserver::handle_federation_http_request(runtime.homeserver, request);

            THEN("each of Bob's devices gets one copy, Carol gets none, and no literal '*' device is queued")
            {
                REQUIRE(response.status == 200U);
                auto queued_devices = std::vector<std::string>{};
                for (auto const& message : store.to_device_messages)
                {
                    REQUIRE(message.sender_user_id == remote_sender);
                    REQUIRE(message.target_user_id == bob.user_id);
                    REQUIRE(message.message_type == "m.room_key_request");
                    REQUIRE(message.content_json == R"({"action":"request_cancellation"})");
                    queued_devices.push_back(message.target_device_id);
                }
                std::ranges::sort(queued_devices);
                REQUIRE(queued_devices == bob_devices);
                REQUIRE(store.next_sync_stream_id == sync_stream_before + bob_devices.size());
            }
        }
    }
}
