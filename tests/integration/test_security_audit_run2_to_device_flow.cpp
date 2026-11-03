// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run-2, F-14 (ADR-0335): the to-device queue is bounded in bytes per recipient. These
// scenarios cover what the unit scenarios cannot: that the byte total is right after a restart
// (hydration from SQLite), and that an inbound m.direct_to_device EDU drops only its oversized
// message.
//
// Spec: server-server-api.md, "Send-to-device messaging": the EDU carries `messages`, a map of user
// ID to device ID to message body; the spec states no size limit, so the limit is an ADR-0335 choice
// and an over-limit message is dropped alone, not the EDU (EDUs are best-effort).

#include "../federation_signing_test_support.hpp"
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>

namespace
{

using merovingian::database::PersistentStore;
using merovingian::database::PersistentToDeviceMessage;

class TemporarySqliteDirectory final
{
public:
    TemporarySqliteDirectory()
    {
        auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = merovingian::tests::temporary_directory() / ("merovingian-run2-to-device-" + std::to_string(now));
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
        return path_ / "to-device.sqlite3";
    }

private:
    std::filesystem::path path_{};
};

[[nodiscard]] auto content_of_size(std::size_t bytes) -> std::string
{
    auto const overhead = std::string_view{R"({"p":""})"}.size();
    REQUIRE(bytes > overhead);
    return std::string{R"({"p":")"} + std::string(bytes - overhead, 'x') + R"("})";
}

[[nodiscard]] auto message_to(std::string_view user, std::string_view device, std::string content)
    -> PersistentToDeviceMessage
{
    return {0U, "@alice:example.org", std::string{user}, std::string{device}, "m.test.message", std::move(content)};
}

[[nodiscard]] auto federation_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.federation.enabled = true;
    security.federation.default_policy = "allow";
    security.federation.max_transaction_size = "1MiB";
    security.federation.remote_timeout = "30s";
    return {merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            merovingian::tests::in_memory_database_config(),
            std::move(security),
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{}};
}

} // namespace

SCENARIO("the byte total of a to-device queue survives acknowledgement and a restart on SQLite",
         "[integration][sqlite][to-device][security][run2][f14]")
{
    GIVEN("a SQLite store allowing 100 queued bytes per recipient, holding two 40-byte rows for one device")
    {
        auto const sqlite = TemporarySqliteDirectory{};
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite.database_path().string());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        store.max_to_device_messages_per_user_device = 0U;
        store.to_device_message_ttl_seconds = 0U;
        store.max_to_device_message_bytes = 100U;
        store.max_to_device_bytes_per_user_device = 100U;
        for (auto ordinal = 0; ordinal < 3; ++ordinal)
        {
            REQUIRE(merovingian::database::enqueue_to_device_message(
                store, message_to("@bob:example.org", "BOB", content_of_size(40U))));
        }
        REQUIRE(merovingian::database::to_device_queue_bytes(store, "@bob:example.org", "BOB") == 80U);

        WHEN("the store is reopened, as at a restart")
        {
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite.database_path().string());
            REQUIRE(reopened.ok);
            auto& hydrated = reopened.store;
            hydrated.max_to_device_messages_per_user_device = 0U;
            hydrated.to_device_message_ttl_seconds = 0U;
            hydrated.max_to_device_message_bytes = 100U;
            hydrated.max_to_device_bytes_per_user_device = 100U;

            THEN("the evicted row was deleted durably, so the hydrated queue and its byte total match")
            {
                REQUIRE(hydrated.to_device_messages.size() == 2U);
                REQUIRE(merovingian::database::to_device_queue_bytes(hydrated, "@bob:example.org", "BOB") == 80U);
            }
            THEN("a message queued after the restart evicts the oldest hydrated row against the same total")
            {
                REQUIRE(merovingian::database::enqueue_to_device_message(
                    hydrated, message_to("@bob:example.org", "BOB", content_of_size(40U))));
                REQUIRE(hydrated.to_device_messages.size() == 2U);
                REQUIRE(merovingian::database::to_device_queue_bytes(hydrated, "@bob:example.org", "BOB") == 80U);
            }
        }

        WHEN("the device acknowledges what it was sent and the store is reopened")
        {
            std::ignore = merovingian::database::drain_to_device_messages(store, "@bob:example.org", "BOB", 0U,
                                                                          store.next_sync_stream_id);
            std::ignore = merovingian::database::drain_to_device_messages(
                store, "@bob:example.org", "BOB", store.next_sync_stream_id, store.next_sync_stream_id);
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite.database_path().string());
            REQUIRE(reopened.ok);

            THEN("no bytes are counted in memory or after hydration")
            {
                REQUIRE(merovingian::database::to_device_queue_bytes(store, "@bob:example.org", "BOB") == 0U);
                REQUIRE(merovingian::database::to_device_queue_bytes(reopened.store, "@bob:example.org", "BOB") == 0U);
            }
        }
    }
}

SCENARIO("an inbound to-device EDU drops its oversized message and keeps the rest",
         "[integration][to-device][federation][security][run2][f14]")
{
    GIVEN("alice with two devices, a per-message limit of 64 bytes and a signed remote server")
    {
        auto started = merovingian::homeserver::start_client_server(federation_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const register_response = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(register_response.response.status == 200U);
        for (auto const* device : {"DEVICE1", "DEVICE2"})
        {
            auto const login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 std::string{
                     R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":")"} +
                     device + R"("})"});
            REQUIRE(login.response.status == 200U);
        }
        runtime.homeserver.database.persistent_store.max_to_device_message_bytes = 64U;

        auto const origin = std::string{"matrix.ping.me.uk"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const keypair = merovingian::federation::test::keypair_from_seed("run2-to-device-seed");
        auto remote = merovingian::federation::FederationRemoteRuntime{};
        remote.server_name = origin;
        remote.signing_key = {origin, key_id, std::numeric_limits<std::uint64_t>::max(), keypair.public_key};
        remote.discovery.server_name = origin;
        remote.discovery.well_known_host = origin;
        remote.discovery.resolved_host = origin;
        remote.discovery.resolved_addresses = {"203.0.113.10"};
        remote.discovery.tls_required = true;
        remote.trust.reputation_score = 100U;
        merovingian::federation::upsert_remote(runtime.homeserver.federation, std::move(remote));

        auto const target = std::string{"/_matrix/federation/v1/send/txn-oversized"};
        auto const body =
            std::string{"{\"origin\":\""} + origin +
            R"(","origin_server_ts":1000,"pdus":[],"edus":[{"edu_type":"m.direct_to_device","content":{"sender":"@james:)" +
            origin + R"(","type":"m.room.encrypted","message_id":"oversized-one","messages":{"@alice:example.org":{)" +
            R"("DEVICE1":)" + content_of_size(65U) + R"(,"DEVICE2":{"value":"small"}}}}}]})";
        auto const signature = merovingian::federation::make_federation_signature(origin, "example.org", "PUT", target,
                                                                                  body, keypair.secret_key);

        WHEN("the signed transaction carries one message over the limit and one within it")
        {
            auto request = merovingian::homeserver::LocalHttpRequest{};
            request.method = "PUT";
            request.target = target;
            request.access_token = std::string{"X-Matrix origin=\""} + origin +
                                   "\",destination=\"example.org\",key=\"" + key_id + "\",sig=\"" + signature + "\"";
            request.body = body;
            auto const response = merovingian::homeserver::handle_federation_http_request(runtime.homeserver, request);

            THEN("the transaction succeeds and only the message within the limit is queued")
            {
                REQUIRE(response.status == 200U);
                auto const& rows = runtime.homeserver.database.persistent_store.to_device_messages;
                REQUIRE(rows.size() == 1U);
                REQUIRE(rows.front().target_device_id == "DEVICE2");
                REQUIRE(rows.front().content_json == R"({"value":"small"})");
            }
        }
    }
}
