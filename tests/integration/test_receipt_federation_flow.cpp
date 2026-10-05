// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// Outbound receipts across federation.
//
// Spec: Matrix Server-Server API v1.19, m.receipt
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#mreceipt
//   "only a single <receipt_type> should be used: m.read. m.read.private MUST NOT appear in
//   this federated m.receipt EDU."
// Spec: Matrix Client-Server API v1.19, Receipts and Fully read markers
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#receipts
//   "m.fully_read does not appear under m.receipt" - the marker is room account data, local to
//   its owner, and is not a receipt to send to other servers.

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sodium.h>

using namespace merovingian::tests;

namespace
{

constexpr auto remote_server = std::string_view{"remote.example.org"};
constexpr auto bob = std::string_view{"@bob:remote.example.org"};

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
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

[[nodiscard]] auto register_alice(merovingian::homeserver::ClientServerRuntime& runtime) -> std::string
{
    auto const registration = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
    REQUIRE(registration.response.status == 200U);
    auto const body = parse_object(registration.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// A dispatch worker that is never started, so every EDU the server enqueues stays in its
// durable queue (store.federation_transactions) for the test to read.
auto install_unstarted_dispatch_worker(merovingian::homeserver::ClientServerRuntime& runtime) -> void
{
    REQUIRE(runtime.homeserver.outbound_client != nullptr);
    auto config = merovingian::federation::DispatchWorkerConfig{};
    config.origin = runtime.homeserver.config.server().server_name;
    config.key_id = "ed25519:test";
    runtime.homeserver.dispatch_worker = std::make_unique<merovingian::federation::DispatchWorker>(
        std::move(config), *runtime.homeserver.outbound_client,
        [](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        },
        merovingian::federation::DispatchClock{}, merovingian::federation::DispatchSleep{},
        &runtime.homeserver.database.persistent_store);
}

[[nodiscard]] auto queued_receipt_edus(merovingian::homeserver::ClientServerRuntime const& runtime)
    -> std::vector<std::string>
{
    auto const marker = std::string{R"("edu_type":"m.receipt")"};
    auto bodies = std::vector<std::string>{};
    for (auto const& transaction : runtime.homeserver.database.persistent_store.federation_transactions)
    {
        if (transaction.server_name == remote_server && transaction.body.find(marker) != std::string::npos)
        {
            bodies.push_back(transaction.body);
        }
    }
    return bodies;
}

[[nodiscard]] auto post(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                        std::string const& path, std::string const& body) -> unsigned
{
    return merovingian::homeserver::handle_client_server_request(runtime, {"POST", path, token, body}).response.status;
}

} // namespace

SCENARIO("Only m.read receipts are federated to other servers",
         "[integration][federation][receipt][edu][security][csaz-4]")
{
    GIVEN("alice shares a room with bob on another server")
    {
        REQUIRE(sodium_init() >= 0);

        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const alice_token = register_alice(runtime);
        auto const room_id = std::string{"!shared:example.org"};
        runtime.homeserver.database.rooms.push_back({
            room_id, "@alice:example.org", {"@alice:example.org", std::string{bob}},
              {}
        });
        auto const receipt_path = [&](std::string_view type) {
            return "/_matrix/client/v3/rooms/" + room_id + "/receipt/" + std::string{type} + "/$event:example.org";
        };

        WHEN("alice sends a public m.read receipt")
        {
            REQUIRE(post(runtime, alice_token, receipt_path("m.read"), "{}") == 200U);

            THEN("bob's server is sent one m.receipt EDU carrying m.read")
            {
                auto const edus = queued_receipt_edus(runtime);
                REQUIRE(edus.size() == 1U);
                REQUIRE(edus.front().find("m.read") != std::string::npos);
            }
        }

        WHEN("alice sends an m.read.private receipt")
        {
            REQUIRE(post(runtime, alice_token, receipt_path("m.read.private"), "{}") == 200U);

            THEN("nothing is sent to bob's server")
            {
                REQUIRE(queued_receipt_edus(runtime).empty());
            }
        }

        WHEN("alice sets an m.fully_read marker through the receipt endpoint")
        {
            REQUIRE(post(runtime, alice_token, receipt_path("m.fully_read"), "{}") == 200U);

            THEN("nothing is sent to bob's server, because the marker is private room account data")
            {
                REQUIRE(queued_receipt_edus(runtime).empty());
            }
        }

        WHEN("alice sets m.fully_read, m.read and m.read.private through /read_markers")
        {
            REQUIRE(post(runtime, alice_token, "/_matrix/client/v3/rooms/" + room_id + "/read_markers",
                         R"({"m.fully_read":"$event:example.org","m.read":"$event:example.org",)"
                         R"("m.read.private":"$event:example.org"})") == 200U);

            THEN("bob's server is sent a single m.receipt EDU with m.read only")
            {
                auto const edus = queued_receipt_edus(runtime);
                REQUIRE(edus.size() == 1U);
                REQUIRE(edus.front().find("m.read") != std::string::npos);
                REQUIRE(edus.front().find("m.read.private") == std::string::npos);
                REQUIRE(edus.front().find("m.fully_read") == std::string::npos);
            }
        }
    }
}
