// SPDX-License-Identifier: GPL-3.0-or-later

// Renaming a device is a change to the device list that other servers track.
// `PUT /devices/{deviceId}` recorded the change for local users sharing a room
// with the owner but never told a remote server, so a remote user's client
// kept the old device name (Complement TestFederationKeyUploadQuery, "Can
// query remote device keys using POST").
// Tags: [integration][federation][device_lists].
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md, "Device Management":
// "Servers must send `m.device_list_update` EDUs to all the servers who share
// a room with a given local user, and must be sent whenever that user's device
// list changes (i.e. for new or deleted devices, when that user joins a room
// which contains servers which are not already receiving updates for that
// user's device list, or changes in device information such as the device's
// human-readable name)."

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
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

constexpr auto sharing_server = std::string_view{"remote.example.org"};
constexpr auto unrelated_server = std::string_view{"elsewhere.example.org"};
constexpr auto bob = std::string_view{"@bob:remote.example.org"};
constexpr auto display_name = std::string_view{"My new displayname"};

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

struct RegisteredUser final
{
    std::string user_id{};
    std::string access_token{};
};

[[nodiscard]] auto register_user(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view localpart)
    -> RegisteredUser
{
    auto const registration = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(registration.response.status == 200U);
    auto const body = parse_object(registration.response.body);
    auto const* user_id = string_member(body, "user_id");
    auto const* token = string_member(body, "access_token");
    REQUIRE(user_id != nullptr);
    REQUIRE(token != nullptr);
    return {*user_id, *token};
}

// A dispatch worker that is never started, so every EDU the server enqueues
// stays in its durable queue (store.federation_transactions) for the test to
// read, with no worker thread racing the read.
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

// Bodies of the queued federation transactions addressed to `destination`
// that carry an EDU of `edu_type`.
[[nodiscard]] auto queued_edus(merovingian::homeserver::ClientServerRuntime const& runtime,
                               std::string_view destination, std::string_view edu_type) -> std::vector<std::string>
{
    auto const marker = std::string{R"("edu_type":")"} + std::string{edu_type} + "\"";
    auto bodies = std::vector<std::string>{};
    for (auto const& transaction : runtime.homeserver.database.persistent_store.federation_transactions)
    {
        if (transaction.server_name == destination && transaction.body.find(marker) != std::string::npos)
        {
            bodies.push_back(transaction.body);
        }
    }
    return bodies;
}

[[nodiscard]] auto device_id_of(merovingian::homeserver::ClientServerRuntime const& runtime, std::string_view user_id)
    -> std::string
{
    auto const& devices = runtime.homeserver.database.persistent_store.devices;
    auto const found = std::ranges::find_if(devices, [user_id](merovingian::database::PersistentDevice const& device) {
        return device.user_id == user_id;
    });
    REQUIRE(found != devices.end());
    return found->device_id;
}

[[nodiscard]] auto rename_device(merovingian::homeserver::ClientServerRuntime& runtime, RegisteredUser const& user,
                                 std::string const& device_id) -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {"PUT", "/_matrix/client/v3/devices/" + device_id, user.access_token,
                         std::string{R"({"display_name":")"} + std::string{display_name} + R"("})"})
        .response;
}

} // namespace

SCENARIO("Renaming a device tells the remote servers that share a room with its owner",
         "[integration][federation][device_lists][regression]")
{
    GIVEN("alice shares a room with bob on another server, and has a second server she shares nothing with")
    {
        REQUIRE(sodium_init() >= 0);

        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unstarted_dispatch_worker(runtime);
        auto const alice = register_user(runtime, "alice");
        auto const device_id = device_id_of(runtime, alice.user_id);
        runtime.homeserver.database.rooms.push_back({
            "!shared:example.org", alice.user_id, {alice.user_id, std::string{bob}},
              {}
        });

        WHEN("alice renames her device")
        {
            auto const response = rename_device(runtime, alice, device_id);
            REQUIRE(response.status == 200U);

            THEN("bob's server is sent an m.device_list_update naming the device and its new name")
            {
                auto const updates = queued_edus(runtime, sharing_server, "m.device_list_update");
                REQUIRE(updates.size() == 1U);
                REQUIRE(updates.front().find(device_id) != std::string::npos);
                REQUIRE(updates.front().find(alice.user_id) != std::string::npos);
                REQUIRE(updates.front().find(std::string{display_name}) != std::string::npos);
            }

            AND_THEN("a server that shares no room with alice is not told")
            {
                REQUIRE(queued_edus(runtime, unrelated_server, "m.device_list_update").empty());
            }
        }

        WHEN("alice tries to rename a device she does not have")
        {
            auto const response = rename_device(runtime, alice, "NOSUCHDEVICE");

            THEN("the request is refused and no server is told anything")
            {
                REQUIRE(response.status == 404U);
                REQUIRE(queued_edus(runtime, sharing_server, "m.device_list_update").empty());
            }
        }
    }
}

SCENARIO("A renamed device's new name is what the account's own key query reports",
         "[integration][device_lists][keys][regression]")
{
    GIVEN("alice has uploaded device keys under a first name and then renamed the device")
    {
        REQUIRE(sodium_init() >= 0);

        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const device_id = device_id_of(runtime, alice.user_id);
        auto const first_name = rename_device(runtime, alice, device_id);
        REQUIRE(first_name.status == 200U);
        auto const upload = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/keys/upload", alice.access_token,
                      std::string{R"({"device_keys":{"user_id":")"} + alice.user_id + R"(","device_id":")" + device_id +
                          R"(","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:)" +
                          device_id + R"(":"curve","ed25519:)" + device_id + R"(":"edkey"},"signatures":{")" +
                          alice.user_id + R"(":{"ed25519:)" + device_id + R"(":"sig"}}}})"});
        REQUIRE(upload.response.status == 200U);
        auto const renamed = merovingian::homeserver::handle_client_server_request(
            runtime, {"PUT", "/_matrix/client/v3/devices/" + device_id, alice.access_token,
                      R"({"display_name":"A different name"})"});
        REQUIRE(renamed.response.status == 200U);

        WHEN("alice queries her own keys")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/query", alice.access_token,
                          std::string{R"({"device_keys":{")"} + alice.user_id + R"(":[]}})"});
            REQUIRE(response.response.status == 200U);
            auto const body = parse_object(response.response.body);

            THEN("the device carries the name it has now, not the one it had at upload")
            {
                auto const* device_keys = object_member_as_object(body, "device_keys");
                REQUIRE(device_keys != nullptr);
                auto const* devices = object_member_as_object(*device_keys, alice.user_id);
                REQUIRE(devices != nullptr);
                auto const* device = object_member_as_object(*devices, device_id);
                REQUIRE(device != nullptr);
                auto const* unsigned_data = object_member_as_object(*device, "unsigned");
                REQUIRE(unsigned_data != nullptr);
                auto const* name = string_member(*unsigned_data, "device_display_name");
                REQUIRE(name != nullptr);
                REQUIRE(*name == "A different name");
            }
        }
    }
}
