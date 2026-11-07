// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Two device-lifecycle rules the spec states and the server used to leave unchecked:
//  - a deleted or logged-out device is announced to the remote servers that share a room with its
//    owner, as an m.device_list_update with `deleted: true` (SS API, Device Management);
//  - a device ID is never the same as one of the account's cross-signing key IDs, at login
//    (403 M_FORBIDDEN) or when such a key is uploaded (403).

#include "../support/cross_signing_fixture.hpp"
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/federation/DispatchWorker.hpp"
#include "merovingian/federation/DispatchWorkerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;
using merovingian::homeserver::handle_client_server_request;

constexpr auto password = std::string_view{"CorrectHorse7!"};
constexpr auto remote_server = std::string_view{"remote.example.org"};
constexpr auto unrelated_server = std::string_view{"elsewhere.example.org"};
constexpr auto bob = std::string_view{"@bob:remote.example.org"};

[[nodiscard]] auto make_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.federation.enabled = true;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto send(ClientServerRuntime& runtime, std::string method, std::string target, std::string token = {},
                        std::string body = {}) -> merovingian::homeserver::LocalHttpResponse
{
    return handle_client_server_request(runtime,
                                        {std::move(method), std::move(target), std::move(token), std::move(body)})
        .response;
}

[[nodiscard]] auto errcode_of(merovingian::homeserver::LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

[[nodiscard]] auto login_body(std::string const& localpart, std::string const& device_id) -> std::string
{
    return R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + localpart +
           R"(:example.org"},"password":")" + std::string{password} + R"(","device_id":")" + device_id + R"("})";
}

auto register_user(ClientServerRuntime& runtime, std::string const& localpart) -> void
{
    REQUIRE(send(runtime, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, password)).status ==
            200U);
}

// Logs `localpart` in under `device_id` and returns the access token.
[[nodiscard]] auto login_as(ClientServerRuntime& runtime, std::string const& localpart, std::string const& device_id)
    -> std::string
{
    auto const login = send(runtime, "POST", "/_matrix/client/v3/login", {}, login_body(localpart, device_id));
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto password_auth() -> std::string
{
    return R"("auth":{"type":"m.login.password","password":")" + std::string{password} + R"("})";
}

// A dispatch worker that is never started, so every EDU the server enqueues stays in its durable
// queue (store.federation_transactions) for the test to read, with no worker thread racing the read.
auto install_unstarted_dispatch_worker(ClientServerRuntime& runtime) -> void
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

// Bodies of the queued federation transactions addressed to `destination` that carry an EDU of
// `edu_type`.
[[nodiscard]] auto queued_edus(ClientServerRuntime const& runtime, std::string_view destination,
                               std::string_view edu_type) -> std::vector<std::string>
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

// The queued deletion announcements for `device_id`, as EDU bodies.
[[nodiscard]] auto deletion_edus(ClientServerRuntime const& runtime, std::string_view destination,
                                 std::string_view device_id) -> std::vector<std::string>
{
    auto matching = std::vector<std::string>{};
    auto const device_marker = std::string{R"("device_id":")"} + std::string{device_id} + "\"";
    for (auto const& body : queued_edus(runtime, destination, "m.device_list_update"))
    {
        if (body.find(R"("deleted":true)") != std::string::npos && body.find(device_marker) != std::string::npos)
        {
            matching.push_back(body);
        }
    }
    return matching;
}

[[nodiscard]] auto stream_id_of(std::string const& edu_body) -> std::optional<std::int64_t>
{
    auto const marker = std::string_view{R"("stream_id":)"};
    auto const at = edu_body.find(marker);
    if (at == std::string::npos)
    {
        return std::nullopt;
    }
    auto position = at + marker.size();
    auto value = std::int64_t{0};
    auto digits = 0;
    while (position < edu_body.size() && edu_body[position] >= '0' && edu_body[position] <= '9')
    {
        value = value * 10 + (edu_body[position] - '0');
        ++position;
        ++digits;
    }
    return digits == 0 ? std::nullopt : std::optional<std::int64_t>{value};
}

[[nodiscard]] auto device_exists(ClientServerRuntime const& runtime, std::string_view user_id,
                                 std::string_view device_id) -> bool
{
    return std::ranges::any_of(runtime.homeserver.database.persistent_store.devices,
                               [user_id, device_id](merovingian::database::PersistentDevice const& device) {
                                   return device.user_id == user_id && device.device_id == device_id;
                               });
}

// alice (devices DEVICE1 and DEVICE2) shares a room with bob on remote.example.org.
struct AliceTokens final
{
    std::string first{};
    std::string second{};
};

[[nodiscard]] auto set_up_shared_room(ClientServerRuntime& runtime) -> AliceTokens
{
    install_unstarted_dispatch_worker(runtime);
    register_user(runtime, "alice");
    auto first = login_as(runtime, "alice", "DEVICE1");
    auto second = login_as(runtime, "alice", "DEVICE2");
    runtime.homeserver.database.rooms.push_back({
        "!shared:example.org", "@alice:example.org", {"@alice:example.org", std::string{bob}},
          {}
    });
    return {std::move(first), std::move(second)};
}

} // namespace

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Device Management (m.device_list_update)
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#device-management
//
// "Servers must send `m.device_list_update` EDUs to all the servers who share a room with a given
// local user, and must be sent whenever that user's device list changes (i.e. for new or deleted
// devices ...)." The EDU's `deleted` is "True if the server is announcing that this device has
// been deleted."
SCENARIO("Deleting a device tells the remote servers that share a room with its owner",
         "[conformance][federation][device_lists][device_removal]")
{
    GIVEN("alice shares a room with bob on another server and owns two devices")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(make_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const tokens = set_up_shared_room(runtime);

        WHEN("alice deletes one device with DELETE /devices/{deviceId}")
        {
            auto const response = send(runtime, "DELETE", "/_matrix/client/v3/devices/DEVICE2", tokens.first,
                                       "{" + password_auth() + "}");
            REQUIRE(response.status == 200U);

            THEN("bob's server is queued an m.device_list_update with deleted true for that device")
            {
                auto const updates = deletion_edus(runtime, remote_server, "DEVICE2");
                // Spec MUST: an EDU is sent for deleted devices to every server sharing a room.
                REQUIRE(updates.size() == 1U);
                REQUIRE(updates.front().find(R"("user_id":"@alice:example.org")") != std::string::npos);
                REQUIRE(stream_id_of(updates.front()).has_value());
            }
            THEN("the announcement carries no device keys")
            {
                auto const updates = deletion_edus(runtime, remote_server, "DEVICE2");
                REQUIRE(updates.size() == 1U);
                REQUIRE(updates.front().find(R"("keys")") == std::string::npos);
            }
            THEN("a server that shares no room with alice is not told")
            {
                REQUIRE(queued_edus(runtime, unrelated_server, "m.device_list_update").empty());
            }
            THEN("the device that stayed is not announced as deleted")
            {
                REQUIRE(deletion_edus(runtime, remote_server, "DEVICE1").empty());
            }
        }

        WHEN("alice deletes a device she does not own")
        {
            auto const response = send(runtime, "DELETE", "/_matrix/client/v3/devices/NOSUCHDEVICE", tokens.first,
                                       "{" + password_auth() + "}");

            THEN("the request is refused and nothing is announced")
            {
                REQUIRE(response.status == 404U);
                REQUIRE(queued_edus(runtime, remote_server, "m.device_list_update").empty());
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Device Management (m.device_list_update), stream_id
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#device-management
//
// "Servers send `m.device_list_update` EDUs in a sequence per origin user, each with a unique
// `stream_id`." One EDU per deleted device, each with its own stream_id; `prev_id` names the
// stream_ids of prior EDUs not yet referred to.
SCENARIO("Deleting several devices at once announces each with its own stream_id",
         "[conformance][federation][device_lists][device_removal]")
{
    GIVEN("alice shares a room with bob on another server and owns three devices")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(make_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const tokens = set_up_shared_room(runtime);
        std::ignore = login_as(runtime, "alice", "DEVICE3");

        WHEN("alice deletes two of them with POST /delete_devices")
        {
            auto const response = send(runtime, "POST", "/_matrix/client/v3/delete_devices", tokens.first,
                                       R"({"devices":["DEVICE2","DEVICE3"],)" + password_auth() + "}");
            REQUIRE(response.status == 200U);

            THEN("each deleted device is announced once to bob's server")
            {
                REQUIRE(deletion_edus(runtime, remote_server, "DEVICE2").size() == 1U);
                REQUIRE(deletion_edus(runtime, remote_server, "DEVICE3").size() == 1U);
                REQUIRE(deletion_edus(runtime, remote_server, "DEVICE1").empty());
            }
            THEN("the two announcements have different stream_ids")
            {
                auto const first = stream_id_of(deletion_edus(runtime, remote_server, "DEVICE2").front());
                auto const second = stream_id_of(deletion_edus(runtime, remote_server, "DEVICE3").front());
                REQUIRE(first.has_value());
                REQUIRE(second.has_value());
                // Spec MUST: the stream_id is "unique for a given user_id".
                REQUIRE(*first != *second);
            }
            THEN("the later announcement names the earlier one in prev_id")
            {
                auto const first = stream_id_of(deletion_edus(runtime, remote_server, "DEVICE2").front());
                REQUIRE(first.has_value());
                auto const later = deletion_edus(runtime, remote_server, "DEVICE3").front();
                REQUIRE(later.find(R"("prev_id":[)" + std::to_string(*first) + "]") != std::string::npos);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Device Management (m.device_list_update)
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#device-management
//
// A logout deletes the device (CS API POST /logout), so it is a deleted device for the remote
// servers as well.
SCENARIO("Logging out tells the remote servers that share a room with the user the device is gone",
         "[conformance][federation][device_lists][device_removal]")
{
    GIVEN("alice shares a room with bob on another server and owns two devices")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(make_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const tokens = set_up_shared_room(runtime);

        WHEN("the second device logs out")
        {
            REQUIRE(send(runtime, "POST", "/_matrix/client/v3/logout", tokens.second).status == 200U);

            THEN("bob's server is queued a deleted announcement for that device only")
            {
                REQUIRE(deletion_edus(runtime, remote_server, "DEVICE2").size() == 1U);
                REQUIRE(deletion_edus(runtime, remote_server, "DEVICE1").empty());
            }
        }

        WHEN("alice logs out of every device")
        {
            REQUIRE(send(runtime, "POST", "/_matrix/client/v3/logout/all", tokens.first).status == 200U);

            THEN("bob's server is queued a deleted announcement for each device")
            {
                REQUIRE(deletion_edus(runtime, remote_server, "DEVICE1").size() == 1U);
                REQUIRE(deletion_edus(runtime, remote_server, "DEVICE2").size() == 1U);
                REQUIRE_FALSE(device_exists(runtime, "@alice:example.org", "DEVICE1"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /login
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3login
//
// Request body (client-server-api.md:4839): the `device_id` "must not be the same as a
// cross-signing key ID". Responses (client-server-api.md:4888): 403 `M_FORBIDDEN` when "the
// requested device ID is the same as a cross-signing key ID".
SCENARIO("A login naming a cross-signing key ID as its device is refused", "[conformance][client-server][auth][keys]")
{
    GIVEN("alice has uploaded cross-signing keys")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(make_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        register_user(runtime, "alice");
        auto const token = login_as(runtime, "alice", "DEVICE1");
        auto const set = make_cross_signing_set("@alice:example.org", true);
        auto const upload = send(runtime, "POST", "/_matrix/client/v3/keys/device_signing/upload", token,
                                 R"({)" + password_auth() + "," + set.members() + "}");
        REQUIRE(upload.status == 200U);

        WHEN("alice logs in with her master key's ID as the device ID")
        {
            auto const login =
                send(runtime, "POST", "/_matrix/client/v3/login", {}, login_body("alice", set.master.public_key));

            THEN("the login is refused with 403 M_FORBIDDEN and no device is created")
            {
                // Spec MUST: 403 M_FORBIDDEN for a device ID equal to a cross-signing key ID.
                REQUIRE(login.status == 403U);
                REQUIRE(errcode_of(login) == "M_FORBIDDEN");
                REQUIRE_FALSE(device_exists(runtime, "@alice:example.org", set.master.public_key));
            }
        }
        WHEN("alice logs in with her self-signing or user-signing key's ID as the device ID")
        {
            auto const self_login =
                send(runtime, "POST", "/_matrix/client/v3/login", {}, login_body("alice", set.self_signing.public_key));
            auto const user_login =
                send(runtime, "POST", "/_matrix/client/v3/login", {}, login_body("alice", set.user_signing.public_key));

            THEN("both are refused with 403 M_FORBIDDEN")
            {
                REQUIRE(self_login.status == 403U);
                REQUIRE(errcode_of(self_login) == "M_FORBIDDEN");
                REQUIRE(user_login.status == 403U);
                REQUIRE(errcode_of(user_login) == "M_FORBIDDEN");
            }
        }
        WHEN("alice logs in with an ordinary device ID")
        {
            auto const login = send(runtime, "POST", "/_matrix/client/v3/login", {}, login_body("alice", "LAPTOP"));

            THEN("the login succeeds")
            {
                REQUIRE(login.status == 200U);
                REQUIRE(device_exists(runtime, "@alice:example.org", "LAPTOP"));
            }
        }
        WHEN("bob logs in with a device ID that is alice's master key ID")
        {
            register_user(runtime, "bob");
            auto const login =
                send(runtime, "POST", "/_matrix/client/v3/login", {}, login_body("bob", set.master.public_key));

            THEN("the login succeeds, because the rule is about the account's own cross-signing keys")
            {
                REQUIRE(login.status == 200U);
            }
        }
        WHEN("a login omits the device ID")
        {
            auto const body = std::string{
                R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":")" +
                std::string{password} + R"("})"};
            auto const login = send(runtime, "POST", "/_matrix/client/v3/login", {}, body);

            THEN("the server-generated device ID is accepted")
            {
                REQUIRE(login.status == 200U);
                auto const parsed = parse_object(login.body);
                auto const* device_id = string_member(parsed, "device_id");
                REQUIRE(device_id != nullptr);
                REQUIRE(device_exists(runtime, "@alice:example.org", *device_id));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /keys/device_signing/upload
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3keysdevice_signingupload
//
// Responses (client-server-api.md:28072): 403 "The public key of one of the keys is the same as one
// of the user's device IDs, or the request is not authorised for any other reason." Cross-signing
// section: "servers MUST not allow devices to have the same IDs as cross-signing keys".
SCENARIO("A cross-signing upload whose key is the ID of one of the user's devices is refused",
         "[conformance][client-server][keys][e2ee]")
{
    GIVEN("alice owns a device named DEVICE1")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(make_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        register_user(runtime, "alice");
        auto const token = login_as(runtime, "alice", "DEVICE1");

        WHEN("she uploads a master key whose ID is that of one of her devices")
        {
            auto const set = make_cross_signing_set("@alice:example.org", true);
            std::ignore = login_as(runtime, "alice", set.master.public_key);
            auto const upload = send(runtime, "POST", "/_matrix/client/v3/keys/device_signing/upload", token,
                                     R"({)" + password_auth() + "," + set.master_member() + "}");

            THEN("the upload is refused with 403 and the key is not stored")
            {
                // Spec: 403 when the key's public key is the same as one of the user's device IDs.
                REQUIRE(upload.status == 403U);
                REQUIRE(errcode_of(upload) == "M_FORBIDDEN");
                REQUIRE(runtime.homeserver.database.persistent_store.cross_signing_keys.empty());
            }
        }
        WHEN("she uploads a valid master key and a user-signing key whose ID is that of one of her devices")
        {
            auto const set = make_cross_signing_set("@alice:example.org", true);
            std::ignore = login_as(runtime, "alice", set.user_signing.public_key);
            auto const upload =
                send(runtime, "POST", "/_matrix/client/v3/keys/device_signing/upload", token,
                     R"({)" + password_auth() + "," + set.master_member() + "," + set.user_signing_member() + "}");

            THEN("nothing from the upload is stored")
            {
                REQUIRE(upload.status == 403U);
                REQUIRE(runtime.homeserver.database.persistent_store.cross_signing_keys.empty());
            }
        }
        WHEN("she uploads a master key whose ID matches no device of hers")
        {
            auto const set = make_cross_signing_set("@alice:example.org", true);
            auto const upload = send(runtime, "POST", "/_matrix/client/v3/keys/device_signing/upload", token,
                                     R"({)" + password_auth() + "," + set.master_member() + "}");

            THEN("the upload is accepted")
            {
                REQUIRE(upload.status == 200U);
                REQUIRE(runtime.homeserver.database.persistent_store.cross_signing_keys.size() == 1U);
            }
        }
        WHEN("bob has a device named like the master key alice uploads")
        {
            register_user(runtime, "bob");
            auto const set = make_cross_signing_set("@alice:example.org", true);
            std::ignore = login_as(runtime, "bob", set.master.public_key);
            auto const upload = send(runtime, "POST", "/_matrix/client/v3/keys/device_signing/upload", token,
                                     R"({)" + password_auth() + "," + set.master_member() + "}");

            THEN("the upload is accepted, because only the uploader's own devices count")
            {
                REQUIRE(upload.status == 200U);
            }
        }
    }
}
