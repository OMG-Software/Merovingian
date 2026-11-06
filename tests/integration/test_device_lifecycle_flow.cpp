// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A device's chosen display name survives a restart and is what other users see, and deleting a device deletes the
// to-device messages queued for it (analysis C6 and C10).
//
// Spec (C6): Matrix Client-Server API v1.19, POST /login `initial_device_display_name` ("A display name to assign to
// the newly-created device"), GET /devices `display_name` ("Absent if no name has been set") and POST /keys/query
// `unsigned.device_display_name` ("The display name which the user set on the device").
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3login
//
// C10 is this server's rule: a login that reuses a device ID must not receive what was queued for the old device.

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentToDeviceMessage.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <variant>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto sqlite_config(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto unique_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-device-lifecycle-" + std::to_string(now) + ".sqlite3");
}

struct Reply final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> Reply
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
    return {static_cast<std::uint16_t>(result.response.status), result.response.body};
}

[[nodiscard]] auto login(ClientServerRuntime& rt, std::string const& localpart, std::string const& device_id,
                         std::string const& display_name) -> std::string
{
    auto body = std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + device_id + "\"";
    if (!display_name.empty())
    {
        body += R"(,"initial_device_display_name":")" + display_name + "\"";
    }
    body += "}";
    auto const reply = call(rt, "POST", "/_matrix/client/v3/login", {}, body);
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* token = string_member(parsed, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

void upload_device_keys(ClientServerRuntime& rt, std::string const& token, std::string const& localpart,
                        std::string const& device_id)
{
    auto const body = std::string{R"({"device_keys":{"user_id":"@)"} + localpart + R"(:example.org","device_id":")" +
                      device_id + R"(","algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:)" +
                      device_id + R"(":"CURVE_)" + device_id + R"(","ed25519:)" + device_id + R"(":"ED_)" + device_id +
                      R"("}}})";
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/keys/upload", token, body).status == 200U);
}

// The `unsigned.device_display_name` that `viewer` is shown for @alice's `device_id`, if any; REQUIREs the device is
// listed.
[[nodiscard]] auto shown_display_name(ClientServerRuntime& rt, std::string const& viewer_token,
                                      std::string const& device_id) -> std::optional<std::string>
{
    auto const reply =
        call(rt, "POST", "/_matrix/client/v3/keys/query", viewer_token, R"({"device_keys":{"@alice:example.org":[]}})");
    REQUIRE(reply.status == 200U);
    auto const body = parse_object(reply.body);
    auto const* all = object_member_as_object(body, "device_keys");
    REQUIRE(all != nullptr);
    auto const* devices = object_member_as_object(*all, "@alice:example.org");
    REQUIRE(devices != nullptr);
    auto const* device = object_member_as_object(*devices, device_id);
    REQUIRE(device != nullptr);
    auto const* unsigned_data = object_member_as_object(*device, "unsigned");
    if (unsigned_data == nullptr)
    {
        return std::nullopt;
    }
    auto const* name = string_member(*unsigned_data, "device_display_name");
    return name == nullptr ? std::nullopt : std::optional<std::string>{*name};
}

[[nodiscard]] auto listed_display_name(ClientServerRuntime& rt, std::string const& token, std::string const& device_id)
    -> std::optional<std::string>
{
    auto const reply = call(rt, "GET", "/_matrix/client/v3/devices", token);
    REQUIRE(reply.status == 200U);
    auto const body = parse_object(reply.body);
    auto const* devices = object_member_as_array(body, "devices");
    REQUIRE(devices != nullptr);
    for (auto const& entry : *devices)
    {
        auto const* object = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        REQUIRE(object != nullptr);
        auto const* id = string_member(*object, "device_id");
        if (id != nullptr && *id == device_id)
        {
            auto const* name = string_member(*object, "display_name");
            return name == nullptr ? std::nullopt : std::optional<std::string>{*name};
        }
    }
    FAIL("device not listed: " << device_id);
    return std::nullopt;
}

} // namespace

SCENARIO("a device's initial display name is kept across a restart and shown to other users",
         "[integration][device][display-name][c6]")
{
    GIVEN("a user with one device named at login and one not named, and another user")
    {
        auto const path = unique_path();
        std::filesystem::remove(path);
        auto const config = sqlite_config(path);
        auto alice_named = std::string{};
        auto bob_token = std::string{};
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            auto& rt = started.runtime;
            REQUIRE(call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json("alice", "CorrectHorse7!"))
                        .status == 200U);
            REQUIRE(call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json("bob", "CorrectHorse7!"))
                        .status == 200U);
            alice_named = login(rt, "alice", "NAMED", "Jungle Phone");
            auto const alice_plain = login(rt, "alice", "PLAIN", "");
            upload_device_keys(rt, alice_named, "alice", "NAMED");
            upload_device_keys(rt, alice_plain, "alice", "PLAIN");
        }

        WHEN("the server restarts and the devices are listed and queried")
        {
            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto& rt = restarted.runtime;
            bob_token = login(rt, "bob", "BOBDEV", "");

            THEN("the chosen name is kept, and a device with no chosen name has none rather than its device ID")
            {
                REQUIRE(listed_display_name(rt, alice_named, "NAMED") == std::optional<std::string>{"Jungle Phone"});
                REQUIRE(listed_display_name(rt, alice_named, "PLAIN") == std::nullopt);
                REQUIRE(shown_display_name(rt, bob_token, "NAMED") == std::optional<std::string>{"Jungle Phone"});
                REQUIRE(shown_display_name(rt, bob_token, "PLAIN") == std::nullopt);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("deleting a device deletes the to-device messages queued for it", "[integration][device][to-device][c10]")
{
    GIVEN("a user with two devices, each with a queued message, and a message queued for all devices")
    {
        auto const path = unique_path();
        std::filesystem::remove(path);
        auto const config = sqlite_config(path);
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            auto& rt = started.runtime;
            REQUIRE(call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json("alice", "CorrectHorse7!"))
                        .status == 200U);
            std::ignore = login(rt, "alice", "OLD", "");
            std::ignore = login(rt, "alice", "KEEP", "");
            auto& store = rt.homeserver.database.persistent_store;
            for (auto const* device : {"OLD", "KEEP", "*"})
            {
                REQUIRE(merovingian::database::enqueue_to_device_message(
                    store, {0U, "@alice:example.org", "@alice:example.org", device, "m.room_key",
                            R"({"for":")" + std::string{device} + R"("})"}));
            }
            REQUIRE(store.to_device_messages.size() == 3U);

            WHEN("the OLD device is deleted")
            {
                REQUIRE(merovingian::database::delete_device(store, "@alice:example.org", "OLD"));

                THEN("nothing addressed to OLD is held, in memory or after a restart, and the rest is")
                {
                    auto const addressed_to_old = [](merovingian::database::PersistentToDeviceMessage const& row) {
                        return row.target_device_id == "OLD";
                    };
                    REQUIRE(std::ranges::none_of(store.to_device_messages, addressed_to_old));
                    REQUIRE(store.to_device_messages.size() == 2U);

                    auto restarted = merovingian::homeserver::start_client_server(config);
                    REQUIRE(restarted.started);
                    auto const& reloaded = restarted.runtime.homeserver.database.persistent_store.to_device_messages;
                    REQUIRE(std::ranges::none_of(reloaded, addressed_to_old));
                    REQUIRE(reloaded.size() == 2U);
                }
            }
        }
        std::filesystem::remove(path);
    }
}
