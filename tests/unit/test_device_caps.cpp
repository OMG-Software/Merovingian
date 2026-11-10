// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run-4 F-05 (ADR-0582). Device creation had no cap on a user's devices and none on a device's
// display name, and one device-list announcement scanned the device tables once per device under the runtime lock.
// Policy: a NEW device past `device_count_limit` is 403 M_FORBIDDEN with nothing written (a device the user already
// holds always logs in); a display name over `device_display_name_byte_limit` bytes is 400 M_TOO_LARGE with nothing
// stored, at POST /login, POST /register and PUT /devices/{deviceId}; an announcement of all of a user's devices makes
// a fixed number of passes over the device tables.

#include "../support/e2ee_caps_support.hpp"
#include "merovingian/database/PersistentDevice.hpp"
#include "merovingian/database/PersistentDeviceKey.hpp"
#include "merovingian/federation/DeviceListUpdateBatch.hpp"
#include "merovingian/federation/key_query.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/device_limits.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace
{

namespace hs = merovingian::homeserver;
using merovingian::tests::caps_config;
using merovingian::tests::register_and_login_alice;

constexpr auto alice = std::string_view{"@alice:example.org"};

[[nodiscard]] auto devices_of(hs::ClientServerRuntime const& runtime, std::string_view user) -> std::size_t
{
    auto const& devices = runtime.homeserver.database.persistent_store.devices;
    return static_cast<std::size_t>(std::ranges::count_if(devices, [user](auto const& device) {
        return device.user_id == user;
    }));
}

// Logs alice in on `DEVICE1` .. up to `count` devices in all, straight through the auth service (an HTTP login
// per device would meet the login rate limit, which is not what these scenarios are about).
auto fill_devices(hs::ClientServerRuntime& runtime, std::size_t count) -> void
{
    for (auto index = std::size_t{2U}; devices_of(runtime, alice) < count; ++index)
    {
        auto const result =
            hs::login_local_user_by_id(runtime.homeserver, alice, "FILL" + std::to_string(index), false, {});
        REQUIRE(result.ok);
    }
    REQUIRE(devices_of(runtime, alice) == count);
}

[[nodiscard]] auto login_with(hs::ClientServerRuntime& runtime, std::string_view device_id,
                              std::string_view display_name = {}) -> hs::LocalHttpResponse
{
    auto body = std::string{
        R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":")"};
    body += device_id;
    body += '"';
    if (!display_name.empty())
    {
        body += R"(,"initial_device_display_name":")";
        body += display_name;
        body += '"';
    }
    body += '}';
    return hs::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/login", {}, std::move(body)})
        .response;
}

[[nodiscard]] auto name_of(hs::ClientServerRuntime const& runtime, std::string_view device_id) -> std::string
{
    for (auto const& device : runtime.homeserver.database.persistent_store.devices)
    {
        if (device.user_id == alice && device.device_id == device_id)
        {
            return device.display_name;
        }
    }
    return "<no such device>";
}

[[nodiscard]] auto contains(std::string const& haystack, std::string_view needle) -> bool
{
    return haystack.find(needle) != std::string::npos;
}

} // namespace

SCENARIO("a user at the device cap cannot create another device, but a device they hold still logs in",
         "[homeserver][client-server][devices][limits][security][f05]")
{
    GIVEN("a user holding exactly the maximum number of devices")
    {
        auto started = hs::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        std::ignore = register_and_login_alice(runtime);
        fill_devices(runtime, hs::device_count_limit);
        auto const sessions_before = runtime.homeserver.database.sessions.size();

        WHEN("the user logs in with a device ID they do not hold")
        {
            auto const refused = login_with(runtime, "ONEMORE");

            THEN("it is 403 M_FORBIDDEN and no device or session row is created")
            {
                REQUIRE(refused.status == 403U);
                REQUIRE(contains(refused.body, "M_FORBIDDEN"));
                REQUIRE(devices_of(runtime, alice) == hs::device_count_limit);
                REQUIRE(name_of(runtime, "ONEMORE") == "<no such device>");
                REQUIRE(runtime.homeserver.database.sessions.size() == sessions_before);
            }
        }

        WHEN("the user logs in again with a device ID they hold")
        {
            auto const accepted = login_with(runtime, "DEVICE1");

            THEN("it succeeds and the device count does not change")
            {
                REQUIRE(accepted.status == 200U);
                REQUIRE(devices_of(runtime, alice) == hs::device_count_limit);
                // F-08 (ADR-0590): the login on a held device replaces its session, so the count is unchanged.
                REQUIRE(runtime.homeserver.database.sessions.size() == sessions_before);
            }
        }

        WHEN("an application service logs in as the user with a new device ID")
        {
            auto const refused = hs::login_appservice_user(runtime.homeserver, alice, "ASDEVICE", {});

            THEN("it is refused 403 and writes nothing")
            {
                REQUIRE_FALSE(refused.ok);
                REQUIRE(refused.status == 403U);
                REQUIRE(devices_of(runtime, alice) == hs::device_count_limit);
                REQUIRE(runtime.homeserver.database.sessions.size() == sessions_before);
            }
        }

        WHEN("an application service logs in as the user with a device ID they hold")
        {
            auto const accepted = hs::login_appservice_user(runtime.homeserver, alice, "DEVICE1", {});

            THEN("it succeeds")
            {
                REQUIRE(accepted.ok);
                REQUIRE(devices_of(runtime, alice) == hs::device_count_limit);
            }
        }

        WHEN("a login by user ID (the SSO and token path) names a new device")
        {
            auto const refused = hs::login_local_user_by_id(runtime.homeserver, alice, "SSODEVICE", false, {});

            THEN("it is refused 403 and writes nothing")
            {
                REQUIRE_FALSE(refused.ok);
                REQUIRE(refused.status == 403U);
                REQUIRE(devices_of(runtime, alice) == hs::device_count_limit);
                REQUIRE(runtime.homeserver.database.sessions.size() == sessions_before);
            }
        }
    }

    GIVEN("a user one device short of the cap")
    {
        auto started = hs::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        std::ignore = register_and_login_alice(runtime);
        fill_devices(runtime, hs::device_count_limit - 1U);

        WHEN("the user logs in with a new device ID")
        {
            auto const accepted = login_with(runtime, "LASTONE");

            THEN("it succeeds and the user is at the cap")
            {
                REQUIRE(accepted.status == 200U);
                REQUIRE(devices_of(runtime, alice) == hs::device_count_limit);
            }
        }
    }
}

SCENARIO("a device display name is at most 256 bytes at login, registration and rename, and is never truncated",
         "[homeserver][client-server][devices][limits][security][f05]")
{
    GIVEN("a registered user")
    {
        auto started = hs::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);
        auto const at_limit = std::string(hs::device_display_name_byte_limit, 'n');
        auto const over_limit = std::string(hs::device_display_name_byte_limit + 1U, 'n');
        // 129 two-byte characters: 129 code points, 258 bytes. Bytes are what is measured.
        auto over_in_bytes_only = std::string{};
        for (auto index = 0; index < 129; ++index)
        {
            over_in_bytes_only += "\xC3\xA9";
        }

        WHEN("POST /login names a display name of exactly 256 bytes")
        {
            auto const accepted = login_with(runtime, "NAMED", at_limit);

            THEN("it is accepted and stored whole")
            {
                REQUIRE(accepted.status == 200U);
                REQUIRE(name_of(runtime, "NAMED") == at_limit);
            }
        }

        WHEN("POST /login names a display name of 257 bytes")
        {
            auto const devices_before = devices_of(runtime, alice);
            auto const refused = login_with(runtime, "TOOBIG", over_limit);

            THEN("it is 400 M_TOO_LARGE and no device is stored")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(contains(refused.body, "M_TOO_LARGE"));
                REQUIRE(name_of(runtime, "TOOBIG") == "<no such device>");
                REQUIRE(devices_of(runtime, alice) == devices_before);
            }
        }

        WHEN("POST /login names a display name of 129 characters that is 258 bytes")
        {
            auto const refused = login_with(runtime, "TOOBIG", over_in_bytes_only);

            THEN("it is refused: the limit counts bytes, not code points")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(contains(refused.body, "M_TOO_LARGE"));
                REQUIRE(name_of(runtime, "TOOBIG") == "<no such device>");
            }
        }

        WHEN("PUT /devices/{deviceId} renames a device to exactly 256 bytes")
        {
            auto const accepted =
                hs::handle_client_server_request(runtime, {"PUT", "/_matrix/client/v3/devices/DEVICE1", token,
                                                           R"({"display_name":")" + at_limit + R"("})"})
                    .response;

            THEN("it is accepted and stored whole")
            {
                REQUIRE(accepted.status == 200U);
                REQUIRE(name_of(runtime, "DEVICE1") == at_limit);
            }
        }

        WHEN("PUT /devices/{deviceId} renames a device to 257 bytes")
        {
            auto const before = name_of(runtime, "DEVICE1");
            auto const refused =
                hs::handle_client_server_request(runtime, {"PUT", "/_matrix/client/v3/devices/DEVICE1", token,
                                                           R"({"display_name":")" + over_limit + R"("})"})
                    .response;

            THEN("it is 400 M_TOO_LARGE and the stored name is unchanged")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(contains(refused.body, "M_TOO_LARGE"));
                REQUIRE(name_of(runtime, "DEVICE1") == before);
            }
        }

        WHEN("POST /register names a display name of 257 bytes")
        {
            auto const users_before = runtime.homeserver.database.users.size();
            auto const devices_before = runtime.homeserver.database.persistent_store.devices.size();
            auto const refused =
                hs::handle_client_server_request(
                    runtime,
                    {"POST",
                     "/_matrix/client/v3/register",
                     {},
                     R"({"username":"bob","password":"CorrectHorse7!","initial_device_display_name":")" + over_limit +
                         R"(","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})"})
                    .response;

            THEN("it is 400 M_TOO_LARGE and no account or device is created")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(contains(refused.body, "M_TOO_LARGE"));
                REQUIRE(runtime.homeserver.database.users.size() == users_before);
                REQUIRE(runtime.homeserver.database.persistent_store.devices.size() == devices_before);
            }
        }

        WHEN("POST /register names a display name of exactly 256 bytes")
        {
            auto const accepted =
                hs::handle_client_server_request(
                    runtime,
                    {"POST",
                     "/_matrix/client/v3/register",
                     {},
                     R"({"username":"bob","password":"CorrectHorse7!","device_id":"BOBDEV","initial_device_display_name":")" +
                         at_limit +
                         R"(","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})"})
                    .response;

            THEN("the account is created with the whole name")
            {
                REQUIRE(accepted.status == 200U);
                auto const& devices = runtime.homeserver.database.persistent_store.devices;
                REQUIRE(std::ranges::any_of(devices, [&at_limit](auto const& device) {
                    return device.user_id == "@bob:example.org" && device.display_name == at_limit;
                }));
            }
        }
    }
}

namespace
{

// A store holding `own` devices of alice, each with a published key, and `other` devices of bob.
[[nodiscard]] auto store_with_devices(std::size_t own, std::size_t other) -> merovingian::database::PersistentStore
{
    auto store = merovingian::database::PersistentStore{};
    for (auto index = std::size_t{0U}; index < own + other; ++index)
    {
        auto const user = std::string{index < own ? "@alice:example.org" : "@bob:example.org"};
        auto const device = "D" + std::to_string(index);
        store.devices.push_back({user, device, "name " + device});
        store.device_keys.push_back({user, device,
                                     R"({"algorithms":["m.olm.v1.curve25519-aes-sha2"],"device_id":")" + device +
                                         R"(","keys":{"curve25519:)" + device + R"(":"AAAA","ed25519:)" + device +
                                         R"(":"BBBB"},"user_id":")" + user + R"("})"});
    }
    // One of alice's devices published nothing.
    store.devices.push_back({"@alice:example.org", "NOKEYS", {}});
    return store;
}

} // namespace

SCENARIO("announcing all of a user's devices makes a fixed number of passes over the device tables",
         "[federation][keys][edu][device-list-update][limits][f05]")
{
    namespace fed = merovingian::federation;

    GIVEN("two stores, one with 3 and one with 150 devices for the user, plus another user's devices")
    {
        auto const small = store_with_devices(3U, 4U);
        auto const large = store_with_devices(150U, 40U);

        WHEN("the announcement batch is built for the user in each")
        {
            auto const small_before = small.device_table_rows_examined.value();
            auto const small_batch = fed::build_device_list_update_batch(small, "@alice:example.org", std::nullopt, 9);
            auto const small_rows = small.device_table_rows_examined.value() - small_before;
            auto const large_before = large.device_table_rows_examined.value();
            auto const large_batch = fed::build_device_list_update_batch(large, "@alice:example.org", std::nullopt, 9);
            auto const large_rows = large.device_table_rows_examined.value() - large_before;

            THEN("every device has one entry, and each build reads the device table twice and the key table once")
            {
                REQUIRE(small_batch.entries.size() == 4U);
                REQUIRE(large_batch.entries.size() == 151U);
                REQUIRE(small_rows == 2U * small.devices.size() + small.device_keys.size());
                REQUIRE(large_rows == 2U * large.devices.size() + large.device_keys.size());
            }

            THEN("announcing the devices one at a time reads far more, so the count would show that regression")
            {
                auto const per_device_before = large.device_table_rows_examined.value();
                for (auto const& entry : large_batch.entries)
                {
                    REQUIRE(fed::build_device_list_update_content(large, "@alice:example.org", entry.device_id, 9)
                                .has_value());
                }
                auto const per_device_rows = large.device_table_rows_examined.value() - per_device_before;
                REQUIRE(per_device_rows > 50U * large_rows);
            }

            THEN("each entry is byte-for-byte what the single-device builder returns")
            {
                for (auto const& entry : large_batch.entries)
                {
                    auto const single =
                        fed::build_device_list_update_content(large, "@alice:example.org", entry.device_id, 9);
                    REQUIRE(single.has_value());
                    REQUIRE(entry.content == *single);
                }
                auto const nokeys = std::ranges::find_if(large_batch.entries, [](auto const& entry) {
                    return entry.device_id == "NOKEYS";
                });
                REQUIRE(nokeys != large_batch.entries.end());
                REQUIRE_FALSE(nokeys->has_keys);
                REQUIRE(std::ranges::count_if(large_batch.entries, [](auto const& entry) {
                            return entry.has_keys;
                        }) == 150);
            }
        }

        WHEN("the batch is limited to one device")
        {
            auto const batch = fed::build_device_list_update_batch(large, "@alice:example.org", "D7", 9);

            THEN("it holds that device alone")
            {
                REQUIRE(batch.entries.size() == 1U);
                REQUIRE(batch.entries.front().device_id == "D7");
                REQUIRE(batch.entries.front().has_keys);
                REQUIRE(batch.entries.front().content ==
                        *fed::build_device_list_update_content(large, "@alice:example.org", "D7", 9));
            }
        }
    }
}
