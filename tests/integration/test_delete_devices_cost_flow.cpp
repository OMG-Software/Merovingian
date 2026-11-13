// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Run-3 C02 (ADR-0669). POST /delete_devices took an array of any length and, for each listed ID, scanned the whole
// device table and the whole session table under the runtime lock, so one request of 200,000 absent IDs held the
// lock for entries x (devices + sessions). Policy: a list over `device_count_limit` entries is 400 M_INVALID_PARAM
// with nothing deleted, repeated IDs are handled once, and `delete_local_device` finds the device through the
// user's own rows and the session (user, device) index, so the rows it reads are the caller's, not the server's.

#include "../support/E2eeCapsSupport.hpp"
#include "merovingian/database/PersistentDevice.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/DeviceLimits.hpp"
#include "merovingian/homeserver/LocalSession.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
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

auto add_other_users(hs::ClientServerRuntime& runtime, std::size_t users) -> void
{
    for (auto index = std::size_t{0U}; index < users; ++index)
    {
        auto const user = "@other" + std::to_string(index) + ":example.org";
        for (auto device = std::size_t{0U}; device < 2U; ++device)
        {
            auto const device_id = "OD" + std::to_string(device);
            REQUIRE(merovingian::database::store_device(runtime.homeserver.database.persistent_store,
                                                        {user, device_id, "other"}));
            runtime.homeserver.database.sessions.push_back(
                hs::LocalSession{user, device_id, "hash-" + user + device_id, false, {}, {}});
        }
    }
}

auto login_device(hs::ClientServerRuntime& runtime, std::string const& device_id) -> void
{
    REQUIRE(hs::login_local_user_by_id(runtime.homeserver, alice, device_id, false, {}).ok);
}

[[nodiscard]] auto held_device_rows(hs::ClientServerRuntime const& runtime, std::string_view device_id) -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const& device : runtime.homeserver.database.persistent_store.devices)
    {
        count += static_cast<std::size_t>(device.user_id == alice && device.device_id == device_id);
    }
    return count;
}

[[nodiscard]] auto delete_devices(hs::ClientServerRuntime& runtime, std::string const& token,
                                  std::string const& devices) -> hs::LocalHttpResponse
{
    auto body = R"({"auth":{"type":"m.login.password","password":"CorrectHorse7!"},"devices":[)" + devices + "]}";
    return hs::handle_client_server_request(runtime,
                                            {"POST", "/_matrix/client/v3/delete_devices", token, std::move(body)})
        .response;
}

} // namespace

SCENARIO("deleting absent devices reads only the caller's own rows, however many other devices exist",
         "[homeserver][client-server][devices][cost][security][c02]")
{
    GIVEN("a server with many other users' devices and sessions, and a user with four devices")
    {
        auto started = hs::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        std::ignore = register_and_login_alice(runtime);
        login_device(runtime, "SECOND");
        login_device(runtime, "THIRD");
        add_other_users(runtime, 300U);
        auto const& store = runtime.homeserver.database.persistent_store;
        REQUIRE(store.devices.size() >= 603U);

        WHEN("delete_local_device is asked for 500 device IDs the user does not hold")
        {
            auto const devices_before = store.device_table_rows_examined.value();
            auto const sessions_before = runtime.homeserver.database.sessions.rows_examined().value();
            auto all_not_found = true;
            for (auto index = std::size_t{0U}; index < 500U; ++index)
            {
                auto const result = hs::delete_local_device(runtime.homeserver, alice, "NOPE" + std::to_string(index));
                all_not_found = all_not_found && !result.ok && result.status == 404U;
            }

            THEN("each answers 404 and reads exactly the user's four device rows and no session")
            {
                REQUIRE(all_not_found);
                REQUIRE(store.device_table_rows_examined.value() - devices_before == 500U * 4U);
                REQUIRE(runtime.homeserver.database.sessions.rows_examined().value() == sessions_before);
            }
        }

        WHEN("a device the user holds is deleted")
        {
            auto const sessions_before = runtime.homeserver.database.sessions.rows_examined().value();
            auto const result = hs::delete_local_device(runtime.homeserver, alice, "SECOND");

            THEN("it is removed, its session is revoked, and only that device's one session was read")
            {
                REQUIRE(result.ok);
                REQUIRE(held_device_rows(runtime, "SECOND") == 0U);
                REQUIRE(held_device_rows(runtime, "THIRD") == 1U);
                REQUIRE(runtime.homeserver.database.sessions.rows_examined().value() - sessions_before == 1U);
            }
        }
    }
}

SCENARIO("POST /delete_devices refuses a list longer than the device cap and handles a repeated ID once",
         "[homeserver][client-server][devices][cost][security][c02]")
{
    GIVEN("a user with four devices")
    {
        auto started = hs::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);
        login_device(runtime, "SECOND");
        login_device(runtime, "THIRD");

        WHEN("the list holds one more entry than the cap")
        {
            auto list = std::string{R"("SECOND")"};
            for (auto index = std::size_t{1U}; index <= hs::device_count_limit; ++index)
            {
                list += R"(,"A)" + std::to_string(index) + '"';
            }
            auto const response = delete_devices(runtime, token, list);

            THEN("it is 400 M_INVALID_PARAM and nothing is deleted")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(held_device_rows(runtime, "SECOND") == 1U);
            }
        }

        WHEN("the list holds exactly the cap, with absent IDs and a held one")
        {
            auto list = std::string{R"("SECOND")"};
            for (auto index = std::size_t{1U}; index < hs::device_count_limit; ++index)
            {
                list += R"(,"A)" + std::to_string(index) + '"';
            }
            auto const response = delete_devices(runtime, token, list);

            THEN("it is served: 200 and the held device is deleted")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(held_device_rows(runtime, "SECOND") == 0U);
                REQUIRE(held_device_rows(runtime, "THIRD") == 1U);
            }
        }

        WHEN("two held devices, an absent one and a repeat are listed")
        {
            auto const response = delete_devices(runtime, token, R"("SECOND","NOPE","THIRD","SECOND")");

            THEN("it is 200 and both held devices are deleted")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(held_device_rows(runtime, "SECOND") == 0U);
                REQUIRE(held_device_rows(runtime, "THIRD") == 0U);
                REQUIRE(held_device_rows(runtime, "DEVICE1") == 1U);
            }
        }
    }
}
