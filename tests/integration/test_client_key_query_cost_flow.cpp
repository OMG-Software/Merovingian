// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Run-3 C19 (ADR-0671). A client's POST /keys/query looped over every row of the device-key table once for each
// requested local user that asked for all devices, and capped nothing, so a request of 25,000 users cost
// users x table rows under the runtime lock. Policy: the requested user's own device-key rows are read through the
// index (`device_table_rows_examined` counts them), and a query naming more than
// `federation::max_key_request_entries` users and devices is 413 M_TOO_LARGE before any lookup.
//
// Spec: client-server-api.md, POST /keys/query (states no size limit; 413 M_TOO_LARGE is the spec's code for a
// request the server refuses as too large).

#include "../support/E2eeCapsSupport.hpp"
#include "merovingian/database/PersistentDeviceKey.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/KeyQuery.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace
{

namespace hs = merovingian::homeserver;
using merovingian::tests::caps_config;
using merovingian::tests::register_and_login_alice;

[[nodiscard]] auto device_key_json(std::string_view user, std::string_view device) -> std::string
{
    return std::string{R"({"algorithms":["m.megolm.v1.aes-sha2"],"device_id":")"} + std::string{device} +
           R"(","keys":{"ed25519:)" + std::string{device} + R"(":"key"},"user_id":")" + std::string{user} + R"("})";
}

auto add_device_keys(hs::ClientServerRuntime& runtime, std::string const& user, std::size_t devices) -> void
{
    for (auto index = std::size_t{0U}; index < devices; ++index)
    {
        auto const device = "K" + std::to_string(index);
        REQUIRE(merovingian::database::store_device_key(runtime.homeserver.database.persistent_store,
                                                        {user, device, device_key_json(user, device)}));
    }
}

[[nodiscard]] auto post(hs::ClientServerRuntime& runtime, std::string const& token, std::string_view path,
                        std::string body) -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(runtime, {"POST", std::string{path}, token, std::move(body)}).response;
}

// {"<section>":{"@u0:example.org":<value>, ...}} naming `count` local users.
[[nodiscard]] auto request_naming(std::string_view section, std::size_t count, std::string_view value) -> std::string
{
    auto body = std::string{"{\""} + std::string{section} + "\":{";
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        body += index == 0U ? "" : ",";
        body += "\"@u" + std::to_string(index) + ":example.org\":" + std::string{value};
    }
    body += "}}";
    return body;
}

constexpr auto cap = merovingian::federation::max_key_request_entries;

} // namespace

SCENARIO("a client key query reads the requested user's own device keys, not the whole table",
         "[homeserver][client-server][e2ee][cost][security][c19]")
{
    GIVEN("many other users' device keys and one user with three device keys and no device rows")
    {
        auto started = hs::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);
        for (auto index = std::size_t{0U}; index < 300U; ++index)
        {
            add_device_keys(runtime, "@other" + std::to_string(index) + ":example.org", 2U);
        }
        add_device_keys(runtime, "@ghost:example.org", 3U);
        auto const& store = runtime.homeserver.database.persistent_store;

        WHEN("the user is queried for all of their devices")
        {
            auto const before = store.device_table_rows_examined.value();
            auto const response =
                post(runtime, token, "/_matrix/client/v3/keys/query", R"({"device_keys":{"@ghost:example.org":[]}})");

            THEN("their three devices are answered and exactly their three rows were read")
            {
                REQUIRE(response.status == 200U);
                for (auto const* device : {"K0", "K1", "K2"})
                {
                    REQUIRE(response.body.find(std::string{"\"device_id\":\""} + device + "\"") != std::string::npos);
                }
                REQUIRE(store.device_table_rows_examined.value() - before == 3U);
            }
        }
    }
}

SCENARIO("a client key query naming more than the entry cap is refused whole",
         "[homeserver][client-server][e2ee][cost][security][c19]")
{
    GIVEN("a logged-in user")
    {
        auto started = hs::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);

        WHEN("a query names one user more than the cap")
        {
            auto const refused =
                post(runtime, token, "/_matrix/client/v3/keys/query", request_naming("device_keys", cap + 1U, "[]"));
            auto const served =
                post(runtime, token, "/_matrix/client/v3/keys/query", request_naming("device_keys", cap, "[]"));

            THEN("it is 413 M_TOO_LARGE, and a query at the cap is served")
            {
                REQUIRE(refused.status == 413U);
                REQUIRE(refused.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(served.status == 200U);
            }
        }
    }
}
