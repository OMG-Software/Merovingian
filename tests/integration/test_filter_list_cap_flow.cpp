// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Run-3 finding C09 (ADR-0657): a filter whose list holds more than 100 entries is refused with 400 M_INVALID_PARAM at
// upload, as an inline `filter=` of GET /sync, and when a filter stored before the cap is used.
//
// Spec: client-server-api.md, POST /user/{userId}/filter and GET /sync `filter`.

#include "../support/E2eeCapsSupport.hpp"
#include "../support/JsonTestSupport.hpp"
#include "merovingian/database/PersistentFilter.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>

namespace
{

namespace hs = merovingian::homeserver;

constexpr auto filter_url = "/_matrix/client/v3/user/%40alice%3Aexample.org/filter";

[[nodiscard]] auto types_filter(std::size_t count) -> std::string
{
    auto list = std::string{"["};
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        list += (index == 0U ? "" : ",") + std::string{"\"m.t"} + std::to_string(index) + "\"";
    }
    return R"({"room":{"timeline":{"types":)" + list + "]}}}";
}

[[nodiscard]] auto errcode_of(hs::LocalHttpResponse const& response) -> std::string
{
    return merovingian::tests::string_field(response.body, "errcode");
}

} // namespace

SCENARIO("a filter list over the cap is refused wherever the filter arrives", "[sync][filter][c09][security]")
{
    GIVEN("a logged-in user")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);

        WHEN("a filter with 101 types is uploaded")
        {
            auto const response =
                hs::handle_client_server_request(runtime, {"POST", filter_url, token, types_filter(101U)}).response;

            THEN("it is refused with M_INVALID_PARAM and nothing is stored")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(errcode_of(response) == "M_INVALID_PARAM");
                REQUIRE(runtime.homeserver.database.persistent_store.filters.empty());
            }
        }

        WHEN("a filter with exactly 100 types is uploaded and used for a sync")
        {
            auto const uploaded =
                hs::handle_client_server_request(runtime, {"POST", filter_url, token, types_filter(100U)}).response;
            REQUIRE(uploaded.status == 200U);
            auto const id = merovingian::tests::string_field(uploaded.body, "filter_id");
            auto const synced = hs::handle_client_server_request(
                                    runtime, {"GET", "/_matrix/client/v3/sync?filter=" + id, token, {}}, false)
                                    .response;

            THEN("the sync is served")
            {
                REQUIRE(synced.status == 200U);
            }
        }

        WHEN("an inline filter with 101 types is used for a sync")
        {
            auto const synced =
                hs::handle_client_server_request(
                    runtime, {"GET", "/_matrix/client/v3/sync?filter=" + types_filter(101U), token, {}}, false)
                    .response;

            THEN("the sync is refused with M_INVALID_PARAM")
            {
                REQUIRE(synced.status == 400U);
                REQUIRE(errcode_of(synced) == "M_INVALID_PARAM");
            }
        }

        WHEN("a filter stored before the cap, with 101 types, is used for a sync")
        {
            REQUIRE(merovingian::database::store_filter(runtime.homeserver.database.persistent_store,
                                                        {"@alice:example.org", "legacy", types_filter(101U)}));
            auto const synced = hs::handle_client_server_request(
                                    runtime, {"GET", "/_matrix/client/v3/sync?filter=legacy", token, {}}, false)
                                    .response;

            THEN("the sync is refused with M_INVALID_PARAM")
            {
                REQUIRE(synced.status == 400U);
                REQUIRE(errcode_of(synced) == "M_INVALID_PARAM");
            }
        }

        WHEN("an over-cap filter is given to /messages")
        {
            auto const created =
                hs::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
            auto const room = merovingian::tests::string_field(created.response.body, "room_id");
            auto flat = types_filter(101U);
            flat = flat.substr(flat.find("\"types\""));
            flat = "{" + flat.substr(0U, flat.find(']') + 1U) + "}";
            auto const messages =
                hs::handle_client_server_request(
                    runtime, {"GET", "/_matrix/client/v3/rooms/" + room + "/messages?dir=b&filter=" + flat, token, {}})
                    .response;

            THEN("it is refused with M_INVALID_PARAM")
            {
                REQUIRE(messages.status == 400U);
                REQUIRE(errcode_of(messages) == "M_INVALID_PARAM");
            }
        }
    }
}
