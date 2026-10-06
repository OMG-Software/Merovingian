// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// CSAZ-10 (security audit 2026-09-29). Owner policy: refuse over-cap uploads with
// M_TOO_LARGE and never evict; the caps are operator-configurable.

#include "../support/e2ee_caps_support.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>

namespace
{

using merovingian::tests::caps_config;
using merovingian::tests::register_and_login_alice;
using merovingian::tests::string_field;

[[nodiscard]] auto filter_count_for_alice(merovingian::homeserver::ClientServerRuntime const& runtime) -> std::size_t
{
    auto const& filters = runtime.homeserver.database.persistent_store.filters;
    return static_cast<std::size_t>(std::ranges::count_if(filters, [](auto const& filter) {
        return filter.user_id == "@alice:example.org";
    }));
}

constexpr auto filter_url = "/_matrix/client/v3/user/%40alice%3Aexample.org/filter";

} // namespace

SCENARIO("the filter API returns an identical definition's id and refuses filters beyond the per-user cap",
         "[csaz-10][homeserver][client-server][filter][limits]")
{
    GIVEN("a runtime capped at 2 filters per user and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 100U, 2U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);

        WHEN("the same filter is posted twice, the second time with reordered keys and extra whitespace")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", filter_url, token, R"({"event_format":"client","room":{"timeline":{"limit":5}}})"});
            auto const second = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", filter_url, token,
                          R"({ "room" : { "timeline" : { "limit" : 5 } } , "event_format" : "client" })"});

            THEN("both calls succeed with the same filter_id and only one filter is stored")
            {
                REQUIRE(first.response.status == 200U);
                REQUIRE(second.response.status == 200U);
                REQUIRE(string_field(first.response.body, "filter_id") ==
                        string_field(second.response.body, "filter_id"));
                REQUIRE(filter_count_for_alice(runtime) == 1U);
            }
        }

        WHEN("an identical definition is posted while the user is at the cap")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", filter_url, token, R"({"room":{"timeline":{"limit":1}}})"});
            REQUIRE(first.response.status == 200U);
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        runtime, {"POST", filter_url, token, R"({"room":{"timeline":{"limit":2}}})"})
                        .response.status == 200U);
            auto const repeat = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", filter_url, token, R"({"room":{"timeline":{"limit":1}}})"});

            THEN("the existing filter_id is returned and nothing is refused or stored")
            {
                REQUIRE(repeat.response.status == 200U);
                REQUIRE(string_field(repeat.response.body, "filter_id") ==
                        string_field(first.response.body, "filter_id"));
                REQUIRE(filter_count_for_alice(runtime) == 2U);
            }
        }

        WHEN("a third distinct filter is posted while the user holds 2")
        {
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        runtime, {"POST", filter_url, token, R"({"room":{"timeline":{"limit":1}}})"})
                        .response.status == 200U);
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        runtime, {"POST", filter_url, token, R"({"room":{"timeline":{"limit":2}}})"})
                        .response.status == 200U);
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", filter_url, token, R"({"room":{"timeline":{"limit":3}}})"});

            THEN("it is refused with M_TOO_LARGE and the stored filters are unchanged")
            {
                REQUIRE(response.response.status == 400U);
                REQUIRE(response.response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(filter_count_for_alice(runtime) == 2U);
            }
        }
    }
}
