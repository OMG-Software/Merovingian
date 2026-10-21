// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run-1, sp02.account-data-unbounded-linear-scan. Every PUT of a new global
// account-data type added a row to the shared store that push fan-out (per recipient, per event)
// and every /sync scan while the runtime lock is held. Policy, as for the CSAZ-10 caps
// (ADR-0118): refuse a new type over the per-user cap with M_TOO_LARGE, store nothing, never
// evict; updating a type the user already holds is always allowed.

#include "../support/e2ee_caps_support.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>

namespace
{

using merovingian::tests::caps_config;
using merovingian::tests::register_and_login_alice;

[[nodiscard]] auto global_rows_for(merovingian::homeserver::ClientServerRuntime const& runtime, std::string_view user)
    -> std::size_t
{
    auto const& rows = runtime.homeserver.database.persistent_store.account_data;
    return static_cast<std::size_t>(std::ranges::count_if(rows, [user](auto const& row) {
        return row.user_id == user && row.room_id.empty();
    }));
}

[[nodiscard]] auto put_account_data(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                    std::string_view user_path, std::string_view type, std::string body)
    -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime,
               {"PUT", "/_matrix/client/v3/user/" + std::string{user_path} + "/account_data/" + std::string{type},
                token, std::move(body)})
        .response;
}

[[nodiscard]] auto get_account_data(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                    std::string_view type) -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime,
               {"GET", "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/" + std::string{type}, token, {}})
        .response;
}

constexpr auto alice_path = "%40alice%3Aexample.org";

} // namespace

SCENARIO("global account data is refused beyond the per-user cap, and existing types can still be updated",
         "[homeserver][client-server][account-data][limits][security][sp02]")
{
    GIVEN("a runtime capped at 2 global account-data types per user, and a logged-in user holding 2")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 100U, 100U, 2U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);
        REQUIRE(put_account_data(runtime, token, alice_path, "org.example.first", R"({"n":1})").status == 200U);
        REQUIRE(put_account_data(runtime, token, alice_path, "org.example.second", R"({"n":2})").status == 200U);
        REQUIRE(global_rows_for(runtime, "@alice:example.org") == 2U);

        WHEN("a third type, not yet held, is stored")
        {
            auto const refused = put_account_data(runtime, token, alice_path, "org.example.third", R"({"n":3})");

            THEN("it is refused with M_TOO_LARGE, nothing is stored and nothing is evicted")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(refused.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(global_rows_for(runtime, "@alice:example.org") == 2U);
                REQUIRE(get_account_data(runtime, token, "org.example.third").status == 404U);
                REQUIRE(get_account_data(runtime, token, "org.example.first").status == 200U);
            }
        }

        WHEN("a type the user already holds is updated")
        {
            auto const updated = put_account_data(runtime, token, alice_path, "org.example.first", R"({"n":10})");

            THEN("the update succeeds and the row count does not change")
            {
                REQUIRE(updated.status == 200U);
                REQUIRE(global_rows_for(runtime, "@alice:example.org") == 2U);
                auto const fetched = get_account_data(runtime, token, "org.example.first");
                REQUIRE(fetched.status == 200U);
                REQUIRE(fetched.body.find("10") != std::string::npos);
            }
        }
    }
}
