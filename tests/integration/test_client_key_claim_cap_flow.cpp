// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Run-3 C13 (ADR-0670). A client's POST /keys/claim named any number of users and devices (about 40,000 fit in the
// body), forwarded them and merged the remote answer with a search of the response per accepted user, so the merge
// was quadratic under the runtime lock. Policy: the entry cap of the federation twin
// (`federation::max_key_request_entries`, users plus devices) answers 413 M_TOO_LARGE before any key is claimed, and
// the merge looks each user up in a hash set.
//
// Spec: client-server-api.md, POST /keys/claim (states no size limit; 413 M_TOO_LARGE is the spec's code for a
// request the server refuses as too large).

#include "../support/E2eeCapsSupport.hpp"
#include "merovingian/database/PersistentOneTimeKey.hpp"
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

SCENARIO("a client key claim naming more than the entry cap is refused before any key is claimed",
         "[homeserver][client-server][e2ee][cost][security][c13]")
{
    GIVEN("a logged-in user and one stored one-time key")
    {
        auto started = hs::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);
        REQUIRE(merovingian::database::store_one_time_key(
            runtime.homeserver.database.persistent_store,
            {"@u0:example.org", "D", "signed_curve25519:AAAAAQ", R"({"key":"OTK"})"}));

        WHEN("a claim names more users and devices than the cap")
        {
            auto const refused = post(runtime, token, "/_matrix/client/v3/keys/claim",
                                      request_naming("one_time_keys", cap / 2U + 1U, R"({"D":"signed_curve25519"})"));

            THEN("it is 413 M_TOO_LARGE and the stored key was not claimed")
            {
                REQUIRE(refused.status == 413U);
                REQUIRE(refused.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(runtime.homeserver.database.persistent_store.one_time_keys.size() == 1U);
            }
        }

        WHEN("a claim names exactly the cap in users and devices")
        {
            auto const served = post(runtime, token, "/_matrix/client/v3/keys/claim",
                                     request_naming("one_time_keys", cap / 2U, R"({"D":"signed_curve25519"})"));

            THEN("it is served and the stored key is claimed")
            {
                REQUIRE(served.status == 200U);
                REQUIRE(served.body.find("OTK") != std::string::npos);
                REQUIRE(runtime.homeserver.database.persistent_store.one_time_keys.empty());
            }
        }
    }
}
