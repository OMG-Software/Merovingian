// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// `POST /_merovingian/oauth2/register` through the client-server dispatcher: one row per accepted metadata whatever the
// request's form, a repeat that costs no commit, the route and body gates, the rate-limit tier, CORS, the read-back of
// a stored client, and the registration cap (ADR-0779, ADR-0780, ADR-0781).

#include "../support/JsonTestSupport.hpp"
#include "../support/OAuthRegistrationSupport.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/OAuthClientStoreResult.hpp"
#include "merovingian/database/OAuthStore.hpp"
#include "merovingian/database/PersistentOAuthClient.hpp"
#include "merovingian/database/PersistentOAuthSession.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/OAuthClientRegistration.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace merovingian::tests;
namespace db = merovingian::database;
namespace hs = merovingian::homeserver;

// A web client of https://example.com/ with one redirect URI under `path`.
[[nodiscard]] auto web_client(std::string_view path) -> std::string
{
    return R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/)" + std::string{path} +
           R"("],"token_endpoint_auth_method":"none"})";
}

[[nodiscard]] auto client_id_of(hs::LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* client_id = string_member(body, "client_id");
    return client_id == nullptr ? std::string{} : *client_id;
}

[[nodiscard]] auto oauth_error_of(hs::LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* error = string_member(body, "error");
    return error == nullptr ? std::string{} : *error;
}

// Stores a client row directly, with a chosen last use, as a registration long ago would have left it.
auto seed_client(db::PersistentStore& store, std::string client_id, std::uint64_t last_used_at_ms) -> void
{
    REQUIRE(db::store_oauth_client(store, db::PersistentOAuthClient{std::move(client_id), web_client("seeded"),
                                                                    last_used_at_ms, last_used_at_ms}) ==
            db::OAuthClientStoreResult::inserted);
}

} // namespace

SCENARIO("one accepted metadata is one client whatever the request's form", "[integration][oauth][registration]")
{
    GIVEN("a homeserver with the OAuth 2.0 API on")
    {
        auto started = hs::start_client_server(oauth_registration_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto& store = rt.homeserver.database.persistent_store;

        WHEN("the same metadata is sent with another key order, an unknown key and a repeated array entry")
        {
            auto const first = post_client_registration(
                rt, R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],)"
                    R"("grant_types":["authorization_code","refresh_token"]})");
            auto const commits_before = db::committed_transaction_count(store);
            auto const second = post_client_registration(
                rt, R"({"x_vendor":1,"grant_types":["refresh_token","authorization_code","refresh_token"],)"
                    R"("redirect_uris":["https://example.com/cb","https://example.com/cb"],)"
                    R"("client_uri":"https://example.com/"})");
            auto const commits_after = db::committed_transaction_count(store);

            THEN("both are answered with the same client ID, one row is held and the repeat commits nothing")
            {
                REQUIRE(first.status == 201U);
                REQUIRE(second.status == 201U);
                CHECK_FALSE(client_id_of(first).empty());
                CHECK(client_id_of(first) == client_id_of(second));
                CHECK(db::oauth_client_count(store) == 1U);
                CHECK(commits_after == commits_before);
                CHECK(response_header(second, "Cache-Control") == "no-store");
                auto const first_body = parse_object(first.body);
                auto const second_body = parse_object(second.body);
                auto const* issued_first = int_member(first_body, "client_id_issued_at");
                auto const* issued_second = int_member(second_body, "client_id_issued_at");
                REQUIRE(issued_first != nullptr);
                REQUIRE(issued_second != nullptr);
                CHECK(*issued_first == *issued_second);
            }
        }

        WHEN("two clients differ in one redirect URI")
        {
            auto const one = post_client_registration(rt, web_client("one"));
            auto const two = post_client_registration(rt, web_client("two"));

            THEN("each has its own client ID and row")
            {
                REQUIRE(one.status == 201U);
                REQUIRE(two.status == 201U);
                CHECK(client_id_of(one) != client_id_of(two));
                CHECK(db::oauth_client_count(store) == 2U);
            }
        }

        WHEN("a registered client, a stored row that no longer validates and an unknown ID are read back")
        {
            auto const registered = post_client_registration(rt, web_client("cb"));
            REQUIRE(registered.status == 201U);
            REQUIRE(db::store_oauth_client(
                        store, db::PersistentOAuthClient{"stored-invalid", R"({"client_uri":1})", 1U, 1U}) ==
                    db::OAuthClientStoreResult::inserted);

            THEN("only the registered client is found, with its metadata")
            {
                auto const found = hs::find_registered_oauth_client(rt.homeserver, client_id_of(registered));
                REQUIRE(found.has_value());
                CHECK(hs::oauth_client_id_of(rt.homeserver, *found) == client_id_of(registered));
                CHECK_FALSE(hs::find_registered_oauth_client(rt.homeserver, "stored-invalid").has_value());
                CHECK_FALSE(hs::find_registered_oauth_client(rt.homeserver, "no-such-client").has_value());
            }
        }
    }
}

SCENARIO("the registration route and its body are gated", "[integration][oauth][registration]")
{
    GIVEN("a homeserver with the OAuth 2.0 API off")
    {
        auto started = hs::start_client_server(oauth_registration_config(false));
        REQUIRE(started.started);

        WHEN("a client registers")
        {
            auto const response = post_client_registration(started.runtime, web_client("cb"));

            THEN("the route does not exist")
            {
                REQUIRE(response.status == 404U);
                CHECK(response.body.find("M_UNRECOGNIZED") != std::string::npos);
                CHECK(db::oauth_client_count(started.runtime.homeserver.database.persistent_store) == 0U);
            }
        }
    }

    GIVEN("a homeserver with the OAuth 2.0 API on")
    {
        auto started = hs::start_client_server(oauth_registration_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("the endpoint is asked with GET")
        {
            auto const response = post_client_registration(rt, {}, {}, "GET");

            THEN("it is 405 naming POST")
            {
                REQUIRE(response.status == 405U);
                CHECK(response_header(response, "Allow") == "POST");
            }
        }

        WHEN("bodies that are too large, not JSON by type, or malformed are sent")
        {
            auto const over_cap = std::string(db::max_oauth_client_metadata_bytes + 1U, ' ') + web_client("cb");
            auto const over_transport_cap = std::string(rt.limits.max_body_bytes + 1U, ' ') + web_client("cb");
            auto const oversized = post_client_registration(rt, over_cap);
            auto const over_general_cap = post_client_registration(rt, over_transport_cap);
            auto const wrong_type = post_client_registration(rt, web_client("cb"), "text/plain");
            auto const no_type = post_client_registration(rt, web_client("cb"), {});
            auto const malformed = post_client_registration(rt, R"({"client_uri":)");
            auto const charset = post_client_registration(rt, web_client("cb"), "application/json; charset=utf-8");

            THEN("each refusal is 400 invalid_client_metadata and stores nothing, and a charset is accepted")
            {
                for (auto const* refused :
                     std::to_array({&oversized, &over_general_cap, &wrong_type, &no_type, &malformed}))
                {
                    CHECK(refused->status == 400U);
                    CHECK(oauth_error_of(*refused) == "invalid_client_metadata");
                    CHECK(response_header(*refused, "Cache-Control") == "no-store");
                }
                CHECK(charset.status == 201U);
                CHECK(db::oauth_client_count(rt.homeserver.database.persistent_store) == 1U);
            }
        }
    }
}

SCENARIO("registration takes the auth-sensitive rate limit and carries the CORS headers",
         "[integration][oauth][registration][rate-limit][cors]")
{
    GIVEN("a homeserver with the OAuth 2.0 API on and the default rate limits")
    {
        auto started = hs::start_client_server(oauth_registration_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("one address registers 21 times in a minute")
        {
            auto last_status = std::uint16_t{0U};
            auto statuses_ok = true;
            for (auto attempt = 0; attempt < 21; ++attempt)
            {
                auto const response = post_client_registration(rt, web_client("cb"));
                last_status = response.status;
                if (attempt < 20 && response.status != 201U)
                {
                    statuses_ok = false;
                }
            }

            THEN("the first 20 are answered and the 21st is limited")
            {
                // The auth_sensitive tier allows 20 a minute per address (ADR-0775).
                CHECK(statuses_ok);
                CHECK(last_status == 429U);
            }
        }

        WHEN("a browser preflights and posts the registration, and preflights login")
        {
            auto preflight = hs::LocalHttpRequest{"OPTIONS", std::string{oauth_register_path}, {}, {}};
            preflight.headers.push_back({"Origin", "https://app.example.com"});
            auto login_preflight = preflight;
            login_preflight.target = "/_matrix/client/v3/login";
            auto const register_options = hs::handle_client_server_request(rt, preflight, false).response;
            auto const login_options = hs::handle_client_server_request(rt, login_preflight, false).response;
            auto post = preflight;
            post.method = "POST";
            post.body = web_client("cb");
            post.headers.push_back({"Content-Type", "application/json"});
            auto const registered = hs::handle_client_server_request(rt, post, false).response;

            THEN("the registration answers carry the same CORS headers as login")
            {
                REQUIRE(register_options.status == 200U);
                for (auto const name : {"Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
                                        "Access-Control-Allow-Headers", "Access-Control-Max-Age", "Vary"})
                {
                    INFO(name);
                    CHECK_FALSE(response_header(register_options, name).empty());
                    CHECK(response_header(register_options, name) == response_header(login_options, name));
                }
                REQUIRE(registered.status == 201U);
                CHECK(response_header(registered, "Access-Control-Allow-Origin") ==
                      response_header(login_options, "Access-Control-Allow-Origin"));
                CHECK(response_header(registered, "X-Content-Type-Options") == "nosniff");
            }
        }
    }
}

SCENARIO("at the registration cap idle clients go least recently used first, and protected ones never",
         "[integration][oauth][registration][cap]")
{
    GIVEN("a homeserver holding four clients at a cap of four: one with a session, one pending, two idle")
    {
        auto started = hs::start_client_server(oauth_registration_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto& store = rt.homeserver.database.persistent_store;
        rt.limits.max_oauth_clients = 4U;
        seed_client(store, "with-session", 1U);
        seed_client(store, "pending", 2U);
        seed_client(store, "idle-older", 3U);
        seed_client(store, "idle-newer", 4U);
        REQUIRE(db::store_oauth_session(
            store, db::PersistentOAuthSession{"@alice:example.org", "DEVICE", "with-session", "openid", 1U}));
        rt.homeserver.test_oauth_pending_authorisation = [](std::string_view client_id) {
            return client_id == "pending";
        };

        WHEN("one client registers")
        {
            auto const response = post_client_registration(rt, web_client("first"));

            THEN("only the least recently used idle client was removed")
            {
                REQUIRE(response.status == 201U);
                CHECK(db::oauth_client_count(store) == 4U);
                CHECK(db::find_oauth_client(store, "idle-older") == nullptr);
                CHECK(db::find_oauth_client(store, "idle-newer") != nullptr);
            }
        }

        WHEN("a flood of distinct clients registers")
        {
            for (auto index = 0; index < 12; ++index)
            {
                auto const response = post_client_registration(rt, web_client("flood-" + std::to_string(index)));
                CHECK(response.status == 201U);
            }

            THEN("the client with a session and the pending one are still held, and the cap is kept")
            {
                CHECK(db::oauth_client_count(store) == 4U);
                // Spec MUST NOT: delete a client registration that has an active session.
                CHECK(db::find_oauth_client(store, "with-session") != nullptr);
                CHECK(db::find_oauth_client(store, "pending") != nullptr);
                CHECK(db::find_oauth_client(store, "idle-older") == nullptr);
                CHECK(db::find_oauth_client(store, "idle-newer") == nullptr);
            }
        }
    }

    GIVEN("a homeserver at a cap of two whose clients are both protected")
    {
        auto started = hs::start_client_server(oauth_registration_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto& store = rt.homeserver.database.persistent_store;
        rt.limits.max_oauth_clients = 2U;
        seed_client(store, "with-session", 1U);
        seed_client(store, "pending", 2U);
        REQUIRE(db::store_oauth_session(
            store, db::PersistentOAuthSession{"@alice:example.org", "DEVICE", "with-session", "openid", 1U}));
        rt.homeserver.test_oauth_pending_authorisation = [](std::string_view client_id) {
            return client_id == "pending";
        };

        WHEN("a new client registers")
        {
            auto const refused = post_client_registration(rt, web_client("new"));

            THEN("the new one is 503 temporarily_unavailable with nothing stored or removed")
            {
                REQUIRE(refused.status == 503U);
                CHECK(oauth_error_of(refused) == "temporarily_unavailable");
                CHECK(response_header(refused, "Cache-Control") == "no-store");
                CHECK(db::oauth_client_count(store) == 2U);
                CHECK(db::find_oauth_client(store, "with-session") != nullptr);
                CHECK(db::find_oauth_client(store, "pending") != nullptr);
            }
        }
    }
}
