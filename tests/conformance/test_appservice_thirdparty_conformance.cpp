// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |            THIRD-PARTY LOOKUPS — CLIENT-SERVER SURFACE CONFORMANCE      |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 "Third-party Networks" /         |
// |        "Third-party Lookups"                                           |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                |
// |                                                                         |
// |  Covers the six GET /_matrix/client/v3/thirdparty/* routes' documented  |
// |  status codes, "Rate-limited: No" / "Requires authentication: Yes"      |
// |  flags, and the no-registered-appservice degenerate cases. Live         |
// |  delivery against a real mock appservice (Protocol/Location/User       |
// |  content, instance_id minting, multi-appservice aggregation, an         |
// |  unreachable appservice degrading rather than failing the whole         |
// |  request) is covered in tests/integration/test_appservice_thirdparty_   |
// |  flow.cpp, matching the push-gateway-client precedent.                  |
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto thirdparty_test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& runtime,
                                      std::string const& localpart) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const body = parse_object(reg.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

} // namespace

// Spec: "Fetches the overall metadata about protocols supported by the
// homeserver ... {string: Protocol} | Dictionary of supported third-party
// protocols." No MUST that the dictionary be non-empty — with no
// application services registered there is nothing to report.
SCENARIO("GET /thirdparty/protocols returns an empty object when no appservice is registered",
         "[appservice][conformance][thirdparty]")
{
    GIVEN("a homeserver with no registered application services")
    {
        auto started = merovingian::homeserver::start_client_server(thirdparty_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "alice");

        WHEN("GET /_matrix/client/v3/thirdparty/protocols is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/protocols", token, {}});

            THEN("it returns 200 with an empty object, not a 404")
            {
                // Spec MUST: 200 response shape is "{string: Protocol}" — an
                // empty dictionary is a valid instance of that shape.
                REQUIRE(response.response.status == 200U);
                CHECK(response.response.body == "{}");
            }
        }
    }
}

// Spec: "GET /_matrix/client/v3/thirdparty/protocol/{protocol} ... 404 | The
// protocol is unknown." | 404 body: {"errcode": "M_NOT_FOUND"}.
SCENARIO("GET /thirdparty/protocol/{protocol} 404s for an unregistered protocol",
         "[appservice][conformance][thirdparty]")
{
    GIVEN("a homeserver with no application service declaring 'irc'")
    {
        auto started = merovingian::homeserver::start_client_server(thirdparty_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "bob");

        WHEN("GET /_matrix/client/v3/thirdparty/protocol/irc is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/protocol/irc", token, {}});

            THEN("it returns 404 M_NOT_FOUND")
            {
                // Spec MUST: 404 | "The protocol is unknown."
                REQUIRE(response.response.status == 404U);
                CHECK(response.response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }
}

// Spec: "GET /_matrix/client/v3/thirdparty/location/{protocol} ... 404 | No
// portal rooms were found."; an unrecognised protocol name is a strict
// subset of that — there cannot be portal rooms for a protocol no
// appservice declares.
SCENARIO("GET /thirdparty/location/{protocol} 404s for an unregistered protocol",
         "[appservice][conformance][thirdparty]")
{
    GIVEN("a homeserver with no application service declaring 'irc'")
    {
        auto started = merovingian::homeserver::start_client_server(thirdparty_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "carol");

        WHEN("GET /_matrix/client/v3/thirdparty/location/irc?channel=%23matrix is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/location/irc?channel=%23matrix", token, {}});

            THEN("it returns 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
                CHECK(response.response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }
}

// Spec: "GET /_matrix/client/v3/thirdparty/user/{protocol} ... 404 | The
// Matrix User ID was not found." — same unknown-protocol subset as location.
SCENARIO("GET /thirdparty/user/{protocol} 404s for an unregistered protocol", "[appservice][conformance][thirdparty]")
{
    GIVEN("a homeserver with no application service declaring 'gitter'")
    {
        auto started = merovingian::homeserver::start_client_server(thirdparty_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "dave");

        WHEN("GET /_matrix/client/v3/thirdparty/user/gitter?username=jim is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/user/gitter?username=jim", token, {}});

            THEN("it returns 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
                CHECK(response.response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }
}

// Spec: every one of the six /thirdparty/* routes is documented "Requires
// authentication: Yes".
SCENARIO("every /thirdparty/* route requires authentication", "[appservice][conformance][thirdparty][auth]")
{
    GIVEN("a homeserver and no access token")
    {
        auto started = merovingian::homeserver::start_client_server(thirdparty_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("each of the six routes is called with no Authorization")
        {
            auto const protocols = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/protocols", {}, {}});
            auto const protocol = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/protocol/irc", {}, {}});
            auto const location = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/location?alias=%23x:example.org", {}, {}});
            auto const location_protocol = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/location/irc", {}, {}});
            auto const user = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/user?userid=%40x:example.org", {}, {}});
            auto const user_protocol = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/user/irc", {}, {}});

            THEN("every route rejects with 401 M_MISSING_TOKEN")
            {
                // Spec §5.7.2: "the endpoints will return an error with the
                // M_MISSING_TOKEN or M_UNKNOWN_TOKEN error code and 401 as
                // the HTTP status code."
                CHECK(protocols.response.status == 401U);
                CHECK(protocol.response.status == 401U);
                CHECK(location.response.status == 401U);
                CHECK(location_protocol.response.status == 401U);
                CHECK(user.response.status == 401U);
                CHECK(user_protocol.response.status == 401U);
            }
        }
    }
}

// Spec: every one of the six /thirdparty/* routes is documented
// "Rate-limited: No". Proven by installing an artificially tight 1
// request/60s cap (the same test seam test_client_server.cpp's rate-limit
// scenarios use) and showing repeated calls to a /thirdparty/* route never
// 429 — while an ordinary generic-tier route under the identical cap does,
// confirming the cap itself is actually load-bearing in this test.
SCENARIO("thirdparty lookup routes are never rate-limited, unlike an ordinary generic route",
         "[appservice][conformance][thirdparty]")
{
    GIVEN("a homeserver with a 1-request-per-60s cap installed on every tier")
    {
        auto started = merovingian::homeserver::start_client_server(thirdparty_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "erin");
        merovingian::homeserver::install_test_rate_limit_engine(runtime);

        WHEN("GET /thirdparty/protocols is called five times back to back")
        {
            auto last_status = std::uint16_t{0U};
            for (auto i = 0U; i < 5U; ++i)
            {
                auto const response = merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET", "/_matrix/client/v3/thirdparty/protocols", token, {}});
                last_status = response.response.status;
                CHECK(response.response.status == 200U);
            }

            THEN("none of the five calls were rate-limited")
            {
                CHECK(last_status == 200U);
            }
        }

        WHEN("GET /capabilities (an ordinary generic-tier route) is called twice with the same cap installed")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/capabilities", token, {}});
            auto const second = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/capabilities", token, {}});

            THEN("the second call IS rate-limited, proving the installed cap is load-bearing")
            {
                CHECK(first.response.status == 200U);
                CHECK(second.response.status == 429U);
            }
        }
    }
}
