// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |  SECURITY FIX TESTS — Issues #460-#463                                   |
// |                                                                         |
// |  BDD tests for the four security fixes introduced in 0.10.62.           |
// |  Each scenario follows GIVEN/WHEN/THEN and tests the security invariant |
// |  the fix establishes — not implementation details.                      |
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/FederationRemoteRuntime.hpp"
#include "merovingian/federation/InviteAcceptResult.hpp"
#include "merovingian/federation/InviteRequest.hpp"
#include "merovingian/federation/MembershipAcceptResult.hpp"
#include "merovingian/federation/SignedFederationRequest.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

auto constexpr local_server = "example.org";

} // namespace

// ===========================================================================
// Issue #460: Unauthenticated media download/thumbnail via v1 endpoints
// ===========================================================================
// Spec: Matrix v1.19 §13.8 — GET /_matrix/client/v1/media/download and
// /_matrix/client/v1/media/thumbnail require an access token.
//
// GIVEN a locally-stored media blob
// WHEN an unauthenticated GET /_matrix/client/v1/media/download/{serverName}/{mediaId} is sent
// THEN the server responds 401 and does not return the blob
// (and the same for /thumbnail/).
SCENARIO("Unauthenticated v1 media download is rejected with 401", "[security][media][auth][issue-460]")
{
    GIVEN("a started client-server runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        // The test only needs to verify the auth gate stops the request.
        // No media blob needs to be planted — the request must never reach
        // the media handler.
        auto const server_name = std::string{local_server};
        auto const media_id = std::string{"test-media-id-460"};

        WHEN("an unauthenticated GET v1 media download is dispatched")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v1/media/download/" + server_name + "/" + media_id, "", ""});

            THEN("the server responds 401 M_MISSING_TOKEN and does not return any media")
            {
                REQUIRE(result.response.status == 401U);
                REQUIRE(result.response.body.find("M_MISSING_TOKEN") != std::string::npos);
            }
        }
    }
}

SCENARIO("Unauthenticated v1 media thumbnail is rejected with 401", "[security][media][auth][issue-460]")
{
    GIVEN("a started client-server runtime")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const server_name = std::string{local_server};
        auto const media_id = std::string{"test-thumb-id-460"};

        WHEN("an unauthenticated GET v1 media thumbnail is dispatched")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"GET", "/_matrix/client/v1/media/thumbnail/" + server_name + "/" + media_id + "?width=32&height=32",
                 "", ""});

            THEN("the server responds 401 M_MISSING_TOKEN and does not return any media")
            {
                REQUIRE(result.response.status == 401U);
                REQUIRE(result.response.body.find("M_MISSING_TOKEN") != std::string::npos);
            }
        }
    }
}

// ===========================================================================
// Issue #463: Raw bearer access tokens written to logs and audit_log
// ===========================================================================
// GIVEN a request with a valid bearer token that triggers a pre-auth rejection
// WHEN the audit entry is recorded
// THEN the actor field in the audit_events contains a placeholder, never the raw token
SCENARIO("audit log actor field never contains the raw bearer token on 413 rejection", "[security][audit][issue-463]")
{
    GIVEN("a started client-server runtime and a raw bearer token")
    {
        REQUIRE(sodium_init() >= 0);
        auto config = registration_enabled_config();
        config.server().client_api.max_body_size = "64KiB";
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const raw_token = std::string{"sct_secret_bearer_token_463_should_never_appear"};

        // Build an oversized request body to trigger the 413 path.
        auto const body = std::string(100000, 'x'); // > 64 KiB configured body limit

        WHEN("the oversized request is dispatched (triggers 413 pre-auth)")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/sendToDevice/m.room_key_request/txn463", raw_token, body});

            THEN("the server responds 413 and the audit log actor never contains the raw token")
            {
                REQUIRE(result.response.status == 413U);

                // Check every audit event — none should contain the raw token.
                auto const& audit_events = runtime.homeserver.database.audit_events;
                for (auto const& event : audit_events)
                {
                    REQUIRE(event.actor.find(raw_token) == std::string::npos);
                }
            }
        }
    }
}

SCENARIO("audit log actor field never contains the raw bearer token on 429 rejection", "[security][audit][issue-463]")
{
    GIVEN("a started client-server runtime and a logged-in user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        // Register and login a user to get a real access token.
        auto const registered = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/register", "",
                      merovingian::tests::registration_json("rate_test_user_463", "CorrectHorse7!")});
        REQUIRE(registered.response.status == 200U);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/login", "",
                      "{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"rate_test_user_"
                      "463\"},\"password\":\"CorrectHorse7!\",\"device_id\":\"DEV463\"}"});
        REQUIRE(login.response.status == 200U);

        // Extract the access token from the login response.
        auto const& login_body = login.response.body;
        auto const token_begin = login_body.find("\"access_token\":\"");
        REQUIRE(token_begin != std::string::npos);
        auto const token_start = token_begin + std::string{"\"access_token\":\""}.size();
        auto const token_end = login_body.find('"', token_start);
        REQUIRE(token_end != std::string::npos);
        auto const real_token = login_body.substr(token_start, token_end - token_start);

        // Install a strict per-user rate limit to trigger 429 quickly.
        merovingian::homeserver::install_test_per_user_rate_limit_engine(runtime);

        WHEN("multiple requests are sent to trigger rate limiting")
        {
            auto got_429 = false;
            for (auto i = 0; i < 10 && !got_429; ++i)
            {
                auto const result = merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET", "/_matrix/client/v3/account/whoami", real_token, ""});
                if (result.response.status == 429U)
                {
                    got_429 = true;
                }
            }

            THEN("at least one 429 was returned and the audit log actor never contains the raw token")
            {
                REQUIRE(got_429);

                auto const& audit_events = runtime.homeserver.database.audit_events;
                for (auto const& event : audit_events)
                {
                    REQUIRE(event.actor.find(real_token) == std::string::npos);
                }
            }
        }
    }
}
