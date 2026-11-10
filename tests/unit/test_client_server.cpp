// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/cross_signing_fixture.hpp"
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |         MATRIX CLIENT-SERVER API CONFORMANCE TESTS                      |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                 |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST or SHOULD from the Matrix    |
// |  specification. If a test fails:                                         |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// |  The spec section is cited above each SCENARIO. Cross-check it before   |
// |  concluding that a failing assertion is wrong.                           |
// +-------------------------------------------------------------------------+

#include "../federation_signing_test_support.hpp"
#include "../support/MockIdentityServer.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreBackend.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/http/Header.hpp"
#include "merovingian/observability/LogLevel.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
#include <tuple>
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

using namespace merovingian::tests;

} // namespace

// --- Matrix error shape -------------------------------------------------------
// Spec: Matrix Client-Server API v1.19
// Standard error response format
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#standard-error-response
//
// Every error response MUST carry an "errcode" string and an "error" human-
// readable string. The shape is stable across all endpoints.
SCENARIO("Client-server runtime wraps errors in stable Matrix-style shapes", "[homeserver][client-server]")
{
    GIVEN("a Matrix error")
    {
        WHEN("it is rendered")
        {
            auto const body = merovingian::homeserver::matrix_error("M_FORBIDDEN", "denied");
            auto const response = merovingian::homeserver::LocalHttpResponse{403U, body};

            THEN("the response has a stable Matrix error body")
            {
                // Spec MUST: error body is {"errcode":"<CODE>","error":"<msg>"}
                // Do NOT remove/change - clients parse this exact shape to display errors
                REQUIRE(body == R"({"errcode":"M_FORBIDDEN","error":"denied"})");
                REQUIRE(merovingian::homeserver::is_matrix_error_response(response));
            }
        }
    }
}

// ─── MSC4186 sliding sync no-pos repeated poll returns delta ─────────────────
// matrix-rust-sdk sends timeout=0 (no pos in URL) alongside every timeout=30000
// long-poll to get an immediate snapshot.  Before this fix the server used
// since_event_ordering=0 for all no-pos requests, re-delivering every room
// event on every cycle (17 KB per call) and causing the SDK to reset and loop.
// After the fix, the second and subsequent no-pos requests on a connection that
// already has state use conn.last_event_ordering as the baseline, returning an
// empty rooms{} when nothing has changed.

SCENARIO("Sliding Sync diagnostic fields require explicit debug startup enablement",
         "[homeserver][sync][sliding-sync][observability]")
{
    GIVEN("a registration-enabled server configuration")
    {
        auto const config = registration_enabled_config();

        WHEN("the server starts without --debug")
        {
            auto const started = merovingian::homeserver::start_client_server(config);

            THEN("the sensitive request-shape diagnostics are disabled")
            {
                REQUIRE(started.started);
                REQUIRE_FALSE(started.runtime.sliding_sync_debug_diagnostics_enabled);
            }
        }

        WHEN("the server is started with the --debug diagnostic mode")
        {
            auto const started = merovingian::homeserver::start_client_server(config, {.debug_startup_enabled = true});

            THEN("the runtime permits Sliding Sync diagnostic fields")
            {
                REQUIRE(started.started);
                REQUIRE(started.runtime.sliding_sync_debug_diagnostics_enabled);
            }
        }
    }
}
