// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"
//
// +-------------------------------------------------------------------------+
// |         MEROVINGIAN HOMESERVER INTEGRATION TESTS                        |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19                                   |
// |        Matrix Server-Server API v1.19                                   |
// |  CS URL: ../../docs/matrix-v1.19-spec/client-server-api.md               |
// |  SS URL: ../../docs/matrix-v1.19-spec/server-server-api.md               |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec or a   |
// |  hard security invariant. If a test fails:                              |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// +-------------------------------------------------------------------------+

#include "../support/CrossSigningFixture.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/crypto/Ed25519SecretKeyHandle.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentServerSigningKey.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/DispatchWorker.hpp"
#include "merovingian/federation/ResolvedAddressSet.hpp"
#include "merovingian/federation/ServerDiscoveryNetwork.hpp"
#include "merovingian/federation/SrvRecord.hpp"
#include "merovingian/federation/WellKnownServerResult.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalRoom.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/RoomService.hpp"
#include "merovingian/observability/HealthStatus.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

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

[[nodiscard]] auto extract_token(std::string const& body) -> std::string
{
    auto const marker = std::string{"\"access_token\":\""};
    auto const start = body.find(marker);
    REQUIRE(start != std::string::npos);
    auto const value_start = start + marker.size();
    auto const value_end = body.find('"', value_start);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_start, value_end - value_start);
}

} // namespace

SCENARIO("Cross-signing key upload stores and returns all three key types",
         "[homeserver][vertical][keys][cross-signing]")
{
    GIVEN("a logged-in user uploading cross-signing keys")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const reg = merovingian::homeserver::handle_client_server_request(
            rt, {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            rt, {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},)"
                 R"("password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = extract_token(login.response.body);

        auto const cross_signing_body =
            merovingian::tests::fresh_cross_signing_upload_body("@alice:example.org", true, true, true);

        WHEN("the user uploads cross-signing keys via device_signing/upload")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/keys/device_signing/upload", token, cross_signing_body});
            REQUIRE(upload.response.status == 200U);

            THEN("all three key types are stored and returned by keys/query")
            {
                auto& store = rt.homeserver.database.persistent_store;
                auto master_count = std::size_t{0U};
                auto self_signing_count = std::size_t{0U};
                auto user_signing_count = std::size_t{0U};
                for (auto const& cskey : store.cross_signing_keys)
                {
                    if (cskey.user_id != "@alice:example.org")
                    {
                        continue;
                    }
                    if (cskey.key_type == "master")
                    {
                        ++master_count;
                    }
                    else if (cskey.key_type == "self_signing")
                    {
                        ++self_signing_count;
                    }
                    else if (cskey.key_type == "user_signing")
                    {
                        ++user_signing_count;
                    }
                }
                // Spec MUST: cross-signing key upload MUST persist all three key types.
                // Do NOT remove - Element's "Unable to set up keys" error is caused
                // by only storing the master key and losing self_signing/user_signing.
                REQUIRE(master_count == 1U);
                REQUIRE(self_signing_count == 1U);
                REQUIRE(user_signing_count == 1U);

                auto const query_body = std::string{R"({"device_keys":{"@alice:example.org":[]}})"};
                auto const query = merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", "/_matrix/client/v3/keys/query", token, query_body});
                REQUIRE(query.response.status == 200U);
                REQUIRE(query.response.body.find("\"master_keys\"") != std::string::npos);
                REQUIRE(query.response.body.find("\"self_signing_keys\"") != std::string::npos);
                REQUIRE(query.response.body.find("\"user_signing_keys\"") != std::string::npos);
            }
        }
    }
}
