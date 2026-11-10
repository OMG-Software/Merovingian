// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"
//
// +-------------------------------------------------------------------------+
// |  SECURITY AUDIT FED-6, FED-8, FED-11                                    |
// |  Medium-severity federation findings from 2026-09-29 audit.           |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md                |
// +-------------------------------------------------------------------------+

#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/MembershipFixtureSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "FederationSigningTestSupport.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
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
#include "merovingian/events/EventId.hpp"
#include "merovingian/federation/FederationKeyRecord.hpp"
#include "merovingian/federation/FederationRemoteRuntime.hpp"
#include "merovingian/federation/FederationResponse.hpp"
#include "merovingian/federation/SignedFederationRequest.hpp"
#include "merovingian/federation/InboundRequest.hpp"
#include "merovingian/homeserver/CreateRoomOptions.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/WorkerPool.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/RoomService.hpp"
#include "merovingian/homeserver/StateBookkeeping.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <sodium.h>

#include <algorithm>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace
{
auto constexpr local_server = "example.org";
auto constexpr remote_origin = "remote.example.org";
auto constexpr remote_key_id = "ed25519:auto";
auto constexpr remote_key_seed = "fed-6-8-11-audit-remote-seed";

[[nodiscard]] auto remote_for_test() -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = remote_origin;
    remote.signing_key = {remote_origin, remote_key_id, 2000U,
                          merovingian::federation::test::keypair_from_seed(remote_key_seed).public_key};
    remote.discovery.server_name = remote_origin;
    remote.discovery.well_known_host = remote_origin;
    remote.discovery.resolved_host = remote_origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto signed_get(std::string const& target) -> merovingian::federation::SignedFederationRequest
{
    auto req = merovingian::federation::SignedFederationRequest{};
    req.method = "GET";
    req.target = target;
    req.origin = remote_origin;
    req.destination = local_server;
    req.key_id = remote_key_id;
    req.now_ts = 1000U;
    req.canonical_json_verified = true;
    req.body = "";
    req.signature = merovingian::federation::make_federation_signature(
        req.origin, req.destination, req.method, target, req.body,
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    return req;
}

[[nodiscard]] auto federation_runtime_config() -> merovingian::federation::RuntimeFederationConfig
{
    auto config = merovingian::federation::RuntimeFederationConfig{};
    config.enabled = true;
    config.default_policy = "allow";
    config.require_valid_tls = true;
    config.verify_json_signatures = true;
    config.max_transaction_bytes = 16384U;
    config.remote_timeout_seconds = 30U;
    config.server_name = local_server;
    return config;
}

} // namespace

// Spec (SS API v1.19): GET /make_join/{roomId}/{userId},
// GET /make_knock/{roomId}/{userId}, GET /make_leave/{roomId}/{userId} all
// require {userId} to be a user on the origin server. The template provider
// must not be invoked when this precondition fails.
SCENARIO("make_membership rejects a userId that is not on the origin server", "[security][federation][fed-6]")
{
    GIVEN("a runtime with a wired make_membership template provider")
    {
        REQUIRE(sodium_init() >= 0);
        auto runtime = merovingian::federation::make_federation_runtime_state(federation_runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_test());

        auto provider_calls = 0U;
        runtime.membership_template_provider = [&](merovingian::federation::FederationEndpoint, std::string_view,
                                                   std::string_view, std::vector<std::string> const&) {
            ++provider_calls;
            auto tmpl = merovingian::federation::MembershipEventTemplate{};
            tmpl.room_id = "!room:example.org";
            tmpl.user_id = "@member:remote.example.org";
            tmpl.membership = "join";
            tmpl.room_version = "12";
            tmpl.depth = 5;
            tmpl.prev_events = {"$prev:example.org"};
            tmpl.auth_events = {"$auth:example.org"};
            tmpl.content_json = R"({"membership":"join"})";
            return std::optional<merovingian::federation::MembershipEventTemplate>{std::move(tmpl)};
        };

        auto const endpoint = std::string{GENERATE("make_join", "make_leave", "make_knock")};
        auto const room_id = std::string{"!room:example.org"};
        auto const foreign_user = std::string{"@alice:example.org"};
        auto const target = "/_matrix/federation/v1/" + endpoint + "/" + room_id + "/" + foreign_user + "?ver=12";

        WHEN(endpoint + " receives a userId outside the authenticated origin")
        {
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime, signed_get(target));

            THEN("the response is 400 M_INVALID_PARAM")
            {
                REQUIRE(response.status == 400U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* errcode = merovingian::tests::string_member(*root, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == std::string{"M_INVALID_PARAM"});
            }

            THEN("the template provider is never invoked")
            {
                REQUIRE(provider_calls == 0U);
            }
        }
    }
}
