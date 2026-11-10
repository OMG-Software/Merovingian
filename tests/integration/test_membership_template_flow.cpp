// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Project rule (ADR-0318), not a spec requirement: a resident that holds no forward extremity for a room offers no
// membership template, and GET /make_join, /make_leave and /make_knock answer 404 M_NOT_FOUND, the answer they give
// for a room they cannot serve. The spec does not say what a resident answers when it has no tip; a template with
// empty `prev_events` would detach the joiner's event from the room's graph. Moved here from
// tests/conformance/test_event_depth_conformance.cpp (issue 551): conformance tests hold spec requirements only.
#include "../federation_signing_test_support.hpp"
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/FederationRemoteRuntime.hpp"
#include "merovingian/federation/SignedFederationRequest.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <sodium.h>

#include <string>
#include <vector>

namespace
{

auto constexpr local_server = "example.org";
auto constexpr remote_origin = "remote.example.org";
auto constexpr remote_key_id = "ed25519:auto";
auto constexpr remote_key_seed = "membership-template-flow-seed";

[[nodiscard]] auto test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
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

[[nodiscard]] auto remote_for_test() -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = remote_origin;
    remote.signing_key = {remote_origin, remote_key_id, 4'102'444'800'000U,
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
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "GET";
    request.target = target;
    request.origin = remote_origin;
    request.destination = local_server;
    request.key_id = remote_key_id;
    request.now_ts = 1000U;
    request.canonical_json_verified = true;
    request.body = "";
    request.signature = merovingian::federation::make_federation_signature(
        remote_origin, request.destination, request.method, target, request.body,
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    return request;
}

// The path of each membership template endpoint, for the room and a user of the remote server. `ver` names the
// version createRoom gives the room, so a refusal for the room version cannot stand in for the answer tested here.
[[nodiscard]] auto template_target(std::string const& endpoint, std::string const& room_id) -> std::string
{
    auto const query = endpoint == "make_leave" ? std::string{} : std::string{"?ver=12"};
    return "/_matrix/federation/v1/" + endpoint + "/" + room_id + "/@carol:" + remote_origin + query;
}

} // namespace

SCENARIO("A resident with no tips for a room offers no membership template",
         "[integration][federation][membership][template-prev-events][issue-551]")
{
    GIVEN("a room with a local member, and a remote server this server trusts")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());
        auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(reg.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room.ok);
        auto& store = runtime.database.persistent_store;
        REQUIRE_FALSE(merovingian::homeserver::forward_extremities_for_new_event(store, room.value).empty());
        auto const endpoint = GENERATE(as<std::string>{}, "make_join", "make_leave", "make_knock");

        WHEN("GET /" + endpoint + " is asked while the room still has its tips")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation, signed_get(template_target(endpoint, room.value)));

            THEN("it is not answered as a room this server cannot serve")
            {
                INFO("response: " << response.body);
                REQUIRE(response.status != 404U);
            }
        }

        WHEN("the room's tips are gone and GET /" + endpoint + " is asked")
        {
            std::erase_if(store.forward_extremities, [&](auto const& extremity) {
                return extremity.room_id == room.value;
            });
            REQUIRE(merovingian::homeserver::forward_extremities_for_new_event(store, room.value).empty());
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation, signed_get(template_target(endpoint, room.value)));

            THEN("it is answered 404 M_NOT_FOUND, rather than with a template whose prev_events are empty")
            {
                INFO("response: " << response.body);
                REQUIRE(response.status == 404U);
                REQUIRE(response.body.find("M_NOT_FOUND") != std::string::npos);
                REQUIRE(response.body.find("prev_events") == std::string::npos);
            }
        }
    }
}
