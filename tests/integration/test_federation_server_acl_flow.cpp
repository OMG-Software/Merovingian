// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |         MATRIX SERVER ACL (MSC4436) INTEGRATION FLOW TESTS              |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19 §Server Access Control Lists      |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md                 |
// |                                                                         |
//  These scenarios exercise the real end-to-end path through the federation |
//  inbound handler.  They verify that m.room.server_acl state events are    |
//  enforced at the federation boundary: on protected room-scoped          |
//  endpoints, per-PDU inside /send transactions, and per-room-local EDU.    |
// +-------------------------------------------------------------------------+

#include "../federation_signing_test_support.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/federation/FederationRemoteRuntime.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/security.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;

auto constexpr local_server_name = std::string_view{"example.org"};

[[nodiscard]] auto acl_test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    enable_token_registration(security);
    security.federation.enabled = true;
    security.federation.default_policy = "allow";
    security.federation.max_transaction_size = "1MiB";
    security.federation.remote_timeout = "30s";
    auto config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
    config.database().backend = merovingian::config::DatabaseBackend::sqlite;
    config.database().sqlite_path =
        (std::filesystem::temp_directory_path() /
         ("merovingian-acl-flow-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
          ".sqlite3"))
            .string();
    return config;
}

[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view localpart,
                                      std::string_view password, std::string_view device_id) -> std::string
{
    auto const registration = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/register", {}, registration_json(localpart, password)});
    REQUIRE(registration.response.status == 200U);

    auto const login_body =
        std::string{"{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"@"} +
        std::string{localpart} + ":example.org\"},\"password\":\"" + std::string{password} + "\",\"device_id\":\"" +
        std::string{device_id} + "\"}";
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, login_body});
    REQUIRE(login.response.status == 200U);
    return *string_member(parse_object(login.response.body), "access_token");
}

[[nodiscard]] auto create_room(merovingian::homeserver::ClientServerRuntime& runtime,
                               std::string const& token) -> std::string
{
    auto const create = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat","room_version":"12"})"});
    REQUIRE(create.response.status == 200U);
    return *string_member(parse_object(create.response.body), "room_id");
}

[[nodiscard]] auto set_server_acl(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                  std::string const& room_id, std::string const& content_json) -> bool
{
    auto const target = std::string{"/_matrix/client/v3/rooms/"} + room_id + "/state/m.room.server_acl";
    auto const response =
        merovingian::homeserver::handle_client_server_request(runtime, {"PUT", target, token, content_json});
    return response.response.status == 200U;
}

[[nodiscard]] auto remote_for(std::string const& origin, std::string const& key_id,
                              std::string const& key_seed) -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = origin;
    remote.signing_key = {origin, key_id, 2000U, merovingian::federation::test::keypair_from_seed(key_seed).public_key};
    remote.discovery.server_name = origin;
    remote.discovery.well_known_host = origin;
    remote.discovery.resolved_host = origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto federation_authorization(std::string const& origin, std::string const& key_id,
                                            std::string const& key_seed, std::string const& method,
                                            std::string const& target, std::string const& body) -> std::string
{
    auto const destination = std::string{local_server_name};
    auto const signature = merovingian::federation::make_federation_signature(
        origin, destination, method, target, body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return origin + '|' + key_id + '|' + signature + '|' + destination + "|1000|canonical";
}

[[nodiscard]] auto make_federation_request(merovingian::homeserver::HomeserverRuntime& runtime,
                                           std::string const& method, std::string const& target,
                                           std::string const& body, std::string const& origin,
                                           std::string const& key_id) -> merovingian::homeserver::LocalHttpResponse
{
    auto request = merovingian::homeserver::LocalHttpRequest{};
    request.method = method;
    request.target = target;
    request.body = body;
    request.sig_verified = true;
    request.verified_origin = origin;
    request.verified_key_id = key_id;
    return merovingian::homeserver::handle_federation_http_request(runtime, request);
}

[[nodiscard]] auto signed_message_pdu(std::string const& room_id, std::string const& sender_localpart,
                                      std::string const& origin, std::string const& key_id,
                                      std::string const& key_seed) -> std::string
{
    auto const sender = std::string{"@"} + sender_localpart + ":" + origin;
    auto const unsigned_json =
        std::string{"{\"auth_events\":[],\"content\":{\"body\":\"acl-test\",\"msgtype\":\"m.text\"},\"depth\":1,"
                    "\"origin_server_ts\":1,\"prev_events\":[],\"room_id\":\""} +
        room_id + "\",\"sender\":\"" + sender + "\",\"type\":\"m.room.message\"}";
    return merovingian::federation::test::make_signed_event_json(unsigned_json, origin, key_id, key_seed, "12");
}

[[nodiscard]] auto pdu_errors_object(std::string const& body) -> std::optional<merovingian::canonicaljson::Object>
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(body);
    if (parsed.error != merovingian::canonicaljson::ParseError::none)
    {
        return std::nullopt;
    }
    auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    if (root == nullptr)
    {
        return std::nullopt;
    }
    auto const* pdus = object_member_as_object(*root, "pdus");
    if (pdus == nullptr)
    {
        return std::nullopt;
    }
    return *pdus;
}

[[nodiscard]] auto typing_transaction_body(std::string const& origin, std::string const& room_id,
                                           std::string const& user_id, bool typing) -> std::string
{
    auto const content = std::string{"{\"room_id\":\""} + room_id + "\",\"user_id\":\"" + user_id +
                         "\",\"typing\":" + (typing ? "true" : "false") + "}";
    return std::string{"{\"origin\":\""} + origin +
           "\",\"origin_server_ts\":1000,\"pdus\":[],\"edus\":[{\"edu_type\":\"m.typing\",\"content\":" + content +
           "}]}";
}

// The ACL fixture under an operator policy: `allowed` empty keeps default_policy=allow.
[[nodiscard]] auto operator_policy_config(std::vector<std::string> denied, std::vector<std::string> allowed = {})
    -> merovingian::config::Config
{
    auto config = acl_test_config();
    config.security().federation.denied_servers = std::move(denied);
    if (!allowed.empty())
    {
        config.security().federation.default_policy = "deny";
        config.security().federation.allowed_servers = std::move(allowed);
    }
    return config;
}

// Counts what would have gone to the network for `watched`. It answers with the key the fixtures sign with.
[[nodiscard]] auto counting_key_resolver(
    std::shared_ptr<std::atomic<int>> lookups, // SHARED_PTR: reviewed — the test and the resolver both read the count
    std::string watched, std::string key_seed)
    -> std::function<std::optional<merovingian::federation::FederationRemoteRuntime>(std::string_view,
                                                                                     std::string_view)>
{
    return [lookups = std::move(lookups), watched = std::move(watched), key_seed = std::move(key_seed)](
               std::string_view server_name,
               std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
        if (server_name == watched)
        {
            ++*lookups;
        }
        return remote_for(std::string{server_name}, std::string{key_id}, key_seed);
    };
}

// The error /send reports for the one PDU it was given, or empty when it reports none.
[[nodiscard]] auto single_pdu_error(std::string const& response_body) -> std::string
{
    auto const pdus = pdu_errors_object(response_body);
    if (!pdus.has_value() || pdus->empty())
    {
        return {};
    }
    auto const* entry = std::get_if<merovingian::canonicaljson::Object>(&pdus->front().value->storage());
    auto const* error_text = entry == nullptr ? nullptr : string_member(*entry, "error");
    return error_text == nullptr ? std::string{} : *error_text;
}

} // namespace

// --- Protected endpoint enforcement ------------------------------------------
// Spec: Matrix Server-Server API v1.19 §Server Access Control Lists
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#server-access-control-lists
//
// Room-scoped federation endpoints (state, state_ids, backfill, make/send
// membership, invite, hierarchy, get_missing_events) MUST be rejected with
// 403 M_FORBIDDEN when the requesting origin is denied by the room's ACL.
// Rooms with no ACL event MUST remain open to all servers.
SCENARIO("Protected federation endpoints enforce per-room server ACLs", "[integration][federation][security][acl]")
{
    GIVEN("a started runtime with a room whose ACL denies evil.org and allows *.ping.me.uk")
    {
        auto started = merovingian::homeserver::start_client_server(acl_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);

        auto const token = register_and_login(runtime, "acladmin", "CorrectHorse7!", "ACL_DEV");
        auto const room_id = create_room(runtime, token);
        REQUIRE(set_server_acl(runtime, token, room_id,
                               R"({"allow":["*.ping.me.uk"],"deny":["evil.org"],"allow_ip_literals":true})"));

        auto const denied_origin = std::string{"evil.org"};
        auto const allowed_origin = std::string{"matrix.ping.me.uk"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const key_seed = std::string{"acl-test-key"};
        merovingian::federation::upsert_remote(runtime.homeserver.federation,
                                               remote_for(denied_origin, key_id, key_seed));
        merovingian::federation::upsert_remote(runtime.homeserver.federation,
                                               remote_for(allowed_origin, key_id, key_seed));

        auto const target = std::string{"/_matrix/federation/v1/state_ids/"} + room_id;

        WHEN("a denied origin requests a protected endpoint")
        {
            auto const response = make_federation_request(runtime.homeserver, "GET", target, "", denied_origin, key_id);

            THEN("the request is rejected with 403 M_FORBIDDEN before reaching the handler")
            {
                REQUIRE(response.status == 403U);
                auto const body = parse_object(response.body);
                REQUIRE(*string_member(body, "errcode") == "M_FORBIDDEN");
            }
        }

        WHEN("an allowed origin requests the same protected endpoint")
        {
            auto const response =
                make_federation_request(runtime.homeserver, "GET", target, "", allowed_origin, key_id);

            THEN("the request passes the ACL gate and reaches the endpoint handler")
            {
                // The handler itself may return 400/404/200 for its own reasons;
                // the important behaviour is that it is NOT 403 from the ACL gate.
                REQUIRE(response.status != 403U);
            }
        }
    }
}

// --- Default allow when no ACL event exists ----------------------------------
// Spec: A room with no m.room.server_acl state event MUST allow all servers.
SCENARIO("Rooms with no server ACL event allow all federated origins", "[integration][federation][security][acl]")
{
    GIVEN("a started runtime with a room but no ACL state event")
    {
        auto started = merovingian::homeserver::start_client_server(acl_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);

        auto const token = register_and_login(runtime, "acladmin2", "CorrectHorse7!", "ACL_DEV2");
        auto const room_id = create_room(runtime, token);

        auto const origin = std::string{"untrusted.example.net"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const key_seed = std::string{"acl-test-key-2"};
        merovingian::federation::upsert_remote(runtime.homeserver.federation, remote_for(origin, key_id, key_seed));

        WHEN("any origin requests a protected endpoint")
        {
            auto const target = std::string{"/_matrix/federation/v1/state/"} + room_id;
            auto const response = make_federation_request(runtime.homeserver, "GET", target, "", origin, key_id);

            THEN("the ACL gate permits the request")
            {
                REQUIRE(response.status != 403U);
            }
        }
    }
}

// --- Per-PDU enforcement inside /send transactions -----------------------------
// Spec: The receiving server MUST apply the room's server ACL to each PDU in
// the transaction.  A PDU from a denied sender's homeserver MUST be rejected,
// even if the transport origin is an allowed server that is relaying it.
SCENARIO("Inbound /send transaction rejects PDUs from servers denied by room ACL",
         "[integration][federation][security][acl]")
{
    GIVEN("a started runtime with a room that allows *.ping.me.uk and denies evil.org")
    {
        auto started = merovingian::homeserver::start_client_server(acl_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);

        auto const token = register_and_login(runtime, "aclpdu", "CorrectHorse7!", "ACL_PDU");
        auto const room_id = create_room(runtime, token);
        REQUIRE(set_server_acl(runtime, token, room_id,
                               R"({"allow":["*.ping.me.uk"],"deny":["evil.org"],"allow_ip_literals":true})"));

        auto const allowed_origin = std::string{"matrix.ping.me.uk"};
        auto const denied_origin = std::string{"evil.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const key_seed = std::string{"acl-pdu-key"};
        merovingian::federation::upsert_remote(runtime.homeserver.federation,
                                               remote_for(allowed_origin, key_id, key_seed));

        WHEN("a transaction relays a PDU whose sender is on a denied homeserver through an allowed origin")
        {
            auto const pdu_json = signed_message_pdu(room_id, "baduser", denied_origin, key_id, key_seed);
            auto const body = std::string{"{\"origin\":\""} + allowed_origin +
                              "\",\"origin_server_ts\":1000,\"pdus\":[" + pdu_json + "]}";
            auto const target = std::string{"/_matrix/federation/v1/send/txn-acl-pdu-denied"};
            auto const response =
                make_federation_request(runtime.homeserver, "PUT", target, body, allowed_origin, key_id);

            THEN("the transaction itself succeeds and reports the PDU as rejected")
            {
                REQUIRE(response.status == 200U);
                auto const pdus = pdu_errors_object(response.body);
                REQUIRE(pdus.has_value());
                REQUIRE(!pdus->empty());
                auto const* first_error =
                    std::get_if<merovingian::canonicaljson::Object>(&pdus->front().value->storage());
                REQUIRE(first_error != nullptr);
                auto const* error_text = string_member(*first_error, "error");
                REQUIRE(error_text != nullptr);
                REQUIRE(error_text->find("ACL") != std::string::npos);
            }
        }

        WHEN("a transaction carries a PDU whose sender belongs to the allowed origin")
        {
            auto const pdu_json = signed_message_pdu(room_id, "gooduser", allowed_origin, key_id, key_seed);
            auto const body = std::string{"{\"origin\":\""} + allowed_origin +
                              "\",\"origin_server_ts\":1000,\"pdus\":[" + pdu_json + "]}";
            auto const target = std::string{"/_matrix/federation/v1/send/txn-acl-pdu-allowed"};
            auto const response =
                make_federation_request(runtime.homeserver, "PUT", target, body, allowed_origin, key_id);

            THEN("the PDU is not rejected by the ACL gate")
            {
                REQUIRE(response.status == 200U);
                auto const pdus = pdu_errors_object(response.body);
                // pdus may contain errors from later auth checks, but the ACL
                // gate must not have added a rejection for this event.
                REQUIRE(pdus.has_value());
                REQUIRE_FALSE(std::ranges::any_of(*pdus, [&](merovingian::canonicaljson::ObjectMember const& m) {
                    auto const* err_obj = std::get_if<merovingian::canonicaljson::Object>(&m.value->storage());
                    if (err_obj == nullptr)
                    {
                        return false;
                    }
                    auto const* text = string_member(*err_obj, "error");
                    return text != nullptr && text->find("ACL") != std::string::npos;
                }));
            }
        }
    }
}

// --- Per-EDU enforcement for room-local EDUs ---------------------------------
// Spec: Room-local EDUs (m.typing, m.receipt) MUST be dropped when the
// transport origin is denied access to the room by the server ACL.
SCENARIO("Inbound room-local typing EDU is dropped when the origin is denied by room ACL",
         "[integration][federation][security][acl]")
{
    GIVEN("a started runtime with a room that allows *.ping.me.uk and denies evil.org")
    {
        auto started = merovingian::homeserver::start_client_server(acl_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);

        auto const token = register_and_login(runtime, "acledu", "CorrectHorse7!", "ACL_EDU");
        auto const room_id = create_room(runtime, token);
        REQUIRE(set_server_acl(runtime, token, room_id,
                               R"({"allow":["*.ping.me.uk"],"deny":["evil.org"],"allow_ip_literals":true})"));

        auto const allowed_origin = std::string{"matrix.ping.me.uk"};
        auto const denied_origin = std::string{"evil.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const key_seed = std::string{"acl-edu-key"};
        merovingian::federation::upsert_remote(runtime.homeserver.federation,
                                               remote_for(allowed_origin, key_id, key_seed));
        merovingian::federation::upsert_remote(runtime.homeserver.federation,
                                               remote_for(denied_origin, key_id, key_seed));

        WHEN("a typing EDU arrives from a denied origin")
        {
            auto const body = typing_transaction_body(denied_origin, room_id, "@bad:evil.org", true);
            auto const target = std::string{"/_matrix/federation/v1/send/txn-acl-edu-denied"};
            auto const response =
                make_federation_request(runtime.homeserver, "PUT", target, body, denied_origin, key_id);

            THEN("the transaction succeeds but the typing state is not updated")
            {
                REQUIRE(response.status == 200U);
                auto const typing_in_room = std::ranges::any_of(runtime.homeserver.typing_users, [&](auto const& t) {
                    return t.room_id == room_id;
                });
                REQUIRE_FALSE(typing_in_room);
            }
        }

        WHEN("a typing EDU arrives from an allowed origin")
        {
            auto const user_id = std::string{"@good:matrix.ping.me.uk"};
            // An inbound typing EDU is applied only for a user joined to the room (F-55).
            runtime.homeserver.database.persistent_store.memberships.push_back({room_id, user_id, "join", 0U});
            auto const body = typing_transaction_body(allowed_origin, room_id, user_id, true);
            auto const target = std::string{"/_matrix/federation/v1/send/txn-acl-edu-allowed"};
            auto const response =
                make_federation_request(runtime.homeserver, "PUT", target, body, allowed_origin, key_id);

            THEN("the typing state is updated because the EDU passed the ACL gate")
            {
                REQUIRE(response.status == 200U);
                auto const typing_in_room = std::ranges::any_of(runtime.homeserver.typing_users, [&](auto const& t) {
                    return t.room_id == room_id && t.user_id == user_id && t.typing;
                });
                REQUIRE(typing_in_room);
            }
        }
    }
}

// --- Request signature path also enforces ACLs --------------------------------
// The test harness's handle_local_http_request path parses the pipe-delimited
// Authorization header and drives the same federation core.  This scenario
// confirms the ACL gate is reached through that entry point as well.
SCENARIO("Server ACL is enforced through the local router's federation Authorization header path",
         "[integration][federation][security][acl]")
{
    GIVEN("a started runtime with a room that denies evil.org")
    {
        auto started = merovingian::homeserver::start_client_server(acl_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);

        auto const token = register_and_login(runtime, "aclauth", "CorrectHorse7!", "ACL_AUTH");
        auto const room_id = create_room(runtime, token);
        REQUIRE(set_server_acl(runtime, token, room_id, R"({"allow":["*"],"deny":["evil.org"]})"));

        auto const origin = std::string{"evil.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const key_seed = std::string{"acl-auth-key"};
        merovingian::federation::upsert_remote(runtime.homeserver.federation, remote_for(origin, key_id, key_seed));

        WHEN("a denied origin reaches the local router with a real X-Matrix Authorization header")
        {
            auto const target = std::string{"/_matrix/federation/v1/state_ids/"} + room_id;
            auto const body = std::string{};
            auto const authorization = federation_authorization(origin, key_id, key_seed, "GET", target, body);
            auto const response = merovingian::homeserver::handle_local_http_request(
                runtime.homeserver, {"GET", target, authorization, body});

            THEN("the ACL gate rejects it with 403 M_FORBIDDEN")
            {
                REQUIRE(response.status == 403U);
                auto const parsed = parse_object(response.body);
                REQUIRE(*string_member(parsed, "errcode") == "M_FORBIDDEN");
            }
        }
    }
}

// --- The operator's own federation policy, for the server that wrote an event --
// The spec defines no operator-level server deny, so these are this project's rules (ADR-0390, ADR-0391):
// security.federation.denied_servers, default_policy=deny and an admin's scope-federation rule hold for what a
// server wrote however it reaches us, and nothing is sent to or fetched from a server they exclude.
SCENARIO("A relayed PDU whose sender's server the operator excludes is refused without a key lookup",
         "[integration][federation][security][operator-policy]")
{
    auto const allowed_origin = std::string{"matrix.ping.me.uk"};
    auto const key_id = std::string{"ed25519:auto"};
    auto const key_seed = std::string{"operator-policy-key"};

    auto const send_relayed = [&](merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                  std::string const& sender_server, std::string const& txn) {
        auto const room_id = create_room(runtime, token);
        merovingian::federation::upsert_remote(runtime.homeserver.federation,
                                               remote_for(allowed_origin, key_id, key_seed));
        auto const pdu_json = signed_message_pdu(room_id, "someone", sender_server, key_id, key_seed);
        auto const body = std::string{"{\"origin\":\""} + allowed_origin + "\",\"origin_server_ts\":1000,\"pdus\":[" +
                          pdu_json + "]}";
        return make_federation_request(runtime.homeserver, "PUT", "/_matrix/federation/v1/send/" + txn, body,
                                       allowed_origin, key_id);
    };

    GIVEN("a server that lists evil.org in denied_servers")
    {
        auto started = merovingian::homeserver::start_client_server(operator_policy_config({"evil.org"}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        auto const lookups = std::make_shared<std::atomic<int>>(0);
        runtime.homeserver.federation.remote_key_resolver = counting_key_resolver(lookups, "evil.org", key_seed);
        auto const token = register_and_login(runtime, "opdeny", "CorrectHorse7!", "OP_DENY");

        // The author's server is excluded and the carrying peer is not, so an origin check alone passes this.
        WHEN("an allowed peer relays a PDU that a user on evil.org wrote")
        {
            auto const response = send_relayed(runtime, token, "evil.org", "txn-op-denied");

            THEN("the transaction succeeds, the PDU is refused, and no key is fetched for evil.org")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(single_pdu_error(response.body).find("operator policy") != std::string::npos);
                REQUIRE(lookups->load() == 0);
            }
        }

        // Control: the same relay from a permitted author shows the refusal above is the policy's.
        WHEN("an allowed peer relays a PDU that a user on another server wrote")
        {
            auto const response = send_relayed(runtime, token, "other.example.net", "txn-op-other");

            THEN("the operator's policy is not what refuses it")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(single_pdu_error(response.body).find("operator policy") == std::string::npos);
            }
        }
    }

    GIVEN("a server federating only with an allow list")
    {
        auto started = merovingian::homeserver::start_client_server(operator_policy_config({}, {allowed_origin}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        auto const lookups = std::make_shared<std::atomic<int>>(0);
        runtime.homeserver.federation.remote_key_resolver =
            counting_key_resolver(lookups, "unlisted.example", key_seed);
        auto const token = register_and_login(runtime, "opallow", "CorrectHorse7!", "OP_ALLOW");

        // With an allow list, the author is judged as an origin would be.
        WHEN("a listed peer relays a PDU that a user on an unlisted server wrote")
        {
            auto const response = send_relayed(runtime, token, "unlisted.example", "txn-op-unlisted");

            THEN("the PDU is refused and no key is fetched for the unlisted server")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(single_pdu_error(response.body).find("operator policy") != std::string::npos);
                REQUIRE(lookups->load() == 0);
            }
        }
    }

    GIVEN("a server with an admin's federation deny rule for evil.org")
    {
        auto started = merovingian::homeserver::start_client_server(acl_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        auto const lookups = std::make_shared<std::atomic<int>>(0);
        runtime.homeserver.federation.remote_key_resolver = counting_key_resolver(lookups, "evil.org", key_seed);
        auto const token = register_and_login(runtime, "oprule", "CorrectHorse7!", "OP_RULE");
        {
            auto const guard = std::lock_guard{runtime.homeserver.mutex};
            runtime.homeserver.database.persistent_store.policy_rules.push_back(
                {"rule-evil", "federation", "evil.org", "deny", ""});
        }

        // An admin rule is runtime state rather than config, and it is judged on this path too.
        WHEN("an allowed peer relays a PDU that a user on evil.org wrote")
        {
            auto const response = send_relayed(runtime, token, "evil.org", "txn-op-rule");

            THEN("the PDU is refused and no key is fetched for evil.org")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(single_pdu_error(response.body).find("operator policy") != std::string::npos);
                REQUIRE(lookups->load() == 0);
            }
        }
    }
}

SCENARIO("Operator policy never refuses this server's own events", "[integration][federation][operator-policy]")
{
    GIVEN("federation state on an allow list that does not name this server")
    {
        auto config = merovingian::federation::RuntimeFederationConfig{};
        config.enabled = true;
        config.default_policy = "deny";
        config.allowed_servers = {"listed.example"};
        config.server_name = "self.example";
        auto const state = merovingian::federation::make_federation_runtime_state(std::move(config));

        WHEN("each kind of server name is judged")
        {
            auto const own = merovingian::federation::operator_policy_refusal(state, "self.example");
            auto const listed = merovingian::federation::operator_policy_refusal(state, "listed.example");
            auto const unlisted = merovingian::federation::operator_policy_refusal(state, "unlisted.example");

            THEN("only the server off the list is refused")
            {
                REQUIRE(own.empty());
                REQUIRE(listed.empty());
                REQUIRE_FALSE(unlisted.empty());
            }
        }
    }
}

SCENARIO("A send_join answer loses what an excluded server wrote and fetches no key for it",
         "[integration][federation][security][operator-policy]")
{
    GIVEN("a joining server that lists evil.org in denied_servers, and an answer from two servers")
    {
        auto started = merovingian::homeserver::start_client_server(operator_policy_config({"evil.org"}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        auto const key_id = std::string{"ed25519:auto"};
        auto const key_seed = std::string{"operator-policy-join-key"};
        auto const lookups = std::make_shared<std::atomic<int>>(0);
        runtime.homeserver.federation.cached_pdu_key_lookup = {};
        runtime.homeserver.federation.remote_key_resolver = counting_key_resolver(lookups, "evil.org", key_seed);

        auto const room_id = std::string{"!joining:good.example"};
        auto const event_of = [&](std::string const& server) {
            return merovingian::canonicaljson::parse_lossless(
                       signed_message_pdu(room_id, "someone", server, key_id, key_seed))
                .value;
        };
        auto answer = merovingian::canonicaljson::Array{};
        answer.push_back(event_of("evil.org"));
        answer.push_back(event_of("good.example"));
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        WHEN("the answer is filtered")
        {
            auto const kept = merovingian::homeserver::filter_verified_send_join_events(runtime.homeserver, answer,
                                                                                        *policy, local_server_name);

            THEN("only the allowed server's event is kept and evil.org is never asked for a key")
            {
                REQUIRE(kept.size() == 1U);
                REQUIRE(lookups->load() == 0);
            }
        }
    }
}

SCENARIO("A signed outbound call to a server the operator excludes is not made",
         "[integration][federation][security][operator-policy]")
{
    GIVEN("a server that lists evil.org in denied_servers and allows only friend.example otherwise")
    {
        auto started =
            merovingian::homeserver::start_client_server(operator_policy_config({"evil.org"}, {"friend.example"}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        auto const signing_key = merovingian::homeserver::ensure_runtime_server_signing_key(runtime.homeserver);
        REQUIRE(signing_key.has_value());
        auto const call_to = [&](std::string const& destination) {
            auto const transaction = merovingian::federation::make_outbound_transaction(
                destination, "GET", "/_matrix/federation/v1/version", local_server_name, {});
            return merovingian::homeserver::perform_sync_outbound_call(
                runtime.homeserver, merovingian::homeserver::OutboundAnswerTrust::unverified, {}, transaction,
                signing_key->key_id,
                merovingian::core::SecretBuffer{runtime.homeserver.database.signing_secret_key.bytes()},
                "test.operator_policy", 5U);
        };

        WHEN("a call is attempted to a denied server and to one off the allow list")
        {
            auto const [denied_ok, denied_body] = call_to("evil.org");
            auto const [unlisted_ok, unlisted_body] = call_to("unlisted.example");

            THEN("neither is made and each answer names the policy")
            {
                REQUIRE_FALSE(denied_ok);
                REQUIRE(denied_body == "remote server is denied");
                REQUIRE_FALSE(unlisted_ok);
                REQUIRE(unlisted_body == "remote server is not in federation allow list");
            }
        }
    }
}

SCENARIO("sendToDevice answers 200 and queues nothing for a server the operator excludes",
         "[integration][federation][security][operator-policy]")
{
    GIVEN("a server that lists evil.org in denied_servers, with its dispatch worker not started")
    {
        auto started = merovingian::homeserver::start_client_server(operator_policy_config({"evil.org"}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        REQUIRE(runtime.homeserver.outbound_client != nullptr);
        auto worker_config = merovingian::federation::DispatchWorkerConfig{};
        worker_config.origin = runtime.homeserver.config.server().server_name;
        worker_config.key_id = "ed25519:test";
        runtime.homeserver.dispatch_worker = std::make_unique<merovingian::federation::DispatchWorker>(
            std::move(worker_config), *runtime.homeserver.outbound_client,
            [](std::string_view) {
                return std::optional<merovingian::federation::ServerDiscoveryResult>{};
            },
            merovingian::federation::DispatchClock{}, merovingian::federation::DispatchSleep{},
            &runtime.homeserver.database.persistent_store);
        auto const token = register_and_login(runtime, "opdevice", "CorrectHorse7!", "OP_DEVICE");

        WHEN("a user sends a to-device message to one user on evil.org and one elsewhere")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/sendToDevice/m.test/op1", token,
                          R"({"messages":{"@x:evil.org":{"*":{}},"@y:good.example":{"*":{}}}})"});

            THEN("the request succeeds and only the other server has a transaction queued")
            {
                REQUIRE(response.response.status == 200U);
                auto const guard = std::lock_guard{runtime.homeserver.mutex};
                auto const& queued = runtime.homeserver.database.persistent_store.federation_transactions;
                REQUIRE(queued.size() == 1U);
                REQUIRE(queued.front().server_name == "good.example");
            }
        }
    }
}

// Server-Server API > Checks performed on receipt of a PDU, step 1, and the room version's event format. A send_join
// answer is events received from a remote server like any other, so what breaks the format is not stored. The
// oversized event below is genuinely signed: a signature does not make it valid.
SCENARIO("A send_join answer loses events outside the room version's event format",
         "[integration][federation][send-join-format][pdu-format]")
{
    GIVEN("a joining server, and a resident's answer holding a valid event and ones breaking each format rule")
    {
        auto started = merovingian::homeserver::start_client_server(acl_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        auto const key_id = std::string{"ed25519:auto"};
        auto const key_seed = std::string{"send-join-format-key"};
        runtime.homeserver.federation.cached_pdu_key_lookup = {};
        runtime.homeserver.federation.remote_key_resolver =
            counting_key_resolver(std::make_shared<std::atomic<int>>(0), {}, key_seed);

        auto const event_of = [&](std::string const& prev_events, std::string const& body) {
            auto const unsigned_json =
                std::string{R"({"auth_events":[],"content":{"body":")"} + body +
                R"(","msgtype":"m.text"},"depth":1,"origin_server_ts":1,"prev_events":)" + prev_events +
                R"(,"room_id":"!joining:good.example","sender":"@someone:good.example","type":"m.room.message"})";
            return merovingian::canonicaljson::parse_lossless(
                       merovingian::federation::test::make_signed_event_json(unsigned_json, "good.example", key_id,
                                                                             key_seed, "12"))
                .value;
        };
        auto twenty_one = std::string{"["};
        for (auto index = 0; index < 21; ++index)
        {
            twenty_one += (index == 0 ? "\"$e" : ",\"$e") + std::to_string(index) + "\"";
        }
        twenty_one += "]";
        auto answer = merovingian::canonicaljson::Array{};
        answer.push_back(event_of("[]", "valid"));
        answer.push_back(event_of(twenty_one, "too many prev_events"));
        answer.push_back(event_of("[]", std::string(70000U, 'x')));
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        WHEN("the answer is filtered")
        {
            auto const kept = merovingian::homeserver::filter_verified_send_join_events(runtime.homeserver, answer,
                                                                                        *policy, local_server_name);

            THEN("only the valid event is kept")
            {
                REQUIRE(kept.size() == 1U);
            }
        }
    }
}
