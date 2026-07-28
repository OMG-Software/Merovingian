// SPDX-License-Identifier: GPL-3.0-or-later
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
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/security.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace
{

using namespace merovingian::tests;

auto constexpr local_server_name = std::string_view{"example.org"};

[[nodiscard]] auto acl_test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    enable_token_registration(security);
    security.federation.enabled = true;
    security.federation.default_policy = "allow";
    security.federation.max_transaction_size = "1MiB";
    security.federation.remote_timeout = "30s";
    auto config = merovingian::config::Config{
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
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

[[nodiscard]] auto create_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::string
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

[[nodiscard]] auto remote_for(std::string const& origin, std::string const& key_id, std::string const& key_seed)
    -> merovingian::federation::FederationRemoteRuntime
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
                                      std::string const& origin, std::string const& key_id, std::string const& key_seed)
    -> std::string
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
        REQUIRE(set_server_acl(runtime, token, room_id, R"({"deny":["evil.org"]})"));

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
