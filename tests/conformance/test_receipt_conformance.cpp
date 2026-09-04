// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX RECEIPT CONFORMANCE TESTS                                   |
// |                                                                          |
// |  Spec: Matrix Client-Server API v1.19                                     |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                  |
// |                                                                          |
// |  Covers POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}.|
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto conformance_config() -> merovingian::config::Config
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

[[nodiscard]] auto logged_in_token(merovingian::homeserver::ClientServerRuntime& runtime,
                                   std::string_view localpart = "alice") -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);

    auto const login_body =
        std::string{"{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"@"} +
        std::string{localpart} + ":example.org\"},\"password\":\"CorrectHorse7!\",\"device_id\":\"DEVICE1\"}";
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, login_body});
    REQUIRE(login.response.status == 200U);

    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    REQUIRE(!token->empty());
    return *token;
}

[[nodiscard]] auto room_id_from_create(std::string const& create_response_body) -> std::string
{
    auto const body = parse_object(create_response_body);
    auto const* room_id = string_member(body, "room_id");
    REQUIRE(room_id != nullptr);
    REQUIRE(!room_id->empty());
    return *room_id;
}

[[nodiscard]] auto event_id_from_send(std::string const& send_response_body) -> std::string
{
    auto const body = parse_object(send_response_body);
    auto const* event_id = string_member(body, "event_id");
    REQUIRE(event_id != nullptr);
    REQUIRE(!event_id->empty());
    return *event_id;
}

[[nodiscard]] auto first_room_ephemeral_events(merovingian::homeserver::ClientServerRuntime& runtime,
                                               std::string const& token, std::string const& room_id)
    -> merovingian::canonicaljson::Array
{
    auto const sync =
        merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/sync", token, {}});
    REQUIRE(sync.response.status == 200U);

    auto const body = parse_object(sync.response.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    REQUIRE(rooms != nullptr);
    auto const* join = object_member_as_object(*rooms, "join");
    REQUIRE(join != nullptr);

    for (auto const& member : *join)
    {
        if (member.key != room_id)
            continue;
        auto const* room_obj = std::get_if<merovingian::canonicaljson::Object>(&member.value->storage());
        REQUIRE(room_obj != nullptr);
        auto const* ephemeral = object_member_as_object(*room_obj, "ephemeral");
        if (ephemeral == nullptr)
            return {};
        auto const* events = object_member_as_array(*ephemeral, "events");
        if (events == nullptr)
            return {};
        return *events;
    }
    REQUIRE(false);
    return {};
}

[[nodiscard]] auto find_receipt_for_event(merovingian::canonicaljson::Array const& events, std::string const& event_id)
    -> merovingian::canonicaljson::Object const*
{
    for (auto const& ev : events)
    {
        auto const* ev_obj = std::get_if<merovingian::canonicaljson::Object>(&ev.storage());
        if (ev_obj == nullptr)
            continue;
        auto const* type = string_member(*ev_obj, "type");
        if (type == nullptr || *type != "m.receipt")
            continue;
        auto const* content = object_member_as_object(*ev_obj, "content");
        if (content == nullptr)
            continue;
        if (object_member_as_object(*content, event_id) != nullptr)
            return content;
    }
    return nullptr;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint: POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3roomsroomidreceiptreceipttypeeventid
//
// A valid m.read receipt is accepted and reflected in the next /sync response
// as an m.receipt ephemeral event.
SCENARIO("POST /rooms/{roomId}/receipt/m.read/{eventId} accepts and surfaces a read receipt",
         "[conformance][client-server][receipt]")
{
    GIVEN("a running client-server with a logged-in user in a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        auto const create = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"name":"receipt room"})"});
        REQUIRE(create.response.status == 200U);
        auto const room_id = room_id_from_create(create.response.body);

        auto const send = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn_receipt", token,
                              R"({"msgtype":"m.text","body":"hello"})"});
        REQUIRE(send.response.status == 200U);
        auto const event_id = event_id_from_send(send.response.body);

        WHEN("the user sends an m.read receipt for the event")
        {
            auto const receipt = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.read/" + event_id, token, {}});

            THEN("the server returns 200 and the receipt appears in the next /sync")
            {
                REQUIRE(receipt.response.status == 200U);

                auto const ephemeral = first_room_ephemeral_events(started.runtime, token, room_id);
                auto const* receipt_content = find_receipt_for_event(ephemeral, event_id);
                REQUIRE(receipt_content != nullptr);
                auto const* event_receipts = object_member_as_object(*receipt_content, event_id);
                REQUIRE(event_receipts != nullptr);
                auto const* read_users = object_member_as_object(*event_receipts, "m.read");
                REQUIRE(read_users != nullptr);
                REQUIRE(object_member_as_object(*read_users, "@alice:example.org") != nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint: POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
//
// The receiptType MUST be one of m.read, m.read.private, or m.fully_read.
SCENARIO("POST /rooms/{roomId}/receipt/{receiptType}/{eventId} rejects an invalid receipt type",
         "[conformance][client-server][receipt]")
{
    GIVEN("a running client-server with a logged-in user in a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        auto const create = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"name":"receipt room"})"});
        REQUIRE(create.response.status == 200U);
        auto const room_id = room_id_from_create(create.response.body);

        WHEN("the user sends a receipt with an unsupported type")
        {
            auto const receipt = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.invalid/$x:example.org", token, {}});

            THEN("the server responds with 400 M_INVALID_PARAM")
            {
                REQUIRE(receipt.response.status == 400U);
                auto const body = parse_object(receipt.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_INVALID_PARAM");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint: POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
//
// Non-members MUST receive a 403 M_FORBIDDEN response.
SCENARIO("POST /rooms/{roomId}/receipt/{receiptType}/{eventId} rejects non-members with M_FORBIDDEN",
         "[conformance][client-server][receipt]")
{
    GIVEN("a running client-server with two users and a room owned by one of them")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice_token = logged_in_token(started.runtime, "alice");
        auto const bob_token = logged_in_token(started.runtime, "bob");

        auto const create = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/createRoom", alice_token, R"({"name":"private room"})"});
        REQUIRE(create.response.status == 200U);
        auto const room_id = room_id_from_create(create.response.body);

        WHEN("bob tries to send a receipt in a room he has not joined")
        {
            auto const receipt = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.read/$x:example.org", bob_token, {}});

            THEN("the server responds with 403 M_FORBIDDEN")
            {
                REQUIRE(receipt.response.status == 403U);
                auto const body = parse_object(receipt.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_FORBIDDEN");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint: POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
//
// The request body MUST be a JSON object when present; a malformed body is
// rejected with M_BAD_JSON.
SCENARIO("POST /rooms/{roomId}/receipt/{receiptType}/{eventId} rejects a malformed body with M_BAD_JSON",
         "[conformance][client-server][receipt]")
{
    GIVEN("a running client-server with a logged-in user in a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime);

        auto const create = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"name":"receipt room"})"});
        REQUIRE(create.response.status == 200U);
        auto const room_id = room_id_from_create(create.response.body);

        WHEN("the user sends a malformed receipt body")
        {
            auto const receipt = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.read/$x:example.org", token, "not-json"});

            THEN("the server responds with 400 M_BAD_JSON")
            {
                REQUIRE(receipt.response.status == 400U);
                auto const body = parse_object(receipt.response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_BAD_JSON");
            }
        }
    }
}
