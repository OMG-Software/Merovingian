// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |         MATRIX RECEIPT CONFORMANCE TESTS                                   |
// |                                                                          |
// |  Spec: Matrix Client-Server API v1.19                                     |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                  |
// |                                                                          |
// |  Covers POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}.|
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

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
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
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

namespace
{

// Shared fixture for the receipt-visibility scenarios: alice and bob in a public room, and an
// event from bob for alice to read.
struct SharedRoom final
{
    std::string alice{};
    std::string bob{};
    std::string room_id{};
    std::string event_id{};
};

[[nodiscard]] auto make_shared_room(merovingian::homeserver::ClientServerRuntime& runtime) -> SharedRoom
{
    auto fixture = SharedRoom{};
    fixture.alice = logged_in_token(runtime, "alice");
    fixture.bob = logged_in_token(runtime, "bob");
    auto const create = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", fixture.alice, R"({"preset":"public_chat"})"});
    REQUIRE(create.response.status == 200U);
    fixture.room_id = room_id_from_create(create.response.body);
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + fixture.room_id + "/join", fixture.bob, "{}"})
                .response.status == 200U);
    auto const send = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + fixture.room_id + "/send/m.room.message/txn_vis", fixture.bob,
                  R"({"msgtype":"m.text","body":"hello"})"});
    REQUIRE(send.response.status == 200U);
    fixture.event_id = event_id_from_send(send.response.body);
    return fixture;
}

// Every receipt type/user pair present in m.receipt ephemeral events for a room in /sync.
struct SyncReceipts final
{
    std::vector<std::string> receipt_types{};
    std::vector<std::string> users_with_any_receipt{};
    std::vector<std::string> users_with_type{};
};

[[nodiscard]] auto sync_receipts(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                 std::string const& room_id, std::string_view type_of_interest) -> SyncReceipts
{
    auto out = SyncReceipts{};
    auto const events = first_room_ephemeral_events(runtime, token, room_id);
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
        for (auto const& by_event : *content)
        {
            auto const* by_type = std::get_if<merovingian::canonicaljson::Object>(&by_event.value->storage());
            if (by_type == nullptr)
                continue;
            for (auto const& type_member : *by_type)
            {
                out.receipt_types.push_back(type_member.key);
                auto const* users = std::get_if<merovingian::canonicaljson::Object>(&type_member.value->storage());
                if (users == nullptr)
                    continue;
                for (auto const& user : *users)
                {
                    out.users_with_any_receipt.push_back(user.key);
                    if (type_member.key == type_of_interest)
                        out.users_with_type.push_back(user.key);
                }
            }
        }
    }
    return out;
}

// event_id carried by the room account data event of `event_type` in the user's /sync, or empty.
[[nodiscard]] auto room_account_data_event_id(merovingian::homeserver::ClientServerRuntime& runtime,
                                              std::string const& token, std::string const& room_id,
                                              std::string_view event_type) -> std::string
{
    auto const sync =
        merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/sync", token, {}});
    REQUIRE(sync.response.status == 200U);
    auto const body = parse_object(sync.response.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    auto const* join = rooms == nullptr ? nullptr : object_member_as_object(*rooms, "join");
    auto const* room = join == nullptr ? nullptr : object_member_as_object(*join, room_id);
    auto const* account_data = room == nullptr ? nullptr : object_member_as_object(*room, "account_data");
    auto const* events = account_data == nullptr ? nullptr : object_member_as_array(*account_data, "events");
    if (events == nullptr)
        return {};
    for (auto const& ev : *events)
    {
        auto const* ev_obj = std::get_if<merovingian::canonicaljson::Object>(&ev.storage());
        auto const* type = ev_obj == nullptr ? nullptr : string_member(*ev_obj, "type");
        if (type == nullptr || *type != event_type)
            continue;
        auto const* content = object_member_as_object(*ev_obj, "content");
        auto const* event_id = content == nullptr ? nullptr : string_member(*content, "event_id");
        return event_id == nullptr ? std::string{} : *event_id;
    }
    return {};
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Section: Receipts — Security considerations (private read receipts)
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#receipts
//
// "Servers MUST NOT send the m.read.private receipt to any other user than the one which
// originally sent it."
SCENARIO("/sync sends an m.read.private receipt only to the user who sent it",
         "[conformance][client-server][receipt][security][csaz-4]")
{
    GIVEN("alice and bob in a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const fixture = make_shared_room(started.runtime);

        WHEN("alice sends an m.read.private receipt")
        {
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        started.runtime,
                        {"POST",
                         "/_matrix/client/v3/rooms/" + fixture.room_id + "/receipt/m.read.private/" + fixture.event_id,
                         fixture.alice,
                         {}})
                        .response.status == 200U);

            THEN("bob's /sync contains no receipt from alice")
            {
                auto const bob_view = sync_receipts(started.runtime, fixture.bob, fixture.room_id, "m.read.private");
                REQUIRE(bob_view.users_with_any_receipt.empty());
                REQUIRE(bob_view.users_with_type.empty());
            }

            THEN("alice's own /sync contains her private receipt")
            {
                auto const alice_view =
                    sync_receipts(started.runtime, fixture.alice, fixture.room_id, "m.read.private");
                REQUIRE(alice_view.users_with_type == std::vector<std::string>{"@alice:example.org"});
            }
        }

        WHEN("alice sends both an m.read and an m.read.private receipt")
        {
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        started.runtime,
                        {"POST",
                         "/_matrix/client/v3/rooms/" + fixture.room_id + "/receipt/m.read/" + fixture.event_id,
                         fixture.alice,
                         {}})
                        .response.status == 200U);
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        started.runtime,
                        {"POST",
                         "/_matrix/client/v3/rooms/" + fixture.room_id + "/receipt/m.read.private/" + fixture.event_id,
                         fixture.alice,
                         {}})
                        .response.status == 200U);

            THEN("bob sees the public m.read receipt but not the private one")
            {
                auto const bob_view = sync_receipts(started.runtime, fixture.bob, fixture.room_id, "m.read");
                REQUIRE(bob_view.users_with_type == std::vector<std::string>{"@alice:example.org"});
                REQUIRE(bob_view.receipt_types == std::vector<std::string>{"m.read"});
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Section: Receipts / Fully read markers
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#fully-read-markers
//
// "`m.fully_read` does not appear under `m.receipt`: this endpoint effectively calls
// `/read_markers` internally when presented with a receipt type of `m.fully_read`." The
// marker is "kept as an event in the room's account data" and, on update, "the server MUST
// send the updated account data event through to the client via the event stream".
SCENARIO("m.fully_read is delivered as room account data and never under m.receipt",
         "[conformance][client-server][receipt][read-markers][csaz-4]")
{
    GIVEN("alice and bob in a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const fixture = make_shared_room(started.runtime);

        WHEN("alice sends an m.fully_read receipt")
        {
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        started.runtime,
                        {"POST",
                         "/_matrix/client/v3/rooms/" + fixture.room_id + "/receipt/m.fully_read/" + fixture.event_id,
                         fixture.alice,
                         {}})
                        .response.status == 200U);

            THEN("m.fully_read appears under m.receipt for neither user")
            {
                auto const alice_view = sync_receipts(started.runtime, fixture.alice, fixture.room_id, "m.fully_read");
                auto const bob_view = sync_receipts(started.runtime, fixture.bob, fixture.room_id, "m.fully_read");
                REQUIRE(alice_view.users_with_type.empty());
                REQUIRE(bob_view.users_with_type.empty());
                REQUIRE(alice_view.receipt_types.empty());
                REQUIRE(bob_view.receipt_types.empty());
            }

            THEN("alice receives m.fully_read as room account data and bob does not")
            {
                REQUIRE(room_account_data_event_id(started.runtime, fixture.alice, fixture.room_id, "m.fully_read") ==
                        fixture.event_id);
                REQUIRE(
                    room_account_data_event_id(started.runtime, fixture.bob, fixture.room_id, "m.fully_read").empty());
            }
        }

        WHEN("alice sets m.fully_read, m.read and m.read.private through /read_markers")
        {
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        started.runtime,
                        {"POST", "/_matrix/client/v3/rooms/" + fixture.room_id + "/read_markers", fixture.alice,
                         R"({"m.fully_read":")" + fixture.event_id + R"(","m.read":")" + fixture.event_id +
                             R"(","m.read.private":")" + fixture.event_id + R"("})"})
                        .response.status == 200U);

            THEN("alice has the fully-read marker as account data")
            {
                REQUIRE(room_account_data_event_id(started.runtime, fixture.alice, fixture.room_id, "m.fully_read") ==
                        fixture.event_id);
            }

            THEN("bob sees only alice's public m.read receipt")
            {
                auto const bob_view = sync_receipts(started.runtime, fixture.bob, fixture.room_id, "m.read");
                REQUIRE(bob_view.receipt_types == std::vector<std::string>{"m.read"});
                REQUIRE(bob_view.users_with_type == std::vector<std::string>{"@alice:example.org"});
            }

            THEN("alice sees her m.read and m.read.private receipts but no m.fully_read receipt")
            {
                auto const alice_view = sync_receipts(started.runtime, fixture.alice, fixture.room_id, "m.read");
                REQUIRE(std::ranges::find(alice_view.receipt_types, "m.read") != alice_view.receipt_types.end());
                REQUIRE(std::ranges::find(alice_view.receipt_types, "m.read.private") !=
                        alice_view.receipt_types.end());
                REQUIRE(std::ranges::find(alice_view.receipt_types, "m.fully_read") == alice_view.receipt_types.end());
            }
        }
    }
}

namespace
{

// A room where bob has posted a thread root, a reply in that thread, and then a later message
// in the main timeline, in that order.
struct ThreadedRoom final
{
    std::string alice{};
    std::string bob{};
    std::string room_id{};
    std::string root_id{};
    std::string thread_reply_id{};
    std::string latest_main_id{};
};

[[nodiscard]] auto send_as(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                           std::string const& room_id, std::string const& txn_id, std::string const& body)
    -> std::string
{
    auto const send = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn_id, token, body});
    REQUIRE(send.response.status == 200U);
    return event_id_from_send(send.response.body);
}

[[nodiscard]] auto make_threaded_room(merovingian::homeserver::ClientServerRuntime& runtime) -> ThreadedRoom
{
    auto fixture = ThreadedRoom{};
    fixture.alice = logged_in_token(runtime, "alice");
    fixture.bob = logged_in_token(runtime, "bob");
    auto const create = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", fixture.alice, R"({"preset":"public_chat"})"});
    REQUIRE(create.response.status == 200U);
    fixture.room_id = room_id_from_create(create.response.body);
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + fixture.room_id + "/join", fixture.bob, "{}"})
                .response.status == 200U);
    fixture.root_id =
        send_as(runtime, fixture.bob, fixture.room_id, "txn_root", R"({"msgtype":"m.text","body":"root"})");
    fixture.thread_reply_id =
        send_as(runtime, fixture.bob, fixture.room_id, "txn_thread",
                R"({"msgtype":"m.text","body":"in thread","m.relates_to":{"rel_type":"m.thread","event_id":")" +
                    fixture.root_id + R"("}})");
    fixture.latest_main_id =
        send_as(runtime, fixture.bob, fixture.room_id, "txn_latest", R"({"msgtype":"m.text","body":"latest"})");
    return fixture;
}

[[nodiscard]] auto post_receipt(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                std::string const& room_id, std::string const& receipt_type,
                                std::string const& event_id, std::string const& body) -> std::uint16_t
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/receipt/" + receipt_type + "/" + event_id,
                         token, body})
        .response.status;
}

// unread_notifications.notification_count for the room in an initial /sync.
[[nodiscard]] auto notification_count(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                      std::string const& room_id) -> std::int64_t
{
    auto const sync =
        merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/sync", token, {}});
    REQUIRE(sync.response.status == 200U);
    auto const body = parse_object(sync.response.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    REQUIRE(rooms != nullptr);
    auto const* join = object_member_as_object(*rooms, "join");
    REQUIRE(join != nullptr);
    auto const* room = object_member_as_object(*join, room_id);
    REQUIRE(room != nullptr);
    auto const* unread = object_member_as_object(*room, "unread_notifications");
    REQUIRE(unread != nullptr);
    auto const* count = int_member(*unread, "notification_count");
    REQUIRE(count != nullptr);
    return *count;
}

// The thread_id alice's m.read receipt on `event_id` carries in her /sync: "<absent>" when the
// receipt carries none, "<missing>" when there is no such receipt.
[[nodiscard]] auto receipt_thread_id(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                     std::string const& room_id, std::string const& event_id) -> std::string
{
    auto const events = first_room_ephemeral_events(runtime, token, room_id);
    auto const* content = find_receipt_for_event(events, event_id);
    if (content == nullptr)
        return "<missing>";
    auto const* by_type = object_member_as_object(*content, event_id);
    auto const* users = by_type == nullptr ? nullptr : object_member_as_object(*by_type, "m.read");
    auto const* receipt = users == nullptr ? nullptr : object_member_as_object(*users, "@alice:example.org");
    if (receipt == nullptr)
        return "<missing>";
    auto const* thread_id = string_member(*receipt, "thread_id");
    return thread_id == nullptr ? std::string{"<absent>"} : *thread_id;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId} —
//                     Threaded read receipts
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#threaded-read-receipts
//
// A thread_id is "main" or a thread root's event ID; an invalid thread_id is rejected with 400.
SCENARIO("POST /receipt rejects an invalid thread_id with M_INVALID_PARAM",
         "[conformance][client-server][receipt][threaded-receipts]")
{
    GIVEN("alice in a room with a message to acknowledge")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture requirement: the runtime starts before endpoint requests are made.
        REQUIRE(started.started);
        auto const fixture = make_threaded_room(started.runtime);

        // A thread_id is "The thread root's event ID (or main)": one naming no event in the room
        // is not a thread root. Refusing it also stops a client minting a receipt row per
        // invented thread.
        WHEN("the thread_id is empty, not a string, sent with m.fully_read, or names no event in the room")
        {
            auto const bodies = std::vector<std::pair<std::string, std::string>>{
                {"m.read",         R"({"thread_id":""})"                    },
                {"m.read",         R"({"thread_id":7})"                     },
                {"m.fully_read",   R"({"thread_id":"main"})"                },
                {"m.read",         R"({"thread_id":"not-a-thread"})"        },
                {"m.read.private", R"({"thread_id":"$missing:example.org"})"},
            };
            THEN("each request is refused with 400 M_INVALID_PARAM")
            {
                for (auto const& [receipt_type, body] : bodies)
                {
                    auto const response = merovingian::homeserver::handle_client_server_request(
                        started.runtime, {"POST",
                                          "/_matrix/client/v3/rooms/" + fixture.room_id + "/receipt/" + receipt_type +
                                              "/" + fixture.latest_main_id,
                                          fixture.alice, body});
                    // Spec: malformed or incompatible thread_id values produce HTTP 400.
                    REQUIRE(response.response.status == 400U);
                    auto const error = parse_object(response.response.body);
                    auto const* errcode = string_member(error, "errcode");
                    // Fixture check: this endpoint maps the specified 400 response to M_INVALID_PARAM.
                    REQUIRE(errcode != nullptr);
                    // Fixture check: this endpoint maps the specified 400 response to M_INVALID_PARAM.
                    REQUIRE(*errcode == "M_INVALID_PARAM");
                }
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint: POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3roomsroomidreceiptreceipttypeeventid
// Spec: thread_id names a thread root (or "main"); an event directly in a thread is not its root.
// Spec: thread roots and events related to a root by non-thread relations are in the main timeline.
SCENARIO("POST /receipt accepts only thread roots as thread_id and accepts main-timeline events",
         "[conformance][client-server][receipt][threaded-receipts]")
{
    GIVEN("a room with a thread root, a reply, and a non-thread relation to the root")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture requirement: the runtime starts before endpoint requests are made.
        REQUIRE(started.started);
        auto const fixture = make_threaded_room(started.runtime);
        auto const referenced_main_id =
            send_as(started.runtime, fixture.bob, fixture.room_id, "txn_reference",
                    R"({"msgtype":"m.text","body":"reference","m.relates_to":{"rel_type":"m.reference","event_id":")" +
                        fixture.root_id + R"("}})");
        auto const referenced_thread_reply_id = send_as(
            started.runtime, fixture.bob, fixture.room_id, "txn_reference_thread",
            R"({"msgtype":"m.text","body":"reply to reference","m.relates_to":{"rel_type":"m.thread","event_id":")" +
                referenced_main_id + R"("}})");

        WHEN("alice names a direct thread reply as the receipt's thread root")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + fixture.room_id + "/receipt/m.read/" + fixture.thread_reply_id,
                 fixture.alice, R"({"thread_id":")" + fixture.thread_reply_id + R"("})"});
            THEN("the server rejects it and stores no receipt for that reply")
            {
                // Spec MUST: return 400 when thread_id is invalid.
                REQUIRE(response.response.status == 400U);
                auto const error = parse_object(response.response.body);
                auto const* errcode = string_member(error, "errcode");
                // Fixture check: the local endpoint maps this invalid parameter to its M_INVALID_PARAM error.
                REQUIRE(errcode != nullptr);
                // Fixture check: the local endpoint maps this invalid parameter to its M_INVALID_PARAM error.
                REQUIRE(*errcode == "M_INVALID_PARAM");
                // Fixture invariant: a refused receipt request does not create a stored receipt.
                REQUIRE(receipt_thread_id(started.runtime, fixture.alice, fixture.room_id, fixture.thread_reply_id) ==
                        "<missing>");
            }
        }

        WHEN("alice acknowledges the main timeline and replies using their actual thread roots")
        {
            THEN("main and both actual thread roots are accepted")
            {
                // Spec: "main" identifies the main timeline for a threaded receipt.
                REQUIRE(post_receipt(started.runtime, fixture.alice, fixture.room_id, "m.read", fixture.latest_main_id,
                                     R"({"thread_id":"main"})") == 200U);
                // Spec: this event's relation targets the actual root and therefore its receipt uses that thread ID.
                REQUIRE(post_receipt(started.runtime, fixture.alice, fixture.room_id, "m.read", fixture.thread_reply_id,
                                     R"({"thread_id":")" + fixture.root_id + R"("})") == 200U);
                // The m.reference event stays in the main timeline and can root its own m.thread reply.
                REQUIRE(post_receipt(started.runtime, fixture.alice, fixture.room_id, "m.read",
                                     referenced_thread_reply_id,
                                     R"({"thread_id":")" + referenced_main_id + R"("})") == 200U);
                // Spec: the receipt data includes the requested thread_id categorization.
                REQUIRE(receipt_thread_id(started.runtime, fixture.alice, fixture.room_id, fixture.latest_main_id) ==
                        "main");
                // Spec: a receipt for a thread reply carries the root ID as thread_id.
                REQUIRE(receipt_thread_id(started.runtime, fixture.alice, fixture.room_id, fixture.thread_reply_id) ==
                        fixture.root_id);
                // Spec: a receipt for a thread reply carries the root ID as thread_id.
                REQUIRE(receipt_thread_id(started.runtime, fixture.alice, fixture.room_id,
                                          referenced_thread_reply_id) == referenced_main_id);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, Receipts
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#receipts
//
// "Each user_id, receipt_type, and categorisation (unthreaded, or thread_id) tuple must be
// associated with only a single event_id." A threaded receipt is a separate marker: it must not
// replace the user's main-timeline or unthreaded receipt, and /sync carries its thread_id.
SCENARIO("a threaded receipt is kept apart from the user's other receipts and carries its thread_id",
         "[conformance][client-server][receipt][threaded-receipts]")
{
    GIVEN("bob's thread root, a reply in that thread, and a later main-timeline message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture requirement: the runtime starts before these endpoint scenarios execute.
        REQUIRE(started.started);
        auto const fixture = make_threaded_room(started.runtime);

        WHEN("alice reads the main timeline to the latest message, then reads the thread")
        {
            // Spec: HTTP 200 means the requested receipt was sent.
            REQUIRE(post_receipt(started.runtime, fixture.alice, fixture.room_id, "m.read", fixture.latest_main_id,
                                 R"({"thread_id":"main"})") == 200U);
            // Spec: HTTP 200 means the requested receipt was sent.
            REQUIRE(post_receipt(started.runtime, fixture.alice, fixture.room_id, "m.read", fixture.thread_reply_id,
                                 R"({"thread_id":")" + fixture.root_id + R"("})") == 200U);

            THEN("both receipts are delivered, each with its own thread_id")
            {
                // Spec: sync receipt content includes the thread_id categorization.
                REQUIRE(receipt_thread_id(started.runtime, fixture.alice, fixture.room_id, fixture.latest_main_id) ==
                        "main");
                // Spec: sync receipt content includes the thread_id categorization.
                REQUIRE(receipt_thread_id(started.runtime, fixture.alice, fixture.room_id, fixture.thread_reply_id) ==
                        fixture.root_id);
            }
            THEN("alice has no unread notifications left in the room")
            {
                // Spec MUST: notifications at and before the user's read position are marked read.
                REQUIRE(notification_count(started.runtime, fixture.alice, fixture.room_id) == 0);
            }
        }

        WHEN("alice sends an unthreaded receipt for the latest message")
        {
            // Spec: an absent thread_id represents an unthreaded receipt.
            REQUIRE(post_receipt(started.runtime, fixture.alice, fixture.room_id, "m.read", fixture.latest_main_id,
                                 {}) == 200U);

            THEN("the receipt carries no thread_id")
            {
                // Spec: an unthreaded receipt has no thread_id categorization in sync.
                REQUIRE(receipt_thread_id(started.runtime, fixture.alice, fixture.room_id, fixture.latest_main_id) ==
                        "<absent>");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, Push Notifications — "Marking notifications as read"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#receiving-notifications
//
// "When the user updates their read receipt ... notifications prior to and including that event
// MUST be marked as read. Which specific events are affected can vary depending on whether a
// threaded read receipt was used." With threaded receipts "the server is to partition the
// notification count to each thread (with the main timeline being its own thread)", and "an
// unthreaded read receipt on D would mark A, B, C, and D as read".
SCENARIO("a read receipt clears the notifications of the events it covers and no others",
         "[conformance][client-server][receipt][threaded-receipts][notifications]")
{
    GIVEN("bob's thread root, a reply in that thread, and a later main-timeline message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture requirement: the runtime starts before these endpoint scenarios execute.
        REQUIRE(started.started);
        auto const fixture = make_threaded_room(started.runtime);
        // Fixture state: one main root, one thread reply, and one later main message are unread.
        // Fixture state: all three incoming messages are unread before Alice sends a receipt.
        REQUIRE(notification_count(started.runtime, fixture.alice, fixture.room_id) == 3);

        WHEN("alice sends an unthreaded receipt for the latest message")
        {
            // Spec: HTTP 200 means the requested receipt was sent.
            REQUIRE(post_receipt(started.runtime, fixture.alice, fixture.room_id, "m.read", fixture.latest_main_id,
                                 {}) == 200U);
            THEN("every earlier event, in the thread or not, is read")
            {
                // Spec MUST: an unthreaded receipt marks preceding notifications across the room as read.
                REQUIRE(notification_count(started.runtime, fixture.alice, fixture.room_id) == 0);
            }
        }

        WHEN("alice sends a main-timeline receipt for the latest message")
        {
            // Spec: HTTP 200 means the requested receipt was sent.
            REQUIRE(post_receipt(started.runtime, fixture.alice, fixture.room_id, "m.read", fixture.latest_main_id,
                                 R"({"thread_id":"main"})") == 200U);
            THEN("the main timeline is read but the reply in the thread is still unread")
            {
                // Spec: threaded receipts partition notification counts by timeline.
                REQUIRE(notification_count(started.runtime, fixture.alice, fixture.room_id) == 1);
            }
        }

        WHEN("alice sends only a receipt in the thread")
        {
            // Spec: HTTP 200 means the requested receipt was sent.
            REQUIRE(post_receipt(started.runtime, fixture.alice, fixture.room_id, "m.read.private",
                                 fixture.thread_reply_id, R"({"thread_id":")" + fixture.root_id + R"("})") == 200U);
            THEN("the thread is read but both main-timeline messages are still unread")
            {
                // Spec: threaded receipts partition notification counts by timeline.
                REQUIRE(notification_count(started.runtime, fixture.alice, fixture.room_id) == 2);
            }
        }

        WHEN("alice reads the main timeline and then sends a thread receipt for an earlier event")
        {
            // Spec: HTTP 200 means the requested receipt was sent.
            REQUIRE(post_receipt(started.runtime, fixture.alice, fixture.room_id, "m.read", fixture.latest_main_id,
                                 R"({"thread_id":"main"})") == 200U);
            // Spec: HTTP 200 means the requested receipt was sent.
            REQUIRE(post_receipt(started.runtime, fixture.alice, fixture.room_id, "m.read", fixture.thread_reply_id,
                                 R"({"thread_id":")" + fixture.root_id + R"("})") == 200U);
            THEN("the thread receipt does not move the main-timeline read position back")
            {
                // Spec: each thread's receipt and notification position is separate.
                REQUIRE(notification_count(started.runtime, fixture.alice, fixture.room_id) == 0);
            }
        }
    }
}

namespace
{

// The room's entry in rooms.join of an initial /sync with an inline `filter`.
[[nodiscard]] auto synced_room_with_filter(merovingian::homeserver::ClientServerRuntime& runtime,
                                           std::string const& token, std::string const& room_id,
                                           std::string const& filter) -> merovingian::canonicaljson::Object
{
    auto const target = filter.empty() ? std::string{"/_matrix/client/v3/sync"}
                                       : std::string{"/_matrix/client/v3/sync?filter="} + filter;
    auto const sync = merovingian::homeserver::handle_client_server_request(runtime, {"GET", target, token, {}});
    REQUIRE(sync.response.status == 200U);
    auto const body = parse_object(sync.response.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    REQUIRE(rooms != nullptr);
    auto const* join = object_member_as_object(*rooms, "join");
    REQUIRE(join != nullptr);
    auto const* room = object_member_as_object(*join, room_id);
    REQUIRE(room != nullptr);
    return *room;
}

[[nodiscard]] auto count_in(merovingian::canonicaljson::Object const& counts, std::string_view key) -> std::int64_t
{
    auto const* count = int_member(counts, key);
    REQUIRE(count != nullptr);
    return *count;
}

constexpr auto thread_counts_filter = std::string_view{R"({"room":{"timeline":{"unread_thread_notifications":true}}})"};

} // namespace

// Spec: Matrix Client-Server API v1.19, GET /sync and Filtering
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// RoomEventFilter `unread_thread_notifications`: "If true, enables per-thread notification
// counts. Only applies to the /sync endpoint." Joined room `unread_notifications`: "If
// unread_thread_notifications was specified as true on the RoomEventFilter, these counts will only
// be for the main timeline rather than all events in the room." `unread_thread_notifications`:
// "the notification counts for each thread in this room. The object is keyed by thread root ID ...
// If a thread does not have any notifications it can be omitted from this object. If no threads
// have notification counts, this whole object can be omitted."
SCENARIO("/sync splits unread counts by thread when the filter asks for it",
         "[conformance][client-server][receipt][threaded-receipts][thread-notifications]")
{
    GIVEN("bob's thread root, a reply in that thread, and a later main-timeline message")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture requirement: the runtime starts before these sync scenarios execute.
        REQUIRE(started.started);
        auto const fixture = make_threaded_room(started.runtime);

        WHEN("alice syncs without unread_thread_notifications")
        {
            auto const room = synced_room_with_filter(started.runtime, fixture.alice, fixture.room_id, {});

            THEN("the room's counts cover every event, in a thread or not, and no per-thread counts are sent")
            {
                auto const* unread = object_member_as_object(room, "unread_notifications");
                // Spec: joined-room unread_notifications is present for the returned room.
                REQUIRE(unread != nullptr);
                // Spec: without the per-thread filter, the count covers all unread room events.
                REQUIRE(count_in(*unread, "notification_count") == 3);
                // Spec: unread_thread_notifications applies only when the filter requests it.
                REQUIRE(object_member_as_object(room, "unread_thread_notifications") == nullptr);
            }
        }

        WHEN("alice syncs with unread_thread_notifications")
        {
            auto const room = synced_room_with_filter(started.runtime, fixture.alice, fixture.room_id,
                                                      std::string{thread_counts_filter});

            THEN("unread_notifications counts only the main timeline")
            {
                auto const* unread = object_member_as_object(room, "unread_notifications");
                // Spec: with unread_thread_notifications enabled, unread_notifications counts the main timeline.
                REQUIRE(unread != nullptr);
                // Spec: the main timeline contains two unread events in this fixture.
                REQUIRE(count_in(*unread, "notification_count") == 2);
                // Fixture behavior: neither main-timeline event is a highlight.
                REQUIRE(count_in(*unread, "highlight_count") == 0);
            }
            THEN("unread_thread_notifications counts the thread under its root's event ID")
            {
                auto const* threads = object_member_as_object(room, "unread_thread_notifications");
                // Spec: this field carries per-thread notification counts when requested.
                REQUIRE(threads != nullptr);
                // Spec: the only thread with unread notifications is represented by one entry.
                REQUIRE(threads->size() == 1U);
                auto const* thread = object_member_as_object(*threads, fixture.root_id);
                // Spec: the per-thread object is keyed by the thread root event ID.
                REQUIRE(thread != nullptr);
                // Spec: the thread contains one unread reply in this fixture.
                REQUIRE(count_in(*thread, "notification_count") == 1);
                // Fixture behavior: the unread thread reply is not a highlight.
                REQUIRE(count_in(*thread, "highlight_count") == 0);
            }
        }

        WHEN("alice reads the thread and then syncs with unread_thread_notifications")
        {
            // Spec: HTTP 200 means the requested receipt was sent.
            REQUIRE(post_receipt(started.runtime, fixture.alice, fixture.room_id, "m.read", fixture.thread_reply_id,
                                 R"({"thread_id":")" + fixture.root_id + R"("})") == 200U);
            auto const room = synced_room_with_filter(started.runtime, fixture.alice, fixture.room_id,
                                                      std::string{thread_counts_filter});

            THEN("the thread, having no notifications, is not listed and the main timeline is unchanged")
            {
                // Spec permits omitting unread_thread_notifications when no threads have notification counts.
                REQUIRE(object_member_as_object(room, "unread_thread_notifications") == nullptr);
                auto const* unread = object_member_as_object(room, "unread_notifications");
                // Spec: joined-room unread_notifications remains present.
                REQUIRE(unread != nullptr);
                // Spec: marking the thread read leaves the two main-timeline notifications unread.
                REQUIRE(count_in(*unread, "notification_count") == 2);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, Push Notifications — "Marking notifications as read"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#receiving-notifications
//
// "When the user updates their read receipt (either by using the API or by sending an event),
// notifications prior to and including that event MUST be marked as read. Which specific events
// are affected can vary depending on whether a threaded read receipt was used." An event the user
// sends is in one thread (the main timeline or a thread), so it marks that thread read (ADR-0170).
SCENARIO("an event the user sends marks the events before it in its thread as read",
         "[conformance][client-server][receipt][threaded-receipts][own-event-read]")
{
    GIVEN("bob's thread root, a reply in that thread, and a later main-timeline message, none read by alice")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        // Fixture requirement: the runtime starts before these message scenarios execute.
        REQUIRE(started.started);
        auto const fixture = make_threaded_room(started.runtime);
        // Fixture state: the three incoming messages are unread before alice sends anything.
        REQUIRE(notification_count(started.runtime, fixture.alice, fixture.room_id) == 3);

        WHEN("alice sends a message in the main timeline")
        {
            std::ignore = send_as(started.runtime, fixture.alice, fixture.room_id, "txn_alice_main",
                                  R"({"msgtype":"m.text","body":"hi"})");

            THEN("the main timeline before it is read, and the reply in the thread is not")
            {
                // Spec MUST: notifications preceding an event sent by the user in that thread are marked read.
                REQUIRE(notification_count(started.runtime, fixture.alice, fixture.room_id) == 1);
            }
        }

        WHEN("alice replies in the thread")
        {
            std::ignore =
                send_as(started.runtime, fixture.alice, fixture.room_id, "txn_alice_thread",
                        R"({"msgtype":"m.text","body":"me too","m.relates_to":{"rel_type":"m.thread","event_id":")" +
                            fixture.root_id + R"("}})");

            THEN("the thread is read and both main-timeline messages are not")
            {
                // Spec MUST: notifications preceding an event sent by the user in that thread are marked read.
                REQUIRE(notification_count(started.runtime, fixture.alice, fixture.room_id) == 2);
            }
        }

        WHEN("alice changes her display name, which the server sends to the room as her membership")
        {
            auto const put = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"PUT", "/_matrix/client/v3/profile/@alice:example.org/displayname", fixture.alice,
                                  R"({"displayname":"Alice Liddell"})"});
            // Fixture check: update succeeds before unread state is inspected.
            REQUIRE(put.response.status == 200U);

            THEN("nothing is marked read: a state event the server sends for her is not her reading the room")
            {
                // Fixture behavior: a server-sent profile membership event does not advance Alice's read marker.
                REQUIRE(notification_count(started.runtime, fixture.alice, fixture.room_id) == 3);
            }
        }
    }
}
