// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ClientEvent `unsigned`: `transaction_id` for the device that sent an event and `membership`
// for the user the event is served to. Complement TestTxnInEvent, TestTxnScopeOnLocalEcho,
// TestTxnIdWithRefreshToken and TestMembershipOnEvents read them.
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto unsigned_config() -> merovingian::config::Config
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

struct Reply final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> Reply
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
    return {static_cast<std::uint16_t>(result.response.status), result.response.body};
}

[[nodiscard]] auto register_user(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    auto const registered =
        call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!"));
    REQUIRE(registered.status == 200U);
    return *string_member(parse_object(registered.body), "user_id");
}

// A fresh access token for `localpart` on the device `device_id`: a second login with the same
// device ID is the same device (client-server-api.md, "Transaction identifiers").
[[nodiscard]] auto login_device(ClientServerRuntime& rt, std::string const& localpart, std::string const& device_id)
    -> std::string
{
    auto const login = call(rt, "POST", "/_matrix/client/v3/login", {},
                            R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")" + localpart +
                                R"("},"password":"CorrectHorse7!","device_id":")" + device_id + R"("})");
    REQUIRE(login.status == 200U);
    return *string_member(parse_object(login.body), "access_token");
}

[[nodiscard]] auto event_id_of(Reply const& reply) -> std::string
{
    REQUIRE(reply.status == 200U);
    return *string_member(parse_object(reply.body), "event_id");
}

// The event `event_id` in the joined room's /sync timeline; nullopt when it is not there.
[[nodiscard]] auto synced_event(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                                std::string const& event_id) -> std::optional<merovingian::canonicaljson::Object>
{
    auto const synced = call(rt, "GET", "/_matrix/client/v3/sync", token);
    REQUIRE(synced.status == 200U);
    auto const body = parse_object(synced.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    REQUIRE(rooms != nullptr);
    auto const* join = object_member_as_object(*rooms, "join");
    REQUIRE(join != nullptr);
    auto const* room = object_member_as_object(*join, room_id);
    if (room == nullptr)
    {
        return std::nullopt;
    }
    auto const* timeline = object_member_as_object(*room, "timeline");
    REQUIRE(timeline != nullptr);
    auto const* events = object_member_as_array(*timeline, "events");
    REQUIRE(events != nullptr);
    for (auto const& entry : *events)
    {
        auto const& event = std::get<merovingian::canonicaljson::Object>(entry.storage());
        auto const* id = string_member(event, "event_id");
        if (id != nullptr && *id == event_id)
        {
            return event;
        }
    }
    return std::nullopt;
}

[[nodiscard]] auto fetched_event(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                                 std::string const& event_id) -> merovingian::canonicaljson::Object
{
    auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + event_id, token);
    REQUIRE(reply.status == 200U);
    return parse_object(reply.body);
}

[[nodiscard]] auto unsigned_string(merovingian::canonicaljson::Object const& event, std::string_view key)
    -> std::optional<std::string>
{
    auto const* unsigned_data = object_member_as_object(event, "unsigned");
    if (unsigned_data == nullptr)
    {
        return std::nullopt;
    }
    auto const* value = string_member(*unsigned_data, key);
    if (value == nullptr)
    {
        return std::nullopt;
    }
    return *value;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: ClientEvent `unsigned.transaction_id`, Transaction identifiers
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#transaction-identifiers
//
// `transaction_id`: "The client-supplied transaction ID, for example, provided via PUT
// /rooms/{roomId}/send/{eventType}/{txnId}, if the client being given the event is the same one
// which sent it." The scope of a transaction ID is a single device, and a login with an
// existing `device_id` is the same device, so a new access token for it is the same client.
SCENARIO("The device that sent an event is given its transaction ID, no other client is",
         "[conformance][client-server][event-format][unsigned]")
{
    GIVEN("alice's two sessions on one device, a third device, and bob, all in one room")
    {
        auto started = merovingian::homeserver::start_client_server(unsigned_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        std::ignore = register_user(rt, "alice");
        std::ignore = register_user(rt, "bob");
        auto const sender = login_device(rt, "alice", "DEVA");
        auto const same_device = login_device(rt, "alice", "DEVA");
        auto const other_device = login_device(rt, "alice", "DEVB");
        auto const bob = login_device(rt, "bob", "BOBDEV");
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", sender, R"({"preset":"public_chat"})");
        REQUIRE(created.status == 200U);
        auto const room_id = *string_member(parse_object(created.body), "room_id");
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room_id, bob, "{}").status == 200U);

        auto const event_id =
            event_id_of(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/abcdefg", sender,
                             R"({"msgtype":"m.text","body":"first"})"));

        WHEN("each client reads the event from /sync")
        {
            auto const own = synced_event(rt, sender, room_id, event_id);
            auto const same = synced_event(rt, same_device, room_id, event_id);
            auto const other = synced_event(rt, other_device, room_id, event_id);
            auto const peer = synced_event(rt, bob, room_id, event_id);

            THEN("only the sending device's sessions are given the transaction ID")
            {
                REQUIRE(own.has_value());
                REQUIRE(same.has_value());
                REQUIRE(other.has_value());
                REQUIRE(peer.has_value());
                // Spec MUST: the client that sent the event is given the transaction ID.
                REQUIRE(unsigned_string(*own, "transaction_id") == std::optional<std::string>{"abcdefg"});
                // Spec MUST: a transaction ID is scoped to a device, so a new token for the
                // same device is the same client.
                REQUIRE(unsigned_string(*same, "transaction_id") == std::optional<std::string>{"abcdefg"});
                // Spec MUST: only "the same one which sent it" is given it: another device is not.
                REQUIRE_FALSE(unsigned_string(*other, "transaction_id").has_value());
                REQUIRE_FALSE(unsigned_string(*peer, "transaction_id").has_value());
            }
        }

        WHEN("each client fetches the event with GET /rooms/{roomId}/event/{eventId}")
        {
            auto const own = fetched_event(rt, sender, room_id, event_id);
            auto const same = fetched_event(rt, same_device, room_id, event_id);
            auto const other = fetched_event(rt, other_device, room_id, event_id);
            auto const peer = fetched_event(rt, bob, room_id, event_id);

            THEN("only the sending device's sessions are given the transaction ID")
            {
                // Spec MUST: the client that sent the event is given the transaction ID.
                REQUIRE(unsigned_string(own, "transaction_id") == std::optional<std::string>{"abcdefg"});
                REQUIRE(unsigned_string(same, "transaction_id") == std::optional<std::string>{"abcdefg"});
                // Spec MUST: no other client is.
                REQUIRE_FALSE(unsigned_string(other, "transaction_id").has_value());
                REQUIRE_FALSE(unsigned_string(peer, "transaction_id").has_value());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: ClientEvent `unsigned.membership`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `membership`: "The room membership of the user making the request, at the time of the event.
// This property is the value of the membership property of the requesting user's m.room.member
// state at the point of the event, including any changes caused by the event. If the user had
// yet to join the room at the time of the event (i.e, they have no m.room.member state), this
// property is set to leave." Homeservers SHOULD populate it wherever practical.
// Spec: Matrix Client-Server API v1.19, ClientEvent `unsigned` (transaction_id, membership)
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// Both fields describe the client reading the event: `transaction_id` "if the client being given
// the event is the same one which sent it", `membership` "the room membership of the user making
// the request". `unsigned` is not covered by the event's signatures, so a PDU's sender can put
// anything there; this server must never pass the sender's copy of either field on to a client.
SCENARIO("A stored event's own unsigned.transaction_id and unsigned.membership never reach a client",
         "[conformance][client-server][event-format][unsigned][unsigned-forged]")
{
    GIVEN("a message whose stored copy carries a transaction_id and membership its sender chose")
    {
        auto started = merovingian::homeserver::start_client_server(unsigned_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        std::ignore = register_user(rt, "alice");
        std::ignore = register_user(rt, "bob");
        auto const alice = login_device(rt, "alice", "DEVA");
        auto const bob = login_device(rt, "bob", "BOBDEV");
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})");
        REQUIRE(created.status == 200U);
        auto const room_id = *string_member(parse_object(created.body), "room_id");
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room_id, bob, "{}").status == 200U);
        auto const event_id =
            event_id_of(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/f1", alice,
                             R"({"msgtype":"m.text","body":"hello"})"));

        auto& store = rt.homeserver.database.persistent_store;
        auto const stored = store.events.find(event_id);
        REQUIRE(stored != store.events.end());
        REQUIRE(stored->json.find("\"unsigned\"") == std::string::npos);
        REQUIRE(stored->json.front() == '{');
        auto forged = std::string{R"({"unsigned":{"age":5,"membership":"ban","transaction_id":"forged-txn"},)"} +
                      stored->json.substr(1U);
        REQUIRE(merovingian::database::replace_event_json(store, event_id, std::move(forged)));

        WHEN("bob, who did not send it, reads it from /sync and GET /rooms/{roomId}/event/{eventId}")
        {
            auto const synced = synced_event(rt, bob, room_id, event_id);
            auto const fetched = fetched_event(rt, bob, room_id, event_id);

            THEN("neither carries the stored transaction_id, and the membership is bob's own")
            {
                REQUIRE(synced.has_value());
                // Spec MUST: transaction_id only for "the same one which sent it".
                REQUIRE_FALSE(unsigned_string(*synced, "transaction_id").has_value());
                REQUIRE_FALSE(unsigned_string(fetched, "transaction_id").has_value());
                // Spec MUST: membership is "the room membership of the user making the request".
                REQUIRE(unsigned_string(*synced, "membership") == std::optional<std::string>{"join"});
                REQUIRE(unsigned_string(fetched, "membership") == std::optional<std::string>{"join"});
            }
        }

        WHEN("bob pages back over it with GET /rooms/{roomId}/messages")
        {
            auto const page = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&limit=20", bob);
            REQUIRE(page.status == 200U);
            auto const body = parse_object(page.body);
            auto const* chunk = object_member_as_array(body, "chunk");
            REQUIRE(chunk != nullptr);
            auto const found = std::ranges::find_if(*chunk, [&](merovingian::canonicaljson::Value const& entry) {
                auto const* id =
                    string_member(std::get<merovingian::canonicaljson::Object>(entry.storage()), "event_id");
                return id != nullptr && *id == event_id;
            });
            REQUIRE(found != chunk->end());
            auto const& event = std::get<merovingian::canonicaljson::Object>(found->storage());

            THEN("the sender's transaction_id and membership are not passed on")
            {
                // Spec MUST: transaction_id only for "the same one which sent it".
                REQUIRE_FALSE(unsigned_string(event, "transaction_id").has_value());
                // Spec MUST: membership is the requesting user's, never the sender's choice.
                REQUIRE(unsigned_string(event, "membership") != std::optional<std::string>{"ban"});
            }
        }
    }
}

SCENARIO("An event carries the requesting user's membership at the time of the event",
         "[conformance][client-server][event-format][unsigned]")
{
    GIVEN("a message sent before bob joined and another after, and bob's join between them")
    {
        auto started = merovingian::homeserver::start_client_server(unsigned_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        std::ignore = register_user(rt, "alice");
        std::ignore = register_user(rt, "bob");
        auto const alice = login_device(rt, "alice", "DEVA");
        auto const bob = login_device(rt, "bob", "BOBDEV");
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})");
        REQUIRE(created.status == 200U);
        auto const room_id = *string_member(parse_object(created.body), "room_id");
        auto const before =
            event_id_of(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/m1", alice,
                             R"({"msgtype":"m.text","body":"prejoin"})"));
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room_id, bob, "{}").status == 200U);
        auto const after =
            event_id_of(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/m2", alice,
                             R"({"msgtype":"m.text","body":"postjoin"})"));

        WHEN("bob reads both messages from /sync")
        {
            auto const early = synced_event(rt, bob, room_id, before);
            auto const late = synced_event(rt, bob, room_id, after);

            THEN("the message before his join says leave and the one after says join")
            {
                REQUIRE(early.has_value());
                REQUIRE(late.has_value());
                // Spec MUST: "If the user had yet to join the room at the time of the event ...
                // this property is set to leave."
                REQUIRE(unsigned_string(*early, "membership") == std::optional<std::string>{"leave"});
                // Spec MUST: the value of the user's membership "at the point of the event".
                REQUIRE(unsigned_string(*late, "membership") == std::optional<std::string>{"join"});
            }
        }

        WHEN("bob fetches both messages with GET /rooms/{roomId}/event/{eventId}")
        {
            auto const early = fetched_event(rt, bob, room_id, before);
            auto const late = fetched_event(rt, bob, room_id, after);

            THEN("the message before his join says leave and the one after says join")
            {
                REQUIRE(unsigned_string(early, "membership") == std::optional<std::string>{"leave"});
                REQUIRE(unsigned_string(late, "membership") == std::optional<std::string>{"join"});
            }
        }

        WHEN("alice, who created the room, reads the first message")
        {
            auto const own = fetched_event(rt, alice, room_id, before);

            THEN("it carries her own membership, join")
            {
                // Spec MUST: the membership is the requesting user's, not the sender's.
                REQUIRE(unsigned_string(own, "membership") == std::optional<std::string>{"join"});
            }
        }
    }
}
