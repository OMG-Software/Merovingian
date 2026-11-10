// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ClientEvent `unsigned`: `transaction_id` for the device that sent an event and `membership`
// for the user the event is served to. Complement TestTxnInEvent, TestTxnScopeOnLocalEcho,
// TestTxnIdWithRefreshToken and TestMembershipOnEvents read them.
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

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
    GIVEN("alice on a device that logs in again after sending, a second device, and bob, all in one room")
    {
        auto started = merovingian::homeserver::start_client_server(unsigned_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        std::ignore = register_user(rt, "alice");
        std::ignore = register_user(rt, "bob");
        auto const sender = login_device(rt, "alice", "DEVA");
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
            // POST /login `device_id`: a login on a known device invalidates its earlier access tokens, so the sender
            // reads first and the new token reads after it.
            auto const same_device = login_device(rt, "alice", "DEVA");
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
            // As above: the earlier token stops working at the second login.
            auto const same_device = login_device(rt, "alice", "DEVA");
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
// Endpoint / Section: ClientEvent `unsigned.transaction_id` and `unsigned.membership`
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

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: ClientEvent `unsigned.membership`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `membership`: "The room membership of the user making the request, at the time of the event.
// This property is the value of the membership property of the requesting user's m.room.member
// state at the point of the event, including any changes caused by the event. If the user had
// yet to join the room at the time of the event (i.e, they have no m.room.member state), this
// property is set to leave." Homeservers SHOULD populate it wherever practical.
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

namespace
{

// What a hostile relay writes into a PDU's `unsigned`: every key this server serves as its own.
constexpr auto forged_unsigned_text =
    R"({"age":5,"forged_extra":"x","m.relations":{"m.replace":{"content":{"body":"* forged"},"event_id":"$fake","sender":"@alice:localhost","type":"m.room.message"}},"membership":"ban","prev_content":{"topic":"forged previous"},"redacted_because":{"content":{},"sender":"@mallory:localhost","type":"m.room.redaction"},"transaction_id":"forged-txn"})";

// Puts the forged `unsigned` into the stored copy of `event_id`, as ingesting a remote PDU used to.
auto forge_stored_unsigned(ClientServerRuntime& rt, std::string const& event_id) -> void
{
    auto& store = rt.homeserver.database.persistent_store;
    auto const stored = store.events.find(event_id);
    REQUIRE(stored != store.events.end());
    REQUIRE(stored->json.front() == '{');
    REQUIRE(stored->json.find("\"unsigned\"") == std::string::npos);
    auto forged = std::string{"{\"unsigned\":"} + forged_unsigned_text + "," + stored->json.substr(1U);
    REQUIRE(merovingian::database::replace_event_json(store, event_id, std::move(forged)));
}

[[nodiscard]] auto has_key(merovingian::canonicaljson::Object const& object, std::string_view key) -> bool
{
    return std::ranges::any_of(object, [key](auto const& member) {
        return member.key == key;
    });
}

// The event `event_id` in `events`.
[[nodiscard]] auto event_in(merovingian::canonicaljson::Array const* events, std::string const& event_id)
    -> std::optional<merovingian::canonicaljson::Object>
{
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

// Everything a client is given in `unsigned` is something this server computed: none of the forged
// keys is served, and a key the server does compute for the viewer (membership, transaction_id,
// prev_content) is its own value, never the forged one.
auto require_only_server_computed(merovingian::canonicaljson::Object const& event,
                                  std::optional<std::string> const& own_txn) -> void
{
    auto const* unsigned_data = object_member_as_object(event, "unsigned");
    if (unsigned_data == nullptr)
    {
        return;
    }
    for (auto const* key : {"age", "forged_extra", "m.relations", "redacted_because"})
    {
        // Spec: the server serving the event is the one that generates these.
        REQUIRE_FALSE(has_key(*unsigned_data, key));
    }
    if (auto const* membership = string_member(*unsigned_data, "membership"); membership != nullptr)
    {
        REQUIRE(*membership == "join");
    }
    if (auto const* txn = string_member(*unsigned_data, "transaction_id"); txn != nullptr)
    {
        REQUIRE(own_txn.has_value());
        REQUIRE(*txn == *own_txn);
    }
    if (auto const* previous = object_member_as_object(*unsigned_data, "prev_content"); previous != nullptr)
    {
        auto const* topic = string_member(*previous, "topic");
        REQUIRE(topic != nullptr);
        REQUIRE(*topic == "one");
    }
}

[[nodiscard]] auto sliding_sync_room(ClientServerRuntime& rt, std::string const& token, std::string const& room_id)
    -> merovingian::canonicaljson::Object
{
    auto const reply = call(
        rt, "POST", "/_matrix/client/unstable/org.matrix.msc4186/sync?timeout=0", token,
        R"({"conn_id":"unsigned","lists":{"0":{"ranges":[[0,19]],"required_state":[["m.room.topic",""]],"timeline_limit":50}}})");
    REQUIRE(reply.status == 200U);
    auto const body = parse_object(reply.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    REQUIRE(rooms != nullptr);
    auto const* room = object_member_as_object(*rooms, room_id);
    REQUIRE(room != nullptr);
    return *room;
}

constexpr auto sync_with_long_timeline =
    "/_matrix/client/v3/sync?filter=%7B%22room%22%3A%7B%22timeline%22%3A%7B%22limit%22%3A50%7D%7D%7D";

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: ClientEvent `unsigned` (`age`, `membership`, `prev_content`, `redacted_because`,
// `transaction_id`, `m.relations`), "Server-side aggregation of m.replace relationships", "Redactions"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `unsigned` is covered by no signature, so the server that stored an event may not present a copy
// written by another server as its own: `m.relations.m.replace` is the server's assertion that a
// replacement is valid, `redacted_because` "the event that redacted this event". A client is given
// `unsigned` built from what this server computed, on every read path, for a message and for a
// state event that replaced another.
SCENARIO("A client is never served an unsigned object a remote server wrote, on any read path",
         "[conformance][client-server][event-format][unsigned][unsigned-forged][unsigned-served]")
{
    GIVEN("a message, and a topic that replaced an earlier one, whose stored copies carry a forged unsigned")
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
        auto const message =
            event_id_of(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/t1", alice,
                             R"({"msgtype":"m.text","body":"hello"})"));
        auto const first_topic = event_id_of(call(
            rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.topic", alice, R"({"topic":"one"})"));
        auto const second_topic = event_id_of(call(
            rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.topic", alice, R"({"topic":"two"})"));
        forge_stored_unsigned(rt, message);
        forge_stored_unsigned(rt, second_topic);

        WHEN("bob reads them with GET /rooms/{roomId}/event/{eventId}")
        {
            auto const message_event = fetched_event(rt, bob, room_id, message);
            auto const topic_event = fetched_event(rt, bob, room_id, second_topic);

            THEN("neither carries a forged key, and the server's own values are there")
            {
                require_only_server_computed(message_event, std::nullopt);
                require_only_server_computed(topic_event, std::nullopt);
                // Spec MUST: membership is the requesting user's own, computed by the server.
                REQUIRE(unsigned_string(message_event, "membership") == std::optional<std::string>{"join"});
                // Spec: replaces_state is the ID of the state event this one replaced.
                REQUIRE(unsigned_string(topic_event, "replaces_state") == std::optional<std::string>{first_topic});
            }
        }

        WHEN("bob pages back with GET /rooms/{roomId}/messages")
        {
            auto const page = call(rt, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&limit=50", bob);
            REQUIRE(page.status == 200U);
            auto const body = parse_object(page.body);
            auto const message_event = event_in(object_member_as_array(body, "chunk"), message);
            auto const topic_event = event_in(object_member_as_array(body, "chunk"), second_topic);

            THEN("neither carries a forged key, and the topic names the event it replaced")
            {
                REQUIRE(message_event.has_value());
                REQUIRE(topic_event.has_value());
                require_only_server_computed(*message_event, std::nullopt);
                require_only_server_computed(*topic_event, std::nullopt);
                REQUIRE(unsigned_string(*topic_event, "replaces_state") == std::optional<std::string>{first_topic});
            }
        }

        WHEN("bob and alice read them from /sync")
        {
            auto const bob_sync = call(rt, "GET", sync_with_long_timeline, bob);
            auto const alice_sync = call(rt, "GET", sync_with_long_timeline, alice);
            REQUIRE(bob_sync.status == 200U);
            REQUIRE(alice_sync.status == 200U);
            auto const timeline_of = [&](Reply const& reply) {
                auto const body = parse_object(reply.body);
                auto const* rooms = object_member_as_object(body, "rooms");
                REQUIRE(rooms != nullptr);
                auto const* join = object_member_as_object(*rooms, "join");
                REQUIRE(join != nullptr);
                auto const* room = object_member_as_object(*join, room_id);
                REQUIRE(room != nullptr);
                auto const* timeline = object_member_as_object(*room, "timeline");
                REQUIRE(timeline != nullptr);
                return merovingian::canonicaljson::Array{*object_member_as_array(*timeline, "events")};
            };
            auto const bob_events = timeline_of(bob_sync);
            auto const alice_events = timeline_of(alice_sync);
            auto const bob_message = event_in(&bob_events, message);
            auto const bob_topic = event_in(&bob_events, second_topic);
            auto const alice_message = event_in(&alice_events, message);

            THEN("neither carries a forged key, and each reader is given only their own values")
            {
                REQUIRE(bob_message.has_value());
                REQUIRE(bob_topic.has_value());
                REQUIRE(alice_message.has_value());
                require_only_server_computed(*bob_message, std::nullopt);
                require_only_server_computed(*bob_topic, std::nullopt);
                require_only_server_computed(*alice_message, std::string{"t1"});
                REQUIRE(unsigned_string(*bob_message, "membership") == std::optional<std::string>{"join"});
                REQUIRE_FALSE(unsigned_string(*bob_message, "transaction_id").has_value());
                // Spec MUST: the sending device is given the transaction ID this server recorded.
                REQUIRE(unsigned_string(*alice_message, "transaction_id") == std::optional<std::string>{"t1"});
                REQUIRE(unsigned_string(*bob_topic, "replaces_state") == std::optional<std::string>{first_topic});
                // Spec: prev_content is the content of the state event replaced, computed by the server.
                auto const* previous =
                    object_member_as_object(*object_member_as_object(*bob_topic, "unsigned"), "prev_content");
                REQUIRE(previous != nullptr);
                REQUIRE(*string_member(*previous, "topic") == "one");
            }
        }

        WHEN("bob and alice read them from sliding sync")
        {
            auto const bob_room = sliding_sync_room(rt, bob, room_id);
            auto const alice_room = sliding_sync_room(rt, alice, room_id);
            auto const bob_message = event_in(object_member_as_array(bob_room, "timeline"), message);
            auto const bob_topic = event_in(object_member_as_array(bob_room, "timeline"), second_topic);
            auto const alice_message = event_in(object_member_as_array(alice_room, "timeline"), message);
            auto const required_topic = event_in(object_member_as_array(bob_room, "required_state"), second_topic);

            THEN("timeline and required_state carry no forged key and keep event_id")
            {
                REQUIRE(bob_message.has_value());
                REQUIRE(bob_topic.has_value());
                REQUIRE(alice_message.has_value());
                REQUIRE(required_topic.has_value());
                require_only_server_computed(*bob_message, std::nullopt);
                require_only_server_computed(*bob_topic, std::nullopt);
                require_only_server_computed(*required_topic, std::nullopt);
                require_only_server_computed(*alice_message, std::string{"t1"});
            }

            THEN("each reader is given their own membership and the sending device its transaction ID")
            {
                REQUIRE(bob_message.has_value());
                REQUIRE(alice_message.has_value());
                // Spec MUST: membership is the requesting user's at the event.
                REQUIRE(unsigned_string(*bob_message, "membership") == std::optional<std::string>{"join"});
                REQUIRE_FALSE(unsigned_string(*bob_message, "transaction_id").has_value());
                // Spec MUST: transaction_id only for the device that sent the event.
                REQUIRE(unsigned_string(*alice_message, "transaction_id") == std::optional<std::string>{"t1"});
            }
        }
    }
}
