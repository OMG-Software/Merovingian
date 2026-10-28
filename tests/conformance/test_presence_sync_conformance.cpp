// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |         MATRIX PRESENCE: READ, /sync AND set_presence CONFORMANCE        |
// |                                                                          |
// |  Spec: Matrix Client-Server API v1.19                                    |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                   |
// |                                                                          |
// |  Covers GET /_matrix/client/v3/presence/{userId}/status, the /sync       |
// |  `set_presence` parameter and the `presence` section of /sync.           |
// |  PUT is covered by test_presence_conformance.cpp.                        |
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;
using merovingian::homeserver::LocalHttpResponse;

[[nodiscard]] auto conformance_config() -> merovingian::config::Config
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

[[nodiscard]] auto call(ClientServerRuntime& runtime, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {std::move(method), std::move(target), token, std::move(body)})
        .response;
}

[[nodiscard]] auto logged_in_token(ClientServerRuntime& runtime, std::string_view localpart) -> std::string
{
    // Fixture: registration must succeed before the user can log in.
    REQUIRE(call(runtime, "POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json(localpart, "CorrectHorse7!"))
                .status == 200U);
    auto const login_body = std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} +
                            std::string{localpart} + R"(:example.org"},"password":"CorrectHorse7!","device_id":")" +
                            std::string{localpart} + R"(_DEV"})";
    auto const login = call(runtime, "POST", "/_matrix/client/v3/login", {}, login_body);
    // Fixture: login must succeed so later requests are authenticated.
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    // Fixture: the login response carries the access token.
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto status_path(std::string_view localpart) -> std::string
{
    return "/_matrix/client/v3/presence/%40" + std::string{localpart} + "%3Aexample.org/status";
}

auto put_presence(ClientServerRuntime& runtime, std::string const& token, std::string_view localpart, std::string body)
    -> void
{
    // Fixture: the presence update must be accepted before it is observed.
    REQUIRE(call(runtime, "PUT", status_path(localpart), token, std::move(body)).status == 200U);
}

[[nodiscard]] auto create_public_room(ClientServerRuntime& runtime, std::string const& token) -> std::string
{
    auto const created = call(runtime, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})");
    // Fixture: room creation must succeed.
    REQUIRE(created.status == 200U);
    auto const body = parse_object(created.body);
    auto const* room_id = string_member(body, "room_id");
    // Fixture: the creation response carries the room ID.
    REQUIRE(room_id != nullptr);
    return *room_id;
}

auto join(ClientServerRuntime& runtime, std::string const& token, std::string const& room_id) -> void
{
    // Fixture: the join must succeed.
    REQUIRE(call(runtime, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", token, "{}").status == 200U);
}

struct SyncedPresence final
{
    std::string next_batch{};
    // sender and content.presence of each m.presence event in the response.
    std::vector<std::pair<std::string, std::string>> events{};

    [[nodiscard]] auto presence_of(std::string_view sender) const -> std::optional<std::string>
    {
        for (auto const& [who, state] : events)
        {
            if (who == sender)
            {
                return state;
            }
        }
        return std::nullopt;
    }
};

[[nodiscard]] auto sync_presence(ClientServerRuntime& runtime, std::string const& token, std::string const& since = {},
                                 std::string const& extra_query = {}) -> SyncedPresence
{
    auto target = std::string{"/_matrix/client/v3/sync?timeout=0"};
    if (!since.empty())
    {
        target += "&since=" + since;
    }
    target += extra_query;
    auto const synced = call(runtime, "GET", target, token);
    // Fixture: the sync must succeed.
    REQUIRE(synced.status == 200U);
    auto const body = parse_object(synced.body);
    auto out = SyncedPresence{};
    auto const* next_batch = string_member(body, "next_batch");
    // Spec MUST: a /sync response carries next_batch.
    REQUIRE(next_batch != nullptr);
    out.next_batch = *next_batch;
    auto const* presence = object_member_as_object(body, "presence");
    auto const* events = presence == nullptr ? nullptr : object_member_as_array(*presence, "events");
    if (events == nullptr)
    {
        return out;
    }
    for (auto const& value : *events)
    {
        auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        // Spec MUST: each presence event is an object.
        REQUIRE(event != nullptr);
        auto const* type = string_member(*event, "type");
        auto const* sender = string_member(*event, "sender");
        auto const* content = object_member_as_object(*event, "content");
        // Spec MUST: an m.presence event has type, sender and content.
        REQUIRE(type != nullptr);
        REQUIRE(*type == "m.presence");
        REQUIRE(sender != nullptr);
        REQUIRE(content != nullptr);
        auto const* state = string_member(*content, "presence");
        // Spec MUST: content.presence is required.
        REQUIRE(state != nullptr);
        out.events.emplace_back(*sender, *state);
    }
    return out;
}

[[nodiscard]] auto status_of(ClientServerRuntime& runtime, std::string const& token, std::string_view localpart)
    -> LocalHttpResponse
{
    return call(runtime, "GET", status_path(localpart), token);
}

[[nodiscard]] auto presence_field(LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* state = string_member(body, "presence");
    return state == nullptr ? std::string{} : *state;
}

// A sync that must not mark its user online, so a test can read a peer's presence without
// changing its own.
constexpr auto quiet = std::string_view{"&set_presence=offline"};

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint: GET /_matrix/client/v3/presence/{userId}/status
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3presenceuseridstatus
//
// 200: "The presence state for this user." with `presence` required, one of online, offline,
// unavailable. A user can read their own presence before ever setting it.
SCENARIO("GET /presence/{userId}/status returns a user's own presence before they set one",
         "[conformance][client-server][presence]")
{
    GIVEN("a logged-in user who has never set a presence")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime, "alice");

        WHEN("the user reads their own presence")
        {
            auto const response = status_of(started.runtime, token, "alice");

            THEN("the response is 200 and carries a presence from the enumeration")
            {
                // Spec MUST: 200 with the required `presence` key.
                REQUIRE(response.status == 200U);
                auto const state = presence_field(response);
                REQUIRE((state == "online" || state == "offline" || state == "unavailable"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint: PUT and GET /_matrix/client/v3/presence/{userId}/status
//
// PUT: "The new presence state was set", with `status_msg` "The status message to attach to this
// state". GET returns `presence` and the `status_msg` "if one was set".
SCENARIO("A presence set with PUT is what GET returns", "[conformance][client-server][presence]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const token = logged_in_token(started.runtime, "alice");

        WHEN("the user sets unavailable with a status message and reads it back")
        {
            put_presence(started.runtime, token, "alice", R"({"presence":"unavailable","status_msg":"in a meeting"})");
            auto const response = status_of(started.runtime, token, "alice");

            THEN("the presence and the status message are returned")
            {
                // Spec MUST: GET returns the state PUT set.
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                REQUIRE(presence_field(response) == "unavailable");
                auto const* status_msg = string_member(body, "status_msg");
                REQUIRE(status_msg != nullptr);
                REQUIRE(*status_msg == "in a meeting");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint: GET /_matrix/client/v3/presence/{userId}/status and "Security considerations"
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3presenceuseridstatus
//
// "Presence information is published to all users who share a room with the target user", and
// 403 is "You are not allowed to see this user's presence status".
SCENARIO("GET /presence/{userId}/status is limited to users who share a room", "[conformance][client-server][presence]")
{
    GIVEN("alice and bob sharing a room, and carol sharing none with alice")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = logged_in_token(runtime, "alice");
        auto const bob = logged_in_token(runtime, "bob");
        auto const carol = logged_in_token(runtime, "carol");
        auto const room_id = create_public_room(runtime, alice);
        join(runtime, bob, room_id);
        put_presence(runtime, bob, "bob", R"({"presence":"online","status_msg":"hello"})");
        put_presence(runtime, carol, "carol", R"({"presence":"online","status_msg":"secret"})");

        WHEN("alice reads bob's presence and carol's presence")
        {
            auto const bobs = status_of(runtime, alice, "bob");
            auto const carols = status_of(runtime, alice, "carol");

            THEN("bob's is returned and carol's is refused with 403 M_FORBIDDEN, naming nothing about her")
            {
                // Spec MUST: a user sharing a room is visible.
                REQUIRE(bobs.status == 200U);
                REQUIRE(presence_field(bobs) == "online");
                // Spec MUST: otherwise "You are not allowed to see this user's presence status".
                REQUIRE(carols.status == 403U);
                auto const body = parse_object(carols.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_FORBIDDEN");
                REQUIRE(carols.body.find("secret") == std::string::npos);
            }
        }

        WHEN("alice reads the presence of a user who does not exist")
        {
            auto const missing = status_of(runtime, alice, "nobody");

            THEN("the answer is the same 403 as for a user she may not see, which reveals who exists")
            {
                REQUIRE(missing.status == 403U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint: GET /sync, parameter `set_presence`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// "If this parameter is omitted then the client is automatically marked as online when it uses
// this API. Otherwise if the parameter is set to 'offline' then the client is not marked as being
// online when it uses this API. When set to 'unavailable', the client is marked as being idle."
SCENARIO("The /sync set_presence parameter decides the presence a sync gives the user",
         "[conformance][client-server][presence]")
{
    GIVEN("two users sharing a room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = logged_in_token(runtime, "alice");
        auto const bob = logged_in_token(runtime, "bob");
        auto const room_id = create_public_room(runtime, alice);
        join(runtime, bob, room_id);
        auto const bob_before = sync_presence(runtime, bob, {}, std::string{quiet});

        WHEN("alice syncs without set_presence")
        {
            std::ignore = sync_presence(runtime, alice);

            THEN("she is online to bob, in a sync and when read directly")
            {
                // Spec MUST: omitted means "automatically marked as online".
                REQUIRE(presence_field(status_of(runtime, bob, "alice")) == "online");
                auto const incremental = sync_presence(runtime, bob, bob_before.next_batch, std::string{quiet});
                REQUIRE(incremental.presence_of("@alice:example.org") == std::optional<std::string>{"online"});
            }
        }

        WHEN("alice syncs with set_presence=unavailable")
        {
            std::ignore = sync_presence(runtime, alice, {}, "&set_presence=unavailable");

            THEN("she is idle to bob, in a sync and when read directly")
            {
                // Spec MUST: "When set to 'unavailable', the client is marked as being idle."
                REQUIRE(presence_field(status_of(runtime, bob, "alice")) == "unavailable");
                auto const incremental = sync_presence(runtime, bob, bob_before.next_batch, std::string{quiet});
                REQUIRE(incremental.presence_of("@alice:example.org") == std::optional<std::string>{"unavailable"});
            }
        }

        WHEN("alice, set unavailable, syncs with set_presence=offline")
        {
            put_presence(runtime, alice, "alice", R"({"presence":"unavailable"})");
            std::ignore = sync_presence(runtime, alice, {}, std::string{quiet});

            THEN("the sync does not mark her online")
            {
                // Spec MUST: "offline" means "not marked as being online when it uses this API".
                REQUIRE(presence_field(status_of(runtime, bob, "alice")) == "unavailable");
            }
        }

        WHEN("a sync names a presence outside the enumeration")
        {
            auto const response = call(runtime, "GET", "/_matrix/client/v3/sync?timeout=0&set_presence=dancing", alice);

            THEN("it is refused with 400 M_INVALID_PARAM and alice is not marked online")
            {
                // Spec: set_presence is "One of: [offline, online, unavailable]".
                REQUIRE(response.status == 400U);
                auto const body = parse_object(response.body);
                auto const* errcode = string_member(body, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_INVALID_PARAM");
                REQUIRE(presence_field(status_of(runtime, bob, "alice")) != "online");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Section: Presence, "Events": `m.presence`; GET /sync `presence`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#presence
//
// "Presence events are sent to interested parties where users share a room membership." A user who
// starts sharing a room is interested from then on, whenever their presence was last set.
SCENARIO("A user who starts sharing a room is sent their peer's presence in the next sync",
         "[conformance][client-server][presence]")
{
    GIVEN("alice and bob, each with a presence set before they share any room")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = logged_in_token(runtime, "alice");
        auto const bob = logged_in_token(runtime, "bob");
        put_presence(runtime, alice, "alice", R"({"presence":"online"})");
        put_presence(runtime, bob, "bob", R"({"presence":"unavailable"})");
        auto const room_id = create_public_room(runtime, alice);
        auto const alice_since = sync_presence(runtime, alice, {}, std::string{quiet}).next_batch;
        auto const bob_since = sync_presence(runtime, bob, {}, std::string{quiet}).next_batch;

        WHEN("bob joins alice's room")
        {
            join(runtime, bob, room_id);
            auto const alice_sync = sync_presence(runtime, alice, alice_since, std::string{quiet});
            auto const bob_sync = sync_presence(runtime, bob, bob_since, std::string{quiet});

            THEN("alice is sent bob's presence and bob is sent alice's, though neither changed since their tokens")
            {
                // Spec MUST: interested parties (users sharing a room) are sent presence events.
                REQUIRE(alice_sync.presence_of("@bob:example.org") == std::optional<std::string>{"unavailable"});
                REQUIRE(bob_sync.presence_of("@alice:example.org") == std::optional<std::string>{"online"});
            }

            AND_THEN("a sync from those responses repeats nothing")
            {
                auto const alice_next = sync_presence(runtime, alice, alice_sync.next_batch, std::string{quiet});
                auto const bob_next = sync_presence(runtime, bob, bob_sync.next_batch, std::string{quiet});
                REQUIRE(alice_next.events.empty());
                REQUIRE(bob_next.events.empty());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Section: Presence, "Events": `m.presence`; GET /sync `presence`
//
// A change of a peer's presence is an update the sharing user is sent, including "unavailable".
SCENARIO("A change of a peer's presence reaches users who share a room, and only them",
         "[conformance][client-server][presence]")
{
    GIVEN("alice and bob sharing a room, and carol sharing none")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = logged_in_token(runtime, "alice");
        auto const bob = logged_in_token(runtime, "bob");
        auto const carol = logged_in_token(runtime, "carol");
        auto const room_id = create_public_room(runtime, alice);
        join(runtime, bob, room_id);
        auto const bob_since = sync_presence(runtime, bob, {}, std::string{quiet}).next_batch;
        auto const carol_since = sync_presence(runtime, carol, {}, std::string{quiet}).next_batch;

        WHEN("alice sets unavailable with a status message")
        {
            put_presence(runtime, alice, "alice", R"({"presence":"unavailable","status_msg":"away"})");
            auto const bob_sync = sync_presence(runtime, bob, bob_since, std::string{quiet});
            auto const carol_sync = sync_presence(runtime, carol, carol_since, std::string{quiet});

            THEN("bob is sent it and carol is not")
            {
                // Spec MUST: sent to users who share a room, and only to them.
                REQUIRE(bob_sync.presence_of("@alice:example.org") == std::optional<std::string>{"unavailable"});
                REQUIRE_FALSE(carol_sync.presence_of("@alice:example.org").has_value());
            }
        }
    }
}
