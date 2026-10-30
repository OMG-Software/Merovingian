// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Classic /sync: a hole in the room's own event graph makes the timeline `limited` (ADR-0289).
//
// Spec (client-server-api.md, "Syncing"): "the server sends a `limited` response containing `E8`,
// `E9` and `E10` but omitting `E7`. This forms a gap ... The client may therefore end up with 'gaps'
// in its knowledge of the message timeline. The client can fill these gaps using the
// `/rooms/{roomId}/messages` API." `prev_batch` is "A token that can be supplied to the `from`
// parameter of the `/rooms/<room_id>/messages` endpoint in order to retrieve earlier events."
// The `limited` field text ("True if the number of events returned was limited by the `limit` on
// the filter") does not say what to report for events the server never received over federation;
// the project treats a hole in its own graph as a gap (Complement TestSyncTimelineGap).
//
// A hole is made here by pointing a stored event's `prev_events` at an event ID the store does not
// hold, which is what an event received over federation with its predecessors missing looks like.

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/stream_token.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto gap_config() -> merovingian::config::Config
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

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
}

// A user, a room they created, and the messages they sent into it.
struct Fixture final
{
    merovingian::homeserver::ClientServerStartResult started;
    std::string token{};
    std::string room_id{};
    int sent{0};

    Fixture()
        : started{merovingian::homeserver::start_client_server(gap_config())}
    {
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const registered =
            call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json("alice", "CorrectHorse7!"));
        REQUIRE(registered.response.status == 200U);
        token = std::string{*string_member(parse_object(registered.response.body), "access_token")};
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", token, "{}");
        REQUIRE(created.response.status == 200U);
        room_id = std::string{*string_member(parse_object(created.response.body), "room_id")};
    }

    [[nodiscard]] auto rt() -> ClientServerRuntime&
    {
        return started.runtime;
    }

    // Sends a text message whose body is `text`.
    auto send(std::string const& text) -> void
    {
        ++sent;
        auto const response =
            call(rt(), "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/t" + std::to_string(sent),
                 token, R"({"msgtype":"m.text","body":")" + text + R"("})");
        REQUIRE(response.response.status == 200U);
    }

    // /sync from `since` (an initial sync when empty), with an optional filter JSON.
    [[nodiscard]] auto sync(std::string const& since = {}, std::string const& filter = {})
        -> merovingian::canonicaljson::Object
    {
        auto target = std::string{"/_matrix/client/v3/sync"};
        auto separator = '?';
        if (!since.empty())
        {
            target += separator + std::string{"since="} + since;
            separator = '&';
        }
        if (!filter.empty())
        {
            target += separator + std::string{"filter="} + filter;
        }
        auto const synced = call(rt(), "GET", target, token);
        REQUIRE(synced.response.status == 200U);
        return parse_object(synced.response.body);
    }

    // The event row whose content.body is `text`.
    [[nodiscard]] auto row_with_body(std::string const& text) -> merovingian::database::PersistentEvent const&
    {
        auto& events = rt().homeserver.database.persistent_store.events;
        auto const found = std::ranges::find_if(events, [&](auto const& event) {
            return event.json.find("\"body\":\"" + text + "\"") != std::string::npos;
        });
        REQUIRE(found != events.end());
        return *found;
    }

    // Points `text`'s event at predecessors the store does not hold.
    auto make_hole_before(std::string const& text) -> void
    {
        auto& events = rt().homeserver.database.persistent_store.events;
        auto const row = events.find(row_with_body(text).event_id);
        events.modify(row, [](auto& event) {
            event.prev_event_ids = {"$never-received:example.org"};
        });
    }

    auto set_prev(std::string const& text, std::vector<std::string> prev) -> void
    {
        auto& events = rt().homeserver.database.persistent_store.events;
        auto const row = events.find(row_with_body(text).event_id);
        events.modify(row, [&](auto& event) {
            event.prev_event_ids = std::move(prev);
        });
    }
};

[[nodiscard]] auto next_batch_of(merovingian::canonicaljson::Object const& body) -> std::string
{
    auto const* next_batch = string_member(body, "next_batch");
    REQUIRE(next_batch != nullptr);
    return *next_batch;
}

[[nodiscard]] auto timeline_of(merovingian::canonicaljson::Object const& body, std::string const& room_id)
    -> merovingian::canonicaljson::Object const*
{
    auto const* rooms = object_member_as_object(body, "rooms");
    auto const* join = rooms == nullptr ? nullptr : object_member_as_object(*rooms, "join");
    auto const* room = join == nullptr ? nullptr : object_member_as_object(*join, room_id);
    return room == nullptr ? nullptr : object_member_as_object(*room, "timeline");
}

[[nodiscard]] auto state_types_of(merovingian::canonicaljson::Object const& body, std::string const& room_id)
    -> std::vector<std::string>
{
    auto result = std::vector<std::string>{};
    auto const* rooms = object_member_as_object(body, "rooms");
    auto const* join = rooms == nullptr ? nullptr : object_member_as_object(*rooms, "join");
    auto const* room = join == nullptr ? nullptr : object_member_as_object(*join, room_id);
    auto const* state = room == nullptr ? nullptr : object_member_as_object(*room, "state");
    auto const* events = state == nullptr ? nullptr : object_member_as_array(*state, "events");
    if (events != nullptr)
    {
        for (auto const& entry : *events)
        {
            result.push_back(*string_member(std::get<merovingian::canonicaljson::Object>(entry.storage()), "type"));
        }
    }
    return result;
}

// The content.body of every message in an event array, oldest first. Events without one are skipped.
[[nodiscard]] auto bodies_of(merovingian::canonicaljson::Array const& events) -> std::vector<std::string>
{
    auto result = std::vector<std::string>{};
    for (auto const& entry : events)
    {
        auto const& event = std::get<merovingian::canonicaljson::Object>(entry.storage());
        auto const* content = object_member_as_object(event, "content");
        auto const* body = content == nullptr ? nullptr : string_member(*content, "body");
        if (body != nullptr)
        {
            result.push_back(*body);
        }
    }
    return result;
}

struct TimelineView final
{
    std::vector<std::string> bodies{};
    bool limited{false};
    std::string prev_batch{};
};

[[nodiscard]] auto view_of(merovingian::canonicaljson::Object const& body, std::string const& room_id) -> TimelineView
{
    auto const* timeline = timeline_of(body, room_id);
    REQUIRE(timeline != nullptr);
    auto const* events = object_member_as_array(*timeline, "events");
    REQUIRE(events != nullptr);
    auto const* limited = bool_member(*timeline, "limited");
    REQUIRE(limited != nullptr);
    auto const* prev_batch = string_member(*timeline, "prev_batch");
    REQUIRE(prev_batch != nullptr);
    return {bodies_of(*events), *limited, *prev_batch};
}

// The bodies GET /rooms/{roomId}/messages?dir=b returns from `from`, newest first.
[[nodiscard]] auto messages_before(Fixture& f, std::string const& from) -> std::vector<std::string>
{
    auto const response =
        call(f.rt(), "GET", "/_matrix/client/v3/rooms/" + f.room_id + "/messages?dir=b&limit=50&from=" + from, f.token);
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* chunk = object_member_as_array(body, "chunk");
    REQUIRE(chunk != nullptr);
    return bodies_of(*chunk);
}

[[nodiscard]] auto holds(std::vector<std::string> const& bodies, std::string const& text) -> bool
{
    return std::ranges::find(bodies, text) != bodies.end();
}

} // namespace

SCENARIO("An initial sync whose timeline holds a hole in the event graph is limited and starts after the hole",
         "[sync][dag-gap]")
{
    GIVEN("a room of five messages, the third of which has predecessors this server never received")
    {
        auto f = Fixture{};
        for (auto const* text : {"m1", "m2", "m3", "m4", "m5"})
        {
            f.send(text);
        }
        f.make_hole_before("m3");

        WHEN("the user makes an initial sync")
        {
            auto const view = view_of(f.sync(), f.room_id);

            THEN("only the events from the hole on are sent, and the timeline is limited")
            {
                REQUIRE(view.bodies == std::vector<std::string>{"m3", "m4", "m5"});
                REQUIRE(view.limited);
            }

            THEN("prev_batch lets /messages reach the events before the hole")
            {
                REQUIRE(view.prev_batch == std::to_string(f.row_with_body("m3").stream_ordering));
                auto const earlier = messages_before(f, view.prev_batch);
                REQUIRE(holds(earlier, "m2"));
                REQUIRE(holds(earlier, "m1"));
                REQUIRE_FALSE(holds(earlier, "m3"));
            }
        }
    }
}

SCENARIO("An incremental sync whose new events cross a hole in the event graph is limited", "[sync][dag-gap]")
{
    GIVEN("a client synced after the first message, then four more arrived and the fourth has missing predecessors")
    {
        auto f = Fixture{};
        f.send("m1");
        auto const since = next_batch_of(f.sync());
        for (auto const* text : {"m2", "m3", "m4", "m5"})
        {
            f.send(text);
        }
        f.make_hole_before("m4");

        WHEN("the client syncs from its token")
        {
            auto const view = view_of(f.sync(since), f.room_id);

            THEN("the events before the hole are left to /messages and the timeline is limited")
            {
                REQUIRE(view.bodies == std::vector<std::string>{"m4", "m5"});
                REQUIRE(view.limited);
                auto const earlier = messages_before(f, view.prev_batch);
                REQUIRE(holds(earlier, "m3"));
                REQUIRE(holds(earlier, "m2"));
            }
        }

        WHEN("the client syncs from its token and the newest hole is older than an earlier one")
        {
            f.make_hole_before("m2");
            auto const view = view_of(f.sync(since), f.room_id);

            THEN("the timeline starts after the newest hole")
            {
                REQUIRE(view.bodies == std::vector<std::string>{"m4", "m5"});
                REQUIRE(view.limited);
            }
        }
    }
}

SCENARIO("A timeline with no hole and within the limit is not limited", "[sync][dag-gap]")
{
    GIVEN("a room of five messages, every event's predecessors held")
    {
        auto f = Fixture{};
        f.send("m1");
        auto const since = next_batch_of(f.sync());
        for (auto const* text : {"m2", "m3", "m4", "m5"})
        {
            f.send(text);
        }

        WHEN("the user makes an initial sync")
        {
            auto const view = view_of(f.sync(), f.room_id);

            THEN("every message is sent and the timeline is not limited")
            {
                REQUIRE(view.bodies == std::vector<std::string>{"m1", "m2", "m3", "m4", "m5"});
                REQUIRE_FALSE(view.limited);
            }
        }

        WHEN("the client syncs incrementally")
        {
            auto const view = view_of(f.sync(since), f.room_id);

            THEN("the new messages are sent and the timeline is not limited")
            {
                REQUIRE(view.bodies == std::vector<std::string>{"m2", "m3", "m4", "m5"});
                REQUIRE_FALSE(view.limited);
            }
        }
    }
}

SCENARIO("A timeline still reports a window larger than the filter limit as limited", "[sync][dag-gap]")
{
    GIVEN("a room of five messages and a filter limit of two")
    {
        auto f = Fixture{};
        for (auto const* text : {"m1", "m2", "m3", "m4", "m5"})
        {
            f.send(text);
        }

        WHEN("the user makes an initial sync")
        {
            auto const view = view_of(f.sync({}, R"({"room":{"timeline":{"limit":2}}})"), f.room_id);

            THEN("the newest two are sent and the timeline is limited")
            {
                REQUIRE(view.bodies == std::vector<std::string>{"m4", "m5"});
                REQUIRE(view.limited);
            }
        }
    }
}

SCENARIO("A hole closes once the missing predecessors are held", "[sync][dag-gap]")
{
    GIVEN("a room of five messages whose third message had a hole")
    {
        auto f = Fixture{};
        for (auto const* text : {"m1", "m2", "m3", "m4", "m5"})
        {
            f.send(text);
        }
        auto const real_prev = f.row_with_body("m3").prev_event_ids;
        f.make_hole_before("m3");
        REQUIRE(view_of(f.sync(), f.room_id).limited);

        WHEN("the predecessors are received and the user makes an initial sync again")
        {
            f.set_prev("m3", real_prev);
            auto const view = view_of(f.sync(), f.room_id);

            THEN("the timeline holds every message and is not limited because of the hole")
            {
                REQUIRE(view.bodies == std::vector<std::string>{"m1", "m2", "m3", "m4", "m5"});
                REQUIRE_FALSE(view.limited);
            }
        }
    }
}

SCENARIO("Which stored predecessors count as held", "[sync][dag-gap]")
{
    GIVEN("a room of three messages")
    {
        auto f = Fixture{};
        for (auto const* text : {"m1", "m2", "m3"})
        {
            f.send(text);
        }
        auto& store = f.rt().homeserver.database.persistent_store;

        WHEN("the third message's predecessor was rejected")
        {
            auto const m2 = f.row_with_body("m2").event_id;
            REQUIRE(merovingian::database::set_event_status(store, m2, "rejected"));
            f.set_prev("m3", {m2});
            auto const view = view_of(f.sync(), f.room_id);

            THEN("it is in the graph, so there is no hole")
            {
                REQUIRE(view.bodies == std::vector<std::string>{"m1", "m3"});
                REQUIRE_FALSE(view.limited);
            }
        }

        WHEN("the third message's predecessor was soft-failed")
        {
            auto const m2 = f.row_with_body("m2").event_id;
            REQUIRE(merovingian::database::set_event_status(store, m2, "soft_failed"));
            f.set_prev("m3", {m2});
            auto const view = view_of(f.sync(), f.room_id);

            THEN("it is in the graph, so there is no hole")
            {
                REQUIRE(view.bodies == std::vector<std::string>{"m1", "m3"});
                REQUIRE_FALSE(view.limited);
            }
        }

        WHEN("the third message's predecessor is an outlier")
        {
            auto const m2 = f.row_with_body("m2").event_id;
            REQUIRE(merovingian::database::set_event_status(store, m2, "outlier"));
            f.set_prev("m3", {m2});
            auto const view = view_of(f.sync(), f.room_id);

            THEN("it is not part of the graph this server has walked, so there is a hole before the third message")
            {
                REQUIRE(view.bodies.back() == "m3");
                REQUIRE_FALSE(holds(view.bodies, "m1"));
                REQUIRE(view.limited);
            }
        }

        WHEN("only one of the third message's predecessors is held")
        {
            auto const m2 = f.row_with_body("m2").event_id;
            f.set_prev("m3", {m2, "$never-received:example.org"});
            auto const view = view_of(f.sync(), f.room_id);

            THEN("there is a hole before it")
            {
                REQUIRE(view.bodies == std::vector<std::string>{"m3"});
                REQUIRE(view.limited);
            }
        }
    }
}

// Spec: "The limited response includes a state delta which describes how the state of the room
// changes over the gap" and, with lazy-loading, "the server MUST return membership events for
// events in the gap".
SCENARIO("A limited incremental sync carries the state that changed over the gap", "[sync][dag-gap]")
{
    GIVEN("a client synced, then the topic changed and two messages arrived, the second after a hole")
    {
        auto f = Fixture{};
        f.send("m1");
        auto const since = next_batch_of(f.sync());
        REQUIRE(call(f.rt(), "PUT", "/_matrix/client/v3/rooms/" + f.room_id + "/state/m.room.topic/", f.token,
                     R"({"topic":"new topic"})")
                    .response.status == 200U);
        f.send("m2");
        f.send("m3");
        f.make_hole_before("m3");

        WHEN("the client syncs from its token")
        {
            auto const response = f.sync(since);
            auto const view = view_of(response, f.room_id);

            THEN("the topic change in the omitted part of the timeline arrives in the state")
            {
                REQUIRE(view.limited);
                REQUIRE(view.bodies == std::vector<std::string>{"m3"});
                auto const types = state_types_of(response, f.room_id);
                REQUIRE(std::ranges::find(types, "m.room.topic") != types.end());
            }
        }
    }
}
