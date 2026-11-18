// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE here encodes a MUST or SHOULD of the Matrix v1.19 spec   |
// |  (the scenario header quotes it). If one fails, fix the IMPLEMENTATION  |
// |  first. Do NOT weaken, comment out or remove an assertion, or change an |
// |  expected value, without citing the spec section that changed.          |
// +-------------------------------------------------------------------------+
//
// GET /_matrix/client/v3/sync `use_state_after` and the `state_after` section of joined and left rooms
// (client-server-api.md, GET /sync, "Joined Room", "Left Room"; ADR-0818 to ADR-0820).
#include "../support/JsonTestSupport.hpp"
#include "../support/SyncStateAfterSupport.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;
using namespace merovingian::tests::state_after_support;

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, query parameter `use_state_after`; Joined Room `state`,
// `state_after` URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// "If this is set to true, servers MUST respond with the state between the previous sync and the end of the timeline in
// state_after and MUST omit state. If false, servers MUST respond with the state between the previous sync and the
// start of the timeline in state and MUST omit state_after." "By default, this is false." `state_after`: "all state up
// to the end of the timeline, if since is not given, or full_state is true".
SCENARIO("An initial sync answers state_after or state as use_state_after asks",
         "[conformance][client-server][sync][state-after]")
{
    GIVEN("a room whose topic changed inside the last two events")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room = create_room(rt, alice, "public_chat");
        set_topic(rt, alice, room, "first");
        say(rt, alice, room, "a");
        set_topic(rt, alice, room, "second");
        say(rt, alice, room, "b");
        constexpr auto two_events = std::string_view{R"({"room":{"timeline":{"limit":2}}})"};

        WHEN("alice syncs with use_state_after=true")
        {
            auto const synced = sync(rt, alice, two_events, {}, k_state_after);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after is the whole state at the end of the timeline, and state is omitted")
            {
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(joined);
                auto const after = events_of(joined, "state_after");
                REQUIRE(topics_in(after) == std::vector<std::string>{"second"});
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(member_keys(after) == Keys{user_id("alice")});
            }
        }
        WHEN("alice syncs with use_state_after=false")
        {
            auto const synced = sync(rt, alice, two_events, {}, k_state_before);
            auto const& joined = required_room(synced, "join", room);

            THEN("state is the state at the start of the timeline, and state_after is omitted")
            {
                // Spec MUST: with use_state_after false or absent the room carries state and omits state_after.
                require_state_only(joined);
                REQUIRE(topics_in(events_of(joined, "state")) == std::vector<std::string>{"first"});
            }
        }
        WHEN("alice syncs without the parameter")
        {
            auto const synced = sync(rt, alice, two_events);
            auto const& joined = required_room(synced, "join", room);

            THEN("it is as if it were false")
            {
                // Spec MUST: with use_state_after false or absent the room carries state and omits state_after.
                require_state_only(joined);
                REQUIRE(topics_in(events_of(joined, "state")) == std::vector<std::string>{"first"});
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, query parameter `use_state_after`; Joined Room `state_after`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `state_after`: "Updates to the state, between the time indicated by the since parameter, and the end of the
// timeline". "If this field is set, even if it is empty, clients MUST only update their local state with events in this
// list, and MUST NOT update their local state with events in timeline." "Required if use_state_after was set to true in
// the request, even if it is empty."
SCENARIO("An incremental sync's state_after holds what changed up to the end of the timeline",
         "[conformance][client-server][sync][state-after]")
{
    GIVEN("a room alice has synced")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room = create_room(rt, alice, "public_chat");
        set_topic(rt, alice, room, "first");
        auto const initial = sync(rt, alice, k_no_filter, {}, k_state_after);

        WHEN("only a message arrived")
        {
            say(rt, alice, room, "hello");
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after is present and empty, and state is omitted")
            {
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(joined);
                REQUIRE(events_of(joined, "state_after").empty());
            }
        }
        WHEN("only a message arrived and the parameter is false or absent")
        {
            say(rt, alice, room, "hello");
            auto const off = sync(rt, alice, k_no_filter, initial.next_batch, k_state_before);
            auto const absent = sync(rt, alice, k_no_filter, initial.next_batch);

            THEN("state is present and state_after is omitted")
            {
                // Spec MUST: with use_state_after false or absent the room carries state and omits state_after.
                require_state_only(required_room(off, "join", room));
                // Spec MUST: with use_state_after false or absent the room carries state and omits state_after.
                require_state_only(required_room(absent, "join", room));
            }
        }
        WHEN("the timeline carries a topic change")
        {
            say(rt, alice, room, "before");
            set_topic(rt, alice, room, "second");
            say(rt, alice, room, "after");
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after repeats the change, as the client takes no state from the timeline, and nothing else")
            {
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(joined);
                REQUIRE(topics_in(events_of(joined, "timeline")) == std::vector<std::string>{"second"});
                auto const after = events_of(joined, "state_after");
                REQUIRE(event_types(after) == Keys{"m.room.topic"});
                REQUIRE(topics_in(after) == std::vector<std::string>{"second"});
            }
        }
        WHEN("the topic changed twice since the last sync")
        {
            set_topic(rt, alice, room, "second");
            set_topic(rt, alice, room, "third");
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);

            THEN("state_after holds the value at the end of the timeline, once")
            {
                REQUIRE(topics_in(events_of(required_room(synced, "join", room), "state_after")) ==
                        std::vector<std::string>{"third"});
            }
        }
        WHEN("a topic change falls in the gap of a limited sync")
        {
            set_topic(rt, alice, room, "second");
            say(rt, alice, room, "one");
            say(rt, alice, room, "two");
            auto const synced = sync(rt, alice, k_one_event, initial.next_batch, k_state_after);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after holds the change and not the state that did not change")
            {
                auto const* timeline = object_member_as_object(joined, "timeline");
                REQUIRE(timeline != nullptr);
                REQUIRE(events_of(joined, "timeline").size() == 1U);
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(joined);
                auto const after = events_of(joined, "state_after");
                REQUIRE(event_types(after) == Keys{"m.room.topic"});
                REQUIRE(topics_in(after) == std::vector<std::string>{"second"});
            }
        }
        WHEN("the timeline filter hides a topic change")
        {
            constexpr auto hide_topic = std::string_view{R"({"room":{"timeline":{"not_types":["m.room.topic"]}}})"};
            set_topic(rt, alice, room, "hidden");
            auto const synced = sync(rt, alice, hide_topic, initial.next_batch, k_state_after);

            THEN("state_after still reports it, because the next sync starts after it")
            {
                auto const& joined = required_room(synced, "join", room);
                REQUIRE(events_of(joined, "timeline").empty());
                REQUIRE(topics_in(events_of(joined, "state_after")) == std::vector<std::string>{"hidden"});
                auto const next = sync(rt, alice, hide_topic, synced.next_batch, k_state_after);
                auto const* again = room_section(next, "join", room);
                REQUIRE((again == nullptr || events_of(*again, "state_after").empty()));
            }
        }
        WHEN("the state filter excludes the type that changed")
        {
            constexpr auto no_topic = std::string_view{R"({"room":{"state":{"not_types":["m.room.topic"]}}})"};
            set_topic(rt, alice, room, "second");
            auto const synced = sync(rt, alice, no_topic, initial.next_batch, k_state_after);

            THEN("state_after is present and does not hold it")
            {
                auto const& joined = required_room(synced, "join", room);
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(joined);
                REQUIRE(events_of(joined, "state_after").empty());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, query parameter `use_state_after`; Joined Room `state_after`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `use_state_after`: "the state between the previous sync and the end of the timeline". State resolution can move a key
// back to an older event: no event of the window is about that key, and only comparing the two states shows the change.
SCENARIO("state_after reports a key that state resolution moved back to an older event",
         "[conformance][client-server][sync][state-after]")
{
    GIVEN("a room with a forked graph whose resolved topic went back to an earlier event")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room = create_room(rt, alice, "public_chat");
        auto const old_topic = set_topic(rt, alice, room, "old");
        set_topic(rt, alice, room, "new");
        auto const initial = sync(rt, alice, k_no_filter, {}, k_state_after);
        say(rt, alice, room, "the event that arrived with the fork");

        auto& store = rt.homeserver.database.persistent_store;
        std::ignore = store.forward_extremities.insert({room, old_topic}, user_id("alice"));
        // What a resolution that picked the older topic writes, through the writer it uses.
        REQUIRE(merovingian::database::store_state(store, {room, "m.room.topic", "", old_topic}));

        WHEN("alice syncs with use_state_after=true")
        {
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);

            THEN("state_after holds the older event, and the unchanged state stays out")
            {
                auto const after = events_of(required_room(synced, "join", room), "state_after");
                REQUIRE(topics_in(after) == std::vector<std::string>{"old"});
                REQUIRE_FALSE(event_types(after).contains("m.room.create"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, query parameter `use_state_after`; Joined Room `state_after`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `full_state`: "If this is set to true, then all state events will be returned, even if since is non-empty."
// `state_after`: "all state up to the end of the timeline, if since is not given, or full_state is true".
SCENARIO("full_state=true returns the whole state in the section use_state_after names",
         "[conformance][client-server][sync][state-after]")
{
    GIVEN("a room alice has synced, whose topic changed since")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room = create_room(rt, alice, "public_chat");
        set_topic(rt, alice, room, "first");
        auto const initial = sync(rt, alice, k_no_filter);
        set_topic(rt, alice, room, "second");

        WHEN("alice asks for the full state with use_state_after=true")
        {
            auto const extra = std::string{"&full_state=true"} + std::string{k_state_after};
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, extra);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after holds all state, the timeline's change included, and state is omitted")
            {
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(joined);
                auto const after = events_of(joined, "state_after");
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(topics_in(after) == std::vector<std::string>{"second"});
            }
        }
        WHEN("alice asks for the full state with use_state_after=false")
        {
            auto const extra = std::string{"&full_state=true"} + std::string{k_state_before};
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, extra);
            auto const& joined = required_room(synced, "join", room);

            THEN("state holds all state up to the start of the timeline, and state_after is omitted")
            {
                // Spec MUST: with use_state_after false or absent the room carries state and omits state_after.
                require_state_only(joined);
                auto const state = events_of(joined, "state");
                REQUIRE(event_types(state).contains("m.room.create"));
                REQUIRE(topics_in(state) == std::vector<std::string>{"first"});
            }
        }
        WHEN("nothing changed and alice asks for the full state with use_state_after=true")
        {
            auto const caught_up = sync(rt, alice, k_no_filter, initial.next_batch);
            auto const extra = std::string{"&full_state=true"} + std::string{k_state_after};
            auto const synced = sync(rt, alice, k_no_filter, caught_up.next_batch, extra);

            THEN("the room is still reported, with all state")
            {
                auto const& joined = required_room(synced, "join", room);
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(joined);
                REQUIRE(event_types(events_of(joined, "state_after")).contains("m.room.create"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, Left Room
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// Left Room `state`: "The state updates for the room up to the start of the timeline. MUST be omitted if
// use_state_after was set to true in the request." `state_after`: "The state updates for the room up to the end of the
// timeline. If this field is set, even if it is empty, clients MUST only update their local state with events in this
// list, and MUST NOT update their local state with events in timeline." Room History Visibility: "After a user has left
// a room, they may see any events which they were allowed to see before they left the room, but no events received
// after they left."
SCENARIO("A left room answers state_after or state as use_state_after asks",
         "[conformance][client-server][sync][state-after]")
{
    GIVEN("a room dave joined and synced, and whose topic changed before he left")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        set_topic(rt, alice, room, "first");
        room_post(rt, dave, room, "join");
        auto const synced_before = sync(rt, dave, k_no_filter, {}, k_state_after);
        set_topic(rt, alice, room, "changed before the leave");
        room_post(rt, dave, room, "leave");
        set_topic(rt, alice, room, "changed after the leave");

        WHEN("dave makes an initial sync with include_leave and use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_include_leave, {}, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after is the state up to his leave, the leave included, and state is omitted")
            {
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(left);
                auto const after = events_of(left, "state_after");
                REQUIRE(topics_in(after) == std::vector<std::string>{"changed before the leave"});
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(member_keys(after).count(user_id("dave")) == 1U);
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "leave");
            }
        }
        WHEN("dave makes an initial sync with include_leave, without the parameter and with it false")
        {
            auto const absent = sync(rt, dave, k_include_leave);
            auto const off = sync(rt, dave, k_include_leave, {}, k_state_before);

            THEN("state is present and state_after is omitted")
            {
                // Spec MUST: with use_state_after false or absent the room carries state and omits state_after.
                require_state_only(required_room(absent, "leave", room));
                // Spec MUST: with use_state_after false or absent the room carries state and omits state_after.
                require_state_only(required_room(off, "leave", room));
            }
        }
        WHEN("dave makes an incremental sync with use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_no_filter, synced_before.next_batch, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after holds what changed up to his leave and the leave, though the timeline carries it")
            {
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(left);
                REQUIRE(content_of(events_of(left, "timeline"), "m.room.member", user_id("dave"), "membership") ==
                        "leave");
                auto const after = events_of(left, "state_after");
                REQUIRE(topics_in(after) == std::vector<std::string>{"changed before the leave"});
                REQUIRE(event_types(after) == Keys{"m.room.member", "m.room.topic"});
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "leave");
            }
        }
        WHEN("dave makes an incremental sync without the parameter")
        {
            auto const synced = sync(rt, dave, k_no_filter, synced_before.next_batch);

            THEN("state is present and state_after is omitted")
            {
                // Spec MUST: with use_state_after false or absent the room carries state and omits state_after.
                require_state_only(required_room(synced, "leave", room));
            }
        }
        WHEN("dave makes an incremental sync with full_state=true and use_state_after=true")
        {
            auto const extra = std::string{"&full_state=true"} + std::string{k_state_after};
            auto const synced = sync(rt, dave, k_no_filter, synced_before.next_batch, extra);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after is present and state is omitted")
            {
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(left);
            }
        }
        WHEN("dave makes an incremental sync with full_state=true and use_state_after=false")
        {
            auto const extra = std::string{"&full_state=true"} + std::string{k_state_before};
            auto const synced = sync(rt, dave, k_no_filter, synced_before.next_batch, extra);

            THEN("state is present and state_after is omitted")
            {
                // Spec MUST: with use_state_after false or absent the room carries state and omits state_after.
                require_state_only(required_room(synced, "leave", room));
            }
        }
    }
    GIVEN("a room dave left and synced, then was banned from after its topic changed")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        room_post(rt, dave, room, "join");
        room_post(rt, dave, room, "leave");
        auto const after_leave = sync(rt, dave, k_no_filter, {}, k_state_after);
        set_topic(rt, alice, room, "secret");
        room_post(rt, alice, room, "ban", R"({"user_id":")" + user_id("dave") + R"("})");

        WHEN("dave syncs with use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_no_filter, after_leave.next_batch, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after holds his ban and nothing of what happened after he left")
            {
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(left);
                auto const after = events_of(left, "state_after");
                REQUIRE(topics_in(after).empty());
                REQUIRE(event_types(after) == Keys{"m.room.member"});
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "ban");
            }
        }
        WHEN("dave makes an initial sync with include_leave and use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_include_leave, {}, k_state_after);
            auto const after = events_of(required_room(synced, "leave", room), "state_after");

            THEN("state_after is the room as of his leave, with his own membership the ban")
            {
                REQUIRE(topics_in(after).empty());
                REQUIRE(member_keys(after).count(user_id("dave")) == 1U);
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "ban");
            }
        }
    }
    GIVEN("a private room erin was invited to and declined, never having joined")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const erin = register_user(rt, "erin");
        auto const room = create_room(rt, alice, "private_chat");
        set_topic(rt, alice, room, "secret");
        room_post(rt, alice, room, "invite", R"({"user_id":")" + user_id("erin") + R"("})");
        room_post(rt, erin, room, "leave");

        WHEN("erin makes an initial sync with include_leave and use_state_after=true")
        {
            auto const synced = sync(rt, erin, k_include_leave, {}, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after holds only her own leave, as she never could read the room")
            {
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(left);
                auto const after = events_of(left, "state_after");
                REQUIRE(event_types(after) == Keys{"m.room.member"});
                REQUIRE(content_of(after, "m.room.member", user_id("erin"), "membership") == "leave");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, query parameter `use_state_after`; Joined Room `state_after`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `state_after`: "State updates for m.room.member events will be incomplete if lazy_load_members is enabled in the
// /sync filter, and only return the member events required to display the senders of the timeline events in this
// response." Lazy-loading room members: "servers MUST include the syncing user's own membership event ... when the full
// state of rooms is requested". Redundancy follows ADR-0450; a timeline event is not state here, so ADR-0819 forces
// every change.
//
// The scenario has four GIVENs: a joined room seen through lazy-loading (initial, acknowledged and lost-response
// incrementals, a display-name change, a kick, a limited gap, `full_state`), a departed member's own view, a user who
// joins, speaks and leaves inside one window, and a user banned after a later joiner arrived.
SCENARIO("Lazy-loading selects the members of state_after", "[conformance][client-server][sync][state-after]")
{
    // Bob and carol have both spoken, but a one-event timeline holds only bob's message, so a lazy-loaded answer must
    // name bob and leave carol out until she is in a timeline.
    GIVEN("a room of alice, bob and carol, in which bob and carol have spoken")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const carol = register_user(rt, "carol");
        auto const room = create_room(rt, alice, "public_chat");
        room_post(rt, bob, room, "join");
        room_post(rt, carol, room, "join");
        set_topic(rt, alice, room, "first");
        say(rt, carol, room, "carol");
        say(rt, bob, room, "bob");

        WHEN("alice makes an initial sync with lazy-loading and use_state_after=true")
        {
            auto const synced = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after keeps other state and only the sender's and her own membership")
            {
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(joined);
                auto const after = events_of(joined, "state_after");
                REQUIRE(topics_in(after) == std::vector<std::string>{"first"});
                REQUIRE(member_keys(after) == Keys{user_id("alice"), user_id("bob")});
            }
        }
        WHEN("alice makes an initial sync with lazy-loading and use_state_after=false")
        {
            auto const synced = sync(rt, alice, k_lazy_one_event, {}, k_state_before);
            auto const& joined = required_room(synced, "join", room);

            THEN("state holds those members, and state_after is omitted")
            {
                // Spec MUST: with use_state_after false or absent the room carries state and omits state_after.
                require_state_only(joined);
                REQUIRE(member_keys(events_of(joined, "state")) == Keys{user_id("alice"), user_id("bob")});
            }
        }
        // The tracker (ADR-0450) records that the client was sent carol's membership once the next request proves it
        // arrived, so the later sync repeats nothing it was told.
        WHEN("carol speaks in two incremental syncs, each acknowledging the last")
        {
            auto const first = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            say(rt, carol, room, "carol again");
            auto const second = sync(rt, alice, k_lazy, first.next_batch, k_state_after);
            say(rt, carol, room, "carol once more");
            auto const third = sync(rt, alice, k_lazy, second.next_batch, k_state_after);

            THEN("carol's membership comes once, then is redundant")
            {
                REQUIRE(member_keys(events_of(required_room(second, "join", room), "state_after")) ==
                        Keys{user_id("carol")});
                auto const after = events_of(required_room(third, "join", room), "state_after");
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(required_room(third, "join", room));
                REQUIRE(member_keys(after).empty());
            }
        }
        // Two events about bob in one window must not produce two member events: state_after is the state at the end
        // of the timeline, so only the later one is sent.
        WHEN("bob speaks and then changes his display name in the same window")
        {
            auto const first = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            say(rt, bob, room, "still bob");
            set_display_name(rt, bob, room, "bob", "Bobby");
            auto const synced = sync(rt, alice, k_lazy, first.next_batch, k_state_after);
            auto const after = events_of(required_room(synced, "join", room), "state_after");

            THEN("state_after holds his membership as of the end of the timeline, once")
            {
                REQUIRE(member_keys(after) == Keys{user_id("bob")});
                REQUIRE(content_of(after, "m.room.member", user_id("bob"), "displayname") == "Bobby");
            }
        }
        // A timeline event is not state to a `use_state_after` client, so lazy-loading cannot drop a change merely
        // because its subject is not a sender (ADR-0819 forces every change).
        WHEN("the timeline carries a membership change about someone who did not speak")
        {
            auto const first = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            room_post(rt, alice, room, "kick", R"({"user_id":")" + user_id("carol") + R"("})");
            auto const synced = sync(rt, alice, k_lazy, first.next_batch, k_state_after);
            auto const after = events_of(required_room(synced, "join", room), "state_after");

            THEN("state_after holds it, because the client takes no state from the timeline")
            {
                REQUIRE(content_of(after, "m.room.member", user_id("carol"), "membership") == "leave");
            }
        }
        // With a one-event timeline limit the leave falls before the timeline's start; the client cannot read it from
        // the timeline, so state_after must carry it, while unchanged state (the topic) stays out.
        WHEN("a membership change falls in the gap of a limited sync")
        {
            auto const first = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            room_post(rt, carol, room, "leave");
            say(rt, bob, room, "one");
            say(rt, bob, room, "two");
            auto const synced = sync(rt, alice, k_lazy_one_event, first.next_batch, k_state_after);
            auto const after = events_of(required_room(synced, "join", room), "state_after");

            THEN("state_after holds it, and the state that did not change stays out")
            {
                REQUIRE(content_of(after, "m.room.member", user_id("carol"), "membership") == "leave");
                REQUIRE(topics_in(after).empty());
            }
        }
        // The spec requires the syncing user's own membership "when the full state of rooms is requested"; carol, who
        // is not in the timeline, is not sent.
        WHEN("alice asks for the full state with lazy-loading and use_state_after=true")
        {
            auto const first = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            auto const acknowledged = sync(rt, alice, k_lazy_one_event, first.next_batch, k_state_after);
            auto const extra = std::string{"&full_state=true"} + std::string{k_state_after};
            auto const synced = sync(rt, alice, k_lazy_one_event, acknowledged.next_batch, extra);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after holds her own membership and all other state")
            {
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(joined);
                auto const after = events_of(joined, "state_after");
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(member_keys(after).contains(user_id("alice")));
                REQUIRE_FALSE(member_keys(after).contains(user_id("carol")));
            }
        }
    }
    // A left room takes the same lazy-loading rule: the sender (bob) and the user's own leave are sent, nobody else.
    GIVEN("a room of alice and dave that dave leaves after bob spoke")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        room_post(rt, bob, room, "join");
        room_post(rt, dave, room, "join");
        auto const before = sync(rt, dave, k_lazy_one_event, {}, k_state_after);
        say(rt, bob, room, "bob");
        room_post(rt, dave, room, "leave");

        WHEN("dave makes an incremental sync with lazy-loading and use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_lazy, before.next_batch, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after holds his leave and the sender's membership")
            {
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(left);
                auto const after = events_of(left, "state_after");
                REQUIRE(member_keys(after) == Keys{user_id("bob"), user_id("dave")});
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "leave");
            }
        }
        // An initial sync with include_leave reports the left room as new to the client, so the other state is sent but
        // members are still limited to his own.
        WHEN("dave makes an initial sync with include_leave, lazy-loading and use_state_after=true")
        {
            constexpr auto lazy = std::string_view{
                R"({"room":{"include_leave":true,"timeline":{"limit":1},"state":{"lazy_load_members":true}}})"};
            auto const synced = sync(rt, dave, lazy, {}, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after keeps other state and holds only his own membership among members")
            {
                // Spec MUST: with use_state_after=true the room carries state_after and omits state.
                require_state_after_only(left);
                auto const after = events_of(left, "state_after");
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(member_keys(after) == Keys{user_id("dave")});
            }
        }
    }
    // Dave is a sender in his own timeline, so the sender rule and the own-membership rule both name him: his member
    // key must still appear once, as the leave, not as the earlier join the timeline also carries.
    GIVEN("a room dave joins, speaks in and leaves, all after his last sync")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        auto const before = sync(rt, dave, k_lazy, {}, k_state_after);
        room_post(rt, dave, room, "join");
        say(rt, dave, room, "hello and goodbye");
        room_post(rt, dave, room, "leave");

        WHEN("dave syncs with lazy-loading and use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_lazy, before.next_batch, k_state_after);
            auto const after = events_of(required_room(synced, "leave", room), "state_after");

            THEN("his own membership is there once, as the leave, so his earlier join cannot override it")
            {
                REQUIRE(member_keys(after).count(user_id("dave")) == 1U);
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "leave");
            }
        }
    }
    // What a departed user may learn is capped at his leave (ADR-0820): the ban is his own membership and may be told,
    // but erin's join after he left may not.
    GIVEN("a room dave left and synced, which erin then joined, and from which dave was then banned")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const dave = register_user(rt, "dave");
        auto const erin = register_user(rt, "erin");
        auto const room = create_room(rt, alice, "public_chat");
        room_post(rt, dave, room, "join");
        room_post(rt, dave, room, "leave");
        auto const after_leave = sync(rt, dave, k_lazy_one_event, {}, k_state_after);
        room_post(rt, erin, room, "join");
        say(rt, erin, room, "dave cannot know I am here");
        room_post(rt, alice, room, "ban", R"({"user_id":")" + user_id("dave") + R"("})");

        WHEN("dave makes a limited incremental sync with lazy-loading and use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_lazy_one_event, after_leave.next_batch, k_state_after);
            auto const after = events_of(required_room(synced, "leave", room), "state_after");

            THEN("state_after holds his ban and does not show who joined after he left")
            {
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "ban");
                REQUIRE_FALSE(member_keys(after).contains(user_id("erin")));
            }
        }
    }
}
