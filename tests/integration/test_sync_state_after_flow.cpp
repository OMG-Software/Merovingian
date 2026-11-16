// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// GET /_matrix/client/v3/sync `use_state_after`: what this project decides beyond the spec's rows, driven through the
// client-server stack (ADR-0763 to ADR-0765). What the spec states is in
// tests/conformance/test_sync_state_after_conformance.cpp.
#include "../support/JsonTestSupport.hpp"
#include "../support/SyncStateAfterSupport.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using namespace merovingian::tests;
using namespace merovingian::tests::state_after_support;

constexpr auto k_full_state_after = std::string_view{"&full_state=true&use_state_after=true"};

} // namespace

// ADR-0763: a sync that finds nothing new in a joined room does not report it.
SCENARIO("A joined room with nothing new is not reported with use_state_after",
         "[integration][sync][state-after][flow]")
{
    GIVEN("a room alice has synced")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room = create_room(rt, alice, "public_chat");
        auto const initial = sync(rt, alice, k_no_filter, {}, k_state_after);

        WHEN("nothing happened")
        {
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);

            THEN("the room is not reported")
            {
                REQUIRE(room_section(synced, "join", room) == nullptr);
            }
        }
    }
}

// ADR-0764: a delta chain is bounded (`max_state_group_delta_depth`); a window with more changes than it holds falls
// back to comparing the two states and still sends one event per changed key.
SCENARIO("A state_after delta survives more state changes than one delta chain can hold",
         "[integration][sync][state-after][flow]")
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

        WHEN("more state changes than one delta chain can hold happened")
        {
            for (auto index = 0; index < 120; ++index)
            {
                set_topic(rt, alice, room, "t" + std::to_string(index));
            }
            auto const synced = sync(rt, alice, k_one_event, initial.next_batch, k_state_after);

            THEN("state_after still holds only the key that changed, with its last value")
            {
                auto const after = events_of(required_room(synced, "join", room), "state_after");
                REQUIRE(event_types(after) == Keys{"m.room.topic"});
                REQUIRE(topics_in(after) == std::vector<std::string>{"t119"});
            }
        }
    }
}

// ADR-0764: the chain walk (`state_changes_along_chain`) answers a single-extremity room from the state groups alone.
// The fallback reads the room's current state rows, which `state_rows_examined` counts, so a wide state shows which
// path ran.
SCENARIO("A state_after delta of an unforked room is read from the state groups, not the room's state",
         "[integration][sync][state-after][flow][state-index]")
{
    GIVEN("a room with sixty state events that alice has synced, and one forward extremity")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room = create_room(rt, alice, "public_chat");
        for (auto index = 0; index < 60; ++index)
        {
            auto const sent =
                call(rt, "PUT", "/_matrix/client/v3/rooms/" + room + "/state/org.example.key/k" + std::to_string(index),
                     alice, R"({"value":"v"})");
            REQUIRE(sent.status == 200U);
        }
        auto const initial = sync(rt, alice, k_no_filter, {}, k_state_after);
        auto const& store = rt.homeserver.database.persistent_store;
        REQUIRE(store.forward_extremities.tips_of_room(room).size() == 1U);

        WHEN("a topic change arrives and alice syncs with use_state_after=true")
        {
            set_topic(rt, alice, room, "second");
            auto const before = store.state_rows_examined.value();
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);
            auto const examined = store.state_rows_examined.value() - before;

            THEN("only the topic is sent, and far fewer than sixty state rows were read")
            {
                auto const after = events_of(required_room(synced, "join", room), "state_after");
                REQUIRE(event_types(after) == Keys{"m.room.topic"});
                REQUIRE(examined < 30U);
            }
        }
        WHEN("only a message arrives and alice syncs with use_state_after=true")
        {
            say(rt, alice, room, "hello");
            auto const before = store.state_rows_examined.value();
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);
            auto const examined = store.state_rows_examined.value() - before;

            THEN("state_after is empty, and far fewer than sixty state rows were read")
            {
                REQUIRE(events_of(required_room(synced, "join", room), "state_after").empty());
                REQUIRE(examined < 30U);
            }
        }
    }
}

// The parser accepts only the exact string `true`, as `full_state` does (ADR-0763).
SCENARIO("use_state_after is true only for the exact string true", "[integration][sync][state-after][flow]")
{
    GIVEN("a room alice has synced")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room = create_room(rt, alice, "public_chat");
        auto const initial = sync(rt, alice, k_no_filter);
        set_topic(rt, alice, room, "second");

        WHEN("the value is True, 1 or empty")
        {
            auto const capital = sync(rt, alice, k_no_filter, initial.next_batch, "&use_state_after=True");
            auto const one = sync(rt, alice, k_no_filter, initial.next_batch, "&use_state_after=1");
            auto const empty = sync(rt, alice, k_no_filter, initial.next_batch, "&use_state_after=");

            THEN("each is read as false: state is present and state_after is omitted")
            {
                require_state_only(required_room(capital, "join", room));
                require_state_only(required_room(one, "join", room));
                require_state_only(required_room(empty, "join", room));
            }
        }
        WHEN("the value is true")
        {
            auto const exact = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);

            THEN("state_after is present and state is omitted")
            {
                require_state_after_only(required_room(exact, "join", room));
            }
        }
    }
}

// ADR-0763: a client that joined inside the window held nothing of the room, so it is sent the whole state, with its
// own join, as an initial sync would. (The spec does not state it for an incremental sync.)
SCENARIO("state_after of a room joined in the window is the room's whole state",
         "[integration][sync][state-after][flow]")
{
    GIVEN("a room bob joins after his first sync")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const room = create_room(rt, alice, "public_chat");
        set_topic(rt, alice, room, "first");
        auto const initial = sync(rt, bob, k_no_filter, {}, k_state_after);
        room_post(rt, bob, room, "join");

        WHEN("bob syncs with use_state_after=true")
        {
            auto const synced = sync(rt, bob, k_no_filter, initial.next_batch, k_state_after);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after holds all state, his own join included, and state is omitted")
            {
                require_state_after_only(joined);
                auto const after = events_of(joined, "state_after");
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(topics_in(after) == std::vector<std::string>{"first"});
                REQUIRE(content_of(after, "m.room.member", user_id("bob"), "membership") == "join");
            }
        }
    }
}

// ADR-0765: the spec's Left Room `state_after` row does not name `full_state`, so a left room's `state_after` stays a
// delta, as its `state` does (ADR-0453).
SCENARIO("full_state=true leaves a left room's state_after a delta", "[integration][sync][state-after][flow]")
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

        WHEN("dave makes an incremental sync with full_state=true and use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_no_filter, synced_before.next_batch, k_full_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after is the delta: the topic and his leave, not the whole state")
            {
                require_state_after_only(left);
                auto const after = events_of(left, "state_after");
                REQUIRE_FALSE(event_types(after).contains("m.room.create"));
                REQUIRE(event_types(after) == Keys{"m.room.member", "m.room.topic"});
            }
        }
    }
}

// ADR-0765: a client that was not joined at `since` held nothing of the room, so a left room's `state_after` is the
// whole state as of the leave, not a delta that would hide the create event, power levels and join rules.
SCENARIO("A room joined and left inside one sync window gives state_after its whole readable state",
         "[integration][sync][state-after][flow]")
{
    GIVEN("a room dave joins and leaves after his last sync, in which the topic changed before he joined")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        auto const before = sync(rt, dave, k_no_filter, {}, k_state_after);
        set_topic(rt, alice, room, "before dave");
        room_post(rt, dave, room, "join");
        say(rt, dave, room, "hello and goodbye");
        room_post(rt, dave, room, "leave");
        set_topic(rt, alice, room, "after dave left");

        WHEN("dave syncs with use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_no_filter, before.next_batch, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after is the room as of his leave: create, power levels, join rules, the topic and his leave")
            {
                require_state_after_only(left);
                auto const after = events_of(left, "state_after");
                auto const types = event_types(after);
                REQUIRE(types.contains("m.room.create"));
                REQUIRE(types.contains("m.room.power_levels"));
                REQUIRE(types.contains("m.room.join_rules"));
                REQUIRE(topics_in(after) == std::vector<std::string>{"before dave"});
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "leave");
                REQUIRE(member_keys(after).count(user_id("dave")) == 1U);
            }
        }
        WHEN("dave syncs with lazy-loading and use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_lazy, before.next_batch, k_state_after);
            auto const after = events_of(required_room(synced, "leave", room), "state_after");

            THEN("the whole state comes with only his own membership, once, as the leave")
            {
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(member_keys(after).count(user_id("dave")) == 1U);
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "leave");
            }
        }
    }
    GIVEN("a room dave left and synced, then rejoined and left again before his next sync")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        room_post(rt, dave, room, "join");
        room_post(rt, dave, room, "leave");
        auto const after_first_leave = sync(rt, dave, k_no_filter, {}, k_state_after);
        room_post(rt, dave, room, "join");
        room_post(rt, dave, room, "leave");

        WHEN("dave syncs with use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_no_filter, after_first_leave.next_batch, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after is the whole readable state as of the second leave")
            {
                auto const after = events_of(left, "state_after");
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "leave");
            }
        }
    }
    GIVEN("a room dave was joined in at his last sync and left after its topic changed")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        room_post(rt, dave, room, "join");
        auto const joined = sync(rt, dave, k_no_filter, {}, k_state_after);
        set_topic(rt, alice, room, "changed");
        room_post(rt, dave, room, "leave");

        WHEN("dave syncs with use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_no_filter, joined.next_batch, k_state_after);
            auto const after = events_of(required_room(synced, "leave", room), "state_after");

            THEN("state_after is still the delta, as the client holds the rest of the state")
            {
                REQUIRE_FALSE(event_types(after).contains("m.room.create"));
                REQUIRE(event_types(after) == Keys{"m.room.member", "m.room.topic"});
            }
        }
    }
    GIVEN("a private room erin was invited to and declined inside one window")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const erin = register_user(rt, "erin");
        auto const room = create_room(rt, alice, "private_chat");
        auto const before = sync(rt, erin, k_no_filter, {}, k_state_after);
        room_post(rt, alice, room, "invite", R"({"user_id":")" + user_id("erin") + R"("})");
        room_post(rt, erin, room, "leave");

        WHEN("erin syncs with use_state_after=true")
        {
            auto const synced = sync(rt, erin, k_no_filter, before.next_batch, k_state_after);
            auto const after = events_of(required_room(synced, "leave", room), "state_after");

            THEN("she is told only her own leave, as she never could read the room")
            {
                REQUIRE(event_types(after) == Keys{"m.room.member"});
                REQUIRE(content_of(after, "m.room.member", user_id("erin"), "membership") == "leave");
            }
        }
    }
}

// ADR-0450: a lost response must not make the server think the client holds a member it never received.
SCENARIO("A lazy-loaded member whose response was lost is sent again in state_after",
         "[integration][sync][state-after][flow]")
{
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

        WHEN("the response that carried carol's membership is lost and the client retries")
        {
            auto const first = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            say(rt, carol, room, "carol again");
            auto const lost = sync(rt, alice, k_lazy, first.next_batch, k_state_after);
            REQUIRE(member_keys(events_of(required_room(lost, "join", room), "state_after")) == Keys{user_id("carol")});
            auto const retried = sync(rt, alice, k_lazy, first.next_batch, k_state_after);

            THEN("it is sent again")
            {
                REQUIRE(member_keys(events_of(required_room(retried, "join", room), "state_after")) ==
                        Keys{user_id("carol")});
            }
        }
        WHEN("the client acknowledged bob, and bob leaves and rejoins")
        {
            auto const bob_first = sync(rt, bob, k_lazy, {}, k_state_after);
            say(rt, alice, room, "alice");
            auto const bob_second = sync(rt, bob, k_lazy, bob_first.next_batch, k_state_after);
            auto const bob_third = sync(rt, bob, k_lazy, bob_second.next_batch, k_state_after);
            room_post(rt, bob, room, "leave");
            auto const bob_left = sync(rt, bob, k_lazy, bob_third.next_batch, k_state_after);
            room_post(rt, bob, room, "join");
            say(rt, alice, room, "welcome back");
            auto const rejoined = sync(rt, bob, k_lazy, bob_left.next_batch, k_state_after);
            auto const after = events_of(required_room(rejoined, "join", room), "state_after");

            THEN("the tracker is not consulted, and his own join is in state_after though the timeline carries it")
            {
                REQUIRE(member_keys(after).contains(user_id("alice")));
                REQUIRE(content_of(after, "m.room.member", user_id("bob"), "membership") == "join");
                REQUIRE(event_types(after).contains("m.room.create"));
            }
        }
    }
}
