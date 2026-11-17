// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// GET /_matrix/client/v3/sync `use_state_after`: what this project decides beyond the spec's rows, driven through the
// client-server stack (ADR-0818 to ADR-0820). What the spec states is in
// tests/conformance/test_sync_state_after_conformance.cpp.
#include "../support/JsonTestSupport.hpp"
#include "../support/StatePduSupport.hpp"
#include "../support/SyncStateAfterSupport.hpp"
#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/PduIngestionStatus.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"

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

constexpr auto k_topic_a = std::string_view{"$topic_a:example.org"};
constexpr auto k_topic_b = std::string_view{"$topic_b:example.org"};

// The event ID of the room's current `m.room.topic`, or "" when it has none.
[[nodiscard]] auto current_topic(ClientServerRuntime const& rt, std::string const& room) -> std::string
{
    return merovingian::database::find_current_state_event_id(rt.homeserver.database.persistent_store, room,
                                                              "m.room.topic", "")
        .value_or(std::string{});
}

// Forks alice's room through the ingestion path, so that the room's resolved state and the state recorded for its
// newest event disagree: topic A on the room's tip, then a name change after A and a topic B after A, each on its own
// branch. State resolution v2 orders the two topics, both at the same mainline position, by `origin_server_ts`, and A
// (9000) wins over B (2000): the room's topic is A, while B, the newest event, records topic B.
auto fork_between_two_topics(ClientServerRuntime& rt, std::string const& room) -> void
{
    namespace pdus = merovingian::tests::state_pdu_support;
    auto& hs = rt.homeserver;
    auto const& store = hs.database.persistent_store;
    auto const alice_id = user_id("alice");
    auto const auth_ids = std::vector<std::string>{
        merovingian::database::find_current_state_event_id(store, room, "m.room.power_levels", "").value_or(""),
        merovingian::database::find_current_state_event_id(store, room, "m.room.member", alice_id).value_or("")};
    auto const tips = store.forward_extremities.tips_of_room(room);
    REQUIRE(tips.size() == 1U);
    auto const accepted = [&](merovingian::federation::InboundPduEnvelope const& pdu) {
        REQUIRE(merovingian::homeserver::ingest_pdu_event(hs, pdu).status ==
                merovingian::federation::PduIngestionStatus::accepted);
    };
    accepted(pdus::make_topic_pdu(room, std::string{k_topic_a}, alice_id, "topic-A", {tips.front()}, auth_ids, 9000));
    auto name = Object{};
    name.push_back(
        merovingian::canonicaljson::make_member("name", merovingian::canonicaljson::Value{std::string{"witness"}}));
    accepted(pdus::make_state_pdu(room, "$witness:example.org", alice_id, "m.room.name", std::move(name),
                                  {std::string{k_topic_a}}, auth_ids, 2500));
    accepted(pdus::make_topic_pdu(room, std::string{k_topic_b}, alice_id, "topic-B", {std::string{k_topic_a}}, auth_ids,
                                  2000));
    REQUIRE(store.forward_extremities.tips_of_room(room).size() == 2U);
    REQUIRE(current_topic(rt, room) == k_topic_a);
}

} // namespace

// ADR-0818: a sync that finds nothing new in a joined room does not report it.
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

// ADR-0819: a delta chain is bounded (`max_state_group_delta_depth`); a window with more changes than it holds falls
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

// ADR-0819: the chain walk (`state_changes_along_chain`) answers a single-extremity room from the state groups alone.
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

// The parser accepts only the exact string `true`, as `full_state` does (ADR-0818).
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

// ADR-0818: a client that joined inside the window held nothing of the room, so it is sent the whole state, with its
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

// ADR-0820: the spec's Left Room `state_after` row does not name `full_state`, so a left room's `state_after` stays a
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

// ADR-0820: a client that was not joined at `since` held nothing of the room, so a left room's `state_after` is the
// whole state as of the leave, not a delta that would hide the create event, power levels and join rules.
//
// Each GIVEN is one way the join that the leave ended can fall relative to `since`: after it (a join and leave inside
// one window, the first GIVEN; a rejoin after an earlier departure, the second), before it (the third, which must stay
// a delta so the rule is not widened to every left room), or never at all (the fourth, an invite that was declined).
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
        // The sync that fixes `since` is taken before dave is in the room, so he holds none of its state.
        auto const before = sync(rt, dave, k_no_filter, {}, k_state_after);
        // A topic set before his join is state he is entitled to read, and the one a delta would wrongly leave out.
        set_topic(rt, alice, room, "before dave");
        room_post(rt, dave, room, "join");
        say(rt, dave, room, "hello and goodbye");
        room_post(rt, dave, room, "leave");
        // A change after the leave is beyond what he may read (ADR-0357), so it must not appear in his state_after.
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
                // The create event, power levels and join rules never changed in the window, so only a whole-state
                // answer, not a delta, sends them.
                REQUIRE(types.contains("m.room.create"));
                REQUIRE(types.contains("m.room.power_levels"));
                REQUIRE(types.contains("m.room.join_rules"));
                // The topic is the one in force at his leave: "before dave", not the later "after dave left".
                REQUIRE(topics_in(after) == std::vector<std::string>{"before dave"});
                // His own key is the current member event, the leave, and it appears once (ADR-0820).
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "leave");
                REQUIRE(member_keys(after).count(user_id("dave")) == 1U);
            }
        }
        // ADR-0820: a whole-state answer treats the room as new to the client, so lazy-loading does not consult the
        // tracker and does not send his membership a second time.
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
    // The join this leave ended began after `since` although dave had an earlier membership of the room: the rule
    // reads the join's ordering, not whether the room was ever known to him.
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
    // The control: he was joined at `since`, so he holds the room's state and a delta is correct. Without this case a
    // rule that made every left room whole would pass the scenarios above.
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
    // An invitee was never joined, so there is no join to cap the readable state at: the answer is only her own
    // membership (ADR-0820, a user who never joined), not the private room's state.
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

// The review of 1.1.1's `state_after` (ADR-0827): the client is told the room's resolved state. With the room forked at
// `since`, the state recorded for the newest event at or below `since` is one branch's, so a delta measured from it
// lost a key that resolution later moved back to that branch's value: neither the chain walk nor the fallback saw a
// difference, and a `state_after` client, which takes no state from the timeline, kept the old value.
SCENARIO("A state_after delta is exact when the room was forked at since",
         "[integration][sync][state-after][flow][state-change-log]")
{
    GIVEN("a forked room whose resolved topic is not the newest event's recorded topic, synced by alice")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room = create_room(rt, alice, "public_chat");
        fork_between_two_topics(rt, room);
        auto const initial = sync(rt, alice, k_no_filter, {}, k_state_after);
        REQUIRE(topics_in(events_of(required_room(initial, "join", room), "state_after")) ==
                std::vector<std::string>{"topic-A"});

        WHEN("a message arrives, resolution moves the topic back to B, and alice syncs with use_state_after=true")
        {
            say(rt, alice, room, "after the fork");
            // recompute_current_state writes a resolution's outcome through this writer.
            REQUIRE(merovingian::database::store_state(
                rt.homeserver.database.persistent_store,
                merovingian::database::PersistentStateEvent{room, "m.room.topic", "", std::string{k_topic_b}}));
            REQUIRE(current_topic(rt, room) == k_topic_b);
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);

            THEN("state_after holds topic B, which the room now has and alice was never told")
            {
                auto const after = events_of(required_room(synced, "join", room), "state_after");
                REQUIRE(topics_in(after) == std::vector<std::string>{"topic-B"});
            }
        }
        WHEN("only a message arrives and alice syncs with use_state_after=true")
        {
            say(rt, alice, room, "after the fork");
            REQUIRE(current_topic(rt, room) == k_topic_a);
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);

            THEN("state_after holds no topic: alice already has the room's topic")
            {
                auto const after = events_of(required_room(synced, "join", room), "state_after");
                REQUIRE(topics_in(after).empty());
            }
        }
    }
}

// ADR-0827: a delta reads the room's changes since `since` from the state change log, so a message in a forked room
// costs no read of the room's state, where the fallback this replaced read the whole of it twice.
SCENARIO("A state_after delta of a forked room with only a message reads none of the room's state",
         "[integration][sync][state-after][flow][state-change-log][state-index]")
{
    GIVEN("a forked room with sixty more state events, synced by alice")
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
        fork_between_two_topics(rt, room);
        auto const initial = sync(rt, alice, k_no_filter, {}, k_state_after);
        auto const& store = rt.homeserver.database.persistent_store;

        WHEN("a message arrives and alice syncs with use_state_after=true")
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

// ADR-0827: a left room's `state_after` is measured from the state the client was told at `since`, the resolved state,
// not the state recorded for the newest event at `since`, which on a forked room is one branch's.
SCENARIO("A left room's state_after is measured from what the client was told when the room was forked",
         "[integration][sync][state-after][flow][state-change-log]")
{
    GIVEN("a forked room bob was told the resolved topic of, and then left")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const room = create_room(rt, alice, "public_chat");
        room_post(rt, bob, room, "join");
        fork_between_two_topics(rt, room);
        auto const initial = sync(rt, bob, k_no_filter, {}, k_state_after);
        REQUIRE(topics_in(events_of(required_room(initial, "join", room), "state_after")) ==
                std::vector<std::string>{"topic-A"});
        room_post(rt, bob, room, "leave");
        REQUIRE(current_topic(rt, room) == k_topic_a);

        WHEN("bob syncs with use_state_after=true")
        {
            auto const synced = sync(rt, bob, k_no_filter, initial.next_batch, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after holds no topic, which bob already has, and his leave is reported")
            {
                auto const after = events_of(left, "state_after");
                REQUIRE(topics_in(after).empty());
                auto const timeline = events_of(left, "timeline");
                REQUIRE(member_keys(timeline).contains(user_id("bob")));
            }
        }
    }
}

// ADR-0827: a `since` answered before the change log started (an earlier process, or a database restored or upgraded
// from one) is not trusted for a delta: the room's whole state is sent once, and the next sync is a delta again.
SCENARIO("A state_after since from before the change log started gets the room's whole state once",
         "[integration][sync][state-after][flow][state-change-log]")
{
    GIVEN("a room alice synced before the server's change log started again, as at a restart")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room = create_room(rt, alice, "public_chat");
        auto const initial = sync(rt, alice, k_no_filter, {}, k_state_after);
        auto& store = rt.homeserver.database.persistent_store;
        store.state_change_log.start(merovingian::homeserver::visible_stream_position(rt.homeserver.database));

        WHEN("the topic changes and alice syncs from her old token")
        {
            set_topic(rt, alice, room, "after the restart");
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);

            THEN("state_after is the room's whole state")
            {
                auto const after = events_of(required_room(synced, "join", room), "state_after");
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(topics_in(after) == std::vector<std::string>{"after the restart"});
            }

            AND_WHEN("only a message arrives and she syncs from the new token")
            {
                say(rt, alice, room, "hello");
                auto const next = sync(rt, alice, k_no_filter, synced.next_batch, k_state_after);

                THEN("state_after is a delta again, and empty")
                {
                    REQUIRE(events_of(required_room(next, "join", room), "state_after").empty());
                }
            }
        }
    }
}
