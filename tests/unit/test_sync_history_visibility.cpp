// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for sync::HistoryVisibility and sync::room_read_access_for (CSAZ-2, CSAZ-3).
//
// Spec (client-server-api.md, "Room History Visibility", server behaviour): "By default if no
// `history_visibility` is set, or if the value is not understood, the visibility is assumed to
// be `shared`. The rules governing whether a user is allowed to see an event depend on the state
// of the room at that event.
//   1. If the `history_visibility` was set to `world_readable`, allow.
//   2. If the user's `membership` was `join`, allow.
//   3. If `history_visibility` was set to `shared`, and the user joined the room at any point
//      after the event was sent, allow.
//   4. If the user's `membership` was `invite`, and the `history_visibility` was set to
//      `invited`, allow.
//   5. Otherwise, deny."
// These tests build the store directly (events, ADR-0064 state groups, state transitions) so
// each rule, the two special cases and every fail-closed path are exercised in isolation.

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/sync/history_visibility.hpp"
#include "merovingian/sync/room_read_access.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using merovingian::database::PersistentEvent;
using merovingian::database::PersistentStateGroup;
using merovingian::database::PersistentStateGroupStateEntry;
using merovingian::database::PersistentStore;
using merovingian::sync::HistoryVisibility;
using merovingian::sync::HistoryVisibilityValue;
using merovingian::sync::RoomReadKind;

constexpr auto room = std::string_view{"!room:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};

auto add_event(PersistentStore& store, std::string_view event_id, std::string_view json, std::uint64_t ordering,
               std::string_view status = "accepted") -> void
{
    auto event = PersistentEvent{};
    event.event_id = std::string{event_id};
    event.room_id = std::string{room};
    event.sender_user_id = "@alice:example.org";
    event.json = std::string{json};
    event.stream_ordering = ordering;
    event.status = std::string{status};
    store.events.push_back(std::move(event));
}

[[nodiscard]] auto visibility_json(std::string_view value) -> std::string
{
    return R"({"type":"m.room.history_visibility","state_key":"","content":{"history_visibility":")" +
           std::string{value} + R"("}})";
}

[[nodiscard]] auto member_json(std::string_view user, std::string_view membership) -> std::string
{
    return R"({"type":"m.room.member","state_key":")" + std::string{user} + R"(","content":{"membership":")" +
           std::string{membership} + R"("}})";
}

auto add_group(PersistentStore& store, std::string_view group_id, std::optional<std::string> parent,
               std::vector<std::pair<std::pair<std::string, std::string>, std::string>> entries) -> void
{
    store.state_groups.push_back({std::string{group_id}, std::string{room}, std::move(parent), 0U});
    for (auto& [key, event_id] : entries)
    {
        store.state_group_state.push_back(
            {std::string{group_id}, std::move(key.first), std::move(key.second), std::move(event_id)});
    }
}

auto map_event(PersistentStore& store, std::string_view event_id, std::string_view group_id) -> void
{
    store.event_state_groups.push_back({std::string{event_id}, std::string{group_id}});
}

auto add_transition(PersistentStore& store, std::string_view type, std::string_view state_key,
                    std::string_view event_id, std::string_view previous_event_id) -> void
{
    store.state_transitions.push_back({std::string{room}, std::string{type}, std::string{state_key},
                                       std::string{event_id}, std::string{previous_event_id}});
    merovingian::database::rebuild_state_transition_index(store);
}

// A room with one message ("$msg", ordering 10) whose state has the given visibility and bob's
// membership, and optionally a later join of bob ("$later", ordering 20).
struct Timeline final
{
    PersistentStore store{};
};

[[nodiscard]] auto timeline(std::string_view visibility, std::string_view membership, bool joins_later) -> Timeline
{
    auto result = Timeline{};
    auto& store = result.store;
    add_event(store, "$vis", visibility_json(visibility), 1U);
    add_event(store, "$member", member_json(bob, membership), 2U);
    add_event(store, "$msg", R"({"type":"m.room.message","content":{"body":"x"}})", 10U);
    add_group(store, "g1", std::nullopt,
              {
                  {{"m.room.history_visibility", ""},   "$vis"   },
                  {{"m.room.member", std::string{bob}}, "$member"}
    });
    map_event(store, "$msg", "g1");
    if (joins_later)
    {
        add_event(store, "$later", member_json(bob, "join"), 20U);
        add_group(store, "g2", "g1",
                  {
                      {{"m.room.member", std::string{bob}}, "$later"}
        });
        map_event(store, "$later", "g2");
    }
    return result;
}

[[nodiscard]] auto expected_by_rules(std::string_view visibility, std::string_view membership, bool joins_later) -> bool
{
    if (visibility == "world_readable")
    {
        return true; // rule 1
    }
    if (membership == "join")
    {
        return true; // rule 2
    }
    if (visibility == "shared" && joins_later)
    {
        return true; // rule 3
    }
    return membership == "invite" && visibility == "invited"; // rule 4, else rule 5
}

} // namespace

SCENARIO("parse_history_visibility reads the four values and treats anything else as shared",
         "[sync][history-visibility][csaz-3]")
{
    using merovingian::sync::parse_history_visibility;

    GIVEN("the wire values of m.room.history_visibility")
    {
        THEN("each of the four maps to itself")
        {
            REQUIRE(parse_history_visibility("world_readable") == HistoryVisibilityValue::world_readable);
            REQUIRE(parse_history_visibility("shared") == HistoryVisibilityValue::shared);
            REQUIRE(parse_history_visibility("invited") == HistoryVisibilityValue::invited);
            REQUIRE(parse_history_visibility("joined") == HistoryVisibilityValue::joined);
        }

        THEN("a value that is not understood, or is empty or differently cased, is shared")
        {
            // Spec: "if the value is not understood, the visibility is assumed to be `shared`."
            REQUIRE(parse_history_visibility("banana") == HistoryVisibilityValue::shared);
            REQUIRE(parse_history_visibility("") == HistoryVisibilityValue::shared);
            REQUIRE(parse_history_visibility("JOINED") == HistoryVisibilityValue::shared);
        }
    }
}

SCENARIO("HistoryVisibility applies the five rules to the state at the event", "[sync][history-visibility][csaz-3]")
{
    GIVEN("every combination of visibility, the user's membership at the event, and a later join")
    {
        WHEN("the user asks whether they may see the event")
        {
            THEN("the answer is exactly what rules 1 to 5 give")
            {
                for (auto const* visibility : {"world_readable", "shared", "invited", "joined"})
                {
                    for (auto const* membership : {"join", "invite", "leave"})
                    {
                        for (auto const joins_later : {false, true})
                        {
                            INFO("visibility=" << visibility << " membership=" << membership
                                               << " joins_later=" << joins_later);
                            auto fixture = timeline(visibility, membership, joins_later);
                            auto filter = HistoryVisibility{fixture.store, bob};
                            REQUIRE(filter.can_see(fixture.store.events[2]) ==
                                    expected_by_rules(visibility, membership, joins_later));
                        }
                    }
                }
            }
        }
    }

    GIVEN("an event whose room has no history_visibility event at all")
    {
        auto store = PersistentStore{};
        add_event(store, "$member", member_json(bob, "leave"), 2U);
        add_event(store, "$msg", R"({"type":"m.room.message","content":{}})", 10U);
        add_event(store, "$later", member_json(bob, "join"), 20U);
        add_group(store, "g1", std::nullopt,
                  {
                      {{"m.room.member", std::string{bob}}, "$member"}
        });
        add_group(store, "g2", "g1",
                  {
                      {{"m.room.member", std::string{bob}}, "$later"}
        });
        map_event(store, "$msg", "g1");
        map_event(store, "$later", "g2");

        WHEN("bob, who joined afterwards, asks")
        {
            auto filter = HistoryVisibility{store, bob};

            THEN("the default, shared, lets him see it")
            {
                REQUIRE(filter.can_see_event_id("$msg"));
            }
        }
    }

    GIVEN("a visibility value the server does not understand")
    {
        auto fixture = timeline("banana", "leave", /*joins_later=*/true);

        WHEN("bob, who joined afterwards, asks")
        {
            auto filter = HistoryVisibility{fixture.store, bob};

            THEN("it is treated as shared")
            {
                REQUIRE(filter.can_see(fixture.store.events[2]));
            }
        }
    }

    GIVEN("a delta state group that overrides the visibility of its parent")
    {
        auto fixture = timeline("shared", "leave", /*joins_later=*/false);
        auto& store = fixture.store;
        add_event(store, "$vis2", visibility_json("world_readable"), 11U);
        add_event(store, "$msg2", R"({"type":"m.room.message","content":{}})", 12U);
        add_group(store, "g3", "g1",
                  {
                      {{"m.room.history_visibility", ""}, "$vis2"}
        });
        map_event(store, "$msg2", "g3");

        WHEN("bob, who is not a member, asks about an event before and one after the override")
        {
            auto filter = HistoryVisibility{store, bob};

            THEN("only the one after, in a world_readable state, is visible")
            {
                REQUIRE_FALSE(filter.can_see_event_id("$msg"));
                REQUIRE(filter.can_see_event_id("$msg2"));
            }
        }
    }
}

SCENARIO("HistoryVisibility fails closed when the state at an event cannot be determined",
         "[sync][history-visibility][csaz-3][security]")
{
    GIVEN("a room where bob is joined and the visibility is shared")
    {
        auto fixture = timeline("shared", "join", /*joins_later=*/false);
        auto& store = fixture.store;
        add_event(store, "$nogroup", R"({"type":"m.room.message","content":{}})", 11U);
        add_event(store, "$orphan", R"({"type":"m.room.message","content":{}})", 12U);
        add_group(store, "g-orphan", "g-missing-parent", {});
        map_event(store, "$orphan", "g-orphan");
        add_event(store, "$danglinggroup", R"({"type":"m.room.message","content":{}})", 13U);
        add_group(store, "g-dangling", std::nullopt,
                  {
                      {{"m.room.member", std::string{bob}}, "$no-such-event"}
        });
        map_event(store, "$danglinggroup", "g-dangling");
        add_event(store, "$cycle", R"({"type":"m.room.message","content":{}})", 14U);
        add_group(store, "g-cycle-a", "g-cycle-b", {});
        add_group(store, "g-cycle-b", "g-cycle-a", {});
        map_event(store, "$cycle", "g-cycle-a");

        WHEN("bob asks about events whose state is missing or broken")
        {
            auto filter = HistoryVisibility{store, bob};

            THEN("an event with a state group is visible, and every unresolvable one is not")
            {
                REQUIRE(filter.can_see_event_id("$msg"));
                REQUIRE_FALSE(filter.can_see_event_id("$nogroup"));       // no state group recorded
                REQUIRE_FALSE(filter.can_see_event_id("$orphan"));        // parent group is missing
                REQUIRE_FALSE(filter.can_see_event_id("$danglinggroup")); // names an event not in the store
                REQUIRE_FALSE(filter.can_see_event_id("$cycle"));         // parent links form a cycle
                REQUIRE_FALSE(filter.can_see_event_id("$unknown-event"));
            }
        }
    }

    GIVEN("rejected and soft-failed events that do have state")
    {
        auto fixture = timeline("world_readable", "join", /*joins_later=*/false);
        auto& store = fixture.store;
        add_event(store, "$rejected", R"({"type":"m.room.message","content":{}})", 11U, "rejected");
        add_event(store, "$softfailed", R"({"type":"m.room.message","content":{}})", 12U, "soft_failed");
        map_event(store, "$rejected", "g1");
        map_event(store, "$softfailed", "g1");

        WHEN("bob asks about them")
        {
            auto filter = HistoryVisibility{store, bob};

            THEN("they are never visible, whatever the state says")
            {
                REQUIRE_FALSE(filter.can_see_event_id("$rejected"));
                REQUIRE_FALSE(filter.can_see_event_id("$softfailed"));
                REQUIRE(filter.can_see_event_id("$msg"));
            }
        }
    }
}

SCENARIO("HistoryVisibility shows a history_visibility event when the visibility before or after allows",
         "[sync][history-visibility][csaz-3]")
{
    GIVEN("a visibility event that changed shared to joined, with bob joining later")
    {
        // State at the event has visibility `joined` and bob not joined (rule 2 and 3 fail
        // "after"); the visibility BEFORE was `shared`, and bob joined later (rule 3).
        auto store = PersistentStore{};
        add_event(store, "$vis-old", visibility_json("shared"), 1U);
        add_event(store, "$vis-new", visibility_json("joined"), 5U);
        add_event(store, "$member", member_json(bob, "leave"), 2U);
        add_event(store, "$later", member_json(bob, "join"), 20U);
        add_group(
            store, "g-new", std::nullopt,
            {
                {{"m.room.history_visibility", ""},   "$vis-new"},
                {{"m.room.member", std::string{bob}}, "$member" }
        });
        add_group(store, "g-later", "g-new",
                  {
                      {{"m.room.member", std::string{bob}}, "$later"}
        });
        map_event(store, "$vis-new", "g-new");
        map_event(store, "$later", "g-later");

        WHEN("the replaced event is recorded as the predecessor")
        {
            add_transition(store, "m.room.history_visibility", "", "$vis-new", "$vis-old");
            auto filter = HistoryVisibility{store, bob};

            THEN("bob sees it, because the visibility before it allowed")
            {
                REQUIRE(filter.can_see_event_id("$vis-new"));
            }
        }

        WHEN("no predecessor is recorded for it")
        {
            auto filter = HistoryVisibility{store, bob};

            THEN("only the state after it counts, and bob does not see it")
            {
                REQUIRE_FALSE(filter.can_see_event_id("$vis-new"));
            }
        }

        WHEN("the recorded predecessor is not in the store")
        {
            add_transition(store, "m.room.history_visibility", "", "$vis-new", "$vis-missing");
            auto filter = HistoryVisibility{store, bob};

            THEN("the before state is unknown and bob does not see it")
            {
                REQUIRE_FALSE(filter.can_see_event_id("$vis-new"));
            }
        }
    }
}

SCENARIO("HistoryVisibility shows the user's own membership events that start or end their join",
         "[sync][history-visibility][csaz-3]")
{
    GIVEN("a joined-only room where bob's leave event has a recorded join before it")
    {
        auto store = PersistentStore{};
        add_event(store, "$vis", visibility_json("joined"), 1U);
        add_event(store, "$join", member_json(bob, "join"), 3U);
        add_event(store, "$leave", member_json(bob, "leave"), 6U);
        add_event(store, "$other-leave", member_json("@carol:example.org", "leave"), 7U);
        add_group(store, "g-leave", std::nullopt,
                  {
                      {{"m.room.history_visibility", ""},   "$vis"  },
                      {{"m.room.member", std::string{bob}}, "$leave"}
        });
        map_event(store, "$leave", "g-leave");
        map_event(store, "$other-leave", "g-leave");
        add_transition(store, "m.room.member", std::string{bob}, "$leave", "$join");
        add_transition(store, "m.room.member", "@carol:example.org", "$other-leave", "$carol-join");

        WHEN("bob asks about his own leave and about carol's")
        {
            auto filter = HistoryVisibility{store, bob};

            THEN("his own is visible (membership before was join) and carol's is not")
            {
                REQUIRE(filter.can_see_event_id("$leave"));
                REQUIRE_FALSE(filter.can_see_event_id("$other-leave"));
            }
        }
    }

    GIVEN("a joined-only room where bob's invite has nothing before it")
    {
        auto store = PersistentStore{};
        add_event(store, "$vis", visibility_json("joined"), 1U);
        add_event(store, "$invite", member_json(bob, "invite"), 3U);
        add_group(store, "g-invite", std::nullopt,
                  {
                      {{"m.room.history_visibility", ""},   "$vis"   },
                      {{"m.room.member", std::string{bob}}, "$invite"}
        });
        map_event(store, "$invite", "g-invite");
        add_transition(store, "m.room.member", std::string{bob}, "$invite", "");

        WHEN("bob asks about it")
        {
            auto filter = HistoryVisibility{store, bob};

            THEN("neither his membership before (none) nor after (invite) allows it, under joined")
            {
                REQUIRE_FALSE(filter.can_see_event_id("$invite"));
            }
        }
    }
}

SCENARIO("room_read_access_for grants current, as-of-departure or no read access", "[sync][room-read-access][csaz-2]")
{
    using merovingian::sync::room_read_access_for;

    GIVEN("a membership chain join, leave for bob, recorded as state transitions")
    {
        auto store = PersistentStore{};
        add_event(store, "$join", member_json(bob, "join"), 3U);
        add_event(store, "$leave", member_json(bob, "leave"), 6U);
        store.state.push_back({std::string{room}, "m.room.member", std::string{bob}, "$leave"});
        add_transition(store, "m.room.member", std::string{bob}, "$join", "");
        add_transition(store, "m.room.member", std::string{bob}, "$leave", "$join");

        WHEN("the membership row says leave")
        {
            store.memberships.push_back({std::string{room}, std::string{bob}, "leave", 7U});
            auto const access = room_read_access_for(store, room, bob);

            THEN("bob reads as of the event that ended his join")
            {
                REQUIRE(access.kind == RoomReadKind::as_of);
                REQUIRE(access.boundary_event_id == "$leave");
                REQUIRE(access.boundary_ordering == 6U);
            }
        }

        WHEN("the membership row says ban")
        {
            store.memberships.push_back({std::string{room}, std::string{bob}, "ban", 7U});

            THEN("a ban is a departure too")
            {
                REQUIRE(room_read_access_for(store, room, bob).kind == RoomReadKind::as_of);
            }
        }

        WHEN("the membership row was deleted by /forget")
        {
            THEN("a forgotten room grants nothing")
            {
                REQUIRE(room_read_access_for(store, room, bob).kind == RoomReadKind::none);
            }
        }

        WHEN("the row says invite or knock")
        {
            store.memberships.push_back({std::string{room}, std::string{bob}, "invite", 7U});

            THEN("neither is membership")
            {
                REQUIRE(room_read_access_for(store, room, bob).kind == RoomReadKind::none);
                store.memberships.front().membership = "knock";
                REQUIRE(room_read_access_for(store, room, bob).kind == RoomReadKind::none);
            }
        }
    }

    GIVEN("a user whose only membership events are an invite and the leave that declined it")
    {
        auto store = PersistentStore{};
        add_event(store, "$invite", member_json(bob, "invite"), 3U);
        add_event(store, "$decline", member_json(bob, "leave"), 6U);
        store.state.push_back({std::string{room}, "m.room.member", std::string{bob}, "$decline"});
        add_transition(store, "m.room.member", std::string{bob}, "$invite", "");
        add_transition(store, "m.room.member", std::string{bob}, "$decline", "$invite");
        store.memberships.push_back({std::string{room}, std::string{bob}, "leave", 7U});

        WHEN("his access is classified")
        {
            THEN("a declined invite is none, never as-of")
            {
                REQUIRE(room_read_access_for(store, room, bob).kind == RoomReadKind::none);
            }
        }
    }

    GIVEN("a user who was banned straight after an invite, never having joined")
    {
        auto store = PersistentStore{};
        add_event(store, "$invite", member_json(bob, "invite"), 3U);
        add_event(store, "$ban", member_json(bob, "ban"), 6U);
        store.state.push_back({std::string{room}, "m.room.member", std::string{bob}, "$ban"});
        add_transition(store, "m.room.member", std::string{bob}, "$invite", "");
        add_transition(store, "m.room.member", std::string{bob}, "$ban", "$invite");
        store.memberships.push_back({std::string{room}, std::string{bob}, "ban", 7U});

        WHEN("his access is classified")
        {
            THEN("nothing is readable")
            {
                REQUIRE(room_read_access_for(store, room, bob).kind == RoomReadKind::none);
            }
        }
    }

    GIVEN("a user who joined, left, was invited again and declined")
    {
        auto store = PersistentStore{};
        add_event(store, "$join", member_json(bob, "join"), 3U);
        add_event(store, "$leave", member_json(bob, "leave"), 6U);
        add_event(store, "$invite", member_json(bob, "invite"), 8U);
        add_event(store, "$decline", member_json(bob, "leave"), 9U);
        store.state.push_back({std::string{room}, "m.room.member", std::string{bob}, "$decline"});
        add_transition(store, "m.room.member", std::string{bob}, "$join", "");
        add_transition(store, "m.room.member", std::string{bob}, "$leave", "$join");
        add_transition(store, "m.room.member", std::string{bob}, "$invite", "$leave");
        add_transition(store, "m.room.member", std::string{bob}, "$decline", "$invite");
        store.memberships.push_back({std::string{room}, std::string{bob}, "leave", 10U});

        WHEN("his access is classified")
        {
            auto const access = room_read_access_for(store, room, bob);

            THEN("the boundary is the leave that ended the join, not the later decline")
            {
                REQUIRE(access.kind == RoomReadKind::as_of);
                REQUIRE(access.boundary_event_id == "$leave");
            }
        }
    }

    GIVEN("a projection row saying leave while the room's state still says join")
    {
        auto store = PersistentStore{};
        add_event(store, "$join", member_json(bob, "join"), 3U);
        store.state.push_back({std::string{room}, "m.room.member", std::string{bob}, "$join"});
        store.memberships.push_back({std::string{room}, std::string{bob}, "leave", 7U});

        WHEN("his access is classified")
        {
            THEN("the contradiction fails closed")
            {
                REQUIRE(room_read_access_for(store, room, bob).kind == RoomReadKind::none);
            }
        }
    }

    GIVEN("a membership row that is missing while the state says join")
    {
        auto store = PersistentStore{};
        add_event(store, "$join", member_json(bob, "join"), 3U);
        store.state.push_back({std::string{room}, "m.room.member", std::string{bob}, "$join"});

        WHEN("his access is classified")
        {
            THEN("the current state's join still counts")
            {
                REQUIRE(room_read_access_for(store, room, bob).kind == RoomReadKind::current);
            }
        }
    }
}

SCENARIO("room_state_event_ids is bounded by what the access entitles the user to", "[sync][room-read-access][csaz-2]")
{
    using merovingian::sync::room_read_access_for;
    using merovingian::sync::room_state_event_ids;

    GIVEN("a room whose state changes at ordering 10 (before bob leaves at 20) and 30 (after)")
    {
        auto store = PersistentStore{};
        add_event(store, "$name-1", R"({"type":"m.room.name","state_key":"","content":{"name":"one"}})", 10U);
        add_event(store, "$leave", member_json(bob, "leave"), 20U);
        add_event(store, "$name-2", R"({"type":"m.room.name","state_key":"","content":{"name":"two"}})", 30U);
        add_group(store, "g1", std::nullopt,
                  {
                      {{"m.room.name", ""}, "$name-1"}
        });
        add_group(store, "g2", "g1",
                  {
                      {{"m.room.member", std::string{bob}}, "$leave"}
        });
        add_group(store, "g3", "g2",
                  {
                      {{"m.room.name", ""}, "$name-2"}
        });
        map_event(store, "$name-1", "g1");
        map_event(store, "$leave", "g2");
        map_event(store, "$name-2", "g3");
        store.state.push_back({std::string{room}, "m.room.name", "", "$name-2"});
        store.state.push_back({std::string{room}, "m.room.member", std::string{bob}, "$leave"});

        auto const as_of = merovingian::sync::RoomReadAccess{RoomReadKind::as_of, "$leave", 20U};
        auto const current = merovingian::sync::RoomReadAccess{RoomReadKind::current, {}, 0U};
        auto const none = merovingian::sync::RoomReadAccess{};

        auto const contains = [](std::optional<std::vector<std::string>> const& ids, std::string_view id) {
            return ids.has_value() && std::ranges::find(*ids, id) != ids->end();
        };

        WHEN("a departed user asks, with and without an at position past their departure")
        {
            auto const without_at = room_state_event_ids(store, room, as_of, std::nullopt);
            auto const far_future = room_state_event_ids(store, room, as_of, 9999U);

            THEN("both stop at the event that ended their join")
            {
                REQUIRE(contains(without_at, "$name-1"));
                REQUIRE_FALSE(contains(without_at, "$name-2"));
                REQUIRE(contains(far_future, "$name-1"));
                REQUIRE_FALSE(contains(far_future, "$name-2"));
            }
        }

        WHEN("a joined user asks for the current state, and for the state at an earlier position")
        {
            auto const now = room_state_event_ids(store, room, current, std::nullopt);
            auto const earlier = room_state_event_ids(store, room, current, 15U);
            auto const before_everything = room_state_event_ids(store, room, current, 5U);

            THEN("each is the state at that point")
            {
                REQUIRE(contains(now, "$name-2"));
                REQUIRE(contains(earlier, "$name-1"));
                REQUIRE_FALSE(contains(earlier, "$name-2"));
                REQUIRE(before_everything.has_value());
                REQUIRE(before_everything->empty());
            }
        }

        WHEN("a user with no read access asks")
        {
            THEN("there is no state to read")
            {
                REQUIRE_FALSE(room_state_event_ids(store, room, none, std::nullopt).has_value());
            }
        }

        WHEN("the event at the boundary has no recorded state")
        {
            store.event_state_groups.clear();

            THEN("the state cannot be determined, so nothing is returned")
            {
                REQUIRE_FALSE(room_state_event_ids(store, room, as_of, std::nullopt).has_value());
            }
        }
    }
}

SCENARIO("HistoryVisibility judges an event with no state group by the user's own membership timeline",
         "[sync][history-visibility][csaz-3][security]")
{
    GIVEN("events with no state group and bob's membership chain join, leave, join")
    {
        auto store = PersistentStore{};
        add_event(store, "$join1", member_json(bob, "join"), 3U);
        add_event(store, "$before", R"({"type":"m.room.message","content":{}})", 4U);
        add_event(store, "$leave", member_json(bob, "leave"), 6U);
        add_event(store, "$away", R"({"type":"m.room.message","content":{}})", 7U);
        add_event(store, "$join2", member_json(bob, "join"), 9U);
        add_event(store, "$again", R"({"type":"m.room.message","content":{}})", 10U);
        add_event(store, "$early", R"({"type":"m.room.message","content":{}})", 1U);
        store.state.push_back({std::string{room}, "m.room.member", std::string{bob}, "$join2"});
        add_transition(store, "m.room.member", std::string{bob}, "$join1", "");
        add_transition(store, "m.room.member", std::string{bob}, "$leave", "$join1");
        add_transition(store, "m.room.member", std::string{bob}, "$join2", "$leave");

        WHEN("bob asks about each")
        {
            auto filter = HistoryVisibility{store, bob};

            THEN("only rule 2 applies: visible exactly when his latest membership at that point was join")
            {
                REQUIRE_FALSE(filter.can_see_event_id("$early"));
                REQUIRE(filter.can_see_event_id("$join1"));
                REQUIRE(filter.can_see_event_id("$before"));
                REQUIRE_FALSE(filter.can_see_event_id("$away"));
                REQUIRE(filter.can_see_event_id("$again"));
            }
        }
    }

    GIVEN("events with no state group and a membership chain whose predecessor is missing")
    {
        auto store = PersistentStore{};
        add_event(store, "$join", member_json(bob, "join"), 3U);
        add_event(store, "$msg", R"({"type":"m.room.message","content":{}})", 4U);
        store.state.push_back({std::string{room}, "m.room.member", std::string{bob}, "$join"});
        add_transition(store, "m.room.member", std::string{bob}, "$join", "$not-stored");

        WHEN("bob asks")
        {
            auto filter = HistoryVisibility{store, bob};

            THEN("the timeline cannot be determined, so nothing is visible")
            {
                REQUIRE_FALSE(filter.can_see_event_id("$msg"));
            }
        }
    }

    GIVEN("an event that HAS a state group alongside one that has none, in a joined-only room")
    {
        auto fixture = timeline("joined", "leave", /*joins_later=*/false);
        auto& store = fixture.store;
        add_event(store, "$join", member_json(bob, "join"), 3U);
        add_event(store, "$nogroup", R"({"type":"m.room.message","content":{}})", 11U);
        store.state.push_back({std::string{room}, "m.room.member", std::string{bob}, "$join"});
        add_transition(store, "m.room.member", std::string{bob}, "$join", "");

        WHEN("bob asks about both")
        {
            auto filter = HistoryVisibility{store, bob};

            THEN("the one with a group still gets the full check, the other the fallback")
            {
                REQUIRE_FALSE(filter.can_see_event_id("$msg")); // group says membership leave, visibility joined
                REQUIRE(filter.can_see_event_id("$nogroup"));   // no group: joined at that point
            }
        }
    }
}
