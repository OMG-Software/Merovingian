// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A copy of a PersistentStore carries everything the original holds. The copy operations were a
// hand-written member list, and `state_transitions` with its index was added later without joining
// it, so a copy answered every `find_state_transition` with nothing (`unsigned.replaces_state`,
// and the membership walks of history visibility and room read access). They are now defaulted
// (ADR-0523).

#include "merovingian/database/PersistentStateTransition.hpp"
#include "merovingian/database/PersistentStore.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>

namespace
{

[[nodiscard]] auto store_with_one_transition() -> merovingian::database::PersistentStore
{
    auto store = merovingian::database::PersistentStore{};
    store.state_transitions.push_back(merovingian::database::PersistentStateTransition{
        "!room:example.org", "m.room.member", "@alice:example.org", "$second", "$first"});
    merovingian::database::rebuild_state_transition_index(store);
    return store;
}

[[nodiscard]] auto previous_of_second(merovingian::database::PersistentStore const& store) -> std::string
{
    auto const* transition = merovingian::database::find_state_transition(store, "!room:example.org", "m.room.member",
                                                                          "@alice:example.org", "$second");
    return transition == nullptr ? std::string{} : transition->previous_event_id;
}

} // namespace

SCENARIO("A copied store keeps its state transitions and their index", "[database][persistence][store_copy]")
{
    GIVEN("a store holding one indexed state transition")
    {
        auto const store = store_with_one_transition();
        REQUIRE(previous_of_second(store) == "$first");

        WHEN("the store is copied by construction")
        {
            auto const copied = merovingian::database::PersistentStore{store};

            THEN("the copy finds the transition")
            {
                CHECK(copied.state_transitions.size() == 1U);
                CHECK(previous_of_second(copied) == "$first");
            }
        }

        WHEN("the store is copied by assignment over a store that held other transitions")
        {
            auto assigned = merovingian::database::PersistentStore{};
            assigned.state_transitions.push_back(merovingian::database::PersistentStateTransition{
                "!other:example.org", "m.room.topic", "", "$topic", ""});
            merovingian::database::rebuild_state_transition_index(assigned);
            assigned = store;

            THEN("the destination holds exactly the source's transitions")
            {
                CHECK(assigned.state_transitions.size() == 1U);
                CHECK(previous_of_second(assigned) == "$first");
                CHECK(merovingian::database::find_state_transition(assigned, "!other:example.org", "m.room.topic", "",
                                                                   "$topic") == nullptr);
            }
        }

        WHEN("a copy is moved")
        {
            auto copied = merovingian::database::PersistentStore{store};
            auto const moved = std::move(copied);

            THEN("the move destination still finds the transition")
            {
                CHECK(previous_of_second(moved) == "$first");
            }
        }
    }
}
