// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ForwardExtremityTable: a room's tips, counted by the server of each tip's sender, and the rule that decides
// whether an accepted event may become one (ADR-0602, refining ADR-0374).

#include "merovingian/config/FederationStateResolutionConfig.hpp"
#include "merovingian/database/ForwardExtremityTable.hpp"
#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/StateResolutionLimits.hpp"
#include "merovingian/homeserver/StateBookkeeping.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using merovingian::database::ForwardExtremityTable;
using merovingian::database::PersistentStore;
using merovingian::homeserver::event_may_become_forward_extremity;

auto const room = std::string{"!room:example.org"};
auto const hostile = std::string{"@mallory:hostile.example.org"};
auto const honest = std::string{"@alice:honest.example.org"};

[[nodiscard]] auto limits_with_cap(std::uint32_t cap, std::uint32_t max_state_groups = 1000U)
    -> merovingian::events::StateResolutionLimits
{
    auto config = merovingian::config::FederationStateResolutionConfig{};
    config.max_state_tips_per_server = cap;
    config.max_state_groups = max_state_groups;
    return merovingian::homeserver::state_resolution_limits(config);
}

// `count` tips of `room` sent by `sender`, each in a state group of its own.
auto add_tips(PersistentStore& store, std::string const& prefix, std::string const& sender, int count) -> void
{
    for (auto index = 0; index < count; ++index)
    {
        auto const event_id = prefix + std::to_string(index);
        REQUIRE(store.forward_extremities.insert({room, event_id}, sender));
        store.event_state_groups.assign(event_id, "sg:" + event_id);
    }
}

} // namespace

SCENARIO("ForwardExtremityTable counts a room's tips by the server of their sender", "[database][tip_cap]")
{
    GIVEN("a table holding tips from two servers in two rooms")
    {
        auto table = ForwardExtremityTable{};
        REQUIRE(table.insert({room, "$a"}, hostile));
        REQUIRE(table.insert({room, "$b"}, "@other:hostile.example.org"));
        REQUIRE(table.insert({room, "$c"}, honest));
        REQUIRE(table.insert({"!elsewhere:example.org", "$d"}, hostile));

        THEN("two users of one server count together, and another room is not charged")
        {
            REQUIRE(table.count_for_sender_server(room, hostile) == 2U);
            REQUIRE(table.count_for_sender_server(room, honest) == 1U);
            REQUIRE(table.count_for_sender_server("!elsewhere:example.org", hostile) == 1U);
            REQUIRE(table.count_for_room(room) == 3U);
            REQUIRE(table.size() == 4U);
        }

        THEN("a room's tips keep the order they arrived in")
        {
            REQUIRE(table.tips_of_room(room) == std::vector<std::string>{"$a", "$b", "$c"});
        }

        WHEN("the same tip is inserted again")
        {
            auto const added = table.insert({room, "$a"}, honest);

            THEN("nothing changes")
            {
                REQUIRE_FALSE(added);
                REQUIRE(table.count_for_sender_server(room, hostile) == 2U);
                REQUIRE(table.count_for_sender_server(room, honest) == 1U);
            }
        }

        WHEN("a tip is erased")
        {
            REQUIRE(table.erase(room, "$a"));

            THEN("its server is refunded and the rest keep their order")
            {
                REQUIRE(table.count_for_sender_server(room, hostile) == 1U);
                REQUIRE(table.tips_of_room(room) == std::vector<std::string>{"$b", "$c"});
                REQUIRE_FALSE(table.contains(room, "$a"));
                REQUIRE_FALSE(table.erase(room, "$a"));
            }
        }

        WHEN("a room is erased")
        {
            table.erase_room(room);

            THEN("only that room's tips go")
            {
                REQUIRE(table.size() == 1U);
                REQUIRE(table.count_for_room(room) == 0U);
                REQUIRE(table.count_for_sender_server(room, hostile) == 0U);
            }
        }

        WHEN("the servers are counted again from what the events say")
        {
            table.recount_servers([](std::string_view) {
                return honest;
            });

            THEN("every tip is charged to the named server")
            {
                REQUIRE(table.count_for_sender_server(room, honest) == 3U);
                REQUIRE(table.count_for_sender_server(room, hostile) == 0U);
            }
        }
    }
}

SCENARIO("Hydration charges each forward extremity to its event's sender", "[database][tip_cap]")
{
    GIVEN("a store whose tips were read before its events were indexed")
    {
        auto store = PersistentStore{};
        auto event = merovingian::database::PersistentEvent{};
        event.event_id = "$a";
        event.room_id = room;
        event.sender_user_id = hostile;
        store.events.push_back(event);
        REQUIRE(store.forward_extremities.insert({room, "$a"}, {}));
        REQUIRE(store.forward_extremities.count_for_sender_server(room, hostile) == 0U);

        WHEN("the servers are rebuilt")
        {
            merovingian::database::rebuild_forward_extremity_servers(store);

            THEN("the tip is charged to its sender's server")
            {
                REQUIRE(store.forward_extremities.count_for_sender_server(room, hostile) == 1U);
            }
        }
    }
}

SCENARIO("An accepted event is refused tip status only past its own server's cap",
         "[pdu_ingestion][state_groups][tip_cap][boundary]")
{
    GIVEN("a room where one server holds one tip fewer than its cap")
    {
        auto store = PersistentStore{};
        auto const limits = limits_with_cap(3U);
        add_tips(store, "$h", hostile, 2);

        THEN("the server's state event citing no tip is allowed")
        {
            REQUIRE(event_may_become_forward_extremity(store, room, hostile, {"$old"}, true, limits));
        }
    }

    GIVEN("a room where one server holds exactly its cap")
    {
        auto store = PersistentStore{};
        auto const limits = limits_with_cap(3U);
        add_tips(store, "$h", hostile, 3);

        THEN("the server's state event citing no tip is refused")
        {
            REQUIRE_FALSE(event_may_become_forward_extremity(store, room, hostile, {"$old"}, true, limits));
        }

        THEN("a state event from another user of that server is refused too")
        {
            REQUIRE_FALSE(
                event_may_become_forward_extremity(store, room, "@b:hostile.example.org", {"$old"}, true, limits));
        }

        THEN("a state event citing a current tip replaces it and is never refused")
        {
            REQUIRE(event_may_become_forward_extremity(store, room, hostile, {"$old", "$h1"}, true, limits));
        }

        THEN("another server's state event is not charged for those tips")
        {
            REQUIRE(event_may_become_forward_extremity(store, room, honest, {"$old"}, true, limits));
        }

        THEN("the same server in another room is not charged for them")
        {
            REQUIRE(
                event_may_become_forward_extremity(store, "!elsewhere:example.org", hostile, {"$old"}, true, limits));
        }

        THEN("its message that would add a state group of its own is refused")
        {
            store.event_state_groups.assign("$old", "sg:$old");
            REQUIRE_FALSE(event_may_become_forward_extremity(store, room, hostile, {"$old"}, false, limits));
        }

        THEN("its message in a state group a tip already holds adds no state and is allowed")
        {
            store.event_state_groups.assign("$old", "sg:$h1");
            REQUIRE(event_may_become_forward_extremity(store, room, hostile, {"$old"}, false, limits));
        }
    }

    GIVEN("a room holding as many tips as resolution allows, from one server under its cap")
    {
        auto store = PersistentStore{};
        auto const limits = limits_with_cap(10U, 3U);
        add_tips(store, "$h", hostile, 3);

        THEN("a message citing no tip is still refused (ADR-0374)")
        {
            REQUIRE_FALSE(event_may_become_forward_extremity(store, room, honest, {"$old"}, false, limits));
        }

        THEN("a state event from a server under its cap is still allowed (ADR-0374)")
        {
            REQUIRE(event_may_become_forward_extremity(store, room, honest, {"$old"}, true, limits));
        }
    }
}
