// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ForwardExtremityTable: a room's tips, counted by the server of each tip's sender, and the rule that decides
// whether an accepted event may become one (ADR-0602, refining ADR-0374), and the joint cap on the tips of senders
// without power, from which a power holder is exempt (C21, ADR-0695).

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
#include <utility>
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

namespace
{

auto const moderator = std::string{"@mod:honest.example.org"};
auto const banner = std::string{"@banner:honest.example.org"};
auto const member = std::string{"@carol:honest.example.org"};

[[nodiscard]] auto limits_with_caps(std::uint32_t per_server, std::uint32_t unprivileged)
    -> merovingian::events::StateResolutionLimits
{
    auto config = merovingian::config::FederationStateResolutionConfig{};
    config.max_state_tips_per_server = per_server;
    config.max_unprivileged_state_tips = unprivileged;
    return merovingian::homeserver::state_resolution_limits(config);
}

auto add_room_state_event(PersistentStore& store, std::string const& event_id, std::string const& event_type,
                          std::string const& content) -> void
{
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = event_id;
    event.room_id = room;
    event.sender_user_id = moderator;
    event.json = R"({"type":")" + event_type + R"(","state_key":"","sender":")" + moderator + R"(","room_id":")" +
                 room + R"(","content":)" + content + "}";
    store.events.push_back(std::move(event));
    store.state.push_back({room, event_type, "", event_id});
}

// A version 10 room where the moderator may change the power levels (100), the banner may only ban (50), and
// everyone else holds the default 0.
auto add_moderated_room(PersistentStore& store) -> void
{
    add_room_state_event(store, "$create", "m.room.create",
                         R"({"room_version":"10","creator":")" + moderator + R"("})");
    add_room_state_event(store, "$power", "m.room.power_levels",
                         R"({"users":{")" + moderator + R"(":100,")" + banner +
                             R"(":50},"ban":50,"state_default":50,"events":{"m.room.power_levels":100}})");
}

// One tip of `room`, sent by `sender`, whose event the store holds.
auto add_sent_tip(PersistentStore& store, std::string const& event_id, std::string const& sender) -> void
{
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = event_id;
    event.room_id = room;
    event.sender_user_id = sender;
    store.events.push_back(std::move(event));
    REQUIRE(store.forward_extremities.insert({room, event_id}, sender));
    store.event_state_groups.assign(event_id, "sg:" + event_id);
}

// One tip from each of `count` server names one operator runs, each well under the per-server cap.
auto add_tips_from_many_servers(PersistentStore& store, int count) -> void
{
    for (auto index = 0; index < count; ++index)
    {
        auto const name = std::to_string(index);
        add_sent_tip(store, "$s" + name, "@m:h" + name + ".hostile.example.org");
    }
}

} // namespace

SCENARIO("Senders without power share one cap on a room's tips, however many server names they run",
         "[pdu_ingestion][state_groups][tip_cap][unprivileged_tip_cap][boundary]")
{
    auto const limits = limits_with_caps(2U, 4U);
    auto const fresh_server_sender = std::string{"@m:h99.hostile.example.org"};

    GIVEN("a moderated room whose tips come one each from three server names, one fewer than the joint cap")
    {
        auto store = PersistentStore{};
        add_moderated_room(store);
        add_tips_from_many_servers(store, 3);

        WHEN("a sender without power from yet another server name sends a state event citing no tip")
        {
            auto const allowed =
                event_may_become_forward_extremity(store, room, fresh_server_sender, {"$old"}, true, limits);

            THEN("it becomes a tip: at the cap it is served")
            {
                REQUIRE(allowed);
            }
        }
    }

    GIVEN("a moderated room whose tips come one each from four server names, exactly the joint cap")
    {
        auto store = PersistentStore{};
        add_moderated_room(store);
        add_tips_from_many_servers(store, 4);

        WHEN("senders try to add tips")
        {
            auto const fresh_server =
                event_may_become_forward_extremity(store, room, fresh_server_sender, {"$old"}, true, limits);
            auto const honest_member = event_may_become_forward_extremity(store, room, member, {"$old"}, true, limits);
            auto const citing_tip =
                event_may_become_forward_extremity(store, room, fresh_server_sender, {"$old", "$s0"}, true, limits);
            auto const from_moderator =
                event_may_become_forward_extremity(store, room, moderator, {"$old"}, true, limits);
            auto const from_banner = event_may_become_forward_extremity(store, room, banner, {"$old"}, true, limits);

            THEN("a further sender without power is refused, whichever server it names")
            {
                REQUIRE_FALSE(fresh_server);
                REQUIRE_FALSE(honest_member);
            }

            THEN("an event citing a current tip replaces it and is still served")
            {
                REQUIRE(citing_tip);
            }

            THEN("a moderator's tip is never refused, nor one from a sender who may only ban")
            {
                REQUIRE(from_moderator);
                REQUIRE(from_banner);
            }
        }
    }

    GIVEN("a moderated room where senders without power fill the joint cap and the moderators' server holds one tip")
    {
        auto store = PersistentStore{};
        add_moderated_room(store);
        add_tips_from_many_servers(store, 4);
        add_sent_tip(store, "$m0", moderator);
        REQUIRE(store.forward_extremities.count_for_sender_server(room, moderator) == 1U);

        WHEN("the moderator, the banner and an unprivileged user of the same server send state events citing no tip")
        {
            auto const from_moderator =
                event_may_become_forward_extremity(store, room, moderator, {"$old"}, true, limits);
            auto const from_banner = event_may_become_forward_extremity(store, room, banner, {"$old"}, true, limits);
            auto const from_member = event_may_become_forward_extremity(store, room, member, {"$old"}, true, limits);

            THEN("the power holders are admitted past the joint cap and the member is not")
            {
                REQUIRE(from_moderator);
                REQUIRE(from_banner);
                REQUIRE_FALSE(from_member);
            }
        }

        WHEN("the moderators' own server then holds its own cap")
        {
            add_sent_tip(store, "$m1", banner);
            auto const from_moderator =
                event_may_become_forward_extremity(store, room, moderator, {"$old"}, true, limits);

            THEN("its own tips, which no other server can add, refuse it as for any server (ADR-0602)")
            {
                REQUIRE_FALSE(from_moderator);
            }
        }
    }

    GIVEN("a moderated room holding more tips than the joint cap, of which only three are from senders without power")
    {
        auto store = PersistentStore{};
        add_moderated_room(store);
        add_tips_from_many_servers(store, 3);
        add_sent_tip(store, "$m0", moderator);
        add_sent_tip(store, "$m1", banner);
        REQUIRE(store.forward_extremities.count_for_room(room) == 5U);

        WHEN("a sender without power from another server name sends a state event citing no tip")
        {
            auto const allowed =
                event_may_become_forward_extremity(store, room, fresh_server_sender, {"$old"}, true, limits);

            THEN("it is served: a power holder's tips are not charged to the joint cap")
            {
                REQUIRE(allowed);
            }
        }

        WHEN("one more tip arrives whose event the store does not hold")
        {
            REQUIRE(store.forward_extremities.insert({room, "$unknown"}, "@m:h50.hostile.example.org"));
            auto const allowed =
                event_may_become_forward_extremity(store, room, fresh_server_sender, {"$old"}, true, limits);

            THEN("that tip counts as one without power and the joint cap is reached")
            {
                REQUIRE_FALSE(allowed);
            }
        }
    }
}
