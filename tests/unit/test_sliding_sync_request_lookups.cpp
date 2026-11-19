// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run 3, finding C07: a sliding sync request learns the caller's rooms from the user's own rows, and the
// user's own receipt rows through the receipt index, however many rooms and lists it names (ADR-0665, ADR-0737).
//
// Spec: MSC4186 list `filters` (is_invite, is_encrypted, room_types) and the `by_notification_count` sort.

#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentInvite.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentReceipt.hpp"
#include "merovingian/database/PersistentRoom.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/SlidingSyncRequestLookups.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace sync = merovingian::sync;

constexpr auto alice = "@alice:example.org";

[[nodiscard]] auto room_name(std::size_t number) -> std::string
{
    return "!room" + std::to_string(number) + ":example.org";
}

auto add_state(db::PersistentStore& store, std::string const& room_id, std::string type, std::string event_id) -> void
{
    store.state.push_back(db::PersistentStateEvent{room_id, std::move(type), "", std::move(event_id)});
}

// `rooms` rooms: alice is joined to the even ones, invited to every fifth odd one, bob is joined to all. Every third
// room is encrypted and every room has a create event of type "m.space" when its number is divisible by four.
// `receipts` read receipts of other users, and one of alice's for room 0, all written through the store so the receipt
// index is in step.
[[nodiscard]] auto build_store(std::size_t rooms, std::size_t receipts) -> db::PersistentStore
{
    auto store = db::PersistentStore{};
    for (auto number = std::size_t{0U}; number < rooms; ++number)
    {
        auto const id = room_name(number);
        store.rooms.push_back(db::PersistentRoom{id, "@bob:example.org", false});
        store.memberships.push_back(db::PersistentMembership{id, "@bob:example.org", "join", number + 1U});
        if (number % 2U == 0U)
        {
            store.memberships.push_back(db::PersistentMembership{id, alice, "join", number + 1U});
        }
        else if (number % 5U == 0U)
        {
            store.memberships.push_back(db::PersistentMembership{id, alice, "invite", number + 1U});
        }
        if (number % 3U == 0U)
        {
            add_state(store, id, "m.room.encryption", "$enc" + std::to_string(number));
        }
        auto create = db::PersistentEvent{};
        create.event_id = "$create" + std::to_string(number);
        create.room_id = id;
        create.sender_user_id = "@bob:example.org";
        create.json = number % 4U == 0U ? R"({"type":"m.room.create","content":{"type":"m.space"}})"
                                        : R"({"type":"m.room.create","content":{}})";
        create.stream_ordering = number + 1U;
        store.events.push_back(std::move(create));
        add_state(store, id, "m.room.create", "$create" + std::to_string(number));
    }
    for (auto number = std::size_t{0U}; number < receipts; ++number)
    {
        auto receipt = db::PersistentReceipt{};
        receipt.room_id = room_name(number % rooms);
        receipt.user_id = "@reader" + std::to_string(number) + ":example.org";
        receipt.event_id = "$create" + std::to_string(number % rooms);
        REQUIRE(db::store_receipt(store, std::move(receipt)));
    }
    auto own = db::PersistentReceipt{};
    own.room_id = room_name(0U);
    own.user_id = alice;
    own.event_id = "$create0";
    REQUIRE(db::store_receipt(store, std::move(own)));
    db::rebuild_membership_index(store);
    db::rebuild_state_index(store);
    return store;
}

} // namespace

SCENARIO("A request's lookups answer the filters from the user's own rows", "[sync][sliding-sync][c07][unit]")
{
    GIVEN("sixty rooms of which alice is joined to thirty and invited to six")
    {
        auto const store = build_store(60U, 20U);
        auto lookups = sync::SlidingSyncRequestLookups{store, alice};

        WHEN("the joined rooms and the invites are asked for")
        {
            auto joined = lookups.joined_rooms();
            std::ranges::sort(joined);

            THEN("they are exactly alice's and only her own membership rows were read")
            {
                REQUIRE(joined.size() == 30U);
                REQUIRE(std::ranges::all_of(joined, [&](std::string const& id) {
                    return id != room_name(1U) && id != room_name(5U);
                }));
                REQUIRE(lookups.is_invited(room_name(5U)));
                REQUIRE_FALSE(lookups.is_invited(room_name(2U)));
                REQUIRE_FALSE(lookups.is_invited(room_name(7U)));
                REQUIRE(lookups.membership_rows_visited() == 36U);
                REQUIRE(lookups.room_rows_visited() == 60U);
            }
        }
        WHEN("only an invite and its filters are asked for, as a long-poll's wake check does")
        {
            auto const invited = lookups.is_invited(room_name(5U));
            auto const encrypted = lookups.is_encrypted(room_name(5U));
            auto const& type = lookups.room_type(room_name(5U));
            auto const direct = lookups.is_dm(room_name(5U));

            THEN("they are answered from alice's own rows, and the server's room table is never read")
            {
                REQUIRE(invited);
                REQUIRE_FALSE(encrypted);
                REQUIRE(type.empty());
                REQUIRE_FALSE(direct);
                REQUIRE(lookups.membership_rows_visited() == 36U);
                REQUIRE(lookups.room_rows_visited() == 0U);
            }
        }
        WHEN("encryption and room type are asked for every room")
        {
            auto encrypted = std::size_t{0U};
            auto spaces = std::size_t{0U};
            for (auto number = std::size_t{0U}; number < 60U; ++number)
            {
                encrypted += lookups.is_encrypted(room_name(number)) ? 1U : 0U;
                spaces += lookups.room_type(room_name(number)) == "m.space" ? 1U : 0U;
            }

            THEN("every third room is encrypted and every fourth is a space, except the two encrypted rooms alice is "
                 "only invited to, which answer from an invite that holds no stripped state here (ADR-0864)")
            {
                // Rooms 15 and 45 are encrypted and alice is invited to them; the invited rooms are odd, so none is
                // a space.
                REQUIRE(encrypted == 18U);
                REQUIRE(spaces == 15U);
            }
        }
    }
}

SCENARIO("A request's lookups keep a join row only for a room the store holds", "[sync][sliding-sync][unit]")
{
    GIVEN("alice joined to four rooms the store holds and holding a join row for a room it does not")
    {
        auto store = build_store(8U, 0U);
        store.memberships.push_back(db::PersistentMembership{"!gone:example.org", alice, "join", 99U});
        db::rebuild_membership_index(store);
        auto lookups = sync::SlidingSyncRequestLookups{store, alice};

        WHEN("the joined rooms are asked for twice")
        {
            auto const first = lookups.joined_rooms();
            auto const& second = lookups.joined_rooms();

            THEN("the room the store lacks is left out, in row order, and the room table is read once")
            {
                REQUIRE(first == std::vector<std::string>{room_name(0U), room_name(2U), room_name(4U), room_name(6U)});
                REQUIRE(second == first);
                REQUIRE(lookups.room_rows_visited() == 8U);
            }
        }
    }
}

SCENARIO("A request's lookups read only the user's own receipt rows", "[sync][sliding-sync][c07][c23][unit]")
{
    GIVEN("a store with 400 receipts of other users and one of alice's, over 200 rooms")
    {
        auto const store = build_store(200U, 400U);
        REQUIRE(store.receipts.size() == 401U);
        auto lookups = sync::SlidingSyncRequestLookups{store, alice};

        WHEN("the read markers of every room are asked for, twice")
        {
            auto const before = store.receipt_rows_examined.value();
            for (auto pass = 0; pass < 2; ++pass)
            {
                for (auto number = std::size_t{0U}; number < 200U; ++number)
                {
                    std::ignore = lookups.read_markers(room_name(number));
                }
            }

            auto const examined = store.receipt_rows_examined.value() - before;

            THEN("only alice's one row was examined, once: not the table, and not once per pass")
            {
                REQUIRE(examined == 1U);
            }
            THEN("alice's own receipt is the one that counts for her, and a room without one reads nothing")
            {
                REQUIRE(lookups.read_markers(room_name(0U)).unthreaded == 1U);
                REQUIRE(lookups.read_markers(room_name(2U)).unthreaded == 0U);
            }
        }
    }
}

// ADR-0864: a user only invited to a room may be told what the invite's stripped state says, never the room's current
// state or events. A list ranks and filters an invited room by its invite.
SCENARIO("A request's lookups answer an invited room from its invite, not from the room",
         "[sync][sliding-sync][invites][unit]")
{
    GIVEN("a room alice is invited to at position 7, now named Current, encrypted and a space, with a newer event, "
          "whose invite's stripped state names it Invited with a plain create event")
    {
        auto store = db::PersistentStore{};
        auto const id = room_name(1U);
        store.rooms.push_back(db::PersistentRoom{id, "@bob:example.org", false});
        store.memberships.push_back(db::PersistentMembership{id, alice, "invite", 7U});
        add_state(store, id, "m.room.encryption", "$enc");
        add_state(store, id, "m.room.create", "$create");
        add_state(store, id, "m.room.name", "$name");
        auto create = db::PersistentEvent{};
        create.event_id = "$create";
        create.room_id = id;
        create.sender_user_id = "@bob:example.org";
        create.json = R"({"type":"m.room.create","state_key":"","content":{"type":"m.space"}})";
        create.stream_ordering = 1U;
        store.events.push_back(std::move(create));
        auto name = db::PersistentEvent{};
        name.event_id = "$name";
        name.room_id = id;
        name.sender_user_id = "@bob:example.org";
        name.json = R"({"type":"m.room.name","state_key":"","content":{"name":"Current"}})";
        name.stream_ordering = 50U;
        store.events.push_back(std::move(name));
        auto invite = db::PersistentInvite{};
        invite.room_id = id;
        invite.user_id = alice;
        invite.sender_user_id = "@bob:example.org";
        invite.event_id = "$invite";
        invite.stream_ordering = 7U;
        invite.invite_state_events_json = {
            R"({"type":"m.room.create","state_key":"","sender":"@bob:example.org","content":{}})",
            R"({"type":"m.room.name","state_key":"","sender":"@bob:example.org","content":{"name":"Invited"}})"};
        auto const invite_stored = db::upsert_invite(store, std::move(invite));
        REQUIRE(invite_stored);
        db::rebuild_membership_index(store);
        db::rebuild_state_index(store);
        auto lookups = sync::SlidingSyncRequestLookups{store, alice};

        WHEN("its sort keys and filters are asked for")
        {
            auto const& room_name_key = lookups.room_name(id);
            auto const encrypted = lookups.is_encrypted(id);
            auto const& type = lookups.room_type(id);
            auto const recency = lookups.recency(id, {});

            THEN("each is the invite's: its stripped name and create event, and the invite's position")
            {
                REQUIRE(lookups.invited_rooms() == std::vector<std::string>{id});
                REQUIRE(room_name_key == "Invited");
                REQUIRE_FALSE(encrypted);
                REQUIRE(type.empty());
                REQUIRE(recency == 7U);
                REQUIRE(lookups.recency_rows_visited() == 0U);
            }
        }
        WHEN("the request withholds the invite")
        {
            lookups.withhold_invite(id);

            THEN("the room is no longer an invite of this request")
            {
                REQUIRE_FALSE(lookups.is_invited(id));
                REQUIRE(lookups.invited_rooms().empty());
            }
        }
    }
}
