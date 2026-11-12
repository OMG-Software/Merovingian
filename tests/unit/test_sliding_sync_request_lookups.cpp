// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run 3, finding C07: a sliding sync request learns the caller's rooms from the user's own rows, and the
// receipts table once, however many rooms and lists it names (ADR-0665).
//
// Spec: MSC4186 list `filters` (is_invite, is_encrypted, room_types) and the `by_notification_count` sort.

#include "merovingian/database/PersistentEvent.hpp"
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
// `receipts` read receipts of bob's, and one of alice's for room 0.
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
        receipt.user_id = "@bob:example.org";
        receipt.event_id = "$create" + std::to_string(number % rooms);
        store.receipts.push_back(std::move(receipt));
    }
    auto own = db::PersistentReceipt{};
    own.room_id = room_name(0U);
    own.user_id = alice;
    own.event_id = "$create0";
    store.receipts.push_back(std::move(own));
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

            THEN("every third room is encrypted and every fourth is a space")
            {
                REQUIRE(encrypted == 20U);
                REQUIRE(spaces == 15U);
            }
        }
    }
}

SCENARIO("A request's lookups read the receipts table once for every room", "[sync][sliding-sync][c07][unit]")
{
    GIVEN("a store with 400 receipts and 200 rooms")
    {
        auto const store = build_store(200U, 400U);
        auto lookups = sync::SlidingSyncRequestLookups{store, alice};

        WHEN("the read markers of every room are asked for, twice")
        {
            for (auto pass = 0; pass < 2; ++pass)
            {
                for (auto number = std::size_t{0U}; number < 200U; ++number)
                {
                    std::ignore = lookups.read_markers(room_name(number));
                }
            }

            THEN("the receipts were visited once each, not once per room")
            {
                REQUIRE(lookups.receipt_rows_visited() == store.receipts.size());
            }
            THEN("alice's own receipt is the one that counts for her, and a room without one reads nothing")
            {
                REQUIRE(lookups.read_markers(room_name(0U)).unthreaded == 1U);
                REQUIRE(lookups.read_markers(room_name(2U)).unthreaded == 0U);
            }
        }
    }
}
