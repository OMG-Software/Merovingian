// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Run-3 C12 (ADR-0674). A recipient's to-device queue is bounded per device and per user, and a message that would pass
// a bound evicted the OLDEST rows, whoever sent them, so any local user or federated server could delete the
// Olm-encrypted room keys other senders had queued by sending enough messages. Policy: no sender (a local user, or a
// remote server for everything its users send) can stop another sender's message from being queued, by evicting it or
// by occupying the space it needs. A sender may hold at most half of a device's budget (and of the user's); a message
// from a sender at its share evicts that sender's own oldest row; a message that finds the budget full evicts the
// oldest row of the sender holding the most. A message from a sender under its share is never dropped. ADR-0618's rule
// (the oldest row across a user's devices goes first) holds per sender.
//
// Spec: client-server-api.md, "Send-to-Device messaging": "Servers should store pending messages for local users until
// they are successfully delivered". The spec states no limit; the bounds are ADR-0335 and ADR-0618 decisions.

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentToDeviceMessage.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;

[[nodiscard]] auto message_from(std::string_view sender, std::string_view device, std::size_t ordinal)
    -> db::PersistentToDeviceMessage
{
    return {0U,
            std::string{sender},
            "@bob:example.org",
            std::string{device},
            "m.room.encrypted",
            "{\"n\":" + std::to_string(ordinal) + "}"};
}

// A device queue capped at four rows (so a sender's share is two) and no user bound.
[[nodiscard]] auto bounded_store() -> db::PersistentStore
{
    auto store = db::PersistentStore{};
    store.local_server_name = "example.org";
    store.max_to_device_messages_per_user_device = 4U;
    store.max_to_device_bytes_per_user_device = 0U;
    store.max_to_device_messages_per_user = 0U;
    store.max_to_device_bytes_per_user = 0U;
    store.to_device_message_ttl_seconds = 0U;
    return store;
}

auto send(db::PersistentStore& store, std::string_view sender, std::string_view device, std::size_t first,
          std::size_t last) -> void
{
    for (auto ordinal = first; ordinal <= last; ++ordinal)
    {
        REQUIRE(db::enqueue_to_device_message(store, message_from(sender, device, ordinal)));
    }
}

[[nodiscard]] auto rows_from(db::PersistentStore const& store, std::string_view sender) -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(store.to_device_messages, [sender](auto const& row) {
        return row.sender_user_id == sender;
    }));
}

[[nodiscard]] auto holds(db::PersistentStore const& store, std::string_view sender, std::size_t ordinal) -> bool
{
    auto const content = "{\"n\":" + std::to_string(ordinal) + "}";
    return std::ranges::any_of(store.to_device_messages, [&](auto const& row) {
        return row.sender_user_id == sender && row.content_json == content;
    });
}

constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto mallory = std::string_view{"@mallory:example.org"};

} // namespace

SCENARIO("a sender that fills a device's queue first cannot stop another sender's message from being queued",
         "[database][to-device][security][c12]")
{
    GIVEN("a device queue capped at four rows that mallory has flooded with ten messages")
    {
        auto store = bounded_store();
        send(store, mallory, "DEV", 1U, 10U);

        WHEN("alice sends two room keys to the same device")
        {
            send(store, alice, "DEV", 1U, 2U);

            THEN("both are queued, and mallory's oldest rows were the ones evicted")
            {
                REQUIRE(holds(store, alice, 1U));
                REQUIRE(holds(store, alice, 2U));
                REQUIRE(rows_from(store, mallory) == 2U);
                REQUIRE(holds(store, mallory, 9U));
                REQUIRE(holds(store, mallory, 10U));
                REQUIRE(store.to_device_messages.size() == 4U);
            }
        }

        WHEN("a sender that holds nothing sends one message to a queue held full by one sender's share")
        {
            send(store, alice, "DEV", 1U, 1U);

            THEN("it is queued without evicting anything beyond the flooder's own oldest row")
            {
                REQUIRE(holds(store, alice, 1U));
                REQUIRE(holds(store, mallory, 10U));
            }
        }
    }

    GIVEN("a device queue holding two of alice's room keys")
    {
        auto store = bounded_store();
        send(store, alice, "DEV", 1U, 2U);

        WHEN("alice, at her share, sends three more and mallory floods ten")
        {
            send(store, alice, "DEV", 3U, 5U);
            send(store, mallory, "DEV", 1U, 10U);

            THEN("alice's own oldest rows went first, and mallory evicted only her own")
            {
                REQUIRE(rows_from(store, alice) == 2U);
                REQUIRE_FALSE(holds(store, alice, 1U));
                REQUIRE_FALSE(holds(store, alice, 3U));
                REQUIRE(holds(store, alice, 4U));
                REQUIRE(holds(store, alice, 5U));
                REQUIRE(rows_from(store, mallory) == 2U);
            }
        }
    }
}

SCENARIO("a full queue gives way to a sender under its share by evicting the largest holder's oldest row",
         "[database][to-device][security][c12]")
{
    GIVEN("a full device queue holding two rows each of alice (older) and mallory")
    {
        auto store = bounded_store();
        send(store, alice, "DEV", 1U, 2U);
        send(store, mallory, "DEV", 1U, 2U);

        WHEN("a third sender with no rows sends one message")
        {
            auto const newcomer = std::string_view{"@carol:example.org"};
            send(store, newcomer, "DEV", 1U, 1U);

            THEN("it is queued, and of the two equal holders the one with the oldest row loses that row")
            {
                REQUIRE(holds(store, newcomer, 1U));
                REQUIRE_FALSE(holds(store, alice, 1U));
                REQUIRE(holds(store, alice, 2U));
                REQUIRE(rows_from(store, mallory) == 2U);
                REQUIRE(store.to_device_messages.size() == 4U);
            }
        }
    }
}

SCENARIO("a remote server's users share one share, and one server cannot crowd out another server or a local user",
         "[database][to-device][security][c12]")
{
    GIVEN("a device queue flooded by three users of one remote server in one federation transaction")
    {
        auto store = bounded_store();
        auto flood = std::vector<db::PersistentToDeviceMessage>{};
        for (auto ordinal = std::size_t{1U}; ordinal <= 12U; ++ordinal)
        {
            auto const user = std::string{"@u"} + std::to_string(ordinal % 3U) + ":evil.example";
            flood.push_back(message_from(user, "DEV", ordinal));
        }
        REQUIRE(db::enqueue_to_device_messages(store, std::move(flood)));

        WHEN("a user of another remote server and a local user each send a room key")
        {
            REQUIRE(db::enqueue_to_device_message(store, message_from("@d:good.example", "DEV", 1U)));
            REQUIRE(db::enqueue_to_device_message(store, message_from(alice, "DEV", 1U)));

            THEN("both are queued and the flooding server holds only its share")
            {
                REQUIRE(holds(store, "@d:good.example", 1U));
                REQUIRE(holds(store, alice, 1U));
                auto from_evil = std::size_t{0U};
                for (auto const& row : store.to_device_messages)
                {
                    from_evil += static_cast<std::size_t>(row.sender_user_id.ends_with(":evil.example"));
                }
                REQUIRE(from_evil == 2U);
            }
        }
    }
}

SCENARIO("the per-user bound is shared out per sender and evicts the sender's oldest row across devices",
         "[database][to-device][security][c12]")
{
    GIVEN("a user capped at six rows: mallory holds two on a stale device and one on another, carol two on a third")
    {
        auto store = bounded_store();
        store.max_to_device_messages_per_user_device = 0U;
        store.max_to_device_messages_per_user = 6U;
        send(store, mallory, "OLD", 1U, 2U);
        send(store, mallory, "DEV1", 3U, 3U);
        send(store, "@carol:example.org", "DEV3", 1U, 2U);

        WHEN("alice sends a room key to the third device, then mallory, at her share, sends two more")
        {
            send(store, alice, "DEV3", 1U, 1U);
            send(store, mallory, "DEV1", 4U, 5U);

            THEN("alice's key and carol's rows are queued, and mallory's oldest rows went first, the stale device's "
                 "included")
            {
                REQUIRE(holds(store, alice, 1U));
                REQUIRE(rows_from(store, "@carol:example.org") == 2U);
                REQUIRE(rows_from(store, mallory) == 3U);
                REQUIRE_FALSE(holds(store, mallory, 1U));
                REQUIRE_FALSE(holds(store, mallory, 2U));
                REQUIRE(holds(store, mallory, 5U));
            }
        }
    }

    GIVEN("a user capped at six rows and flooded by mallory across two devices")
    {
        auto store = bounded_store();
        store.max_to_device_messages_per_user_device = 0U;
        store.max_to_device_messages_per_user = 6U;
        send(store, mallory, "OLD", 1U, 6U);
        send(store, mallory, "DEV1", 7U, 12U);

        WHEN("alice sends four room keys")
        {
            send(store, alice, "DEV1", 1U, 4U);

            THEN("all are queued up to her share of three, mallory's oldest rows making the room, then her own oldest "
                 "goes")
            {
                REQUIRE(rows_from(store, alice) == 3U);
                REQUIRE_FALSE(holds(store, alice, 1U));
                REQUIRE(holds(store, alice, 4U));
                REQUIRE(rows_from(store, mallory) == 3U);
                REQUIRE(holds(store, mallory, 12U));
            }
        }
    }
}

SCENARIO("shares are computed from the rows held, so a copied and re-indexed store behaves the same",
         "[database][to-device][security][c12]")
{
    GIVEN("a flooded device queue that is copied and re-indexed, as after a reload")
    {
        auto original = bounded_store();
        send(original, mallory, "DEV", 1U, 10U);
        auto store = original;
        db::rebuild_key_indexes(store);

        WHEN("alice sends a room key and mallory floods again")
        {
            send(store, alice, "DEV", 1U, 1U);
            send(store, mallory, "DEV", 11U, 20U);

            THEN("alice's key is still queued")
            {
                REQUIRE(holds(store, alice, 1U));
                REQUIRE(rows_from(store, mallory) == 2U);
            }
        }

        WHEN("the flooded device is deleted and the queue is rebuilt from nothing")
        {
            store.to_device_messages.clear();
            db::rebuild_key_indexes(store);
            send(store, alice, "DEV", 1U, 3U);

            THEN("alice, alone, may use the whole queue, so all three are held")
            {
                REQUIRE(rows_from(store, alice) == 3U);
                REQUIRE(holds(store, alice, 3U));
            }
        }
    }
}
