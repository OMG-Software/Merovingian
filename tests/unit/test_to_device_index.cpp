// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Release-gate audit, classic-sync to-device and key row scans (ADR-0618).
//
// The to-device queue of every user sat in one vector, and an enqueue, a drain and an erase each walked all of it
// under runtime.mutex. It is now indexed by (user, device) and by user, and one user's rows are bounded across all
// of their devices.
//
// Spec: client-server-api.md, "Send-to-Device messaging": "Servers should store pending messages for local users
// until they are successfully delivered". The spec states no limit; the bounds are ADR-0335 and ADR-0618 decisions.

#include "merovingian/database/PersistentFallbackKey.hpp"
#include "merovingian/database/PersistentOneTimeKey.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentToDeviceMessage.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;

constexpr auto newest = std::numeric_limits<std::uint64_t>::max();

[[nodiscard]] auto message_to(std::string_view user, std::string_view device, std::string content = R"({"n":1})")
    -> db::PersistentToDeviceMessage
{
    return {0U, "@sender:example.org", std::string{user}, std::string{device}, "m.test", std::move(content)};
}

[[nodiscard]] auto unbounded_store() -> db::PersistentStore
{
    auto store = db::PersistentStore{};
    store.max_to_device_messages_per_user_device = 0U;
    store.max_to_device_bytes_per_user_device = 0U;
    store.max_to_device_messages_per_user = 0U;
    store.max_to_device_bytes_per_user = 0U;
    store.to_device_message_ttl_seconds = 0U;
    return store;
}

// Other users' rows, written straight into the vector as a loaded table would be, then indexed as hydration does.
auto seed_other_users(db::PersistentStore& store, std::size_t rows) -> void
{
    for (auto row = std::size_t{0U}; row < rows; ++row)
    {
        auto message = message_to("@other" + std::to_string(row % 50U) + ":example.org", "DEV");
        message.stream_id = db::allocate_sync_stream_id(store);
        store.to_device_messages.push_back(std::move(message));
    }
    db::rebuild_key_indexes(store);
}

[[nodiscard]] auto rows_of(db::PersistentStore const& store, std::string_view user) -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(store.to_device_messages, [user](auto const& row) {
        return row.target_user_id == user;
    }));
}

} // namespace

SCENARIO("to-device work costs the recipient's own rows, whatever other users hold",
         "[database][to-device][security][gate-m-sync]")
{
    GIVEN("five thousand rows of other users and two rows for bob")
    {
        auto store = unbounded_store();
        store.max_to_device_messages_per_user_device = 100U;
        seed_other_users(store, 5000U);
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "BOB")));
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "BOB")));

        WHEN("one more message is queued for bob")
        {
            auto const before = store.to_device_rows_examined.value();
            REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "BOB")));

            THEN("only bob's rows were read")
            {
                REQUIRE(store.to_device_rows_examined.value() - before <= 4U);
            }
        }

        WHEN("bob's device drains its queue")
        {
            auto const before = store.to_device_rows_examined.value();
            auto const drained = db::drain_to_device_messages(store, "@bob:example.org", "BOB", 0U, newest);

            THEN("both rows come back and only they were read")
            {
                REQUIRE(drained.size() == 2U);
                REQUIRE(store.to_device_rows_examined.value() - before <= 2U);
            }
        }

        WHEN("bob acknowledges his rows")
        {
            auto const first = db::drain_to_device_messages(store, "@bob:example.org", "BOB", 0U, newest);
            REQUIRE(first.size() == 2U);
            auto const before = store.to_device_rows_examined.value();
            auto const again =
                db::drain_to_device_messages(store, "@bob:example.org", "BOB", first.back().stream_id, newest);

            THEN("they are removed for the cost of bob's rows, and every other row stays")
            {
                REQUIRE(again.empty());
                REQUIRE(store.to_device_rows_examined.value() - before <= 8U);
                REQUIRE(rows_of(store, "@bob:example.org") == 0U);
                REQUIRE(store.to_device_messages.size() == 5000U);
            }
        }

        WHEN("the long-poll asks whether bob's device has anything new")
        {
            auto const before = store.to_device_rows_examined.value();
            auto const has_new = db::has_to_device_message_after(store, "@bob:example.org", "BOB", 0U);

            THEN("the answer costs bob's rows only")
            {
                REQUIRE(has_new);
                REQUIRE(store.to_device_rows_examined.value() - before <= 2U);
            }
        }

        WHEN("the bytes of bob's queue are asked for")
        {
            auto const before = store.to_device_rows_examined.value();
            auto const bytes = db::to_device_queue_bytes(store, "@bob:example.org", "BOB");

            THEN("the total is exact and costs bob's rows only")
            {
                REQUIRE(bytes == 2U * std::string_view{R"({"n":1})"}.size());
                REQUIRE(store.to_device_rows_examined.value() - before <= 2U);
            }
        }
    }
}

SCENARIO("a device drains exactly what is addressed to it, in stream order, after rows moved",
         "[database][to-device][gate-m-sync]")
{
    GIVEN("rows for two devices and broadcast rows, with a row of another user acknowledged out of the middle")
    {
        auto store = unbounded_store();
        REQUIRE(db::enqueue_to_device_message(store, message_to("@carol:example.org", "C1", R"({"n":0})")));
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B1", R"({"n":1})")));
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B2", R"({"n":2})")));
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "*", R"({"n":3})")));
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "", R"({"n":4})")));
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B1", R"({"n":5})")));
        auto const carol = db::drain_to_device_messages(store, "@carol:example.org", "C1", 0U, newest);
        REQUIRE(carol.size() == 1U);
        std::ignore = db::drain_to_device_messages(store, "@carol:example.org", "C1", carol.front().stream_id, newest);
        REQUIRE(rows_of(store, "@carol:example.org") == 0U);

        WHEN("B1 drains")
        {
            auto const drained = db::drain_to_device_messages(store, "@bob:example.org", "B1", 0U, newest);

            THEN("it gets its own rows and the broadcasts, ascending, once each, and not B2's")
            {
                auto contents = std::vector<std::string>{};
                for (auto const& row : drained)
                {
                    contents.push_back(row.content_json);
                }
                REQUIRE(contents == std::vector<std::string>{R"({"n":1})", R"({"n":3})", R"({"n":4})", R"({"n":5})"});
                REQUIRE(std::ranges::is_sorted(drained, {}, &db::PersistentToDeviceMessage::stream_id));
            }
        }

        WHEN("a device named * asks, as a malformed caller might")
        {
            auto const drained = db::drain_to_device_messages(store, "@bob:example.org", "*", 0U, newest);

            THEN("the broadcast rows come back once each")
            {
                REQUIRE(drained.size() == 2U);
            }
        }

        WHEN("a row is pushed straight into the vector")
        {
            auto direct = message_to("@bob:example.org", "B2", R"({"n":6})");
            direct.stream_id = db::allocate_sync_stream_id(store);
            store.to_device_messages.push_back(std::move(direct));
            auto const drained = db::drain_to_device_messages(store, "@bob:example.org", "B2", 0U, newest);

            THEN("the stale index is not trusted and the row is delivered")
            {
                REQUIRE(drained.size() == 4U);
                REQUIRE(drained.back().content_json == R"({"n":6})");
            }
        }
    }
}

SCENARIO("one user's queued rows are bounded across all of their devices, the oldest going first",
         "[database][to-device][security][gate-m-sync]")
{
    GIVEN("a user limit of four rows, and three rows across two devices")
    {
        auto store = unbounded_store();
        store.max_to_device_messages_per_user = 4U;
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B1", R"({"n":1})")));
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B2", R"({"n":2})")));
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B1", R"({"n":3})")));

        WHEN("a fourth row is queued, exactly at the limit")
        {
            REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B3", R"({"n":4})")));

            THEN("nothing is evicted")
            {
                REQUIRE(rows_of(store, "@bob:example.org") == 4U);
            }
        }

        WHEN("two more rows go to a third device")
        {
            REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B3", R"({"n":4})")));
            REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B3", R"({"n":5})")));

            THEN("the user's oldest row goes, though another device holds it")
            {
                REQUIRE(rows_of(store, "@bob:example.org") == 4U);
                auto const b1 = db::drain_to_device_messages(store, "@bob:example.org", "B1", 0U, newest);
                REQUIRE(b1.size() == 1U);
                REQUIRE(b1.front().content_json == R"({"n":3})");
                REQUIRE(db::drain_to_device_messages(store, "@bob:example.org", "B2", 0U, newest).size() == 1U);
                REQUIRE(db::drain_to_device_messages(store, "@bob:example.org", "B3", 0U, newest).size() == 2U);
            }
        }

        WHEN("another user's queue fills")
        {
            for (auto row = 0; row < 6; ++row)
            {
                REQUIRE(db::enqueue_to_device_message(store, message_to("@carol:example.org", "C1")));
            }

            THEN("bob loses nothing to it")
            {
                REQUIRE(rows_of(store, "@bob:example.org") == 3U);
                REQUIRE(rows_of(store, "@carol:example.org") == 4U);
            }
        }

        WHEN("one batch names more rows for the user than the limit")
        {
            auto batch = std::vector<db::PersistentToDeviceMessage>{};
            for (auto row = 0; row < 6; ++row)
            {
                batch.push_back(message_to("@bob:example.org", "B" + std::to_string(row), R"({"n":9})"));
            }
            REQUIRE(db::enqueue_to_device_messages(store, std::move(batch)));

            THEN("the batch is bounded together, keeping its newest rows")
            {
                REQUIRE(rows_of(store, "@bob:example.org") == 4U);
                REQUIRE(std::ranges::all_of(store.to_device_messages, [](auto const& row) {
                    return row.content_json == R"({"n":9})";
                }));
            }
        }
    }

    GIVEN("a user limit of 20 bytes and two 7-byte rows on separate devices")
    {
        auto store = unbounded_store();
        store.max_to_device_bytes_per_user = 21U;
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B1", R"({"n":1})")));
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B2", R"({"n":2})")));

        WHEN("a third row brings the user exactly to the limit")
        {
            REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B3", R"({"n":3})")));

            THEN("all three stay")
            {
                REQUIRE(rows_of(store, "@bob:example.org") == 3U);
            }

            AND_WHEN("a fourth would pass it")
            {
                REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B4", R"({"n":4})")));

                THEN("the oldest goes")
                {
                    REQUIRE(rows_of(store, "@bob:example.org") == 3U);
                    REQUIRE(db::to_device_queue_bytes(store, "@bob:example.org", "B1") == 0U);
                }
            }
        }

        WHEN("one message is larger than the user's whole budget")
        {
            auto const accepted = db::enqueue_to_device_message(
                store, message_to("@bob:example.org", "B9", R"({"p":"xxxxxxxxxxxxxxxxxxxxxxxx"})"));

            THEN("it is refused and the rows already held stay")
            {
                REQUIRE_FALSE(accepted);
                REQUIRE(rows_of(store, "@bob:example.org") == 2U);
            }
        }
    }
}

SCENARIO("deleting a device drops its queue through the index", "[database][to-device][gate-m-sync]")
{
    GIVEN("a user with two devices, each with queued rows, among other users' rows")
    {
        auto store = unbounded_store();
        store.devices.push_back({"@bob:example.org", "B1", ""});
        store.devices.push_back({"@bob:example.org", "B2", ""});
        seed_other_users(store, 1000U);
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B1")));
        REQUIRE(db::enqueue_to_device_message(store, message_to("@bob:example.org", "B2")));

        WHEN("one device is deleted")
        {
            auto const before = store.to_device_rows_examined.value();
            REQUIRE(db::delete_device(store, "@bob:example.org", "B1"));

            THEN("its row goes for the cost of its own rows, and the other device still drains")
            {
                REQUIRE(store.to_device_rows_examined.value() - before <= 1U);
                REQUIRE(db::drain_to_device_messages(store, "@bob:example.org", "B1", 0U, newest).empty());
                REQUIRE(db::drain_to_device_messages(store, "@bob:example.org", "B2", 0U, newest).size() == 1U);
                REQUIRE(store.to_device_messages.size() == 1001U);
            }
        }
    }
}

SCENARIO("a device's one-time and fallback keys are read without the other devices' rows",
         "[database][keys][security][gate-m-sync]")
{
    GIVEN("a thousand keys of another device and bob's few")
    {
        auto store = db::PersistentStore{};
        for (auto key = 0; key < 1000; ++key)
        {
            auto const key_id = "signed_curve25519:" + std::to_string(key);
            store.one_time_keys.push_back({"@other:example.org", "OTHER", key_id, "{}"});
            store.fallback_keys.push_back({"@other:example.org", "OTHER", key_id, "{}"});
        }
        store.one_time_keys.push_back({"@bob:example.org", "BOB", "signed_curve25519:a", "{}"});
        store.one_time_keys.push_back({"@bob:example.org", "BOB", "signed_curve25519:b", "{}"});
        store.fallback_keys.push_back({"@bob:example.org", "BOB", "signed_curve25519:f", "{}"});
        db::rebuild_key_indexes(store);

        WHEN("bob's device's keys are visited")
        {
            auto one_time = std::size_t{0U};
            auto fallback = std::size_t{0U};
            auto const before = store.key_rows_examined.value();
            db::for_each_device_one_time_key(store, "@bob:example.org", "BOB", [&](db::PersistentOneTimeKey const&) {
                ++one_time;
            });
            db::for_each_device_fallback_key(store, "@bob:example.org", "BOB", [&](db::PersistentFallbackKey const&) {
                ++fallback;
            });

            THEN("exactly bob's rows are visited and read")
            {
                REQUIRE(one_time == 2U);
                REQUIRE(fallback == 1U);
                REQUIRE(store.key_rows_examined.value() - before == 3U);
            }
        }
    }
}
