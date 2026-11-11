// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run-2, F-13 (ADR-0336) and F-14 (ADR-0335).
//
// F-13: PUT /sendToDevice enqueued each message by walking the whole shared queue, with a scan of
// the batch's evictions for every row, all under runtime.mutex: O(queue x recipients^2). A batch now
// costs one pass over the queue, and one request names at most `max_send_to_device_deliveries`
// local deliveries.
//
// F-14: the queue was bounded in rows, never in bytes. A message is refused over
// `max_to_device_message_bytes` and a recipient's oldest rows are evicted past
// `max_to_device_bytes_per_user_device`.
//
// Spec: client-server-api.md, "Send-to-Device messaging": "Servers should store pending messages
// for local users until they are successfully delivered", and `/sendToDevice` sends "to all known
// devices" for `*`. The spec states no size or delivery limit; the limits are ADR-0335 and
// ADR-0336 decisions.

#include "../support/E2eeCapsSupport.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentToDeviceMessage.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using merovingian::database::PersistentStore;
using merovingian::database::PersistentToDeviceMessage;

// Content of exactly `bytes` bytes: {"p":"xxx..."}.
[[nodiscard]] auto content_of_size(std::size_t bytes) -> std::string
{
    auto const overhead = std::string_view{R"({"p":""})"}.size();
    REQUIRE(bytes > overhead);
    return std::string{R"({"p":")"} + std::string(bytes - overhead, 'x') + R"("})";
}

[[nodiscard]] auto message_to(std::string_view user, std::string_view device, std::string content)
    -> PersistentToDeviceMessage
{
    return {0U, "@alice:example.org", std::string{user}, std::string{device}, "m.test.message", std::move(content)};
}

[[nodiscard]] auto rows_for(PersistentStore const& store, std::string_view user, std::string_view device) -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const& row : store.to_device_messages)
    {
        if (row.target_user_id == user && row.target_device_id == device)
        {
            ++count;
        }
    }
    return count;
}

} // namespace

SCENARIO("one batch of to-device messages costs one pass over the queue, however many recipients it names",
         "[database][to-device][security][run2][f13]")
{
    GIVEN("fifty recipients, each already holding the per-device row cap of ten, and no age limit")
    {
        auto store = PersistentStore{};
        store.max_to_device_messages_per_user_device = 10U;
        store.max_to_device_bytes_per_user_device = 0U;
        store.to_device_message_ttl_seconds = 0U;
        auto constexpr recipients = std::size_t{50U};
        auto constexpr cap = std::size_t{10U};
        for (auto row = std::size_t{0U}; row < cap; ++row)
        {
            for (auto recipient = std::size_t{0U}; recipient < recipients; ++recipient)
            {
                REQUIRE(merovingian::database::enqueue_to_device_message(
                    store, message_to("@bob:example.org", "DEV" + std::to_string(recipient), R"({"n":1})")));
            }
        }
        REQUIRE(store.to_device_messages.size() == recipients * cap);

        WHEN("one batch sends a message to every recipient, each of which must evict a row")
        {
            auto batch = std::vector<PersistentToDeviceMessage>{};
            for (auto recipient = std::size_t{0U}; recipient < recipients; ++recipient)
            {
                batch.push_back(message_to("@bob:example.org", "DEV" + std::to_string(recipient), R"({"n":2})"));
            }
            auto const queue_rows = store.to_device_messages.size();
            auto const examined_before = store.to_device_rows_examined.value();
            REQUIRE(merovingian::database::enqueue_to_device_messages(store, std::move(batch)));
            auto const examined = store.to_device_rows_examined.value() - examined_before;

            THEN("the queue is walked a small constant number of times, not once per message")
            {
                // The old shape walked the whole queue once per message and scanned the batch's evictions
                // for every row: recipients x queue rows examined. One indexing pass, plus work on only
                // the batch recipients' own rows, is a few times the queue's size.
                REQUIRE(examined >= queue_rows);
                REQUIRE(examined <= 4U * (queue_rows + recipients));
            }
            THEN("every recipient still holds exactly the cap, with the newest message in place of its oldest")
            {
                for (auto recipient = std::size_t{0U}; recipient < recipients; ++recipient)
                {
                    REQUIRE(rows_for(store, "@bob:example.org", "DEV" + std::to_string(recipient)) == cap);
                }
                REQUIRE(store.to_device_messages.size() == recipients * cap);
                auto newest = std::size_t{0U};
                for (auto const& row : store.to_device_messages)
                {
                    newest += row.content_json == R"({"n":2})" ? 1U : 0U;
                }
                REQUIRE(newest == recipients);
            }
        }
    }
}

SCENARIO("a recipient's queued bytes are bounded, and the oldest rows go first",
         "[database][to-device][security][run2][f14]")
{
    GIVEN("a store allowing 100 queued bytes per recipient, no row cap and no age limit")
    {
        auto store = PersistentStore{};
        store.max_to_device_messages_per_user_device = 0U;
        store.to_device_message_ttl_seconds = 0U;
        store.max_to_device_message_bytes = 100U;
        store.max_to_device_bytes_per_user_device = 100U;
        REQUIRE(merovingian::database::enqueue_to_device_message(
            store, message_to("@carol:example.org", "CAROL", content_of_size(40U))));

        WHEN("three 40-byte messages are queued for one device")
        {
            for (auto ordinal = 0; ordinal < 3; ++ordinal)
            {
                REQUIRE(merovingian::database::enqueue_to_device_message(
                    store, message_to("@bob:example.org", "BOB", content_of_size(40U))));
            }

            THEN("only the two newest fit, the byte total is exact, and another recipient is untouched")
            {
                REQUIRE(rows_for(store, "@bob:example.org", "BOB") == 2U);
                REQUIRE(merovingian::database::to_device_queue_bytes(store, "@bob:example.org", "BOB") == 80U);
                REQUIRE(rows_for(store, "@carol:example.org", "CAROL") == 1U);
                REQUIRE(merovingian::database::to_device_queue_bytes(store, "@carol:example.org", "CAROL") == 40U);
            }
        }

        WHEN("a message whose content is over the per-message limit is offered")
        {
            auto const oversized = content_of_size(101U);

            THEN("it does not fit and the store refuses to queue it")
            {
                REQUIRE_FALSE(merovingian::database::to_device_content_fits(store, oversized));
                REQUIRE(merovingian::database::to_device_content_fits(store, content_of_size(100U)));
                REQUIRE_FALSE(merovingian::database::enqueue_to_device_message(
                    store, message_to("@bob:example.org", "BOB", oversized)));
                REQUIRE(rows_for(store, "@bob:example.org", "BOB") == 0U);
            }
        }

        WHEN("a device is acknowledged and the freed bytes are used again")
        {
            for (auto ordinal = 0; ordinal < 2; ++ordinal)
            {
                REQUIRE(merovingian::database::enqueue_to_device_message(
                    store, message_to("@bob:example.org", "BOB", content_of_size(40U))));
            }
            auto const first_sync = merovingian::database::drain_to_device_messages(store, "@bob:example.org", "BOB",
                                                                                    0U, store.next_sync_stream_id);
            REQUIRE(first_sync.size() == 2U);
            // A later sync acknowledges the rows the first one delivered.
            std::ignore = merovingian::database::drain_to_device_messages(
                store, "@bob:example.org", "BOB", store.next_sync_stream_id, store.next_sync_stream_id);
            auto const after_ack = merovingian::database::to_device_queue_bytes(store, "@bob:example.org", "BOB");
            for (auto ordinal = 0; ordinal < 2; ++ordinal)
            {
                REQUIRE(merovingian::database::enqueue_to_device_message(
                    store, message_to("@bob:example.org", "BOB", content_of_size(40U))));
            }

            THEN("acknowledged rows no longer count, so later messages are kept in full")
            {
                REQUIRE(after_ack < 80U);
                REQUIRE(rows_for(store, "@bob:example.org", "BOB") == 2U);
                REQUIRE(merovingian::database::to_device_queue_bytes(store, "@bob:example.org", "BOB") == 80U);
            }
        }
    }
}
