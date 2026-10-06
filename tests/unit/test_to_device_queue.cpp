// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/persistent_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <thread>

namespace
{

[[nodiscard]] auto make_message(std::uint64_t ordinal, std::string_view target_user, std::string_view target_device)
    -> merovingian::database::PersistentToDeviceMessage
{
    return {0U,
            "@alice:example.org",
            std::string{target_user},
            std::string{target_device},
            "m.test.message",
            std::string{"{\"ordinal\":"} + std::to_string(ordinal) + "}"};
}

} // namespace

// CSAZ-10: the per-recipient to-device queue must be bounded so rows for a
// non-existent device cannot grow without limit.
SCENARIO("the per-recipient to-device queue drops the oldest rows once the cap is reached",
         "[database][sync][security][csaz-10]")
{
    GIVEN("a memory store with a per-recipient cap of 5")
    {
        auto store = merovingian::database::PersistentStore{};
        store.max_to_device_messages_per_user_device = 5U;
        store.to_device_message_ttl_seconds = 0U;

        WHEN("10 messages are enqueued for the same user and device")
        {
            for (auto ordinal = std::uint64_t{1U}; ordinal <= 10U; ++ordinal)
            {
                REQUIRE(merovingian::database::enqueue_to_device_message(
                    store, make_message(ordinal, "@bob:example.org", "BOB_DEVICE")));
            }

            THEN("only the 5 newest rows remain")
            {
                REQUIRE(store.to_device_messages.size() == 5U);
                REQUIRE(store.to_device_messages.front().content_json == "{\"ordinal\":6}");
                REQUIRE(store.to_device_messages.back().content_json == "{\"ordinal\":10}");
            }
        }
    }
}

// CSAZ-10: rows older than the configured TTL must be evicted even if the
// recipient has never acknowledged them (for example, because the device does
// not exist).
SCENARIO("to-device rows are evicted once the TTL expires", "[database][sync][security][csaz-10]")
{
    GIVEN("a memory store with a 1-second to-device TTL")
    {
        auto store = merovingian::database::PersistentStore{};
        store.max_to_device_messages_per_user_device = 0U;
        store.to_device_message_ttl_seconds = 1U;

        WHEN("a message is enqueued and the TTL passes before it is drained")
        {
            REQUIRE(merovingian::database::enqueue_to_device_message(
                store, make_message(1U, "@bob:example.org", "BOB_DEVICE")));
            REQUIRE(store.to_device_messages.size() == 1U);
            std::this_thread::sleep_for(std::chrono::milliseconds{1200});

            auto const drained = merovingian::database::drain_to_device_messages(
                store, "@bob:example.org", "BOB_DEVICE", 0U, store.next_sync_stream_id);

            THEN("the expired row is purged and not returned")
            {
                REQUIRE(drained.empty());
                REQUIRE(store.to_device_messages.empty());
            }
        }
    }
}

// CSAZ-10: the cap is per recipient; a different user/device pair must not
// cause another recipient's rows to be dropped.
SCENARIO("the per-recipient to-device cap is isolated by user and device", "[database][sync][security][csaz-10]")
{
    GIVEN("a memory store with a per-recipient cap of 3")
    {
        auto store = merovingian::database::PersistentStore{};
        store.max_to_device_messages_per_user_device = 3U;
        store.to_device_message_ttl_seconds = 0U;

        WHEN("messages are enqueued for two different recipients")
        {
            for (auto ordinal = std::uint64_t{1U}; ordinal <= 5U; ++ordinal)
            {
                REQUIRE(merovingian::database::enqueue_to_device_message(
                    store, make_message(ordinal, "@bob:example.org", "BOB_DEVICE")));
                REQUIRE(merovingian::database::enqueue_to_device_message(
                    store, make_message(ordinal, "@carol:example.org", "CAROL_DEVICE")));
            }

            THEN("each recipient keeps only its 3 newest rows")
            {
                auto bob_count = std::size_t{0U};
                auto carol_count = std::size_t{0U};
                for (auto const& message : store.to_device_messages)
                {
                    if (message.target_user_id == "@bob:example.org")
                    {
                        ++bob_count;
                    }
                    if (message.target_user_id == "@carol:example.org")
                    {
                        ++carol_count;
                    }
                }
                REQUIRE(bob_count == 3U);
                REQUIRE(carol_count == 3U);
            }
        }
    }
}
