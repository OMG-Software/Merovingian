// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The sync stream counter and the stream token epoch on a store with no runtime: the counter's ceiling (ADR-0315)
// and the epoch write (ADR-0592). The request-level scenarios are in
// tests/integration/test_sync_stream_ceiling_flow.cpp and tests/integration/test_sync_restore_flow.cpp.
#include "merovingian/database/PersistentStore.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <tuple>

SCENARIO("The sync stream counter refuses to pass its ceiling rather than wrap", "[database][sync-stream][security]")
{
    GIVEN("a store whose counter is at the ceiling")
    {
        auto store = merovingian::database::PersistentStore{};
        store.next_sync_stream_id = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
        auto const at_ceiling = store.next_sync_stream_id;

        WHEN("another stream id is requested")
        {
            THEN("no id is issued and the counter stays where it was")
            {
                REQUIRE_THROWS_AS(std::ignore = merovingian::database::allocate_sync_stream_id(store),
                                  std::overflow_error);
                REQUIRE(store.next_sync_stream_id == at_ceiling);
            }
        }
    }

    GIVEN("a store whose counter is just below the ceiling")
    {
        auto store = merovingian::database::PersistentStore{};
        store.next_sync_stream_id = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) - 1U;

        WHEN("another stream id is requested")
        {
            auto const issued = merovingian::database::allocate_sync_stream_id(store);

            THEN("the ceiling itself is issued")
            {
                REQUIRE(issued == static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()));
            }
        }
    }
}

// ADR-0592: zero is a token's "no epoch", so the store never takes it, and a failed write leaves the epoch the
// tokens already handed out carry.
SCENARIO("The stream token epoch is written only when it is not zero and the write succeeds",
         "[database][sync-stream][restore]")
{
    GIVEN("a store holding an epoch")
    {
        auto store = merovingian::database::PersistentStore{};
        REQUIRE(merovingian::database::persist_stream_token_epoch(store, 0x1234U));

        WHEN("zero is written")
        {
            auto const written = merovingian::database::persist_stream_token_epoch(store, 0U);

            THEN("it is refused and the epoch is kept")
            {
                REQUIRE_FALSE(written);
                REQUIRE(store.stream_token_epoch == 0x1234U);
            }
        }

        WHEN("another epoch is written but the write fails")
        {
            merovingian::database::force_persist_failure_for_statement(store, "upsert_stream_token_epoch");
            auto const written = merovingian::database::persist_stream_token_epoch(store, 0x5678U);

            THEN("it is refused and the epoch is kept")
            {
                REQUIRE_FALSE(written);
                REQUIRE(store.stream_token_epoch == 0x1234U);
            }
        }

        WHEN("another epoch is written")
        {
            auto const written = merovingian::database::persist_stream_token_epoch(store, 0x5678U);

            THEN("the store holds it")
            {
                REQUIRE(written);
                REQUIRE(store.stream_token_epoch == 0x5678U);
            }
        }
    }
}
