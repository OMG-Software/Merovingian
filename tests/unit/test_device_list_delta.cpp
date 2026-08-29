// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Behaviour of the shared device-list delta collector that backs the
// device_lists field of /sync, the MSC4186 e2ee extension, and /keys/changes.
//
// Spec: docs/matrix-v1.19-spec/client-server-api.md, "Extensions to /sync" —
// `changed` and `left` list the users whose devices changed, or with whom no
// encrypted room is shared any more, since the previous sync response.

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/sync/device_list_delta.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

SCENARIO("Device-list deltas report each subject user at most once", "[sync][device-lists]")
{
    GIVEN("a change log holding many rows for the same two subject users")
    {
        auto store = merovingian::database::PersistentStore{};
        for (auto stream_id = std::uint64_t{1U}; stream_id <= 200U; ++stream_id)
        {
            store.device_list_changes.push_back({stream_id, "@alice:example.org", "@bob:example.org", "changed"});
            store.device_list_changes.push_back({stream_id, "@alice:example.org", "@carol:example.org", "changed"});
        }

        WHEN("the observer's delta is collected from the start of the stream")
        {
            auto const delta = merovingian::sync::collect_device_list_delta(store, "@alice:example.org", 0U);

            THEN("each subject appears exactly once rather than once per change row")
            {
                REQUIRE(delta.changed == std::vector<std::string>{"@bob:example.org", "@carol:example.org"});
                REQUIRE(delta.left.empty());
            }

            THEN("the highest observed stream id is reported so callers can advance their token")
            {
                REQUIRE(delta.max_stream_id == 200U);
            }
        }
    }
}

SCENARIO("Device-list deltas resolve a subject's most recent change type", "[sync][device-lists]")
{
    GIVEN("a subject that changed devices and later left every shared encrypted room")
    {
        auto store = merovingian::database::PersistentStore{};
        store.device_list_changes = {
            {1U, "@alice:example.org", "@bob:example.org",   "changed"},
            {2U, "@alice:example.org", "@bob:example.org",   "left"   },
            {3U, "@alice:example.org", "@carol:example.org", "left"   },
            {4U, "@alice:example.org", "@carol:example.org", "changed"},
        };

        WHEN("the observer's delta is collected")
        {
            auto const delta = merovingian::sync::collect_device_list_delta(store, "@alice:example.org", 0U);

            THEN("each subject lands in the list matching its latest change and appears in no other")
            {
                REQUIRE(delta.left == std::vector<std::string>{"@bob:example.org"});
                REQUIRE(delta.changed == std::vector<std::string>{"@carol:example.org"});
            }
        }
    }
}

SCENARIO("Device-list deltas honour the observer and the stream range", "[sync][device-lists]")
{
    GIVEN("changes recorded for two different observers across a range of stream ids")
    {
        auto store = merovingian::database::PersistentStore{};
        store.device_list_changes = {
            {5U,  "@alice:example.org", "@early:example.org",   "changed"},
            {15U, "@alice:example.org", "@inrange:example.org", "changed"},
            {25U, "@alice:example.org", "@late:example.org",    "changed"},
            {15U, "@dave:example.org",  "@other:example.org",   "changed"},
        };

        WHEN("a bounded range is collected for one observer")
        {
            auto const delta = merovingian::sync::collect_device_list_delta(store, "@alice:example.org", 10U, 20U);

            THEN("only that observer's changes inside the half-open range are reported")
            {
                REQUIRE(delta.changed == std::vector<std::string>{"@inrange:example.org"});
                REQUIRE(delta.max_stream_id == 15U);
            }
        }

        WHEN("a range containing no changes is collected")
        {
            auto const delta = merovingian::sync::collect_device_list_delta(store, "@alice:example.org", 100U, 200U);

            THEN("both lists are empty and the range's lower bound is preserved")
            {
                REQUIRE(delta.changed.empty());
                REQUIRE(delta.left.empty());
                REQUIRE(delta.max_stream_id == 100U);
            }
        }
    }
}
