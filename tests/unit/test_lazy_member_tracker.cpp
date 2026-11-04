// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/joining_threads.hpp"
#include "merovingian/sync/lazy_member_tracker.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <string>

namespace
{

using merovingian::sync::LazyMemberTracker;
using merovingian::sync::StreamToken;

[[nodiscard]] auto key_for(std::string_view device = "DEV", std::string_view filter = "F")
    -> LazyMemberTracker::StreamKey
{
    return {"@alice:example.org", device, filter};
}

auto record_one(LazyMemberTracker& tracker, LazyMemberTracker::StreamKey const& key, std::string_view room,
                std::string_view user, std::string_view event, StreamToken next, std::optional<StreamToken> since)
    -> void
{
    auto const sent = std::array{
        LazyMemberTracker::SentMember{user, event}
    };
    tracker.record(key, room, sent, next, since);
}

} // namespace

// Spec: client-server-api.md "Lazy-loading room members": "the server MAY assume that clients will remember
// membership events they have already been sent". A member counts as held only once the client has presented
// the exact `next_batch` of the response that carried it, and then for every later token (ADR-0450). "At or
// past" is not proof: a later response can cover an earlier one the client never received.
SCENARIO("A member is acknowledged only after an exact since settles it, then by any token past it on every component",
         "[sync][lazy-sync][lazy-tracker]")
{
    GIVEN("a member recorded under the next_batch (10, 20, 30)")
    {
        auto tracker = LazyMemberTracker{};
        auto const key = key_for();
        record_one(tracker, key, "!r:x", "@bob:x", "$m1", {10U, 20U, 30U}, std::nullopt);

        WHEN("no request has presented that token yet")
        {
            THEN("the member is not acknowledged: the client may never have received the response")
            {
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m1", {10U, 20U, 30U}));
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m1", {99U, 99U, 99U}));
            }
        }
        WHEN("a request presents exactly that token")
        {
            tracker.begin_request(key, StreamToken{10U, 20U, 30U});

            THEN("the member is acknowledged at that token")
            {
                REQUIRE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m1", {10U, 20U, 30U}));
            }
            THEN("a token behind on the event ordering does not acknowledge it")
            {
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m1", {9U, 20U, 30U}));
            }
            THEN("a token behind on the membership ordering does not acknowledge it")
            {
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m1", {10U, 19U, 30U}));
            }
            THEN("a token behind on the sync stream id does not acknowledge it")
            {
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m1", {10U, 20U, 29U}));
            }
            THEN("a token past it on every component acknowledges it")
            {
                REQUIRE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m1", {11U, 21U, 31U}));
            }
            THEN("a changed event is not acknowledged")
            {
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m2", {11U, 21U, 31U}));
            }
            THEN("another room, user, device or filter acknowledges nothing")
            {
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!other:x", "@bob:x", "$m1", {11U, 21U, 31U}));
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@carol:x", "$m1", {11U, 21U, 31U}));
                REQUIRE_FALSE(tracker.is_acknowledged(key_for("DEV2"), "!r:x", "@bob:x", "$m1", {11U, 21U, 31U}));
                REQUIRE_FALSE(tracker.is_acknowledged(key_for("DEV", "G"), "!r:x", "@bob:x", "$m1", {11U, 21U, 31U}));
            }
        }
    }
}

// A client aborts a long-poll and retries the same `since` while the first request is still running. The first
// answers a dead connection; the second answers later, without the member (limited). The client presents the
// second's token, which is past the first's, but it never received the member.
SCENARIO("A later response's token does not acknowledge a member an earlier, lost response carried",
         "[sync][lazy-sync][lazy-tracker]")
{
    GIVEN("a member recorded at R1 = (10, 10, 10) by a response the client never received")
    {
        auto tracker = LazyMemberTracker{};
        auto const key = key_for();
        record_one(tracker, key, "!r:x", "@bob:x", "$m1", {10U, 10U, 10U}, StreamToken{5U, 5U, 5U});

        WHEN("the client presents R2 = (12, 12, 12), the token of a different response, past R1")
        {
            tracker.begin_request(key, StreamToken{12U, 12U, 12U});

            THEN("the member is not acknowledged and its entry is gone")
            {
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m1", {12U, 12U, 12U}));
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m1", {99U, 99U, 99U}));
                REQUIRE(tracker.member_count() == 0U);
            }
        }
    }
}

SCENARIO("A settled member stays held across later tokens and is dropped by an older one",
         "[sync][lazy-sync][lazy-tracker]")
{
    GIVEN("a member recorded at R1 and settled by a request presenting exactly R1")
    {
        auto tracker = LazyMemberTracker{};
        auto const key = key_for();
        auto const r1 = StreamToken{10U, 10U, 10U};
        record_one(tracker, key, "!r:x", "@bob:x", "$m1", r1, StreamToken{5U, 5U, 5U});
        tracker.begin_request(key, r1);

        WHEN("a later request presents R3 past R1")
        {
            tracker.begin_request(key, StreamToken{30U, 30U, 30U});

            THEN("the member is still acknowledged")
            {
                REQUIRE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m1", {30U, 30U, 30U}));
                REQUIRE(tracker.member_count() == 1U);
            }
        }
        WHEN("a request presents a token older than R1")
        {
            tracker.begin_request(key, StreamToken{9U, 9U, 9U});

            THEN("the entry is deleted")
            {
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m1", {30U, 30U, 30U}));
                REQUIRE(tracker.member_count() == 0U);
            }
        }
        WHEN("the member is sent again at R2 and a request presents R3, not R2")
        {
            auto const r2 = StreamToken{20U, 20U, 20U};
            record_one(tracker, key, "!r:x", "@bob:x", "$m1", r2, r1);
            tracker.begin_request(key, StreamToken{30U, 30U, 30U});

            THEN("the entry is deleted: the client never presented the response that re-sent it")
            {
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m1", {40U, 40U, 40U}));
                REQUIRE(tracker.member_count() == 0U);
            }
        }
        WHEN("the member is sent again at R2 and a request presents exactly R2")
        {
            auto const r2 = StreamToken{20U, 20U, 20U};
            record_one(tracker, key, "!r:x", "@bob:x", "$m1", r2, r1);
            tracker.begin_request(key, r2);

            THEN("it is acknowledged again")
            {
                REQUIRE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$m1", {20U, 20U, 20U}));
            }
        }
    }
}

SCENARIO("A request whose since does not cover an entry deletes it", "[sync][lazy-sync][lazy-tracker]")
{
    GIVEN("a member recorded under token (10, 10, 10) and another under (20, 20, 20)")
    {
        auto tracker = LazyMemberTracker{};
        auto const key = key_for();
        record_one(tracker, key, "!r:x", "@bob:x", "$b", {10U, 10U, 10U}, std::nullopt);
        record_one(tracker, key, "!r:x", "@carol:x", "$c", {20U, 20U, 20U}, StreamToken{10U, 10U, 10U});

        WHEN("a client retries with the older token (10, 10, 10)")
        {
            tracker.begin_request(key, StreamToken{10U, 10U, 10U});

            THEN("the entry it could not have received is gone even for a later token, the covered one stays")
            {
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@carol:x", "$c", {30U, 30U, 30U}));
                REQUIRE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$b", {30U, 30U, 30U}));
                REQUIRE(tracker.member_count() == 1U);
            }
        }
        WHEN("a request has no since")
        {
            tracker.begin_request(key, std::nullopt);

            THEN("everything under the stream is gone")
            {
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$b", {30U, 30U, 30U}));
                REQUIRE(tracker.key_count() == 0U);
                REQUIRE(tracker.member_count() == 0U);
            }
        }
        WHEN("a request with no since arrives on another stream")
        {
            tracker.begin_request(key_for("OTHER"), std::nullopt);

            THEN("this stream is untouched")
            {
                REQUIRE(tracker.member_count() == 2U);
                REQUIRE(tracker.key_count() == 1U);
            }
        }
    }
}

SCENARIO("A response the client cannot acknowledge records nothing", "[sync][lazy-sync][lazy-tracker]")
{
    GIVEN("a response whose next_batch equals the request's since")
    {
        auto tracker = LazyMemberTracker{};
        auto const key = key_for();
        auto const token = StreamToken{5U, 5U, 5U};

        WHEN("its members are recorded")
        {
            record_one(tracker, key, "!r:x", "@bob:x", "$b", token, token);

            THEN("nothing is held")
            {
                REQUIRE(tracker.member_count() == 0U);
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$b", {9U, 9U, 9U}));
            }
        }
    }
}

SCENARIO("A request that cannot be tracked is never acknowledged", "[sync][lazy-sync][lazy-tracker]")
{
    GIVEN("a tracker with a 16 byte filter limit")
    {
        auto limits = LazyMemberTracker::Limits{};
        limits.max_filter_bytes = 16U;
        auto tracker = LazyMemberTracker{limits};

        WHEN("a request without a device records a member")
        {
            auto const no_device = LazyMemberTracker::StreamKey{"@alice:example.org", "", "F"};
            record_one(tracker, no_device, "!r:x", "@bob:x", "$b", {1U, 1U, 1U}, std::nullopt);

            THEN("nothing is held and nothing is acknowledged")
            {
                REQUIRE(tracker.member_count() == 0U);
                REQUIRE_FALSE(tracker.is_acknowledged(no_device, "!r:x", "@bob:x", "$b", {9U, 9U, 9U}));
            }
        }
        WHEN("a request with a 17 byte filter records a member")
        {
            auto const long_filter = std::string(17U, 'f');
            auto const key = key_for("DEV", long_filter);
            record_one(tracker, key, "!r:x", "@bob:x", "$b", {1U, 1U, 1U}, std::nullopt);

            THEN("it is untracked: nothing is held and the member would be sent every time")
            {
                REQUIRE(tracker.member_count() == 0U);
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$b", {9U, 9U, 9U}));
            }
        }
        WHEN("a request with a 16 byte filter records a member")
        {
            auto const exact = std::string(16U, 'f');
            auto const key = key_for("DEV", exact);
            record_one(tracker, key, "!r:x", "@bob:x", "$b", {1U, 1U, 1U}, std::nullopt);

            tracker.begin_request(key, StreamToken{1U, 1U, 1U});

            THEN("it is tracked")
            {
                REQUIRE(tracker.is_acknowledged(key, "!r:x", "@bob:x", "$b", {9U, 9U, 9U}));
            }
        }
    }
}

SCENARIO("Every cap holds and eviction leads to a resend, never an omission", "[sync][lazy-sync][lazy-tracker]")
{
    GIVEN("a tracker capped at 2 streams, 2 rooms per stream, 2 members per room and 5 members in all")
    {
        auto limits = LazyMemberTracker::Limits{};
        limits.max_keys = 2U;
        limits.max_rooms_per_key = 2U;
        limits.max_members_per_room = 2U;
        limits.max_tracked_members = 5U;
        auto tracker = LazyMemberTracker{limits};
        auto const key = key_for();
        auto const late = StreamToken{99U, 99U, 99U};

        WHEN("three members are recorded in one room")
        {
            record_one(tracker, key, "!r:x", "@a:x", "$a", {1U, 1U, 1U}, std::nullopt);
            record_one(tracker, key, "!r:x", "@b:x", "$b", {1U, 1U, 1U}, std::nullopt);
            record_one(tracker, key, "!r:x", "@c:x", "$c", {1U, 1U, 1U}, std::nullopt);

            tracker.begin_request(key, StreamToken{1U, 1U, 1U});

            THEN("the room holds two and the least recently used one is sent again")
            {
                REQUIRE(tracker.member_count() == 2U);
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@a:x", "$a", late));
                REQUIRE(tracker.is_acknowledged(key, "!r:x", "@b:x", "$b", late));
                REQUIRE(tracker.is_acknowledged(key, "!r:x", "@c:x", "$c", late));
            }
        }
        WHEN("a member is used, then a third is recorded")
        {
            record_one(tracker, key, "!r:x", "@a:x", "$a", {1U, 1U, 1U}, std::nullopt);
            record_one(tracker, key, "!r:x", "@b:x", "$b", {1U, 1U, 1U}, std::nullopt);
            tracker.begin_request(key, StreamToken{1U, 1U, 1U});

            REQUIRE(tracker.is_acknowledged(key, "!r:x", "@a:x", "$a", late));
            record_one(tracker, key, "!r:x", "@c:x", "$c", {1U, 1U, 1U}, std::nullopt);

            THEN("the one not used is evicted")
            {
                REQUIRE(tracker.is_acknowledged(key, "!r:x", "@a:x", "$a", late));
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!r:x", "@b:x", "$b", late));
            }
        }
        WHEN("three rooms are recorded for one stream")
        {
            record_one(tracker, key, "!1:x", "@a:x", "$a", {1U, 1U, 1U}, std::nullopt);
            record_one(tracker, key, "!2:x", "@a:x", "$a", {1U, 1U, 1U}, std::nullopt);
            record_one(tracker, key, "!3:x", "@a:x", "$a", {1U, 1U, 1U}, std::nullopt);

            tracker.begin_request(key, StreamToken{1U, 1U, 1U});

            THEN("two rooms are held and the oldest room's member is sent again")
            {
                REQUIRE(tracker.member_count() == 2U);
                REQUIRE_FALSE(tracker.is_acknowledged(key, "!1:x", "@a:x", "$a", late));
                REQUIRE(tracker.is_acknowledged(key, "!3:x", "@a:x", "$a", late));
            }
        }
        WHEN("three streams are recorded")
        {
            record_one(tracker, key_for("D1"), "!r:x", "@a:x", "$a", {1U, 1U, 1U}, std::nullopt);
            record_one(tracker, key_for("D2"), "!r:x", "@a:x", "$a", {1U, 1U, 1U}, std::nullopt);
            record_one(tracker, key_for("D3"), "!r:x", "@a:x", "$a", {1U, 1U, 1U}, std::nullopt);

            tracker.begin_request(key_for("D1"), StreamToken{1U, 1U, 1U});
            tracker.begin_request(key_for("D3"), StreamToken{1U, 1U, 1U});

            THEN("two streams are held and the oldest stream's member is sent again")
            {
                REQUIRE(tracker.key_count() == 2U);
                REQUIRE_FALSE(tracker.is_acknowledged(key_for("D1"), "!r:x", "@a:x", "$a", late));
                REQUIRE(tracker.is_acknowledged(key_for("D3"), "!r:x", "@a:x", "$a", late));
            }
        }
        WHEN("more members are recorded than the total cap allows across streams")
        {
            for (auto const* device : {"D1", "D2"})
            {
                record_one(tracker, key_for(device), "!1:x", "@a:x", "$a", {1U, 1U, 1U}, std::nullopt);
                record_one(tracker, key_for(device), "!1:x", "@b:x", "$b", {1U, 1U, 1U}, std::nullopt);
                record_one(tracker, key_for(device), "!2:x", "@a:x", "$a", {1U, 1U, 1U}, std::nullopt);
            }

            tracker.begin_request(key_for("D1"), StreamToken{1U, 1U, 1U});
            tracker.begin_request(key_for("D2"), StreamToken{1U, 1U, 1U});

            THEN("the total never exceeds the cap and the evicted stream is simply resent")
            {
                REQUIRE(tracker.member_count() <= 5U);
                REQUIRE_FALSE(tracker.is_acknowledged(key_for("D1"), "!1:x", "@a:x", "$a", late));
                REQUIRE(tracker.is_acknowledged(key_for("D2"), "!2:x", "@a:x", "$a", late));
            }
        }
    }
}

SCENARIO("Driving the tracker from several threads keeps its counts within the caps", "[sync][lazy-sync][lazy-tracker]")
{
    GIVEN("a small tracker and four threads that record and check members")
    {
        auto limits = LazyMemberTracker::Limits{};
        limits.max_keys = 4U;
        limits.max_rooms_per_key = 4U;
        limits.max_members_per_room = 4U;
        limits.max_tracked_members = 32U;
        auto tracker = LazyMemberTracker{limits};
        auto hits = std::array<std::atomic<std::size_t>, 4>{};

        WHEN("each thread records its own members and reads them back")
        {
            auto threads = merovingian::tests::JoiningThreads{};
            for (auto index = std::size_t{0U}; index < hits.size(); ++index)
            {
                threads.emplace_back([&tracker, &hits, index] {
                    auto const device = "D" + std::to_string(index);
                    auto const key = key_for(device);
                    for (auto round = 0U; round < 200U; ++round)
                    {
                        auto const user = "@u" + std::to_string(round % 6U) + ":x";
                        auto const room = "!r" + std::to_string(round % 3U) + ":x";
                        tracker.begin_request(key, StreamToken{round, round, round});
                        if (tracker.is_acknowledged(key, room, user, "$e",
                                                    StreamToken{round + 1U, round + 1U, round + 1U}))
                        {
                            ++hits[index];
                        }
                        record_one(tracker, key, room, user, "$e", StreamToken{round + 1U, round + 1U, round + 1U},
                                   StreamToken{round, round, round});
                    }
                });
            }
            threads.join();

            THEN("the caps hold once the threads have finished")
            {
                REQUIRE(tracker.key_count() <= 4U);
                REQUIRE(tracker.member_count() <= 32U);
            }
        }
    }
}
