// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// How a sticky event's remaining lifetime is shown to clients (MSC4354, ADR-0853, ADR-0855): the clock the readers use,
// and `attach_sticky_remaining`, which adds both remaining-time fields to an event's `unsigned` only while the event
// has an unexpired row, keeping what `unsigned` already holds, and `carries_sticky_remaining`. The proposal is not in
// Matrix v1.19, so these are project-level checks.
#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentStickyEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/database/StickyEventStore.hpp"
#include "merovingian/database/StickyEventView.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>

namespace
{

namespace cj = merovingian::canonicaljson;
namespace db = merovingian::database;

constexpr auto event_id = "$sticky:example.org";
constexpr auto clock_ms = std::int64_t{10'000};
constexpr auto expires_ms = std::int64_t{12'500};

// The event as a client would be sent it before the remaining time is attached.
[[nodiscard]] auto client_event() -> cj::Object
{
    auto event = cj::Object{};
    event.push_back(cj::make_member("event_id", cj::Value{std::string{event_id}}));
    event.push_back(cj::make_member("type", cj::Value{std::string{"org.matrix.msc4143.rtc.member"}}));
    return event;
}

[[nodiscard]] auto with_unsigned(cj::Value unsigned_value) -> cj::Object
{
    auto event = client_event();
    event.push_back(cj::make_member("unsigned", std::move(unsigned_value)));
    return event;
}

[[nodiscard]] auto text_of(cj::Object const& event) -> std::string
{
    return cj::serialize_canonical(cj::Value{event}).output;
}

// A store whose sticky clock reads `clock_ms`, holding one sticky row for `event_id` when `expiry` is given.
[[nodiscard]] auto store_with_row(std::int64_t expiry) -> db::PersistentStoreOpenResult
{
    auto opened = db::open_persistent_store();
    REQUIRE(opened.ok);
    auto const recorded =
        db::record_sticky_event(opened.store, {event_id, "!room:example.org", "@alice:example.org", clock_ms, expiry},
                                {60U, 1000U}, clock_ms)
            .recorded;
    REQUIRE(recorded);
    opened.store.test_sticky_clock_ms = clock_ms;
    return opened;
}

constexpr auto both_fields = R"("msc4354_sticky_duration_ttl_ms":2500,"sticky_duration_remaining_ms":2500)";
constexpr auto bare_event = R"({"event_id":"$sticky:example.org","type":"org.matrix.msc4143.rtc.member")";

} // namespace

SCENARIO("the sticky clock is the test clock when one is set, else the system clock", "[database][sticky-events]")
{
    GIVEN("a store without a test clock and one with a test clock")
    {
        auto plain = db::PersistentStore{};
        auto pinned = db::PersistentStore{};
        pinned.test_sticky_clock_ms = 42;

        WHEN("each clock is read around a reading of the system clock")
        {
            auto const before = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count();
            auto const plain_now = db::sticky_clock_now_ms(plain);
            auto const after = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
            auto const pinned_now = db::sticky_clock_now_ms(pinned);

            THEN("the pinned store reads its value and the other reads the system clock")
            {
                REQUIRE(pinned_now == 42);
                REQUIRE(plain_now >= before);
                REQUIRE(plain_now <= after);
            }
        }
    }
}

SCENARIO("an event without an unexpired sticky row is served unchanged", "[database][sticky-events]")
{
    GIVEN("a store with no sticky rows")
    {
        auto store = db::PersistentStore{};
        store.test_sticky_clock_ms = clock_ms;
        auto event = client_event();

        WHEN("the remaining time is attached")
        {
            db::attach_sticky_remaining(store, event_id, event);

            THEN("the event has no unsigned")
            {
                REQUIRE(text_of(event) == std::string{bare_event} + "}");
            }
        }
    }

    GIVEN("a store holding a sticky row for another event")
    {
        auto opened = store_with_row(expires_ms);
        auto event = client_event();

        WHEN("the remaining time is attached for an event with no row")
        {
            db::attach_sticky_remaining(opened.store, "$other:example.org", event);

            THEN("the event is unchanged")
            {
                REQUIRE(text_of(event) == std::string{bare_event} + "}");
            }
        }
    }

    GIVEN("a sticky row that has expired by the store's clock")
    {
        auto opened = store_with_row(expires_ms);
        opened.store.test_sticky_clock_ms = expires_ms;
        auto event = with_unsigned(cj::Value{cj::Object{cj::make_member("age", cj::Value{std::int64_t{5}})}});

        WHEN("the remaining time is attached")
        {
            db::attach_sticky_remaining(opened.store, event_id, event);

            THEN("neither field is added and unsigned keeps what it held")
            {
                REQUIRE(text_of(event) == std::string{bare_event} + R"(,"unsigned":{"age":5}})");
            }
        }
    }
}

SCENARIO("an event with an unexpired sticky row is served both remaining-time fields", "[database][sticky-events]")
{
    GIVEN("a sticky row with 2500 ms left")
    {
        auto opened = store_with_row(expires_ms);

        WHEN("the event has no unsigned")
        {
            auto event = client_event();
            db::attach_sticky_remaining(opened.store, event_id, event);

            THEN("unsigned is added holding both fields")
            {
                REQUIRE(text_of(event) == std::string{bare_event} + R"(,"unsigned":{)" + both_fields + "}}");
            }
        }

        WHEN("unsigned holds other members and stale remaining-time fields")
        {
            auto held = cj::Object{};
            held.push_back(cj::make_member("age", cj::Value{std::int64_t{5}}));
            held.push_back(cj::make_member("sticky_duration_remaining_ms", cj::Value{std::int64_t{1}}));
            held.push_back(cj::make_member("msc4354_sticky_duration_ttl_ms", cj::Value{std::int64_t{1}}));
            held.push_back(cj::make_member("transaction_id", cj::Value{std::string{"txn"}}));
            auto event = with_unsigned(cj::Value{std::move(held)});
            db::attach_sticky_remaining(opened.store, event_id, event);

            THEN("the other members are kept and the stale fields are replaced, each once")
            {
                REQUIRE(text_of(event) == std::string{bare_event} + R"(,"unsigned":{"age":5,)" + both_fields +
                                              R"(,"transaction_id":"txn"}})");
            }
        }

        WHEN("unsigned is not an object")
        {
            auto event = with_unsigned(cj::Value{std::string{"not an object"}});
            db::attach_sticky_remaining(opened.store, event_id, event);

            THEN("it is replaced by an object holding only both fields")
            {
                REQUIRE(text_of(event) == std::string{bare_event} + R"(,"unsigned":{)" + both_fields + "}}");
            }
        }
    }
}

// The serializers use `carries_sticky_remaining` to drop an event the sticky section offers when its row expired
// between selection and serialization, so the section never carries an event without its remaining time (ADR-0858).
SCENARIO("an event carries its sticky remaining time only when attach_sticky_remaining added it",
         "[database][sticky-events]")
{
    GIVEN("a sticky row with 2500 ms left")
    {
        auto opened = store_with_row(expires_ms);

        WHEN("the remaining time is attached while the row is unexpired")
        {
            auto event = client_event();
            db::attach_sticky_remaining(opened.store, event_id, event);

            auto const served = cj::Value{std::move(event)};

            THEN("the event carries it")
            {
                REQUIRE(db::carries_sticky_remaining(served));
            }
        }

        WHEN("the clock reaches the expiry before the remaining time is attached")
        {
            opened.store.test_sticky_clock_ms = expires_ms;
            auto event = with_unsigned(cj::Value{cj::Object{}});
            db::attach_sticky_remaining(opened.store, event_id, event);

            auto const served = cj::Value{std::move(event)};

            THEN("the event does not carry it")
            {
                REQUIRE_FALSE(db::carries_sticky_remaining(served));
            }
        }

        WHEN("the value is not an object, or its unsigned is not an object or holds only the unstable name")
        {
            auto unstable = cj::Object{};
            unstable.push_back(cj::make_member("msc4354_sticky_duration_ttl_ms", cj::Value{std::int64_t{1}}));
            auto const only_unstable = cj::Value{with_unsigned(cj::Value{std::move(unstable)})};
            auto const unsigned_text = cj::Value{with_unsigned(cj::Value{std::string{"x"}})};

            THEN("none carries it")
            {
                REQUIRE_FALSE(db::carries_sticky_remaining(cj::Value{std::string{"event"}}));
                REQUIRE_FALSE(db::carries_sticky_remaining(unsigned_text));
                REQUIRE_FALSE(db::carries_sticky_remaining(only_unstable));
            }
        }
    }
}
