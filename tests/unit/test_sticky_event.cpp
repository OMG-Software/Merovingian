// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// MSC4354 sticky events (ADR-0853, ADR-0854): the pure functions that decide whether a PDU is sticky, parse a client's
// duration and compute when the event stops being sticky. The MSC is not in Matrix v1.19, so these are project-level
// checks of the ADR's rules.

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/events/StickyEvent.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using merovingian::events::sticky_duration_of;

[[nodiscard]] auto pdu(std::string_view json) -> merovingian::canonicaljson::Value
{
    auto parsed = merovingian::canonicaljson::parse_preserving_numbers(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return std::move(parsed.value);
}

[[nodiscard]] auto duration_in(std::string_view json) -> std::optional<std::int64_t>
{
    return sticky_duration_of(pdu(json));
}

constexpr auto int64_max = std::numeric_limits<std::int64_t>::max();
constexpr auto int64_min = std::numeric_limits<std::int64_t>::min();

} // namespace

SCENARIO("a PDU with one valid sticky field is sticky for that duration", "[events][sticky-events]")
{
    GIVEN("a message event with only the stable field, and one with only the unstable field")
    {
        WHEN("each is read")
        {
            auto const stable = duration_in(R"({"type":"m.x","sticky":{"duration_ms":5000}})");
            auto const unstable = duration_in(R"({"type":"m.x","msc4354_sticky":{"duration_ms":7}})");

            THEN("the duration is the one the field names")
            {
                REQUIRE(stable == std::optional<std::int64_t>{5000});
                REQUIRE(unstable == std::optional<std::int64_t>{7});
            }
        }
    }

    GIVEN("a duration above the one-hour cap")
    {
        WHEN("it is read")
        {
            auto const read = duration_in(R"({"sticky":{"duration_ms":99999999999}})");

            THEN("it is returned as given, because the cap applies when the expiry is computed")
            {
                REQUIRE(read == std::optional<std::int64_t>{99'999'999'999});
            }
        }
    }

    GIVEN("a duration of exactly 1 and the largest 64-bit integer")
    {
        WHEN("each is read")
        {
            auto const one = duration_in(R"({"sticky":{"duration_ms":1}})");
            auto const huge = duration_in(R"({"sticky":{"duration_ms":9007199254740991}})");
            auto const beyond = duration_in(R"({"sticky":{"duration_ms":9223372036854775807}})");

            THEN("canonical JSON's largest integer is sticky and one beyond its range is not")
            {
                REQUIRE(one == std::optional<std::int64_t>{1});
                REQUIRE(huge == std::optional<std::int64_t>{9'007'199'254'740'991});
                REQUIRE_FALSE(beyond.has_value());
            }
        }
    }
}

SCENARIO("a PDU carrying both sticky fields is sticky only when they agree", "[events][sticky-events]")
{
    GIVEN("both fields with the same duration")
    {
        WHEN("it is read")
        {
            auto const read = duration_in(R"({"sticky":{"duration_ms":300},"msc4354_sticky":{"duration_ms":300}})");

            THEN("it is sticky for that duration")
            {
                REQUIRE(read == std::optional<std::int64_t>{300});
            }
        }
    }

    GIVEN("both fields with different durations")
    {
        WHEN("it is read")
        {
            auto const read = duration_in(R"({"sticky":{"duration_ms":300},"msc4354_sticky":{"duration_ms":301}})");

            THEN("it is an ordinary event")
            {
                REQUIRE_FALSE(read.has_value());
            }
        }
    }

    GIVEN("one valid field and one malformed field")
    {
        WHEN("each pairing is read")
        {
            auto const bad_unstable = duration_in(R"({"sticky":{"duration_ms":300},"msc4354_sticky":{"duration_ms":0}})");
            auto const bad_stable = duration_in(R"({"sticky":"x","msc4354_sticky":{"duration_ms":300}})");

            THEN("neither is sticky, so a malformed field cannot hide behind a valid one")
            {
                REQUIRE_FALSE(bad_unstable.has_value());
                REQUIRE_FALSE(bad_stable.has_value());
            }
        }
    }
}

SCENARIO("a PDU whose sticky field is malformed is an ordinary event", "[events][sticky-events]")
{
    GIVEN("sticky objects whose duration_ms is zero, negative, a float, a string, too large or missing")
    {
        auto const documents = std::vector<std::string>{
            R"({"sticky":{"duration_ms":0}})",
            R"({"sticky":{"duration_ms":-1}})",
            R"({"sticky":{"duration_ms":-9223372036854775808}})",
            R"({"sticky":{"duration_ms":1.5}})",
            R"({"sticky":{"duration_ms":1.0}})",
            R"({"sticky":{"duration_ms":1e3}})",
            R"({"sticky":{"duration_ms":"5000"}})",
            R"({"sticky":{"duration_ms":9223372036854775808}})",
            R"({"sticky":{"duration_ms":null}})",
            R"({"sticky":{"duration_ms":true}})",
            R"({"sticky":{"duration_ms":[5]}})",
            R"({"sticky":{}})",
            R"({"sticky":{"other":5}})",
            R"({"msc4354_sticky":{"duration_ms":0}})",
            R"({"msc4354_sticky":{"duration_ms":"5"}})"};

        WHEN("each is read")
        {
            auto read = std::vector<std::optional<std::int64_t>>{};
            for (auto const& document : documents)
            {
                read.push_back(duration_in(document));
            }

            THEN("none is sticky")
            {
                for (auto index = std::size_t{0U}; index < documents.size(); ++index)
                {
                    INFO(documents[index]);
                    REQUIRE_FALSE(read[index].has_value());
                }
            }
        }
    }

    GIVEN("a sticky field that is not an object")
    {
        auto const documents = std::vector<std::string>{R"({"sticky":5})",     R"({"sticky":"5"})", R"({"sticky":null})",
                                                        R"({"sticky":[]})",    R"({"sticky":true})",
                                                        R"({"msc4354_sticky":5})"};

        WHEN("each is read")
        {
            auto read = std::vector<std::optional<std::int64_t>>{};
            for (auto const& document : documents)
            {
                read.push_back(duration_in(document));
            }

            THEN("none is sticky")
            {
                for (auto index = std::size_t{0U}; index < documents.size(); ++index)
                {
                    INFO(documents[index]);
                    REQUIRE_FALSE(read[index].has_value());
                }
            }
        }
    }
}

SCENARIO("a PDU with no sticky field, a state event, or a non-object is not sticky", "[events][sticky-events]")
{
    GIVEN("an event naming neither field")
    {
        WHEN("it is read")
        {
            THEN("it is not sticky")
            {
                REQUIRE_FALSE(duration_in(R"({"type":"m.room.message","content":{}})").has_value());
            }
        }
    }

    GIVEN("a state event that carries a valid sticky field")
    {
        WHEN("each form is read")
        {
            auto const stable = duration_in(R"({"state_key":"","sticky":{"duration_ms":5000}})");
            auto const unstable = duration_in(R"({"state_key":"@a:b","msc4354_sticky":{"duration_ms":5000}})");

            THEN("it is not sticky, whatever the state key")
            {
                REQUIRE_FALSE(stable.has_value());
                REQUIRE_FALSE(unstable.has_value());
            }
        }
    }

    GIVEN("a sticky field in content, not at the top level")
    {
        WHEN("it is read")
        {
            THEN("it is not sticky")
            {
                REQUIRE_FALSE(duration_in(R"({"content":{"sticky":{"duration_ms":5000}}})").has_value());
            }
        }
    }

    GIVEN("a value that is not an object")
    {
        WHEN("it is read")
        {
            THEN("it is not sticky")
            {
                REQUIRE_FALSE(sticky_duration_of(pdu("5")).has_value());
                REQUIRE_FALSE(sticky_duration_of(pdu("[]")).has_value());
            }
        }
    }
}

SCENARIO("a client's sticky duration text is whole decimal digits of at least 1", "[events][sticky-events]")
{
    using merovingian::events::parse_sticky_duration_text;

    GIVEN("well-formed text")
    {
        WHEN("it is parsed")
        {
            THEN("the value is returned, with leading zeros accepted as for the delay parameter")
            {
                REQUIRE(parse_sticky_duration_text("1") == std::optional<std::int64_t>{1});
                REQUIRE(parse_sticky_duration_text("3600000") == std::optional<std::int64_t>{3'600'000});
                REQUIRE(parse_sticky_duration_text("007") == std::optional<std::int64_t>{7});
                REQUIRE(parse_sticky_duration_text("9007199254740991") ==
                        std::optional<std::int64_t>{9'007'199'254'740'991});
            }
        }
    }

    GIVEN("text that is not a whole decimal from 1 to 2^53 - 1, canonical JSON's largest integer")
    {
        auto const values = std::vector<std::string>{"",      "0",     "00",    "-1",   "+1",   " 1", "1 ", "1.5",
                                                     "1e3",   "0x10",  "abc",   "1a",   "٣",    "9223372036854775808",
                                                     "99999999999999999999", "-0", "9007199254740992",
                                                     "9223372036854775807"};

        WHEN("each is parsed")
        {
            auto parsed = std::vector<std::optional<std::int64_t>>{};
            for (auto const& value : values)
            {
                parsed.push_back(parse_sticky_duration_text(value));
            }

            THEN("each is refused")
            {
                for (auto index = std::size_t{0U}; index < values.size(); ++index)
                {
                    INFO(values[index]);
                    REQUIRE_FALSE(parsed[index].has_value());
                }
            }
        }
    }
}

SCENARIO("a sticky event expires an hour at most after it was first seen", "[events][sticky-events]")
{
    using merovingian::events::max_sticky_duration_ms;
    using merovingian::events::sticky_expiry_ms;

    GIVEN("an event stamped at the moment it was received")
    {
        WHEN("the expiry is computed for a short duration")
        {
            THEN("it is the stamp plus the duration")
            {
                REQUIRE(sticky_expiry_ms(1'000, 1'000, 5'000) == 6'000);
            }
        }

        WHEN("the expiry is computed for exactly the cap, and for more")
        {
            THEN("the duration is capped at one hour")
            {
                REQUIRE(max_sticky_duration_ms == 3'600'000);
                REQUIRE(sticky_expiry_ms(1'000, 1'000, 3'600'000) == 3'601'000);
                REQUIRE(sticky_expiry_ms(1'000, 1'000, 3'600'001) == 3'601'000);
                REQUIRE(sticky_expiry_ms(1'000, 1'000, int64_max) == 3'601'000);
            }
        }
    }

    GIVEN("an event stamped in the future by its sender")
    {
        WHEN("the expiry is computed")
        {
            THEN("the received time is used, so the sender cannot extend its life")
            {
                REQUIRE(sticky_expiry_ms(9'000'000, 1'000, 5'000) == 6'000);
            }
        }
    }

    GIVEN("an event stamped before it was received")
    {
        WHEN("the expiry is computed")
        {
            THEN("the stamp is used, so a late arrival is sticky for less time")
            {
                REQUIRE(sticky_expiry_ms(1'000, 9'000'000, 5'000) == 6'000);
            }
        }
    }

    GIVEN("extreme inputs")
    {
        WHEN("the sum would overflow")
        {
            THEN("it saturates at the largest value")
            {
                REQUIRE(sticky_expiry_ms(int64_max, int64_max, 3'600'000) == int64_max);
                REQUIRE(sticky_expiry_ms(int64_max - 1, int64_max, 3'600'000) == int64_max);
                REQUIRE(sticky_expiry_ms(int64_max - 3'600'000, int64_max, 3'600'000) == int64_max);
            }
        }

        WHEN("the stamp is negative or the smallest value")
        {
            THEN("the sum is exact or saturates at the smallest value, with no overflow")
            {
                REQUIRE(sticky_expiry_ms(-5'000, 1'000, 3'000) == -2'000);
                REQUIRE(sticky_expiry_ms(int64_min, int64_min, 3'600'000) == int64_min + 3'600'000);
                REQUIRE(sticky_expiry_ms(int64_min, 0, int64_min) == int64_min);
                REQUIRE(sticky_expiry_ms(int64_min, int64_min, int64_min) == int64_min);
            }
        }
    }
}

SCENARIO("the remaining sticky time is positive or absent", "[events][sticky-events]")
{
    using merovingian::events::sticky_remaining_ms;

    GIVEN("an expiry in the future")
    {
        WHEN("the remaining time is asked for")
        {
            THEN("it is the difference, down to 1 millisecond")
            {
                REQUIRE(sticky_remaining_ms(10'000, 4'000) == std::optional<std::int64_t>{6'000});
                REQUIRE(sticky_remaining_ms(10'000, 9'999) == std::optional<std::int64_t>{1});
            }
        }
    }

    GIVEN("an expiry that is now or past")
    {
        WHEN("the remaining time is asked for")
        {
            THEN("it is absent, never zero or negative")
            {
                REQUIRE_FALSE(sticky_remaining_ms(10'000, 10'000).has_value());
                REQUIRE_FALSE(sticky_remaining_ms(10'000, 10'001).has_value());
                REQUIRE_FALSE(sticky_remaining_ms(0, 5).has_value());
                REQUIRE_FALSE(sticky_remaining_ms(-5, 0).has_value());
            }
        }
    }

    GIVEN("extreme clock values")
    {
        WHEN("the difference would overflow")
        {
            THEN("it saturates or is absent, with no overflow")
            {
                REQUIRE(sticky_remaining_ms(int64_max, -5) == std::optional<std::int64_t>{int64_max});
                REQUIRE(sticky_remaining_ms(int64_max, int64_min) == std::optional<std::int64_t>{int64_max});
                REQUIRE_FALSE(sticky_remaining_ms(int64_min, 5).has_value());
                REQUIRE_FALSE(sticky_remaining_ms(int64_min, int64_max).has_value());
                REQUIRE(sticky_remaining_ms(5, int64_min) == std::optional<std::int64_t>{int64_max});
            }
        }
    }
}

SCENARIO("the composed sticky object and the field names follow ADR-0853", "[events][sticky-events]")
{
    GIVEN("a duration")
    {
        WHEN("the sticky object is built and serialised")
        {
            auto const object = merovingian::events::sticky_object(1'234);
            auto const serialised = merovingian::canonicaljson::serialize_canonical(object);

            THEN("it is {\"duration_ms\": N}, and a PDU holding it under either name reads back")
            {
                REQUIRE(serialised.output == R"({"duration_ms":1234})");
                REQUIRE(duration_in(R"({"sticky":)" + serialised.output + "}") == std::optional<std::int64_t>{1'234});
                REQUIRE(duration_in(R"({"msc4354_sticky":)" + serialised.output + "}") ==
                        std::optional<std::int64_t>{1'234});
            }
        }
    }

    GIVEN("the field name constants")
    {
        WHEN("they are read")
        {
            THEN("they are the stable and unstable names")
            {
                REQUIRE(merovingian::events::sticky_field == "sticky");
                REQUIRE(merovingian::events::unstable_sticky_field == "msc4354_sticky");
                REQUIRE(merovingian::events::sticky_remaining_field == "sticky_duration_remaining_ms");
                REQUIRE(merovingian::events::unstable_sticky_remaining_field == "msc4354_sticky_duration_ttl_ms");
            }
        }
    }
}
