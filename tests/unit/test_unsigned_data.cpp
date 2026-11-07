// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for events::without_unsigned and events::without_unsigned_json (ADR-0402).
//
// Spec (server-server-api.md, "Calculating the reference hash for an event", "Signing events"): the
// `signatures` and `unsigned` properties are not covered by a signature or hash, so a received PDU is
// stored without the `unsigned` a remote server supplied.

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/events/unsigned_data.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>

namespace
{

[[nodiscard]] auto canonical(merovingian::canonicaljson::Value const& value) -> std::string
{
    return merovingian::canonicaljson::serialize_canonical(value).output;
}

[[nodiscard]] auto parsed(std::string const& json) -> merovingian::canonicaljson::Value
{
    auto result = merovingian::canonicaljson::parse_lossless(json);
    REQUIRE(result.error == merovingian::canonicaljson::ParseError::none);
    return std::move(result.value);
}

} // namespace

SCENARIO("A received PDU is stored without its top-level unsigned object", "[events][unsigned][unit]")
{
    GIVEN("an event value carrying a remote server's unsigned object")
    {
        auto const event = parsed(R"({"type":"m.room.message","unsigned":{"age":1},"content":{"unsigned":"kept"}})");

        WHEN("the unsigned member is removed")
        {
            auto const stripped = merovingian::events::without_unsigned(event);

            THEN("only the top-level member goes; a nested member of the same name stays")
            {
                REQUIRE(canonical(stripped) == R"({"content":{"unsigned":"kept"},"type":"m.room.message"})");
            }
        }
    }

    GIVEN("an event value with no unsigned member, and a value that is not an object")
    {
        auto const event = parsed(R"({"type":"m.room.message"})");
        auto const array = parsed("[1,2]");

        WHEN("they are passed through")
        {
            THEN("each is returned unchanged")
            {
                REQUIRE(canonical(merovingian::events::without_unsigned(event)) == canonical(event));
                REQUIRE(canonical(merovingian::events::without_unsigned(array)) == "[1,2]");
            }
        }
    }
}

SCENARIO("Event text is stripped of unsigned, or refused when it cannot be", "[events][unsigned][unit]")
{
    GIVEN("event text that names no unsigned member")
    {
        auto const text = std::string{R"({ "type" : "m.room.message" })"};

        WHEN("it is stripped")
        {
            auto const stripped = merovingian::events::without_unsigned_json(text);

            THEN("it comes back byte for byte, whitespace included")
            {
                REQUIRE(stripped.has_value());
                REQUIRE(*stripped == text);
            }
        }
    }

    GIVEN("event text whose only mention of unsigned is inside content")
    {
        auto const text = std::string{R"({"content":{"unsigned":1},"type":"x"})"};

        WHEN("it is stripped")
        {
            auto const stripped = merovingian::events::without_unsigned_json(text);

            THEN("it comes back unchanged")
            {
                REQUIRE(stripped.has_value());
                REQUIRE(*stripped == text);
            }
        }
    }

    GIVEN("event text with a top-level unsigned member")
    {
        WHEN("it is stripped")
        {
            auto const stripped = merovingian::events::without_unsigned_json(
                R"({"type":"x","unsigned":{"age":5,"redacted_because":{}},"content":{}})");

            THEN("the result is canonical JSON without the member")
            {
                REQUIRE(stripped.has_value());
                REQUIRE(*stripped == R"({"content":{},"type":"x"})");
            }
        }
    }

    GIVEN("text that names unsigned but is not a JSON object")
    {
        WHEN("it is stripped")
        {
            THEN("nothing is returned, so the caller refuses the event")
            {
                REQUIRE_FALSE(merovingian::events::without_unsigned_json(R"(["unsigned"])").has_value());
                REQUIRE_FALSE(merovingian::events::without_unsigned_json(R"({"unsigned":)").has_value());
                REQUIRE_FALSE(merovingian::events::without_unsigned_json(R"("unsigned")").has_value());
            }
        }
    }
}
