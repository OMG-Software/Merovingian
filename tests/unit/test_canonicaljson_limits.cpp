// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstddef>
#include <string>

// These tests cover the object-member-count DoS fix: an unauthenticated
// caller (e.g. POST /login, /register) could previously submit a body full
// of unique object keys and drive the parser's and serializer's O(n^2)
// duplicate-key scans into billions of string comparisons. Both scans are
// now O(n) via a hash-set membership check, and the parser additionally
// enforces an explicit member-count cap as defense in depth.
namespace
{
[[nodiscard]] auto make_object_with_unique_keys(std::size_t member_count) -> std::string
{
    auto input = std::string{"{"};
    for (auto index = std::size_t{0U}; index < member_count; ++index)
    {
        if (index != 0U)
        {
            input.push_back(',');
        }
        input += "\"k" + std::to_string(index) + "\":0";
    }
    input.push_back('}');
    return input;
}
} // namespace

SCENARIO("Canonical JSON parser still rejects a duplicate object key after the O(n) rewrite", "[canonicaljson][limits]")
{
    GIVEN("an object with a repeated key")
    {
        auto constexpr input = "{\"a\":1,\"b\":2,\"a\":3}";

        WHEN("it is parsed")
        {
            auto const parsed = merovingian::canonicaljson::parse_lossless(input);

            THEN("duplicate key parsing still fails")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::duplicate_object_key);
            }
        }
    }
}

SCENARIO("Canonical JSON parser accepts a large object below the member cap", "[canonicaljson][limits]")
{
    GIVEN("an object with many unique keys, comfortably under the member cap")
    {
        auto const input = make_object_with_unique_keys(4096U);

        WHEN("it is parsed")
        {
            auto const parsed = merovingian::canonicaljson::parse_lossless(input);

            THEN("the large but legal object still parses")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(object != nullptr);
                REQUIRE(object->size() == 4096U);
            }
        }
    }
}

SCENARIO("Canonical JSON parser rejects an object that exceeds the member cap", "[canonicaljson][limits]")
{
    GIVEN("an object with one more member than the parser's member cap allows")
    {
        auto const input = make_object_with_unique_keys(merovingian::canonicaljson::max_object_members + 1U);

        WHEN("it is parsed")
        {
            auto const parsed = merovingian::canonicaljson::parse_lossless(input);

            THEN("the object is rejected as too_many_object_members")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::too_many_object_members);
            }
        }
    }
}

SCENARIO("Canonical JSON parser accepts an object exactly at the member cap", "[canonicaljson][limits]")
{
    GIVEN("an object with exactly the parser's member cap of unique keys")
    {
        auto const input = make_object_with_unique_keys(merovingian::canonicaljson::max_object_members);

        WHEN("it is parsed")
        {
            auto const parsed = merovingian::canonicaljson::parse_lossless(input);

            THEN("the boundary value is still accepted")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
            }
        }
    }
}

SCENARIO("object_has_duplicate_keys still reports true and false correctly after the O(n) rewrite",
         "[canonicaljson][limits]")
{
    GIVEN("an object with a duplicated key and an object with all-unique keys")
    {
        auto const duplicate_input = std::string{"{\"a\":1,\"b\":2,\"a\":3}"};
        auto const unique_input = make_object_with_unique_keys(2048U);

        // Build the Object trees directly with the general parser bypassed —
        // parse_json/parse_lossless already reject duplicates before
        // serialization would ever see them, so exercise
        // object_has_duplicate_keys against hand-built trees instead.
        auto duplicate_object = merovingian::canonicaljson::Object{};
        duplicate_object.push_back(
            merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{1}}));
        duplicate_object.push_back(
            merovingian::canonicaljson::make_member("b", merovingian::canonicaljson::Value{std::int64_t{2}}));
        duplicate_object.push_back(
            merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{3}}));

        auto const parsed_unique = merovingian::canonicaljson::parse_lossless(unique_input);
        REQUIRE(parsed_unique.error == merovingian::canonicaljson::ParseError::none);
        auto const* unique_object = std::get_if<merovingian::canonicaljson::Object>(&parsed_unique.value.storage());
        REQUIRE(unique_object != nullptr);

        WHEN("duplicate detection runs over each tree")
        {
            auto const has_duplicate = merovingian::canonicaljson::object_has_duplicate_keys(duplicate_object);
            auto const has_no_duplicate = merovingian::canonicaljson::object_has_duplicate_keys(*unique_object);

            THEN("the duplicated tree reports true and the all-unique tree reports false")
            {
                REQUIRE(has_duplicate);
                REQUIRE_FALSE(has_no_duplicate);
            }
        }
    }
}

SCENARIO("Permissive JSON parsing refuses integers outside the canonical range without wrapping",
         "[canonicaljson][security][http-7]")
{
    GIVEN("integers above the canonical maximum or below the minimum, including UINT64_MAX")
    {
        auto const input = GENERATE("18446744073709551615", "9007199254740992", "9223372036854775807",
                                    "9223372036854775808", "[18446744073709551615]", "{\"value\":18446744073709551615}",
                                    "-9007199254740992", "-9223372036854775808");
        CAPTURE(input);
        WHEN("the general JSON parser reads the input")
        {
            auto const parsed = merovingian::canonicaljson::parse_json(input);
            THEN("the integer is refused rather than stored as a negative value")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::integer_out_of_range);
                REQUIRE(std::holds_alternative<std::nullptr_t>(parsed.value.storage()));
            }
        }
    }
    GIVEN("the canonical integer boundaries and a floating point value")
    {
        auto const input = GENERATE("9007199254740991", "-9007199254740991", "0", "1.5");
        CAPTURE(input);
        WHEN("the general JSON parser reads the input")
        {
            auto const parsed = merovingian::canonicaljson::parse_json(input);
            THEN("permitted integers and floating point JSON remain supported")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
            }
        }
    }
}

// ADR-0398: X-Matrix authentication rebuilds the signed bytes from the numbers as they were sent.
SCENARIO("Numbers Canonical JSON cannot represent can be kept exactly as they were received",
         "[canonicaljson][raw-numbers]")
{
    GIVEN("a body holding a float, an exponent, an out-of-range integer and a negative zero, keys out of order")
    {
        auto const body = std::string_view{R"({"z":1.50,"y":1E5,"x":9007199254740993,"w":-0,"v":[7,{"b":2,"a":1.0}]})"};

        WHEN("it is parsed keeping those numbers and serialized")
        {
            auto const parsed = merovingian::canonicaljson::parse_preserving_numbers(body);
            REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
            auto const general = merovingian::canonicaljson::serialize_canonical(parsed.value);
            auto const strict = merovingian::canonicaljson::serialize_canonical_strict(parsed.value);

            THEN("each number's bytes survive, the keys are sorted, and the strict path used for hashes refuses it")
            {
                REQUIRE(general.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(general.output == R"({"v":[7,{"a":1.0,"b":2}],"w":-0,"x":9007199254740993,"y":1E5,"z":1.50})");
                REQUIRE(strict.error != merovingian::canonicaljson::CanonicalJsonError::none);
            }
        }

        WHEN("it is parsed by the canonical parser")
        {
            auto const parsed = merovingian::canonicaljson::parse_lossless(body);

            THEN("it is still refused")
            {
                REQUIRE(parsed.error != merovingian::canonicaljson::ParseError::none);
            }
        }
    }

    GIVEN("text that is not JSON, and a bad number form")
    {
        WHEN("it is parsed keeping numbers")
        {
            auto const not_json = merovingian::canonicaljson::parse_preserving_numbers(R"({"a":)");
            auto const leading_zero = merovingian::canonicaljson::parse_preserving_numbers(R"({"a":007})");
            auto const duplicate = merovingian::canonicaljson::parse_preserving_numbers(R"({"a":1.5,"a":2})");

            THEN("every other rule of the parser still holds")
            {
                REQUIRE(not_json.error != merovingian::canonicaljson::ParseError::none);
                REQUIRE(leading_zero.error != merovingian::canonicaljson::ParseError::none);
                REQUIRE(duplicate.error == merovingian::canonicaljson::ParseError::duplicate_object_key);
            }
        }
    }
}
