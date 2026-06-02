// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/signable.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Canonical JSON parser accepts and canonicalizes Matrix-style objects", "[canonicaljson][parser]")
{
    GIVEN("a Matrix-style JSON object")
    {
        auto constexpr input =
            "{\"unsigned\":{},\"origin\":\"example.org\",\"depth\":12,\"content\":{\"body\":\"hi\"}}";

        WHEN("it is parsed and serialized canonically")
        {
            auto const parsed = merovingian::canonicaljson::parse_lossless(input);
            auto const serialized = merovingian::canonicaljson::serialize_canonical(parsed.value);

            THEN("the canonical output is deterministic")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(serialized.output ==
                        "{\"content\":{\"body\":\"hi\"},\"depth\":12,\"origin\":\"example.org\",\"unsigned\":{}}");
            }
        }
    }
}

SCENARIO("Canonical JSON parser rejects duplicate object keys", "[canonicaljson][parser]")
{
    GIVEN("an object with duplicate keys")
    {
        auto constexpr input = "{\"a\":1,\"a\":2}";

        WHEN("it is parsed")
        {
            auto const parsed = merovingian::canonicaljson::parse_lossless(input);

            THEN("duplicate key parsing fails")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::duplicate_object_key);
            }
        }
    }
}

SCENARIO("Canonical JSON parser rejects invalid UTF-8 strings", "[canonicaljson][parser]")
{
    GIVEN("a JSON string containing invalid UTF-8")
    {
        auto const input = std::string{"\"\xC0\x80\"", 4U};

        WHEN("it is parsed")
        {
            auto const parsed = merovingian::canonicaljson::parse_lossless(input);

            THEN("invalid string parsing fails")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::invalid_string);
            }
        }
    }
}

SCENARIO("Canonical JSON parser rejects non-integer and out-of-range numbers", "[canonicaljson][parser]")
{
    GIVEN("fractional, exponent, and out-of-range number tokens")
    {
        auto constexpr fractional_input = "1.25";
        auto constexpr exponent_input = "1e2";
        auto constexpr too_large_input = "9223372036854775808";
        auto constexpr unsigned_64_input = "18446744073709551615";

        WHEN("the number tokens are parsed")
        {
            auto const fractional = merovingian::canonicaljson::parse_lossless(fractional_input);
            auto const exponent = merovingian::canonicaljson::parse_lossless(exponent_input);
            auto const too_large = merovingian::canonicaljson::parse_lossless(too_large_input);
            auto const unsigned_64 = merovingian::canonicaljson::parse_lossless(unsigned_64_input);

            THEN("lossy or out-of-range numbers are rejected")
            {
                REQUIRE(fractional.error == merovingian::canonicaljson::ParseError::invalid_number);
                REQUIRE(exponent.error == merovingian::canonicaljson::ParseError::invalid_number);
                REQUIRE(too_large.error == merovingian::canonicaljson::ParseError::integer_out_of_range);
                REQUIRE(unsigned_64.error == merovingian::canonicaljson::ParseError::integer_out_of_range);
            }
        }
    }
}

SCENARIO("Canonical JSON parser rejects leading zeros and explicit positive signs",
         "[canonicaljson][parser]")
{
    GIVEN("non-canonical integer tokens")
    {
        auto constexpr leading_zero_short = "01";
        auto constexpr leading_zero_long = "007";
        auto constexpr explicit_positive = "+5";
        auto constexpr leading_positive_negative = "+-1";
        auto constexpr signed_zero = "-0";

        WHEN("the tokens are parsed")
        {
            auto const short_result = merovingian::canonicaljson::parse_lossless(leading_zero_short);
            auto const long_result = merovingian::canonicaljson::parse_lossless(leading_zero_long);
            auto const positive_result = merovingian::canonicaljson::parse_lossless(explicit_positive);
            auto const both_result = merovingian::canonicaljson::parse_lossless(leading_positive_negative);
            auto const signed_zero_result = merovingian::canonicaljson::parse_lossless(signed_zero);

            THEN("every non-canonical shape is rejected as invalid_number")
            {
                REQUIRE(short_result.error == merovingian::canonicaljson::ParseError::invalid_number);
                REQUIRE(long_result.error == merovingian::canonicaljson::ParseError::invalid_number);
                REQUIRE(positive_result.error == merovingian::canonicaljson::ParseError::invalid_number);
                REQUIRE(both_result.error == merovingian::canonicaljson::ParseError::invalid_number);
                // "-0" is technically `^-?0$` so it matches the canonical shape;
                // the from_chars round-trip will succeed with value 0. The
                // canonical-JSON spec permits it; pin that here so a future
                // tightening does not silently break it.
                REQUIRE(signed_zero_result.error == merovingian::canonicaljson::ParseError::none);
            }
        }
    }
}

SCENARIO("Canonical JSON parser accepts the full int64 boundary range", "[canonicaljson][parser]")
{
    GIVEN("canonical int64 literals covering zero, negatives, and the int64 boundary")
    {
        auto constexpr zero = "0";
        auto constexpr positive_small = "42";
        auto constexpr negative_small = "-7";
        auto constexpr int64_min = "-9223372036854775808";
        auto constexpr int64_max = "9223372036854775807";

        WHEN("the literals are parsed")
        {
            auto const zero_result = merovingian::canonicaljson::parse_lossless(zero);
            auto const positive_result = merovingian::canonicaljson::parse_lossless(positive_small);
            auto const negative_result = merovingian::canonicaljson::parse_lossless(negative_small);
            auto const min_result = merovingian::canonicaljson::parse_lossless(int64_min);
            auto const max_result = merovingian::canonicaljson::parse_lossless(int64_max);

            THEN("all canonical int64 shapes parse as int64 with no error")
            {
                REQUIRE(zero_result.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(positive_result.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(negative_result.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(min_result.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(max_result.error == merovingian::canonicaljson::ParseError::none);
            }
        }
    }
}

SCENARIO("Canonical JSON parser rejects trailing garbage after a complete value",
         "[canonicaljson][parser]")
{
    GIVEN("a complete JSON value followed by a second top-level value")
    {
        auto constexpr input = "1 2";
        auto constexpr array_with_trailing = "[1]  garbage";

        WHEN("the inputs are parsed")
        {
            auto const first = merovingian::canonicaljson::parse_lossless(input);
            auto const second = merovingian::canonicaljson::parse_lossless(array_with_trailing);

            THEN("trailing data is rejected")
            {
                // YYJSON_READ_STOP_WHEN_DONE makes the parser return
                // MEROVINGIAN_YYJSON_READ_ERROR_UNEXPECTED_CONTENT, which the
                // adapter maps to ParseError::trailing_data.
                REQUIRE(first.error == merovingian::canonicaljson::ParseError::trailing_data);
                REQUIRE(second.error == merovingian::canonicaljson::ParseError::trailing_data);
            }
        }
    }
}

SCENARIO("Canonical JSON parser decodes unicode escapes", "[canonicaljson][parser]")
{
    GIVEN("a string with unicode escapes")
    {
        auto constexpr input = "\"snowman=\\u2603 smile=\\uD83D\\uDE00\"";

        WHEN("it is parsed and serialized")
        {
            auto const parsed = merovingian::canonicaljson::parse_lossless(input);
            auto const serialized = merovingian::canonicaljson::serialize_canonical(parsed.value);

            THEN("the escaped code points are decoded")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(serialized.output == "\"snowman=☃ smile=😀\"");
            }
        }
    }
}

SCENARIO("Canonical JSON parser rejects excessive nesting", "[canonicaljson][parser]")
{
    GIVEN("a deeply nested JSON array")
    {
        auto input = std::string{};
        for (auto index = 0U; index < 70U; ++index)
        {
            input.push_back('[');
        }
        for (auto index = 0U; index < 70U; ++index)
        {
            input.push_back(']');
        }

        WHEN("it is parsed")
        {
            auto const parsed = merovingian::canonicaljson::parse_lossless(input);

            THEN("the parser rejects the nesting depth")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::nesting_too_deep);
            }
        }
    }
}

SCENARIO("Canonical JSON signable object view serializes deterministically", "[canonicaljson][signable]")
{
    GIVEN("an object with unsorted keys")
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless("{\"z\":3,\"a\":1}");

        WHEN("the signable view is serialized")
        {
            auto const signable = merovingian::canonicaljson::make_signable_object_view(parsed.value);

            THEN("keys are sorted deterministically")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(signable.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(signable.output == "{\"a\":1,\"z\":3}");
            }
        }
    }
}

SCENARIO("Canonical JSON parse error names are stable", "[canonicaljson][parser]")
{
    GIVEN("canonical JSON parse error values")
    {
        auto constexpr no_error = merovingian::canonicaljson::ParseError::none;
        auto constexpr duplicate_key = merovingian::canonicaljson::ParseError::duplicate_object_key;
        auto constexpr integer_range = merovingian::canonicaljson::ParseError::integer_out_of_range;

        WHEN("their names are requested")
        {
            auto const no_error_name = std::string{merovingian::canonicaljson::parse_error_name(no_error)};
            auto const duplicate_key_name = std::string{merovingian::canonicaljson::parse_error_name(duplicate_key)};
            auto const integer_range_name = std::string{merovingian::canonicaljson::parse_error_name(integer_range)};

            THEN("the diagnostic names are stable")
            {
                REQUIRE(no_error_name == "none");
                REQUIRE(duplicate_key_name == "duplicate_object_key");
                REQUIRE(integer_range_name == "integer_out_of_range");
            }
        }
    }
}
