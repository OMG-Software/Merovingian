// SPDX-License-Identifier: GPL-3.0-or-later

#include <catch2/catch_test_macros.hpp>
#include <merovingian/canonicaljson/parser.hpp>
#include <merovingian/canonicaljson/serializer.hpp>
#include <merovingian/canonicaljson/signable.hpp>
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
