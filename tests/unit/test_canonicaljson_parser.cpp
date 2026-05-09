// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/canonicaljson/parser.hpp>
#include <merovingian/canonicaljson/serializer.hpp>
#include <merovingian/canonicaljson/signable.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("Canonical JSON parser accepts and canonicalizes Matrix-style objects", "[canonicaljson][parser]")
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(
        "{\"unsigned\":{},\"origin\":\"example.org\",\"depth\":12,\"content\":{\"body\":\"hi\"}}"
    );

    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

    auto const serialized = merovingian::canonicaljson::serialize_canonical(parsed.value);

    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(serialized.output == "{\"content\":{\"body\":\"hi\"},\"depth\":12,\"origin\":\"example.org\",\"unsigned\":{}}");
}

TEST_CASE("Canonical JSON parser rejects duplicate object keys", "[canonicaljson][parser]")
{
    auto const parsed = merovingian::canonicaljson::parse_lossless("{\"a\":1,\"a\":2}");

    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::duplicate_object_key);
}

TEST_CASE("Canonical JSON parser rejects invalid UTF-8 strings", "[canonicaljson][parser]")
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(std::string{"\"\xC0\x80\"", 4U});

    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::invalid_string);
}

TEST_CASE("Canonical JSON parser rejects non-integer and out-of-range numbers", "[canonicaljson][parser]")
{
    auto const fractional = merovingian::canonicaljson::parse_lossless("1.25");
    auto const exponent = merovingian::canonicaljson::parse_lossless("1e2");
    auto const too_large = merovingian::canonicaljson::parse_lossless("9223372036854775808");

    REQUIRE(fractional.error == merovingian::canonicaljson::ParseError::invalid_number);
    REQUIRE(exponent.error == merovingian::canonicaljson::ParseError::invalid_number);
    REQUIRE(too_large.error == merovingian::canonicaljson::ParseError::integer_out_of_range);
}

TEST_CASE("Canonical JSON parser decodes unicode escapes", "[canonicaljson][parser]")
{
    auto const parsed = merovingian::canonicaljson::parse_lossless("\"snowman=\\u2603 smile=\\uD83D\\uDE00\"");

    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

    auto const serialized = merovingian::canonicaljson::serialize_canonical(parsed.value);

    REQUIRE(serialized.output == "\"snowman=☃ smile=😀\"");
}

TEST_CASE("Canonical JSON parser rejects excessive nesting", "[canonicaljson][parser]")
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

    auto const parsed = merovingian::canonicaljson::parse_lossless(input);

    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::nesting_too_deep);
}

TEST_CASE("Canonical JSON signable object view serializes deterministically", "[canonicaljson][signable]")
{
    auto const parsed = merovingian::canonicaljson::parse_lossless("{\"z\":3,\"a\":1}");
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

    auto const signable = merovingian::canonicaljson::make_signable_object_view(parsed.value);

    REQUIRE(signable.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(signable.output == "{\"a\":1,\"z\":3}");
}

TEST_CASE("Canonical JSON parse error names are stable", "[canonicaljson][parser]")
{
    REQUIRE(std::string{merovingian::canonicaljson::parse_error_name(merovingian::canonicaljson::ParseError::none)} == "none");
    REQUIRE(
        std::string{merovingian::canonicaljson::parse_error_name(merovingian::canonicaljson::ParseError::duplicate_object_key)}
        == "duplicate_object_key"
    );
    REQUIRE(
        std::string{merovingian::canonicaljson::parse_error_name(merovingian::canonicaljson::ParseError::integer_out_of_range)}
        == "integer_out_of_range"
    );
}
