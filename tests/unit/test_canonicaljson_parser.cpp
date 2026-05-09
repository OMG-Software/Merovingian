// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/canonicaljson/parser.hpp>
#include <merovingian/canonicaljson/serializer.hpp>
#include <merovingian/canonicaljson/signable.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("Canonical JSON parser accepts and canonicalizes Matrix-style objects", "[canonicaljson][parser]")
{
    // Given
    auto constexpr input = "{\"unsigned\":{},\"origin\":\"example.org\",\"depth\":12,\"content\":{\"body\":\"hi\"}}";

    // When
    auto const parsed = merovingian::canonicaljson::parse_lossless(input);
    auto const serialized = merovingian::canonicaljson::serialize_canonical(parsed.value);

    // Then
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(serialized.output == "{\"content\":{\"body\":\"hi\"},\"depth\":12,\"origin\":\"example.org\",\"unsigned\":{}}");
}

TEST_CASE("Canonical JSON parser rejects duplicate object keys", "[canonicaljson][parser]")
{
    // Given
    auto constexpr input = "{\"a\":1,\"a\":2}";

    // When
    auto const parsed = merovingian::canonicaljson::parse_lossless(input);

    // Then
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::duplicate_object_key);
}

TEST_CASE("Canonical JSON parser rejects invalid UTF-8 strings", "[canonicaljson][parser]")
{
    // Given
    auto const input = std::string{"\"\xC0\x80\"", 4U};

    // When
    auto const parsed = merovingian::canonicaljson::parse_lossless(input);

    // Then
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::invalid_string);
}

TEST_CASE("Canonical JSON parser rejects non-integer and out-of-range numbers", "[canonicaljson][parser]")
{
    // Given
    auto constexpr fractional_input = "1.25";
    auto constexpr exponent_input = "1e2";
    auto constexpr too_large_input = "9223372036854775808";

    // When
    auto const fractional = merovingian::canonicaljson::parse_lossless(fractional_input);
    auto const exponent = merovingian::canonicaljson::parse_lossless(exponent_input);
    auto const too_large = merovingian::canonicaljson::parse_lossless(too_large_input);

    // Then
    REQUIRE(fractional.error == merovingian::canonicaljson::ParseError::invalid_number);
    REQUIRE(exponent.error == merovingian::canonicaljson::ParseError::invalid_number);
    REQUIRE(too_large.error == merovingian::canonicaljson::ParseError::integer_out_of_range);
}

TEST_CASE("Canonical JSON parser decodes unicode escapes", "[canonicaljson][parser]")
{
    // Given
    auto constexpr input = "\"snowman=\\u2603 smile=\\uD83D\\uDE00\"";

    // When
    auto const parsed = merovingian::canonicaljson::parse_lossless(input);
    auto const serialized = merovingian::canonicaljson::serialize_canonical(parsed.value);

    // Then
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    REQUIRE(serialized.output == "\"snowman=☃ smile=😀\"");
}

TEST_CASE("Canonical JSON parser rejects excessive nesting", "[canonicaljson][parser]")
{
    // Given
    auto input = std::string{};
    for (auto index = 0U; index < 70U; ++index)
    {
        input.push_back('[');
    }
    for (auto index = 0U; index < 70U; ++index)
    {
        input.push_back(']');
    }

    // When
    auto const parsed = merovingian::canonicaljson::parse_lossless(input);

    // Then
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::nesting_too_deep);
}

TEST_CASE("Canonical JSON signable object view serializes deterministically", "[canonicaljson][signable]")
{
    // Given
    auto const parsed = merovingian::canonicaljson::parse_lossless("{\"z\":3,\"a\":1}");

    // When
    auto const signable = merovingian::canonicaljson::make_signable_object_view(parsed.value);

    // Then
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    REQUIRE(signable.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(signable.output == "{\"a\":1,\"z\":3}");
}

TEST_CASE("Canonical JSON parse error names are stable", "[canonicaljson][parser]")
{
    // Given
    auto constexpr no_error = merovingian::canonicaljson::ParseError::none;
    auto constexpr duplicate_key = merovingian::canonicaljson::ParseError::duplicate_object_key;
    auto constexpr integer_range = merovingian::canonicaljson::ParseError::integer_out_of_range;

    // When
    auto const no_error_name = std::string{merovingian::canonicaljson::parse_error_name(no_error)};
    auto const duplicate_key_name = std::string{merovingian::canonicaljson::parse_error_name(duplicate_key)};
    auto const integer_range_name = std::string{merovingian::canonicaljson::parse_error_name(integer_range)};

    // Then
    REQUIRE(no_error_name == "none");
    REQUIRE(duplicate_key_name == "duplicate_object_key");
    REQUIRE(integer_range_name == "integer_out_of_range");
}
