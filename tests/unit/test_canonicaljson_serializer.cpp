// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/canonicaljson/parser.hpp>
#include <merovingian/canonicaljson/serializer.hpp>
#include <merovingian/canonicaljson/value.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>

TEST_CASE("Canonical JSON serializes primitive values", "[canonicaljson]")
{
    // Given
    auto const null_value = merovingian::canonicaljson::Value{nullptr};
    auto const bool_value = merovingian::canonicaljson::Value{true};
    auto const integer_value = merovingian::canonicaljson::Value{std::int64_t{-42}};

    // When
    auto const null_result = merovingian::canonicaljson::serialize_canonical(null_value);
    auto const bool_result = merovingian::canonicaljson::serialize_canonical(bool_value);
    auto const integer_result = merovingian::canonicaljson::serialize_canonical(integer_value);

    // Then
    REQUIRE(null_result.output == "null");
    REQUIRE(bool_result.output == "true");
    REQUIRE(integer_result.output == "-42");
}

TEST_CASE("Canonical JSON escapes strings deterministically", "[canonicaljson]")
{
    // Given
    auto const value = merovingian::canonicaljson::Value{std::string{"quote=\" slash=\\ newline=\n"}};

    // When
    auto const result = merovingian::canonicaljson::serialize_canonical(value);

    // Then
    REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(result.output == "\"quote=\\\" slash=\\\\ newline=\\n\"");
}

TEST_CASE("Canonical JSON preserves escaped control code points when reserializing", "[canonicaljson]")
{
    // Given
    auto const parsed = merovingian::canonicaljson::parse_lossless("\"\\u0000\\u001f\"");

    // When
    auto const result = merovingian::canonicaljson::serialize_canonical(parsed.value);

    // Then
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(result.output == "\"\\u0000\\u001f\"");
}

TEST_CASE("Canonical JSON rejects programmatic invalid UTF-8 strings", "[canonicaljson]")
{
    // Given
    auto const value = merovingian::canonicaljson::Value{std::string{"\xC0\x80", 2U}};

    // When
    auto const result = merovingian::canonicaljson::serialize_canonical(value);

    // Then
    REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::invalid_string);
}

TEST_CASE("Canonical JSON serializes arrays without whitespace", "[canonicaljson]")
{
    // Given
    auto array = merovingian::canonicaljson::Array{};
    array.emplace_back(std::int64_t{1});
    array.emplace_back(false);
    array.emplace_back(std::string{"x"});

    // When
    auto const result = merovingian::canonicaljson::serialize_canonical(
        merovingian::canonicaljson::Value{std::move(array)}
    );

    // Then
    REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(result.output == "[1,false,\"x\"]");
}

TEST_CASE("Canonical JSON sorts object keys lexicographically", "[canonicaljson]")
{
    // Given
    auto object = merovingian::canonicaljson::Object{};
    object.push_back(merovingian::canonicaljson::make_member("z", merovingian::canonicaljson::Value{std::int64_t{3}}));
    object.push_back(merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{1}}));
    object.push_back(merovingian::canonicaljson::make_member("m", merovingian::canonicaljson::Value{std::int64_t{2}}));

    // When
    auto const result = merovingian::canonicaljson::serialize_canonical(
        merovingian::canonicaljson::Value{std::move(object)}
    );

    // Then
    REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(result.output == "{\"a\":1,\"m\":2,\"z\":3}");
}

TEST_CASE("Canonical JSON rejects duplicate object keys", "[canonicaljson]")
{
    // Given
    auto object = merovingian::canonicaljson::Object{};
    object.push_back(merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{1}}));
    object.push_back(merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{2}}));

    // When
    auto const result = merovingian::canonicaljson::serialize_canonical(
        merovingian::canonicaljson::Value{std::move(object)}
    );

    // Then
    REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::duplicate_object_key);
    REQUIRE(result.output.empty());
}

TEST_CASE("Canonical JSON error names are stable", "[canonicaljson]")
{
    // Given
    auto constexpr no_error = merovingian::canonicaljson::CanonicalJsonError::none;
    auto constexpr duplicate_key = merovingian::canonicaljson::CanonicalJsonError::duplicate_object_key;
    auto constexpr invalid_string = merovingian::canonicaljson::CanonicalJsonError::invalid_string;

    // When
    auto const no_error_name = std::string{merovingian::canonicaljson::canonical_json_error_name(no_error)};
    auto const duplicate_key_name = std::string{merovingian::canonicaljson::canonical_json_error_name(duplicate_key)};
    auto const invalid_string_name = std::string{merovingian::canonicaljson::canonical_json_error_name(invalid_string)};

    // Then
    REQUIRE(no_error_name == "none");
    REQUIRE(duplicate_key_name == "duplicate_object_key");
    REQUIRE(invalid_string_name == "invalid_string");
}
