// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/canonicaljson/parser.hpp>
#include <merovingian/canonicaljson/serializer.hpp>
#include <merovingian/canonicaljson/value.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>

TEST_CASE("Canonical JSON serializes primitive values", "[canonicaljson]")
{
    REQUIRE(merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{nullptr}).output == "null");
    REQUIRE(merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{true}).output == "true");
    REQUIRE(merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::int64_t{-42}}).output == "-42");
}

TEST_CASE("Canonical JSON escapes strings deterministically", "[canonicaljson]")
{
    auto const result = merovingian::canonicaljson::serialize_canonical(
        merovingian::canonicaljson::Value{std::string{"quote=\" slash=\\ newline=\n"}}
    );

    REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(result.output == "\"quote=\\\" slash=\\\\ newline=\\n\"");
}

TEST_CASE("Canonical JSON preserves escaped control code points when reserializing", "[canonicaljson]")
{
    auto const parsed = merovingian::canonicaljson::parse_lossless("\"\\u0000\\u001f\"");
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

    auto const result = merovingian::canonicaljson::serialize_canonical(parsed.value);

    REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(result.output == "\"\\u0000\\u001f\"");
}

TEST_CASE("Canonical JSON rejects programmatic invalid UTF-8 strings", "[canonicaljson]")
{
    auto const result = merovingian::canonicaljson::serialize_canonical(
        merovingian::canonicaljson::Value{std::string{"\xC0\x80", 2U}}
    );

    REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::invalid_string);
}

TEST_CASE("Canonical JSON serializes arrays without whitespace", "[canonicaljson]")
{
    auto array = merovingian::canonicaljson::Array{};
    array.emplace_back(std::int64_t{1});
    array.emplace_back(false);
    array.emplace_back(std::string{"x"});

    auto const result = merovingian::canonicaljson::serialize_canonical(
        merovingian::canonicaljson::Value{std::move(array)}
    );

    REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(result.output == "[1,false,\"x\"]");
}

TEST_CASE("Canonical JSON sorts object keys lexicographically", "[canonicaljson]")
{
    auto object = merovingian::canonicaljson::Object{};
    object.push_back(merovingian::canonicaljson::make_member("z", merovingian::canonicaljson::Value{std::int64_t{3}}));
    object.push_back(merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{1}}));
    object.push_back(merovingian::canonicaljson::make_member("m", merovingian::canonicaljson::Value{std::int64_t{2}}));

    auto const result = merovingian::canonicaljson::serialize_canonical(
        merovingian::canonicaljson::Value{std::move(object)}
    );

    REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
    REQUIRE(result.output == "{\"a\":1,\"m\":2,\"z\":3}");
}

TEST_CASE("Canonical JSON rejects duplicate object keys", "[canonicaljson]")
{
    auto object = merovingian::canonicaljson::Object{};
    object.push_back(merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{1}}));
    object.push_back(merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{2}}));

    auto const result = merovingian::canonicaljson::serialize_canonical(
        merovingian::canonicaljson::Value{std::move(object)}
    );

    REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::duplicate_object_key);
    REQUIRE(result.output.empty());
}

TEST_CASE("Canonical JSON error names are stable", "[canonicaljson]")
{
    REQUIRE(std::string{merovingian::canonicaljson::canonical_json_error_name(merovingian::canonicaljson::CanonicalJsonError::none)} == "none");
    REQUIRE(
        std::string{merovingian::canonicaljson::canonical_json_error_name(merovingian::canonicaljson::CanonicalJsonError::duplicate_object_key)}
        == "duplicate_object_key"
    );
    REQUIRE(
        std::string{merovingian::canonicaljson::canonical_json_error_name(merovingian::canonicaljson::CanonicalJsonError::invalid_string)}
        == "invalid_string"
    );
}
