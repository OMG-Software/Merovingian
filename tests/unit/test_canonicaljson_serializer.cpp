// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/canonicaljson/parser.hpp>
#include <merovingian/canonicaljson/serializer.hpp>
#include <merovingian/canonicaljson/value.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>

SCENARIO("Canonical JSON serializes primitive values", "[canonicaljson]")
{
    GIVEN("primitive canonical JSON values")
    {
        auto const null_value = merovingian::canonicaljson::Value{nullptr};
        auto const bool_value = merovingian::canonicaljson::Value{true};
        auto const integer_value = merovingian::canonicaljson::Value{std::int64_t{-42}};

        WHEN("they are serialized canonically")
        {
            auto const null_result = merovingian::canonicaljson::serialize_canonical(null_value);
            auto const bool_result = merovingian::canonicaljson::serialize_canonical(bool_value);
            auto const integer_result = merovingian::canonicaljson::serialize_canonical(integer_value);

            THEN("the compact JSON spellings are emitted")
            {
                REQUIRE(null_result.output == "null");
                REQUIRE(bool_result.output == "true");
                REQUIRE(integer_result.output == "-42");
            }
        }
    }
}

SCENARIO("Canonical JSON escapes strings deterministically", "[canonicaljson]")
{
    GIVEN("a string containing escapable characters")
    {
        auto const value = merovingian::canonicaljson::Value{std::string{"quote=\" slash=\\ newline=\n"}};

        WHEN("it is serialized canonically")
        {
            auto const result = merovingian::canonicaljson::serialize_canonical(value);

            THEN("the string is escaped deterministically")
            {
                REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(result.output == "\"quote=\\\" slash=\\\\ newline=\\n\"");
            }
        }
    }
}

SCENARIO("Canonical JSON preserves escaped control code points when reserializing", "[canonicaljson]")
{
    GIVEN("parsed escaped control code points")
    {
        auto const parsed = merovingian::canonicaljson::parse_lossless("\"\\u0000\\u001f\"");

        WHEN("the parsed value is serialized canonically")
        {
            auto const result = merovingian::canonicaljson::serialize_canonical(parsed.value);

            THEN("control code points are emitted as escapes")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(result.output == "\"\\u0000\\u001f\"");
            }
        }
    }
}

SCENARIO("Canonical JSON rejects programmatic invalid UTF-8 strings", "[canonicaljson]")
{
    GIVEN("a string value containing invalid UTF-8")
    {
        auto const value = merovingian::canonicaljson::Value{std::string{"\xC0\x80", 2U}};

        WHEN("it is serialized canonically")
        {
            auto const result = merovingian::canonicaljson::serialize_canonical(value);

            THEN("serialization rejects the string")
            {
                REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::invalid_string);
            }
        }
    }
}

SCENARIO("Canonical JSON serializes arrays without whitespace", "[canonicaljson]")
{
    GIVEN("an array value")
    {
        auto array = merovingian::canonicaljson::Array{};
        array.emplace_back(std::int64_t{1});
        array.emplace_back(false);
        array.emplace_back(std::string{"x"});

        WHEN("it is serialized canonically")
        {
            auto const result = merovingian::canonicaljson::serialize_canonical(
                merovingian::canonicaljson::Value{std::move(array)}
            );

            THEN("no insignificant whitespace is emitted")
            {
                REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(result.output == "[1,false,\"x\"]");
            }
        }
    }
}

SCENARIO("Canonical JSON sorts object keys lexicographically", "[canonicaljson]")
{
    GIVEN("an object with unsorted keys")
    {
        auto object = merovingian::canonicaljson::Object{};
        object.push_back(merovingian::canonicaljson::make_member("z", merovingian::canonicaljson::Value{std::int64_t{3}}));
        object.push_back(merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{1}}));
        object.push_back(merovingian::canonicaljson::make_member("m", merovingian::canonicaljson::Value{std::int64_t{2}}));

        WHEN("it is serialized canonically")
        {
            auto const result = merovingian::canonicaljson::serialize_canonical(
                merovingian::canonicaljson::Value{std::move(object)}
            );

            THEN("object keys are sorted lexicographically")
            {
                REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(result.output == "{\"a\":1,\"m\":2,\"z\":3}");
            }
        }
    }
}

SCENARIO("Canonical JSON rejects duplicate object keys", "[canonicaljson]")
{
    GIVEN("an object with duplicate keys")
    {
        auto object = merovingian::canonicaljson::Object{};
        object.push_back(merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{1}}));
        object.push_back(merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{2}}));

        WHEN("it is serialized canonically")
        {
            auto const result = merovingian::canonicaljson::serialize_canonical(
                merovingian::canonicaljson::Value{std::move(object)}
            );

            THEN("serialization rejects the duplicate key")
            {
                REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::duplicate_object_key);
                REQUIRE(result.output.empty());
            }
        }
    }
}

SCENARIO("Canonical JSON error names are stable", "[canonicaljson]")
{
    GIVEN("canonical JSON error values")
    {
        auto constexpr no_error = merovingian::canonicaljson::CanonicalJsonError::none;
        auto constexpr duplicate_key = merovingian::canonicaljson::CanonicalJsonError::duplicate_object_key;
        auto constexpr invalid_string = merovingian::canonicaljson::CanonicalJsonError::invalid_string;

        WHEN("their names are requested")
        {
            auto const no_error_name = std::string{merovingian::canonicaljson::canonical_json_error_name(no_error)};
            auto const duplicate_key_name = std::string{merovingian::canonicaljson::canonical_json_error_name(duplicate_key)};
            auto const invalid_string_name = std::string{merovingian::canonicaljson::canonical_json_error_name(invalid_string)};

            THEN("the diagnostic names are stable")
            {
                REQUIRE(no_error_name == "none");
                REQUIRE(duplicate_key_name == "duplicate_object_key");
                REQUIRE(invalid_string_name == "invalid_string");
            }
        }
    }
}
