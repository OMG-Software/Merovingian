// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"

#include <catch2/catch_test_macros.hpp>

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
