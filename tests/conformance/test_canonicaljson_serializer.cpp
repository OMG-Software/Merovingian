// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |          MATRIX CANONICAL JSON SERIALIZER CONFORMANCE TESTS            |
// |                                                                         |
// |  Spec: Matrix v1.18 Appendices — Canonical JSON                        |
// |  URL:  ../../docs/matrix-v1.18-spec/appendices.md#canonical-json        |
// |        ../../docs/matrix-v1.18-spec/appendices.md#grammar               |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix             |
// |  canonical JSON specification. If a test fails:                         |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// |  The spec section is cited above each SCENARIO. Cross-check it before   |
// |  concluding that a failing assertion is wrong.                           |
// +-------------------------------------------------------------------------+

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"

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
        auto const double_value = merovingian::canonicaljson::Value{0.5};

        WHEN("they are serialized canonically")
        {
            auto const null_result = merovingian::canonicaljson::serialize_canonical(null_value);
            auto const bool_result = merovingian::canonicaljson::serialize_canonical(bool_value);
            auto const integer_result = merovingian::canonicaljson::serialize_canonical(integer_value);
            auto const double_result = merovingian::canonicaljson::serialize_canonical(double_value);

            THEN("the compact JSON spellings are emitted")
            {
                REQUIRE(null_result.output == "null");
                REQUIRE(bool_result.output == "true");
                REQUIRE(integer_result.output == "-42");
                REQUIRE(double_result.output == "0.5");
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
        auto const value = merovingian::canonicaljson::Value{
            std::string{"\xC0\x80", 2U}
        };

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
            auto const result =
                merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(array)});

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
        object.push_back(
            merovingian::canonicaljson::make_member("z", merovingian::canonicaljson::Value{std::int64_t{3}}));
        object.push_back(
            merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{1}}));
        object.push_back(
            merovingian::canonicaljson::make_member("m", merovingian::canonicaljson::Value{std::int64_t{2}}));

        WHEN("it is serialized canonically")
        {
            auto const result =
                merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(object)});

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
        object.push_back(
            merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{1}}));
        object.push_back(
            merovingian::canonicaljson::make_member("a", merovingian::canonicaljson::Value{std::int64_t{2}}));

        WHEN("it is serialized canonically")
        {
            auto const result =
                merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(object)});

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
            auto const duplicate_key_name =
                std::string{merovingian::canonicaljson::canonical_json_error_name(duplicate_key)};
            auto const invalid_string_name =
                std::string{merovingian::canonicaljson::canonical_json_error_name(invalid_string)};

            THEN("the diagnostic names are stable")
            {
                REQUIRE(no_error_name == "none");
                REQUIRE(duplicate_key_name == "duplicate_object_key");
                REQUIRE(invalid_string_name == "invalid_string");
            }
        }
    }
}
SCENARIO("Canonical JSON escapes all control characters U+0000 through U+001F as \\u00XX",
         "[conformance][canonicaljson][escaping]")
{
    GIVEN("string values containing control characters")
    {
        // Values are built from raw bytes to avoid C++ escape sequence ambiguity.
        auto nul_str = merovingian::canonicaljson::Value{std::string("\x00", 1U)}; // U+0000
        auto tab_str = merovingian::canonicaljson::Value{std::string("\x09", 1U)}; // U+0009
        auto lf_str = merovingian::canonicaljson::Value{std::string("\x0a", 1U)};  // U+000A
        auto cr_str = merovingian::canonicaljson::Value{std::string("\x0d", 1U)};  // U+000D
        auto us_str = merovingian::canonicaljson::Value{std::string("\x1f", 1U)};  // U+001F
        // Space (U+0020) is the first character ABOVE the control range — MUST NOT be escaped.
        auto space_str = merovingian::canonicaljson::Value{std::string(" ", 1U)}; // U+0020

        WHEN("each string is serialized canonically")
        {
            auto const nul_out = merovingian::canonicaljson::serialize_canonical(nul_str);
            auto const tab_out = merovingian::canonicaljson::serialize_canonical(tab_str);
            auto const lf_out = merovingian::canonicaljson::serialize_canonical(lf_str);
            auto const cr_out = merovingian::canonicaljson::serialize_canonical(cr_str);
            auto const us_out = merovingian::canonicaljson::serialize_canonical(us_str);
            auto const space_out = merovingian::canonicaljson::serialize_canonical(space_str);

            THEN("control characters are escaped per JSON canonical rules")
            {
                REQUIRE(nul_out.output == "\"\\u0000\"");
                REQUIRE(tab_out.output == "\"\\t\"");
                REQUIRE(lf_out.output == "\"\\n\"");
                REQUIRE(cr_out.output == "\"\\r\"");
                REQUIRE(us_out.output == "\"\\u001f\"");
                REQUIRE(space_out.output == "\" \"");
            }
        }
    }
}

// Spec: Matrix v1.18 Appendices — Canonical JSON — Grammar
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#grammar
//
// Object keys MUST be sorted by their Unicode code points. For UTF-8 strings
// this is equivalent to byte-by-byte lexicographic order, because UTF-8 encodes
// code points such that byte order preserves code point order.
//
// Sort order for the keys used below:
//   "A"  = U+0041 → 0x41                   (ASCII uppercase)
//   "a"  = U+0061 → 0x61                   (ASCII lowercase)
//   "z"  = U+007A → 0x7A                   (ASCII lowercase, highest ASCII key)
//   "é"  = U+00E9 → 0xC3 0xA9              (2-byte UTF-8, first byte 0xC3 > 0x7A)
//   "中"  = U+4E2D → 0xE4 0xB8 0xAD        (3-byte UTF-8, first byte 0xE4 > 0xC3)
//
// The JSON is constructed with raw UTF-8 bytes so the sort behaviour is verified
// end-to-end without relying on \u-escape parsing or collation libraries.
SCENARIO("Canonical JSON sorts object keys by Unicode code point (byte order)",
         "[conformance][canonicaljson][key-sorting]")
{
    GIVEN("an object with ASCII and multi-byte UTF-8 keys in intentionally wrong order")
    {
        // Raw UTF-8: é = 0xC3 0xA9, 中 = 0xE4 0xB8 0xAD.
        // The keys are listed out of Unicode order to prove the serializer sorts them.
        auto const json = std::string{"{"
                                      "\"z\":3,"
                                      "\"A\":1,"
                                      "\"\xE4\xB8\xAD\":5,"
                                      "\"a\":2,"
                                      "\"\xC3\xA9\":4"
                                      "}"};
        auto const parsed = merovingian::canonicaljson::parse_lossless(json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("serialized canonically")
        {
            auto const result = merovingian::canonicaljson::serialize_canonical(parsed.value);

            THEN("keys appear in Unicode code point order including multi-byte keys")
            {
                REQUIRE(result.error == merovingian::canonicaljson::CanonicalJsonError::none);
                // Spec MUST: "A" (0x41) < "a" (0x61) < "z" (0x7A) < "é" (0xC3…) < "中" (0xE4…)
                auto const expected = std::string{"{"
                                                  "\"A\":1,"
                                                  "\"a\":2,"
                                                  "\"z\":3,"
                                                  "\"\xC3\xA9\":4,"
                                                  "\"\xE4\xB8\xAD\":5"
                                                  "}"};
                REQUIRE(result.output == expected);
            }
        }
    }
}

// Spec: Matrix v1.18 Appendices — Canonical JSON — Grammar
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#grammar
//
// No insignificant whitespace: no spaces or newlines around ':' or ','
// in the output. The output MUST be the most compact valid JSON.
SCENARIO("Canonical JSON output contains no insignificant whitespace", "[conformance][canonicaljson][whitespace]")
{
    GIVEN("a populated object and array")
    {
        auto const obj_json = std::string{R"({"a":1,"b":2})"};
        auto const arr_json = std::string{R"([1,2,3])"};

        auto const obj_parsed = merovingian::canonicaljson::parse_lossless(obj_json);
        auto const arr_parsed = merovingian::canonicaljson::parse_lossless(arr_json);
        REQUIRE(obj_parsed.error == merovingian::canonicaljson::ParseError::none);
        REQUIRE(arr_parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("each is serialized canonically")
        {
            auto const obj_out = merovingian::canonicaljson::serialize_canonical(obj_parsed.value);
            auto const arr_out = merovingian::canonicaljson::serialize_canonical(arr_parsed.value);

            THEN("no whitespace appears in either output")
            {
                REQUIRE(obj_out.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(arr_out.error == merovingian::canonicaljson::CanonicalJsonError::none);
                // Spec MUST: no whitespace outside string values.
                REQUIRE(obj_out.output.find(' ') == std::string::npos);
                REQUIRE(obj_out.output.find('\n') == std::string::npos);
                REQUIRE(arr_out.output.find(' ') == std::string::npos);
                REQUIRE(arr_out.output.find('\n') == std::string::npos);
            }
        }
    }
}
