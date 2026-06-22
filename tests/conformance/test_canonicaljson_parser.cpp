// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              MATRIX CANONICAL JSON PARSER CONFORMANCE TESTS            |
// |                                                                         |
// |  Spec: Matrix v1.18 Appendices — Canonical JSON                        |
// |  URL:  ../../docs/matrix-v1.18-spec/appendices.md#canonical-json        |
// |        ../../docs/matrix-v1.18-spec/appendices.md#grammar               |
// |        ../../docs/matrix-v1.18-spec/appendices.md#examples              |
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

#include "../support/json_test_support.hpp"
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

SCENARIO("Canonical JSON parser rejects leading zeros, explicit positive signs, and negative zero",
         "[canonicaljson][parser][conformance]")
{
    GIVEN("non-canonical integer tokens")
    {
        auto constexpr leading_zero_short = "01";
        auto constexpr leading_zero_long = "007";
        auto constexpr explicit_positive = "+5";
        auto constexpr leading_positive_negative = "+-1";
        // Spec: Matrix v1.18 Appendices § Canonical JSON:
        // "Numbers that are negative zero MUST NOT appear in canonical JSON."
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
                // Spec MUST: leading zeros are not canonical.
                REQUIRE(short_result.error == merovingian::canonicaljson::ParseError::invalid_number);
                REQUIRE(long_result.error == merovingian::canonicaljson::ParseError::invalid_number);
                REQUIRE(positive_result.error == merovingian::canonicaljson::ParseError::invalid_number);
                REQUIRE(both_result.error == merovingian::canonicaljson::ParseError::invalid_number);
                // Spec MUST: "-0" is explicitly prohibited by the canonical JSON spec.
                // (Previous comment claiming "the spec permits it" was incorrect.)
                REQUIRE(signed_zero_result.error == merovingian::canonicaljson::ParseError::invalid_number);
            }
        }
    }
}

// Spec: Matrix v1.18 Appendices — Canonical JSON — Grammar
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#grammar
//
// "Value MUST be an integer in the range -(2^53)+1 to (2^53)-1 inclusive."
// -(2^53)+1 = -9007199254740991
// (2^53)-1  =  9007199254740991
//
// NOTE: This range is the IEEE 754 double-precision safe integer range, NOT int64.
// Numbers beyond this range lose integer precision in JavaScript environments and
// MUST therefore be rejected.
SCENARIO("Canonical JSON parser accepts integers within the spec's safe integer range",
         "[conformance][canonicaljson][parser][integer-range]")
{
    GIVEN("integer literals within -(2^53)+1 to (2^53)-1 inclusive")
    {
        auto constexpr zero = "0";
        auto constexpr positive_small = "42";
        auto constexpr negative_small = "-7";
        // Exact spec boundaries: -(2^53)+1 = -9007199254740991, (2^53)-1 = 9007199254740991
        auto constexpr spec_min = "-9007199254740991";
        auto constexpr spec_max = "9007199254740991";

        WHEN("each integer is parsed")
        {
            auto const zero_result = merovingian::canonicaljson::parse_lossless(zero);
            auto const pos_result = merovingian::canonicaljson::parse_lossless(positive_small);
            auto const neg_result = merovingian::canonicaljson::parse_lossless(negative_small);
            auto const min_result = merovingian::canonicaljson::parse_lossless(spec_min);
            auto const max_result = merovingian::canonicaljson::parse_lossless(spec_max);

            THEN("all in-range integers parse without error")
            {
                // Spec MUST: integers within [-(2^53)+1, (2^53)-1] are valid.
                REQUIRE(zero_result.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(pos_result.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(neg_result.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(min_result.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(max_result.error == merovingian::canonicaljson::ParseError::none);
            }
        }
    }
}

// Spec: Matrix v1.18 Appendices — Canonical JSON — Grammar
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#grammar
//
// Numbers outside the safe integer range MUST be rejected because they cannot be
// represented exactly in IEEE 754 double-precision and would produce different
// values after a JavaScript parse-serialize round trip.
SCENARIO("Canonical JSON parser rejects integers outside the spec's safe integer range",
         "[conformance][canonicaljson][parser][integer-range]")
{
    GIVEN("integer literals that exceed the spec-mandated safe integer range")
    {
        // These are OUTSIDE [-(2^53)+1, (2^53)-1]:
        auto constexpr beyond_spec_max = "9007199254740992";  // (2^53) — one past the spec max
        auto constexpr beyond_spec_min = "-9007199254740992"; // -(2^53) — one past the spec min
        // int64 boundary values are also outside the spec range:
        auto constexpr int64_max = "9223372036854775807";
        auto constexpr int64_min = "-9223372036854775808";

        WHEN("each out-of-range integer is parsed")
        {
            auto const r1 = merovingian::canonicaljson::parse_lossless(beyond_spec_max);
            auto const r2 = merovingian::canonicaljson::parse_lossless(beyond_spec_min);
            auto const r3 = merovingian::canonicaljson::parse_lossless(int64_max);
            auto const r4 = merovingian::canonicaljson::parse_lossless(int64_min);

            THEN("all out-of-range integers are rejected as integer_out_of_range")
            {
                // Spec MUST: values outside [-(2^53)+1, (2^53)-1] MUST be rejected.
                // If these tests FAIL it means the implementation accepts values the
                // spec forbids — the implementation must be fixed, not this test.
                REQUIRE(r1.error == merovingian::canonicaljson::ParseError::integer_out_of_range);
                REQUIRE(r2.error == merovingian::canonicaljson::ParseError::integer_out_of_range);
                REQUIRE(r3.error == merovingian::canonicaljson::ParseError::integer_out_of_range);
                REQUIRE(r4.error == merovingian::canonicaljson::ParseError::integer_out_of_range);
            }
        }
    }
}

SCENARIO("Canonical JSON parser rejects trailing garbage after a complete value", "[canonicaljson][parser]")
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

// Spec: Matrix v1.18 Appendices — Canonical JSON — Examples
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#examples
//
// The specification provides these exact input/output pairs as canonical JSON
// test vectors. Every implementation MUST produce these exact outputs.
SCENARIO("Canonical JSON spec test vectors produce the exact expected output",
         "[conformance][canonicaljson][parser][spec-vectors]")
{
    GIVEN("the spec-defined input/output pairs from the Examples section")
    {
        // Each pair is {input_json, expected_canonical_output}.
        struct TestVector
        {
            char const* input;
            char const* expected;
        };

        // Vectors from ../../docs/matrix-v1.18-spec/appendices.md#examples
        auto const vectors = std::vector<TestVector>{
            // Empty object
            {"{}", "{}"},
            // Simple object, already sorted — no reordering needed
            {R"({"one":1,"two":"Two"})", R"({"one":1,"two":"Two"})"},
            // Object with unsorted keys — MUST be sorted lexicographically
            {R"({"b":"2","a":"1"})", R"({"a":"1","b":"2"})"},
            // Nested object — keys at every level MUST be sorted
            {
             R"({"auth":{"success":true,"mxid":"@john:example.com","profile":{"display_name":"John Doe","three_pids":[{"medium":"email","address":"john@example.com"}]}},"nonce":"xxxx"})",
             R"({"auth":{"mxid":"@john:example.com","profile":{"display_name":"John Doe","three_pids":[{"address":"john@example.com","medium":"email"}]},"success":true},"nonce":"xxxx"})",
             },
            // Control character U+0000: \u0000 JSON escape MUST round-trip as \u0000
            {"{\"a\":\"\\u0000\"}", "{\"a\":\"\\u0000\"}"},
        };

        WHEN("each vector is parsed and re-serialized canonically")
        {
            THEN("the output exactly matches the spec-defined canonical form")
            {
                for (auto const& vec : vectors)
                {
                    auto const parsed = merovingian::canonicaljson::parse_lossless(vec.input);
                    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                    auto const serialized = merovingian::canonicaljson::serialize_canonical(parsed.value);
                    // Spec MUST: the output MUST exactly equal the expected canonical form.
                    // Do NOT change an expected value without citing the updated spec section.
                    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
                    REQUIRE(serialized.output == std::string{vec.expected});
                }
            }
        }
    }
}

// Spec: Matrix v1.18 Appendices — Canonical JSON — Grammar
// URL:  ../../docs/matrix-v1.18-spec/appendices.md#grammar
//
// Strings MUST NOT use \uXXXX escape sequences for characters above U+001F.
// Unicode escapes for printable characters (A for 'A') MUST be decoded
// to their literal UTF-8 form, not left as escape sequences.
SCENARIO("Canonical JSON normalises unicode escapes for printable characters",
         "[conformance][canonicaljson][parser][unicode]")
{
    GIVEN("a string containing a unicode escape for a printable character")
    {
        // "A" is 'A' — a printable ASCII character that MUST NOT be escaped in output.
        auto constexpr input = R"({"a":"A"})";

        WHEN("it is parsed and serialized canonically")
        {
            auto const parsed = merovingian::canonicaljson::parse_lossless(input);
            auto const serialized = merovingian::canonicaljson::serialize_canonical(parsed.value);

            THEN("the printable character is emitted as literal UTF-8, not as an escape")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
                // Spec MUST: printable characters MUST NOT be escaped in the canonical output.
                // A must round-trip to the literal character 'A'.
                REQUIRE(serialized.output == R"({"a":"A"})");
                REQUIRE(serialized.output.find("\\u0041") == std::string::npos);
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

SCENARIO("General JSON parser accepts doubles used by room tags and account data", "[canonicaljson][parser]")
{
    GIVEN("a JSON object containing a fractional number")
    {
        auto constexpr input = R"({"order":0.5})";

        WHEN("it is parsed with the general JSON parser")
        {
            auto const parsed = merovingian::canonicaljson::parse_json(input);

            THEN("the double is preserved and the canonical parser would have rejected it")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* order_member = merovingian::tests::object_member(*root, "order");
                REQUIRE(order_member != nullptr);
                auto const* order_double = std::get_if<double>(&order_member->storage());
                REQUIRE(order_double != nullptr);
                REQUIRE(*order_double == 0.5);

                auto const canonical = merovingian::canonicaljson::parse_lossless(input);
                REQUIRE(canonical.error == merovingian::canonicaljson::ParseError::invalid_number);
            }
        }
    }

    GIVEN("a JSON object containing exponent notation")
    {
        auto constexpr input = R"({"value":1.25e2})";

        WHEN("it is parsed with the general JSON parser")
        {
            auto const parsed = merovingian::canonicaljson::parse_json(input);

            THEN("the number is preserved as a double")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* value_member = merovingian::tests::object_member(*root, "value");
                REQUIRE(value_member != nullptr);
                auto const* value_double = std::get_if<double>(&value_member->storage());
                REQUIRE(value_double != nullptr);
                REQUIRE(*value_double == 125.0);
            }
        }
    }

    GIVEN("a JSON value with trailing garbage")
    {
        auto constexpr input = "{} extra";

        WHEN("it is parsed with the general JSON parser")
        {
            auto const parsed = merovingian::canonicaljson::parse_json(input);

            THEN("trailing data is rejected")
            {
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::trailing_data);
            }
        }
    }
}
