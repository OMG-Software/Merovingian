// SPDX-License-Identifier: GPL-3.0-or-later

#include "federation_signing_test_support.hpp"
#include "merovingian/federation/inbound_request.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

SCENARIO("X-Matrix Authorization header is parsed into credentials", "[federation][x-matrix][parsing]")
{
    GIVEN("a valid full X-Matrix header with all fields")
    {
        auto const header = std::string_view{"X-Matrix origin=\"matrix.example.org\",key=\"ed25519:auto\","
                                             "sig=\"abc123==\",destination=\"local.example.org\""};

        WHEN("the header is parsed")
        {
            auto const result = merovingian::federation::parse_x_matrix_authorization_header(header);

            THEN("all fields are extracted correctly")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->origin == "matrix.example.org");
                REQUIRE(result->key_id == "ed25519:auto");
                REQUIRE(result->signature == "abc123==");
                REQUIRE(result->destination == "local.example.org");
            }
        }
    }

    GIVEN("a valid minimal X-Matrix header with only required fields")
    {
        auto const header =
            std::string_view{R"(X-Matrix origin="matrix.example.org",key="ed25519:key1",sig="sig+val==")"};

        WHEN("the header is parsed")
        {
            auto const result = merovingian::federation::parse_x_matrix_authorization_header(header);

            THEN("required fields are extracted and destination is empty")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->origin == "matrix.example.org");
                REQUIRE(result->key_id == "ed25519:key1");
                REQUIRE(result->signature == "sig+val==");
                REQUIRE(result->destination.empty());
            }
        }
    }

    GIVEN("X-Matrix headers with missing required fields")
    {
        auto const missing_origin = std::string_view{R"(X-Matrix key="ed25519:auto",sig="abc==")"};
        auto const missing_key = std::string_view{R"(X-Matrix origin="matrix.org",sig="abc==")"};
        auto const missing_sig = std::string_view{"X-Matrix origin=\"matrix.org\",key=\"ed25519:auto\""};

        WHEN("each header is parsed")
        {
            auto const no_origin = merovingian::federation::parse_x_matrix_authorization_header(missing_origin);
            auto const no_key = merovingian::federation::parse_x_matrix_authorization_header(missing_key);
            auto const no_sig = merovingian::federation::parse_x_matrix_authorization_header(missing_sig);

            THEN("all three return nullopt")
            {
                REQUIRE_FALSE(no_origin.has_value());
                REQUIRE_FALSE(no_key.has_value());
                REQUIRE_FALSE(no_sig.has_value());
            }
        }
    }

    GIVEN("malformed or wrong-scheme Authorization header values")
    {
        auto const empty_value = std::string_view{""};
        auto const bearer = std::string_view{"Bearer token123"};
        auto const wrong_case = std::string_view{"x-matrix origin=\"a.org\",key=\"ed25519:k\",sig=\"s\""};
        // Rejected because ':' and '=' are not tchars, so these values were required to
        // be quoted — not because unquoted values are categorically invalid. See the
        // unquoted-token scenario above for the values a sender may legally leave bare.
        auto const unquoted_non_token = std::string_view{"X-Matrix origin=matrix.org,key=ed25519:auto,sig=abc"};
        auto const unclosed_quote = std::string_view{"X-Matrix origin=\"matrix.org,key=\"ed25519:auto\",sig=\"abc\""};

        WHEN("each value is parsed")
        {
            auto const r_empty = merovingian::federation::parse_x_matrix_authorization_header(empty_value);
            auto const r_bearer = merovingian::federation::parse_x_matrix_authorization_header(bearer);
            auto const r_case = merovingian::federation::parse_x_matrix_authorization_header(wrong_case);
            auto const r_unquoted = merovingian::federation::parse_x_matrix_authorization_header(unquoted_non_token);
            auto const r_unclosed = merovingian::federation::parse_x_matrix_authorization_header(unclosed_quote);

            THEN("all return nullopt")
            {
                REQUIRE_FALSE(r_empty.has_value());
                REQUIRE_FALSE(r_bearer.has_value());
                REQUIRE_FALSE(r_case.has_value());
                REQUIRE_FALSE(r_unquoted.has_value());
                REQUIRE_FALSE(r_unclosed.has_value());
            }
        }
    }

    GIVEN("an X-Matrix header with extra whitespace around delimiters")
    {
        auto const spaced = std::string_view{"X-Matrix origin=\"matrix.org\" , key=\"ed25519:auto\" , sig=\"abc==\""};

        WHEN("the header is parsed")
        {
            auto const result = merovingian::federation::parse_x_matrix_authorization_header(spaced);

            THEN("fields are trimmed and extracted correctly")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->origin == "matrix.org");
                REQUIRE(result->key_id == "ed25519:auto");
                REQUIRE(result->signature == "abc==");
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Request Authentication (X-Matrix)
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#request-authentication
//
// "The values must be enclosed in quotes if they contain characters that are not
// allowed in `token`s, as defined in Section 5.6.2 of RFC 9110; if a value is a
// valid `token`, it may or may not be enclosed in quotes."
//
// So a sender is entitled to leave token-shaped values unquoted, and the recipient
// MUST accept them. Rejecting the header outright drops the request — for
// PUT /_matrix/federation/v1/send/{txnId} that silently discards a peer's PDUs.
SCENARIO("X-Matrix parameter values that are valid RFC 9110 tokens may be unquoted", "[federation][x-matrix][parsing]")
{
    GIVEN("a header with an unquoted origin and quoted non-token values")
    {
        // "matrix.example.org" is a valid token (ALPHA/DIGIT and '.'), so it needs no
        // quotes. "ed25519:key1" contains ':' and the signature contains '/' and '=',
        // none of which are tchars, so those stay quoted.
        auto const header = std::string_view{R"(X-Matrix origin=matrix.example.org,key="ed25519:key1",sig="ab/c+d==")"};

        WHEN("the header is parsed")
        {
            auto const result = merovingian::federation::parse_x_matrix_authorization_header(header);

            THEN("every field is extracted")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->origin == "matrix.example.org");
                REQUIRE(result->key_id == "ed25519:key1");
                REQUIRE(result->signature == "ab/c+d==");
            }
        }
    }

    GIVEN("a header whose unquoted values are separated by spaces around the commas")
    {
        auto const header = std::string_view{R"(X-Matrix origin=matrix.example.org , destination=local.example.org , )"
                                             R"(key="ed25519:key1" , sig="abc==")"};

        WHEN("the header is parsed")
        {
            auto const result = merovingian::federation::parse_x_matrix_authorization_header(header);

            THEN("the unquoted values are extracted without the surrounding whitespace")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->origin == "matrix.example.org");
                REQUIRE(result->destination == "local.example.org");
                REQUIRE(result->key_id == "ed25519:key1");
                REQUIRE(result->signature == "abc==");
            }
        }
    }

    GIVEN("headers whose unquoted values are not valid tokens")
    {
        // ':' is not a tchar, so an unquoted key_id is malformed, not merely
        // unfashionable — the sender was required to quote it.
        auto const unquoted_key = std::string_view{R"(X-Matrix origin=matrix.org,key=ed25519:auto,sig="abc==")"};
        // An empty value is never a token: 'token' is 1*tchar.
        auto const empty_origin = std::string_view{R"(X-Matrix origin=,key="ed25519:k",sig="abc==")"};

        WHEN("each header is parsed")
        {
            auto const r_key = merovingian::federation::parse_x_matrix_authorization_header(unquoted_key);
            auto const r_empty = merovingian::federation::parse_x_matrix_authorization_header(empty_origin);

            THEN("both are rejected")
            {
                REQUIRE_FALSE(r_key.has_value());
                REQUIRE_FALSE(r_empty.has_value());
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Request Authentication (X-Matrix)
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#request-authentication
//
// The X-Matrix Authorization header uses RFC 7230 quoted-string values. A
// backslash escapes the next character, so a value containing `\"` must NOT
// terminate the field early. The parser must skip `\"`/`\\` escape sequences
// when scanning for the closing quote and decode them in the extracted value.
SCENARIO("X-Matrix quoted values handle backslash-escaped quotes per RFC 7230",
         "[federation][x-matrix][parsing][conformance][security]")
{
    GIVEN("an X-Matrix header whose sig value contains an escaped quote")
    {
        // Raw header bytes: sig="ab\"cd==" — the \" is an escaped quote inside
        // the value, not the closing delimiter.
        auto const header = std::string_view{R"(X-Matrix origin="matrix.example.org",)"
                                             R"(key="ed25519:auto",sig="ab\"cd==")"};

        WHEN("the header is parsed")
        {
            auto const result = merovingian::federation::parse_x_matrix_authorization_header(header);

            THEN("the escaped quote is decoded and the field is not terminated early")
            {
                // Spec MUST (RFC 7230 §3.2.6): a backslash escapes the next char, so the
                // closing quote is the one after `cd==`, and the value decodes to ab"cd==.
                REQUIRE(result.has_value());
                REQUIRE(result->origin == "matrix.example.org");
                REQUIRE(result->key_id == "ed25519:auto");
                REQUIRE(result->signature == "ab\"cd==");
            }
        }
    }

    GIVEN("an X-Matrix header whose origin value contains an escaped backslash")
    {
        auto const header = std::string_view{R"(X-Matrix origin="x\\y.org",)"
                                             R"(key="ed25519:auto",sig="abc==")"};

        WHEN("the header is parsed")
        {
            auto const result = merovingian::federation::parse_x_matrix_authorization_header(header);

            THEN("the escaped backslash is decoded to a single backslash")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->origin == "x\\y.org");
                REQUIRE(result->key_id == "ed25519:auto");
                REQUIRE(result->signature == "abc==");
            }
        }
    }

    GIVEN("an X-Matrix header where an earlier field's escaped quote is followed by a later field")
    {
        // The escaped quote in key must not consume the key's closing quote and
        // corrupt the subsequent sig field.
        auto const header = std::string_view{R"(X-Matrix origin="matrix.example.org",)"
                                             R"(key="ed25519:a\"b",sig="sigval==")"};

        WHEN("the header is parsed")
        {
            auto const result = merovingian::federation::parse_x_matrix_authorization_header(header);

            THEN("each field is extracted independently despite the embedded escape")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->origin == "matrix.example.org");
                REQUIRE(result->key_id == "ed25519:a\"b");
                REQUIRE(result->signature == "sigval==");
            }
        }
    }
}
