// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         IDENTITY SERVICE API CLIENT — PURE HELPER UNIT TESTS           |
// |                                                                         |
// |  Spec: Matrix Identity Service API v1.19                               |
// |  URL:  ../../docs/matrix-v1.19-spec/identity-service-api.md             |
// |                                                                         |
// |  Covers the network-free helpers only (URL parse, request-body builders,|
// |  response parsers). The IdentityServerClient transport path is exercised |
// |  in conformance/integration with a mock IS.                            |
// +-------------------------------------------------------------------------+

#include "merovingian/identity/identity_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto url_host(merovingian::identity::IdentityServerUrl const& parsed) -> std::string const&
{
    return parsed.host;
}

} // namespace

SCENARIO("parse_identity_server_url accepts HTTPS origins and rejects everything else", "[identity][identity-url]")
{
    GIVEN("a plain https base URL")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::identity::parse_identity_server_url("https://is.example.org");

            THEN("the host is captured with the default 443 port and no path prefix")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(url_host(*parsed) == "is.example.org");
                REQUIRE(parsed->port == 443U);
                REQUIRE(parsed->path.empty());
            }
        }
    }

    GIVEN("an https URL with an explicit port and path prefix")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::identity::parse_identity_server_url("https://is.example.org:8448/v2");

            THEN("the host, port, and path prefix are all captured")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(url_host(*parsed) == "is.example.org");
                REQUIRE(parsed->port == 8448U);
                REQUIRE(parsed->path == "/v2");
            }
        }
    }

    GIVEN("a cleartext URL, a URL with no host, and an out-of-range port")
    {
        WHEN("each is parsed")
        {
            auto const cleartext = merovingian::identity::parse_identity_server_url("http://is.example.org");
            auto const no_host = merovingian::identity::parse_identity_server_url("https://");
            auto const bad_port = merovingian::identity::parse_identity_server_url("https://is.example.org:99999");

            THEN("all are rejected (HTTPS and a non-empty host are mandatory)")
            {
                REQUIRE_FALSE(cleartext.has_value());
                REQUIRE_FALSE(no_host.has_value());
                REQUIRE_FALSE(bad_port.has_value());
            }
        }
    }

    GIVEN("a base URL with a trailing slash")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::identity::parse_identity_server_url("https://is.example.org/");

            THEN("the trailing slash is collapsed so the path is empty")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->path.empty());
            }
        }
    }
}

SCENARIO("build_store_invite_body emits a canonical JSON body with the spec fields", "[identity][identity-body]")
{
    GIVEN("medium, address, room_id, and sender")
    {
        WHEN("the store-invite body is built")
        {
            auto const body = merovingian::identity::build_store_invite_body(
                "email", "alice@example.org", "!room:hs.example.org", "@bob:hs.example.org");

            THEN("the body is canonical JSON with all four fields, keys sorted")
            {
                REQUIRE(body == R"({"address":"alice@example.org","medium":"email",)"
                                R"("room_id":"!room:hs.example.org","sender":"@bob:hs.example.org"})");
            }
        }
    }
}

SCENARIO("build_lookup_body emits the canonical medium/address pair", "[identity][identity-body]")
{
    GIVEN("medium and address")
    {
        WHEN("the lookup body is built")
        {
            auto const body = merovingian::identity::build_lookup_body("email", "alice@example.org");

            THEN("the body contains only address and medium, sorted")
            {
                REQUIRE(body == R"({"address":"alice@example.org","medium":"email"})");
            }
        }
    }
}

SCENARIO("build_bind_body emits client_secret, mxid, and sid", "[identity][identity-body]")
{
    GIVEN("client_secret, sid, and mxid")
    {
        WHEN("the bind body is built")
        {
            auto const body = merovingian::identity::build_bind_body("s3cr3t", "sid-1", "@alice:hs.example.org");

            THEN("the body is canonical JSON with the three fields, keys sorted")
            {
                REQUIRE(body == R"({"client_secret":"s3cr3t","mxid":"@alice:hs.example.org","sid":"sid-1"})");
            }
        }
    }
}

SCENARIO("build_unbind_body emits the four unbind fields", "[identity][identity-body]")
{
    GIVEN("client_secret, sid, medium, and address")
    {
        WHEN("the unbind body is built")
        {
            auto const body = merovingian::identity::build_unbind_body("s3cr3t", "sid-1", "email", "alice@example.org");

            THEN("the body is canonical JSON with all four fields, keys sorted")
            {
                REQUIRE(body == R"({"address":"alice@example.org","client_secret":"s3cr3t",)"
                                R"("medium":"email","sid":"sid-1"})");
            }
        }
    }
}

SCENARIO("build_request_token_body includes next_link only when non-empty", "[identity][identity-body]")
{
    GIVEN("a client_secret, email, and next_link")
    {
        WHEN("the request-token body is built with a next_link")
        {
            auto const body = merovingian::identity::build_request_token_body("s3cr3t", "alice@example.org",
                                                                              "https://hs.example.org/next");

            THEN("the body includes client_secret, email, and next_link, sorted")
            {
                REQUIRE(body == R"({"client_secret":"s3cr3t","email":"alice@example.org",)"
                                R"("next_link":"https://hs.example.org/next"})");
            }
        }
    }

    GIVEN("a client_secret and email with no next_link")
    {
        WHEN("the request-token body is built with an empty next_link")
        {
            auto const body = merovingian::identity::build_request_token_body("s3cr3t", "alice@example.org", "");

            THEN("the body omits next_link entirely")
            {
                REQUIRE(body == R"({"client_secret":"s3cr3t","email":"alice@example.org"})");
            }
        }
    }
}

SCENARIO("parse_store_invite_response extracts the IS-provided token, display_name, and public_keys",
         "[identity][identity-parse]")
{
    GIVEN("a well-formed store-invite response with two public keys")
    {
        auto const body = std::string{
            R"({"token":"invite-token-1","display_name":"alice",)"
            R"("public_keys":[{"public_key":"longterm-key","key_validity_url":"https://is.example.org/kv/lt"},)"
            R"({"public_key":"ephemeral-key","key_validity_url":"https://is.example.org/kv/ephemeral"}]})"};

        WHEN("parsed")
        {
            auto const parsed = merovingian::identity::parse_store_invite_response(body);

            THEN("the token, display_name, and both public keys are captured")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->token == "invite-token-1");
                REQUIRE(parsed->display_name == "alice");
                REQUIRE(parsed->public_keys.size() == 2U);
                REQUIRE(parsed->public_keys[0U].public_key == "longterm-key");
                REQUIRE(parsed->public_keys[0U].key_validity_url == "https://is.example.org/kv/lt");
                REQUIRE(parsed->public_keys[1U].public_key == "ephemeral-key");
                REQUIRE(parsed->public_keys[1U].key_validity_url == "https://is.example.org/kv/ephemeral");
            }
        }
    }

    GIVEN("a store-invite response missing the token")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::identity::parse_store_invite_response(R"({"display_name":"alice"})");

            THEN("parsing fails closed (the token is mandatory)")
            {
                REQUIRE_FALSE(parsed.has_value());
            }
        }
    }

    GIVEN("malformed JSON")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::identity::parse_store_invite_response("not-json");

            THEN("parsing fails closed")
            {
                REQUIRE_FALSE(parsed.has_value());
            }
        }
    }
}

SCENARIO("parse_lookup_response extracts the bound MXID", "[identity][identity-parse]")
{
    GIVEN("a lookup response with a bound MXID")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::identity::parse_lookup_response(R"({"mxid":"@alice:hs.example.org"})");

            THEN("the MXID is captured")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->mxid == "@alice:hs.example.org");
            }
        }
    }

    GIVEN("a lookup response with no mxid field (no binding)")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::identity::parse_lookup_response(R"({})");

            THEN("parsing succeeds with an empty MXID (no binding for this 3PID)")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->mxid.empty());
            }
        }
    }

    GIVEN("malformed JSON")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::identity::parse_lookup_response("not-json");

            THEN("parsing fails closed")
            {
                REQUIRE_FALSE(parsed.has_value());
            }
        }
    }
}

SCENARIO("build_request_msisdn_token_body emits client_secret, country, phone_number, and optional next_link",
         "[identity][identity-body]")
{
    GIVEN("client_secret, country, phone_number, and a next_link")
    {
        WHEN("the msisdn request-token body is built with a next_link")
        {
            auto const body = merovingian::identity::build_request_msisdn_token_body("s3cr3t", "GB", "447700900000",
                                                                                     "https://hs.example.org/next");

            THEN("the body is canonical JSON with all four fields, keys sorted")
            {
                REQUIRE(body == R"({"client_secret":"s3cr3t","country":"GB",)"
                                R"("next_link":"https://hs.example.org/next","phone_number":"447700900000"})");
            }
        }
    }

    GIVEN("client_secret, country, and phone_number with no next_link")
    {
        WHEN("the msisdn request-token body is built with an empty next_link")
        {
            auto const body =
                merovingian::identity::build_request_msisdn_token_body("s3cr3t", "GB", "447700900000", "");

            THEN("the body omits next_link entirely")
            {
                REQUIRE(body == R"({"client_secret":"s3cr3t","country":"GB","phone_number":"447700900000"})");
            }
        }
    }
}

SCENARIO("parse_request_token_response extracts the IS-issued session id", "[identity][identity-parse]")
{
    GIVEN("a well-formed request-token response carrying a sid")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::identity::parse_request_token_response(R"({"sid":"is-issued-sid-1"})");

            THEN("the sid is captured")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(*parsed == "is-issued-sid-1");
            }
        }
    }

    GIVEN("a request-token response missing the sid")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::identity::parse_request_token_response(R"({})");

            THEN("parsing fails closed (the sid is mandatory)")
            {
                REQUIRE_FALSE(parsed.has_value());
            }
        }
    }

    GIVEN("malformed JSON")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::identity::parse_request_token_response("not-json");

            THEN("parsing fails closed")
            {
                REQUIRE_FALSE(parsed.has_value());
            }
        }
    }
}

// Spec: Identity Service API v1.19, GET /_matrix/identity/v2/3pid/getValidated3pid
// URL:  ../../docs/matrix-v1.19-spec/identity-service-api.md
// AUTH-5: the homeserver proves 3PID ownership only by asking the identity
// server whether the session was validated. The 200 body carries `address`,
// `medium` and `validated_at`, all required.
SCENARIO("parse_validated_3pid_response extracts the validated medium, address and time",
         "[identity][identity-parse][auth][3pid][auth-5]")
{
    GIVEN("a well-formed getValidated3pid response")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::identity::parse_validated_3pid_response(
                R"({"address":"alice@example.org","medium":"email","validated_at":1457622739026})");

            THEN("all three fields are captured")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->address == "alice@example.org");
                REQUIRE(parsed->medium == "email");
                REQUIRE(parsed->validated_at_ms == 1457622739026U);
            }
        }
    }

    GIVEN("a response missing one required field")
    {
        auto const missing_address =
            merovingian::identity::parse_validated_3pid_response(R"({"medium":"email","validated_at":1})");
        auto const missing_medium =
            merovingian::identity::parse_validated_3pid_response(R"({"address":"a@b.c","validated_at":1})");
        auto const missing_time =
            merovingian::identity::parse_validated_3pid_response(R"({"address":"a@b.c","medium":"email"})");

        THEN("parsing fails closed for each")
        {
            REQUIRE_FALSE(missing_address.has_value());
            REQUIRE_FALSE(missing_medium.has_value());
            REQUIRE_FALSE(missing_time.has_value());
        }
    }

    GIVEN("a response whose fields have the wrong types")
    {
        auto const string_time = merovingian::identity::parse_validated_3pid_response(
            R"({"address":"a@b.c","medium":"email","validated_at":"1457622739026"})");
        auto const numeric_address =
            merovingian::identity::parse_validated_3pid_response(R"({"address":5,"medium":"email","validated_at":1})");
        auto const object_medium =
            merovingian::identity::parse_validated_3pid_response(R"({"address":"a@b.c","medium":{},"validated_at":1})");

        THEN("parsing fails closed for each")
        {
            REQUIRE_FALSE(string_time.has_value());
            REQUIRE_FALSE(numeric_address.has_value());
            REQUIRE_FALSE(object_medium.has_value());
        }
    }

    GIVEN("a response with an empty address, an empty medium or a non-positive timestamp")
    {
        auto const empty_address =
            merovingian::identity::parse_validated_3pid_response(R"({"address":"","medium":"email","validated_at":1})");
        auto const empty_medium =
            merovingian::identity::parse_validated_3pid_response(R"({"address":"a@b.c","medium":"","validated_at":1})");
        auto const zero_time = merovingian::identity::parse_validated_3pid_response(
            R"({"address":"a@b.c","medium":"email","validated_at":0})");
        auto const negative_time = merovingian::identity::parse_validated_3pid_response(
            R"({"address":"a@b.c","medium":"email","validated_at":-5})");

        THEN("parsing fails closed: an unvalidated session must never look validated")
        {
            REQUIRE_FALSE(empty_address.has_value());
            REQUIRE_FALSE(empty_medium.has_value());
            REQUIRE_FALSE(zero_time.has_value());
            REQUIRE_FALSE(negative_time.has_value());
        }
    }

    GIVEN("malformed JSON or a non-object body")
    {
        THEN("parsing fails closed")
        {
            REQUIRE_FALSE(merovingian::identity::parse_validated_3pid_response("not-json").has_value());
            REQUIRE_FALSE(merovingian::identity::parse_validated_3pid_response("[]").has_value());
            REQUIRE_FALSE(merovingian::identity::parse_validated_3pid_response("").has_value());
        }
    }
}

SCENARIO("build_get_validated_3pid_path puts the sid and client_secret in the query, percent-encoded",
         "[identity][identity-body][auth][3pid][auth-5]")
{
    GIVEN("a sid and client secret")
    {
        WHEN("the path is built")
        {
            auto const path = merovingian::identity::build_get_validated_3pid_path("s3cr3t", "sid-1");

            THEN("it targets the v2 endpoint with both query parameters")
            {
                REQUIRE(path == "/_matrix/identity/v2/3pid/getValidated3pid?sid=sid-1&client_secret=s3cr3t");
            }
        }
    }

    GIVEN("an IS-issued sid containing characters that would corrupt a query string")
    {
        WHEN("the path is built")
        {
            auto const path = merovingian::identity::build_get_validated_3pid_path("s3cr3t", "a&client_secret=x#y z");

            THEN("those characters are percent-encoded so the sid cannot inject another parameter")
            {
                REQUIRE(path.find('#') == std::string::npos);
                REQUIRE(path.find(' ') == std::string::npos);
                REQUIRE(path.find("&client_secret=x") == std::string::npos);
                REQUIRE(path.find("sid=a%26client_secret%3Dx%23y%20z&client_secret=s3cr3t") != std::string::npos);
            }
        }
    }
}