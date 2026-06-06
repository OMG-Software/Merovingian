// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              MATRIX IDENTIFIER GRAMMAR CONFORMANCE TESTS               |
// |                                                                         |
// |  Spec: Matrix v1.18 Appendices — Identifier Grammar                    |
// |  URL:  https://spec.matrix.org/v1.18/appendices/#identifier-grammar    |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST or SHOULD from the Matrix    |
// |  specification. If a test fails:                                         |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// |  The spec section is cited above each SCENARIO. Cross-check it before   |
// |  concluding that a failing assertion is wrong.                           |
// +-------------------------------------------------------------------------+

#include "merovingian/auth/identity.hpp"
#include "merovingian/events/event_id.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <vector>

// ---------------------------------------------------------------------------
// Spec: Matrix v1.18 Appendices — Server Name
// URL:  https://spec.matrix.org/v1.18/appendices/#server-name
//
// server_name = hostname [ ":" port ]
// hostname    = IPv4address / "[" IPv6address "]" / dns_name
// dns_name    = 1*( ALPHA / DIGIT / "-" / "." )
// port        = 1*5DIGIT  ; numeric port 1–65535
//
// A server name MUST NOT contain "@" or "/".
// An empty string is not a valid server name.
// ---------------------------------------------------------------------------

SCENARIO("Server name grammar: bare DNS hostnames are valid",
         "[conformance][identifiers][server-name]")
{
    GIVEN("bare DNS hostnames without explicit ports")
    {
        auto const names = std::vector<std::string_view>{
            "example.org",
            "matrix.example.com",
            "localhost",
            "my-server.example.co.uk",
            "a",
            "A.B.C",
        };

        WHEN("each server name is validated")
        {
            THEN("all bare DNS hostnames are accepted")
            {
                for (auto const& name : names)
                {
                    // Spec MUST: a DNS hostname of letters, digits, hyphens, dots is a valid server name.
                    REQUIRE(merovingian::auth::server_name_is_valid(name));
                }
            }
        }
    }
}

SCENARIO("Server name grammar: hostname with explicit port is valid",
         "[conformance][identifiers][server-name]")
{
    GIVEN("valid hostname:port combinations")
    {
        auto const names = std::vector<std::string_view>{
            "example.org:8448",
            "matrix.example.com:443",
            "localhost:8008",
            "example.org:1",
            "example.org:65535",
        };

        WHEN("each server name is validated")
        {
            THEN("all hostname:port combinations are accepted")
            {
                for (auto const& name : names)
                {
                    // Spec MUST: a DNS hostname with a valid port 1–65535 is a valid server name.
                    REQUIRE(merovingian::auth::server_name_is_valid(name));
                }
            }
        }
    }
}

SCENARIO("Server name grammar: IPv4 address server names are valid",
         "[conformance][identifiers][server-name]")
{
    GIVEN("valid IPv4 address server names")
    {
        auto const names = std::vector<std::string_view>{
            "203.0.113.10",
            "203.0.113.10:8448",
            "1.2.3.4",
        };

        WHEN("each server name is validated")
        {
            THEN("IPv4 addresses with optional port are accepted")
            {
                for (auto const& name : names)
                {
                    // Spec MUST: a dotted-decimal IPv4 address (with optional port) is a valid server name.
                    REQUIRE(merovingian::auth::server_name_is_valid(name));
                }
            }
        }
    }
}

SCENARIO("Server name grammar: bracketed IPv6 address server names are valid",
         "[conformance][identifiers][server-name]")
{
    GIVEN("valid bracketed IPv6 server names")
    {
        auto const names = std::vector<std::string_view>{
            "[2001:db8::1]",
            "[2001:db8::1]:8448",
            "[::1]",
        };

        WHEN("each server name is validated")
        {
            THEN("bracketed IPv6 addresses with optional port are accepted")
            {
                for (auto const& name : names)
                {
                    // Spec MUST: bracket-enclosed IPv6 addresses (with optional port) are valid server names.
                    REQUIRE(merovingian::auth::server_name_is_valid(name));
                }
            }
        }
    }
}

SCENARIO("Server name grammar: invalid server names are rejected",
         "[conformance][identifiers][server-name]")
{
    GIVEN("server names that violate the grammar")
    {
        auto const invalid_names = std::vector<std::string_view>{
            "",                   // empty — spec MUST NOT
            "@example.org",       // '@' is forbidden — spec MUST NOT
            "example.org/path",   // '/' is forbidden — spec MUST NOT
            "example.org:65536",  // port > 65535 — out of range
            "example.org:",       // colon with no port digits
            ":8448",              // no hostname before colon
        };

        WHEN("each invalid name is validated")
        {
            THEN("all invalid server names are rejected")
            {
                for (auto const& name : invalid_names)
                {
                    // Spec MUST: these forms violate the server_name grammar and MUST be rejected.
                    REQUIRE_FALSE(merovingian::auth::server_name_is_valid(name));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: Matrix v1.18 Appendices — User Identifiers
// URL:  https://spec.matrix.org/v1.18/appendices/#user-identifiers
//
// user_id     = "@" localpart ":" server_name
// localpart   = 1*user_id_char
// user_id_char = ALPHA / DIGIT / "-" / "." / "=" / "_" / "/" / "+" (historical)
//
// The full user ID (including "@" and ":") MUST NOT exceed 255 bytes.
// ---------------------------------------------------------------------------

SCENARIO("User ID grammar: valid user IDs are accepted",
         "[conformance][identifiers][user-id]")
{
    GIVEN("well-formed Matrix user IDs")
    {
        auto const valid_ids = std::vector<std::string_view>{
            "@alice:example.org",
            "@bob.smith:matrix.example.com",
            "@user-123:server.net",
            "@test_user:localhost",
            "@a:b",
        };

        WHEN("each user ID is validated")
        {
            THEN("all well-formed user IDs are accepted")
            {
                for (auto const& id : valid_ids)
                {
                    // Spec MUST: '@' + valid localpart + ':' + valid server_name is a valid user ID.
                    REQUIRE(merovingian::auth::user_id_is_valid(id));
                }
            }
        }
    }
}

SCENARIO("User ID grammar: malformed user IDs are rejected",
         "[conformance][identifiers][user-id]")
{
    GIVEN("user IDs that violate the spec grammar")
    {
        auto const invalid_ids = std::vector<std::string_view>{
            "",                           // empty
            "alice:example.org",          // missing '@' sigil
            "@",                          // only sigil, no localpart or server
            "@:example.org",              // empty localpart
            "@alice",                     // missing ':' and server name
            "@alice:",                    // missing server name after ':'
            "@ alice:example.org",        // space in localpart is forbidden
        };

        WHEN("each invalid user ID is validated")
        {
            THEN("all malformed user IDs are rejected")
            {
                for (auto const& id : invalid_ids)
                {
                    // Spec MUST: user IDs without the '@' sigil, without a server name, or with
                    // illegal characters MUST be rejected.
                    REQUIRE_FALSE(merovingian::auth::user_id_is_valid(id));
                }
            }
        }
    }
}

SCENARIO("User ID grammar: user ID exceeding 255 bytes is rejected",
         "[conformance][identifiers][user-id]")
{
    GIVEN("user IDs at and around the 255-byte spec limit")
    {
        // Spec: the full user ID MUST NOT exceed 255 bytes.
        // "@" (1) + localpart + ":" (1) + "example.org" (11) = 13 overhead bytes.
        // To hit exactly 255 total: localpart = 255 - 13 = 242 chars.
        // To hit exactly 256 total: localpart = 256 - 13 = 243 chars.
        auto constexpr server    = std::string_view{":example.org"};
        auto constexpr overhead  = 1U + server.size(); // '@' + ':example.org' = 13
        auto const max_localpart = std::string(255U - overhead, 'a'); // 242 chars
        auto const over_localpart = std::string(256U - overhead, 'a'); // 243 chars

        auto const exactly_255 = "@" + max_localpart + std::string{server};   // 255 bytes
        auto const exactly_256 = "@" + over_localpart + std::string{server};  // 256 bytes

        WHEN("both user IDs are validated")
        {
            THEN("the 255-byte ID is accepted and the 256-byte ID is rejected")
            {
                // Spec MUST: user IDs of exactly 255 bytes are valid.
                REQUIRE(exactly_255.size() == 255U);
                REQUIRE(merovingian::auth::user_id_is_valid(exactly_255));
                // Spec MUST: user IDs exceeding 255 bytes MUST be rejected.
                REQUIRE(exactly_256.size() == 256U);
                REQUIRE_FALSE(merovingian::auth::user_id_is_valid(exactly_256));
            }
        }
    }
}

// Spec: Matrix CS API v1.18 Appendices § User Identifiers
// URL: https://spec.matrix.org/v1.18/appendices/#user-identifiers
//
// New user ID localparts MUST only use: a-z, 0-9, ., _, =, -, /, +
// Historical user IDs MAY contain additional characters (e.g. uppercase ASCII).
// Servers SHOULD accept historical localparts from federation.
// The localpart_is_valid() helper accepts the full historical set so that
// incoming federation user IDs are not incorrectly rejected.
SCENARIO("User ID localpart: normative new-ID characters are accepted",
         "[conformance][identifiers][user-id][localpart]")
{
    GIVEN("localparts using the normative v1.18 character set (lowercase only)")
    {
        auto const normative_valid = std::vector<std::string_view>{
            "alice",
            "alice123",
            "alice.bob",
            "alice-bob",
            "alice_bob",
            "alice=bob",
        };

        WHEN("each localpart is validated")
        {
            THEN("all normative v1.18 localpart characters are accepted")
            {
                for (auto const& lp : normative_valid)
                {
                    // Spec MUST: a-z, 0-9, ., _, =, -, /, + are all normatively valid.
                    REQUIRE(merovingian::auth::localpart_is_valid(lp));
                }
            }
        }
    }
}

// NOTE: This is a historical-compatibility test, not a normative conformance test.
// The spec says new localparts MUST be lowercase; uppercase localparts exist in
// older deployments and servers SHOULD accept them for federation.
SCENARIO("User ID localpart: historical uppercase localparts are accepted for federation compatibility",
         "[identifiers][user-id][localpart][historical]")
{
    GIVEN("an uppercase localpart from a historical deployment")
    {
        WHEN("the localpart is validated")
        {
            THEN("localpart_is_valid accepts it for historical/federation compatibility")
            {
                // Historical compatibility — NOT a new-user-ID conformance requirement.
                // New registrations MUST NOT create uppercase localparts.
                REQUIRE(merovingian::auth::localpart_is_valid("ALICE"));
            }
        }
    }
}

SCENARIO("User ID localpart: forbidden characters are rejected",
         "[conformance][identifiers][user-id][localpart]")
{
    GIVEN("localparts containing characters not in the allowed set")
    {
        auto const invalid = std::vector<std::string_view>{
            "",           // empty localpart is forbidden
            "alice bob",  // space is forbidden
            "@alice",     // sigil is forbidden in localpart
            "alice@",     // sigil is forbidden in localpart
            "alice#bob",  // '#' is forbidden
        };

        WHEN("each localpart is validated")
        {
            THEN("all forbidden localpart characters are rejected")
            {
                for (auto const& lp : invalid)
                {
                    // Spec MUST: spaces, '@', '#' and other unlisted characters are forbidden in localparts.
                    REQUIRE_FALSE(merovingian::auth::localpart_is_valid(lp));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: Matrix v1.18 Appendices — Event IDs (room version 4+)
// URL:  https://spec.matrix.org/v1.18/appendices/#event-ids
//       https://spec.matrix.org/v1.18/rooms/v4/
//
// event_id  = "$" base64url
// base64url = *( ALPHA / DIGIT / "-" / "_" )
//
// In room version 4 and later an event ID is the URL-safe unpadded base64
// encoding of the SHA-256 reference hash of the event, prefixed with "$".
// ---------------------------------------------------------------------------

SCENARIO("Event ID grammar: well-formed event IDs are accepted",
         "[conformance][identifiers][event-id]")
{
    GIVEN("valid room version 4+ event IDs")
    {
        auto const ids = std::vector<std::string_view>{
            "$abc123",
            "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 43 base64url chars (SHA-256 size)
            "$-_valid-url-safe-base64-characters-are-ok_",
        };

        WHEN("each event ID is validated")
        {
            THEN("all well-formed event IDs are accepted")
            {
                for (auto const& id : ids)
                {
                    // Spec MUST: event ID is '$' followed by one or more URL-safe base64 characters.
                    REQUIRE(merovingian::events::event_id_is_valid(id));
                }
            }
        }
    }
}

SCENARIO("Event ID grammar: malformed event IDs are rejected",
         "[conformance][identifiers][event-id]")
{
    GIVEN("event IDs that violate the room version 4+ grammar")
    {
        auto const invalid_ids = std::vector<std::string_view>{
            "",              // empty
            "abc123",        // missing '$' sigil
            "$",             // sigil only, no hash bytes
            "$has spaces",   // spaces are forbidden in base64url
            "$has+plus",     // '+' is standard base64, NOT URL-safe base64
            "$has/slash",    // '/' is standard base64, NOT URL-safe base64
            "$has=padding",  // padding '=' is forbidden (spec requires unpadded)
        };

        WHEN("each invalid event ID is validated")
        {
            THEN("all malformed event IDs are rejected")
            {
                for (auto const& id : invalid_ids)
                {
                    // Spec MUST: standard base64 '+' and '/' chars are forbidden; unpadded only.
                    REQUIRE_FALSE(merovingian::events::event_id_is_valid(id));
                }
            }
        }
    }
}

SCENARIO("Event ID grammar: SHA-256 length event ID matches spec dimensions",
         "[conformance][identifiers][event-id]")
{
    GIVEN("an event ID with the expected 43-character URL-safe base64 body")
    {
        // SHA-256 produces 32 bytes. Unpadded base64url of 32 bytes = 43 characters.
        // ceil(32 * 4 / 3) = ceil(42.67) = 43 chars, no '=' padding needed.
        auto const id = std::string{"$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"};

        WHEN("the event ID is validated")
        {
            THEN("the 43-character base64url event ID is accepted and has the correct length")
            {
                // Spec MUST: a real event ID derived from SHA-256 reference hash will be exactly
                // '$' + 43 base64url characters long.
                REQUIRE(merovingian::events::event_id_is_valid(id));
                REQUIRE(id.size() == 44U); // 1 '$' + 43 base64url chars
            }
        }
    }
}
