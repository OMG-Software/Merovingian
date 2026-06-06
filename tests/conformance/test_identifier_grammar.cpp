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
// user_id_char = a-z / 0-9 / "-" / "." / "=" / "_" / "/" / "+"
//
// The full user ID (including "@" and ":") MUST NOT exceed 255 bytes.
//
// New user IDs MUST use only lowercase ASCII. Servers receiving user IDs
// over federation SHOULD accept historical localparts that include characters
// outside this normative set (e.g. uppercase ASCII, Unicode, '#', etc.),
// because older deployments may have issued such IDs.
//
// Two distinct validators implement this split:
//   localpart_is_valid_new()       — enforces the normative (new-ID) set
//   localpart_is_valid_federated() — accepts the historical set
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

// ---------------------------------------------------------------------------
// Spec: Matrix CS API v1.18 Appendices § User Identifiers
// URL: https://spec.matrix.org/v1.18/appendices/#user-identifiers
//
// NEW localpart (used at registration / local paths):
//   MUST contain only: a-z, 0-9, ., _, =, -, /, +
//   MUST NOT be empty.
//   MUST NOT contain uppercase letters (spec restriction introduced to allow
//   future case-folding without ambiguity).
//
// Use localpart_is_valid_new() for all new-ID creation and local auth paths.
// ---------------------------------------------------------------------------

SCENARIO("New user ID localpart: normative character set is accepted",
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
            "alice/bob",
            "alice+bob",
        };

        WHEN("each localpart is validated as a new user ID localpart")
        {
            THEN("all normative v1.18 localpart characters are accepted")
            {
                for (auto const& lp : normative_valid)
                {
                    // Spec MUST: a-z, 0-9, ., _, =, -, /, + are all normatively valid.
                    REQUIRE(merovingian::auth::localpart_is_valid_new(lp));
                }
            }
        }
    }
}

SCENARIO("New user ID localpart: uppercase letters are rejected",
         "[conformance][identifiers][user-id][localpart]")
{
    GIVEN("localparts containing uppercase ASCII letters")
    {
        auto const uppercase_cases = std::vector<std::string_view>{
            "ALICE",
            "Alice",
            "alicE",
            "A",
        };

        WHEN("each localpart is validated as a new user ID localpart")
        {
            THEN("uppercase letters are rejected — new IDs must be lowercase")
            {
                for (auto const& lp : uppercase_cases)
                {
                    // Spec MUST: new localparts MUST be lowercase. Uppercase is forbidden
                    // for new user IDs. Do NOT relax — allowing uppercase at registration
                    // breaks case-folding guarantees and creates ambiguous identifiers.
                    REQUIRE_FALSE(merovingian::auth::localpart_is_valid_new(lp));
                }
            }
        }
    }
}

SCENARIO("New user ID localpart: forbidden characters are rejected",
         "[conformance][identifiers][user-id][localpart]")
{
    GIVEN("localparts containing characters not in the allowed normative set")
    {
        auto const invalid = std::vector<std::string_view>{
            "",           // empty localpart is forbidden
            "alice bob",  // space is forbidden
            "@alice",     // sigil is forbidden in localpart
            "alice@",     // sigil is forbidden in localpart
            "alice#bob",  // '#' is not in the normative character set
        };

        WHEN("each localpart is validated as a new user ID localpart")
        {
            THEN("all forbidden characters are rejected")
            {
                for (auto const& lp : invalid)
                {
                    // Spec MUST: spaces, '@', '#' and other unlisted characters are forbidden
                    // in new user ID localparts.
                    REQUIRE_FALSE(merovingian::auth::localpart_is_valid_new(lp));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: Matrix CS API v1.18 Appendices § User Identifiers (historical)
// URL: https://spec.matrix.org/v1.18/appendices/#user-identifiers
//
// HISTORICAL localpart (federation / inbound paths):
//   Older servers issued user IDs with characters outside the normative set.
//   Servers SHOULD accept these when received over federation.
//   The permitted set is: any valid UTF-8 code point that is not ':' or NUL,
//   excluding surrogate code points (U+D800–U+DFFF).
//   Empty localparts are non-conformant but accepted for maximum compatibility.
//
// Use localpart_is_valid_federated() for inbound federation user ID parsing.
// ---------------------------------------------------------------------------

SCENARIO("Federated user ID localpart: historical character set is accepted",
         "[conformance][identifiers][user-id][localpart][historical]")
{
    GIVEN("localparts using characters outside the normative set")
    {
        WHEN("uppercase localparts are validated for federation")
        {
            THEN("historical uppercase localparts are accepted")
            {
                // Spec SHOULD: servers must accept historical user IDs received over
                // federation that predate the lowercase restriction.
                REQUIRE(merovingian::auth::localpart_is_valid_federated("ALICE"));
                REQUIRE(merovingian::auth::localpart_is_valid_federated("Alice"));
            }
        }

        WHEN("localparts with non-normative punctuation are validated for federation")
        {
            THEN("historically permitted characters are accepted")
            {
                // Spec SHOULD: '#', '!', '~' and other non-normative characters exist in
                // historical deployments and must be accepted over federation.
                REQUIRE(merovingian::auth::localpart_is_valid_federated("alice#matrix"));
                REQUIRE(merovingian::auth::localpart_is_valid_federated("alice!tag"));
                REQUIRE(merovingian::auth::localpart_is_valid_federated("alice~home"));
            }
        }

        WHEN("localparts with valid multi-byte UTF-8 characters are validated for federation")
        {
            THEN("valid Unicode code points are accepted")
            {
                // Spec SHOULD: any legal non-surrogate Unicode must be accepted.
                // U+00E9 LATIN SMALL LETTER E WITH ACUTE — 2-byte UTF-8: 0xC3 0xA9
                REQUIRE(merovingian::auth::localpart_is_valid_federated("caf\xC3\xA9"));
                // U+4E2D CJK UNIFIED IDEOGRAPH — 3-byte UTF-8: 0xE4 0xB8 0xAD
                REQUIRE(merovingian::auth::localpart_is_valid_federated("\xE4\xB8\xAD"));
            }
        }

        WHEN("an empty localpart is validated for federation")
        {
            THEN("it is accepted for maximum compatibility")
            {
                // Historical deployments may have issued @:server IDs. The federated
                // validator accepts them even though they are technically non-conformant.
                REQUIRE(merovingian::auth::localpart_is_valid_federated(""));
            }
        }
    }
}

SCENARIO("Federated user ID localpart: structurally forbidden characters are rejected",
         "[conformance][identifiers][user-id][localpart][historical]")
{
    GIVEN("localparts that break user ID parsing regardless of era")
    {
        WHEN("a localpart containing ':' is validated for federation")
        {
            THEN("it is rejected — colon breaks user ID parsing in all eras")
            {
                // Spec MUST: ':' is forbidden in localparts — it is the separator between
                // localpart and server_name. Permitting it would corrupt user ID parsing.
                REQUIRE_FALSE(merovingian::auth::localpart_is_valid_federated("alice:evil"));
                REQUIRE_FALSE(merovingian::auth::localpart_is_valid_federated(":"));
            }
        }

        WHEN("a localpart containing a NUL byte is validated for federation")
        {
            THEN("it is rejected — NUL terminates C strings and corrupts storage")
            {
                // Spec MUST: NUL is forbidden. It causes C-string truncation and
                // can bypass security checks in string-handling code.
                auto const with_nul = std::string{"alice\x00bob", 9};
                REQUIRE_FALSE(merovingian::auth::localpart_is_valid_federated(with_nul));
            }
        }

        WHEN("a localpart with invalid UTF-8 bytes is validated for federation")
        {
            THEN("it is rejected — the spec requires legal Unicode")
            {
                // Spec: "any legal non-surrogate Unicode" — invalid UTF-8 byte sequences
                // are not legal Unicode and must be rejected.
                // 0xFF is never valid in UTF-8.
                REQUIRE_FALSE(merovingian::auth::localpart_is_valid_federated("\xFF"));
                // Surrogate code point U+D800 encoded as CESU-8: ED A0 80
                REQUIRE_FALSE(merovingian::auth::localpart_is_valid_federated("\xED\xA0\x80"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: Matrix v1.18 Appendices — User Identifiers (federated user_id)
// URL:  https://spec.matrix.org/v1.18/appendices/#user-identifiers
//
// user_id_is_valid_federated() applies the same structural constraints as
// user_id_is_valid() (255-byte limit, '@' sigil, ':' separator, valid
// server_name) but uses the federated localpart validator, so historical
// characters and empty localparts are accepted.
// ---------------------------------------------------------------------------

SCENARIO("Federated user ID: structural grammar is enforced with historical localpart rules",
         "[conformance][identifiers][user-id][historical]")
{
    GIVEN("user IDs that would be rejected by the strict new-ID validator")
    {
        WHEN("a user ID with an uppercase localpart is validated for federation")
        {
            THEN("it is accepted by the federated validator")
            {
                // Spec SHOULD: historical uppercase localparts are valid for federation.
                // user_id_is_valid() (strict) rejects this; user_id_is_valid_federated() accepts it.
                REQUIRE(merovingian::auth::user_id_is_valid_federated("@Alice:example.org"));
                REQUIRE_FALSE(merovingian::auth::user_id_is_valid("@Alice:example.org"));
            }
        }

        WHEN("a user ID with non-normative punctuation is validated for federation")
        {
            THEN("it is accepted by the federated validator")
            {
                // Spec SHOULD: historical user IDs with '#' in the localpart must be accepted.
                REQUIRE(merovingian::auth::user_id_is_valid_federated("@alice#tag:example.org"));
                REQUIRE_FALSE(merovingian::auth::user_id_is_valid("@alice#tag:example.org"));
            }
        }
    }

    GIVEN("user IDs that violate structural invariants regardless of era")
    {
        WHEN("structurally malformed user IDs are validated for federation")
        {
            THEN("they are rejected even by the federated validator")
            {
                // These are structurally broken, not merely historically unusual.
                REQUIRE_FALSE(merovingian::auth::user_id_is_valid_federated(""));           // empty
                REQUIRE_FALSE(merovingian::auth::user_id_is_valid_federated("alice:x"));    // missing '@'
                REQUIRE_FALSE(merovingian::auth::user_id_is_valid_federated("@alice"));     // no server
                REQUIRE_FALSE(merovingian::auth::user_id_is_valid_federated("@alice:"));    // empty server
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

// Spec: Matrix Appendices v1.18 — Event IDs (room version 4+)
// URL:  https://spec.matrix.org/v1.18/rooms/v4/
//       https://spec.matrix.org/v1.18/appendices/#event-ids
//
// The grammar for event IDs is: '$' followed by one or more URL-safe base64
// characters. This is a SYNTACTIC rule only.
//
// SEMANTIC constraint (room v4+): event IDs are the URL-safe unpadded base64
// encoding of the SHA-256 reference hash of the event. SHA-256 outputs 32
// bytes, which encode to exactly 43 unpadded base64url characters. Therefore
// a real v4+ event ID is ALWAYS 44 characters total ('$' + 43 base64url).
//
// Short IDs such as "$abc123" are grammar-valid but cannot be genuine SHA-256
// derived identifiers. The grammar function event_id_is_valid() is a SYNTAX
// check; it does not enforce the 43-char semantic requirement.
SCENARIO("Event ID grammar vs semantics: short IDs are syntactically valid but not SHA-256 derived",
         "[conformance][identifiers][event-id]")
{
    GIVEN("an event ID shorter than the SHA-256 derived length")
    {
        // Syntactically valid per the grammar ('$' + base64url+)
        // but cannot be a real room-v4+ SHA-256 derived event ID.
        auto const short_id = std::string{"$abc123"};
        auto const real_id = std::string{"$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"};

        WHEN("both IDs are checked against the grammar")
        {
            THEN("both pass the grammar check (syntax only)")
            {
                // Spec grammar: event_id_is_valid() accepts any '$' + base64url+.
                // It is NOT a semantic validator for SHA-256 lengths.
                REQUIRE(merovingian::events::event_id_is_valid(short_id));
                REQUIRE(merovingian::events::event_id_is_valid(real_id));
            }
        }

        WHEN("lengths are compared against the SHA-256 semantic requirement")
        {
            THEN("only the 44-char ID satisfies the v4+ SHA-256 derivation requirement")
            {
                // Spec MUST (semantic): SHA-256 → 32 bytes → 43 base64url chars → 44 total.
                // A short ID cannot represent a real room-v4+ reference hash.
                REQUIRE(short_id.size() < 44U);  // fails semantic check
                REQUIRE(real_id.size() == 44U);  // satisfies semantic check
            }
        }
    }
}
