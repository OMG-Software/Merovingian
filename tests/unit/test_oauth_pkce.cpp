// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// oauth PKCE (RFC 7636, S256 only, ADR-0768) and the crypto::sha256 primitive it hashes with.

#include "merovingian/crypto/Encoding.hpp"
#include "merovingian/crypto/Sha256.hpp"
#include "merovingian/oauth/Pkce.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>

namespace
{

using merovingian::oauth::pkce_challenge_is_valid;
using merovingian::oauth::pkce_s256_matches;
using merovingian::oauth::pkce_verifier_is_valid;

// RFC 7636 appendix B.
constexpr auto rfc_verifier = std::string_view{"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"};
constexpr auto rfc_challenge = std::string_view{"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"};

} // namespace

SCENARIO("crypto::sha256 matches the FIPS 180-2 test vectors", "[crypto][sha256]")
{
    GIVEN("the inputs \"abc\" and the empty string")
    {
        WHEN("they are hashed")
        {
            auto const abc = merovingian::crypto::sha256("abc");
            auto const empty = merovingian::crypto::sha256("");

            THEN("each digest is 32 bytes with the published value")
            {
                REQUIRE(abc.has_value());
                REQUIRE(empty.has_value());
                REQUIRE(abc->size() == merovingian::crypto::sha256_digest_bytes);
                auto const abc_hex =
                    merovingian::crypto::to_hex({reinterpret_cast<unsigned char const*>(abc->data()), abc->size()});
                auto const empty_hex =
                    merovingian::crypto::to_hex({reinterpret_cast<unsigned char const*>(empty->data()), empty->size()});
                REQUIRE(abc_hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
                REQUIRE(empty_hex == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            }
        }
    }
}

SCENARIO("The RFC 7636 appendix B verifier matches its challenge", "[oauth][pkce]")
{
    GIVEN("the appendix B code_verifier and code_challenge")
    {
        WHEN("the verifier is checked against the challenge")
        {
            auto const matches = pkce_s256_matches(rfc_verifier, rfc_challenge);

            THEN("it matches, and both are valid on their own")
            {
                REQUIRE(matches);
                REQUIRE(pkce_verifier_is_valid(rfc_verifier));
                REQUIRE(pkce_challenge_is_valid(rfc_challenge));
            }
        }
    }
}

SCENARIO("A verifier that differs in one character does not match", "[oauth][pkce][security]")
{
    GIVEN("the appendix B verifier with its last character changed")
    {
        auto verifier = std::string{rfc_verifier};
        verifier.back() = 'j';

        WHEN("it is checked against the appendix B challenge")
        {
            auto const matches = pkce_s256_matches(verifier, rfc_challenge);

            THEN("it does not match")
            {
                REQUIRE_FALSE(matches);
            }
        }
    }
}

SCENARIO("The verifier length bounds are 43 and 128", "[oauth][pkce][boundary]")
{
    GIVEN("verifiers of 42, 43, 128 and 129 unreserved characters")
    {
        auto const v42 = std::string(42U, 'a');
        auto const v43 = std::string(43U, 'a');
        auto const v128 = std::string(128U, '~');
        auto const v129 = std::string(129U, '~');

        WHEN("each is validated")
        {
            THEN("only 43 and 128 pass")
            {
                REQUIRE_FALSE(pkce_verifier_is_valid(v42));
                REQUIRE(pkce_verifier_is_valid(v43));
                REQUIRE(pkce_verifier_is_valid(v128));
                REQUIRE_FALSE(pkce_verifier_is_valid(v129));
                REQUIRE_FALSE(pkce_verifier_is_valid(""));
            }
        }
    }
}

SCENARIO("A verifier holding a character outside the unreserved set is refused", "[oauth][pkce][security]")
{
    GIVEN("43-character verifiers each carrying one forbidden byte")
    {
        auto const forbidden = std::string_view{"+/= %!*\x7f"};

        WHEN("each is validated")
        {
            THEN("every one is refused, and a NUL is refused too")
            {
                for (auto const value : forbidden)
                {
                    auto verifier = std::string(43U, 'a');
                    verifier[20] = value;
                    REQUIRE_FALSE(pkce_verifier_is_valid(verifier));
                }
                auto with_nul = std::string(43U, 'a');
                with_nul[0] = '\0';
                REQUIRE_FALSE(pkce_verifier_is_valid(with_nul));
                auto non_ascii = std::string(42U, 'a');
                non_ascii.append("\xc3\xa9");
                REQUIRE_FALSE(pkce_verifier_is_valid(non_ascii));
            }
        }
    }
}

SCENARIO("A challenge must be exactly 43 canonical base64url characters", "[oauth][pkce][security]")
{
    GIVEN("challenges that are padded, too short, too long, standard base64, or non-canonical")
    {
        auto const padded = std::string{rfc_challenge} + "=";
        auto const short_one = std::string{rfc_challenge.substr(0U, 42U)};
        auto const long_one = std::string{rfc_challenge} + "A";
        auto standard = std::string{rfc_challenge};
        standard[5] = '+';
        // `cM` ends the RFC challenge; `cN` decodes to the same 32 bytes with a set unused bit.
        auto non_canonical = std::string{rfc_challenge};
        non_canonical.back() = 'N';

        WHEN("each is validated")
        {
            THEN("every one is refused and none can match the verifier")
            {
                for (auto const& challenge : {padded, short_one, long_one, standard, non_canonical})
                {
                    REQUIRE_FALSE(pkce_challenge_is_valid(challenge));
                    REQUIRE_FALSE(pkce_s256_matches(rfc_verifier, challenge));
                }
            }
        }
    }
}

SCENARIO("An invalid verifier never matches, even against its own hash", "[oauth][pkce][security]")
{
    GIVEN("a 42-character verifier and the challenge computed from it")
    {
        auto const verifier = std::string(42U, 'a');
        auto const digest = merovingian::crypto::sha256(verifier);
        REQUIRE(digest.has_value());
        auto const challenge = merovingian::crypto::base64_urlsafe_encode(*digest);
        REQUIRE(challenge.has_value());

        WHEN("they are checked")
        {
            auto const matches = pkce_s256_matches(verifier, *challenge);

            THEN("the short verifier is refused")
            {
                REQUIRE(pkce_challenge_is_valid(*challenge));
                REQUIRE_FALSE(matches);
            }
        }
    }
}
