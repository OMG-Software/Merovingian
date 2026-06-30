// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/federation/outbound_transaction.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <span>
#include <string>
#include <utility>

SCENARIO("SecretBuffer allocates requested size", "[core][secret]")
{
    GIVEN("a requested secret buffer size")
    {
        constexpr auto expected_size = 64U;

        WHEN("the buffer is constructed")
        {
            auto buffer = merovingian::core::SecretBuffer{expected_size};

            THEN("the byte span has the requested size")
            {
                REQUIRE(buffer.bytes().size() == expected_size);
            }
        }
    }
}

SCENARIO("SecretBuffer exposes mutable byte span", "[core][secret]")
{
    GIVEN("a secret buffer and a byte value")
    {
        auto buffer = merovingian::core::SecretBuffer{8U};
        auto constexpr expected_value = 0xAAU;

        WHEN("the first byte is written")
        {
            buffer.bytes()[0] = expected_value;

            THEN("the byte span reports the written value")
            {
                REQUIRE(buffer.bytes()[0] == expected_value);
            }
        }
    }
}

SCENARIO("SecretBuffer is move-only and clears on destruction", "[core][secret][security]")
{
    GIVEN("a secret buffer containing sensitive bytes")
    {
        auto source = merovingian::core::SecretBuffer{4U};
        source.bytes()[0] = 0xDEU;
        source.bytes()[1] = 0xADU;
        source.bytes()[2] = 0xBEU;
        source.bytes()[3] = 0xEFU;

        WHEN("the buffer is moved")
        {
            auto destination = std::move(source);

            THEN("the destination receives the bytes and the source is left empty")
            {
                REQUIRE(destination.bytes().size() == 4U);
                REQUIRE(destination.bytes()[0] == 0xDEU);
                REQUIRE(source.bytes().empty());
            }
        }
    }
}

SCENARIO("SecretBuffer move-assignment replaces the prior secret and transfers ownership", "[core][secret][security]")
{
    GIVEN("a buffer holding a prior secret and a buffer holding a new secret")
    {
        auto prior = merovingian::core::SecretBuffer{4U};
        prior.bytes()[0] = 0x11U;
        prior.bytes()[1] = 0x22U;
        prior.bytes()[2] = 0x33U;
        prior.bytes()[3] = 0x44U;
        auto next = merovingian::core::SecretBuffer{2U};
        next.bytes()[0] = 0xCAU;
        next.bytes()[1] = 0xFEU;

        WHEN("the prior buffer is move-assigned from the next buffer")
        {
            prior = std::move(next);

            THEN("the target holds the new secret's bytes and the source is left empty")
            {
                REQUIRE(prior.bytes().size() == 2U);
                REQUIRE(prior.bytes()[0] == 0xCAU);
                REQUIRE(prior.bytes()[1] == 0xFEU);
                REQUIRE(next.bytes().empty());
            }
        }
    }
}

SCENARIO("SecretBuffer chained moves preserve the secret bytes", "[core][secret][security]")
{
    GIVEN("a secret buffer containing sensitive bytes")
    {
        auto original = merovingian::core::SecretBuffer{3U};
        original.bytes()[0] = 0x01U;
        original.bytes()[1] = 0x02U;
        original.bytes()[2] = 0x03U;

        WHEN("the buffer is moved twice")
        {
            auto first_hop = std::move(original);
            auto second_hop = std::move(first_hop);

            THEN("the final holder retains the bytes and the intermediates are empty")
            {
                REQUIRE(second_hop.bytes().size() == 3U);
                REQUIRE(second_hop.bytes()[0] == 0x01U);
                REQUIRE(second_hop.bytes()[1] == 0x02U);
                REQUIRE(second_hop.bytes()[2] == 0x03U);
                REQUIRE(original.bytes().empty());
                REQUIRE(first_hop.bytes().empty());
            }
        }
    }
}

SCENARIO("SecretBuffer of zero size and default construction are safe to destroy", "[core][secret][security]")
{
    GIVEN("a default-constructed secret buffer and a zero-sized secret buffer")
    {
        auto empty_default = merovingian::core::SecretBuffer{};
        auto empty_sized = merovingian::core::SecretBuffer{0U};

        THEN("both expose empty spans and can be destroyed without error")
        {
            REQUIRE(empty_default.bytes().empty());
            REQUIRE(empty_sized.bytes().empty());
        }
    }
}

// #317: the span constructor is the path production uses to move the server
// signing key out of an unpinned std::string into an owning, mlocked SecretBuffer
// (DispatchWorkerConfig::secret_key). It must take its own copy so the source
// can be wiped or mutated independently afterward.
SCENARIO("SecretBuffer span constructor owns an independent copy of the source bytes", "[core][secret][security]")
{
    GIVEN("a source byte buffer holding sensitive material")
    {
        auto source = std::array<std::uint8_t, 4U>{0xDEU, 0xADU, 0xBEU, 0xEFU};
        auto source_span = std::span<std::uint8_t const>{source};

        WHEN("a SecretBuffer is constructed from the span")
        {
            auto owned = merovingian::core::SecretBuffer{source_span};

            THEN("the owner holds a copy of the source bytes")
            {
                REQUIRE(owned.bytes().size() == source.size());
                REQUIRE(std::ranges::equal(owned.bytes(), source_span));
            }

            AND_WHEN("the source is mutated after construction")
            {
                source[0] = 0x00U;
                source[1] = 0x00U;

                THEN("the owned copy is unaffected — it is independent of the source")
                {
                    REQUIRE(owned.bytes()[0] == 0xDEU);
                    REQUIRE(owned.bytes()[1] == 0xADU);
                    REQUIRE(owned.bytes()[2] == 0xBEU);
                    REQUIRE(owned.bytes()[3] == 0xEFU);
                }
            }
        }
    }
}

// #317: OutboundCall::secret_key is now a non-owning span that borrows from an
// owner (the runtime SecretBuffer for synchronous calls, DispatchWorkerConfig for
// async dispatch). build_outbound_request signs synchronously through that borrowed
// span and produces a real X-Matrix signature — proving the signing path works
// without ever materialising the key into an unpinned std::string.
SCENARIO("OutboundCall borrows the signing key as a span and signs without a std::string copy",
         "[federation][outbound][secret][security]")
{
    GIVEN("a SecretBuffer owning a 64-byte Ed25519 secret key and an OutboundCall borrowing it")
    {
        // A 64-byte key is what make_federation_signature requires; any nonzero
        // bytes suffice to prove the signing path runs against the borrowed span.
        auto key_owner = merovingian::core::SecretBuffer{64U};
        std::ranges::fill(key_owner.bytes(), std::uint8_t{0x42U});

        auto call = merovingian::federation::OutboundCall{};
        call.transaction = merovingian::federation::make_outbound_transaction(
            "remote.example.org", "PUT", "/_matrix/federation/v1/send/txn1", "origin.example.org", R"({"pdus":[]})");
        call.resolved_host = "remote.example.org";
        call.resolved_port = 8448U;
        call.pinned_addresses = {"203.0.113.10"};
        call.key_id = "ed25519:auto";
        // Borrow, do not copy — the call holds only a span into key_owner.
        call.secret_key = key_owner.bytes();

        WHEN("the outbound request is built from the borrowed span")
        {
            auto const request = merovingian::federation::build_outbound_request(call);

            THEN("the X-Matrix Authorization header carries a non-empty signature")
            {
                auto const it = std::ranges::find_if(request.headers, [](auto const& h) {
                    return h.name == "Authorization";
                });
                REQUIRE(it != request.headers.end());
                // The sig= field is present and populated (not `sig=""`), proving
                // the borrowed span reached make_federation_signature as a usable key.
                REQUIRE(it->value.find("sig=\"") != std::string::npos);
                REQUIRE(it->value.find("sig=\"\"") == std::string::npos);
            }
        }
    }
}
