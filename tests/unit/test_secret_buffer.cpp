// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/secret_buffer.hpp"

#include <catch2/catch_test_macros.hpp>

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

SCENARIO("SecretBuffer move-assignment replaces the prior secret and transfers ownership",
         "[core][secret][security]")
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
