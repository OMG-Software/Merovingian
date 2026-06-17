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
