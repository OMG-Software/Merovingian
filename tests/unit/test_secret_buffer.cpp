// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/secret_buffer.hpp"

#include <catch2/catch_test_macros.hpp>

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
