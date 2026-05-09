// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/core/secret_buffer.hpp>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("SecretBuffer allocates requested size", "[core][secret]")
{
    // Given
    constexpr auto expected_size = 64U;

    // When
    auto buffer = merovingian::core::SecretBuffer{expected_size};

    // Then
    REQUIRE(buffer.bytes().size() == expected_size);
}

TEST_CASE("SecretBuffer exposes mutable byte span", "[core][secret]")
{
    // Given
    auto buffer = merovingian::core::SecretBuffer{8U};
    auto constexpr expected_value = 0xAAU;

    // When
    buffer.bytes()[0] = expected_value;

    // Then
    REQUIRE(buffer.bytes()[0] == expected_value);
}
