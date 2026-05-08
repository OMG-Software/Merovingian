// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/core/secret_buffer.hpp>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("SecretBuffer allocates requested size", "[core][secret]") {
    auto buffer = merovingian::core::SecretBuffer{64U};

    REQUIRE(buffer.bytes().size() == 64U);
}

TEST_CASE("SecretBuffer exposes mutable byte span", "[core][secret]") {
    auto buffer = merovingian::core::SecretBuffer{8U};

    buffer.bytes()[0] = 0xAAU;

    REQUIRE(buffer.bytes()[0] == 0xAAU);
}
