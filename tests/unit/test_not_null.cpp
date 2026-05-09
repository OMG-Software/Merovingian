// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/core/not_null.hpp>

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>

TEST_CASE("not_null rejects nullptr", "[core][not_null]")
{
    // Given
    auto* value = static_cast<int*>(nullptr);

    // When
    auto make_not_null = [&value]() { return merovingian::core::not_null<int*>{value}; };

    // Then
    REQUIRE_THROWS_AS(make_not_null(), std::invalid_argument);
}

TEST_CASE("not_null preserves valid pointer", "[core][not_null]")
{
    // Given
    auto value = 42;

    // When
    auto ptr = merovingian::core::not_null<int*>{&value};

    // Then
    REQUIRE(*ptr.get() == 42);
}
