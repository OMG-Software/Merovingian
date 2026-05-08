// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/core/not_null.hpp>

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>

TEST_CASE("not_null rejects nullptr", "[core][not_null]") {
    REQUIRE_THROWS_AS(
        merovingian::core::not_null<int*>{nullptr},
        std::invalid_argument
    );
}

TEST_CASE("not_null preserves valid pointer", "[core][not_null]") {
    auto value = 42;

    auto ptr = merovingian::core::not_null<int*>{&value};

    REQUIRE(*ptr.get() == 42);
}
