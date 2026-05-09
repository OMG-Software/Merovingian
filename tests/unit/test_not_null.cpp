// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/core/not_null.hpp>

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>

SCENARIO("not_null rejects nullptr", "[core][not_null]")
{
    GIVEN("a null pointer")
    {
        auto* value = static_cast<int*>(nullptr);

        WHEN("a not_null wrapper is constructed")
        {
            auto make_not_null = [&value]() { return merovingian::core::not_null<int*>{value}; };

            THEN("construction throws invalid_argument")
            {
                REQUIRE_THROWS_AS(make_not_null(), std::invalid_argument);
            }
        }
    }
}

SCENARIO("not_null preserves valid pointer", "[core][not_null]")
{
    GIVEN("a valid pointer")
    {
        auto value = 42;

        WHEN("a not_null wrapper is constructed")
        {
            auto ptr = merovingian::core::not_null<int*>{&value};

            THEN("the wrapped pointer dereferences to the original value")
            {
                REQUIRE(*ptr.get() == 42);
            }
        }
    }
}
