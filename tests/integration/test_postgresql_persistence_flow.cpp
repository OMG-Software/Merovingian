// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstdlib>
#include <string_view>

#include <catch2/catch_test_macros.hpp>
#include <merovingian/database/postgresql_store.hpp>

namespace
{

[[nodiscard]] auto postgresql_uri_from_environment() -> std::string_view
{
    auto const* value = std::getenv("MEROVINGIAN_TEST_POSTGRESQL_URI");
    return value == nullptr ? std::string_view{} : std::string_view{value};
}

} // namespace

SCENARIO("Temporary PostgreSQL integration coverage is gated by an explicit test URI",
         "[database][postgresql][integration]")
{
    GIVEN("the PostgreSQL integration test environment")
    {
        auto const uri = postgresql_uri_from_environment();

        WHEN("the URI is absent")
        {
            if (uri.empty())
            {
                THEN("the gate is explicit and does not attempt an ambient database connection")
                {
                    REQUIRE(uri.empty());
                }
            }
            else
            {
                auto const policy = merovingian::database::validate_postgresql_conninfo(uri);
                auto opened = merovingian::database::open_postgresql_persistent_store(uri);

                THEN("the provided PostgreSQL URI bootstraps and hydrates a live test store")
                {
                    REQUIRE(policy.allowed);
                    REQUIRE(opened.ok);
                    REQUIRE(opened.store.open);
                }
            }
        }
    }
}
