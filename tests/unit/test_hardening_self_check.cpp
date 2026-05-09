// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/platform/hardening_self_check.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("Startup hardening self-check reports stable baseline checks", "[platform][hardening]")
{
    // Given / When
    auto const self_check = merovingian::platform::run_startup_hardening_self_check();

    // Then
    REQUIRE(self_check.count() == 4U);
    REQUIRE(self_check.checks()[0].name == "stack protector");
    REQUIRE(self_check.checks()[1].name == "FORTIFY_SOURCE");
    REQUIRE(self_check.checks()[2].name == "runtime sandbox");
    REQUIRE(self_check.checks()[2].status == merovingian::platform::HardeningStatus::unknown);
    REQUIRE(self_check.checks()[3].name == "filesystem restrictions");
    REQUIRE(self_check.checks()[3].status == merovingian::platform::HardeningStatus::unknown);
}

TEST_CASE("Hardening status names are stable for startup logs", "[platform][hardening]")
{
    // Given / When / Then
    REQUIRE(
        std::string{merovingian::platform::hardening_status_name(merovingian::platform::HardeningStatus::enabled)}
        == "enabled"
    );
    REQUIRE(
        std::string{merovingian::platform::hardening_status_name(merovingian::platform::HardeningStatus::disabled)}
        == "disabled"
    );
    REQUIRE(
        std::string{merovingian::platform::hardening_status_name(merovingian::platform::HardeningStatus::unknown)}
        == "unknown"
    );
}
