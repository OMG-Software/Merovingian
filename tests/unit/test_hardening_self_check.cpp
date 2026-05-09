// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/platform/hardening_self_check.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Startup hardening self-check reports stable baseline checks", "[platform][hardening]")
{
    GIVEN("the expected baseline check count")
    {
        auto constexpr expected_count = 13U;

        WHEN("the startup hardening self-check runs")
        {
            auto const self_check = merovingian::platform::run_startup_hardening_self_check();

            THEN("it reports the stable baseline check names")
            {
                REQUIRE(self_check.count() == expected_count);
                REQUIRE(self_check.checks()[0].name == "compiler hardening");
                REQUIRE(self_check.checks()[1].name == "linker hardening");
                REQUIRE(self_check.checks()[2].name == "PIE");
                REQUIRE(self_check.checks()[3].name == "RELRO");
                REQUIRE(self_check.checks()[4].name == "stack protector");
                REQUIRE(self_check.checks()[5].name == "FORTIFY_SOURCE");
                REQUIRE(self_check.checks()[6].name == "seccomp");
                REQUIRE(self_check.checks()[7].name == "pledge/unveil");
                REQUIRE(self_check.checks()[8].name == "capsicum");
                REQUIRE(self_check.checks()[9].name == "privilege drop");
                REQUIRE(self_check.checks()[10].name == "filesystem restrictions");
                REQUIRE(self_check.checks()[11].name == "core dump policy");
                REQUIRE(self_check.checks()[12].name == "secret redaction policy");
            }
        }
    }
}

SCENARIO("Unimplemented runtime hardening checks remain unknown", "[platform][hardening]")
{
    GIVEN("the unknown hardening status")
    {
        auto constexpr unknown = merovingian::platform::HardeningStatus::unknown;

        WHEN("the startup hardening self-check runs")
        {
            auto const self_check = merovingian::platform::run_startup_hardening_self_check();

            THEN("unimplemented runtime checks are reported as unknown")
            {
                REQUIRE(self_check.checks()[6].status == unknown);
                REQUIRE(self_check.checks()[7].status == unknown);
                REQUIRE(self_check.checks()[8].status == unknown);
                REQUIRE(self_check.checks()[9].status == unknown);
                REQUIRE(self_check.checks()[10].status == unknown);
                REQUIRE(self_check.checks()[11].status == unknown);
            }
        }
    }
}

SCENARIO("Secret redaction policy self-check is enabled", "[platform][hardening]")
{
    GIVEN("the enabled hardening status")
    {
        auto constexpr enabled = merovingian::platform::HardeningStatus::enabled;

        WHEN("the startup hardening self-check runs")
        {
            auto const self_check = merovingian::platform::run_startup_hardening_self_check();

            THEN("the secret redaction policy check is enabled")
            {
                REQUIRE(self_check.checks()[12].name == "secret redaction policy");
                REQUIRE(self_check.checks()[12].status == enabled);
            }
        }
    }
}

SCENARIO("Hardening status names are stable for startup logs", "[platform][hardening]")
{
    GIVEN("hardening status values")
    {
        auto constexpr enabled = merovingian::platform::HardeningStatus::enabled;
        auto constexpr disabled = merovingian::platform::HardeningStatus::disabled;
        auto constexpr unknown = merovingian::platform::HardeningStatus::unknown;

        WHEN("the status names are requested")
        {
            auto const enabled_name = std::string{merovingian::platform::hardening_status_name(enabled)};
            auto const disabled_name = std::string{merovingian::platform::hardening_status_name(disabled)};
            auto const unknown_name = std::string{merovingian::platform::hardening_status_name(unknown)};

            THEN("the diagnostic names are stable")
            {
                REQUIRE(enabled_name == "enabled");
                REQUIRE(disabled_name == "disabled");
                REQUIRE(unknown_name == "unknown");
            }
        }
    }
}
