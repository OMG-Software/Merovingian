// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/hardening_self_check.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
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

SCENARIO("Runtime hardening checks deferred for alpha carry documented exceptions", "[platform][hardening]")
{
    GIVEN("the alpha exception hardening status")
    {
        auto constexpr alpha_exception = merovingian::platform::HardeningStatus::alpha_exception;

        WHEN("the startup hardening self-check runs")
        {
            auto const self_check = merovingian::platform::run_startup_hardening_self_check();

            THEN("placeholder runtime checks are tagged alpha_exception with a non-empty note")
            {
                auto const& checks = self_check.checks();
                // Indices 7–11: pledge/unveil, capsicum, privilege drop,
                // filesystem restrictions, core dump policy — still alpha exceptions.
                // Index 6 (seccomp) is now probe-based, not alpha_exception.
                auto const deferred_indices = {7U, 8U, 9U, 10U, 11U};
                for (auto const index : deferred_indices)
                {
                    REQUIRE(checks[index].status == alpha_exception);
                    REQUIRE_FALSE(checks[index].note.empty());
                }
            }

            AND_THEN("probe-derived checks are no longer alpha_exception")
            {
                // linker hardening (index 1) and RELRO (index 3) are driven by the
                // ELF program-header probe; seccomp (index 6) by a /proc/self/status
                // probe. All three may report `enabled` or `unknown` depending on
                // the build and runtime state, but never `alpha_exception`.
                auto const& checks = self_check.checks();
                REQUIRE(checks[1].name == "linker hardening");
                REQUIRE(checks[3].name == "RELRO");
                REQUIRE(checks[6].name == "seccomp");
                REQUIRE(checks[1].status != alpha_exception);
                REQUIRE(checks[3].status != alpha_exception);
                REQUIRE(checks[6].status != alpha_exception);
            }
        }
    }
}

SCENARIO("Hardening self-check fails closed for production while accepting alpha", "[platform][hardening]")
{
    GIVEN("a startup hardening self-check report")
    {
        auto const self_check = merovingian::platform::run_startup_hardening_self_check();

        WHEN("the report is queried for production readiness")
        {
            THEN("alpha_exception entries block production readiness")
            {
                REQUIRE_FALSE(self_check.is_production_ready());
                REQUIRE(self_check.production_blocker_count() > 0U);
            }

            AND_THEN("the report still permits alpha operation")
            {
                REQUIRE(self_check.is_alpha_ready());
            }
        }
    }
}

SCENARIO("Production-blocking hardening checks expose their documented notes", "[platform][hardening]")
{
    GIVEN("a startup hardening self-check report")
    {
        auto const self_check = merovingian::platform::run_startup_hardening_self_check();

        WHEN("production blockers are collected")
        {
            auto const blockers = self_check.production_blockers();

            THEN("alpha_exception blockers reference the alpha exception documentation")
            {
                // ELF-probe-derived checks (linker hardening, RELRO) are now
                // `unknown` rather than `alpha_exception`; they carry informative
                // notes but do not reference the alpha-exceptions doc.
                REQUIRE_FALSE(blockers.empty());
                for (auto const& blocker : blockers)
                {
                    if (blocker.status == merovingian::platform::HardeningStatus::alpha_exception)
                    {
                        REQUIRE(blocker.note.find("docs/hardening-alpha-exceptions.md") != std::string::npos);
                    }
                }
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
        auto constexpr alpha_exception = merovingian::platform::HardeningStatus::alpha_exception;

        WHEN("the status names are requested")
        {
            auto const enabled_name = std::string{merovingian::platform::hardening_status_name(enabled)};
            auto const disabled_name = std::string{merovingian::platform::hardening_status_name(disabled)};
            auto const unknown_name = std::string{merovingian::platform::hardening_status_name(unknown)};
            auto const alpha_exception_name =
                std::string{merovingian::platform::hardening_status_name(alpha_exception)};

            THEN("the diagnostic names are stable")
            {
                REQUIRE(enabled_name == "enabled");
                REQUIRE(disabled_name == "disabled");
                REQUIRE(unknown_name == "unknown");
                REQUIRE(alpha_exception_name == "alpha_exception");
            }
        }
    }
}
