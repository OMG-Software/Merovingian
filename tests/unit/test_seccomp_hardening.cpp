// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/hardening_self_check.hpp"
#include "merovingian/platform/seccomp_hardening.hpp"

#include <catch2/catch_test_macros.hpp>

SCENARIO("seccomp hardening check maps probe results to the correct status",
         "[platform][hardening][seccomp]")
{
    GIVEN("a probe result indicating the filter is active")
    {
        auto const result = merovingian::platform::SeccompProbeResult{.probed = true, .seccomp_active = true};

        WHEN("the check is derived from the probe")
        {
            auto const check = merovingian::platform::seccomp_check_from_probe(result);

            THEN("the check is enabled")
            {
                REQUIRE(check.status == merovingian::platform::HardeningStatus::enabled);
                REQUIRE(check.note.empty());
            }
        }
    }

    GIVEN("a probe result where the probe ran but no filter is active")
    {
        auto const result = merovingian::platform::SeccompProbeResult{.probed = true, .seccomp_active = false};

        WHEN("the check is derived from the probe")
        {
            auto const check = merovingian::platform::seccomp_check_from_probe(result);

            THEN("the check is unknown with a non-empty note")
            {
                REQUIRE(check.status == merovingian::platform::HardeningStatus::unknown);
                REQUIRE_FALSE(check.note.empty());
            }
        }
    }

    GIVEN("a probe result where the probe could not run")
    {
        auto const result = merovingian::platform::SeccompProbeResult{.probed = false, .seccomp_active = false};

        WHEN("the check is derived from the probe")
        {
            auto const check = merovingian::platform::seccomp_check_from_probe(result);

            THEN("the check is unknown")
            {
                REQUIRE(check.status == merovingian::platform::HardeningStatus::unknown);
            }
        }
    }

    GIVEN("any probe result")
    {
        auto const active = merovingian::platform::SeccompProbeResult{.probed = true, .seccomp_active = true};
        auto const inactive = merovingian::platform::SeccompProbeResult{.probed = true, .seccomp_active = false};
        auto const unprobed = merovingian::platform::SeccompProbeResult{.probed = false, .seccomp_active = false};

        WHEN("checks are derived from each result")
        {
            auto const check_active = merovingian::platform::seccomp_check_from_probe(active);
            auto const check_inactive = merovingian::platform::seccomp_check_from_probe(inactive);
            auto const check_unprobed = merovingian::platform::seccomp_check_from_probe(unprobed);

            THEN("the check is never alpha_exception or disabled")
            {
                auto constexpr alpha_exception = merovingian::platform::HardeningStatus::alpha_exception;
                auto constexpr disabled = merovingian::platform::HardeningStatus::disabled;
                REQUIRE(check_active.status != alpha_exception);
                REQUIRE(check_inactive.status != alpha_exception);
                REQUIRE(check_unprobed.status != alpha_exception);
                REQUIRE(check_active.status != disabled);
                REQUIRE(check_inactive.status != disabled);
                REQUIRE(check_unprobed.status != disabled);
            }
        }
    }
}

#ifdef __linux__
SCENARIO("seccomp probe reads /proc/self/status successfully on Linux", "[platform][hardening][seccomp][linux]")
{
    GIVEN("a Linux process running the test binary")
    {
        WHEN("the seccomp status is probed")
        {
            auto const result = merovingian::platform::probe_seccomp_status();

            THEN("the probe succeeds and returns a definitive seccomp_active value")
            {
                // probed == true means /proc/self/status was read successfully and
                // the Seccomp: field was parsed. seccomp_active reflects the actual
                // runtime environment — true in Docker containers (Docker's default
                // seccomp profile is active), false on bare hosts without a filter.
                // We do not apply apply_seccomp_filter() here because that would
                // permanently alter the test process's syscall table.
                REQUIRE(result.probed);
                // seccomp_active is environment-dependent; no assertion on its value.
            }
        }
    }
}
#endif
