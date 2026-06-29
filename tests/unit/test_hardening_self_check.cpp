// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/hardening_self_check.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

SCENARIO("Startup hardening self-check reports stable baseline checks", "[platform][hardening]")
{
    GIVEN("the expected baseline check count")
    {
        auto constexpr expected_count = 15U;

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
                REQUIRE(self_check.checks()[12].name == "no_new_privs");
                REQUIRE(self_check.checks()[13].name == "capability bounding");
                REQUIRE(self_check.checks()[14].name == "secret redaction policy");
            }
        }
    }
}

SCENARIO("Runtime hardening checks that cannot be confirmed at startup report unknown", "[platform][hardening]")
{
    GIVEN("a test process where runtime controls are not yet applied")
    {
        WHEN("the startup hardening self-check runs")
        {
            auto const self_check = merovingian::platform::run_startup_hardening_self_check();

            THEN("placeholder runtime checks are either enabled or unknown")
            {
                auto const& checks = self_check.checks();
                // Indices 7-13: pledge/unveil, capsicum, privilege drop,
                // filesystem restrictions, core dump policy, no_new_privs,
                // capability bounding. These report `enabled` when the control is
                // active or not applicable to this platform, and `unknown` when the
                // probe returns false (e.g. controls not yet applied in a test
                // process). Index 6 (seccomp) is probe-based and reports `unknown`
                // in the test process because apply_seccomp_filter() is not called.
                auto const deferred_indices = {7U, 8U, 9U, 10U, 11U, 12U, 13U};
                for (auto const index : deferred_indices)
                {
                    auto const status = checks[index].status;
                    REQUIRE((status == merovingian::platform::HardeningStatus::enabled ||
                             status == merovingian::platform::HardeningStatus::unknown));
                    if (status == merovingian::platform::HardeningStatus::unknown)
                    {
                        REQUIRE_FALSE(checks[index].note.empty());
                    }
                }
            }

            AND_THEN("probe-derived checks are never disabled")
            {
                // linker hardening (index 1) and RELRO (index 3) are driven by the
                // ELF program-header probe; seccomp (index 6) by a /proc/self/status
                // probe. All three may report `enabled` or `unknown` depending on the
                // build and runtime state, but never `disabled`.
                auto const& checks = self_check.checks();
                REQUIRE(checks[1].name == "linker hardening");
                REQUIRE(checks[3].name == "RELRO");
                REQUIRE(checks[6].name == "seccomp");
                REQUIRE(checks[1].status != merovingian::platform::HardeningStatus::disabled);
                REQUIRE(checks[3].status != merovingian::platform::HardeningStatus::disabled);
                REQUIRE(checks[6].status != merovingian::platform::HardeningStatus::disabled);
            }
        }
    }
}

SCENARIO("Hardening self-check fails closed when any control is not enabled", "[platform][hardening]")
{
    GIVEN("a startup hardening self-check report in a test process")
    {
        auto const self_check = merovingian::platform::run_startup_hardening_self_check();

        WHEN("the report is queried for readiness")
        {
            THEN("any unknown or disabled control blocks readiness")
            {
                // The test process does not apply runtime hardening controls, so
                // at least some checks are expected to be unknown. is_ready()
                // therefore returns false.
                REQUIRE_FALSE(self_check.is_ready());
                REQUIRE(self_check.production_blocker_count() > 0U);
            }

            AND_THEN("every blocker is a non-enabled check")
            {
                for (auto const& blocker : self_check.production_blockers())
                {
                    REQUIRE(blocker.status != merovingian::platform::HardeningStatus::enabled);
                }
            }
        }
    }
}

SCENARIO("Production-blocking hardening checks expose explanatory notes", "[platform][hardening]")
{
    GIVEN("a startup hardening self-check report")
    {
        auto const self_check = merovingian::platform::run_startup_hardening_self_check();

        WHEN("production blockers are collected")
        {
            auto const blockers = self_check.production_blockers();

            THEN("every blocker carries a non-empty note")
            {
                REQUIRE_FALSE(blockers.empty());
                for (auto const& blocker : blockers)
                {
                    REQUIRE_FALSE(blocker.note.empty());
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
                REQUIRE(self_check.checks()[14].name == "secret redaction policy");
                REQUIRE(self_check.checks()[14].status == enabled);
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

SCENARIO("Platform-specific sandbox controls reflect their applicability in the self-check",
         "[platform][hardening][bsd][portable]")
{
    GIVEN("the hardening self-check report")
    {
        auto const self_check = merovingian::platform::run_startup_hardening_self_check();
        auto const& checks = self_check.checks();

        WHEN("platform-specific sandbox controls are examined")
        {
            REQUIRE(checks[7].name == "pledge/unveil");
            REQUIRE(checks[8].name == "capsicum");

#ifdef __linux__
            // On Linux, pledge/unveil and Capsicum are not applicable controls —
            // the server reports `enabled` (no security gap from the absence of a
            // BSD-only primitive on a non-BSD platform).
            THEN("pledge/unveil and capsicum are enabled (not applicable on Linux)")
            {
                REQUIRE(checks[7].status == merovingian::platform::HardeningStatus::enabled);
                REQUIRE(checks[8].status == merovingian::platform::HardeningStatus::enabled);
            }
#elif defined(__OpenBSD__)
            // On OpenBSD, pledge has not been called yet in the test process.
            THEN("pledge/unveil is unknown (not yet applied in test process)")
            {
                REQUIRE(checks[7].status == merovingian::platform::HardeningStatus::unknown);
                REQUIRE(checks[8].status == merovingian::platform::HardeningStatus::enabled);
            }
#elif defined(__FreeBSD__)
            // On FreeBSD, cap_enter has not been called yet in the test process.
            THEN("capsicum is unknown (not yet entered in test process)")
            {
                REQUIRE(checks[7].status == merovingian::platform::HardeningStatus::enabled);
                REQUIRE(checks[8].status == merovingian::platform::HardeningStatus::unknown);
            }
#else
            THEN("pledge/unveil and capsicum are unknown on unsupported platforms")
            {
                REQUIRE(checks[7].status == merovingian::platform::HardeningStatus::unknown);
                REQUIRE(checks[8].status == merovingian::platform::HardeningStatus::unknown);
            }
#endif
        }
    }
}

#ifndef __linux__
SCENARIO("Hardening self-check maps Linux-only controls to appropriate non-Linux statuses",
         "[platform][hardening][bsd][portable]")
{
    GIVEN("the hardening self-check report on a non-Linux platform")
    {
        auto const self_check = merovingian::platform::run_startup_hardening_self_check();
        auto const& checks = self_check.checks();

        WHEN("seccomp is examined on a non-Linux host")
        {
            THEN("seccomp status is unknown — not enabled or disabled")
            {
                // /proc/self/status does not exist on BSD; probe_seccomp_status
                // returns {probed: false, seccomp_active: false} which maps to
                // `unknown`. unknown is the correct signal — the OS cannot run
                // seccomp-bpf at all.
                REQUIRE(checks[6].name == "seccomp");
                REQUIRE(checks[6].status == merovingian::platform::HardeningStatus::unknown);
                REQUIRE(checks[6].status != merovingian::platform::HardeningStatus::enabled);
                REQUIRE(checks[6].status != merovingian::platform::HardeningStatus::disabled);
            }
        }

        WHEN("Linux process-capability controls are examined on a non-Linux host")
        {
            THEN("core dump policy, no_new_privs, and capability bounding are unknown")
            {
                // PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS, and cap_set_proc are Linux
                // kernel features. On non-Linux hosts the implementation returns
                // enabled_or_unknown(false, ...) = unknown for each.
                REQUIRE(checks[11].name == "core dump policy");
                REQUIRE(checks[12].name == "no_new_privs");
                REQUIRE(checks[13].name == "capability bounding");
                REQUIRE(checks[11].status == merovingian::platform::HardeningStatus::unknown);
                REQUIRE(checks[12].status == merovingian::platform::HardeningStatus::unknown);
                REQUIRE(checks[13].status == merovingian::platform::HardeningStatus::unknown);
            }
        }
    }
}
#endif // !__linux__
