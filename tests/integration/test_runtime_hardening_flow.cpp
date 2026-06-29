// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/runtime_hardening.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

SCENARIO("Integrated runtime hardening flow accepts a complete Linux deployment profile",
         "[platform][hardening][integration]")
{
    GIVEN("a default Linux hardening profile and required gates")
    {
        auto const profile = merovingian::platform::default_linux_hardening_profile();
        auto const gates = std::vector<merovingian::platform::HardeningGate>{
            {"privilege-drop",      merovingian::platform::HardeningAction::privilege_drop,
             merovingian::platform::HardeningMode::required, true },
            {"seccomp",             merovingian::platform::HardeningAction::syscall_filter,
             merovingian::platform::HardeningMode::required, true },
            {"capability-bounding", merovingian::platform::HardeningAction::capability_bounding,
             merovingian::platform::HardeningMode::required, true },
            {"systemd-sandbox",     merovingian::platform::HardeningAction::sandbox_profile,
             merovingian::platform::HardeningMode::optional, false},
        };

        WHEN("profile and gates are evaluated")
        {
            auto const profile_decision = merovingian::platform::evaluate_runtime_hardening_profile(profile);
            auto const gate_decision = merovingian::platform::evaluate_hardening_gates(gates);

            THEN("the complete hardened flow is accepted")
            {
                REQUIRE(profile_decision.accepted);
                REQUIRE(gate_decision.accepted);
                REQUIRE_FALSE(profile_decision.fail_closed);
                REQUIRE_FALSE(gate_decision.fail_closed);
            }
        }
    }
}

SCENARIO("Integrated runtime hardening flow rejects incomplete required deployment gates",
         "[platform][hardening][integration]")
{
    GIVEN("a profile with a missing required syscall filter gate")
    {
        auto const profile = merovingian::platform::default_linux_hardening_profile();
        auto const gates = std::vector<merovingian::platform::HardeningGate>{
            {"seccomp", merovingian::platform::HardeningAction::syscall_filter,
             merovingian::platform::HardeningMode::required, false},
        };

        WHEN("profile and gates are evaluated")
        {
            auto const profile_decision = merovingian::platform::evaluate_runtime_hardening_profile(profile);
            auto const gate_decision = merovingian::platform::evaluate_hardening_gates(gates);

            THEN("the hardening flow fails closed")
            {
                REQUIRE(profile_decision.accepted);
                REQUIRE_FALSE(gate_decision.accepted);
                REQUIRE(gate_decision.fail_closed);
                REQUIRE(gate_decision.reason == "required hardening gate unavailable: seccomp");
            }
        }
    }
}

SCENARIO("Integrated runtime hardening flow accepts BSD deployment with optional unavailable sandbox controls",
         "[platform][hardening][bsd][integration]")
{
    GIVEN("a BSD profile in optional mode with optional sandbox gates unavailable")
    {
        // pledge and Capsicum are documented alpha exceptions — not yet implemented.
        // They are optional gates; their absence must not block startup.
        auto profile = merovingian::platform::default_bsd_hardening_profile();
        profile.mode = merovingian::platform::HardeningMode::optional;
        auto const gates = std::vector<merovingian::platform::HardeningGate>{
            {"pledge",   merovingian::platform::HardeningAction::sandbox_profile,
             merovingian::platform::HardeningMode::optional, false},
            {"capsicum", merovingian::platform::HardeningAction::sandbox_profile,
             merovingian::platform::HardeningMode::optional, false},
        };

        WHEN("profile and gates are evaluated")
        {
            auto const profile_decision = merovingian::platform::evaluate_runtime_hardening_profile(profile);
            auto const gate_decision = merovingian::platform::evaluate_hardening_gates(gates);

            THEN("the BSD optional flow is accepted without the sandbox controls")
            {
                REQUIRE(profile_decision.accepted);
                REQUIRE(gate_decision.accepted);
                REQUIRE_FALSE(gate_decision.fail_closed);
            }
        }
    }
}

SCENARIO("Integrated runtime hardening flow fails closed when a required BSD gate is unavailable",
         "[platform][hardening][bsd][integration]")
{
    GIVEN("a BSD profile where a required sandbox gate is unavailable")
    {
        // Simulates a future state where pledge becomes required but the OS
        // version or build configuration does not provide it. Required +
        // unavailable must always fail closed — same semantics as Linux seccomp.
        auto const profile = merovingian::platform::default_bsd_hardening_profile();
        auto const gates = std::vector<merovingian::platform::HardeningGate>{
            {"pledge",   merovingian::platform::HardeningAction::sandbox_profile,
             merovingian::platform::HardeningMode::required, false},
            {"capsicum", merovingian::platform::HardeningAction::sandbox_profile,
             merovingian::platform::HardeningMode::optional, false},
        };

        WHEN("profile and gates are evaluated")
        {
            auto const profile_decision = merovingian::platform::evaluate_runtime_hardening_profile(profile);
            auto const gate_decision = merovingian::platform::evaluate_hardening_gates(gates);

            THEN("the required unavailable BSD gate fails closed while the profile itself is valid")
            {
                REQUIRE(profile_decision.accepted);
                REQUIRE_FALSE(gate_decision.accepted);
                REQUIRE(gate_decision.fail_closed);
                REQUIRE(gate_decision.reason == "required hardening gate unavailable: pledge");
            }
        }
    }
}
