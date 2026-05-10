// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/platform/runtime_hardening.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

SCENARIO("Integrated runtime hardening flow accepts a complete Linux deployment profile", "[platform][hardening][integration]")
{
    GIVEN("a default Linux hardening profile and required gates")
    {
        auto const profile = merovingian::platform::default_linux_hardening_profile();
        auto const gates = std::vector<merovingian::platform::HardeningGate>{
            {"privilege-drop", merovingian::platform::HardeningAction::privilege_drop, merovingian::platform::HardeningMode::required, true},
            {"seccomp", merovingian::platform::HardeningAction::syscall_filter, merovingian::platform::HardeningMode::required, true},
            {"capability-bounding", merovingian::platform::HardeningAction::capability_bounding, merovingian::platform::HardeningMode::required, true},
            {"systemd-sandbox", merovingian::platform::HardeningAction::sandbox_profile, merovingian::platform::HardeningMode::optional, false},
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

SCENARIO("Integrated runtime hardening flow rejects incomplete required deployment gates", "[platform][hardening][integration]")
{
    GIVEN("a profile with a missing required syscall filter gate")
    {
        auto const profile = merovingian::platform::default_linux_hardening_profile();
        auto const gates = std::vector<merovingian::platform::HardeningGate>{
            {"seccomp", merovingian::platform::HardeningAction::syscall_filter, merovingian::platform::HardeningMode::required, false},
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
