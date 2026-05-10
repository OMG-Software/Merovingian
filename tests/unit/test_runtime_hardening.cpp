// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/platform/runtime_hardening.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

SCENARIO("Runtime hardening exposes Linux BSD and portable profile names", "[platform][hardening]")
{
    GIVEN("runtime hardening enums")
    {
        WHEN("names are requested")
        {
            THEN("platforms, modes, and actions are named")
            {
                REQUIRE(std::string{merovingian::platform::hardening_platform_name(merovingian::platform::HardeningPlatform::linux)} == "linux");
                REQUIRE(std::string{merovingian::platform::hardening_platform_name(merovingian::platform::HardeningPlatform::bsd)} == "bsd");
                REQUIRE(std::string{merovingian::platform::hardening_platform_name(merovingian::platform::HardeningPlatform::portable)} == "portable");
                REQUIRE(std::string{merovingian::platform::hardening_mode_name(merovingian::platform::HardeningMode::required)} == "required");
                REQUIRE(std::string{merovingian::platform::hardening_action_name(merovingian::platform::HardeningAction::syscall_filter)} == "syscall_filter");
                REQUIRE(std::string{merovingian::platform::hardening_action_name(merovingian::platform::HardeningAction::capability_bounding)} == "capability_bounding");
            }
        }
    }
}

SCENARIO("Default Linux BSD and portable hardening profiles are accepted", "[platform][hardening]")
{
    GIVEN("default runtime hardening profiles")
    {
        auto const linux = merovingian::platform::default_linux_hardening_profile();
        auto const bsd = merovingian::platform::default_bsd_hardening_profile();
        auto const portable = merovingian::platform::default_portable_hardening_profile();

        WHEN("profiles are evaluated")
        {
            auto const linux_decision = merovingian::platform::evaluate_runtime_hardening_profile(linux);
            auto const bsd_decision = merovingian::platform::evaluate_runtime_hardening_profile(bsd);
            auto const portable_decision = merovingian::platform::evaluate_runtime_hardening_profile(portable);

            THEN("all default profiles pass validation")
            {
                REQUIRE(linux_decision.accepted);
                REQUIRE(bsd_decision.accepted);
                REQUIRE(portable_decision.accepted);
                REQUIRE(linux.platform == merovingian::platform::HardeningPlatform::linux);
                REQUIRE(bsd.platform == merovingian::platform::HardeningPlatform::bsd);
                REQUIRE(portable.mode == merovingian::platform::HardeningMode::optional);
            }
        }
    }
}

SCENARIO("Runtime hardening primitives fail closed when unsafe", "[platform][hardening]")
{
    GIVEN("unsafe profile variants")
    {
        auto missing_privilege_drop = merovingian::platform::default_linux_hardening_profile();
        missing_privilege_drop.privilege_drop.user.clear();
        auto unsafe_filesystem = merovingian::platform::default_linux_hardening_profile();
        unsafe_filesystem.filesystem.writable_paths.push_back("/");
        auto unsafe_resources = merovingian::platform::default_linux_hardening_profile();
        unsafe_resources.resources.max_core_bytes = 1024U;
        auto unsafe_memory = merovingian::platform::default_linux_hardening_profile();
        unsafe_memory.memory.disable_core_dumps = false;
        auto unsafe_random = merovingian::platform::default_linux_hardening_profile();
        unsafe_random.random.fail_if_unavailable = false;
        auto unsafe_signal = merovingian::platform::default_linux_hardening_profile();
        unsafe_signal.signals.block_unexpected_signals = false;

        WHEN("profiles are evaluated")
        {
            auto const privilege_decision = merovingian::platform::evaluate_runtime_hardening_profile(missing_privilege_drop);
            auto const filesystem_decision = merovingian::platform::evaluate_runtime_hardening_profile(unsafe_filesystem);
            auto const resource_decision = merovingian::platform::evaluate_runtime_hardening_profile(unsafe_resources);
            auto const memory_decision = merovingian::platform::evaluate_runtime_hardening_profile(unsafe_memory);
            auto const random_decision = merovingian::platform::evaluate_runtime_hardening_profile(unsafe_random);
            auto const signal_decision = merovingian::platform::evaluate_runtime_hardening_profile(unsafe_signal);

            THEN("unsafe primitives are rejected with fail-closed decisions")
            {
                REQUIRE_FALSE(privilege_decision.accepted);
                REQUIRE(privilege_decision.fail_closed);
                REQUIRE(privilege_decision.reason == "privilege drop plan is incomplete");
                REQUIRE_FALSE(filesystem_decision.accepted);
                REQUIRE(filesystem_decision.reason == "filesystem restriction plan is unsafe");
                REQUIRE_FALSE(resource_decision.accepted);
                REQUIRE(resource_decision.reason == "resource limit plan is unsafe");
                REQUIRE_FALSE(memory_decision.accepted);
                REQUIRE(memory_decision.reason == "memory locking plan is unsafe");
                REQUIRE_FALSE(random_decision.accepted);
                REQUIRE(random_decision.reason == "random source plan is unsafe");
                REQUIRE_FALSE(signal_decision.accepted);
                REQUIRE(signal_decision.reason == "signal handling plan is unsafe");
            }
        }
    }
}

SCENARIO("Linux and BSD hardening documentation gates fail closed when incomplete", "[platform][hardening]")
{
    GIVEN("incomplete OS-specific hardening profiles")
    {
        auto linux = merovingian::platform::default_linux_hardening_profile();
        linux.linux.no_new_privs_required = false;
        auto bsd = merovingian::platform::default_bsd_hardening_profile();
        bsd.bsd.pledge_documented = false;

        WHEN("profiles are evaluated")
        {
            auto const linux_decision = merovingian::platform::evaluate_runtime_hardening_profile(linux);
            auto const bsd_decision = merovingian::platform::evaluate_runtime_hardening_profile(bsd);

            THEN("required OS hardening documentation is enforced")
            {
                REQUIRE_FALSE(linux_decision.accepted);
                REQUIRE(linux_decision.reason == "linux hardening plan is incomplete");
                REQUIRE_FALSE(bsd_decision.accepted);
                REQUIRE(bsd_decision.reason == "bsd hardening plan is incomplete");
            }
        }
    }
}

SCENARIO("Required hardening CI gates fail closed when unavailable", "[platform][hardening][ci]")
{
    GIVEN("required and optional hardening gates")
    {
        auto gates = std::vector<merovingian::platform::HardeningGate>{
            {"seccomp", merovingian::platform::HardeningAction::syscall_filter, merovingian::platform::HardeningMode::required, true},
            {"landlock", merovingian::platform::HardeningAction::sandbox_profile, merovingian::platform::HardeningMode::optional, false},
        };
        auto missing_required = gates;
        missing_required[0].available = false;
        auto unnamed = gates;
        unnamed[0].name.clear();

        WHEN("gates are evaluated")
        {
            auto const accepted = merovingian::platform::evaluate_hardening_gates(gates);
            auto const rejected_required = merovingian::platform::evaluate_hardening_gates(missing_required);
            auto const rejected_unnamed = merovingian::platform::evaluate_hardening_gates(unnamed);

            THEN("optional unavailable gates pass while required unavailable gates fail closed")
            {
                REQUIRE(accepted.accepted);
                REQUIRE_FALSE(rejected_required.accepted);
                REQUIRE(rejected_required.reason == "required hardening gate unavailable: seccomp");
                REQUIRE_FALSE(rejected_unnamed.accepted);
                REQUIRE(rejected_unnamed.reason == "hardening gate name is required");
            }
        }
    }
}

SCENARIO("Linux BSD and CI hardening notes cover deployment security profiles", "[platform][hardening]")
{
    GIVEN("hardening profile notes")
    {
        WHEN("notes are requested")
        {
            auto const linux_notes = merovingian::platform::linux_deployment_profile_notes();
            auto const bsd_notes = merovingian::platform::bsd_deployment_profile_notes();
            auto const ci_notes = merovingian::platform::runtime_hardening_ci_gate_notes();

            THEN("notes document required platform hardening surfaces")
            {
                REQUIRE(linux_notes.size() == 3U);
                REQUIRE(linux_notes[0].find("seccomp") != std::string::npos);
                REQUIRE(linux_notes[1].find("Landlock") != std::string::npos);
                REQUIRE(linux_notes[2].find("systemd") != std::string::npos);
                REQUIRE(bsd_notes.size() == 3U);
                REQUIRE(bsd_notes[0].find("pledge") != std::string::npos);
                REQUIRE(bsd_notes[1].find("Capsicum") != std::string::npos);
                REQUIRE(bsd_notes[2].find("setrlimit") != std::string::npos);
                REQUIRE(ci_notes.size() == 3U);
                REQUIRE(ci_notes[0].find("fail-closed") != std::string::npos);
                REQUIRE(ci_notes[1].find("BSD build") != std::string::npos);
                REQUIRE(ci_notes[2].find("static analysis") != std::string::npos);
            }
        }
    }
}
